//! Client IP resolution behind no proxy, Cloudflare, or trusted X-Forwarded-For proxies.

use std::net::IpAddr;
use std::time::Duration;

use axum::http::HeaderMap;
use ipnet::IpNet;

use crate::config::TrustProxy;

/// Cloudflare ranges from https://www.cloudflare.com/ips-v4 and /ips-v6.
pub const CLOUDFLARE_V4: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

pub const CLOUDFLARE_V6: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

const CF_URLS: [&str; 2] = [
    "https://www.cloudflare.com/ips-v4",
    "https://www.cloudflare.com/ips-v6",
];

pub fn builtin_cloudflare_ranges() -> Vec<IpNet> {
    CLOUDFLARE_V4
        .iter()
        .chain(CLOUDFLARE_V6)
        .map(|s| s.parse().expect("built-in Cloudflare range is valid"))
        .collect()
}

#[derive(Debug, Clone)]
pub enum ClientIpResolver {
    Peer,
    Cloudflare(Vec<IpNet>),
    Xff(Vec<IpNet>),
}

fn contains(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(&ip))
}

fn header_ip(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)?
        .to_str()
        .ok()?
        .trim()
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical())
}

impl ClientIpResolver {
    /// Build the resolver; with `CF_REFRESH=true` the ranges are fetched once,
    /// falling back to the built-in list on any error.
    pub async fn from_config(tp: &TrustProxy) -> Self {
        match tp {
            TrustProxy::None => Self::Peer,
            TrustProxy::Xff(nets) => Self::Xff(nets.clone()),
            TrustProxy::Cloudflare { refresh, extra } => {
                let mut ranges = if *refresh {
                    match fetch_cloudflare_ranges().await {
                        Ok(r) => {
                            tracing::info!(count = r.len(), "fetched Cloudflare IP ranges");
                            r
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Cloudflare range refresh failed, using built-in list");
                            builtin_cloudflare_ranges()
                        }
                    }
                } else {
                    builtin_cloudflare_ranges()
                };
                ranges.extend(extra.iter().copied());
                Self::Cloudflare(ranges)
            }
        }
    }

    pub fn resolve(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.to_canonical();
        match self {
            Self::Peer => peer,
            Self::Cloudflare(ranges) => {
                if contains(ranges, peer) {
                    header_ip(headers, "cf-connecting-ip").unwrap_or(peer)
                } else {
                    peer
                }
            }
            Self::Xff(trusted) => {
                if !contains(trusted, peer) {
                    return peer;
                }
                // Walk X-Forwarded-For right to left; the first hop not added by
                // a trusted proxy is the client. Multiple headers concatenate.
                let hops: Vec<&str> = headers
                    .get_all("x-forwarded-for")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .flat_map(|v| v.split(','))
                    .map(str::trim)
                    .collect();
                let mut last = peer;
                for hop in hops.iter().rev() {
                    let Ok(ip) = hop.parse::<IpAddr>().map(|ip| ip.to_canonical()) else {
                        // Garbage hop: stop at the last trusted address we saw.
                        return last;
                    };
                    if !contains(trusted, ip) {
                        return ip;
                    }
                    last = ip;
                }
                last
            }
        }
    }
}

async fn fetch_cloudflare_ranges() -> Result<Vec<IpNet>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for url in CF_URLS {
        let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("{url}: HTTP {}", resp.status()));
        }
        let text = resp.text().await.map_err(|e| e.to_string())?;
        let nets = parse_range_list(&text).ok_or_else(|| format!("{url}: unparsable list"))?;
        out.extend(nets);
    }
    Ok(out)
}

/// Parse one CIDR per line; `None` if any line is invalid or the list is empty.
fn parse_range_list(text: &str) -> Option<Vec<IpNet>> {
    let nets: Option<Vec<IpNet>> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.parse().ok())
        .collect();
    nets.filter(|n| !n.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn hdr(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn builtin_ranges_parse() {
        assert_eq!(
            builtin_cloudflare_ranges().len(),
            CLOUDFLARE_V4.len() + CLOUDFLARE_V6.len()
        );
    }

    #[test]
    fn peer_mode_ignores_headers() {
        let h = hdr(&[
            ("cf-connecting-ip", "1.2.3.4"),
            ("x-forwarded-for", "1.2.3.4"),
        ]);
        assert_eq!(
            ClientIpResolver::Peer.resolve(ip("192.0.2.9"), &h),
            ip("192.0.2.9")
        );
    }

    #[test]
    fn spoofed_cf_header_from_non_cloudflare_peer_is_ignored() {
        let r = ClientIpResolver::Cloudflare(builtin_cloudflare_ranges());
        let h = hdr(&[("cf-connecting-ip", "1.2.3.4")]);
        assert_eq!(r.resolve(ip("192.0.2.9"), &h), ip("192.0.2.9"));
        assert_eq!(r.resolve(ip("2001:db8::1"), &h), ip("2001:db8::1"));
    }

    #[test]
    fn cf_header_from_cloudflare_peer_is_used() {
        let r = ClientIpResolver::Cloudflare(builtin_cloudflare_ranges());
        let h = hdr(&[("cf-connecting-ip", "198.51.100.7")]);
        assert_eq!(r.resolve(ip("162.158.1.1"), &h), ip("198.51.100.7"));
        assert_eq!(r.resolve(ip("2606:4700::1"), &h), ip("198.51.100.7"));
        assert_eq!(r.resolve(ip("::ffff:172.64.0.1"), &h), ip("198.51.100.7"));
        // Missing or garbage header falls back to the peer.
        assert_eq!(
            r.resolve(ip("162.158.1.1"), &HeaderMap::new()),
            ip("162.158.1.1")
        );
        let bad = hdr(&[("cf-connecting-ip", "not-an-ip")]);
        assert_eq!(r.resolve(ip("162.158.1.1"), &bad), ip("162.158.1.1"));
    }

    #[test]
    fn xff_rightmost_untrusted() {
        let r = ClientIpResolver::Xff(vec!["10.0.0.0/8".parse().unwrap()]);
        let h = hdr(&[("x-forwarded-for", "6.6.6.6, 198.51.100.7, 10.0.0.2")]);
        // Spoofed leftmost entry is ignored; client is the hop before our proxies.
        assert_eq!(r.resolve(ip("10.0.0.1"), &h), ip("198.51.100.7"));
        // Untrusted peer: header ignored.
        assert_eq!(r.resolve(ip("203.0.113.1"), &h), ip("203.0.113.1"));
        // Multiple headers are concatenated in order.
        let h2 = hdr(&[
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-for", "198.51.100.8"),
        ]);
        assert_eq!(r.resolve(ip("10.0.0.1"), &h2), ip("198.51.100.8"));
        // All hops trusted -> leftmost trusted.
        let h3 = hdr(&[("x-forwarded-for", "10.1.1.1, 10.0.0.2")]);
        assert_eq!(r.resolve(ip("10.0.0.1"), &h3), ip("10.1.1.1"));
        // Garbage hop -> last trusted address seen.
        let h4 = hdr(&[("x-forwarded-for", "198.51.100.7, junk, 10.0.0.2")]);
        assert_eq!(r.resolve(ip("10.0.0.1"), &h4), ip("10.0.0.2"));
        // No header -> peer.
        assert_eq!(r.resolve(ip("10.0.0.1"), &HeaderMap::new()), ip("10.0.0.1"));
    }

    #[test]
    fn range_list_parsing() {
        assert_eq!(
            parse_range_list("1.2.3.0/24\n\n2001:db8::/32\n")
                .unwrap()
                .len(),
            2
        );
        assert!(parse_range_list("").is_none());
        assert!(parse_range_list("<html>").is_none());
    }
}
