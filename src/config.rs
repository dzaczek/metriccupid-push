//! Environment configuration. Parsed once at startup; any invalid value is a
//! fatal error with a message naming the variable (never its secret value).

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use ipnet::IpNet;

pub const MIN_SECRET_LEN: usize = 32;
const DEFAULT_PUSHOVER_API_URL: &str = "https://api.pushover.net/1/messages.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    SelfHosted,
    /// Placeholder for the future hosted Pro mode (App Store JWS licences).
    Hosted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustProxy {
    /// Client IP = TCP peer address.
    None,
    /// Trust `CF-Connecting-IP` only when the TCP peer is a Cloudflare address.
    Cloudflare { refresh: bool, extra: Vec<IpNet> },
    /// Trust `X-Forwarded-For` hops added by these proxies (rightmost untrusted hop wins).
    Xff(Vec<IpNet>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    pub per_sec: NonZeroU32,
    pub burst: NonZeroU32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub global: Rate,
    pub per_ip: Rate,
    pub per_secret: Rate,
    /// Auth failures from one IP within `ban_window` that trigger a ban.
    pub ban_threshold: u32,
    pub ban_window: Duration,
    pub ban_duration: Duration,
}

/// A relay secret. `Debug` never prints the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Clone)]
pub struct Config {
    pub pushover_app_token: String,
    pub pushover_user_key: String,
    pub pushover_api_url: String,
    pub secrets: Vec<Secret>,
    pub bind: SocketAddr,
    pub trust_proxy: TrustProxy,
    pub mode: Mode,
    pub allow_emergency: bool,
    pub dedup_window: Duration,
    pub quota_reserve: u64,
    pub limits: Limits,
    pub log_format: LogFormat,
    pub log_level: tracing::Level,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("pushover_app_token", &"<redacted>")
            .field("pushover_user_key", &"<redacted>")
            .field("pushover_api_url", &self.pushover_api_url)
            .field("secrets", &self.secrets.len())
            .field("bind", &self.bind)
            .field("trust_proxy", &self.trust_proxy)
            .field("mode", &self.mode)
            .field("allow_emergency", &self.allow_emergency)
            .field("dedup_window", &self.dedup_window)
            .field("quota_reserve", &self.quota_reserve)
            .field("limits", &self.limits)
            .field("log_format", &self.log_format)
            .field("log_level", &self.log_level)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from an arbitrary key lookup (used by tests).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        // Treat empty values as unset.
        let get = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let mode = match get("MODE").as_deref() {
            None | Some("selfhosted") => Mode::SelfHosted,
            Some("hosted") => Mode::Hosted,
            Some(_) => return err("MODE must be `selfhosted` or `hosted`"),
        };

        let required = |k: &str| match get(k) {
            Some(v) => Ok(v),
            None if mode == Mode::Hosted => Ok(String::new()),
            None => err(format!("{k} is required")),
        };
        let pushover_app_token = required("PUSHOVER_APP_TOKEN")?;
        let pushover_user_key = required("PUSHOVER_USER_KEY")?;
        for (k, v) in [
            ("PUSHOVER_APP_TOKEN", &pushover_app_token),
            ("PUSHOVER_USER_KEY", &pushover_user_key),
        ] {
            if !v.chars().all(|c| c.is_ascii_alphanumeric()) {
                return err(format!("{k} must be alphanumeric"));
            }
        }

        let secrets = parse_secrets(get("RELAY_SECRETS"), mode)?;

        let bind = match get("BIND") {
            None => SocketAddr::from(([0, 0, 0, 0], 8080)),
            Some(v) => v
                .parse()
                .map_err(|_| ConfigError("BIND must be ip:port, e.g. 0.0.0.0:8080".into()))?,
        };

        let trust_proxy = parse_trust_proxy(
            get("TRUST_PROXY").as_deref(),
            get("CF_REFRESH").as_deref(),
            get("CF_IPS_EXTRA").as_deref(),
        )?;

        let pushover_api_url =
            get("PUSHOVER_API_URL").unwrap_or_else(|| DEFAULT_PUSHOVER_API_URL.to_string());
        if !(pushover_api_url.starts_with("https://") || pushover_api_url.starts_with("http://")) {
            return err("PUSHOVER_API_URL must start with http:// or https://");
        }

        let allow_emergency = parse_bool("ALLOW_EMERGENCY", get("ALLOW_EMERGENCY"), false)?;
        let dedup_window = Duration::from_secs(parse_num(
            "DEDUP_WINDOW_SECS",
            get("DEDUP_WINDOW_SECS"),
            300,
        )?);
        let quota_reserve = parse_num("QUOTA_RESERVE", get("QUOTA_RESERVE"), 500)?;

        let rate = |name: &str, per_sec: u32, burst: u32| -> Result<Rate, ConfigError> {
            let p = format!("RATE_{name}_PER_SEC");
            let b = format!("RATE_{name}_BURST");
            Ok(Rate {
                per_sec: parse_nonzero(&p, get(&p), per_sec)?,
                burst: parse_nonzero(&b, get(&b), burst)?,
            })
        };
        let limits = Limits {
            global: rate("GLOBAL", 50, 100)?,
            per_ip: rate("IP", 5, 20)?,
            per_secret: rate("SECRET", 2, 30)?,
            ban_threshold: parse_nonzero("AUTH_BAN_THRESHOLD", get("AUTH_BAN_THRESHOLD"), 10)?
                .get(),
            ban_window: Duration::from_secs(parse_num(
                "AUTH_BAN_WINDOW_SECS",
                get("AUTH_BAN_WINDOW_SECS"),
                900,
            )?),
            ban_duration: Duration::from_secs(parse_num(
                "AUTH_BAN_SECS",
                get("AUTH_BAN_SECS"),
                900,
            )?),
        };

        let log_format = match get("LOG_FORMAT").as_deref() {
            None | Some("text") => LogFormat::Text,
            Some("json") => LogFormat::Json,
            Some(_) => return err("LOG_FORMAT must be `text` or `json`"),
        };
        let log_level = match get("LOG_LEVEL") {
            None => tracing::Level::INFO,
            Some(v) => v
                .parse()
                .map_err(|_| ConfigError("LOG_LEVEL must be error|warn|info|debug|trace".into()))?,
        };

        Ok(Config {
            pushover_app_token,
            pushover_user_key,
            pushover_api_url,
            secrets,
            bind,
            trust_proxy,
            mode,
            allow_emergency,
            dedup_window,
            quota_reserve,
            limits,
            log_format,
            log_level,
        })
    }
}

fn parse_secrets(raw: Option<String>, mode: Mode) -> Result<Vec<Secret>, ConfigError> {
    let Some(raw) = raw else {
        return if mode == Mode::Hosted {
            Ok(Vec::new())
        } else {
            err("RELAY_SECRETS is required (comma-separated, each at least 32 characters)")
        };
    };
    let mut out = Vec::new();
    for (i, s) in raw.split(',').map(str::trim).enumerate() {
        if s.len() < MIN_SECRET_LEN {
            return err(format!(
                "RELAY_SECRETS entry #{} is shorter than {MIN_SECRET_LEN} characters",
                i + 1
            ));
        }
        let secret = Secret(s.as_bytes().to_vec());
        if out.contains(&secret) {
            return err(format!("RELAY_SECRETS entry #{} is a duplicate", i + 1));
        }
        out.push(secret);
    }
    Ok(out)
}

fn parse_trust_proxy(
    mode: Option<&str>,
    cf_refresh: Option<&str>,
    cf_extra: Option<&str>,
) -> Result<TrustProxy, ConfigError> {
    match mode {
        None | Some("none") => Ok(TrustProxy::None),
        Some("cloudflare") => Ok(TrustProxy::Cloudflare {
            refresh: parse_bool("CF_REFRESH", cf_refresh.map(str::to_string), false)?,
            extra: match cf_extra {
                Some(v) => parse_cidrs("CF_IPS_EXTRA", v)?,
                None => Vec::new(),
            },
        }),
        Some(v) if v.starts_with("xff:") => {
            let nets = parse_cidrs("TRUST_PROXY", &v[4..])?;
            if nets.is_empty() {
                return err("TRUST_PROXY=xff: needs at least one CIDR");
            }
            Ok(TrustProxy::Xff(nets))
        }
        Some(_) => err("TRUST_PROXY must be `none`, `cloudflare` or `xff:<cidr>[,<cidr>...]`"),
    }
}

/// Parse a comma-separated CIDR list; a bare IP is accepted as a /32 or /128.
pub fn parse_cidrs(var: &str, raw: &str) -> Result<Vec<IpNet>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
                .map(|n| n.trunc())
                .map_err(|_| ConfigError(format!("{var}: `{s}` is not a valid CIDR")))
        })
        .collect()
}

fn parse_bool(var: &str, v: Option<String>, default: bool) -> Result<bool, ConfigError> {
    match v.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None => Ok(default),
        Some("true" | "1" | "yes") => Ok(true),
        Some("false" | "0" | "no") => Ok(false),
        Some(_) => err(format!("{var} must be true or false")),
    }
}

fn parse_num<T: std::str::FromStr>(
    var: &str,
    v: Option<String>,
    default: T,
) -> Result<T, ConfigError> {
    match v {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|_| ConfigError(format!("{var} must be a non-negative integer"))),
    }
}

fn parse_nonzero(var: &str, v: Option<String>, default: u32) -> Result<NonZeroU32, ConfigError> {
    let n: u32 = parse_num(var, v, default)?;
    NonZeroU32::new(n).ok_or_else(|| ConfigError(format!("{var} must be greater than 0")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SECRET: &str = "test-secret-0123456789abcdef0123456789";

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let mut m: HashMap<String, String> = HashMap::from([
            ("PUSHOVER_APP_TOKEN".into(), "apptoken123".into()),
            ("PUSHOVER_USER_KEY".into(), "userkey123".into()),
            ("RELAY_SECRETS".into(), SECRET.into()),
        ]);
        for (k, v) in pairs {
            m.insert(k.to_string(), v.to_string());
        }
        Config::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn defaults() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.bind.to_string(), "0.0.0.0:8080");
        assert_eq!(c.mode, Mode::SelfHosted);
        assert_eq!(c.trust_proxy, TrustProxy::None);
        assert!(!c.allow_emergency);
        assert_eq!(c.dedup_window, Duration::from_secs(300));
        assert_eq!(c.quota_reserve, 500);
        assert_eq!(c.limits.global.per_sec.get(), 50);
        assert_eq!(c.limits.per_ip.burst.get(), 20);
        assert_eq!(c.limits.per_secret.burst.get(), 30);
        assert_eq!(c.limits.ban_threshold, 10);
        assert_eq!(c.log_format, LogFormat::Text);
    }

    #[test]
    fn missing_required() {
        let e = Config::from_lookup(|_| None).unwrap_err();
        assert!(e.0.contains("PUSHOVER_APP_TOKEN"), "{e}");
    }

    #[test]
    fn hosted_mode_needs_no_keys() {
        let c = Config::from_lookup(|k| (k == "MODE").then(|| "hosted".to_string())).unwrap();
        assert_eq!(c.mode, Mode::Hosted);
    }

    #[test]
    fn short_secret_rejected_without_leaking_it() {
        let e = cfg(&[("RELAY_SECRETS", &format!("{SECRET},tooshortsecret"))]).unwrap_err();
        assert!(e.0.contains("#2"));
        assert!(!e.0.contains("tooshort"));
    }

    #[test]
    fn multiple_secrets() {
        let other = "another-secret-abcdefghijklmnopqrstuvwxyz";
        let c = cfg(&[("RELAY_SECRETS", &format!("{SECRET}, {other}"))]).unwrap();
        assert_eq!(c.secrets.len(), 2);
        assert!(cfg(&[("RELAY_SECRETS", &format!("{SECRET},{SECRET}"))]).is_err());
    }

    #[test]
    fn trust_proxy_modes() {
        let c = cfg(&[("TRUST_PROXY", "xff:10.0.0.0/8, 192.168.1.1")]).unwrap();
        assert_eq!(
            c.trust_proxy,
            TrustProxy::Xff(vec![
                "10.0.0.0/8".parse().unwrap(),
                "192.168.1.1/32".parse().unwrap()
            ])
        );
        let c = cfg(&[
            ("TRUST_PROXY", "cloudflare"),
            ("CF_IPS_EXTRA", "2001:db8::/32"),
        ])
        .unwrap();
        assert!(
            matches!(c.trust_proxy, TrustProxy::Cloudflare { refresh: false, ref extra } if extra.len() == 1)
        );
        assert!(cfg(&[("TRUST_PROXY", "xff:")]).is_err());
        assert!(cfg(&[("TRUST_PROXY", "xff:notacidr")]).is_err());
        assert!(cfg(&[("TRUST_PROXY", "everything")]).is_err());
    }

    #[test]
    fn invalid_values() {
        assert!(cfg(&[("BIND", "8080")]).is_err());
        assert!(cfg(&[("ALLOW_EMERGENCY", "maybe")]).is_err());
        assert!(cfg(&[("RATE_IP_PER_SEC", "0")]).is_err());
        assert!(cfg(&[("DEDUP_WINDOW_SECS", "-1")]).is_err());
        assert!(cfg(&[("LOG_FORMAT", "xml")]).is_err());
        assert!(cfg(&[("MODE", "pro")]).is_err());
        assert!(cfg(&[("PUSHOVER_API_URL", "ftp://x")]).is_err());
        assert!(cfg(&[("PUSHOVER_APP_TOKEN", "abc&user=x")]).is_err());
    }

    #[test]
    fn debug_redacts() {
        let s = format!("{:?}", cfg(&[]).unwrap());
        assert!(!s.contains(SECRET));
        assert!(!s.contains("apptoken123"));
        assert!(!s.contains("userkey123"));
    }
}
