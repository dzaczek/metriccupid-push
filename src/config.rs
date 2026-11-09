//! Environment configuration. Parsed once at startup; any invalid value is a
//! fatal error with a message naming the variable (never its secret value).

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;

pub const MIN_SECRET_LEN: usize = 32;
const DEFAULT_PUSHOVER_API_URL: &str = "https://api.pushover.net/1/messages.json";
pub const DEFAULT_GATEWAY_URL: &str = "https://push-metriccupid.sysop.cat";
pub const DEFAULT_APNS_TOPIC: &str = "cat.sysop.MetricCupid";
pub const APNS_PRODUCTION_URL: &str = "https://api.push.apple.com";
pub const APNS_SANDBOX_URL: &str = "https://api.sandbox.push.apple.com";

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

/// How v2 pushes reach APNs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsMode {
    /// HTTP/2 to Apple with our own provider key.
    Direct,
    /// Record pushes in memory (tests, local development).
    Mock,
    /// Forward push jobs to a hosted gateway (`GATEWAY_URL`).
    Gateway,
}

/// APNs provider key (`.p8`, PKCS#8 PEM). `Debug` never prints the key.
#[derive(Clone)]
pub struct ApnsKey {
    pub pem: String,
    pub key_id: String,
    pub team_id: String,
}

impl fmt::Debug for ApnsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApnsKey")
            .field("pem", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("team_id", &self.team_id)
            .finish()
    }
}

/// A token bucket refilled per hour (used for group registration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HourlyRate {
    pub per_hour: NonZeroU32,
    pub burst: NonZeroU32,
}

/// Settings for the v2 end-to-end encrypted mailbox (see PROTOCOL.md).
#[derive(Debug, Clone)]
pub struct V2Config {
    pub data_dir: PathBuf,
    pub apns_mode: ApnsMode,
    pub apns_key: Option<ApnsKey>,
    pub apns_topic: String,
    pub apns_production_url: String,
    pub apns_sandbox_url: String,
    pub gateway_url: String,
    pub hosted_open_registration: bool,
    pub rate_messages: Rate,
    pub rate_commands: Rate,
    pub rate_gateway: Rate,
    pub rate_groups: HourlyRate,
    pub ws_ping: Duration,
    /// Seconds the last Mac of a group may stay offline (stream lost without
    /// a `bye`) before its phones get a presence push. 0 = immediately.
    pub mac_offline_grace: u64,
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
    /// `false` when none of the v1 variables are set: `/v1/notify` is then 404.
    pub v1_enabled: bool,
    pub v2: V2Config,
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
            .field("v1_enabled", &self.v1_enabled)
            .field("v2", &self.v2)
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

        // v1 (Pushover relay) is optional: it is enabled when any of its
        // variables is set, and then all of them are required.
        const V1_VARS: [&str; 3] = ["PUSHOVER_APP_TOKEN", "PUSHOVER_USER_KEY", "RELAY_SECRETS"];
        let v1_enabled = mode == Mode::SelfHosted && V1_VARS.iter().any(|k| get(k).is_some());
        let required = |k: &str| match get(k) {
            Some(v) => Ok(v),
            None if !v1_enabled => Ok(String::new()),
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

        let secrets = parse_secrets(get("RELAY_SECRETS"), v1_enabled)?;

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

        let v2 = parse_v2(&get, mode)?;

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
            v1_enabled,
            v2,
        })
    }
}

fn parse_rate(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
    per_sec: u32,
    burst: u32,
) -> Result<Rate, ConfigError> {
    let p = format!("RATE_{name}_PER_SEC");
    let b = format!("RATE_{name}_BURST");
    Ok(Rate {
        per_sec: parse_nonzero(&p, get(&p), per_sec)?,
        burst: parse_nonzero(&b, get(&b), burst)?,
    })
}

fn parse_url(var: &str, v: String) -> Result<String, ConfigError> {
    if !(v.starts_with("https://") || v.starts_with("http://")) {
        return err(format!("{var} must start with http:// or https://"));
    }
    Ok(v.trim_end_matches('/').to_string())
}

fn parse_v2(get: &impl Fn(&str) -> Option<String>, mode: Mode) -> Result<V2Config, ConfigError> {
    let apns_mode = match get("APNS_MODE").as_deref() {
        None if mode == Mode::Hosted => ApnsMode::Direct,
        None => ApnsMode::Gateway,
        Some("direct") => ApnsMode::Direct,
        Some("mock") => ApnsMode::Mock,
        Some("gateway") => ApnsMode::Gateway,
        Some(_) => return err("APNS_MODE must be `direct`, `mock` or `gateway`"),
    };
    if mode == Mode::Hosted && apns_mode == ApnsMode::Gateway {
        return err(
            "APNS_MODE=gateway is not allowed with MODE=hosted (the hosted server is the gateway)",
        );
    }

    let apns_key = if apns_mode == ApnsMode::Direct {
        let raw = get("APNS_KEY_P8")
            .ok_or_else(|| ConfigError("APNS_KEY_P8 is required with APNS_MODE=direct".into()))?;
        let pem = if raw.contains("-----BEGIN") {
            // Allow a PEM squashed into one line with literal "\n".
            raw.replace("\\n", "\n")
        } else {
            std::fs::read_to_string(&raw)
                .map_err(|e| ConfigError(format!("APNS_KEY_P8: cannot read file: {e}")))?
        };
        let id = |k: &str| -> Result<String, ConfigError> {
            let v = get(k)
                .ok_or_else(|| ConfigError(format!("{k} is required with APNS_MODE=direct")))?;
            if v.len() != 10 || !v.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return err(format!("{k} must be 10 alphanumeric characters"));
            }
            Ok(v)
        };
        Some(ApnsKey {
            pem,
            key_id: id("APNS_KEY_ID")?,
            team_id: id("APNS_TEAM_ID")?,
        })
    } else {
        None
    };

    let apns_topic = get("APNS_TOPIC").unwrap_or_else(|| DEFAULT_APNS_TOPIC.to_string());
    if apns_topic.len() > 255
        || !apns_topic
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return err("APNS_TOPIC must be a bundle id like cat.sysop.MetricCupid");
    }

    Ok(V2Config {
        data_dir: PathBuf::from(get("DATA_DIR").unwrap_or_else(|| "/data".to_string())),
        apns_mode,
        apns_key,
        apns_topic,
        apns_production_url: parse_url(
            "APNS_PRODUCTION_URL",
            get("APNS_PRODUCTION_URL").unwrap_or_else(|| APNS_PRODUCTION_URL.into()),
        )?,
        apns_sandbox_url: parse_url(
            "APNS_SANDBOX_URL",
            get("APNS_SANDBOX_URL").unwrap_or_else(|| APNS_SANDBOX_URL.into()),
        )?,
        gateway_url: parse_url(
            "GATEWAY_URL",
            get("GATEWAY_URL").unwrap_or_else(|| DEFAULT_GATEWAY_URL.into()),
        )?,
        hosted_open_registration: parse_bool(
            "HOSTED_OPEN_REGISTRATION",
            get("HOSTED_OPEN_REGISTRATION"),
            false,
        )?,
        rate_messages: parse_rate(get, "V2_MESSAGES", 2, 60)?,
        rate_commands: parse_rate(get, "V2_COMMANDS", 1, 20)?,
        rate_gateway: parse_rate(get, "V2_GATEWAY", 5, 50)?,
        rate_groups: HourlyRate {
            per_hour: parse_nonzero("RATE_V2_GROUPS_PER_HOUR", get("RATE_V2_GROUPS_PER_HOUR"), 6)?,
            burst: parse_nonzero("RATE_V2_GROUPS_BURST", get("RATE_V2_GROUPS_BURST"), 3)?,
        },
        ws_ping: Duration::from_secs(
            parse_nonzero("WS_PING_SECS", get("WS_PING_SECS"), 30)?
                .get()
                .into(),
        ),
        mac_offline_grace: parse_num("MAC_OFFLINE_GRACE_SECS", get("MAC_OFFLINE_GRACE_SECS"), 120)?,
    })
}

fn parse_secrets(raw: Option<String>, v1_enabled: bool) -> Result<Vec<Secret>, ConfigError> {
    let Some(raw) = raw else {
        return if !v1_enabled {
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
        // Any v1 variable enables v1, which then needs all of them.
        let e = Config::from_lookup(|k| (k == "RELAY_SECRETS").then(|| SECRET.to_string()))
            .unwrap_err();
        assert!(e.0.contains("PUSHOVER_APP_TOKEN"), "{e}");
    }

    #[test]
    fn v1_disabled_when_unconfigured() {
        let c = Config::from_lookup(|_| None).unwrap();
        assert!(!c.v1_enabled);
        assert!(c.secrets.is_empty());
        assert!(cfg(&[]).unwrap().v1_enabled);
    }

    #[test]
    fn v2_defaults() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.v2.apns_mode, ApnsMode::Gateway);
        assert_eq!(c.v2.gateway_url, DEFAULT_GATEWAY_URL);
        assert_eq!(c.v2.apns_topic, DEFAULT_APNS_TOPIC);
        assert_eq!(c.v2.data_dir, PathBuf::from("/data"));
        assert!(!c.v2.hosted_open_registration);
        assert_eq!(c.v2.rate_messages.per_sec.get(), 2);
        assert_eq!(c.v2.rate_messages.burst.get(), 60);
        assert_eq!(c.v2.rate_commands.burst.get(), 20);
        assert_eq!(c.v2.ws_ping, Duration::from_secs(30));
        assert_eq!(c.v2.mac_offline_grace, 120);
    }

    #[test]
    fn v2_apns_modes() {
        let e = cfg(&[("APNS_MODE", "direct")]).unwrap_err();
        assert!(e.0.contains("APNS_KEY_P8"), "{e}");
        let pem = "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----";
        let c = cfg(&[
            ("APNS_MODE", "direct"),
            ("APNS_KEY_P8", pem),
            ("APNS_KEY_ID", "ABCDE12345"),
            ("APNS_TEAM_ID", "TEAM123456"),
        ])
        .unwrap();
        let key = c.v2.apns_key.unwrap();
        assert!(key.pem.contains("\nabc\n"));
        assert!(!format!("{key:?}").contains("abc"));
        assert!(cfg(&[
            ("APNS_MODE", "direct"),
            ("APNS_KEY_P8", pem),
            ("APNS_KEY_ID", "short"),
            ("APNS_TEAM_ID", "TEAM123456"),
        ])
        .is_err());
        assert!(cfg(&[("APNS_MODE", "carrier-pigeon")]).is_err());
        assert!(cfg(&[("MODE", "hosted"), ("APNS_MODE", "gateway")]).is_err());
        let c = Config::from_lookup(|k| match k {
            "MODE" => Some("hosted".into()),
            "APNS_MODE" => Some("mock".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.v2.apns_mode, ApnsMode::Mock);
        assert!(!c.v1_enabled, "v1 stays off in hosted mode");
        assert!(cfg(&[("GATEWAY_URL", "ftp://x")]).is_err());
        assert!(cfg(&[("APNS_TOPIC", "bad topic")]).is_err());
        assert!(cfg(&[("WS_PING_SECS", "0")]).is_err());
    }

    #[test]
    fn hosted_mode_needs_no_pushover_keys() {
        let c = Config::from_lookup(|k| match k {
            "MODE" => Some("hosted".into()),
            "APNS_MODE" => Some("mock".into()),
            _ => None,
        })
        .unwrap();
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
