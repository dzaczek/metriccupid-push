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

/// How the hosted service decides who may use it (PROTOCOL.md section 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenceMode {
    /// Any group may register and send (open beta, and always when self-hosted).
    Open,
    /// Groups need a verified App Store `AppTransaction` (hosted default).
    AppTransaction,
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
    pub licence_mode: LicenceMode,
    /// Accept TestFlight (`Sandbox`) transactions.
    pub licence_allow_sandbox: bool,
    /// Groups one purchase may be attached to.
    pub licence_max_groups: u32,
    /// Unix seconds until which unlicensed groups may still send.
    pub licence_grace_until: Option<u64>,
    pub gateway_open: bool,
    /// `GATEWAY_REQUIRE_LICENCE`: gateway registrations need a licence that
    /// counts for the gateway (production, or sandbox while
    /// `gateway_sandbox_licences_count`). Off: a licence only raises the quotas.
    pub gateway_require_licence: bool,
    /// `GATEWAY_ACTIVITY_LINES`: keep Live Activity `lines` on gateway pushes.
    pub gateway_activity_lines: bool,
    /// `GATEWAY_APNS_SANDBOX`: accept gateway pushes with `env=sandbox`.
    pub gateway_apns_sandbox: bool,
    /// `GATEWAY_SANDBOX_LICENCES_COUNT`: TestFlight licences count as
    /// licensed for the gateway (quotas, strict mode).
    pub gateway_sandbox_licences_count: bool,
    /// All gateway pushes together, apart from the hosted global bucket.
    pub gateway_global: Rate,
    /// Per gateway group and hour, on top of `rate_gateway`.
    pub gateway_group_hourly: HourlyRate,
    pub gateway_max_tokens_per_group: u32,
    pub gateway_max_groups: u32,
    /// `LICENCE_REVOKED_TX`: refused purchase ids.
    pub licence_revoked: RevokedTx,
    pub rate_messages: Rate,
    pub rate_commands: Rate,
    pub rate_gateway: Rate,
    pub rate_groups: HourlyRate,
    /// `RATE_GROUP_*`: every signed request of one group.
    pub rate_group: Rate,
    pub ws_ping: Duration,
    /// `WS_MAX_STREAMS`: open Mac streams on the server.
    pub ws_max_streams: u32,
    /// `WS_MAX_MACS_PER_GROUP`: open Mac streams per group.
    pub ws_max_macs_per_group: u32,
    /// `WS_MAX_PER_IP`: open Mac streams per client IP (IPv6 /64).
    pub ws_max_per_ip: u32,
    /// Seconds the last Mac of a group may stay offline (stream lost without
    /// a `bye`) before its phones get a presence push. 0 = immediately.
    pub mac_offline_grace: u64,
    /// Max length (base64 characters) of a snapshot's `sealed`.
    pub snapshot_max_bytes: usize,
}

/// Revoked App Store purchase ids. `Debug` prints only the count: the ids
/// are never logged.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RevokedTx(pub std::collections::HashSet<String>);

impl fmt::Debug for RevokedTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RevokedTx({} ids)", self.0.len())
    }
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
    /// `RATE_GLOBAL_*`: authenticated requests (v2: checked after the
    /// signature; v1: before it, as before).
    pub global: Rate,
    /// `RATE_ANON_GLOBAL_*`: group registrations and failed authentications.
    pub anon_global: Rate,
    /// `RATE_PRE_AUTH_*`: all pre-signature work of signed routes.
    pub pre_auth: Rate,
    pub per_ip: Rate,
    pub per_secret: Rate,
    /// Auth failures from one IP within `ban_window` that trigger a ban.
    pub ban_threshold: u32,
    pub ban_window: Duration,
    pub ban_duration: Duration,
    /// `AUTH_ABUSE_*`: rate-limited answers that trigger a ban.
    pub abuse: crate::limits::AbuseRule,
    /// `REPLAY_CAP`: signatures remembered at once; when full, new signed
    /// requests get `503` (fail closed) instead of evicting live entries.
    pub replay_cap: usize,
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

/// Admin panel credentials and access rules. `Debug` never prints secrets.
#[derive(Clone)]
pub struct AdminConfig {
    pub bind: SocketAddr,
    pub user: String,
    /// argon2id PHC string.
    pub password_hash: String,
    /// Decoded TOTP secret (from base32).
    pub totp_secret: Vec<u8>,
    /// Empty only with `allow_any`.
    pub allow_ips: Vec<IpNet>,
    pub allow_any: bool,
    /// `ADMIN_ALLOW_ANY_WITHOUT_ACCESS`; `None` when unset.
    pub allow_any_without_access: Option<bool>,
    /// Cloudflare Access JWT check (`ADMIN_CF_ACCESS_*`), off when `None`.
    pub cf_access: Option<CfAccessConfig>,
    pub session_secs: u64,
    pub events_retention_days: u64,
}

/// Cloudflare Access application the admin hostname sits behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfAccessConfig {
    /// Team domain, e.g. `j23.cloudflareaccess.com`.
    pub team_domain: String,
    /// Accepted application AUD tags.
    pub auds: Vec<String>,
}

impl CfAccessConfig {
    /// Expected `iss` claim.
    pub fn issuer(&self) -> String {
        format!("https://{}", self.team_domain)
    }

    /// The team's JWKS endpoint.
    pub fn certs_url(&self) -> String {
        format!("https://{}/cdn-cgi/access/certs", self.team_domain)
    }
}

impl fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminConfig")
            .field("bind", &self.bind)
            .field("user", &self.user)
            .field("password_hash", &"<redacted>")
            .field("totp_secret", &"<redacted>")
            .field("allow_ips", &self.allow_ips)
            .field("allow_any", &self.allow_any)
            .field("allow_any_without_access", &self.allow_any_without_access)
            .field("cf_access", &self.cf_access)
            .field("session_secs", &self.session_secs)
            .field("events_retention_days", &self.events_retention_days)
            .finish()
    }
}

/// Whether the admin listener runs. A misconfigured panel does not stop the
/// public API: it is `Refused` and the reason is logged at startup.
#[derive(Debug, Clone)]
pub enum AdminSetting {
    /// `ADMIN_BIND` not set.
    Off,
    Refused(String),
    On(AdminConfig),
}

impl AdminSetting {
    pub fn config(&self) -> Option<&AdminConfig> {
        match self {
            Self::On(c) => Some(c),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Config {
    /// `MAX_CONNECTIONS`: open TCP connections on the public listener
    /// (WebSocket streams included); further clients wait in the backlog.
    pub max_connections: usize,
    /// `MAX_CONNECTIONS_PER_IP`: open connections per TCP peer (IPv6 /64);
    /// trusted proxies (`TRUST_PROXY`) are exempt.
    pub max_connections_per_ip: usize,
    /// `HEADER_READ_TIMEOUT_SECS`: a client must send complete request
    /// headers within this time, else the connection is closed.
    pub header_read_timeout: Duration,
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
    pub admin: AdminSetting,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("max_connections", &self.max_connections)
            .field("max_connections_per_ip", &self.max_connections_per_ip)
            .field("header_read_timeout", &self.header_read_timeout)
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
            .field("admin", &self.admin)
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
            get("CF_IPS_EXTRA_ALLOW_SUBNET"),
        )?;

        // Not trimmed: the Pushover client posts to this exact URL.
        let pushover_api_url =
            get("PUSHOVER_API_URL").unwrap_or_else(|| DEFAULT_PUSHOVER_API_URL.to_string());
        parse_url("PUSHOVER_API_URL", pushover_api_url.clone())?;

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
            anon_global: rate("ANON_GLOBAL", 20, 60)?,
            pre_auth: rate("PRE_AUTH", 200, 400)?,
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
            abuse: crate::limits::AbuseRule {
                threshold: parse_nonzero("AUTH_ABUSE_THRESHOLD", get("AUTH_ABUSE_THRESHOLD"), 100)?
                    .get(),
                window: parse_nonzero("AUTH_ABUSE_WINDOW_SECS", get("AUTH_ABUSE_WINDOW_SECS"), 60)?
                    .get()
                    .into(),
                duration: parse_nonzero("AUTH_ABUSE_BAN_SECS", get("AUTH_ABUSE_BAN_SECS"), 300)?
                    .get()
                    .into(),
            },
            replay_cap: parse_nonzero("REPLAY_CAP", get("REPLAY_CAP"), 100_000)?.get() as usize,
        };
        let max_connections =
            parse_nonzero("MAX_CONNECTIONS", get("MAX_CONNECTIONS"), 8192)?.get() as usize;
        let max_connections_per_ip =
            parse_nonzero("MAX_CONNECTIONS_PER_IP", get("MAX_CONNECTIONS_PER_IP"), 64)?.get()
                as usize;
        let header_read_timeout = Duration::from_secs(
            parse_nonzero(
                "HEADER_READ_TIMEOUT_SECS",
                get("HEADER_READ_TIMEOUT_SECS"),
                10,
            )?
            .get()
            .into(),
        );

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
        let admin = parse_admin(&get);

        Ok(Config {
            max_connections,
            max_connections_per_ip,
            header_read_timeout,
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
            admin,
        })
    }
}

/// The admin panel (README "Admin panel"). Off without `ADMIN_BIND`; any
/// problem refuses the panel only (fail closed), never the public API.
fn parse_admin(get: &impl Fn(&str) -> Option<String>) -> AdminSetting {
    if get("ADMIN_BIND").is_none() {
        return AdminSetting::Off;
    }
    match parse_admin_on(get) {
        Ok(c) => AdminSetting::On(c),
        Err(e) => AdminSetting::Refused(e.0),
    }
}

fn parse_admin_on(get: &impl Fn(&str) -> Option<String>) -> Result<AdminConfig, ConfigError> {
    let bind = get("ADMIN_BIND")
        .unwrap_or_default()
        .parse()
        .map_err(|_| ConfigError("ADMIN_BIND must be ip:port, e.g. 0.0.0.0:8081".into()))?;
    let need =
        |k: &str| get(k).ok_or_else(|| ConfigError(format!("{k} is required with ADMIN_BIND")));
    let user = need("ADMIN_USER")?;
    if user.chars().count() > 64 || user.chars().any(char::is_control) {
        return err("ADMIN_USER must be at most 64 characters without control characters");
    }
    // Quotes survive `docker run --env-file`; a PHC string never has them.
    let password_hash = need("ADMIN_PASSWORD_HASH")?
        .trim_matches(|c| c == '\'' || c == '"')
        .to_string();
    if !password_hash.starts_with("$argon2id$")
        || argon2::password_hash::PasswordHash::new(&password_hash).is_err()
    {
        return err(
            "ADMIN_PASSWORD_HASH must be an argon2id PHC string (metriccupid-push admin-setup)",
        );
    }
    let totp_secret = crate::admin::auth::base32_decode(&need("ADMIN_TOTP_SECRET")?)
        .filter(|s| s.len() >= 16)
        .ok_or_else(|| {
            ConfigError(
                "ADMIN_TOTP_SECRET must be base32 of at least 16 bytes (admin-setup)".into(),
            )
        })?;
    let allow_ips = match get("ADMIN_ALLOW_IPS") {
        Some(v) => parse_cidrs("ADMIN_ALLOW_IPS", &v)?,
        None => Vec::new(),
    };
    // `0.0.0.0/0` or `::/0` allows every address: it is allow-any, with the
    // same Cloudflare Access requirement and startup warning.
    let allow_any = parse_bool("ADMIN_ALLOW_ANY", get("ADMIN_ALLOW_ANY"), false)?
        || allow_ips.iter().any(|n| n.prefix_len() == 0);
    if allow_ips.is_empty() && !allow_any {
        return err("ADMIN_ALLOW_IPS is empty; set it (or ADMIN_ALLOW_ANY=true to allow every IP)");
    }
    let cf_access = parse_cf_access(get("ADMIN_CF_ACCESS_TEAM"), get("ADMIN_CF_ACCESS_AUD"))?;
    let allow_any_without_access = match get("ADMIN_ALLOW_ANY_WITHOUT_ACCESS") {
        None => None,
        v => Some(parse_bool("ADMIN_ALLOW_ANY_WITHOUT_ACCESS", v, false)?),
    };
    // Unset is tolerated for now (startup warning); an explicit `false`
    // refuses an open panel that has no Access check.
    if allow_any && cf_access.is_none() && allow_any_without_access == Some(false) {
        return err(
            "ADMIN_ALLOW_ANY=true needs ADMIN_CF_ACCESS_TEAM and ADMIN_CF_ACCESS_AUD \
             (or ADMIN_ALLOW_ANY_WITHOUT_ACCESS=true)",
        );
    }
    let hours = parse_nonzero("ADMIN_SESSION_HOURS", get("ADMIN_SESSION_HOURS"), 12)?.get();
    let days = parse_nonzero(
        "ADMIN_EVENTS_RETENTION_DAYS",
        get("ADMIN_EVENTS_RETENTION_DAYS"),
        30,
    )?
    .get();
    Ok(AdminConfig {
        bind,
        user,
        password_hash,
        totp_secret,
        allow_ips,
        allow_any,
        allow_any_without_access,
        cf_access,
        session_secs: u64::from(hours) * 3600,
        events_retention_days: u64::from(days),
    })
}

/// `ADMIN_CF_ACCESS_TEAM` (`j23` or `j23.cloudflareaccess.com`) and
/// `ADMIN_CF_ACCESS_AUD` (comma-separated AUD tags): both or neither.
fn parse_cf_access(
    team: Option<String>,
    aud: Option<String>,
) -> Result<Option<CfAccessConfig>, ConfigError> {
    let (team, aud) = match (team, aud) {
        (None, None) => return Ok(None),
        (Some(t), Some(a)) => (t, a),
        _ => return err("ADMIN_CF_ACCESS_TEAM and ADMIN_CF_ACCESS_AUD must be set together"),
    };
    let team = team.to_ascii_lowercase();
    let team = team
        .strip_prefix("https://")
        .unwrap_or(&team)
        .trim_end_matches('/');
    let ok_host = !team.is_empty()
        && team.len() <= 253
        && team.split('.').all(|l| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !ok_host {
        return err("ADMIN_CF_ACCESS_TEAM must be a team name (e.g. `j23`) or team domain");
    }
    let team_domain = if team.contains('.') {
        team.to_string()
    } else {
        format!("{team}.cloudflareaccess.com")
    };
    let auds: Vec<String> = aud
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if auds.is_empty()
        || auds
            .iter()
            .any(|a| a.len() > 256 || !a.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return err("ADMIN_CF_ACCESS_AUD must be one or more comma-separated AUD tags");
    }
    Ok(Some(CfAccessConfig { team_domain, auds }))
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

/// An upstream URL: `https://`, or `http://` only to a loopback host (local
/// tests and development). Plain HTTP elsewhere would expose auth keys,
/// licences and push contents on the network.
fn parse_url(var: &str, v: String) -> Result<String, ConfigError> {
    if v.starts_with("https://") {
        return Ok(v.trim_end_matches('/').to_string());
    }
    let Some(rest) = v.strip_prefix("http://") else {
        return err(format!("{var} must start with https://"));
    };
    if !is_loopback_authority(rest) {
        return err(format!(
            "{var} must use https:// (http:// is accepted only for 127.0.0.1, ::1 or localhost)"
        ));
    }
    Ok(v.trim_end_matches('/').to_string())
}

/// The host of `authority[/path]` is a loopback address or `localhost`.
fn is_loopback_authority(rest: &str) -> bool {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_prefix('[') {
        // [v6]:port
        Some(r) => r.split(']').next().unwrap_or(""),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
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
        licence_mode: parse_licence_mode(get, mode)?,
        licence_allow_sandbox: parse_bool(
            "LICENCE_ALLOW_SANDBOX",
            get("LICENCE_ALLOW_SANDBOX"),
            true,
        )?,
        licence_max_groups: parse_nonzero("LICENCE_MAX_GROUPS", get("LICENCE_MAX_GROUPS"), 3)?
            .get(),
        licence_grace_until: get("LICENCE_GRACE_UNTIL")
            .map(|v| {
                parse_rfc3339(&v).ok_or_else(|| {
                    ConfigError(
                        "LICENCE_GRACE_UNTIL must be an RFC 3339 time (2026-11-16T00:00:00Z) or a date (2026-11-16)".into(),
                    )
                })
            })
            .transpose()?,
        gateway_open: parse_bool("GATEWAY_OPEN", get("GATEWAY_OPEN"), false)?,
        gateway_require_licence: parse_bool(
            "GATEWAY_REQUIRE_LICENCE",
            get("GATEWAY_REQUIRE_LICENCE"),
            false,
        )?,
        gateway_activity_lines: parse_bool(
            "GATEWAY_ACTIVITY_LINES",
            get("GATEWAY_ACTIVITY_LINES"),
            false,
        )?,
        gateway_apns_sandbox: parse_bool(
            "GATEWAY_APNS_SANDBOX",
            get("GATEWAY_APNS_SANDBOX"),
            false,
        )?,
        gateway_sandbox_licences_count: parse_bool(
            "GATEWAY_SANDBOX_LICENCES_COUNT",
            get("GATEWAY_SANDBOX_LICENCES_COUNT"),
            true,
        )?,
        gateway_global: Rate {
            per_sec: parse_nonzero("GATEWAY_GLOBAL_PER_SEC", get("GATEWAY_GLOBAL_PER_SEC"), 20)?,
            burst: parse_nonzero("GATEWAY_GLOBAL_BURST", get("GATEWAY_GLOBAL_BURST"), 100)?,
        },
        gateway_group_hourly: HourlyRate {
            per_hour: parse_nonzero("GATEWAY_GROUP_PER_HOUR", get("GATEWAY_GROUP_PER_HOUR"), 600)?,
            burst: parse_nonzero("GATEWAY_GROUP_BURST", get("GATEWAY_GROUP_BURST"), 100)?,
        },
        gateway_max_tokens_per_group: parse_nonzero(
            "GATEWAY_MAX_TOKENS_PER_GROUP",
            get("GATEWAY_MAX_TOKENS_PER_GROUP"),
            30,
        )?
        .get(),
        gateway_max_groups: parse_nonzero("GATEWAY_MAX_GROUPS", get("GATEWAY_MAX_GROUPS"), 2000)?
            .get(),
        licence_revoked: RevokedTx(
            get("LICENCE_REVOKED_TX")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        ),
        rate_messages: parse_rate(get, "V2_MESSAGES", 2, 60)?,
        rate_commands: parse_rate(get, "V2_COMMANDS", 1, 20)?,
        rate_gateway: parse_rate(get, "V2_GATEWAY", 1, 30)?,
        rate_groups: HourlyRate {
            per_hour: parse_nonzero("RATE_V2_GROUPS_PER_HOUR", get("RATE_V2_GROUPS_PER_HOUR"), 6)?,
            burst: parse_nonzero("RATE_V2_GROUPS_BURST", get("RATE_V2_GROUPS_BURST"), 3)?,
        },
        rate_group: parse_rate(get, "GROUP", 5, 60)?,
        ws_ping: Duration::from_secs(
            parse_nonzero("WS_PING_SECS", get("WS_PING_SECS"), 30)?
                .get()
                .into(),
        ),
        ws_max_streams: parse_nonzero("WS_MAX_STREAMS", get("WS_MAX_STREAMS"), 1024)?.get(),
        ws_max_macs_per_group: parse_nonzero(
            "WS_MAX_MACS_PER_GROUP",
            get("WS_MAX_MACS_PER_GROUP"),
            3,
        )?
        .get(),
        ws_max_per_ip: parse_nonzero("WS_MAX_PER_IP", get("WS_MAX_PER_IP"), 20)?.get(),
        mac_offline_grace: parse_num("MAC_OFFLINE_GRACE_SECS", get("MAC_OFFLINE_GRACE_SECS"), 120)?,
        snapshot_max_bytes: parse_snapshot_max(get("V2_SNAPSHOT_MAX_BYTES"))?,
    })
}

/// `LICENCE_MODE`, with `HOSTED_OPEN_REGISTRATION=true` kept as an alias for
/// `open`. Self-hosted servers never require a licence.
fn parse_licence_mode(
    get: &impl Fn(&str) -> Option<String>,
    mode: Mode,
) -> Result<LicenceMode, ConfigError> {
    let open_alias = parse_bool(
        "HOSTED_OPEN_REGISTRATION",
        get("HOSTED_OPEN_REGISTRATION"),
        false,
    )?;
    let explicit = match get("LICENCE_MODE").as_deref() {
        None => None,
        Some("open") => Some(LicenceMode::Open),
        Some("app_transaction") => Some(LicenceMode::AppTransaction),
        Some(_) => return err("LICENCE_MODE must be `open` or `app_transaction`"),
    };
    match (mode, explicit) {
        (Mode::SelfHosted, Some(LicenceMode::AppTransaction)) => {
            err("LICENCE_MODE=app_transaction needs MODE=hosted")
        }
        (Mode::SelfHosted, _) => Ok(LicenceMode::Open),
        (Mode::Hosted, Some(LicenceMode::AppTransaction)) if open_alias => err(
            "HOSTED_OPEN_REGISTRATION=true contradicts LICENCE_MODE=app_transaction; remove one",
        ),
        (Mode::Hosted, Some(m)) => Ok(m),
        (Mode::Hosted, None) if open_alias => Ok(LicenceMode::Open),
        (Mode::Hosted, None) => Ok(LicenceMode::AppTransaction),
    }
}

/// Unix seconds of an RFC 3339 time, or of midnight UTC of a `YYYY-MM-DD` date.
pub fn parse_rfc3339(v: &str) -> Option<u64> {
    use time::format_description::well_known::Rfc3339;
    let t = match time::OffsetDateTime::parse(v, &Rfc3339) {
        Ok(t) => t,
        Err(_) => {
            let mut it = v.splitn(3, '-');
            let (y, m, d) = (it.next()?, it.next()?, it.next()?);
            if y.len() != 4 || m.len() != 2 || d.len() != 2 {
                return None;
            }
            let month = time::Month::try_from(m.parse::<u8>().ok()?).ok()?;
            time::Date::from_calendar_date(y.parse().ok()?, month, d.parse().ok()?)
                .ok()?
                .midnight()
                .assume_utc()
        }
    };
    u64::try_from(t.unix_timestamp()).ok()
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
    cf_extra_allow_subnet: Option<String>,
) -> Result<TrustProxy, ConfigError> {
    match mode {
        None | Some("none") => Ok(TrustProxy::None),
        Some("cloudflare") => {
            let extra = match cf_extra {
                Some(v) => parse_cidrs("CF_IPS_EXTRA", v)?,
                None => Vec::new(),
            };
            let allow_subnet =
                parse_bool("CF_IPS_EXTRA_ALLOW_SUBNET", cf_extra_allow_subnet, false)?;
            if !allow_subnet {
                if let Some(n) = extra.iter().find(|n| contains_bridge_gateway(n)) {
                    return err(format!(
                        "CF_IPS_EXTRA: `{n}` contains the Docker bridge gateway address; every \
                         host-published connection comes from it, so anyone could forge \
                         CF-Connecting-IP. Trust only the cloudflared container (a /32, e.g. \
                         172.30.53.20/32) or set CF_IPS_EXTRA_ALLOW_SUBNET=true"
                    ));
                }
            }
            Ok(TrustProxy::Cloudflare {
                refresh: parse_bool("CF_REFRESH", cf_refresh.map(str::to_string), false)?,
                extra,
            })
        }
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

/// `net` is outside Cloudflare's ranges.
fn outside_cloudflare(net: &IpNet) -> bool {
    !crate::client_ip::builtin_cloudflare_ranges()
        .iter()
        .any(|cf| cf.contains(net))
}

/// `net` (outside Cloudflare's ranges) contains the `.1` / `::1` address
/// Docker gives a bridge network's gateway: `x.y.z.1` of its network
/// address (IPv4) or the network address with the last 16 bits set to 1
/// (IPv6). Loopback is never a bridge gateway (cloudflared on the host).
fn contains_bridge_gateway(net: &IpNet) -> bool {
    let gw: std::net::IpAddr = match net {
        IpNet::V4(n) => (u32::from(n.network()) & !0xff | 1).to_be_bytes().into(),
        IpNet::V6(n) => (u128::from(n.network()) & !0xffff | 1).to_be_bytes().into(),
    };
    !gw.is_loopback() && outside_cloudflare(net) && net.contains(&gw)
}

/// Startup warnings for `CF_IPS_EXTRA` entries broader than one container
/// (IPv4 shorter than /29, IPv6 shorter than /125) outside Cloudflare.
pub fn cf_extra_warnings(tp: &TrustProxy) -> Vec<String> {
    let TrustProxy::Cloudflare { extra, .. } = tp else {
        return Vec::new();
    };
    extra
        .iter()
        .filter(|n| {
            let broad = match n {
                IpNet::V4(v) => v.prefix_len() < 29,
                IpNet::V6(v) => v.prefix_len() < 125,
            };
            broad && outside_cloudflare(n)
        })
        .map(|n| {
            format!(
                "CF_IPS_EXTRA: `{n}` is a whole subnet outside Cloudflare; every address in it \
                 may set CF-Connecting-IP. Prefer the cloudflared container's /32"
            )
        })
        .collect()
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

/// `V2_SNAPSHOT_MAX_BYTES`: 1 KB ..= 1 MB, default 192 KB.
fn parse_snapshot_max(v: Option<String>) -> Result<usize, ConfigError> {
    let n: usize = parse_num("V2_SNAPSHOT_MAX_BYTES", v, 192 * 1024)?;
    if !(1024..=1024 * 1024).contains(&n) {
        return err("V2_SNAPSHOT_MAX_BYTES must be between 1024 and 1048576");
    }
    Ok(n)
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
        assert_eq!(c.v2.licence_mode, LicenceMode::Open);
        assert!(c.v2.licence_allow_sandbox);
        assert_eq!(c.v2.licence_max_groups, 3);
        assert_eq!(c.v2.licence_grace_until, None);
        assert_eq!(c.v2.rate_messages.per_sec.get(), 2);
        assert_eq!(c.v2.rate_messages.burst.get(), 60);
        assert_eq!(c.v2.rate_commands.burst.get(), 20);
        assert_eq!(c.v2.ws_ping, Duration::from_secs(30));
        assert_eq!(c.v2.mac_offline_grace, 120);
        assert_eq!(c.v2.snapshot_max_bytes, 192 * 1024);
    }

    #[test]
    fn v2_snapshot_max() {
        let c = cfg(&[("V2_SNAPSHOT_MAX_BYTES", "65536")]).unwrap();
        assert_eq!(c.v2.snapshot_max_bytes, 65536);
        assert!(cfg(&[("V2_SNAPSHOT_MAX_BYTES", "10")]).is_err());
        assert!(cfg(&[("V2_SNAPSHOT_MAX_BYTES", "99999999")]).is_err());
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
    fn licence_mode_and_alias() {
        let hosted = |pairs: &[(&str, &str)]| {
            let mut m: HashMap<String, String> = HashMap::from([
                ("MODE".into(), "hosted".into()),
                ("APNS_MODE".into(), "mock".into()),
            ]);
            for (k, v) in pairs {
                m.insert(k.to_string(), v.to_string());
            }
            Config::from_lookup(|k| m.get(k).cloned()).map(|c| c.v2)
        };
        assert_eq!(
            hosted(&[]).unwrap().licence_mode,
            LicenceMode::AppTransaction
        );
        assert_eq!(
            hosted(&[("HOSTED_OPEN_REGISTRATION", "true")])
                .unwrap()
                .licence_mode,
            LicenceMode::Open
        );
        assert_eq!(
            hosted(&[("LICENCE_MODE", "open")]).unwrap().licence_mode,
            LicenceMode::Open
        );
        assert!(hosted(&[
            ("LICENCE_MODE", "app_transaction"),
            ("HOSTED_OPEN_REGISTRATION", "true")
        ])
        .is_err());
        assert!(hosted(&[("LICENCE_MODE", "paid")]).is_err());
        assert!(cfg(&[("LICENCE_MODE", "app_transaction")]).is_err());
        let v = hosted(&[
            ("LICENCE_GRACE_UNTIL", "2026-11-16"),
            ("LICENCE_ALLOW_SANDBOX", "false"),
            ("LICENCE_MAX_GROUPS", "5"),
        ])
        .unwrap();
        assert_eq!(v.licence_grace_until, Some(1_794_787_200));
        assert!(!v.licence_allow_sandbox);
        assert_eq!(v.licence_max_groups, 5);
        assert_eq!(
            hosted(&[("LICENCE_GRACE_UNTIL", "2026-11-16T12:00:00+01:00")])
                .unwrap()
                .licence_grace_until,
            Some(1_794_787_200 + 11 * 3600)
        );
        assert!(hosted(&[("LICENCE_GRACE_UNTIL", "next week")]).is_err());
        assert!(hosted(&[("LICENCE_MAX_GROUPS", "0")]).is_err());
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
            ("CF_IPS_EXTRA", "2001:db8::20/128"),
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
    fn cf_ips_extra_bridge_subnet_is_refused_unless_allowed() {
        let cf = |extra: &str, allow: Option<&str>| {
            let mut p = vec![("TRUST_PROXY", "cloudflare"), ("CF_IPS_EXTRA", extra)];
            if let Some(a) = allow {
                p.push(("CF_IPS_EXTRA_ALLOW_SUBNET", a));
            }
            cfg(&p)
        };
        // The whole compose network contains its gateway .1: refused.
        for bad in [
            "172.31.250.0/24",
            "172.30.0.0/16",
            "172.30.53.1",
            "fd00:1::/64",
        ] {
            let e = cf(bad, None).unwrap_err();
            assert!(e.0.contains("CF_IPS_EXTRA_ALLOW_SUBNET"), "{bad}: {e}");
        }
        // Explicit opt-in keeps the old behaviour, with a warning.
        let c = cf("172.31.250.0/24", Some("true")).unwrap();
        assert_eq!(cf_extra_warnings(&c.trust_proxy).len(), 1);
        assert!(cf("172.31.250.0/24", Some("maybe")).is_err());
        // One container: accepted, no warning.
        let c = cf("172.31.250.20/32", None).unwrap();
        assert!(cf_extra_warnings(&c.trust_proxy).is_empty());
        // A subnet without the gateway: accepted, but warned about.
        let c = cf("172.31.250.16/28", None).unwrap();
        assert_eq!(cf_extra_warnings(&c.trust_proxy).len(), 1);
        // Cloudflare's own ranges are never refused or warned about.
        let c = cf("162.158.0.0/16", None).unwrap();
        assert!(cf_extra_warnings(&c.trust_proxy).is_empty());
        // cloudflared on the same host (no Docker bridge): accepted.
        assert!(cf("127.0.0.1", None).is_ok());
        assert!(cf("::1", None).is_ok());
        assert!(cf_extra_warnings(&TrustProxy::None).is_empty());
    }

    #[test]
    fn gateway_settings() {
        let v = cfg(&[]).unwrap().v2;
        assert!(!v.gateway_open);
        assert!(!v.gateway_require_licence);
        assert!(!v.gateway_activity_lines);
        assert!(!v.gateway_apns_sandbox);
        assert!(v.gateway_sandbox_licences_count);
        assert!(
            !cfg(&[("GATEWAY_SANDBOX_LICENCES_COUNT", "false")])
                .unwrap()
                .v2
                .gateway_sandbox_licences_count
        );
        assert_eq!(
            (v.gateway_global.per_sec.get(), v.gateway_global.burst.get()),
            (20, 100)
        );
        assert_eq!(
            (
                v.gateway_group_hourly.per_hour.get(),
                v.gateway_group_hourly.burst.get()
            ),
            (600, 100)
        );
        assert_eq!(
            (v.rate_gateway.per_sec.get(), v.rate_gateway.burst.get()),
            (1, 30)
        );
        assert_eq!(v.gateway_max_tokens_per_group, 30);
        assert_eq!(v.gateway_max_groups, 2000);
        assert!(v.licence_revoked.0.is_empty());
        let v = cfg(&[
            ("GATEWAY_REQUIRE_LICENCE", "true"),
            ("GATEWAY_ACTIVITY_LINES", "true"),
            ("GATEWAY_APNS_SANDBOX", "true"),
            ("GATEWAY_MAX_GROUPS", "5"),
            ("LICENCE_REVOKED_TX", " secret-tx-1 , secret-tx-2 ,"),
        ])
        .unwrap()
        .v2;
        assert!(v.gateway_require_licence && v.gateway_activity_lines && v.gateway_apns_sandbox);
        assert_eq!(v.gateway_max_groups, 5);
        assert_eq!(v.licence_revoked.0.len(), 2);
        assert!(v.licence_revoked.0.contains("secret-tx-2"));
        assert!(
            !format!("{v:?}").contains("secret-tx"),
            "revoked ids are never printed"
        );
        assert!(cfg(&[("GATEWAY_MAX_TOKENS_PER_GROUP", "0")]).is_err());
        assert!(cfg(&[("GATEWAY_REQUIRE_LICENCE", "maybe")]).is_err());
    }

    #[test]
    fn phase1_limits_defaults_and_overrides() {
        let c = cfg(&[]).unwrap();
        assert_eq!(
            (
                c.limits.anon_global.per_sec.get(),
                c.limits.anon_global.burst.get()
            ),
            (20, 60)
        );
        assert_eq!(
            (c.v2.rate_group.per_sec.get(), c.v2.rate_group.burst.get()),
            (5, 60)
        );
        assert_eq!(c.limits.abuse, crate::limits::AbuseRule::default());
        assert_eq!(
            (
                c.limits.abuse.threshold,
                c.limits.abuse.window,
                c.limits.abuse.duration
            ),
            (100, 60, 300)
        );
        assert_eq!(
            (
                c.limits.pre_auth.per_sec.get(),
                c.limits.pre_auth.burst.get()
            ),
            (200, 400)
        );
        assert_eq!(c.max_connections_per_ip, 64);
        assert_eq!(c.header_read_timeout, Duration::from_secs(10));
        assert_eq!(c.limits.replay_cap, 100_000);
        assert_eq!(c.max_connections, 8192);
        assert_eq!(
            (
                c.v2.ws_max_streams,
                c.v2.ws_max_macs_per_group,
                c.v2.ws_max_per_ip
            ),
            (1024, 3, 20)
        );
        let c = cfg(&[
            ("RATE_ANON_GLOBAL_PER_SEC", "7"),
            ("RATE_GROUP_BURST", "11"),
            ("AUTH_ABUSE_THRESHOLD", "5"),
            ("AUTH_ABUSE_WINDOW_SECS", "30"),
            ("AUTH_ABUSE_BAN_SECS", "60"),
            ("REPLAY_CAP", "500"),
            ("MAX_CONNECTIONS", "64"),
            ("WS_MAX_STREAMS", "6000"),
            ("WS_MAX_MACS_PER_GROUP", "4"),
            ("WS_MAX_PER_IP", "50"),
        ])
        .unwrap();
        assert_eq!(c.limits.anon_global.per_sec.get(), 7);
        assert_eq!(c.v2.rate_group.burst.get(), 11);
        assert_eq!(
            c.limits.abuse,
            crate::limits::AbuseRule {
                threshold: 5,
                window: 30,
                duration: 60
            }
        );
        assert_eq!((c.limits.replay_cap, c.max_connections), (500, 64));
        assert_eq!(
            (
                c.v2.ws_max_streams,
                c.v2.ws_max_macs_per_group,
                c.v2.ws_max_per_ip
            ),
            (6000, 4, 50)
        );
        for zero in [
            "WS_MAX_STREAMS",
            "WS_MAX_MACS_PER_GROUP",
            "WS_MAX_PER_IP",
            "MAX_CONNECTIONS",
            "REPLAY_CAP",
            "AUTH_ABUSE_THRESHOLD",
            "RATE_GROUP_PER_SEC",
            "RATE_PRE_AUTH_BURST",
            "MAX_CONNECTIONS_PER_IP",
            "HEADER_READ_TIMEOUT_SECS",
        ] {
            assert!(cfg(&[(zero, "0")]).is_err(), "{zero}");
        }
    }

    #[test]
    fn upstream_urls_need_https_except_loopback() {
        for ok in [
            "https://gw.example",
            "http://127.0.0.1:9999",
            "http://127.0.0.5",
            "http://[::1]:8080/x",
            "http://localhost:1234",
        ] {
            assert!(cfg(&[("GATEWAY_URL", ok)]).is_ok(), "{ok}");
        }
        for bad in [
            "http://gw.example",
            "http://10.0.0.1",
            "http://127.0.0.1.example.com",
            "http://user@127.0.0.1:1",
            "http://localhost.evil",
            "ftp://x",
        ] {
            assert!(cfg(&[("GATEWAY_URL", bad)]).is_err(), "{bad}");
            assert!(cfg(&[("APNS_PRODUCTION_URL", bad)]).is_err(), "{bad}");
            assert!(cfg(&[("APNS_SANDBOX_URL", bad)]).is_err(), "{bad}");
            assert!(cfg(&[("PUSHOVER_API_URL", bad)]).is_err(), "{bad}");
        }
        let c = cfg(&[("PUSHOVER_API_URL", "http://127.0.0.1:1/1/messages.json/")]).unwrap();
        assert_eq!(
            c.pushover_api_url, "http://127.0.0.1:1/1/messages.json/",
            "kept as is"
        );
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

    const PHC: &str = "$argon2id$v=19$m=8,t=1,p=1$BwcHBwcHBwcHBwcHBwcHBw$9t2Q7m2G2Jx1d2c8Uq2m0mJ8l2m3Yk1pZ7c2wq3cXxU";

    fn admin(pairs: &[(&str, &str)]) -> AdminSetting {
        let mut all = vec![
            ("ADMIN_BIND", "127.0.0.1:8081"),
            ("ADMIN_USER", "admin"),
            ("ADMIN_PASSWORD_HASH", PHC),
            ("ADMIN_TOTP_SECRET", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        ];
        all.extend_from_slice(pairs);
        cfg(&all).unwrap().admin
    }

    #[test]
    fn admin_settings() {
        assert!(matches!(cfg(&[]).unwrap().admin, AdminSetting::Off));
        // No allowlist: refused (fail closed), the public API still starts.
        assert!(
            matches!(admin(&[]), AdminSetting::Refused(ref e) if e.contains("ADMIN_ALLOW_IPS"))
        );
        let AdminSetting::On(a) = admin(&[("ADMIN_ALLOW_IPS", "127.0.0.1/32, 2001:db8::/48")])
        else {
            panic!("expected On");
        };
        assert_eq!(a.allow_ips.len(), 2);
        assert_eq!(a.session_secs, 12 * 3600);
        assert_eq!(a.events_retention_days, 30);
        assert_eq!(a.totp_secret, b"12345678901234567890");
        assert!(!format!("{a:?}").contains("argon2id"), "hash redacted");
        assert!(matches!(
            admin(&[("ADMIN_ALLOW_ANY", "true")]),
            AdminSetting::On(ref a) if a.allow_any && a.allow_ips.is_empty()
        ));
        // Quoted hash (docker run --env-file keeps quotes).
        let quoted = format!("'{PHC}'");
        assert!(matches!(
            admin(&[("ADMIN_ALLOW_ANY", "true"), ("ADMIN_PASSWORD_HASH", &quoted)]),
            AdminSetting::On(ref a) if a.password_hash == PHC
        ));
        for bad in [
            ("ADMIN_PASSWORD_HASH", "plaintext"),
            ("ADMIN_TOTP_SECRET", "not base32!"),
            ("ADMIN_TOTP_SECRET", "GEZDGNBV"),
            ("ADMIN_ALLOW_IPS", "nonsense"),
            ("ADMIN_SESSION_HOURS", "0"),
            ("ADMIN_BIND", "8081"),
        ] {
            assert!(
                matches!(
                    admin(&[("ADMIN_ALLOW_ANY", "true"), bad]),
                    AdminSetting::Refused(_)
                ),
                "{bad:?}"
            );
        }
        // ADMIN_ALLOW_ANY without Access: started (warning) unless explicitly refused.
        assert!(matches!(
            admin(&[("ADMIN_ALLOW_ANY", "true"), ("ADMIN_ALLOW_ANY_WITHOUT_ACCESS", "true")]),
            AdminSetting::On(ref a) if a.allow_any_without_access == Some(true)
        ));
        assert!(matches!(
            admin(&[("ADMIN_ALLOW_ANY", "true"), ("ADMIN_ALLOW_ANY_WITHOUT_ACCESS", "false")]),
            AdminSetting::Refused(ref e) if e.contains("ADMIN_CF_ACCESS_TEAM")
        ));
        const AUD: &str = "1a7f85adede665228b2c7b9f5067d974c7358fe920ea774d63c115716a041b6f";
        for team in [
            "j23",
            "J23.cloudflareaccess.com",
            "https://j23.cloudflareaccess.com/",
        ] {
            let AdminSetting::On(a) = admin(&[
                ("ADMIN_ALLOW_ANY", "true"),
                ("ADMIN_ALLOW_ANY_WITHOUT_ACCESS", "false"),
                ("ADMIN_CF_ACCESS_TEAM", team),
                ("ADMIN_CF_ACCESS_AUD", &format!(" {AUD} , other1 ")),
            ]) else {
                panic!("expected On for {team}");
            };
            let c = a.cf_access.unwrap();
            assert_eq!(c.team_domain, "j23.cloudflareaccess.com");
            assert_eq!(c.issuer(), "https://j23.cloudflareaccess.com");
            assert_eq!(
                c.certs_url(),
                "https://j23.cloudflareaccess.com/cdn-cgi/access/certs"
            );
            assert_eq!(c.auds, vec![AUD.to_string(), "other1".to_string()]);
        }
        for bad in [
            vec![("ADMIN_CF_ACCESS_TEAM", "j23")],
            vec![("ADMIN_CF_ACCESS_AUD", AUD)],
            vec![
                ("ADMIN_CF_ACCESS_TEAM", "j23/x"),
                ("ADMIN_CF_ACCESS_AUD", AUD),
            ],
            vec![
                ("ADMIN_CF_ACCESS_TEAM", "j23"),
                ("ADMIN_CF_ACCESS_AUD", ","),
            ],
            vec![
                ("ADMIN_CF_ACCESS_TEAM", "j23"),
                ("ADMIN_CF_ACCESS_AUD", "a b"),
            ],
            vec![("ADMIN_ALLOW_ANY_WITHOUT_ACCESS", "maybe")],
        ] {
            let mut pairs = vec![("ADMIN_ALLOW_ANY", "true")];
            pairs.extend(bad.iter().copied());
            assert!(matches!(admin(&pairs), AdminSetting::Refused(_)), "{bad:?}");
        }
        // An all-addresses allowlist is allow-any: same Access rules.
        for all in ["0.0.0.0/0", "::/0", "10.0.0.0/8, 0.0.0.0/0"] {
            assert!(
                matches!(
                    admin(&[("ADMIN_ALLOW_IPS", all)]),
                    AdminSetting::On(ref a) if a.allow_any
                ),
                "{all}"
            );
            assert!(
                matches!(
                    admin(&[("ADMIN_ALLOW_IPS", all), ("ADMIN_ALLOW_ANY_WITHOUT_ACCESS", "false")]),
                    AdminSetting::Refused(ref e) if e.contains("ADMIN_CF_ACCESS_TEAM")
                ),
                "{all}"
            );
        }
        assert!(matches!(
            admin(&[("ADMIN_ALLOW_IPS", "10.0.0.0/8"), ("ADMIN_ALLOW_ANY_WITHOUT_ACCESS", "false")]),
            AdminSetting::On(ref a) if !a.allow_any
        ));
        let mut no_user = cfg(&[("ADMIN_BIND", "127.0.0.1:8081")]).unwrap().admin;
        assert!(matches!(no_user, AdminSetting::Refused(ref e) if e.contains("ADMIN_USER")));
        no_user = AdminSetting::Off;
        assert!(no_user.config().is_none());
    }

    #[test]
    fn debug_redacts() {
        let s = format!("{:?}", cfg(&[]).unwrap());
        assert!(!s.contains(SECRET));
        assert!(!s.contains("apptoken123"));
        assert!(!s.contains("userkey123"));
    }
}
