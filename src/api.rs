//! HTTP API: `POST /v1/notify`, the v2 routes (see `v2`), `GET /healthz`,
//! everything else 404.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tower::limit::ConcurrencyLimitLayer;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::auth::Authenticator;
use crate::client_ip::ClientIpResolver;
use crate::config::{ApnsMode, Config, Mode};
use crate::limits::{ip_key, AuthBans, Clock, ExpiringSet, RateLimits, RetryAfter, V2Limits};
use crate::metrics::{self, ApiTag, Event, MeteredSender, Metrics};
use crate::pushover::{Message, PushoverClient, SendError};
use crate::v2::apns::{ApnsSender, DirectApns, GatewayApns, MockApns};
use crate::v2::licence::{AppTransactionVerifier, LicencePolicy};
use crate::v2::store::{self, Store};
use crate::v2::stream::Hub;
use crate::v2::{self as v2, V2State};

pub const NOTIFY_PATH: &str = "/v1/notify";
pub const MAX_BODY_BYTES: usize = 8 * 1024;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_CONCURRENCY: usize = 64;
const DEDUP_CAP: usize = 10_000;

/// A finished response plus a short outcome label for the log line.
pub type Outcome = (Response, &'static str);

pub struct AppState {
    mode: Mode,
    v1_enabled: bool,
    allow_emergency: bool,
    quota_reserve: u64,
    resolver: ClientIpResolver,
    auth: Authenticator,
    limits: RateLimits,
    bans: AuthBans,
    dedup: Mutex<ExpiringSet<(usize, String)>>,
    pushover: PushoverClient,
    clock: Arc<dyn Clock>,
    v2: V2State,
    metrics: Arc<Metrics>,
}

impl AppState {
    pub fn new(
        config: &Config,
        resolver: ClientIpResolver,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, String> {
        let pushover = PushoverClient::new(
            config.pushover_api_url.clone(),
            config.pushover_app_token.clone(),
            config.pushover_user_key.clone(),
        )
        .map_err(|e| format!("cannot build HTTP client: {e}"))?;
        let l = &config.limits;
        // Metrics are only collected while the admin panel is enabled.
        let metrics = Arc::new(Metrics::new(
            config.admin.config().is_some(),
            config
                .admin
                .config()
                .map_or(30, |a| a.events_retention_days),
            clock.clone(),
        ));
        let v2 = build_v2(config, clock.clone(), metrics.clone())?;
        Ok(Self {
            mode: config.mode,
            v1_enabled: config.v1_enabled,
            allow_emergency: config.allow_emergency,
            quota_reserve: config.quota_reserve,
            resolver,
            auth: Authenticator::new(config.secrets.clone()),
            limits: RateLimits::new(l, config.secrets.len()),
            bans: AuthBans::new(l.ban_threshold, l.ban_window, l.ban_duration),
            dedup: Mutex::new(ExpiringSet::new(config.dedup_window, DEDUP_CAP)),
            pushover,
            clock,
            v2,
            metrics,
        })
    }

    /// Like `new`, but App Store licences are checked against `licence_root`
    /// (DER) instead of Apple Root CA - G3. For tests, which cannot get
    /// Apple-signed transactions.
    pub fn new_with_licence_root(
        config: &Config,
        resolver: ClientIpResolver,
        clock: Arc<dyn Clock>,
        licence_root: Vec<u8>,
    ) -> Result<Self, String> {
        let mut s = Self::new(config, resolver, clock.clone())?;
        s.v2.licence.verifier =
            AppTransactionVerifier::with_root(licence_root, config.v2.licence_allow_sandbox);
        Ok(s)
    }

    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn v2(&self) -> &V2State {
        &self.v2
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Cloudflare's `CF-IPCountry`, only from a trusted proxy.
    pub fn client_country(&self, peer: SocketAddr, headers: &HeaderMap) -> Option<String> {
        self.resolver.country(peer.ip(), headers)
    }

    pub fn auth(&self) -> &Authenticator {
        &self.auth
    }

    /// The in-memory APNs recorder when `APNS_MODE=mock`.
    pub fn mock_apns(&self) -> Option<Arc<MockApns>> {
        self.v2.mock.clone()
    }

    pub fn client_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        self.resolver.resolve(peer.ip(), headers)
    }

    /// Record an auth failure for `ip` and build the generic 401.
    pub fn auth_failed(&self, ip: IpAddr, now: u64, reason: &str) -> Outcome {
        if self.bans.record_failure(ip_key(ip), now) {
            tracing::warn!(client_ip = %ip, "auth failure threshold reached, IP banned");
            self.metrics.record(Event::new("ban").ip(ip).detail(reason));
        }
        tracing::debug!(client_ip = %ip, reason, "auth failed");
        // Generic body: do not tell the client which check failed.
        (
            error(StatusCode::UNAUTHORIZED, "unauthorized"),
            "unauthorized",
        )
    }

    /// Delete expired v2 messages and commands.
    pub async fn cleanup_storage(&self) {
        let now = self.clock.now();
        match self.v2.store.call(move |c| store::cleanup(c, now)).await {
            Ok((m, c)) if m + c > 0 => {
                tracing::debug!(messages = m, commands = c, "retention cleanup")
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "retention cleanup failed"),
        }
    }

    /// Periodic housekeeping: drop expired entries so every map stays bounded.
    pub fn cleanup(&self) {
        let now = self.clock.now();
        self.limits.cleanup();
        self.v2.limits.cleanup();
        self.bans.cleanup(now);
        self.auth.cleanup(now);
        self.dedup
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .purge(now);
    }
}

fn build_v2(
    config: &Config,
    clock: Arc<dyn Clock>,
    metrics: Arc<Metrics>,
) -> Result<V2State, String> {
    let c = &config.v2;
    let store = Store::open(&c.data_dir).map_err(|e| format!("DATA_DIR: {e}"))?;
    let mut mock = None;
    let mut gateway = None;
    let sender: Arc<dyn ApnsSender> = match c.apns_mode {
        ApnsMode::Direct => {
            let key = c
                .apns_key
                .as_ref()
                .ok_or("APNS_MODE=direct needs APNS_KEY_P8")?;
            Arc::new(DirectApns::new(
                key,
                c.apns_topic.clone(),
                c.apns_production_url.clone(),
                c.apns_sandbox_url.clone(),
                clock.clone(),
            )?)
        }
        ApnsMode::Mock => {
            let m = Arc::new(MockApns::new());
            mock = Some(m.clone());
            m
        }
        ApnsMode::Gateway => {
            let g = Arc::new(GatewayApns::new(c.gateway_url.clone(), clock.clone())?);
            gateway = Some(g.clone());
            g
        }
    };
    let sender: Arc<dyn ApnsSender> = Arc::new(MeteredSender {
        inner: sender,
        metrics,
        via: match c.apns_mode {
            ApnsMode::Direct => "direct",
            ApnsMode::Mock => "mock",
            ApnsMode::Gateway => "gateway",
        },
    });
    Ok(V2State {
        store,
        hub: Hub::new(),
        limits: V2Limits::new(c),
        sender,
        mock,
        gateway,
        licence: LicencePolicy {
            mode: c.licence_mode,
            verifier: AppTransactionVerifier::apple(c.licence_allow_sandbox),
            max_groups: c.licence_max_groups,
            grace_until: c.licence_grace_until,
            gateway_open: c.gateway_open,
        },
        ws_ping: c.ws_ping,
        presence: v2::presence::Presence::new(c.mac_offline_grace),
        activities: v2::activity::Activities::new(),
        snapshot_max: c.snapshot_max_bytes,
    })
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            NOTIFY_PATH,
            post(notify)
                .fallback(not_found)
                .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES)),
        )
        .route("/healthz", get(healthz).fallback(not_found))
        .merge(v2::routes(state.mode, state.v2.mock.is_some()))
        .layer(RequestBodyLimitLayer::new(v2::MAX_BODY_BYTES))
        // Only the snapshot route takes bodies above 16 KB.
        .merge(
            v2::snapshot_routes().layer(RequestBodyLimitLayer::new(v2::snapshot_body_limit(
                state.v2.snapshot_max,
            ))),
        )
        .fallback(not_found)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    metrics::track,
                ))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    REQUEST_TIMEOUT,
                ))
                .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENCY)),
        )
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "not_found")
}

pub(crate) fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

pub(crate) fn invalid(detail: impl Into<String>) -> Response {
    let detail: String = detail.into();
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_request", "detail": detail })),
    )
        .into_response()
}

pub(crate) fn too_many(RetryAfter(secs): RetryAfter) -> Response {
    let mut r = error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
        r.headers_mut().insert(header::RETRY_AFTER, v);
    }
    r
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyRequest {
    #[serde(default)]
    pub title: Option<String>,
    pub message: String,
    #[serde(default)]
    pub priority: i64,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub url_title: Option<String>,
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub sound: Option<String>,
    #[serde(default)]
    pub dedup_key: Option<String>,
}

fn max_chars(field: &str, v: &Option<String>, max: usize) -> Result<(), String> {
    match v {
        Some(s) if s.chars().count() > max => Err(format!("{field} longer than {max} characters")),
        Some(s) if s.is_empty() => Err(format!("{field} must not be empty")),
        _ => Ok(()),
    }
}

fn token_chars(field: &str, v: &Option<String>) -> Result<(), String> {
    match v {
        Some(s)
            if !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
        {
            Err(format!("{field} may contain only A-Z, a-z, 0-9, _ and -"))
        }
        _ => Ok(()),
    }
}

impl NotifyRequest {
    /// Validate and convert; the error string is safe to return to the client.
    pub fn validate(self) -> Result<(Message, Option<String>), String> {
        if self.message.trim().is_empty() {
            return Err("message is required".into());
        }
        max_chars("message", &Some(self.message.clone()), 1024)?;
        max_chars("title", &self.title, 250)?;
        if !(-2..=2).contains(&self.priority) {
            return Err("priority must be between -2 and 2".into());
        }
        max_chars("url", &self.url, 512)?;
        if let Some(u) = &self.url {
            let ok = reqwest::Url::parse(u)
                .map(|p| matches!(p.scheme(), "http" | "https") && p.has_host())
                .unwrap_or(false);
            if !ok {
                return Err("url must be an absolute http(s) URL".into());
            }
        }
        max_chars("url_title", &self.url_title, 100)?;
        max_chars("device", &self.device, 25)?;
        token_chars("device", &self.device)?;
        max_chars("sound", &self.sound, 32)?;
        token_chars("sound", &self.sound)?;
        max_chars("dedup_key", &self.dedup_key, 128)?;
        Ok((
            Message {
                title: self.title,
                message: self.message,
                priority: self.priority as i8,
                url: self.url,
                url_title: self.url_title,
                device: self.device,
                sound: self.sound,
            },
            self.dedup_key,
        ))
    }
}

async fn notify(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.resolver.resolve(peer.ip(), &headers);
    let (mut response, outcome) = handle_notify(&state, ip, &headers, &body).await;
    response.extensions_mut().insert(ApiTag {
        route: "notify",
        outcome,
        group: None,
    });
    // Never log secrets, tokens, user keys or message contents.
    tracing::info!(
        client_ip = %ip,
        status = response.status().as_u16(),
        outcome,
        latency_ms = started.elapsed().as_millis() as u64,
        "notify"
    );
    response
}

async fn handle_notify(
    state: &AppState,
    ip: IpAddr,
    headers: &HeaderMap,
    body: &[u8],
) -> (Response, &'static str) {
    if state.mode == Mode::Hosted {
        return (
            error(StatusCode::NOT_IMPLEMENTED, "hosted mode not available yet"),
            "hosted_unavailable",
        );
    }
    if !state.v1_enabled {
        return (error(StatusCode::NOT_FOUND, "not_found"), "v1_disabled");
    }

    let now = state.clock.now();
    if let Err(o) = precheck(state, ip, now) {
        return o;
    }

    let secret = match state.auth.verify(now, "POST", NOTIFY_PATH, headers, body) {
        Ok(i) => i,
        Err(e) => return state.auth_failed(ip, now, e.as_str()),
    };

    if let Err(ra) = state.limits.check_secret(secret) {
        return (too_many(ra), "rate_limited_secret");
    }

    let req: NotifyRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return (invalid(json_error(&e)), "invalid_json"),
    };
    let (message, dedup_key) = match req.validate() {
        Ok(v) => v,
        Err(e) => return (invalid(e), "invalid_request"),
    };

    if message.priority == 2 && !state.allow_emergency {
        return (
            error(StatusCode::FORBIDDEN, "emergency_not_allowed"),
            "emergency_denied",
        );
    }

    if message.priority < 1 {
        if let Some(remaining) = state.pushover.quota_remaining() {
            if remaining < state.quota_reserve {
                return (
                    error(StatusCode::SERVICE_UNAVAILABLE, "quota_reserve"),
                    "quota_guard",
                );
            }
        }
    }

    let dedup_entry = dedup_key.map(|k| (secret, k));
    if let Some(entry) = &dedup_entry {
        let mut dedup = state.dedup.lock().unwrap_or_else(|e| e.into_inner());
        if !dedup.insert_if_absent(entry.clone(), now) {
            return (
                (StatusCode::OK, Json(json!({ "status": "deduplicated" }))).into_response(),
                "deduplicated",
            );
        }
    }

    match state.pushover.send(&message).await {
        Ok(()) => (
            (StatusCode::OK, Json(json!({ "status": "sent" }))).into_response(),
            "sent",
        ),
        Err(e) => {
            // Let the client retry a failed send with the same dedup_key.
            if let Some(entry) = &dedup_entry {
                state
                    .dedup
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(entry);
            }
            match e {
                SendError::Transport => tracing::warn!("pushover request failed (transport)"),
                SendError::Upstream(code) => {
                    tracing::warn!(upstream_status = code, "pushover rejected request")
                }
            }
            (
                error(StatusCode::BAD_GATEWAY, "upstream_error"),
                "upstream_error",
            )
        }
    }
}

/// Ban, per-IP and global checks, done before any authentication work.
// The error is the finished HTTP response; it is only built on the cold path.
#[allow(clippy::result_large_err)]
pub(crate) fn precheck(state: &AppState, ip: IpAddr, now: u64) -> Result<(), Outcome> {
    let key = ip_key(ip);
    if let Some(secs) = state.bans.banned_for(key, now) {
        return Err((too_many(RetryAfter(secs)), "banned"));
    }
    if let Err(ra) = state.limits.check_ip(key) {
        return Err((too_many(ra), "rate_limited_ip"));
    }
    if let Err(ra) = state.limits.check_global() {
        return Err((too_many(ra), "rate_limited_global"));
    }
    Ok(())
}

/// Describe a JSON error without echoing request contents.
pub(crate) fn json_error(e: &serde_json::Error) -> String {
    let msg = e.to_string();
    // serde messages for unknown/missing fields name the field, which is fine;
    // strip the " at line X column Y" suffix.
    match msg.find(" at line ") {
        Some(i) => msg[..i].to_string(),
        None => msg,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(json: &str) -> Result<(Message, Option<String>), String> {
        serde_json::from_str::<NotifyRequest>(json)
            .map_err(|e| e.to_string())?
            .validate()
    }

    #[test]
    fn minimal_valid() {
        let (m, d) = req(r#"{"message":"m"}"#).unwrap();
        assert_eq!(m.priority, 0);
        assert_eq!(m.title, None);
        assert_eq!(d, None);
    }

    #[test]
    fn full_valid() {
        let (m, d) = req(
            r#"{"title":"t","message":"m","priority":2,"url":"https://x.example/a","url_title":"u",
            "device":"my-phone_1","sound":"siren","dedup_key":"host/check"}"#,
        )
        .unwrap();
        assert_eq!(m.priority, 2);
        assert_eq!(m.device.as_deref(), Some("my-phone_1"));
        assert_eq!(d.as_deref(), Some("host/check"));
    }

    #[test]
    fn unknown_field_rejected() {
        let e = req(r#"{"message":"m","token":"x"}"#).unwrap_err();
        assert!(e.contains("unknown field"), "{e}");
    }

    #[test]
    fn invalid_values() {
        assert!(req(r#"{"title":"t"}"#).is_err(), "message required");
        assert!(req(r#"{"message":"  "}"#).is_err());
        assert!(req(&format!(r#"{{"message":"{}"}}"#, "a".repeat(1025))).is_err());
        assert!(
            req(&format!(r#"{{"message":"{}"}}"#, "ż".repeat(1024))).is_ok(),
            "chars, not bytes"
        );
        assert!(req(&format!(
            r#"{{"message":"m","title":"{}"}}"#,
            "a".repeat(251)
        ))
        .is_err());
        assert!(req(r#"{"message":"m","priority":3}"#).is_err());
        assert!(req(r#"{"message":"m","priority":-3}"#).is_err());
        assert!(req(r#"{"message":"m","priority":1.5}"#).is_err());
        assert!(req(r#"{"message":"m","url":"javascript:alert(1)"}"#).is_err());
        assert!(req(r#"{"message":"m","url":"ftp://x.example"}"#).is_err());
        assert!(req(&format!(
            r#"{{"message":"m","url":"https://x.example/{}"}}"#,
            "a".repeat(512)
        ))
        .is_err());
        assert!(req(&format!(
            r#"{{"message":"m","url_title":"{}"}}"#,
            "a".repeat(101)
        ))
        .is_err());
        assert!(req(r#"{"message":"m","device":"a b"}"#).is_err());
        assert!(req(&format!(
            r#"{{"message":"m","device":"{}"}}"#,
            "a".repeat(26)
        ))
        .is_err());
        assert!(req(r#"{"message":"m","sound":"../x"}"#).is_err());
        assert!(req(&format!(
            r#"{{"message":"m","dedup_key":"{}"}}"#,
            "a".repeat(129)
        ))
        .is_err());
        assert!(req(r#"{"message":"m","dedup_key":""}"#).is_err());
    }
}
