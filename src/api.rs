//! HTTP API: `POST /v1/notify`, `GET /healthz`, everything else 404.

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
use crate::config::{Config, Mode};
use crate::limits::{ip_key, AuthBans, Clock, ExpiringSet, RateLimits, RetryAfter};
use crate::pushover::{Message, PushoverClient, SendError};

pub const NOTIFY_PATH: &str = "/v1/notify";
pub const MAX_BODY_BYTES: usize = 8 * 1024;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_CONCURRENCY: usize = 64;
const DEDUP_CAP: usize = 10_000;

pub struct AppState {
    mode: Mode,
    allow_emergency: bool,
    quota_reserve: u64,
    resolver: ClientIpResolver,
    auth: Authenticator,
    limits: RateLimits,
    bans: AuthBans,
    dedup: Mutex<ExpiringSet<(usize, String)>>,
    pushover: PushoverClient,
    clock: Arc<dyn Clock>,
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
        Ok(Self {
            mode: config.mode,
            allow_emergency: config.allow_emergency,
            quota_reserve: config.quota_reserve,
            resolver,
            auth: Authenticator::new(config.secrets.clone()),
            limits: RateLimits::new(l, config.secrets.len()),
            bans: AuthBans::new(l.ban_threshold, l.ban_window, l.ban_duration),
            dedup: Mutex::new(ExpiringSet::new(config.dedup_window, DEDUP_CAP)),
            pushover,
            clock,
        })
    }

    /// Periodic housekeeping: drop expired entries so every map stays bounded.
    pub fn cleanup(&self) {
        let now = self.clock.now();
        self.limits.cleanup();
        self.bans.cleanup(now);
        self.auth.cleanup(now);
        self.dedup
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .purge(now);
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(NOTIFY_PATH, post(notify).fallback(not_found))
        .route("/healthz", get(healthz).fallback(not_found))
        .fallback(not_found)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
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

fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

fn invalid(detail: impl Into<String>) -> Response {
    let detail: String = detail.into();
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_request", "detail": detail })),
    )
        .into_response()
}

fn too_many(RetryAfter(secs): RetryAfter) -> Response {
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
    let (response, outcome) = handle_notify(&state, ip, &headers, &body).await;
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

    let now = state.clock.now();
    let key = ip_key(ip);

    if let Some(secs) = state.bans.banned_for(key, now) {
        return (too_many(RetryAfter(secs)), "banned");
    }
    if let Err(ra) = state.limits.check_ip(key) {
        return (too_many(ra), "rate_limited_ip");
    }
    if let Err(ra) = state.limits.check_global() {
        return (too_many(ra), "rate_limited_global");
    }

    let secret = match state.auth.verify(now, "POST", NOTIFY_PATH, headers, body) {
        Ok(i) => i,
        Err(e) => {
            if state.bans.record_failure(key, now) {
                tracing::warn!(client_ip = %ip, "auth failure threshold reached, IP banned");
            }
            tracing::debug!(client_ip = %ip, reason = e.as_str(), "auth failed");
            // Generic body: do not tell the client which check failed.
            return (
                error(StatusCode::UNAUTHORIZED, "unauthorized"),
                "unauthorized",
            );
        }
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

/// Describe a JSON error without echoing request contents.
fn json_error(e: &serde_json::Error) -> String {
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
