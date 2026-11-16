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
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::auth::Authenticator;
use crate::client_ip::ClientIpResolver;
use crate::config::{ApnsMode, Config, HourlyRate, Mode, Rate};
use crate::controls::Controls;
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
/// Requests handled at once on the public listener (after their body is
/// read); see [`guard`].
pub const MAX_CONCURRENCY: usize = 256;
/// How long a request may wait for one of the [`MAX_CONCURRENCY`] permits
/// before it is shed with `503` and `Retry-After: 1`.
pub const PERMIT_WAIT: Duration = Duration::from_secs(1);
/// Deadline for reading a request body (16 KB routes) before `408`.
pub const BODY_DEADLINE: Duration = Duration::from_secs(3);
/// Deadline for the snapshot route's larger body.
pub const SNAPSHOT_BODY_DEADLINE: Duration = Duration::from_secs(10);
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
    /// Manual bans, suspensions and live limit overrides (admin panel).
    controls: Controls,
    /// [`MAX_CONCURRENCY`] request permits shared by every route.
    permits: Arc<tokio::sync::Semaphore>,
    /// `MAX_CONNECTIONS` (see `crate::serve`).
    max_connections: usize,
    /// `MAX_CONNECTIONS_PER_IP` (see `crate::serve`).
    max_connections_per_ip: usize,
    /// `HEADER_READ_TIMEOUT_SECS` (see `crate::serve`).
    header_read_timeout: Duration,
    /// `TRUSTED_PROXY_IDLE_TIMEOUT_SECS` (see `crate::serve`).
    trusted_proxy_idle_timeout: Duration,
}

/// The replay cut-off is this long before the process started: a client
/// whose clock lags by less never notices a restart, one that lags more
/// gets `401` for (lag - grace) seconds at most. Signatures from the last
/// minute before a restart can therefore be replayed once after it, which
/// is accepted for a restart.
pub const BOOT_GRACE_SECS: u64 = 60;

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
        // Persisted panel controls apply from the first request, whether or
        // not the panel is enabled now.
        let controls = Controls::new(config);
        let now = clock.now();
        if config.mode == Mode::Hosted && config.v2.apns_mode == ApnsMode::Mock {
            tracing::error!(
                "SECURITY: MODE=hosted with APNS_MODE=mock: no real pushes are sent. \
                 GET /v2/debug/pushes answers loopback clients only. Never run this in production."
            );
        }
        // Signed hosted requests and gateway pushes both fill the cache.
        let gw = &config.v2.gateway_global;
        let replay_need = (u64::from(l.global.per_sec.get()) + u64::from(gw.per_sec.get()))
            * crate::auth::REPLAY_TTL.as_secs()
            + u64::from(l.global.burst.get())
            + u64::from(gw.burst.get());
        if replay_need > l.replay_cap as u64 {
            tracing::warn!(
                replay_cap = l.replay_cap,
                needed = replay_need,
                "REPLAY_CAP is below (RATE_GLOBAL_PER_SEC + GATEWAY_GLOBAL_PER_SEC) x 600 + bursts: signed requests get 503 when the replay cache is full"
            );
        }
        let loaded = v2
            .store
            .blocking(|c| controls.load(c, now))
            .map_err(|e| format!("cannot load admin controls: {e}"))?;
        for tx in &loaded.revoked {
            v2.licence.set_revoked(tx, true);
        }
        let s = Self {
            mode: config.mode,
            v1_enabled: config.v1_enabled,
            allow_emergency: config.allow_emergency,
            quota_reserve: config.quota_reserve,
            resolver,
            // Timestamps from before this start are refused: the replay
            // cache is in memory only.
            auth: Authenticator::with_replay(
                config.secrets.clone(),
                now.saturating_sub(BOOT_GRACE_SECS),
                l.replay_cap,
            ),
            limits: RateLimits::new(l, config.secrets.len()),
            bans: AuthBans::with_abuse(l.ban_threshold, l.ban_window, l.ban_duration, l.abuse),
            dedup: Mutex::new(ExpiringSet::new(config.dedup_window, DEDUP_CAP)),
            pushover,
            clock,
            v2,
            metrics,
            controls,
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENCY)),
            max_connections: config.max_connections,
            max_connections_per_ip: config.max_connections_per_ip,
            header_read_timeout: config.header_read_timeout,
            trusted_proxy_idle_timeout: config.trusted_proxy_idle_timeout,
        };
        for key in loaded.overrides {
            tracing::info!(
                key,
                value = s.controls.effective(key),
                "limit override from the admin panel"
            );
            s.apply_limit(key);
        }
        Ok(s)
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

    /// `MAX_CONNECTIONS`.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// `MAX_CONNECTIONS_PER_IP`.
    pub fn max_connections_per_ip(&self) -> usize {
        self.max_connections_per_ip
    }

    /// `HEADER_READ_TIMEOUT_SECS`.
    pub fn header_read_timeout(&self) -> Duration {
        self.header_read_timeout
    }

    /// `TRUSTED_PROXY_IDLE_TIMEOUT_SECS`.
    pub fn trusted_proxy_idle_timeout(&self) -> Duration {
        self.trusted_proxy_idle_timeout
    }

    /// The client IP resolver (`TRUST_PROXY`).
    pub fn resolver(&self) -> &ClientIpResolver {
        &self.resolver
    }

    /// `peer` (a TCP peer) is a proxy trusted by `TRUST_PROXY`: Cloudflare,
    /// `CF_IPS_EXTRA` or an `xff:` network. All clients behind it share its
    /// address, so per-peer connection caps exempt it.
    pub fn is_trusted_proxy(&self, peer: IpAddr) -> bool {
        self.resolver.is_trusted_proxy(peer)
    }

    pub fn v2(&self) -> &V2State {
        &self.v2
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    pub fn controls(&self) -> &Controls {
        &self.controls
    }

    /// Auth-failure bans (listed and lifted by the admin panel).
    pub fn auth_bans(&self) -> &AuthBans {
        &self.bans
    }

    /// Rebuild whatever uses live key `key` from its effective value (the
    /// panel override, else the configuration). Rates replace their limiter
    /// as a whole; the rest are atomics.
    pub fn apply_limit(&self, key: &str) {
        let c = &self.controls;
        let nz = |k: &str| {
            std::num::NonZeroU32::new(c.effective(k)).unwrap_or(std::num::NonZeroU32::MIN)
        };
        let rate = |p: &str, b: &str| Rate {
            per_sec: nz(p),
            burst: nz(b),
        };
        let policy = &self.v2.licence;
        use std::sync::atomic::Ordering::Relaxed;
        match key {
            "RATE_GLOBAL_PER_SEC" | "RATE_GLOBAL_BURST" => self
                .limits
                .set_global(rate("RATE_GLOBAL_PER_SEC", "RATE_GLOBAL_BURST")),
            "RATE_PRE_AUTH_PER_SEC" | "RATE_PRE_AUTH_BURST" => self
                .limits
                .set_pre_auth(rate("RATE_PRE_AUTH_PER_SEC", "RATE_PRE_AUTH_BURST")),
            "RATE_ANON_GLOBAL_PER_SEC" | "RATE_ANON_GLOBAL_BURST" => self
                .limits
                .set_anon(rate("RATE_ANON_GLOBAL_PER_SEC", "RATE_ANON_GLOBAL_BURST")),
            "RATE_GROUP_PER_SEC" | "RATE_GROUP_BURST" => self
                .v2
                .limits
                .set_group(rate("RATE_GROUP_PER_SEC", "RATE_GROUP_BURST")),
            "WS_MAX_STREAMS" => self.v2.hub.max_streams.store(c.effective(key), Relaxed),
            "WS_MAX_MACS_PER_GROUP" => self
                .v2
                .hub
                .max_macs_per_group
                .store(c.effective(key), Relaxed),
            "WS_MAX_PER_IP" => self.v2.hub.max_per_ip.store(c.effective(key), Relaxed),
            "RATE_IP_PER_SEC" | "RATE_IP_BURST" => self
                .limits
                .set_per_ip(rate("RATE_IP_PER_SEC", "RATE_IP_BURST")),
            "RATE_V2_GATEWAY_PER_SEC" | "RATE_V2_GATEWAY_BURST" => self
                .v2
                .limits
                .set_gateway(rate("RATE_V2_GATEWAY_PER_SEC", "RATE_V2_GATEWAY_BURST")),
            "GATEWAY_GROUP_PER_HOUR" | "GATEWAY_GROUP_BURST" => {
                self.v2.limits.set_gateway_hourly(HourlyRate {
                    per_hour: nz("GATEWAY_GROUP_PER_HOUR"),
                    burst: nz("GATEWAY_GROUP_BURST"),
                })
            }
            "GATEWAY_GLOBAL_PER_SEC" | "GATEWAY_GLOBAL_BURST" => self
                .v2
                .limits
                .set_gateway_global(rate("GATEWAY_GLOBAL_PER_SEC", "GATEWAY_GLOBAL_BURST")),
            "GATEWAY_MAX_TOKENS_PER_GROUP" => policy
                .gateway_max_tokens_per_group
                .store(c.effective(key), Relaxed),
            "GATEWAY_MAX_GROUPS" => policy.gateway_max_groups.store(c.effective(key), Relaxed),
            "GATEWAY_OPEN" => policy.gateway_open.store(c.effective(key) != 0, Relaxed),
            "GATEWAY_REQUIRE_LICENCE" => policy
                .gateway_require_licence
                .store(c.effective(key) != 0, Relaxed),
            _ => {}
        }
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

    /// Record an auth failure for `ip` and build the generic 401. Failures
    /// are anonymous work: they draw from the anonymous bucket, never from
    /// the authenticated one; when it is empty the answer is `429`.
    pub fn auth_failed(&self, ip: IpAddr, now: u64, reason: &str) -> Outcome {
        if self.bans.record_failure(ip_key(ip), now) {
            tracing::warn!(client_ip = %ip, "auth failure threshold reached, IP banned");
            self.metrics.record(Event::new("ban").ip(ip).detail(reason));
        }
        tracing::debug!(client_ip = %ip, reason, "auth failed");
        if let Err(ra) = self.limits.check_anon() {
            return (too_many(ra), "rate_limited_anon");
        }
        // Generic body: do not tell the client which check failed.
        (
            error(StatusCode::UNAUTHORIZED, "unauthorized"),
            "unauthorized",
        )
    }

    /// The answer to a failed signature check.
    pub fn auth_error(&self, ip: IpAddr, now: u64, e: crate::auth::AuthError) -> Outcome {
        use crate::auth::AuthError;
        match e {
            // Signed before the boot cut-off: refused, not held against the
            // client (its clock may just lag), but anonymous work: it draws
            // from the anonymous bucket like any failed authentication.
            AuthError::BeforeBoot => match self.limits.check_anon() {
                Err(ra) => (too_many(ra), "rate_limited_anon"),
                Ok(()) => (
                    error(StatusCode::UNAUTHORIZED, "unauthorized"),
                    "before_boot",
                ),
            },
            AuthError::ReplayCacheFull => {
                tracing::warn!("replay cache full: refusing signed requests (REPLAY_CAP)");
                let mut r = error(StatusCode::SERVICE_UNAVAILABLE, "busy");
                r.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                (r, "replay_cache_full")
            }
            e => self.auth_failed(ip, now, e.as_str()),
        }
    }

    /// A `429` with `outcome` on `route` went to `ip`: only anonymous abuse
    /// counts toward a ban (`AUTH_ABUSE_*`): the registration limits of
    /// `POST /v2/groups` (its per-IP bucket included) and the anonymous
    /// bucket (failed authentication). The per-IP bucket of signed routes
    /// does not: many legitimate clients can share one address (NAT), and
    /// they must not be locked out for polling a little too fast.
    pub fn note_rate_limited(&self, ip: IpAddr, route: &str, outcome: &str) {
        let anonymous = match outcome {
            "rate_limited_anon" | "rate_limited_registration" => true,
            "rate_limited_ip" => route == "groups",
            _ => false,
        };
        if !anonymous || route == "gateway.push" {
            return;
        }
        if self.bans.record_abuse(ip_key(ip), self.clock.now()) {
            tracing::warn!(client_ip = %ip, outcome, "sustained rate limiting, IP banned");
            self.metrics
                .record(Event::new("ban").ip(ip).detail("rate_limited"));
        }
    }

    /// Delete expired v2 rows, in batches (one storage call each), so other
    /// requests get the database in between.
    pub async fn cleanup_storage(&self) {
        let now = self.clock.now();
        let (mut m, mut k) = (0, 0);
        loop {
            match self
                .v2
                .store
                .call(move |c| store::cleanup_step(c, now, store::CLEANUP_BATCH))
                .await
            {
                Ok(step) => {
                    m += step.messages;
                    k += step.commands;
                    if !step.more {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "retention cleanup failed");
                    return;
                }
            }
        }
        if m + k > 0 {
            tracing::debug!(messages = m, commands = k, "retention cleanup");
        }
    }

    /// Periodic housekeeping: drop expired entries so every map stays bounded.
    pub fn cleanup(&self) {
        let now = self.clock.now();
        self.limits.cleanup();
        self.v2.limits.cleanup();
        self.bans.cleanup(now);
        self.controls.cleanup(now);
        self.auth.cleanup(now);
        self.v2.purge_unknown_groups(now);
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
        hub: Hub::with_limits(c.ws_max_streams, c.ws_max_macs_per_group, c.ws_max_per_ip),
        unknown_groups: std::sync::Mutex::new(ExpiringSet::new(
            v2::UNKNOWN_GROUP_TTL,
            v2::UNKNOWN_GROUP_CAP,
        )),
        limits: V2Limits::new(c),
        sender,
        mock,
        gateway,
        licence: LicencePolicy {
            mode: c.licence_mode,
            verifier: AppTransactionVerifier::apple(c.licence_allow_sandbox),
            max_groups: c.licence_max_groups,
            grace_until: c.licence_grace_until,
            gateway_open: c.gateway_open.into(),
            gateway_require_licence: c.gateway_require_licence.into(),
            gateway_activity_lines: c.gateway_activity_lines,
            gateway_apns_sandbox: c.gateway_apns_sandbox,
            gateway_sandbox_licences_count: c.gateway_sandbox_licences_count,
            gateway_max_tokens_per_group: c.gateway_max_tokens_per_group.into(),
            gateway_max_groups: c.gateway_max_groups.into(),
            revoked: c.licence_revoked.clone(),
            revoked_live: Default::default(),
        },
        gateway_sends: tokio::sync::Semaphore::new(v2::GATEWAY_MAX_IN_FLIGHT),
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
                .layer(axum::middleware::from_fn_with_state(state.clone(), guard)),
        )
        .with_state(state)
}

/// In front of every route: read the whole body within a deadline (`408`
/// after [`BODY_DEADLINE`], [`SNAPSHOT_BODY_DEADLINE`] for the snapshot),
/// then wait at most [`PERMIT_WAIT`] for one of the shared
/// [`MAX_CONCURRENCY`] permits (`503`, `Retry-After: 1`). A slow client
/// therefore never holds a permit, and nobody queues for one without bound.
/// Also feeds IP-keyed `429`s to the abuse bans.
async fn guard(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let ip = state.client_ip(peer, req.headers());
    let path = req.uri().path();
    let health = path == "/healthz";
    let (limit, deadline) = if path == "/v2/snapshot" {
        (
            v2::snapshot_body_limit(state.v2.snapshot_max),
            SNAPSHOT_BODY_DEADLINE,
        )
    } else {
        (v2::MAX_BODY_BYTES, BODY_DEADLINE)
    };
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit as u64) {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
    }
    let (parts, body) = req.into_parts();
    let bytes = match tokio::time::timeout(deadline, axum::body::to_bytes(body, limit)).await {
        Ok(Ok(b)) => b,
        // Over the limit while streaming (or the client went away).
        Ok(Err(_)) => return error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
        Err(_) => {
            tracing::debug!(client_ip = %ip, "request body not received in time");
            return error(StatusCode::REQUEST_TIMEOUT, "request_timeout");
        }
    };
    let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes));
    // The health check is never shed: a busy server is not an unhealthy one.
    let _permit = if health {
        None
    } else {
        match tokio::time::timeout(PERMIT_WAIT, state.permits.clone().acquire_owned()).await {
            Ok(Ok(p)) => Some(p),
            _ => {
                let mut r = error(StatusCode::SERVICE_UNAVAILABLE, "busy");
                r.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return r;
            }
        }
    };
    let response = next.run(req).await;
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        if let Some(tag) = response.extensions().get::<ApiTag>() {
            state.note_rate_limited(ip, tag.route, tag.outcome);
        }
    }
    response
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
    if let Err(o) = precheck(state, ip, now, GlobalClass::V1) {
        return o;
    }

    let secret = match state.auth.verify(now, "POST", NOTIFY_PATH, headers, body) {
        Ok(i) => i,
        Err(e) => return state.auth_error(ip, now, e),
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

/// Which global bucket a request draws from before authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GlobalClass {
    /// `POST /v2/groups`: the anonymous bucket (`RATE_ANON_GLOBAL_*`).
    Anonymous,
    /// Signed v2 routes: only the cheap `RATE_PRE_AUTH_*` ceiling before
    /// the signature (no tenant can starve it alone: per-IP buckets apply
    /// first, and unknown group ids are cached); once it
    /// verifies, `authenticate` charges the group's and the authenticated
    /// (`RATE_GLOBAL_*`) buckets. Failed requests draw from the anonymous
    /// bucket ([`AppState::auth_failed`]), so a flood of them cannot starve
    /// signed users.
    Signed,
    /// `POST /v2/gateway/push`: like `Signed`, but the gateway's own
    /// `GATEWAY_GLOBAL_*` bucket replaces `RATE_GLOBAL_*`.
    Gateway,
    /// `POST /v1/notify`: `RATE_GLOBAL_*` before the signature, as before.
    V1,
}

/// Manual ban, ban, per-IP and (by class) global checks, done before any
/// authentication work.
// The error is the finished HTTP response; it is only built on the cold path.
#[allow(clippy::result_large_err)]
pub(crate) fn precheck(
    state: &AppState,
    ip: IpAddr,
    now: u64,
    class: GlobalClass,
) -> Result<(), Outcome> {
    // Manual bans from the admin panel come first, on the exact address.
    if let Some(secs) = state.controls.banned_for(ip, now) {
        return Err((too_many(RetryAfter(secs)), "banned_manual"));
    }
    let key = ip_key(ip);
    if let Some(secs) = state.bans.banned_for(key, now) {
        return Err((too_many(RetryAfter(secs)), "banned"));
    }
    if let Err(ra) = state.limits.check_ip(key) {
        return Err((too_many(ra), "rate_limited_ip"));
    }
    match class {
        GlobalClass::Anonymous => {
            if let Err(ra) = state.limits.check_anon() {
                return Err((too_many(ra), "rate_limited_anon"));
            }
        }
        GlobalClass::V1 => {
            if let Err(ra) = state.limits.check_global() {
                return Err((too_many(ra), "rate_limited_global"));
            }
        }
        // A cheap ceiling on the group-key lookups and HMAC checks that
        // follow, before either is done.
        GlobalClass::Signed | GlobalClass::Gateway => {
            if let Err(ra) = state.limits.check_pre_auth() {
                return Err((too_many(ra), "rate_limited_pre_auth"));
            }
        }
    }
    Ok(())
}

/// The authenticated global bucket (signed v2 routes, after the signature).
#[allow(clippy::result_large_err)]
pub(crate) fn check_signed_global(state: &AppState) -> Result<(), Outcome> {
    state
        .limits
        .check_global()
        .map_err(|ra| (too_many(ra), "rate_limited_global"))
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
