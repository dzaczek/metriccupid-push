//! v2 "MetricCupid Push": end-to-end encrypted mailbox, command queue and
//! APNs fan-out for a group of devices. The normative spec is PROTOCOL.md.
//!
//! The server only ever handles ciphertext (`sealed`), opaque ids and APNs
//! tokens. Never log sealed blobs, tokens or keys.

// Handlers return `Result<_, Outcome>` where the error is the finished HTTP
// response; it is only built on the cold path, so its size does not matter.
#![allow(clippy::result_large_err)]

pub mod activity;
pub mod apns;
pub mod licence;
pub mod presence;
pub mod store;
pub mod stream;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use tokio::task::JoinSet;

use self::activity::{
    Activities, ActivityEvent, ActivityLine, Batch, ContentState, ACTIVITY_MAX_SECS,
    ACTIVITY_TTL_SECS, MAX_STALE_SECS, MIN_STALE_SECS,
};
use self::apns::{
    build_background_payload, build_payload, build_presence_payload, ApnsEnv, ApnsSender,
    BackgroundNote, GatewayApns, GatewayPush, GatewayRegistration, McEnvelope, MessageType,
    MockApns, OfflineReason, PresenceNote, PushContent, PushError, PushJob, Urgency, DEVICE_HEADER,
    GROUP_HEADER, MAX_PAYLOAD_BYTES, PRESENCE_COLLAPSE_ID,
};
use self::licence::{LicenceError, LicencePolicy, LicenceReq, VerifiedLicence};
use self::presence::Presence;
use self::store::{
    Attach, Bind, CreateGroup, Device, GroupLicence, Insert, NewMessage, Store, StoreError, Upsert,
};
use self::stream::{CommandFrame, Hub, MAX_CLIENT_FRAME};
use crate::api::{
    check_signed_global, error, invalid, json_error, precheck, too_many, AppState, GlobalClass,
    Outcome,
};
use crate::config::Mode;
use crate::limits::{ip_key, V2Limits};
use crate::metrics::{ApiTag, Event};

/// Max request body for v2 routes.
pub const MAX_BODY_BYTES: usize = 16 * 1024;
pub const MAX_TTL_SECS: u64 = 86_400;
/// Max length (base64 characters) of a command's `sealed`.
pub const MAX_COMMAND_SEALED: usize = 8 * 1024;
/// nonce (12) + tag (16): the smallest valid sealed box.
pub const MIN_SEALED_BYTES: usize = 28;

/// v2 part of the application state.
pub struct V2State {
    pub store: Store,
    pub hub: Hub,
    pub limits: V2Limits,
    pub sender: Arc<dyn ApnsSender>,
    pub mock: Option<Arc<MockApns>>,
    /// Set in `APNS_MODE=gateway`: group registrations are forwarded too.
    pub gateway: Option<Arc<GatewayApns>>,
    pub licence: LicencePolicy,
    pub ws_ping: Duration,
    pub presence: Presence,
    pub activities: Activities,
    /// Max base64 length of a snapshot's `sealed` (`V2_SNAPSHOT_MAX_BYTES`).
    pub snapshot_max: usize,
    /// Gateway pushes in flight to APNs ([`GATEWAY_MAX_IN_FLIGHT`]).
    pub gateway_sends: tokio::sync::Semaphore,
    /// Group ids recently found unknown: a flood of random group ids is
    /// answered from memory instead of SQLite. Cleared for an id when the
    /// group is created.
    pub unknown_groups: std::sync::Mutex<crate::limits::ExpiringSet<String>>,
}

/// How long an unknown group id is remembered ([`V2State::unknown_groups`]).
pub const UNKNOWN_GROUP_TTL: Duration = Duration::from_secs(60);
/// At most this many unknown group ids are remembered (oldest dropped).
pub const UNKNOWN_GROUP_CAP: usize = 100_000;

impl V2State {
    fn unknown_groups(&self) -> std::sync::MutexGuard<'_, crate::limits::ExpiringSet<String>> {
        self.unknown_groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// `group` was looked up and not found within [`UNKNOWN_GROUP_TTL`].
    pub fn is_known_unknown(&self, group: &str, now: u64) -> bool {
        self.unknown_groups().contains(&group.to_string(), now)
    }

    fn remember_unknown(&self, group: &str, now: u64) {
        self.unknown_groups()
            .insert_if_absent(group.to_string(), now);
    }

    /// Drop `group` from the unknown-group cache (it was just created).
    pub fn forget_unknown(&self, group: &str) {
        self.unknown_groups().remove(&group.to_string());
    }

    /// Drop expired entries (periodic cleanup).
    pub fn purge_unknown_groups(&self, now: u64) {
        self.unknown_groups().purge(now);
    }
}

/// At most this many gateway pushes wait on APNs at once; more get `503`
/// with `Retry-After: 1` instead of queueing.
pub const GATEWAY_MAX_IN_FLIGHT: usize = 32;

/// Body limit of `POST /v2/snapshot`: the sealed blob plus the JSON around it.
pub fn snapshot_body_limit(snapshot_max: usize) -> usize {
    snapshot_max + 1024
}

/// `/v2/snapshot` (PROTOCOL.md section 6.6a). Kept apart from [`routes`] so
/// only this route gets the larger body limit.
pub fn snapshot_routes() -> Router<Arc<AppState>> {
    Router::new().route("/v2/snapshot", post(post_snapshot).get(get_snapshot))
}

/// Presence pushes expire after this long (a stale "offline" is useless).
pub const PRESENCE_TTL_SECS: u64 = 3600;

pub fn routes(mode: Mode, mock: bool) -> Router<Arc<AppState>> {
    let mut r = Router::new()
        .route("/v2/groups", post(create_group).delete(delete_group))
        .route("/v2/devices", get(list_devices))
        .route("/v2/status", get(get_status))
        .route(
            "/v2/devices/{device_id}",
            put(put_device).delete(delete_device),
        )
        .route("/v2/messages", post(post_message).get(get_messages))
        .route("/v2/commands", post(post_command).get(get_commands))
        .route("/v2/commands/ack", post(ack_command))
        .route(
            "/v2/activities/{device_id}",
            put(put_activity_token).delete(delete_activity_token),
        )
        .route(
            "/v2/activities/{device_id}/start-token",
            put(put_start_token).delete(delete_start_token),
        )
        .route("/v2/activity-state", post(post_activity_state))
        .route("/v2/heartbeat", post(post_heartbeat))
        .route("/v2/stream", get(open_stream));
    if mode == Mode::Hosted {
        r = r
            .route(apns::GATEWAY_PUSH_PATH, post(gateway_push))
            .route("/v2/licence", put(put_licence));
    }
    if mock {
        r = r.route("/v2/debug/pushes", get(debug_pushes));
    }
    r
}

// ------------------------------------------------------------ validation ---

/// 16 random bytes, base64url without padding (exactly 22 characters).
pub fn is_id128(s: &str) -> bool {
    s.len() == 22
        && URL_SAFE_NO_PAD
            .decode(s)
            .map(|b| b.len() == 16)
            .unwrap_or(false)
}

/// Message / command id or collapse id: 1..=64 of `[A-Za-z0-9_-]`.
pub fn is_token_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Standard base64 (with padding) of at least nonce + tag.
pub fn is_sealed(s: &str, max_len: usize) -> bool {
    s.len() <= max_len
        && STANDARD
            .decode(s)
            .map(|b| b.len() >= MIN_SEALED_BYTES)
            .unwrap_or(false)
}

/// APNs device token: lowercase hex, 64..=200 characters, even length.
pub fn normalize_apns_token(s: &str) -> Option<String> {
    normalize_hex_token(s, 200)
}

/// Live Activity push tokens can be longer than device tokens.
pub const MAX_ACTIVITY_TOKEN_HEX: usize = 512;

fn normalize_hex_token(s: &str, max: usize) -> Option<String> {
    let ok = (64..=max).contains(&s.len())
        && s.len() % 2 == 0
        && s.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| s.to_ascii_lowercase())
}

fn is_name(s: &str) -> bool {
    let n = s.chars().count();
    (1..=64).contains(&n) && !s.chars().any(char::is_control)
}

// ------------------------------------------------------------------ auth ---

/// Which device the request must come from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceRule {
    /// No `X-MC-Device` needed (gateway push).
    None,
    /// Valid `X-MC-Device` header, device need not exist yet (registration).
    Header,
    /// A registered device, optionally of a given kind.
    Registered(Option<&'static str>),
}

struct Authed {
    group: String,
    key: [u8; 32],
    device_id: Option<String>,
    device: Option<Device>,
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn storage_error(e: StoreError) -> Outcome {
    tracing::error!(error = %e, "storage error");
    (
        error(StatusCode::INTERNAL_SERVER_ERROR, "storage_error"),
        "storage_error",
    )
}

/// The signed request target: path plus `?query` when present.
fn target(uri: &Uri) -> &str {
    uri.path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_else(|| uri.path())
}

#[allow(clippy::too_many_arguments)]
async fn authenticate(
    state: &AppState,
    ip: IpAddr,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    rule: DeviceRule,
) -> Result<Authed, Outcome> {
    let now = state.now();
    // Only the gateway push has no device; it skips the hosted global bucket.
    let class = if rule == DeviceRule::None {
        GlobalClass::Gateway
    } else {
        GlobalClass::Signed
    };
    precheck(state, ip, now, class)?;

    let group = header(headers, GROUP_HEADER).filter(|g| is_id128(g));
    let device_id = header(headers, DEVICE_HEADER).filter(|d| is_id128(d));
    let Some(group) = group else {
        return Err(state.auth_failed(ip, now, "bad_group_header"));
    };
    if rule != DeviceRule::None && device_id.is_none() {
        return Err(state.auth_failed(ip, now, "bad_device_header"));
    }
    let v2 = state.v2();
    if v2.is_known_unknown(group, now) {
        return Err(state.auth_failed(ip, now, "unknown_group"));
    }
    let g = group.to_string();
    let key = match v2.store.call(move |c| store::group_key(c, &g)).await {
        Ok(Some(k)) => k,
        Ok(None) => {
            v2.remember_unknown(group, now);
            return Err(state.auth_failed(ip, now, "unknown_group"));
        }
        Err(e) => return Err(storage_error(e)),
    };
    let device_for_sig = if rule == DeviceRule::None {
        ""
    } else {
        device_id.unwrap_or_default()
    };
    let sig = match state.auth().check_v2(
        now,
        &key,
        method,
        target(uri),
        group,
        device_for_sig,
        headers,
        body,
    ) {
        Ok(sig) => sig,
        Err(e) => return Err(state.auth_error(ip, now, e)),
    };
    // Shared buckets only after the signature: anonymous or failed requests
    // never reach them. The group's own bucket first, so one group's flood
    // uses up its own quota before the one all signed users share.
    if let Err(ra) = v2.limits.check_group(group) {
        return Err((too_many(ra), "rate_limited_group_requests"));
    }
    if class == GlobalClass::Signed {
        check_signed_global(state)?;
    }
    // Replay check last: the cache then fills no faster than the buckets
    // above allow.
    if let Err(e) = state.auth().remember(sig, now) {
        return Err(state.auth_error(ip, now, e));
    }
    // Suspended from the admin panel: data kept, every signed route refused.
    if state.controls().is_suspended(group) {
        return Err(group_suspended());
    }

    let mut authed = Authed {
        group: group.to_string(),
        key,
        device_id: device_id.map(str::to_string),
        device: None,
    };
    if let DeviceRule::Registered(kind) = rule {
        let (g, d) = (
            authed.group.clone(),
            authed.device_id.clone().unwrap_or_default(),
        );
        let dev = match v2.store.call(move |c| store::device(c, &g, &d)).await {
            Ok(Some(dev)) => dev,
            Ok(None) => {
                return Err((
                    error(StatusCode::FORBIDDEN, "unknown_device"),
                    "unknown_device",
                ))
            }
            Err(e) => return Err(storage_error(e)),
        };
        if kind.is_some_and(|k| k != dev.kind) {
            return Err((
                error(StatusCode::FORBIDDEN, "wrong_device_kind"),
                "wrong_device_kind",
            ));
        }
        authed.device = Some(dev);
    }
    Ok(authed)
}

fn group_suspended() -> Outcome {
    (
        error(StatusCode::FORBIDDEN, "group_suspended"),
        "group_suspended",
    )
}

fn finish(
    route: &'static str,
    ip: IpAddr,
    started: Instant,
    group: Option<&str>,
    (mut response, outcome): Outcome,
) -> Response {
    response.extensions_mut().insert(ApiTag {
        route,
        outcome,
        group: group.map(str::to_string),
    });
    // Never log sealed blobs, tokens or keys.
    tracing::info!(
        route,
        client_ip = %ip,
        group = group.unwrap_or("-"),
        status = response.status().as_u16(),
        outcome,
        latency_ms = started.elapsed().as_millis() as u64,
        "v2"
    );
    response
}

fn ok(status: StatusCode, body: serde_json::Value, outcome: &'static str) -> Outcome {
    ((status, Json(body)).into_response(), outcome)
}

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(body).map_err(|e| (invalid(json_error(&e)), "invalid_json"))
}

fn bad(detail: &str) -> Outcome {
    (invalid(detail), "invalid_request")
}

// ---------------------------------------------------------------- groups ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateGroupReq {
    group_id: String,
    auth_key: String,
    #[serde(default)]
    licence: Option<LicenceReq>,
    /// Set by a self-hosted server forwarding the registration to its
    /// gateway: such groups only push through the gateway and need no licence.
    #[serde(default)]
    gateway: bool,
}

// -------------------------------------------------------------- licences ---

fn licence_invalid(e: LicenceError) -> Outcome {
    tracing::info!(reason = e.code(), "licence refused");
    (
        (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "licence_invalid", "reason": e.code() })),
        )
            .into_response(),
        "licence_invalid",
    )
}

fn licence_in_use() -> Outcome {
    (
        error(StatusCode::FORBIDDEN, "licence_in_use"),
        "licence_in_use",
    )
}

fn licence_required() -> Outcome {
    (
        error(StatusCode::PAYMENT_REQUIRED, "licence_required"),
        "licence_required",
    )
}

/// A `licence` metrics event: outcome `ok` / `invalid` / `in_use`, detail
/// the refusal reason or `tier/environment`. Never the purchase id or JWS.
/// `group` only once the group is authenticated or created: `POST
/// /v2/groups` is unauthenticated.
fn record_licence(
    state: &AppState,
    group: Option<&str>,
    route: &'static str,
    outcome: &'static str,
    detail: &str,
) {
    let mut e = Event::new("licence").route(route).outcome(outcome);
    if let Some(g) = group {
        e = e.group(g);
    }
    if !detail.is_empty() {
        e = e.detail(detail);
    }
    state.metrics().record(e);
}

/// `licence` in responses: never the purchase id.
fn licence_json(tier: &str, environment: &str, verified_at: u64) -> serde_json::Value {
    json!({ "tier": tier, "environment": environment, "verified_at": verified_at })
}

fn stored_licence_json(l: Option<&GroupLicence>) -> serde_json::Value {
    l.map_or(serde_json::Value::Null, |l| {
        licence_json(&l.tier, &l.environment, l.verified_at)
    })
}

/// 402 unless the group may send: it has a licence that is not revoked, or
/// the server does not enforce one (open mode, self-hosted, grace period).
async fn require_licence(state: &AppState, group: &str) -> Result<(), Outcome> {
    let v2 = state.v2();
    if !v2.licence.enforced(state.now()) {
        return Ok(());
    }
    let g = group.to_string();
    match v2.store.call(move |c| store::group_licence(c, &g)).await {
        // A purchase revoked after it was attached no longer counts.
        Ok(Some(l)) if !v2.licence.is_tx_revoked(&l.app_transaction_id) => Ok(()),
        Ok(_) => Err(licence_required()),
        Err(e) => Err(storage_error(e)),
    }
}

async fn create_group(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let r = handle_create_group(&state, ip, &body).await;
    finish("groups", ip, started, None, r)
}

async fn handle_create_group(state: &AppState, ip: IpAddr, body: &[u8]) -> Outcome {
    let now = state.now();
    if let Err(o) = precheck(state, ip, now, GlobalClass::Anonymous) {
        return o;
    }
    let v2 = state.v2();
    if let Err(ra) = v2.limits.check_group_registration(ip_key(ip)) {
        return (too_many(ra), "rate_limited_registration");
    }
    let req: CreateGroupReq = match parse(body) {
        Ok(r) => r,
        Err(o) => return o,
    };
    if !is_id128(&req.group_id) {
        return bad("group_id must be 16 bytes, base64url without padding");
    }
    // Suspended from the admin panel: no re-registration, licence attach or
    // gateway re-add either.
    if state.controls().is_suspended(&req.group_id) {
        return group_suspended();
    }
    let key: [u8; 32] = match STANDARD
        .decode(&req.auth_key)
        .ok()
        .and_then(|k| k.try_into().ok())
    {
        Some(k) => k,
        None => return bad("auth_key must be 32 bytes, standard base64"),
    };
    if req
        .licence
        .as_ref()
        .is_some_and(|l| l.jws.len() > licence::MAX_JWS_LEN)
    {
        return bad("licence too long");
    }

    // Hosted: verify a supplied licence; in app_transaction mode one is
    // required. In open mode a bad licence is only logged (the Mac learns
    // about it from GET /v2/status and PUT /v2/licence). Self-hosted servers
    // never check, they only forward it to the gateway.
    let policy = &v2.licence;
    // A gateway registration on the hosted server (from a self-hosted
    // server). Closed gateway first, even with a licence.
    let gateway_reg = req.gateway && state.mode() == Mode::Hosted;
    if gateway_reg && !policy.gateway_open() {
        return gateway_closed();
    }
    // Strict gateway mode: the licence must verify and attach, like hosted.
    let strict = gateway_reg && policy.gateway_require_licence();
    let required = policy.required_for_new_groups();
    let attach_required = required || strict;
    let verified: Option<VerifiedLicence> = match (&req.licence, state.mode()) {
        (_, Mode::SelfHosted) => None,
        (Some(l), Mode::Hosted) => match policy.verify(l) {
            Ok(v) => Some(v),
            Err(e) => {
                record_licence(state, None, "groups", "invalid", e.code());
                if attach_required {
                    return licence_invalid(e);
                }
                tracing::info!(reason = e.code(), "open registration: licence ignored");
                None
            }
        },
        (None, Mode::Hosted) if required && !req.gateway => return licence_required(),
        (None, Mode::Hosted) => None,
    };
    // Fallback purchase ids have no per-purchase pool: limit them per IP.
    let verified = match verified {
        Some(v) if licence::is_fallback_id(&v.app_transaction_id) => {
            match v2.limits.check_fallback_attach(ip_key(ip)) {
                Ok(()) => Some(v),
                Err(ra) if attach_required => return (too_many(ra), "rate_limited_licence"),
                Err(_) => {
                    tracing::info!("open registration: fallback-id licence rate-limited, ignored");
                    None
                }
            }
        }
        v => v,
    };
    let gateway_licensed = verified
        .as_ref()
        .is_some_and(|v| policy.gateway_licensed(v));
    if strict && !gateway_licensed {
        return licence_required();
    }

    let g = req.group_id.clone();
    let max = policy.max_groups;
    let max_gateway = policy.gateway_max_groups();
    let lic = verified.clone();
    let stored = v2
        .store
        .call(move |c| {
            if gateway_reg && !store::gateway_has_room(c, &g, max_gateway)? {
                return Ok(None);
            }
            let (created, attached) = match lic {
                Some(lic) if attach_required => {
                    store::create_group_with_licence(c, &g, &key, &lic, max, now)
                        .map(|(created, a)| (created, Some(a)))?
                }
                Some(lic) => {
                    let created = store::create_group(c, &g, &key, now)?;
                    if created == CreateGroup::Conflict {
                        return Ok(Some((created, None)));
                    }
                    (created, Some(store::attach_licence(c, &g, &lic, max, now)?))
                }
                None => (store::create_group(c, &g, &key, now)?, None),
            };
            let refused = created == CreateGroup::Conflict
                || (attach_required && attached == Some(Attach::InUse));
            if gateway_reg && !refused {
                let licensed = gateway_licensed
                    && matches!(attached, Some(Attach::Attached | Attach::Refreshed));
                store::put_gateway_group(c, &g, licensed, now)?;
            }
            Ok(Some((created, attached)))
        })
        .await;
    // Whatever the outcome, the id may exist now: no stale negative cache.
    v2.forget_unknown(&req.group_id);
    let (created, attached) = match stored {
        Ok(None) => {
            return (
                error(StatusCode::SERVICE_UNAVAILABLE, "gateway_full"),
                "gateway_full",
            )
        }
        Ok(Some((CreateGroup::Conflict, _))) => {
            return (
                error(StatusCode::CONFLICT, "group_exists"),
                "group_conflict",
            )
        }
        Ok(Some((_, Some(Attach::InUse)))) if attach_required => {
            record_licence(state, None, "groups", "in_use", "");
            return licence_in_use();
        }
        Ok(Some((c, a))) => (c, a),
        Err(e) => return storage_error(e),
    };
    match (&verified, attached) {
        (Some(v), Some(Attach::Attached | Attach::Refreshed)) => record_licence(
            state,
            Some(&req.group_id),
            "groups",
            "ok",
            &format!("{}/{}", v.tier, v.environment),
        ),
        (Some(_), Some(Attach::InUse)) => record_licence(state, None, "groups", "in_use", ""),
        _ => {}
    }
    let licence = match (&verified, attached) {
        (Some(v), Some(Attach::Attached | Attach::Refreshed)) => {
            licence_json(v.tier, v.environment, now)
        }
        _ => serde_json::Value::Null,
    };

    // Self-hosted with the hosted gateway: the gateway must know the group to
    // accept our signed push jobs. Idempotent, so a client retry after a
    // gateway failure is safe.
    if let Some(gw) = &v2.gateway {
        let mut fwd =
            json!({ "group_id": req.group_id, "auth_key": req.auth_key, "gateway": true });
        if let Some(l) = &req.licence {
            fwd["licence"] = json!(l);
        }
        match gw.register_group(&fwd).await {
            GatewayRegistration::Ok => {}
            GatewayRegistration::Status(402) => {
                return (
                    error(StatusCode::PAYMENT_REQUIRED, "licence_required"),
                    "gateway_licence_required",
                )
            }
            GatewayRegistration::Status(403) => {
                return (
                    (
                        StatusCode::FORBIDDEN,
                        Json(json!({ "error": "licence_invalid", "reason": "gateway" })),
                    )
                        .into_response(),
                    "gateway_licence_invalid",
                )
            }
            GatewayRegistration::Status(409) => {
                return (
                    error(StatusCode::CONFLICT, "group_exists"),
                    "gateway_conflict",
                )
            }
            other => {
                tracing::warn!(?other, "gateway group registration failed");
                return (
                    error(StatusCode::BAD_GATEWAY, "gateway_error"),
                    "gateway_error",
                );
            }
        }
    }

    match created {
        CreateGroup::Created => ok(
            StatusCode::CREATED,
            json!({"status": "created", "licence": licence}),
            "created",
        ),
        _ => ok(
            StatusCode::OK,
            json!({"status": "exists", "licence": licence}),
            "exists",
        ),
    }
}

/// `DELETE /v2/groups` (Mac): delete the caller's group and all its data,
/// which also frees its licence slot.
async fn delete_group(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "DELETE",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(Some("mac")),
        )
        .await?;
        group = Some(a.group.clone());
        let g = a.group.clone();
        let devices = state
            .v2()
            .store
            .call(move |c| {
                let devices = store::list_devices(c, &g)?;
                store::delete_group(c, &g)?;
                Ok(devices)
            })
            .await
            .map_err(storage_error)?;
        let v2 = state.v2();
        for d in devices {
            v2.hub.remove_device(&a.group, &d.device_id);
        }
        // No stale presence or Live Activity state for a deleted group (a
        // stream that ends after this is handled in `push_presence`).
        v2.presence.forget(&a.group);
        v2.activities.forget_group(&a.group);
        Ok((StatusCode::NO_CONTENT.into_response(), "deleted"))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("groups.delete", ip, started, group.as_deref(), r)
}

/// `PUT /v2/licence` (hosted only): attach or refresh the group's licence.
async fn put_licence(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "PUT",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(None),
        )
        .await?;
        group = Some(a.group.clone());
        let req: LicenceReq = parse(&body)?;
        let v2 = state.v2();
        let lic = v2.licence.verify(&req).map_err(|e| {
            record_licence(&state, Some(&a.group), "licence.put", "invalid", e.code());
            licence_invalid(e)
        })?;
        if licence::is_fallback_id(&lic.app_transaction_id) {
            if let Err(ra) = v2.limits.check_fallback_attach(ip_key(ip)) {
                return Err((too_many(ra), "rate_limited_licence"));
            }
        }
        let (g, max, now) = (a.group.clone(), v2.licence.max_groups, state.now());
        let l = lic.clone();
        let attached = v2
            .store
            .call(move |c| store::attach_licence(c, &g, &l, max, now))
            .await
            .map_err(storage_error)?;
        let status = match attached {
            Attach::InUse => {
                record_licence(&state, Some(&a.group), "licence.put", "in_use", "");
                return Err(licence_in_use());
            }
            Attach::Attached => "attached",
            Attach::Refreshed => "refreshed",
        };
        record_licence(
            &state,
            Some(&a.group),
            "licence.put",
            "ok",
            &format!("{}/{}", lic.tier, lic.environment),
        );
        Ok(ok(
            StatusCode::OK,
            json!({ "status": status, "licence": licence_json(lic.tier, lic.environment, now) }),
            status,
        ))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("licence.put", ip, started, group.as_deref(), r)
}

// --------------------------------------------------------------- devices ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceReq {
    kind: String,
    name: String,
    #[serde(default)]
    apns_token: Option<String>,
    #[serde(default)]
    apns_env: Option<String>,
}

async fn put_device(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(device_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(&state, ip, "PUT", &uri, &headers, &body, DeviceRule::Header).await?;
        group = Some(a.group.clone());
        if a.device_id.as_deref() != Some(device_id.as_str()) {
            return Err(bad("X-MC-Device must match the device id in the path"));
        }
        let req: DeviceReq = parse(&body)?;
        if !matches!(req.kind.as_str(), "mac" | "ios") {
            return Err(bad("kind must be mac or ios"));
        }
        if !is_name(&req.name) {
            return Err(bad(
                "name must be 1 to 64 characters without control characters",
            ));
        }
        let env = match req.apns_env.as_deref() {
            None => ApnsEnv::Production,
            Some(e) => {
                ApnsEnv::parse(e).ok_or_else(|| bad("apns_env must be sandbox or production"))?
            }
        };
        let token = match &req.apns_token {
            None => None,
            Some(_) if req.kind != "ios" => {
                return Err(bad("apns_token is only allowed for ios devices"))
            }
            Some(t) => Some(
                normalize_apns_token(t)
                    .ok_or_else(|| bad("apns_token must be 64 to 200 hex characters"))?,
            ),
        };
        let dev = Device {
            device_id: device_id.clone(),
            kind: req.kind,
            name: req.name,
            apns_token: token,
            apns_env: env.as_str().to_string(),
            created_at: 0,
            updated_at: 0,
            last_seen: None,
        };
        let now = state.now();
        let g = a.group.clone();
        match state
            .v2()
            .store
            .call(move |c| store::upsert_device(c, &g, &dev, now))
            .await
        {
            Ok(Upsert::Created) => Ok(ok(
                StatusCode::CREATED,
                json!({"status": "created"}),
                "created",
            )),
            Ok(Upsert::Updated) => Ok(ok(StatusCode::OK, json!({"status": "updated"}), "updated")),
            Ok(Upsert::LimitReached) => {
                Ok((error(StatusCode::CONFLICT, "device_limit"), "device_limit"))
            }
            Err(e) => Err(storage_error(e)),
        }
    }
    .await
    .unwrap_or_else(|o| o);
    finish("devices.put", ip, started, group.as_deref(), r)
}

async fn delete_device(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(device_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "DELETE",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(None),
        )
        .await?;
        group = Some(a.group.clone());
        let (g, d) = (a.group.clone(), device_id.clone());
        match state
            .v2()
            .store
            .call(move |c| store::delete_device(c, &g, &d))
            .await
        {
            Ok(true) => {
                state.v2().hub.remove_device(&a.group, &device_id);
                state.v2().activities.forget_device(&a.group, &device_id);
                Ok((StatusCode::NO_CONTENT.into_response(), "deleted"))
            }
            Ok(false) => Ok((error(StatusCode::NOT_FOUND, "not_found"), "not_found")),
            Err(e) => Err(storage_error(e)),
        }
    }
    .await
    .unwrap_or_else(|o| o);
    finish("devices.delete", ip, started, group.as_deref(), r)
}

async fn list_devices(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "GET",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(None),
        )
        .await?;
        group = Some(a.group.clone());
        let g = a.group.clone();
        let devices = state
            .v2()
            .store
            .call(move |c| store::list_devices(c, &g))
            .await
            .map_err(storage_error)?;
        let hub = &state.v2().hub;
        let list: Vec<_> = devices
            .iter()
            .map(|d| {
                let mut v = json!({
                    "device_id": d.device_id,
                    "kind": d.kind,
                    "name": d.name,
                    "apns_env": d.apns_env,
                    "has_token": d.apns_token.is_some(),
                    "created_at": d.created_at,
                    "updated_at": d.updated_at,
                });
                if d.kind == "mac" {
                    v["online"] = json!(hub.is_online(&a.group, &d.device_id));
                    v["last_seen"] = json!(d.last_seen);
                }
                v
            })
            .collect();
        Ok(ok(StatusCode::OK, json!({ "devices": list }), "listed"))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("devices.list", ip, started, group.as_deref(), r)
}

async fn get_status(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "GET",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(None),
        )
        .await?;
        group = Some(a.group.clone());
        let g = a.group.clone();
        let (devices, licence) = state
            .v2()
            .store
            .call(move |c| Ok((store::list_devices(c, &g)?, store::group_licence(c, &g)?)))
            .await
            .map_err(storage_error)?;
        let policy = &state.v2().licence;
        // A revoked purchase is reported as no licence.
        let licence = licence.filter(|l| !policy.is_tx_revoked(&l.app_transaction_id));
        let hub = &state.v2().hub;
        let macs: Vec<_> = devices
            .iter()
            .filter(|d| d.kind == "mac")
            .map(|d| (d, hub.is_online(&a.group, &d.device_id)))
            .collect();
        let mac_online = macs.iter().any(|(_, online)| *online);
        let mac_last_seen = macs.iter().filter_map(|(d, _)| d.last_seen).max();
        let list: Vec<_> = macs
            .iter()
            .map(|(d, online)| {
                json!({ "device_id": d.device_id, "online": online, "last_seen": d.last_seen })
            })
            .collect();
        let in_force = policy.required_for_new_groups();
        Ok(ok(
            StatusCode::OK,
            json!({
                "mac_online": mac_online,
                "mac_last_seen": mac_last_seen,
                "macs": list,
                "licence": stored_licence_json(licence.as_ref()),
                "licence_required": in_force && licence.is_none() && policy.enforced(state.now()),
                "licence_grace_until": if in_force { policy.grace_until } else { None },
            }),
            "status",
        ))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("status", ip, started, group.as_deref(), r)
}

// -------------------------------------------------------------- messages ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageReq {
    id: String,
    #[serde(rename = "type")]
    kind: MessageType,
    sealed: String,
    #[serde(default)]
    collapse_id: Option<String>,
    urgency: Urgency,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

async fn post_message(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "POST",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(Some("mac")),
        )
        .await?;
        group = Some(a.group.clone());
        require_licence(&state, &a.group).await?;
        if let Err(ra) = state.v2().limits.check_messages(&a.group) {
            return Err((too_many(ra), "rate_limited_group"));
        }
        let req: MessageReq = parse(&body)?;
        if !is_token_id(&req.id) {
            return Err(bad("id must be 1 to 64 characters of A-Z a-z 0-9 _ -"));
        }
        if !is_sealed(&req.sealed, MAX_BODY_BYTES) {
            return Err(bad(
                "sealed must be standard base64 of nonce|ciphertext|tag",
            ));
        }
        if req.collapse_id.as_deref().is_some_and(|c| !is_token_id(c)) {
            return Err(bad(
                "collapse_id must be 1 to 64 characters of A-Z a-z 0-9 _ -",
            ));
        }
        let ttl = req.ttl_secs.unwrap_or(MAX_TTL_SECS);
        if ttl > MAX_TTL_SECS {
            return Err(bad("ttl_secs must be at most 86400"));
        }
        let mc = McEnvelope {
            id: req.id.clone(),
            t: req.kind,
            s: req.sealed.clone(),
        };
        if build_payload(&mc, req.urgency).len() > MAX_PAYLOAD_BYTES {
            return Err((
                error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
                "payload_too_large",
            ));
        }

        let now = state.now();
        let new = NewMessage {
            id: req.id,
            kind: req.kind.as_str().into(),
            sealed: req.sealed,
            urgency: req.urgency.as_str().into(),
            collapse_id: req.collapse_id.clone(),
        };
        let g = a.group.clone();
        let cursor = match state
            .v2()
            .store
            .call(move |c| store::insert_message(c, &g, &new, now))
            .await
        {
            Ok(Insert::Stored(c)) => c,
            Ok(Insert::Duplicate(c)) => {
                return Ok(ok(
                    StatusCode::OK,
                    json!({"status": "duplicate", "cursor": c}),
                    "duplicate",
                ))
            }
            Ok(Insert::Full) => unreachable!("the mailbox evicts instead of filling up"),
            Err(e) => return Err(storage_error(e)),
        };

        let expiration = if ttl == 0 { 0 } else { now + ttl };
        // Summaries feed the phone's widget from the mailbox: no notification.
        let (pushed, failed, unregistered) = if req.kind == MessageType::Summary {
            (0, 0, 0)
        } else {
            fan_out(
                &state,
                &a.group,
                a.key,
                PushContent::Sealed(mc),
                req.urgency,
                req.collapse_id,
                expiration,
            )
            .await
            .map_err(storage_error)?
        };
        Ok(ok(
            StatusCode::OK,
            json!({
                "status": "stored",
                "cursor": cursor,
                "pushed": pushed,
                "failed": failed,
                "unregistered": unregistered,
            }),
            "stored",
        ))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("messages.post", ip, started, group.as_deref(), r)
}

// ------------------------------------------------------------- heartbeat ---

/// A background push older than this is useless: the next one is due.
pub const HEARTBEAT_TTL_SECS: u64 = 900;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatReq {
    id: String,
}

/// `POST /v2/heartbeat` (Mac): wake every phone with a background push so it
/// refreshes its widgets from the mailbox. Nothing is stored.
async fn post_heartbeat(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "POST",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(Some("mac")),
        )
        .await?;
        group = Some(a.group.clone());
        require_licence(&state, &a.group).await?;
        let req: HeartbeatReq = parse(&body)?;
        if !is_token_id(&req.id) {
            return Err(bad("id must be 1 to 64 characters of A-Z a-z 0-9 _ -"));
        }
        if let Err(ra) = state.v2().limits.check_heartbeat(&a.group) {
            return Err((too_many(ra), "rate_limited_group"));
        }
        let expiration = state.now() + HEARTBEAT_TTL_SECS;
        let (pushed, failed, unregistered) = fan_out(
            &state,
            &a.group,
            a.key,
            PushContent::Background(BackgroundNote { id: req.id }),
            Urgency::Normal,
            None,
            expiration,
        )
        .await
        .map_err(storage_error)?;
        Ok(ok(
            StatusCode::OK,
            json!({
                "status": "sent",
                "pushed": pushed,
                "failed": failed,
                "unregistered": unregistered,
            }),
            "sent",
        ))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("heartbeat.post", ip, started, group.as_deref(), r)
}

/// Push to every iOS device of the group concurrently; forget dead tokens.
async fn fan_out(
    state: &AppState,
    group: &str,
    key: [u8; 32],
    content: PushContent,
    urgency: Urgency,
    collapse_id: Option<String>,
    expiration: u64,
) -> Result<(usize, usize, usize), StoreError> {
    // Suspended: nothing is pushed (presence and heartbeats included).
    if state.controls().is_suspended(group) {
        return Ok((0, 0, 0));
    }
    let v2 = state.v2();
    let g = group.to_string();
    let targets = v2.store.call(move |c| store::push_targets(c, &g)).await?;
    let mut set = JoinSet::new();
    for d in targets {
        let Some(token) = d.apns_token.clone() else {
            continue;
        };
        let job = PushJob {
            group_id: group.to_string(),
            auth_key: key,
            device_token: token,
            env: ApnsEnv::parse(&d.apns_env).unwrap_or(ApnsEnv::Production),
            content: content.clone(),
            urgency,
            collapse_id: collapse_id.clone(),
            expiration,
        };
        let sender = v2.sender.clone();
        set.spawn(async move {
            let r = sender.send(&job).await;
            (d.device_id, job.device_token, r)
        });
    }
    let (mut pushed, mut failed, mut unregistered) = (0, 0, 0);
    while let Some(res) = set.join_next().await {
        let Ok((device_id, token, r)) = res else {
            failed += 1;
            continue;
        };
        match r {
            Ok(()) => pushed += 1,
            Err(PushError::Unregistered) => {
                unregistered += 1;
                let g = group.to_string();
                if let Err(e) = v2
                    .store
                    .call(move |c| store::clear_token(c, &g, &device_id, &token))
                    .await
                {
                    tracing::error!(error = %e, "cannot clear APNs token");
                }
            }
            Err(e) => {
                failed += 1;
                match e {
                    PushError::Rejected { status, reason } => {
                        tracing::warn!(group = %group, status, reason, "APNs rejected push")
                    }
                    _ => tracing::warn!(group = %group, "APNs transport error"),
                }
            }
        }
    }
    Ok((pushed, failed, unregistered))
}

// -------------------------------------------------------------- presence ---

/// Send a presence notice to every phone of the group (best effort).
pub async fn push_presence(state: &AppState, group: &str, note: PresenceNote) {
    let g = group.to_string();
    let key = match state
        .v2()
        .store
        .call(move |c| store::group_key(c, &g))
        .await
    {
        Ok(Some(k)) => k,
        Ok(None) => {
            // Deleted meanwhile: drop what is left of its state.
            state.v2().presence.forget(group);
            state.v2().activities.forget_group(group);
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "presence: cannot load group");
            return;
        }
    };
    let online = matches!(note, PresenceNote::Online { .. });
    let limits = &state.v2().limits;
    // "Mac offline" (critical) has its own bucket (12/h), never used up by
    // online notices, and is never dropped: beyond it the notice stays
    // pending and the next presence tick retries it.
    if let PresenceNote::Offline { reason, since } = note {
        if limits.check_presence_offline(group).is_err() {
            tracing::info!(group = %group, "offline push deferred (per-group limit)");
            state.v2().presence.retry(group, reason, since, state.now());
            return;
        }
    }
    // "Back online" (silent): at most 6 per hour; beyond that the state
    // still changes and the Live Activity (silent, coalesced) is still
    // updated, but no notification is pushed.
    if online && limits.check_presence(group).is_err() {
        tracing::info!(group = %group, "online push skipped (per-group limit)");
        state
            .metrics()
            .record(Event::new("presence").group(group).outcome("rate_limited"));
    } else {
        let urgency = match note {
            PresenceNote::Offline { .. } => Urgency::Critical,
            PresenceNote::Online { .. } => Urgency::Silent,
        };
        let expiration = state.now() + PRESENCE_TTL_SECS;
        let state_label = match note {
            PresenceNote::Offline { .. } => "offline",
            PresenceNote::Online { .. } => "online",
        };
        let mut ev = Event::new("presence").group(group).outcome(state_label);
        if let PresenceNote::Offline { reason, .. } = note {
            ev = ev.detail(match reason {
                OfflineReason::Quit => "quit",
                OfflineReason::Sleep => "sleep",
                OfflineReason::Disabled => "disabled",
                OfflineReason::Lost => "lost",
            });
        }
        state.metrics().record(ev);
        match fan_out(
            state,
            group,
            key,
            PushContent::Presence(note),
            urgency,
            Some(PRESENCE_COLLAPSE_ID.to_string()),
            expiration,
        )
        .await
        {
            Ok((pushed, failed, _)) => {
                tracing::info!(group = %group, state = state_label, pushed, failed, "presence push")
            }
            Err(e) => tracing::error!(error = %e, "presence: cannot load devices"),
        }
    }
    // The Live Activity shows "Mac offline" too.
    if let Some(batch) = state.v2().activities.presence(group, online, state.now()) {
        send_activity(state, group, key, batch).await;
    }
}

/// Send every offline notice whose grace period has passed. Run periodically
/// (see `spawn_presence`) and right after a `bye`.
pub async fn presence_tick(state: &AppState) {
    let v2 = state.v2();
    let due = v2.presence.due(state.now(), |g| v2.hub.group_online(g));
    for (group, note) in due {
        push_presence(state, &group, note).await;
    }
}

// -------------------------------------------------------------- activity ---

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ActivityFanOut {
    pub pushed: usize,
    pub failed: usize,
    pub unregistered: usize,
    pub started: usize,
}

/// Push one Live Activity batch to the group's phones: `update` / `end` to
/// every running activity, and a push-to-start to phones with a start token
/// and no running activity while anything is critical.
async fn fan_out_activity(
    state: &AppState,
    group: &str,
    key: [u8; 32],
    batch: Batch,
) -> Result<ActivityFanOut, StoreError> {
    if state.controls().is_suspended(group) {
        return Ok(ActivityFanOut::default());
    }
    let v2 = state.v2();
    let now = state.now();
    let g = group.to_string();
    // iOS ends activities after 8 h: their tokens are useless now.
    let cut = now.saturating_sub(ACTIVITY_MAX_SECS);
    let tokens = v2
        .store
        .call(move |c| {
            store::delete_update_tokens(c, &g, Some(cut))?;
            store::activity_tokens(c, &g)
        })
        .await?;
    let event = batch.note.event;
    let urgency = if batch.raise || event != ActivityEvent::Update {
        Urgency::Critical
    } else {
        Urgency::Silent
    };
    let running: HashSet<&str> = tokens
        .iter()
        .filter(|t| t.kind == "update")
        .map(|t| t.device_id.as_str())
        .collect();
    let mut jobs = Vec::new();
    for t in &tokens {
        let (note, urgency) = if t.kind == "update" {
            (batch.note.clone(), urgency)
        } else if event == ActivityEvent::Update
            && batch.note.state.critical > 0
            && !running.contains(t.device_id.as_str())
            && v2.activities.may_start(group, &t.device_id, now)
        {
            let mut n = batch.note.clone();
            n.event = ActivityEvent::Start;
            (n, Urgency::Critical)
        } else {
            continue;
        };
        jobs.push((
            t.clone(),
            PushJob {
                group_id: group.to_string(),
                auth_key: key,
                device_token: t.push_token.clone(),
                env: ApnsEnv::parse(&t.apns_env).unwrap_or(ApnsEnv::Production),
                content: PushContent::Activity(note),
                urgency,
                collapse_id: None,
                expiration: now + ACTIVITY_TTL_SECS,
            },
        ));
    }
    let mut set = JoinSet::new();
    for (t, job) in jobs {
        let sender = v2.sender.clone();
        set.spawn(async move {
            let r = sender.send(&job).await;
            (t, r)
        });
    }
    let mut out = ActivityFanOut::default();
    while let Some(res) = set.join_next().await {
        let Ok((t, r)) = res else {
            out.failed += 1;
            continue;
        };
        match r {
            Ok(()) if t.kind == "start" => out.started += 1,
            Ok(()) => out.pushed += 1,
            Err(PushError::Unregistered) => {
                out.unregistered += 1;
                let g = group.to_string();
                if let Err(e) = v2
                    .store
                    .call(move |c| {
                        store::clear_activity_token(c, &g, &t.device_id, &t.kind, &t.push_token)
                    })
                    .await
                {
                    tracing::error!(error = %e, "cannot clear activity token");
                }
            }
            Err(e) => {
                out.failed += 1;
                match e {
                    PushError::Rejected { status, reason } => {
                        tracing::warn!(group = %group, status, reason, "APNs rejected activity push")
                    }
                    _ => tracing::warn!(group = %group, "APNs transport error (activity)"),
                }
            }
        }
    }
    if event == ActivityEvent::End {
        let g = group.to_string();
        v2.store
            .call(move |c| store::delete_update_tokens(c, &g, None))
            .await?;
    }
    Ok(out)
}

/// Best effort: log instead of failing (tick and presence paths).
async fn send_activity(state: &AppState, group: &str, key: [u8; 32], batch: Batch) {
    let event = batch.note.event;
    match fan_out_activity(state, group, key, batch).await {
        Ok(r) if r.pushed + r.started + r.failed + r.unregistered > 0 => tracing::info!(
            group = %group,
            event = event.as_str(),
            pushed = r.pushed,
            started = r.started,
            failed = r.failed,
            "activity push"
        ),
        Ok(_) => {}
        Err(e) => tracing::error!(error = %e, "activity: cannot load tokens"),
    }
}

/// Send every coalesced Live Activity state whose interval has passed. Run
/// periodically (see `spawn_activities`).
pub async fn activity_tick(state: &AppState) {
    let v2 = state.v2();
    for (group, batch) in v2.activities.due(state.now()) {
        let g = group.clone();
        match v2.store.call(move |c| store::group_key(c, &g)).await {
            Ok(Some(key)) => send_activity(state, &group, key, batch).await,
            Ok(None) => v2.activities.forget_group(&group),
            Err(e) => tracing::error!(error = %e, "activity: cannot load group"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivityTokenReq {
    push_token: String,
    #[serde(default)]
    apns_env: Option<String>,
    /// When the activity started (Unix seconds); default now.
    #[serde(default)]
    started_at: Option<u64>,
}

/// `PUT`/`DELETE /v2/activities/{device_id}[/start-token]` (the phone itself).
#[allow(clippy::too_many_arguments)]
async fn activity_token(
    state: Arc<AppState>,
    peer: SocketAddr,
    method: &'static str,
    kind: &'static str,
    device_id: String,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            method,
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(Some("ios")),
        )
        .await?;
        group = Some(a.group.clone());
        if a.device_id.as_deref() != Some(device_id.as_str()) {
            return Err(bad("X-MC-Device must match the device id in the path"));
        }
        let v2 = state.v2();
        let g = a.group.clone();
        if method == "DELETE" {
            let removed = v2
                .store
                .call(move |c| store::delete_activity_token(c, &g, &device_id, kind))
                .await
                .map_err(storage_error)?;
            return Ok(if removed {
                (StatusCode::NO_CONTENT.into_response(), "deleted")
            } else {
                (error(StatusCode::NOT_FOUND, "not_found"), "not_found")
            });
        }
        let req: ActivityTokenReq = parse(&body)?;
        let token = normalize_hex_token(&req.push_token, MAX_ACTIVITY_TOKEN_HEX)
            .ok_or_else(|| bad("push_token must be 64 to 512 hex characters"))?;
        let env = match req.apns_env.as_deref() {
            None => ApnsEnv::Production,
            Some(e) => {
                ApnsEnv::parse(e).ok_or_else(|| bad("apns_env must be sandbox or production"))?
            }
        };
        let now = state.now();
        // Clamped: a start in the future or over 8 h ago makes no sense.
        let started_at = req
            .started_at
            .unwrap_or(now)
            .clamp(now.saturating_sub(ACTIVITY_MAX_SECS), now);
        if kind == "update" {
            v2.activities.token_registered(&a.group, &device_id);
        }
        let created = v2
            .store
            .call(move |c| {
                store::put_activity_token(
                    c,
                    &g,
                    &device_id,
                    kind,
                    &token,
                    env.as_str(),
                    started_at,
                    now,
                )
            })
            .await
            .map_err(storage_error)?;
        Ok(if created {
            ok(StatusCode::CREATED, json!({"status": "created"}), "created")
        } else {
            ok(StatusCode::OK, json!({"status": "updated"}), "updated")
        })
    }
    .await
    .unwrap_or_else(|o| o);
    let route = match (kind, method) {
        ("update", "PUT") => "activities.put",
        ("update", _) => "activities.delete",
        (_, "PUT") => "activities.start.put",
        _ => "activities.start.delete",
    };
    finish(route, ip, started, group.as_deref(), r)
}

async fn put_activity_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(device_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    activity_token(state, peer, "PUT", "update", device_id, uri, headers, body).await
}

async fn delete_activity_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(device_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    activity_token(
        state, peer, "DELETE", "update", device_id, uri, headers, body,
    )
    .await
}

async fn put_start_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(device_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    activity_token(state, peer, "PUT", "start", device_id, uri, headers, body).await
}

async fn delete_start_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(device_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    activity_token(
        state, peer, "DELETE", "start", device_id, uri, headers, body,
    )
    .await
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateReq {
    critical: u32,
    warning: u32,
    unknown: u32,
    #[serde(default = "default_true")]
    mac_online: bool,
    #[serde(default)]
    lines: Vec<ActivityLine>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivityStateReq {
    event: ActivityEvent,
    state: StateReq,
    #[serde(default)]
    stale_secs: Option<u64>,
}

async fn post_activity_state(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "POST",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(Some("mac")),
        )
        .await?;
        group = Some(a.group.clone());
        require_licence(&state, &a.group).await?;
        let v2 = state.v2();
        if let Err(ra) = v2.limits.check_activity(&a.group) {
            return Err((too_many(ra), "rate_limited_group"));
        }
        let req: ActivityStateReq = parse(&body)?;
        if req.event == ActivityEvent::Start {
            return Err(bad("event must be update or end"));
        }
        if req
            .stale_secs
            .is_some_and(|s| !(MIN_STALE_SECS..=MAX_STALE_SECS).contains(&s))
        {
            return Err(bad("stale_secs must be 60 to 43200"));
        }
        let now = state.now();
        let cs = ContentState {
            critical: req.state.critical,
            warning: req.state.warning,
            unknown: req.state.unknown,
            mac_online: req.state.mac_online,
            updated_at: now,
            lines: req.state.lines,
        };
        cs.validate().map_err(bad)?;
        match v2
            .activities
            .offer(&a.group, req.event, cs, req.stale_secs, now)
        {
            Some(batch) => {
                let r = fan_out_activity(&state, &a.group, a.key, batch)
                    .await
                    .map_err(storage_error)?;
                Ok(ok(
                    StatusCode::OK,
                    json!({
                        "status": "sent",
                        "pushed": r.pushed,
                        "started": r.started,
                        "failed": r.failed,
                        "unregistered": r.unregistered,
                    }),
                    "sent",
                ))
            }
            None => Ok(ok(
                StatusCode::OK,
                json!({ "status": "coalesced", "send_in": v2.activities.send_in(&a.group, now) }),
                "coalesced",
            )),
        }
    }
    .await
    .unwrap_or_else(|o| o);
    finish("activity.state", ip, started, group.as_deref(), r)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SinceQuery {
    #[serde(default)]
    since: u64,
    /// Client nonce, ignored: lets identical polls in the same second carry
    /// different signatures (replay cache).
    #[serde(default, rename = "n")]
    _n: Option<String>,
}

fn since(uri: &Uri) -> Result<u64, Outcome> {
    Query::<SinceQuery>::try_from_uri(uri)
        .map(|q| q.0.since)
        .map_err(|_| bad("query must be ?since=<cursor>[&n=<nonce>]"))
}

async fn get_messages(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "GET",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(None),
        )
        .await?;
        group = Some(a.group.clone());
        let since = since(&uri)?;
        let now = state.now();
        let g = a.group.clone();
        let (rows, more) = state
            .v2()
            .store
            .call(move |c| store::messages_since(c, &g, since, now))
            .await
            .map_err(storage_error)?;
        let cursor = rows.last().map_or(since, |m| m.cursor);
        let list: Vec<_> = rows
            .into_iter()
            .map(|m| {
                json!({
                    "cursor": m.cursor,
                    "id": m.id,
                    "type": m.kind,
                    "sealed": m.sealed,
                    "urgency": m.urgency,
                    "collapse_id": m.collapse_id,
                    "received_at": m.received_at,
                })
            })
            .collect();
        Ok(ok(
            StatusCode::OK,
            json!({ "messages": list, "cursor": cursor, "more": more }),
            "listed",
        ))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("messages.get", ip, started, group.as_deref(), r)
}

// ------------------------------------------------------------- snapshot ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotReq {
    id: String,
    sealed: String,
}

async fn post_snapshot(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "POST",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(Some("mac")),
        )
        .await?;
        group = Some(a.group.clone());
        require_licence(&state, &a.group).await?;
        if let Err(ra) = state.v2().limits.check_snapshot(&a.group) {
            return Err((too_many(ra), "rate_limited_group"));
        }
        let req: SnapshotReq = parse(&body)?;
        if !is_token_id(&req.id) {
            return Err(bad("id must be 1 to 64 characters of A-Z a-z 0-9 _ -"));
        }
        let max = state.v2().snapshot_max;
        if req.sealed.len() > max {
            return Err((
                error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
                "payload_too_large",
            ));
        }
        if !is_sealed(&req.sealed, max) {
            return Err(bad(
                "sealed must be standard base64 of nonce|ciphertext|tag",
            ));
        }
        let now = state.now();
        let bytes = req.sealed.len() as u64;
        let g = a.group.clone();
        let stored = state
            .v2()
            .store
            .call(move |c| store::put_snapshot(c, &g, &req.id, &req.sealed, now))
            .await
            .map_err(storage_error)?;
        let outcome = if stored { "stored" } else { "duplicate" };
        state.metrics().record(Event {
            bytes: Some(bytes),
            ..Event::new("snapshot").group(&a.group).outcome(outcome)
        });
        Ok(ok(StatusCode::OK, json!({ "status": outcome }), outcome))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("snapshot.post", ip, started, group.as_deref(), r)
}

async fn get_snapshot(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "GET",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(None),
        )
        .await?;
        group = Some(a.group.clone());
        let now = state.now();
        let g = a.group.clone();
        let snap = state
            .v2()
            .store
            .call(move |c| store::snapshot(c, &g, now))
            .await
            .map_err(storage_error)?;
        Ok(match snap {
            Some(s) => ok(
                StatusCode::OK,
                json!({ "id": s.id, "ts": s.received_at, "sealed": s.sealed }),
                "found",
            ),
            None => (StatusCode::NO_CONTENT.into_response(), "empty"),
        })
    }
    .await
    .unwrap_or_else(|o| o);
    finish("snapshot.get", ip, started, group.as_deref(), r)
}

// -------------------------------------------------------------- commands ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandReq {
    id: String,
    sealed: String,
}

async fn post_command(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "POST",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(Some("ios")),
        )
        .await?;
        group = Some(a.group.clone());
        require_licence(&state, &a.group).await?;
        if let Err(ra) = state.v2().limits.check_commands(&a.group) {
            return Err((too_many(ra), "rate_limited_group"));
        }
        let req: CommandReq = parse(&body)?;
        if !is_token_id(&req.id) {
            return Err(bad("id must be 1 to 64 characters of A-Z a-z 0-9 _ -"));
        }
        if !is_sealed(&req.sealed, MAX_COMMAND_SEALED) {
            return Err(bad(
                "sealed must be standard base64 of nonce|ciphertext|tag, at most 8192 characters",
            ));
        }
        let now = state.now();
        let (g, id, sealed) = (a.group.clone(), req.id.clone(), req.sealed.clone());
        match state
            .v2()
            .store
            .call(move |c| store::insert_command(c, &g, &id, &sealed, now))
            .await
        {
            Ok(Insert::Stored(cursor)) => {
                let frame = CommandFrame {
                    cursor,
                    id: req.id,
                    sealed: req.sealed,
                };
                let delivered = state.v2().hub.deliver(&a.group, &frame);
                let status = if delivered { "delivered" } else { "queued" };
                Ok(ok(
                    StatusCode::OK,
                    json!({ "status": status, "delivered": delivered, "cursor": cursor }),
                    status,
                ))
            }
            Ok(Insert::Duplicate(cursor)) => Ok(ok(
                StatusCode::OK,
                json!({ "status": "duplicate", "delivered": false, "cursor": cursor }),
                "duplicate",
            )),
            Ok(Insert::Full) => Ok((
                error(StatusCode::TOO_MANY_REQUESTS, "queue_full"),
                "queue_full",
            )),
            Err(e) => Err(storage_error(e)),
        }
    }
    .await
    .unwrap_or_else(|o| o);
    finish("commands.post", ip, started, group.as_deref(), r)
}

async fn get_commands(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(&state, ip, "GET", &uri, &headers, &body, DeviceRule::Registered(Some("mac"))).await?;
        group = Some(a.group.clone());
        let since = since(&uri)?;
        let now = state.now();
        let g = a.group.clone();
        let (rows, more) = state
            .v2()
            .store
            .call(move |c| store::commands_since(c, &g, since, now, store::PAGE))
            .await
            .map_err(storage_error)?;
        let cursor = rows.last().map_or(since, |m| m.cursor);
        let list: Vec<_> = rows
            .into_iter()
            .map(|c| json!({ "cursor": c.cursor, "id": c.id, "sealed": c.sealed, "received_at": c.received_at }))
            .collect();
        Ok(ok(
            StatusCode::OK,
            json!({ "commands": list, "cursor": cursor, "more": more }),
            "listed",
        ))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("commands.get", ip, started, group.as_deref(), r)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckReq {
    cursor: u64,
}

async fn ack_command(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(
            &state,
            ip,
            "POST",
            &uri,
            &headers,
            &body,
            DeviceRule::Registered(Some("mac")),
        )
        .await?;
        group = Some(a.group.clone());
        let req: AckReq = parse(&body)?;
        let g = a.group.clone();
        let removed = state
            .v2()
            .store
            .call(move |c| store::ack_command(c, &g, req.cursor))
            .await
            .map_err(storage_error)?;
        Ok(ok(StatusCode::OK, json!({ "removed": removed }), "acked"))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("commands.ack", ip, started, group.as_deref(), r)
}

// ---------------------------------------------------------------- stream ---

async fn open_stream(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let started = Instant::now();
    let (mut parts, _body) = req.into_parts();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let ip = state.client_ip(peer, &parts.headers);
    let mut group = None;
    let r = async {
        // The upgrade request is signed like any GET: empty body.
        let a = authenticate(
            &state,
            ip,
            "GET",
            &parts.uri,
            &parts.headers,
            b"",
            DeviceRule::Registered(Some("mac")),
        )
        .await?;
        group = Some(a.group.clone());
        let device = a.device_id.clone().unwrap_or_default();
        // Same rules as `Hub::register`, so replacing the device's own
        // stream is never refused here.
        if let Err(full) = state.v2().hub.can_register(&a.group, &device, ip) {
            let status = match full {
                stream::HubFull::Server => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::TOO_MANY_REQUESTS,
            };
            return Err((error(status, full.code()), full.code()));
        }
        let ws = WebSocketUpgrade::from_request_parts(&mut parts, &state)
            .await
            .map_err(|rej| (rej.into_response(), "not_websocket"))?;
        let st = state.clone();
        let resp = ws
            .max_message_size(MAX_CLIENT_FRAME)
            .max_frame_size(MAX_CLIENT_FRAME)
            .on_upgrade(move |socket| async move {
                let v2 = st.v2();
                let close = |code: u16, reason: &'static str| {
                    axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
                        code,
                        reason: reason.into(),
                    }))
                };
                let mut socket = socket;
                // Before registering: a refusal must not replace (and so
                // close) the device's healthy stream.
                if let Err((code, reason)) = stream_allowed(&st, &a.group, &device, false).await {
                    let _ = socket.send(close(code, reason)).await;
                    return;
                }
                let reg = match v2.hub.register(&a.group, &device, ip) {
                    Ok(reg) => reg,
                    Err(_) => {
                        let _ = socket.send(close(1013, "too many streams")).await;
                        return;
                    }
                };
                if let Err((code, reason)) = admit_stream(&st, &a.group, &device, reg.id).await {
                    let _ = socket.send(close(code, reason)).await;
                    return;
                }
                stream::run(socket, st.clone(), a.group, device, reg).await
            });
        Ok((resp, "upgraded"))
    }
    .await
    .unwrap_or_else(|o| o);
    finish("stream", ip, started, group.as_deref(), r)
}

/// Whether a Mac stream of `device` may run: the group is not suspended and
/// the device still exists. `storage_error_ok`: a database error counts as
/// admitted (used for the re-check after registering, when the same check
/// just passed); otherwise it refuses with 1011.
async fn stream_allowed(
    state: &AppState,
    group: &str,
    device: &str,
    storage_error_ok: bool,
) -> Result<(), (u16, &'static str)> {
    if state.controls().is_suspended(group) {
        return Err((1008, "group suspended"));
    }
    let (g, d) = (group.to_string(), device.to_string());
    match state
        .v2()
        .store
        .call(move |c| store::device(c, &g, &d))
        .await
    {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err((1008, "unknown device")),
        Err(e) if storage_error_ok => {
            tracing::warn!(error = %e, "stream: cannot re-check device, keeping the stream");
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = %e, "stream: cannot check device");
            Err((1011, "storage error"))
        }
    }
}

/// Re-check a stream right after it registered in the hub; on refusal it
/// is unregistered and the close code and reason are returned.
///
/// The upgrade checks first ([`stream_allowed`] before registering, so a
/// refused or failing check never replaces a healthy stream of the device),
/// then again here, for the race: suspended between `authenticate` and the
/// registration (the admin sets the flag before dropping the group's
/// streams, so either that drop sees this registration or this check sees
/// the flag), or the device or group deleted meanwhile (the delete removes
/// the stream after deleting the row, so either it sees this registration
/// or this lookup misses the row). A database error here keeps the stream.
pub async fn admit_stream(
    state: &AppState,
    group: &str,
    device: &str,
    conn_id: u64,
) -> Result<(), (u16, &'static str)> {
    stream_allowed(state, group, device, true)
        .await
        .inspect_err(|_| state.v2().hub.unregister(group, device, conn_id))
}

/// 403 for gateway registrations while `GATEWAY_OPEN` is off.
fn gateway_closed() -> Outcome {
    (
        error(StatusCode::FORBIDDEN, "gateway_closed"),
        "gateway_closed",
    )
}

// --------------------------------------------------------------- gateway ---

async fn gateway_push(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let ip = state.client_ip(peer, &headers);
    let mut group = None;
    let r = async {
        let a = authenticate(&state, ip, "POST", &uri, &headers, &body, DeviceRule::None).await?;
        group = Some(a.group.clone());
        let v2 = state.v2();
        let policy = &v2.licence;
        if !policy.gateway_open() {
            return Err((
                error(StatusCode::FORBIDDEN, "gateway_closed"),
                "gateway_closed",
            ));
        }
        // Only groups registered with `gateway: true` may push to arbitrary
        // tokens; a hosted group pushes to its own devices only.
        let g = a.group.clone();
        let member = v2
            .store
            .call(move |c| store::gateway_member_licence(c, &g))
            .await;
        // A purchase revoked after registration no longer counts.
        let licensed = match member {
            Ok(Some((flag, tx))) => flag && !tx.is_some_and(|t| policy.is_tx_revoked(&t)),
            Ok(None) => {
                return Err((
                    error(StatusCode::FORBIDDEN, "not_gateway_group"),
                    "not_gateway_group",
                ))
            }
            Err(e) => return Err(storage_error(e)),
        };
        // Strict mode: membership needs a licence that counts, at every push.
        if policy.gateway_require_licence() && !licensed {
            return Err((
                error(StatusCode::PAYMENT_REQUIRED, "licence_required"),
                "gateway_licence_required",
            ));
        }
        // Per-group buckets first: a group's rejected requests use up only
        // its own quota, never the bucket shared by all gateway groups.
        if let Err(ra) = v2.limits.check_gateway(&a.group, licensed) {
            return Err((too_many(ra), "rate_limited_gateway"));
        }
        let req: GatewayPush = parse(&body)?;
        // App Store and TestFlight builds use production APNs.
        if req.env == ApnsEnv::Sandbox && !policy.gateway_apns_sandbox {
            return Err((
                invalid("env sandbox is not accepted by this gateway"),
                "sandbox_refused",
            ));
        }
        let token = normalize_apns_token(&req.device_token)
            .ok_or_else(|| bad("device_token must be 64 to 200 hex characters"))?;
        let now = state.now();
        let content = match (req.message, req.presence, req.activity, req.background) {
            (Some(m), None, None, None) => {
                if !is_token_id(&m.id)
                    || !is_sealed(&m.s, MAX_PAYLOAD_BYTES)
                    || m.t == MessageType::Summary
                {
                    return Err(bad(
                        "message must be {id, t, s} with a valid id and sealed box",
                    ));
                }
                PushContent::Sealed(m)
            }
            (None, Some(p), None, None) => PushContent::Presence(p),
            (None, None, None, Some(b)) => {
                if !is_token_id(&b.id) {
                    return Err(bad("background must be {id} with a valid id"));
                }
                PushContent::Background(b)
            }
            (None, None, Some(mut n), None) => {
                n.state.validate().map_err(bad)?;
                let near = |t: u64| t.abs_diff(now) <= MAX_TTL_SECS;
                if !near(n.timestamp)
                    || !n.stale_date.map_or(true, near)
                    || !n.dismissal_date.map_or(true, near)
                {
                    return Err(bad("activity times must be within 24 h of now"));
                }
                // Host / service lines are plaintext on the Lock Screen: a
                // gateway caller could otherwise show any text there.
                if !policy.gateway_activity_lines {
                    n.state.lines.clear();
                }
                PushContent::Activity(n)
            }
            _ => {
                return Err(bad(
                    "exactly one of message, presence, activity or background is required",
                ))
            }
        };
        if req.collapse_id.as_deref().is_some_and(|c| !is_token_id(c)) {
            return Err(bad(
                "collapse_id must be 1 to 64 characters of A-Z a-z 0-9 _ -",
            ));
        }
        if req.expiration != 0 && req.expiration > now + MAX_TTL_SECS {
            return Err(bad("expiration must be 0 or at most 24 h ahead"));
        }
        // The gateway builds the payload itself (fixed presence, heartbeat and
        // push-to-start texts, Live Activity lines dropped unless
        // GATEWAY_ACTIVITY_LINES), so it cannot be used to send arbitrary
        // notification text.
        let payload_len = match &content {
            PushContent::Sealed(m) => build_payload(m, req.urgency).len(),
            PushContent::Presence(p) => build_presence_payload(*p).len(),
            PushContent::Activity(n) => activity::build_activity_payload(n).len(),
            PushContent::Background(b) => build_background_payload(b).len(),
        };
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err((
                error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
                "payload_too_large",
            ));
        }
        // The token must not belong to a hosted user or to another gateway
        // group that used it in the last 24 h.
        let (g, t, st) = (a.group.clone(), token.clone(), state.clone());
        let max_tokens = policy.gateway_max_tokens_per_group();
        let bound = v2
            .store
            .call(move |c| {
                store::bind_gateway_token(c, &g, &t, now, max_tokens, || {
                    st.v2().limits.check_gateway_rebind(&g).is_ok()
                })
            })
            .await
            .map_err(storage_error)?;
        match bound {
            Bind::Bound => {}
            Bind::TakenElsewhere => {
                return Err((error(StatusCode::FORBIDDEN, "token_bound"), "token_bound"))
            }
            Bind::TokenLimit => {
                return Err((
                    error(StatusCode::TOO_MANY_REQUESTS, "token_limit"),
                    "token_limit",
                ))
            }
            Bind::RebindLimit => {
                return Err((
                    error(StatusCode::TOO_MANY_REQUESTS, "rebind_limit"),
                    "rebind_limit",
                ))
            }
        }
        // Charged only for a push that will really be sent.
        if let Err(ra) = v2.limits.check_gateway_global() {
            return Err((too_many(ra), "rate_limited_gateway_global"));
        }
        // Fail fast instead of queueing behind a slow APNs.
        let Ok(_permit) = v2.gateway_sends.try_acquire() else {
            let mut r = error(StatusCode::SERVICE_UNAVAILABLE, "gateway_busy");
            r.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("1"),
            );
            return Err((r, "gateway_busy"));
        };
        let job = PushJob {
            group_id: a.group.clone(),
            auth_key: a.key,
            device_token: token.clone(),
            env: req.env,
            content,
            urgency: req.urgency,
            collapse_id: req.collapse_id,
            expiration: req.expiration,
        };
        let unbind = |token: String| {
            let g = a.group.clone();
            async move {
                if let Err(e) = v2
                    .store
                    .call(move |c| store::unbind_gateway_token(c, &g, &token))
                    .await
                {
                    tracing::error!(error = %e, "gateway: cannot forget token binding");
                }
            }
        };
        match v2.sender.send(&job).await {
            Ok(()) => Ok(ok(StatusCode::OK, json!({"status": "sent"}), "sent")),
            Err(PushError::Unregistered) => {
                unbind(token).await;
                Ok((error(StatusCode::GONE, "unregistered"), "unregistered"))
            }
            Err(PushError::Rejected { status, reason }) => {
                tracing::warn!(status, reason, "gateway: APNs rejected push");
                // A token APNs will never accept must not keep its slot.
                if matches!(reason.as_str(), "BadDeviceToken" | "DeviceTokenNotForTopic") {
                    unbind(token).await;
                }
                Ok((
                    error(StatusCode::BAD_GATEWAY, "upstream_error"),
                    "upstream_error",
                ))
            }
            Err(PushError::Transport) => Ok((
                error(StatusCode::BAD_GATEWAY, "upstream_error"),
                "upstream_error",
            )),
        }
    }
    .await
    .unwrap_or_else(|o| o);
    finish("gateway.push", ip, started, group.as_deref(), r)
}

// ----------------------------------------------------------------- debug ---

/// `APNS_MODE=mock` only: the recorded pushes. Unauthenticated, local dev:
/// only for loopback peers (the TCP peer, never a forwarded header), so a
/// mock-mode server reachable from the network does not hand out device
/// tokens and envelopes.
async fn debug_pushes(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    if !peer.ip().to_canonical().is_loopback() {
        return error(StatusCode::NOT_FOUND, "not_found");
    }
    match &state.v2().mock {
        Some(m) => Json(json!({ "pushes": m.pushes() })).into_response(),
        None => error(StatusCode::NOT_FOUND, "not_found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_validation() {
        assert!(is_id128("AAAAAAAAAAAAAAAAAAAAAA"));
        assert!(is_id128("_-_-_-_-_-_-_-_-_-_-_w"));
        assert!(
            !is_id128("AAAAAAAAAAAAAAAAAAAAAB"),
            "non-canonical trailing bits"
        );
        assert!(!is_id128("AAAAAAAAAAAAAAAAAAAAA"));
        assert!(!is_id128("AAAAAAAAAAAAAAAAAAAAAA=="));
        assert!(!is_id128("AAAAAAAAAAAAAAAAAAAA+/"));
        assert!(is_token_id("abc-_9"));
        assert!(!is_token_id(""));
        assert!(!is_token_id(&"a".repeat(65)));
        assert!(!is_token_id("a b"));
    }

    #[test]
    fn sealed_and_token_validation() {
        let min = STANDARD.encode([0u8; 28]);
        assert!(is_sealed(&min, 100));
        assert!(!is_sealed(&STANDARD.encode([0u8; 27]), 100));
        assert!(!is_sealed(&min, 10));
        assert!(!is_sealed("not base64!", 100));
        assert_eq!(
            normalize_apns_token(&"AB".repeat(32)),
            Some("ab".repeat(32))
        );
        assert_eq!(normalize_apns_token(&"a".repeat(63)), None);
        assert_eq!(normalize_apns_token(&"g".repeat(64)), None);
        assert!(is_name("Jacek's iPhone"));
        assert!(!is_name(""));
        assert!(!is_name("a\nb"));
    }
}
