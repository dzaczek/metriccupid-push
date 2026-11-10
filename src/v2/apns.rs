//! APNs delivery: payload construction and three senders.
//!
//! - [`DirectApns`]: HTTP/2 to Apple with an ES256 provider token.
//! - [`MockApns`]: records pushes in memory (tests, `APNS_MODE=mock`).
//! - [`GatewayApns`]: forwards push jobs to a hosted gateway, signed with the
//!   group's own `auth_key` (PROTOCOL.md, "Gateway").
//!
//! Never log tokens or payloads.

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::activity::{build_activity_payload, ActivityNote, TOPIC_SUFFIX};
use crate::auth::{sign_v2, SIGNATURE_HEADER, TIMESTAMP_HEADER};
use crate::config::ApnsKey;
use crate::limits::Clock;

/// APNs rejects payloads larger than this (bytes of the JSON body).
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// Apple accepts provider tokens for up to 1 h and throttles refreshes more
/// often than every 20 min.
pub const TOKEN_REFRESH_SECS: u64 = 50 * 60;
pub const GROUP_HEADER: &str = "x-mc-group";
pub const DEVICE_HEADER: &str = "x-mc-device";
pub const GATEWAY_PUSH_PATH: &str = "/v2/gateway/push";
pub const GROUPS_PATH: &str = "/v2/groups";

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApnsEnv {
    Sandbox,
    Production,
}

impl ApnsEnv {
    pub fn as_str(self) -> &'static str {
        match self {
            ApnsEnv::Sandbox => "sandbox",
            ApnsEnv::Production => "production",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sandbox" => Some(ApnsEnv::Sandbox),
            "production" => Some(ApnsEnv::Production),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Urgency {
    Critical,
    Normal,
    Silent,
}

impl Urgency {
    pub fn as_str(self) -> &'static str {
        match self {
            Urgency::Critical => "critical",
            Urgency::Normal => "normal",
            Urgency::Silent => "silent",
        }
    }

    /// `apns-priority`: 10 = immediate, 5 = power-friendly.
    pub fn priority(self) -> u8 {
        match self {
            Urgency::Silent => 5,
            _ => 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Alert,
    Result,
    /// Counts and newest alerts for the phone's widget: mailbox only, never pushed.
    Summary,
}

impl MessageType {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageType::Alert => "alert",
            MessageType::Result => "result",
            MessageType::Summary => "summary",
        }
    }

    pub fn category(self) -> &'static str {
        match self {
            MessageType::Alert => "MC_ALERT",
            MessageType::Result => "MC_RESULT",
            MessageType::Summary => "MC_SUMMARY",
        }
    }

    /// Placeholder body shown if the Notification Service Extension cannot
    /// decrypt in time. Never contains alert data.
    pub fn fallback_body(self) -> &'static str {
        match self {
            MessageType::Alert => "New alert",
            MessageType::Result => "Command result",
            MessageType::Summary => "Status update",
        }
    }
}

/// The `mc` object of the APNs payload: everything the phone needs to decrypt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McEnvelope {
    pub id: String,
    pub t: MessageType,
    pub s: String,
}

/// Build the APNs JSON payload (PROTOCOL.md, "APNs payload").
pub fn build_payload(mc: &McEnvelope, urgency: Urgency) -> String {
    let mut aps = json!({
        "alert": { "title": "MetricCupid", "body": mc.t.fallback_body() },
        "mutable-content": 1,
        "category": mc.t.category(),
        "thread-id": "mc",
    });
    if urgency != Urgency::Silent {
        aps["sound"] = json!("default");
    }
    if urgency == Urgency::Critical {
        aps["interruption-level"] = json!("time-sensitive");
    }
    json!({ "aps": aps, "mc": mc }).to_string()
}

/// Why the last Mac of a group went offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OfflineReason {
    /// The app was quit (`bye`).
    Quit,
    /// The Mac went to sleep (`bye`).
    Sleep,
    /// Phone & Watch was turned off in the app (`bye`).
    Disabled,
    /// The stream dropped without a `bye` and stayed down for the grace period.
    Lost,
}

/// A server-generated presence notice (PROTOCOL.md, "Presence"). Contains no
/// alert content, so it is sent in plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum PresenceNote {
    Offline { reason: OfflineReason, since: u64 },
    Online { since: u64 },
}

pub const PRESENCE_COLLAPSE_ID: &str = "mc-presence";
pub const PRESENCE_CATEGORY: &str = "MC_PRESENCE";

impl PresenceNote {
    pub fn title(self) -> &'static str {
        match self {
            PresenceNote::Offline { .. } => "MetricCupid is offline on your Mac",
            PresenceNote::Online { .. } => "MetricCupid is back online",
        }
    }

    pub fn body(self) -> &'static str {
        match self {
            PresenceNote::Offline { reason, .. } => match reason {
                OfflineReason::Quit => {
                    "MetricCupid was quit. Alerts won't reach this iPhone until it's back."
                }
                OfflineReason::Sleep => {
                    "Your Mac went to sleep. Alerts won't reach this iPhone until it wakes."
                }
                OfflineReason::Disabled => {
                    "Phone & Watch was turned off on the Mac. Alerts won't reach this iPhone until it's back on."
                }
                OfflineReason::Lost => {
                    "The connection to your Mac was lost. Alerts won't reach this iPhone until it's back."
                }
            },
            PresenceNote::Online { .. } => "Alerts from your Mac reach this iPhone again.",
        }
    }
}

/// Build the APNs payload of a presence notice. No `mutable-content`: the
/// Notification Service Extension does not run for it.
pub fn build_presence_payload(note: PresenceNote) -> String {
    let mut aps = json!({
        "alert": { "title": note.title(), "body": note.body() },
        "category": PRESENCE_CATEGORY,
        "thread-id": PRESENCE_COLLAPSE_ID,
    });
    match note {
        PresenceNote::Offline { .. } => {
            aps["sound"] = json!("default");
            aps["interruption-level"] = json!("time-sensitive");
        }
        PresenceNote::Online { .. } => aps["interruption-level"] = json!("passive"),
    }
    json!({ "aps": aps, "mc_presence": note }).to_string()
}

/// A background (`content-available`) push that wakes the phone app so it
/// refreshes widgets from the mailbox (PROTOCOL.md, "Heartbeat"). Carries no
/// alert content and shows nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundNote {
    pub id: String,
}

/// `mc.t` of a background push.
pub const BACKGROUND_TYPE: &str = "heartbeat";

/// Build the APNs payload of a background push: no alert, sound or badge.
pub fn build_background_payload(note: &BackgroundNote) -> String {
    json!({
        "aps": { "content-available": 1 },
        "mc": { "id": note.id, "t": BACKGROUND_TYPE },
    })
    .to_string()
}

/// What a push carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushContent {
    /// A sealed message from the Mac.
    Sealed(McEnvelope),
    /// A server-generated presence notice.
    Presence(PresenceNote),
    /// A Live Activity update, start or end (`apns-push-type: liveactivity`).
    Activity(ActivityNote),
    /// A background wake-up (`apns-push-type: background`).
    Background(BackgroundNote),
}

/// One push to one device.
#[derive(Clone)]
pub struct PushJob {
    pub group_id: String,
    /// Group HMAC key; only the gateway sender uses it (to sign the job).
    pub auth_key: [u8; 32],
    pub device_token: String,
    pub env: ApnsEnv,
    pub content: PushContent,
    /// Activities: `Critical` = priority 10 (critical count went up, start,
    /// end), anything else 5.
    pub urgency: Urgency,
    pub collapse_id: Option<String>,
    /// Unix seconds; 0 = deliver once, do not store.
    pub expiration: u64,
}

impl PushJob {
    pub fn payload(&self) -> String {
        match &self.content {
            PushContent::Sealed(mc) => build_payload(mc, self.urgency),
            PushContent::Presence(note) => build_presence_payload(*note),
            PushContent::Activity(note) => build_activity_payload(note),
            PushContent::Background(note) => build_background_payload(note),
        }
    }

    pub fn priority(&self) -> u8 {
        match self.content {
            PushContent::Sealed(_) => self.urgency.priority(),
            PushContent::Presence(PresenceNote::Offline { .. }) => 10,
            PushContent::Presence(PresenceNote::Online { .. }) => 5,
            PushContent::Activity(_) if self.urgency == Urgency::Critical => 10,
            PushContent::Activity(_) => 5,
            // Apple requires 5 for background pushes.
            PushContent::Background(_) => 5,
        }
    }

    /// `apns-push-type`.
    pub fn push_type(&self) -> &'static str {
        match self.content {
            PushContent::Activity(_) => "liveactivity",
            PushContent::Background(_) => "background",
            _ => "alert",
        }
    }

    /// Appended to the app's bundle id for `apns-topic`.
    pub fn topic_suffix(&self) -> &'static str {
        match self.content {
            PushContent::Activity(_) => TOPIC_SUFFIX,
            _ => "",
        }
    }

    fn kind(&self) -> &'static str {
        match &self.content {
            PushContent::Sealed(mc) => mc.t.as_str(),
            PushContent::Presence(_) => "presence",
            PushContent::Activity(_) => "activity",
            PushContent::Background(_) => "background",
        }
    }
}

impl fmt::Debug for PushJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushJob")
            .field("group_id", &self.group_id)
            .field("env", &self.env)
            .field("type", &self.kind())
            .field("urgency", &self.urgency)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError {
    /// The token is no longer valid (410, or 400 BadDeviceToken): forget it.
    Unregistered,
    /// APNs (or the gateway) rejected the push.
    Rejected { status: u16, reason: String },
    /// Network error or timeout.
    Transport,
}

pub trait ApnsSender: Send + Sync + 'static {
    fn send<'a>(&'a self, job: &'a PushJob) -> BoxFuture<'a, Result<(), PushError>>;
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("metriccupid-push/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("cannot build HTTP client: {e}"))
}

#[derive(Deserialize)]
struct ApnsErrorBody {
    reason: String,
}

// ---------------------------------------------------------------- direct ---

pub struct DirectApns {
    http: reqwest::Client,
    key: EcdsaKeyPair,
    rng: SystemRandom,
    key_id: String,
    team_id: String,
    topic: String,
    production_url: String,
    sandbox_url: String,
    clock: Arc<dyn Clock>,
    token: Mutex<Option<(u64, String)>>,
}

/// Decode a PEM block (e.g. an Apple `.p8` file) to DER.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    STANDARD
        .decode(body)
        .map_err(|_| "APNS_KEY_P8 is not valid PEM".to_string())
}

impl DirectApns {
    pub fn new(
        key: &ApnsKey,
        topic: String,
        production_url: String,
        sandbox_url: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, String> {
        let rng = SystemRandom::new();
        let der = pem_to_der(&key.pem)?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
            .map_err(|_| "APNS_KEY_P8 is not a PKCS#8 P-256 private key".to_string())?;
        let http = reqwest::Client::builder()
            .http2_prior_knowledge()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Duration::from_secs(60))
            .http2_keep_alive_while_idle(true)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("metriccupid-push/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("cannot build HTTP/2 client: {e}"))?;
        Ok(Self {
            http,
            key: pair,
            rng,
            key_id: key.key_id.clone(),
            team_id: key.team_id.clone(),
            topic,
            production_url,
            sandbox_url,
            clock,
            token: Mutex::new(None),
        })
    }

    /// ES256 provider JWT: `{"alg":"ES256","kid":KEY_ID}.{"iss":TEAM_ID,"iat":now}`.
    pub fn make_jwt(&self, iat: u64) -> Result<String, PushError> {
        let header = URL_SAFE_NO_PAD.encode(
            json!({ "alg": "ES256", "kid": self.key_id })
                .to_string()
                .as_bytes(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            json!({ "iss": self.team_id, "iat": iat })
                .to_string()
                .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let sig = self
            .key
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|_| PushError::Transport)?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(sig.as_ref())
        ))
    }

    /// The cached provider token, refreshed every [`TOKEN_REFRESH_SECS`].
    pub fn provider_token(&self) -> Result<String, PushError> {
        let now = self.clock.now();
        let mut cached = self.token.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((iat, t)) = cached.as_ref() {
            if now.saturating_sub(*iat) < TOKEN_REFRESH_SECS && *iat <= now {
                return Ok(t.clone());
            }
        }
        let t = self.make_jwt(now)?;
        *cached = Some((now, t.clone()));
        Ok(t)
    }

    fn invalidate_token(&self) {
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    async fn send_inner(&self, job: &PushJob) -> Result<(), PushError> {
        let base = match job.env {
            ApnsEnv::Production => &self.production_url,
            ApnsEnv::Sandbox => &self.sandbox_url,
        };
        let token = self.provider_token()?;
        let mut req = self
            .http
            .post(format!("{base}/3/device/{}", job.device_token))
            .header("authorization", format!("bearer {token}"))
            .header(
                "apns-topic",
                format!("{}{}", self.topic, job.topic_suffix()),
            )
            .header("apns-push-type", job.push_type())
            .header("apns-priority", job.priority().to_string())
            .header("apns-expiration", job.expiration.to_string())
            .header("content-type", "application/json")
            .body(job.payload());
        if let Some(c) = &job.collapse_id {
            req = req.header("apns-collapse-id", c);
        }
        let resp = req.send().await.map_err(|_| PushError::Transport)?;
        let status = resp.status().as_u16();
        if status == 200 {
            return Ok(());
        }
        let reason = resp
            .bytes()
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<ApnsErrorBody>(&b).ok())
            .map(|b| b.reason)
            .unwrap_or_default();
        if status == 410 || (status == 400 && reason == "BadDeviceToken") {
            return Err(PushError::Unregistered);
        }
        if status == 403 && reason == "ExpiredProviderToken" {
            self.invalidate_token();
        }
        Err(PushError::Rejected { status, reason })
    }
}

impl ApnsSender for DirectApns {
    fn send<'a>(&'a self, job: &'a PushJob) -> BoxFuture<'a, Result<(), PushError>> {
        Box::pin(self.send_inner(job))
    }
}

// ------------------------------------------------------------------ mock ---

/// A push recorded by [`MockApns`].
#[derive(Debug, Clone, Serialize)]
pub struct RecordedPush {
    pub group_id: String,
    pub device_token: String,
    pub env: ApnsEnv,
    pub priority: u8,
    pub push_type: &'static str,
    /// `.push-type.liveactivity` for Live Activities, else empty.
    pub topic_suffix: &'static str,
    pub collapse_id: Option<String>,
    pub expiration: u64,
    pub payload: Value,
    /// `sent` or `unregistered`.
    pub outcome: &'static str,
}

/// Keeps at most this many recorded pushes (oldest dropped).
pub const MOCK_CAP: usize = 1000;

#[derive(Default)]
pub struct MockApns {
    pushes: Mutex<Vec<RecordedPush>>,
    unregistered: Mutex<HashSet<String>>,
}

impl MockApns {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every later push to `token` fail like APNs 410 Unregistered.
    pub fn mark_unregistered(&self, token: &str) {
        self.unregistered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token.to_ascii_lowercase());
    }

    pub fn pushes(&self) -> Vec<RecordedPush> {
        self.pushes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn clear(&self) {
        self.pushes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

impl ApnsSender for MockApns {
    fn send<'a>(&'a self, job: &'a PushJob) -> BoxFuture<'a, Result<(), PushError>> {
        Box::pin(async move {
            let gone = self
                .unregistered
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&job.device_token);
            let payload: Value = serde_json::from_str(&job.payload()).unwrap_or(Value::Null);
            let mut pushes = self.pushes.lock().unwrap_or_else(|e| e.into_inner());
            if pushes.len() >= MOCK_CAP {
                pushes.remove(0);
            }
            pushes.push(RecordedPush {
                group_id: job.group_id.clone(),
                device_token: job.device_token.clone(),
                env: job.env,
                priority: job.priority(),
                push_type: job.push_type(),
                topic_suffix: job.topic_suffix(),
                collapse_id: job.collapse_id.clone(),
                expiration: job.expiration,
                payload,
                outcome: if gone { "unregistered" } else { "sent" },
            });
            if gone {
                Err(PushError::Unregistered)
            } else {
                Ok(())
            }
        })
    }
}

// --------------------------------------------------------------- gateway ---

/// Body of `POST /v2/gateway/push`: exactly one of `message`, `presence`,
/// `activity` or `background`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayPush {
    pub device_token: String,
    pub env: ApnsEnv,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<McEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<PresenceNote>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<ActivityNote>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background: Option<BackgroundNote>,
    pub urgency: Urgency,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapse_id: Option<String>,
    pub expiration: u64,
}

/// Outcome of forwarding a group registration to the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayRegistration {
    /// 200 or 201.
    Ok,
    /// Any other HTTP status from the gateway.
    Status(u16),
    Transport,
}

pub struct GatewayApns {
    http: reqwest::Client,
    base_url: String,
    clock: Arc<dyn Clock>,
}

impl GatewayApns {
    pub fn new(base_url: String, clock: Arc<dyn Clock>) -> Result<Self, String> {
        Ok(Self {
            http: http_client()?,
            base_url,
            clock,
        })
    }

    /// Register the group (`group_id` + `auth_key`) with the gateway so it
    /// accepts our signed push jobs.
    pub async fn register_group(&self, body: &Value) -> GatewayRegistration {
        let resp = self
            .http
            .post(format!("{}{GROUPS_PATH}", self.base_url))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await;
        match resp {
            Ok(r) if matches!(r.status().as_u16(), 200 | 201) => GatewayRegistration::Ok,
            Ok(r) => GatewayRegistration::Status(r.status().as_u16()),
            Err(_) => GatewayRegistration::Transport,
        }
    }

    async fn send_inner(&self, job: &PushJob) -> Result<(), PushError> {
        let (mut message, mut presence, mut activity, mut background) = (None, None, None, None);
        match &job.content {
            PushContent::Sealed(mc) => message = Some(mc.clone()),
            PushContent::Presence(note) => presence = Some(*note),
            PushContent::Activity(note) => activity = Some(note.clone()),
            PushContent::Background(note) => background = Some(note.clone()),
        }
        let body = serde_json::to_string(&GatewayPush {
            device_token: job.device_token.clone(),
            env: job.env,
            message,
            presence,
            activity,
            background,
            urgency: job.urgency,
            collapse_id: job.collapse_id.clone(),
            expiration: job.expiration,
        })
        .map_err(|_| PushError::Transport)?;
        let ts = self.clock.now().to_string();
        // Server-to-server: no device, so the device line is empty.
        let sig = sign_v2(
            &job.auth_key,
            &ts,
            "POST",
            GATEWAY_PUSH_PATH,
            &job.group_id,
            "",
            body.as_bytes(),
        );
        let resp = self
            .http
            .post(format!("{}{GATEWAY_PUSH_PATH}", self.base_url))
            .header("content-type", "application/json")
            .header(TIMESTAMP_HEADER, ts)
            .header(SIGNATURE_HEADER, sig)
            .header(GROUP_HEADER, &job.group_id)
            .body(body)
            .send()
            .await
            .map_err(|_| PushError::Transport)?;
        match resp.status().as_u16() {
            200 => Ok(()),
            410 => Err(PushError::Unregistered),
            status => Err(PushError::Rejected {
                status,
                reason: "gateway".into(),
            }),
        }
    }
}

impl ApnsSender for GatewayApns {
    fn send<'a>(&'a self, job: &'a PushJob) -> BoxFuture<'a, Result<(), PushError>> {
        Box::pin(self.send_inner(job))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mc(t: MessageType) -> McEnvelope {
        McEnvelope {
            id: "m1".into(),
            t,
            s: "c2VhbGVk".into(),
        }
    }

    #[test]
    fn payload_shape_alert_critical() {
        let p: Value =
            serde_json::from_str(&build_payload(&mc(MessageType::Alert), Urgency::Critical))
                .unwrap();
        assert_eq!(
            p,
            json!({
                "aps": {
                    "alert": {"title": "MetricCupid", "body": "New alert"},
                    "mutable-content": 1,
                    "category": "MC_ALERT",
                    "sound": "default",
                    "interruption-level": "time-sensitive",
                    "thread-id": "mc"
                },
                "mc": {"id": "m1", "t": "alert", "s": "c2VhbGVk"}
            })
        );
    }

    #[test]
    fn payload_shape_result_silent() {
        let p: Value =
            serde_json::from_str(&build_payload(&mc(MessageType::Result), Urgency::Silent))
                .unwrap();
        assert_eq!(p["aps"]["category"], "MC_RESULT");
        assert!(p["aps"].get("sound").is_none());
        assert!(p["aps"].get("interruption-level").is_none());
        assert_eq!(Urgency::Silent.priority(), 5);
        assert_eq!(Urgency::Normal.priority(), 10);
    }

    #[test]
    fn presence_payload_shape() {
        let off = PresenceNote::Offline {
            reason: OfflineReason::Quit,
            since: 7,
        };
        let p: Value = serde_json::from_str(&build_presence_payload(off)).unwrap();
        assert_eq!(p["aps"]["category"], "MC_PRESENCE");
        assert_eq!(p["aps"]["thread-id"], "mc-presence");
        assert_eq!(p["aps"]["interruption-level"], "time-sensitive");
        assert_eq!(
            p["aps"]["alert"]["title"],
            "MetricCupid is offline on your Mac"
        );
        assert!(p["aps"].get("mutable-content").is_none());
        assert!(p.get("mc").is_none());
        assert_eq!(
            p["mc_presence"],
            json!({"state": "offline", "reason": "quit", "since": 7})
        );
        let on: Value =
            serde_json::from_str(&build_presence_payload(PresenceNote::Online { since: 9 }))
                .unwrap();
        assert_eq!(on["aps"]["interruption-level"], "passive");
        assert!(on["aps"].get("sound").is_none());
        assert_eq!(on["mc_presence"], json!({"state": "online", "since": 9}));
    }

    #[test]
    fn background_payload_shape_and_headers() {
        let job = PushJob {
            group_id: "g".into(),
            auth_key: [0; 32],
            device_token: "aa".into(),
            env: ApnsEnv::Production,
            content: PushContent::Background(BackgroundNote { id: "hb-1".into() }),
            urgency: Urgency::Normal,
            collapse_id: None,
            expiration: 0,
        };
        let p: Value = serde_json::from_str(&job.payload()).unwrap();
        assert_eq!(
            p,
            json!({"aps": {"content-available": 1}, "mc": {"id": "hb-1", "t": "heartbeat"}})
        );
        assert_eq!(job.push_type(), "background");
        assert_eq!(job.priority(), 5);
        assert_eq!(job.topic_suffix(), "");
    }

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now(&self) -> u64 {
            self.0
        }
    }

    /// A throwaway P-256 key generated with
    /// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`.
    pub const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgK3+wXOj+qYgmDXHT
dXDtSfYRru5XrivdGSaIelKtBIihRANCAATny1mZsG6/AJ9r8YVdLlKrMJ4CpQzB
qH5wknmWfGBuaGI8bgJl7LXE1/fX2hgWgqlvm8qTWphAY+IOe7CMedwq
-----END PRIVATE KEY-----";

    fn direct() -> DirectApns {
        DirectApns::new(
            &ApnsKey {
                pem: TEST_P8.into(),
                key_id: "ABCDE12345".into(),
                team_id: "TEAM123456".into(),
            },
            "cat.sysop.MetricCupid".into(),
            "http://127.0.0.1:1".into(),
            "http://127.0.0.1:1".into(),
            Arc::new(FixedClock(1_700_000_000)),
        )
        .unwrap()
    }

    #[test]
    fn jwt_is_es256_and_verifies() {
        let d = direct();
        let jwt = d.make_jwt(1_700_000_000).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header, json!({"alg": "ES256", "kid": "ABCDE12345"}));
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            claims,
            json!({"iss": "TEAM123456", "iat": 1_700_000_000u64})
        );
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig.len(), 64, "JWS ES256 is raw r||s");
        use ring::signature::{KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
        let pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, d.key.public_key().as_ref());
        pk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .unwrap();
    }

    #[test]
    fn provider_token_is_cached() {
        let d = direct();
        let a = d.provider_token().unwrap();
        assert_eq!(a, d.provider_token().unwrap());
        d.invalidate_token();
        // ECDSA signatures are randomized, so a fresh token differs.
        assert_ne!(a, d.provider_token().unwrap());
    }

    #[test]
    fn bad_key_rejected() {
        let r = DirectApns::new(
            &ApnsKey {
                pem: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----".into(),
                key_id: "ABCDE12345".into(),
                team_id: "TEAM123456".into(),
            },
            "t".into(),
            "http://x".into(),
            "http://x".into(),
            Arc::new(FixedClock(0)),
        );
        assert!(r.is_err());
    }
}
