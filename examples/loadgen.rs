//! Local load generator for a server with `MODE=hosted`, `APNS_MODE=mock`,
//! `LICENCE_MODE=open` and `TRUST_PROXY=xff:127.0.0.1/32` (each simulated
//! user gets its own `X-Forwarded-For` address). Normally started by
//! `scripts/loadtest.sh`, which also starts and samples the server:
//!
//!   cargo run --release --example loadgen -- --n 100 --duration 150
//!
//! Options (each also as env `LOADGEN_<NAME>`, upper case):
//!   --url URL            server (default http://127.0.0.1:18080)
//!   --n N                users; each is 1 Mac (stream) + 2 phones (default 10)
//!   --duration SECS      steady phase (default 150)
//!   --ramp SECS          spread user setup over this long (default 60, 10 below 100 users)
//!   --compress F         time compression of the modelled rates (default 10)
//!   --scenario S         ramp-steady | alert-storm | reconnect-storm | abuse
//!   --pid-file PATH      server pid, sampled every second (RSS, CPU, fds)
//!   --restart-cmd CMD    reconnect-storm: shell command that SIGKILLs and restarts the server
//!   --out PATH           JSON report (default target/loadtest/<N>[-<scenario>].json)
//!   --server-env TEXT    recorded in the report as-is
//!
//! Traffic per user follows PLAN-hardening-scaling.md section B, divided by
//! `--compress` (WebSocket pings stay at the real 25 s). Exits 1 when an SLO
//! of section C fails, 2 on bad arguments.

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message;

// ------------------------------------------------------------ settings ---

#[derive(Clone)]
struct Args {
    url: String,
    n: usize,
    duration: u64,
    ramp: u64,
    compress: f64,
    scenario: String,
    pid_file: Option<String>,
    restart_cmd: Option<String>,
    out: String,
    server_env: String,
}

fn parse_args() -> Args {
    let mut kv: HashMap<String, String> = HashMap::new();
    for (k, v) in std::env::vars() {
        if let Some(name) = k.strip_prefix("LOADGEN_") {
            kv.insert(name.to_ascii_lowercase().replace('_', "-"), v);
        }
    }
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let Some(name) = a.strip_prefix("--") else {
            usage(&format!("unexpected argument {a}"));
        };
        let v = it
            .next()
            .unwrap_or_else(|| usage(&format!("--{name} needs a value")));
        kv.insert(name.to_string(), v);
    }
    let num = |k: &str, d: f64| -> f64 {
        kv.get(k).map_or(d, |v| {
            v.parse()
                .unwrap_or_else(|_| usage(&format!("--{k} must be a number")))
        })
    };
    let n = num("n", 10.0) as usize;
    let scenario = kv
        .get("scenario")
        .cloned()
        .unwrap_or_else(|| "ramp-steady".into());
    if !["ramp-steady", "alert-storm", "reconnect-storm", "abuse"].contains(&scenario.as_str()) {
        usage("--scenario must be ramp-steady, alert-storm, reconnect-storm or abuse");
    }
    let suffix = if scenario == "ramp-steady" {
        String::new()
    } else {
        format!("-{scenario}")
    };
    Args {
        url: kv
            .get("url")
            .cloned()
            .unwrap_or_else(|| "http://127.0.0.1:18080".into()),
        n: n.max(1),
        duration: num("duration", 150.0) as u64,
        ramp: num("ramp", if n >= 100 { 60.0 } else { 10.0 }) as u64,
        compress: num("compress", 10.0).max(0.01),
        out: kv
            .get("out")
            .cloned()
            .unwrap_or_else(|| format!("target/loadtest/{n}{suffix}.json")),
        pid_file: kv.get("pid-file").cloned(),
        restart_cmd: kv.get("restart-cmd").cloned(),
        server_env: kv.get("server-env").cloned().unwrap_or_default(),
        scenario,
    }
}

fn usage(msg: &str) -> ! {
    eprintln!("loadgen: {msg} (see the header of examples/loadgen.rs)");
    std::process::exit(2);
}

/// Modelled intervals in real seconds (section B).
const SUMMARY_EVERY: f64 = 900.0;
const SNAPSHOT_EVERY: f64 = 300.0;
const HEARTBEAT_EVERY: f64 = 900.0;
const ALERT_MEAN: f64 = 360.0; // 10/h
const ACTIVITY_MEAN: f64 = 450.0; // 8/h
/// Per phone, besides the heartbeat sync: app use 4.5/h plus 1 command/h.
const APP_USE_MEAN: f64 = 800.0;
const COMMAND_MEAN: f64 = 3600.0;
/// Not compressed: a per-stream cost, not an event.
const WS_PING: Duration = Duration::from_secs(25);
/// The server's fixed heartbeat bucket (1 per 10 min, burst 3) is not
/// configurable; the Mac mirrors it so compressed runs do not get 429s.
const HEARTBEAT_BUCKET_SECS: f64 = 600.0;
const HEARTBEAT_BURST: f64 = 3.0;

const PHASES: [&str; 6] = ["setup", "ramp", "steady", "storm", "tail", "abuse"];
const P_SETUP: u8 = 0;
const P_RAMP: u8 = 1;
const P_STEADY: u8 = 2;
const P_STORM: u8 = 3;
const P_TAIL: u8 = 4;
const P_ABUSE: u8 = 5;

const READ_ROUTES: [&str; 4] = [
    "GET /v2/messages",
    "GET /v2/snapshot",
    "GET /v2/status",
    "GET /v2/devices",
];

// --------------------------------------------------------------- rng ---

/// xorshift64*: enough to spread timings and payloads.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn f64(&mut self) -> f64 {
        (self.u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.u64() % (hi - lo + 1)
    }
    fn exp(&mut self, mean: f64) -> f64 {
        -mean * (1.0 - self.f64()).ln()
    }
    fn bytes<const L: usize>(&mut self) -> [u8; L] {
        let mut b = [0u8; L];
        for c in b.chunks_mut(8) {
            let r = self.u64().to_le_bytes();
            c.copy_from_slice(&r[..c.len()]);
        }
        b
    }
}

// ------------------------------------------------------------- stats ---

#[derive(Default)]
struct RouteStat {
    lat_us: Vec<u32>,
    status: BTreeMap<u16, u64>,
    transport: u64,
}

#[derive(Default)]
struct Commands {
    /// id -> (owner user, posted at)
    pending: HashMap<String, (usize, Instant)>,
    done: HashSet<String>,
    accepted: u64,
    queued: u64,
    received: u64,
    duplicates: u64,
    misrouted: u64,
    decrypt_failed: u64,
    e2e_us: HashMap<u8, Vec<u32>>,
}

struct Sample {
    t: f64,
    phase: u8,
    rss_kb: u64,
    cpu_pct: f64,
    fds: u64,
    streams: usize,
}

struct Ctx {
    args: Args,
    http: reqwest::Client,
    run: String,
    start: Instant,
    phase: AtomicU8,
    stop: watch::Receiver<bool>,
    stats: Mutex<HashMap<(u8, String), RouteStat>>,
    cmds: Mutex<Commands>,
    /// Mac streams that got `ready` and are still open.
    ready: AtomicUsize,
    stream_connects: AtomicU64,
    stream_drops: AtomicU64,
    heartbeats_skipped: AtomicU64,
    setup_failed: AtomicUsize,
    /// phone APNs token -> group id (wrong-group push check).
    tokens: Mutex<HashMap<String, String>>,
    samples: Mutex<Vec<Sample>>,
    phase_times: Mutex<Vec<(u8, f64)>>,
}

impl Ctx {
    fn phase(&self) -> u8 {
        self.phase.load(Relaxed)
    }
    fn set_phase(&self, p: u8) {
        self.phase.store(p, Relaxed);
        self.phase_times
            .lock()
            .unwrap()
            .push((p, self.start.elapsed().as_secs_f64()));
        eprintln!(
            "[{:7.1}s] phase {} (streams ready: {})",
            self.start.elapsed().as_secs_f64(),
            PHASES[p as usize],
            self.ready.load(Relaxed)
        );
    }
    fn stopped(&self) -> bool {
        *self.stop.borrow()
    }
    fn record(&self, phase: u8, route: &str, lat: Duration, status: Option<u16>) {
        let mut s = self.stats.lock().unwrap();
        let r = s.entry((phase, route.to_string())).or_default();
        match status {
            Some(code) => {
                r.lat_us.push(lat.as_micros().min(u32::MAX as u128) as u32);
                *r.status.entry(code).or_default() += 1;
            }
            None => r.transport += 1,
        }
    }
    /// Sleep `secs`; false when the run stopped meanwhile.
    async fn sleep_real(&self, secs: f64) -> bool {
        let mut stop = self.stop.clone();
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs_f64(secs.max(0.0))) => !self.stopped(),
            _ = stop.wait_for(|s| *s) => false,
        }
    }
}

fn unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn id128(label: &str) -> String {
    URL_SAFE_NO_PAD.encode(&Sha256::digest(label)[..16])
}

fn hex64(label: &str) -> String {
    hex::encode(Sha256::digest(label))
}

/// Client address of user `u` as seen by the server (X-Forwarded-For).
fn user_ip(u: usize) -> String {
    let v = u + 1;
    format!("10.{}.{}.{}", (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

// ------------------------------------------------------------ device ---

struct Device {
    c: common::Client,
    ip: String,
}

struct User {
    idx: usize,
    mac: Device,
    phones: [Device; 2],
    phone_cursor: [AtomicU64; 2],
    route_prefix: &'static str,
}

impl User {
    fn new(ctx: &Ctx, idx: usize, ip: String, route_prefix: &'static str) -> Self {
        let label = format!("{}|{route_prefix}|{idx}", ctx.run);
        let keys = common::derive(&Sha256::digest(format!("{label}|key")).into());
        let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(unix);
        let mac = common::Client {
            base: ctx.args.url.trim_end_matches('/').to_string(),
            http: ctx.http.clone(),
            group_id: id128(&format!("{label}|group")),
            device_id: id128(&format!("{label}|mac")),
            keys,
            now,
            nonce: Arc::new(AtomicU64::new(0)),
        };
        let phone = |p: usize| Device {
            c: mac.as_device(&id128(&format!("{label}|phone{p}"))),
            ip: ip.clone(),
        };
        Self {
            idx,
            phones: [phone(0), phone(1)],
            mac: Device { c: mac, ip },
            phone_cursor: [AtomicU64::new(0), AtomicU64::new(0)],
            route_prefix,
        }
    }
    fn token(&self, p: usize) -> String {
        hex64(&format!("{}|token", self.phones[p].c.device_id))
    }
}

/// One signed request; `None` on a transport error. Always recorded.
async fn send(
    ctx: &Ctx,
    d: &Device,
    method: &str,
    target: &str,
    body: &str,
    route: &str,
) -> Option<(u16, Value)> {
    let phase = ctx.phase();
    let target = if method == "GET" {
        d.c.get_target(target)
    } else {
        target.to_string()
    };
    let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
    let mut req = ctx
        .http
        .request(m, format!("{}{target}", d.c.base))
        .header("x-forwarded-for", &d.ip)
        .body(body.to_string());
    if !body.is_empty() {
        req = req.header("content-type", "application/json");
    }
    for (k, v) in d.c.signed_headers(method, &target, body.as_bytes()) {
        req = req.header(k, v);
    }
    finish(ctx, phase, route, Instant::now(), req.send()).await
}

async fn finish(
    ctx: &Ctx,
    phase: u8,
    route: &str,
    t0: Instant,
    fut: impl std::future::Future<Output = reqwest::Result<reqwest::Response>>,
) -> Option<(u16, Value)> {
    let res = async {
        let r = fut.await?;
        let status = r.status().as_u16();
        let text = r.text().await?;
        Ok::<_, reqwest::Error>((status, text))
    }
    .await;
    match res {
        Ok((status, text)) => {
            ctx.record(phase, route, t0.elapsed(), Some(status));
            Some((
                status,
                serde_json::from_str(&text).unwrap_or(Value::String(text)),
            ))
        }
        Err(_) => {
            ctx.record(phase, route, t0.elapsed(), None);
            None
        }
    }
}

fn ok(r: &Option<(u16, Value)>) -> bool {
    matches!(r, Some((s, _)) if (200..300).contains(s))
}

async fn create_group(ctx: &Ctx, u: &User, route: &str) -> Option<(u16, Value)> {
    let body = json!({
        "group_id": u.mac.c.group_id,
        "auth_key": STANDARD.encode(u.mac.c.keys.auth),
    })
    .to_string();
    let req = ctx
        .http
        .post(format!("{}/v2/groups", u.mac.c.base))
        .header("x-forwarded-for", &u.mac.ip)
        .header("content-type", "application/json")
        .body(body);
    finish(ctx, ctx.phase(), route, Instant::now(), req.send()).await
}

/// Retry a setup step on 429/503/transport errors, like a client would.
async fn with_retry<F, Fut>(ctx: &Ctx, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<(u16, Value)>>,
{
    let mut wait = 0.5;
    for _ in 0..8 {
        let r = f().await;
        if ok(&r) {
            return true;
        }
        match r {
            Some((429 | 503, _)) | None => {
                if !ctx.sleep_real(wait).await {
                    return false;
                }
                wait = (wait * 2.0).min(16.0);
            }
            _ => return false,
        }
    }
    false
}

async fn setup_user(ctx: &Ctx, u: &User, mac_count: usize) -> bool {
    let p = u.route_prefix;
    let t0 = Instant::now();
    let (r_groups, r_devices, r_activities) = (
        format!("{p}POST /v2/groups"),
        format!("{p}PUT /v2/devices"),
        format!("{p}PUT /v2/activities"),
    );
    let mut good = with_retry(ctx, || create_group(ctx, u, &r_groups)).await;
    for m in 0..mac_count {
        if !good {
            break;
        }
        let mac = if m == 0 {
            Device {
                c: u.mac.c.clone(),
                ip: u.mac.ip.clone(),
            }
        } else {
            Device {
                c: u.mac
                    .c
                    .as_device(&id128(&format!("{}|extra{m}", u.mac.c.device_id))),
                ip: u.mac.ip.clone(),
            }
        };
        let body = json!({"kind": "mac", "name": "Load Mac", "apns_env": "sandbox"}).to_string();
        let path = format!("/v2/devices/{}", mac.c.device_id);
        good = with_retry(ctx, || send(ctx, &mac, "PUT", &path, &body, &r_devices)).await;
    }
    for i in 0..2 {
        if !good || mac_count != 1 {
            break;
        }
        let ph = &u.phones[i];
        let token = u.token(i);
        ctx.tokens
            .lock()
            .unwrap()
            .insert(token.clone(), u.mac.c.group_id.clone());
        let body = json!({"kind": "ios", "name": "Load iPhone", "apns_token": token, "apns_env": "sandbox"})
            .to_string();
        let path = format!("/v2/devices/{}", ph.c.device_id);
        good = with_retry(ctx, || send(ctx, ph, "PUT", &path, &body, &r_devices)).await;
        if good {
            let body = json!({"push_token": hex64(&format!("{token}|la")), "apns_env": "sandbox"})
                .to_string();
            let path = format!("/v2/activities/{}", ph.c.device_id);
            good = with_retry(ctx, || send(ctx, ph, "PUT", &path, &body, &r_activities)).await;
        }
    }
    ctx.record(
        ctx.phase(),
        &format!("{p}user setup (all steps)"),
        t0.elapsed(),
        Some(if good { 200 } else { 599 }),
    );
    good
}

// ------------------------------------------------------- Mac traffic ---

fn seal(c: &common::Client, kind: &str, id: &str, pt: &Value, rng: &mut Rng) -> String {
    c.seal_json(kind, id, pt, rng.bytes::<12>())
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn msg_id(prefix: &str) -> String {
    format!("{prefix}{}", COUNTER.fetch_add(1, Relaxed))
}

async fn post_alert(ctx: &Ctx, u: &User, rng: &mut Rng, route: &str) -> Option<(u16, Value)> {
    let id = msg_id("a");
    let host = format!("host{}", rng.range(1, 40));
    let alert_id = format!("icinga:{host}!svc{}", rng.range(1, 5));
    let critical = rng.f64() < 0.4;
    let pt = json!({
        "v": 1, "type": "alert", "id": id, "ts": unix(), "alert_id": alert_id,
        "title": format!("{host}: DISK {}", if critical { "CRITICAL" } else { "WARNING" }),
        "host": host, "service": "disk", "severity": if critical { "critical" } else { "warning" },
        "source": "icinga", "summary": "Disk usage above threshold on /var",
        "state": "firing", "actions": ["ack", "mute", "open"],
    });
    let sealed = seal(&u.mac.c, "alert", &id, &pt, rng);
    let body = json!({
        "id": id, "type": "alert", "sealed": sealed,
        "collapse_id": common::collapse_id(&u.mac.c.keys.collapse, &alert_id),
        "urgency": if critical { "critical" } else { "normal" }, "ttl_secs": 3600,
    })
    .to_string();
    send(ctx, &u.mac, "POST", "/v2/messages", &body, route).await
}

async fn post_summary(ctx: &Ctx, u: &User, rng: &mut Rng) {
    let id = msg_id("s");
    let pt = json!({"v": 1, "type": "summary", "id": id, "ts": unix(),
        "critical": rng.range(0, 5), "warning": rng.range(0, 12), "unknown": 0,
        "top": [{"alert_id": "icinga:host1!svc1", "severity": "critical", "host": "host1", "title": "host1: DISK CRITICAL"}]});
    let sealed = seal(&u.mac.c, "summary", &id, &pt, rng);
    let body =
        json!({"id": id, "type": "summary", "sealed": sealed, "urgency": "silent"}).to_string();
    send(
        ctx,
        &u.mac,
        "POST",
        "/v2/messages",
        &body,
        "POST /v2/messages",
    )
    .await;
}

async fn post_snapshot(ctx: &Ctx, u: &User, rng: &mut Rng, size: usize) {
    let id = msg_id("n");
    let mut blob = vec![0u8; size];
    for c in blob.chunks_mut(8) {
        let r = rng.u64().to_le_bytes();
        c.copy_from_slice(&r[..c.len()]);
    }
    let pt = json!({"v": 1, "type": "snapshot", "id": id, "ts": unix(), "compressed": true,
        "count": size / 200, "items": STANDARD.encode(&blob)});
    let sealed = seal(&u.mac.c, "snapshot", &id, &pt, rng);
    let body = json!({"id": id, "sealed": sealed}).to_string();
    send(
        ctx,
        &u.mac,
        "POST",
        "/v2/snapshot",
        &body,
        "POST /v2/snapshot",
    )
    .await;
}

async fn post_activity(ctx: &Ctx, u: &User, rng: &mut Rng) {
    let body = json!({"event": "update", "stale_secs": 2400,
        "state": {"critical": rng.range(0, 3), "warning": rng.range(0, 8), "unknown": 0, "mac_online": true}})
    .to_string();
    send(
        ctx,
        &u.mac,
        "POST",
        "/v2/activity-state",
        &body,
        "POST /v2/activity-state",
    )
    .await;
}

/// A phone's sync after a heartbeat push (or when the app opens).
async fn phone_sync(ctx: &Ctx, u: &User, p: usize) {
    let ph = &u.phones[p];
    let since = u.phone_cursor[p].load(Relaxed);
    let r = send(
        ctx,
        ph,
        "GET",
        &format!("/v2/messages?since={since}"),
        "",
        "GET /v2/messages",
    )
    .await;
    if let Some((200, v)) = r {
        if let Some(c) = v["cursor"].as_u64() {
            u.phone_cursor[p].fetch_max(c, Relaxed);
        }
    }
    send(ctx, ph, "GET", "/v2/snapshot", "", "GET /v2/snapshot").await;
    send(ctx, ph, "GET", "/v2/status", "", "GET /v2/status").await;
}

async fn phone_app_use(ctx: &Ctx, u: &User, p: usize, rng: &mut Rng) {
    let ph = &u.phones[p];
    let x = rng.f64();
    if x < 0.4 {
        let since = u.phone_cursor[p].load(Relaxed);
        send(
            ctx,
            ph,
            "GET",
            &format!("/v2/messages?since={since}"),
            "",
            "GET /v2/messages",
        )
        .await;
    } else if x < 0.7 {
        send(ctx, ph, "GET", "/v2/status", "", "GET /v2/status").await;
    } else if x < 0.9 {
        send(ctx, ph, "GET", "/v2/snapshot", "", "GET /v2/snapshot").await;
    } else {
        send(ctx, ph, "GET", "/v2/devices", "", "GET /v2/devices").await;
    }
}

async fn phone_command(ctx: &Ctx, u: &User, p: usize, rng: &mut Rng) {
    let ph = &u.phones[p];
    let id = URL_SAFE_NO_PAD.encode(rng.bytes::<16>());
    let pt = json!({"v": 1, "type": "command", "id": id, "ts": unix(),
        "action": if rng.f64() < 0.5 { "ack" } else { "mute" }, "alert_id": "icinga:host1!svc1",
        "duration_secs": 3600, "lg_group": ph.c.group_id, "lg_user": u.idx});
    let sealed = seal(&ph.c, "command", &id, &pt, rng);
    let body = json!({"id": id, "sealed": sealed}).to_string();
    ctx.cmds
        .lock()
        .unwrap()
        .pending
        .insert(id.clone(), (u.idx, Instant::now()));
    let r = send(ctx, ph, "POST", "/v2/commands", &body, "POST /v2/commands").await;
    let mut c = ctx.cmds.lock().unwrap();
    match r {
        Some((200, v)) if v["status"] == "delivered" || v["status"] == "queued" => {
            c.accepted += 1;
            if v["status"] == "queued" {
                c.queued += 1;
            }
        }
        _ => {
            c.pending.remove(&id);
        }
    }
}

/// Mac side of a command frame: check, ack, answer with a result.
async fn on_command(
    ctx: Arc<Ctx>,
    u: Arc<User>,
    f: Value,
    ws: mpsc::UnboundedSender<Message>,
    mut rng: Rng,
) {
    let id = f["id"].as_str().unwrap_or("").to_string();
    let plain = common::open(
        &u.mac.c.keys.enc,
        &common::aad(&u.mac.c.group_id, "command", &id),
        f["sealed"].as_str().unwrap_or(""),
    )
    .and_then(|p| serde_json::from_slice::<Value>(&p).ok());
    let fresh = {
        let mut c = ctx.cmds.lock().unwrap();
        let phase = ctx.phase();
        let owner = c.pending.get(&id).map(|(o, _)| *o);
        if owner.is_some_and(|o| o != u.idx) {
            c.misrouted += 1;
        }
        match &plain {
            None => c.decrypt_failed += 1,
            Some(p) if p["lg_group"] != u.mac.c.group_id.as_str() => c.misrouted += 1,
            Some(_) => {}
        }
        if c.done.contains(&id) {
            c.duplicates += 1;
            false
        } else if let Some((owner, t0)) = c.pending.remove(&id) {
            if owner == u.idx {
                c.received += 1;
                c.e2e_us
                    .entry(phase)
                    .or_default()
                    .push(t0.elapsed().as_micros().min(u32::MAX as u128) as u32);
            }
            c.done.insert(id.clone());
            true
        } else {
            // Not posted by this run (or POST failed after delivery).
            c.done.insert(id.clone());
            false
        }
    };
    let _ = ws.send(Message::Text(
        json!({"type": "ack", "cursor": f["cursor"]})
            .to_string()
            .into(),
    ));
    if fresh {
        let rid = msg_id("r");
        let pt = json!({"v": 1, "type": "result", "id": rid, "ts": unix(), "command_id": id,
            "alert_id": "icinga:host1!svc1", "ok": true, "message": "Done"});
        let sealed = seal(&u.mac.c, "result", &rid, &pt, &mut rng);
        let body = json!({"id": rid, "type": "result", "sealed": sealed, "urgency": "normal", "ttl_secs": 3600})
            .to_string();
        send(
            &ctx,
            &u.mac,
            "POST",
            "/v2/messages",
            &body,
            "POST /v2/messages",
        )
        .await;
    }
}

/// Open `mac`'s stream; `Err(Some(status))` for a refused upgrade.
async fn ws_connect(
    d: &Device,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Option<u16>,
> {
    let mut req = d.c.ws_url().into_client_request().map_err(|_| None)?;
    let h = req.headers_mut();
    for (k, v) in d.c.signed_headers("GET", "/v2/stream", b"") {
        h.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(&v).unwrap(),
        );
    }
    h.insert("x-forwarded-for", HeaderValue::from_str(&d.ip).unwrap());
    match tokio::time::timeout(
        Duration::from_secs(20),
        tokio_tungstenite::connect_async(req),
    )
    .await
    {
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(r))) => Err(Some(r.status().as_u16())),
        _ => Err(None),
    }
}

/// The Mac's stream, reconnecting with backoff 1, 2, 4 ... 60 s (+-20%).
async fn mac_stream(ctx: Arc<Ctx>, u: Arc<User>, route: String) {
    let mut rng = Rng::new(u.idx as u64 ^ 0xabcdef);
    let mut backoff = 1.0f64;
    while !ctx.stopped() {
        let phase = ctx.phase();
        let t0 = Instant::now();
        match ws_connect(&u.mac).await {
            Ok(ws) => {
                ctx.record(phase, &route, t0.elapsed(), Some(101));
                ctx.stream_connects.fetch_add(1, Relaxed);
                let (mut tx, mut rx) = ws.split();
                let (wtx, mut wrx) = mpsc::unbounded_channel::<Message>();
                let writer = tokio::spawn(async move {
                    while let Some(m) = wrx.recv().await {
                        if tx.send(m).await.is_err() {
                            break;
                        }
                    }
                });
                let mut ping =
                    tokio::time::interval_at(tokio::time::Instant::now() + WS_PING, WS_PING);
                let mut stop = ctx.stop.clone();
                let mut ready = false;
                loop {
                    tokio::select! {
                        m = rx.next() => match m {
                            Some(Ok(Message::Text(t))) => {
                                let f: Value = serde_json::from_str(t.as_str()).unwrap_or(Value::Null);
                                if f["type"] == "ready" && !ready {
                                    ready = true;
                                    backoff = 1.0;
                                    ctx.ready.fetch_add(1, Relaxed);
                                } else if f["type"] == "command" {
                                    tokio::spawn(on_command(ctx.clone(), u.clone(), f, wtx.clone(), Rng::new(rng.u64())));
                                }
                            }
                            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                            Some(Ok(_)) => {}
                        },
                        _ = ping.tick() => { let _ = wtx.send(Message::Ping(Vec::new().into())); }
                        _ = stop.wait_for(|s| *s) => break,
                    }
                }
                if ready {
                    ctx.ready.fetch_sub(1, Relaxed);
                }
                ctx.stream_drops.fetch_add(1, Relaxed);
                drop(wtx);
                writer.abort();
                if ctx.stopped() {
                    return;
                }
            }
            Err(status) => ctx.record(phase, &route, t0.elapsed(), status),
        }
        let wait = backoff * (0.8 + 0.4 * rng.f64());
        backoff = (backoff * 2.0).min(60.0);
        if !ctx.sleep_real(wait).await {
            return;
        }
    }
}

/// The modelled traffic of one user until the run stops.
async fn user_traffic(ctx: Arc<Ctx>, u: Arc<User>) {
    let mut rng = Rng::new(u.idx as u64 + 1);
    let snapshot_size = rng.range(5_000, 50_000) as usize;
    let c = ctx.args.compress;
    // A Mac starts in a random point of each periodic schedule.
    let t0 = tokio::time::Instant::now();
    let at = |modelled: f64| t0 + Duration::from_secs_f64(modelled / c);
    let mut next_summary = at(rng.f64() * SUMMARY_EVERY);
    let mut next_snapshot = at(rng.f64() * SNAPSHOT_EVERY);
    let mut next_heartbeat = at(rng.f64() * HEARTBEAT_EVERY);
    let mut next_alert = at(rng.exp(ALERT_MEAN));
    let mut next_activity = at(rng.exp(ACTIVITY_MEAN));
    let mut next_app = [at(rng.exp(APP_USE_MEAN)), at(rng.exp(APP_USE_MEAN))];
    let mut next_cmd = [at(rng.exp(COMMAND_MEAN)), at(rng.exp(COMMAND_MEAN))];
    // Mirror of the server's fixed heartbeat bucket, in real seconds.
    let mut hb_tokens = HEARTBEAT_BURST;
    let mut hb_last = Instant::now();
    let mut stop = ctx.stop.clone();
    loop {
        let next = [
            next_summary,
            next_snapshot,
            next_heartbeat,
            next_alert,
            next_activity,
            next_app[0],
            next_app[1],
            next_cmd[0],
            next_cmd[1],
        ];
        let (which, when) = next
            .iter()
            .enumerate()
            .min_by_key(|(_, t)| **t)
            .map(|(i, t)| (i, *t))
            .unwrap();
        tokio::select! {
            _ = tokio::time::sleep_until(when) => {}
            _ = stop.wait_for(|s| *s) => return,
        }
        let (ctx2, u2, mut r2) = (ctx.clone(), u.clone(), Rng::new(rng.u64()));
        match which {
            0 => {
                next_summary += Duration::from_secs_f64(SUMMARY_EVERY / c);
                tokio::spawn(async move { post_summary(&ctx2, &u2, &mut r2).await });
            }
            1 => {
                next_snapshot += Duration::from_secs_f64(SNAPSHOT_EVERY / c);
                tokio::spawn(
                    async move { post_snapshot(&ctx2, &u2, &mut r2, snapshot_size).await },
                );
            }
            2 => {
                next_heartbeat += Duration::from_secs_f64(HEARTBEAT_EVERY / c);
                hb_tokens = (hb_tokens + hb_last.elapsed().as_secs_f64() / HEARTBEAT_BUCKET_SECS)
                    .min(HEARTBEAT_BURST);
                hb_last = Instant::now();
                let post = hb_tokens >= 1.0;
                if post {
                    hb_tokens -= 1.0;
                } else {
                    ctx.heartbeats_skipped.fetch_add(1, Relaxed);
                }
                tokio::spawn(async move {
                    if post {
                        let body = json!({"id": msg_id("h")}).to_string();
                        send(
                            &ctx2,
                            &u2.mac,
                            "POST",
                            "/v2/heartbeat",
                            &body,
                            "POST /v2/heartbeat",
                        )
                        .await;
                    }
                    // Both phones wake up and sync, a little apart.
                    let mut tasks = Vec::new();
                    for p in 0..2 {
                        let (c3, u3) = (ctx2.clone(), u2.clone());
                        let delay = r2.f64() * 2.0;
                        tasks.push(tokio::spawn(async move {
                            if c3.sleep_real(delay).await {
                                phone_sync(&c3, &u3, p).await;
                            }
                        }));
                    }
                    for t in tasks {
                        let _ = t.await;
                    }
                });
            }
            3 => {
                next_alert += Duration::from_secs_f64(rng.exp(ALERT_MEAN) / c);
                tokio::spawn(
                    async move { post_alert(&ctx2, &u2, &mut r2, "POST /v2/messages").await },
                );
            }
            4 => {
                // At least 1.1 s apart: an identical body signed in the same
                // second is a replay (401), as for a real Mac.
                next_activity += Duration::from_secs_f64((rng.exp(ACTIVITY_MEAN) / c).max(1.1));
                tokio::spawn(async move { post_activity(&ctx2, &u2, &mut r2).await });
            }
            5 | 6 => {
                let p = which - 5;
                next_app[p] += Duration::from_secs_f64(rng.exp(APP_USE_MEAN) / c);
                tokio::spawn(async move { phone_app_use(&ctx2, &u2, p, &mut r2).await });
            }
            _ => {
                let p = which - 7;
                next_cmd[p] += Duration::from_secs_f64(rng.exp(COMMAND_MEAN) / c);
                tokio::spawn(async move { phone_command(&ctx2, &u2, p, &mut r2).await });
            }
        }
    }
}

// ----------------------------------------------------------- sampler ---

fn sh(cmd: &str) -> String {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// `ps -o time` on macOS: `[[D-]H:]M:SS.ss`.
fn cpu_secs(t: &str) -> Option<f64> {
    let (days, rest) = match t.split_once('-') {
        Some((d, r)) => (d.parse::<f64>().ok()?, r),
        None => (0.0, t),
    };
    let mut secs = 0.0;
    for part in rest.split(':') {
        secs = secs * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(days * 86400.0 + secs)
}

fn sampler(ctx: Arc<Ctx>, pid_file: String) {
    let mut last: Option<(String, f64, Instant)> = None;
    while !ctx.stopped() {
        let tick = Instant::now();
        let pid = std::fs::read_to_string(&pid_file)
            .unwrap_or_default()
            .trim()
            .to_string();
        if !pid.is_empty() {
            let out = sh(&format!("ps -o rss=,time= -p {pid}"));
            let mut it = out.split_whitespace();
            if let (Some(rss), Some(t)) = (it.next(), it.next()) {
                let rss_kb = rss.parse().unwrap_or(0);
                let cpu = cpu_secs(t).unwrap_or(0.0);
                let cpu_pct = match &last {
                    Some((p, c, at)) if *p == pid => {
                        100.0 * (cpu - c) / at.elapsed().as_secs_f64().max(0.001)
                    }
                    _ => 0.0,
                };
                last = Some((pid.clone(), cpu, Instant::now()));
                let fds = sh(&format!("lsof -nP -p {pid} 2>/dev/null | wc -l"))
                    .trim()
                    .parse::<u64>()
                    .unwrap_or(1)
                    .saturating_sub(1);
                ctx.samples.lock().unwrap().push(Sample {
                    t: ctx.start.elapsed().as_secs_f64(),
                    phase: ctx.phase(),
                    rss_kb,
                    cpu_pct,
                    fds,
                    streams: ctx.ready.load(Relaxed),
                });
            }
        }
        std::thread::sleep(Duration::from_secs(1).saturating_sub(tick.elapsed()));
    }
}

// ------------------------------------------------------------- abuse ---

#[derive(Default)]
struct AbuseReport {
    multi_mac_ok: u64,
    multi_mac_refused: BTreeMap<u16, u64>,
    flood_ips_banned: usize,
    flood_first_ban_secs: Option<f64>,
    slow_body: BTreeMap<String, u64>,
    slow_body_secs: Vec<f64>,
}

/// One group at its maximum rates, 50 groups x 4 Macs, 12 addresses
/// flooding `POST /v2/groups`, 128 slow-body connections.
async fn abusers(
    ctx: Arc<Ctx>,
    n: usize,
    report: Arc<Mutex<AbuseReport>>,
    until: watch::Receiver<bool>,
) {
    let mut tasks = Vec::new();
    // 1. Hog: one tenant as fast as 8 parallel loops go.
    let hog = Arc::new(User::new(&ctx, n + 1, "10.255.0.1".into(), "abuse: hog "));
    if setup_user(&ctx, &hog, 1).await {
        for k in 0..8 {
            let (c, h, until) = (ctx.clone(), hog.clone(), until.clone());
            tasks.push(tokio::spawn(async move {
                let mut rng = Rng::new(k);
                while !*until.borrow() {
                    post_alert(&c, &h, &mut rng, "abuse: hog POST /v2/messages").await;
                    let d = &h.phones[0];
                    send(
                        &c,
                        d,
                        "GET",
                        "/v2/messages?since=0",
                        "",
                        "abuse: hog GET /v2/messages",
                    )
                    .await;
                }
            }));
        }
    }
    // 2. 50 groups, 4 Macs each: the 4th stream must be refused.
    for g in 0..50 {
        let (c, rep, until) = (ctx.clone(), report.clone(), until.clone());
        tasks.push(tokio::spawn(async move {
            let ip = format!("10.253.{}.{}", g / 200, g % 200 + 1);
            let u = User::new(&c, n + 100 + g, ip, "abuse: multi ");
            if !setup_user(&c, &u, 4).await {
                return;
            }
            let mut held = Vec::new();
            for m in 0..4 {
                let d = Device {
                    c: if m == 0 {
                        u.mac.c.clone()
                    } else {
                        u.mac
                            .c
                            .as_device(&id128(&format!("{}|extra{m}", u.mac.c.device_id)))
                    },
                    ip: u.mac.ip.clone(),
                };
                let t0 = Instant::now();
                match ws_connect(&d).await {
                    // Accepted only once `ready` arrives: the quota is checked
                    // again after the upgrade, which may close with 1013.
                    Ok(mut ws) => {
                        let ready = loop {
                            match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                                Ok(Some(Ok(Message::Text(t))))
                                    if t.as_str().contains("\"ready\"") =>
                                {
                                    break true
                                }
                                Ok(Some(Ok(
                                    Message::Text(_) | Message::Ping(_) | Message::Pong(_),
                                ))) => {}
                                _ => break false,
                            }
                        };
                        let code = if ready { 101 } else { 1013 };
                        c.record(
                            c.phase(),
                            "abuse: multi WS /v2/stream",
                            t0.elapsed(),
                            Some(code),
                        );
                        let mut rep = rep.lock().unwrap();
                        if ready {
                            rep.multi_mac_ok += 1;
                            held.push(ws);
                        } else {
                            *rep.multi_mac_refused.entry(code).or_default() += 1;
                        }
                    }
                    Err(s) => {
                        c.record(c.phase(), "abuse: multi WS /v2/stream", t0.elapsed(), s);
                        *rep.lock()
                            .unwrap()
                            .multi_mac_refused
                            .entry(s.unwrap_or(0))
                            .or_default() += 1;
                    }
                }
            }
            let mut until = until;
            let _ = until.wait_for(|s| *s).await;
            drop(held);
        }));
    }
    // 3. 12 addresses flooding group registration.
    let banned = Arc::new(Mutex::new(HashSet::new()));
    for ip_n in 0..12 {
        for k in 0..4 {
            let (c, until, banned, rep) =
                (ctx.clone(), until.clone(), banned.clone(), report.clone());
            tasks.push(tokio::spawn(async move {
                let ip = format!("10.252.0.{}", ip_n + 1);
                let mut i = 0u64;
                while !*until.borrow() {
                    i += 1;
                    let gid = id128(&format!("{}|flood|{ip_n}|{k}|{i}", c.run));
                    let body = json!({"group_id": gid, "auth_key": STANDARD.encode([7u8; 32])})
                        .to_string();
                    let req = c
                        .http
                        .post(format!("{}/v2/groups", c.args.url))
                        .header("x-forwarded-for", &ip)
                        .header("content-type", "application/json")
                        .body(body);
                    let t0 = Instant::now();
                    let phase = c.phase();
                    match req.send().await {
                        Ok(r) => {
                            let status = r.status().as_u16();
                            let retry: u64 = r
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(0);
                            let _ = r.bytes().await;
                            c.record(
                                phase,
                                "abuse: flood POST /v2/groups",
                                t0.elapsed(),
                                Some(status),
                            );
                            // A ban answers 429 with the ban's remaining time.
                            if status == 429 && retry >= 60 && banned.lock().unwrap().insert(ip_n) {
                                let mut rep = rep.lock().unwrap();
                                rep.flood_ips_banned += 1;
                                rep.flood_first_ban_secs
                                    .get_or_insert(c.start.elapsed().as_secs_f64());
                            }
                        }
                        Err(_) => {
                            c.record(phase, "abuse: flood POST /v2/groups", t0.elapsed(), None)
                        }
                    }
                }
            }));
        }
    }
    // 4. 128 connections trickling a body, 1 byte per second.
    let addr = ctx
        .args
        .url
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    for k in 0..128 {
        let (rep, addr, until) = (report.clone(), addr.clone(), until.clone());
        tasks.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let outcome = match tokio::net::TcpStream::connect(&addr).await {
                Err(_) => "connect_failed".to_string(),
                Ok(mut s) => {
                    let head = format!(
                        "POST /v2/messages HTTP/1.1\r\nHost: {addr}\r\nX-Forwarded-For: 10.251.0.{}\r\nContent-Type: application/json\r\nContent-Length: 4000\r\n\r\n",
                        k % 250 + 1
                    );
                    let mut out = "no_answer".to_string();
                    if s.write_all(head.as_bytes()).await.is_ok() {
                        let mut buf = [0u8; 256];
                        for _ in 0..120 {
                            if *until.borrow() {
                                break;
                            }
                            if s.write_all(b"x").await.is_err() {
                                out = "closed".into();
                                break;
                            }
                            match tokio::time::timeout(Duration::from_secs(1), s.read(&mut buf)).await {
                                Ok(Ok(0)) | Ok(Err(_)) => {
                                    out = "closed".into();
                                    break;
                                }
                                Ok(Ok(len)) => {
                                    let line = String::from_utf8_lossy(&buf[..len]);
                                    out = line.split("\r\n").next().unwrap_or("").to_string();
                                    break;
                                }
                                Err(_) => {}
                            }
                        }
                    }
                    out
                }
            };
            let mut rep = rep.lock().unwrap();
            *rep.slow_body.entry(outcome).or_default() += 1;
            rep.slow_body_secs.push(t0.elapsed().as_secs_f64());
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
}

// ------------------------------------------------------------ report ---

fn pct(sorted: &[u32], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[i.min(sorted.len() - 1)] as f64 / 1000.0
}

fn dist(v: &[u32]) -> Value {
    let mut s = v.to_vec();
    s.sort_unstable();
    json!({
        "count": s.len(),
        "p50_ms": pct(&s, 50.0), "p95_ms": pct(&s, 95.0), "p99_ms": pct(&s, 99.0),
        "max_ms": s.last().map_or(0.0, |m| *m as f64 / 1000.0),
    })
}

struct Slo {
    name: String,
    ok: bool,
    value: String,
}

fn slo(list: &mut Vec<Slo>, name: impl Into<String>, ok: bool, value: impl Into<String>) {
    list.push(Slo {
        name: name.into(),
        ok,
        value: value.into(),
    });
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let (stop_tx, stop_rx) = watch::channel(false);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_nodelay(true)
        .build()
        .unwrap();
    let run = format!("{}-{}", unix(), std::process::id());
    let ctx = Arc::new(Ctx {
        args: args.clone(),
        http,
        run,
        start: Instant::now(),
        phase: AtomicU8::new(P_SETUP),
        stop: stop_rx,
        stats: Mutex::default(),
        cmds: Mutex::default(),
        ready: AtomicUsize::new(0),
        stream_connects: AtomicU64::new(0),
        stream_drops: AtomicU64::new(0),
        heartbeats_skipped: AtomicU64::new(0),
        setup_failed: AtomicUsize::new(0),
        tokens: Mutex::default(),
        samples: Mutex::default(),
        phase_times: Mutex::default(),
    });
    eprintln!(
        "loadgen: {} users, scenario {}, steady {} s, ramp {} s, compression {}x, {}",
        args.n, args.scenario, args.duration, args.ramp, args.compress, args.url
    );
    let sampler_thread = args.pid_file.clone().map(|pf| {
        let c = ctx.clone();
        std::thread::spawn(move || sampler(c, pf))
    });
    // Idle baseline for the per-stream memory estimate.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // ---- ramp: users set up over `ramp` seconds, then stream + traffic.
    ctx.set_phase(P_RAMP);
    let ramp_start = Instant::now();
    let mut user_tasks = Vec::new();
    for i in 0..args.n {
        let c = ctx.clone();
        let delay = args.ramp as f64 * i as f64 / args.n as f64;
        user_tasks.push(tokio::spawn(async move {
            if !c.sleep_real(delay).await {
                return;
            }
            let u = Arc::new(User::new(&c, i, user_ip(i), ""));
            if !setup_user(&c, &u, 1).await {
                c.setup_failed.fetch_add(1, Relaxed);
                return;
            }
            tokio::spawn(mac_stream(c.clone(), u.clone(), "WS /v2/stream".into()));
            user_traffic(c, u).await;
        }));
    }
    // Ramp ends when every stream is ready (or setup failed), at most ramp + 60 s.
    let ramp_deadline = ramp_start + Duration::from_secs(args.ramp + 60);
    while ctx.ready.load(Relaxed) + ctx.setup_failed.load(Relaxed) < args.n
        && Instant::now() < ramp_deadline
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let ramp_secs = ramp_start.elapsed().as_secs_f64();

    // ---- scenario phases
    let mut storm = json!({});
    let abuse_report = Arc::new(Mutex::new(AbuseReport::default()));
    match args.scenario.as_str() {
        "ramp-steady" => {
            ctx.set_phase(P_STEADY);
            tokio::time::sleep(Duration::from_secs(args.duration)).await;
        }
        "alert-storm" => {
            ctx.set_phase(P_STEADY);
            tokio::time::sleep(Duration::from_secs(args.duration)).await;
            ctx.set_phase(P_STORM);
            // Every group sends 5 alerts within 10 s.
            let t0 = Instant::now();
            let mut tasks = Vec::new();
            for i in 0..args.n {
                for k in 0..5u64 {
                    let c = ctx.clone();
                    tasks.push(tokio::spawn(async move {
                        let mut rng = Rng::new((i as u64) << 8 | k);
                        tokio::time::sleep(Duration::from_secs_f64(rng.f64() * 10.0)).await;
                        // Storm alerts use a user built from the same seeds.
                        let u = User::new(&c, i, user_ip(i), "");
                        post_alert(&c, &u, &mut rng, "POST /v2/messages (storm alert)").await
                    }));
                }
            }
            let mut pushed = 0u64;
            for t in tasks {
                if let Ok(Some((200, v))) = t.await {
                    pushed += v["pushed"].as_u64().unwrap_or(0);
                }
            }
            let secs = t0.elapsed().as_secs_f64();
            storm = json!({"alerts": args.n * 5, "pushes_confirmed": pushed, "drain_secs": secs,
                           "pushes_per_sec": pushed as f64 / secs});
            ctx.set_phase(P_TAIL);
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        "reconnect-storm" => {
            ctx.set_phase(P_STEADY);
            tokio::time::sleep(Duration::from_secs(args.duration)).await;
            let Some(cmd) = args.restart_cmd.clone() else {
                usage("reconnect-storm needs --restart-cmd");
            };
            let before = ctx.ready.load(Relaxed);
            ctx.set_phase(P_STORM);
            let t0 = Instant::now();
            let restart = tokio::task::spawn_blocking(move || {
                let s = Instant::now();
                let ok = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .status()
                    .is_ok_and(|s| s.success());
                (ok, s.elapsed().as_secs_f64())
            });
            // Wait until the streams dropped, then for their return.
            let mut low = before;
            let (mut t99, mut t100) = (None, None);
            let target99 = (before as f64 * 0.99).ceil() as usize;
            while t0.elapsed() < Duration::from_secs(180) {
                let r = ctx.ready.load(Relaxed);
                low = low.min(r);
                if low < before / 2 {
                    if t99.is_none() && r >= target99 {
                        t99 = Some(t0.elapsed().as_secs_f64());
                    }
                    if r >= before {
                        t100 = Some(t0.elapsed().as_secs_f64());
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let (restart_ok, restart_secs) = restart.await.unwrap_or((false, 0.0));
            storm = json!({"streams_before": before, "streams_lowest": low,
                "streams_after": ctx.ready.load(Relaxed),
                "restart_ok": restart_ok, "restart_cmd_secs": restart_secs,
                "secs_to_99pct": t99, "secs_to_100pct": t100});
            ctx.set_phase(P_TAIL);
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        _ => {
            // abuse: first half baseline, second half with the abusers.
            ctx.set_phase(P_STEADY);
            tokio::time::sleep(Duration::from_secs(args.duration / 2)).await;
            ctx.set_phase(P_ABUSE);
            let (until_tx, until_rx) = watch::channel(false);
            let a = tokio::spawn(abusers(ctx.clone(), args.n, abuse_report.clone(), until_rx));
            tokio::time::sleep(Duration::from_secs(args.duration / 2)).await;
            let _ = until_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(10), a).await;
        }
    }
    // Let in-flight commands land before counting losses.
    let _ = stop_tx.send(true);
    let pending_deadline = Instant::now() + Duration::from_secs(10);
    while !ctx.cmds.lock().unwrap().pending.is_empty() && Instant::now() < pending_deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for t in user_tasks {
        let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
    }

    // Wrong-group pushes: the mock's newest 1000 pushes vs. our tokens.
    let mut push_check = json!(null);
    if let Ok(r) = ctx
        .http
        .get(format!("{}/v2/debug/pushes", args.url))
        .send()
        .await
    {
        if let Ok(v) = r
            .text()
            .await
            .map(|t| serde_json::from_str::<Value>(&t).unwrap_or(Value::Null))
        {
            let tokens = ctx.tokens.lock().unwrap();
            let (mut checked, mut wrong) = (0u64, 0u64);
            for p in v["pushes"].as_array().into_iter().flatten() {
                if let Some(g) = p["device_token"].as_str().and_then(|t| tokens.get(t)) {
                    checked += 1;
                    if p["group_id"] != g.as_str() {
                        wrong += 1;
                    }
                }
            }
            push_check = json!({"checked": checked, "wrong_group": wrong});
        }
    }
    if let Some(t) = sampler_thread {
        let _ = t.join();
    }
    let code = report(
        &ctx,
        ramp_secs,
        storm,
        &abuse_report.lock().unwrap(),
        push_check,
    );
    std::process::exit(code);
}

#[allow(clippy::too_many_lines)]
fn report(ctx: &Ctx, ramp_secs: f64, storm: Value, abuse: &AbuseReport, push_check: Value) -> i32 {
    let a = &ctx.args;
    let stats = ctx.stats.lock().unwrap();
    let cmds = ctx.cmds.lock().unwrap();
    let samples = ctx.samples.lock().unwrap();
    let phase_times = ctx.phase_times.lock().unwrap();
    let phase_len = |p: u8| -> f64 {
        let start = phase_times.iter().find(|(q, _)| *q == p).map(|(_, t)| *t);
        let end = phase_times
            .iter()
            .find(|(q, t)| *q != p && Some(*t) > start && *t >= start.unwrap_or(f64::MAX))
            .map(|(_, t)| *t);
        match (start, end) {
            (Some(s), Some(e)) => e - s,
            (Some(s), None) => ctx.start.elapsed().as_secs_f64() - s,
            _ => 0.0,
        }
    };

    // Per phase, per route.
    let mut phases = serde_json::Map::new();
    let victim = |phase: u8| -> (u64, u64, u64, u64, u64) {
        // (requests, 429, 5xx, other non-2xx, transport)
        let mut t = (0, 0, 0, 0, 0);
        for ((p, route), s) in stats.iter() {
            // "user setup" is a synthetic total (599 = a step failed).
            if *p != phase || route.starts_with("abuse:") || route.ends_with("(all steps)") {
                continue;
            }
            t.0 += s.lat_us.len() as u64 + s.transport;
            for (code, n) in &s.status {
                match code {
                    429 => t.1 += n,
                    500..=599 => t.2 += n,
                    200..=299 | 101 => {}
                    _ => t.3 += n,
                }
            }
            t.4 += s.transport;
        }
        t
    };
    let mut totals = BTreeMap::new();
    for p in 0..PHASES.len() as u8 {
        let mut routes = serde_json::Map::new();
        let mut keys: Vec<_> = stats.keys().filter(|(q, _)| *q == p).collect();
        keys.sort();
        for k in keys {
            let s = &stats[k];
            let mut d = dist(&s.lat_us);
            d["status"] = json!(s
                .status
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect::<BTreeMap<_, _>>());
            d["transport_errors"] = json!(s.transport);
            routes.insert(k.1.clone(), d);
        }
        if routes.is_empty() {
            continue;
        }
        let v = victim(p);
        let secs = phase_len(p);
        let e2e = cmds.e2e_us.get(&p).cloned().unwrap_or_default();
        totals.insert(p, v);
        phases.insert(
            PHASES[p as usize].into(),
            json!({
                "secs": secs,
                "requests": v.0, "req_per_sec": if secs > 0.0 { v.0 as f64 / secs } else { 0.0 },
                "status_429": v.1, "status_5xx": v.2, "status_other_error": v.3, "transport_errors": v.4,
                "command_e2e": dist(&e2e),
                "routes": routes,
            }),
        );
    }

    // Resources.
    let idle_rss = samples
        .iter()
        .find(|s| s.phase == P_SETUP)
        .map(|s| s.rss_kb);
    let in_phase = |p: u8| samples.iter().filter(move |s| s.phase == p);
    let max_rss = samples.iter().map(|s| s.rss_kb).max().unwrap_or(0);
    let steady_rss = in_phase(P_STEADY).map(|s| s.rss_kb).max().unwrap_or(0);
    let cpu_mean = |p: u8| {
        let v: Vec<f64> = in_phase(p).map(|s| s.cpu_pct).collect();
        if v.is_empty() {
            0.0
        } else {
            v.iter().sum::<f64>() / v.len() as f64
        }
    };
    let cpu_max = |p: u8| in_phase(p).map(|s| s.cpu_pct).fold(0.0, f64::max);
    let streams_steady = in_phase(P_STEADY).map(|s| s.streams).max().unwrap_or(0);
    let per_stream_kb = match idle_rss {
        Some(idle) if streams_steady > 0 => {
            Some(steady_rss.saturating_sub(idle) as f64 / streams_steady as f64)
        }
        _ => None,
    };
    let resources = json!({
        "sampled": !samples.is_empty(),
        "idle_rss_mb": idle_rss.map(|k| k as f64 / 1024.0),
        "peak_rss_mb": max_rss as f64 / 1024.0,
        "steady_peak_rss_mb": steady_rss as f64 / 1024.0,
        "rss_per_stream_kb": per_stream_kb,
        "streams_steady": streams_steady,
        "cpu_mean_pct": {"ramp": cpu_mean(P_RAMP), "steady": cpu_mean(P_STEADY), "storm": cpu_mean(P_STORM), "abuse": cpu_mean(P_ABUSE)},
        "cpu_max_pct": {"ramp": cpu_max(P_RAMP), "steady": cpu_max(P_STEADY), "storm": cpu_max(P_STORM), "tail": cpu_max(P_TAIL), "abuse": cpu_max(P_ABUSE)},
        "peak_fds": samples.iter().map(|s| s.fds).max().unwrap_or(0),
        "steady_peak_fds": in_phase(P_STEADY).map(|s| s.fds).max().unwrap_or(0),
    });

    // SLOs (section C).
    let mut slos = Vec::new();
    let big = a.n > 1000;
    let route_p99 = |phase: u8, route: &str| -> Option<f64> {
        stats.get(&(phase, route.to_string())).map(|s| {
            let mut v = s.lat_us.clone();
            v.sort_unstable();
            pct(&v, 99.0)
        })
    };
    let lost = cmds.pending.len() as u64;
    slo(
        &mut slos,
        "no lost commands",
        lost == 0,
        format!("{lost} of {} accepted", cmds.accepted),
    );
    slo(
        &mut slos,
        "no command to the wrong group",
        cmds.misrouted == 0 && cmds.decrypt_failed == 0,
        format!(
            "misrouted {}, undecryptable {}",
            cmds.misrouted, cmds.decrypt_failed
        ),
    );
    let wrong_push = push_check["wrong_group"].as_u64().unwrap_or(0);
    slo(
        &mut slos,
        "no push to the wrong group",
        wrong_push == 0,
        push_check.to_string(),
    );
    let storm_kill = a.scenario == "reconnect-storm";
    let (mut r429, mut r5xx, mut other, mut transport) = (0, 0, 0, 0);
    for (p, v) in &totals {
        r429 += v.1;
        r5xx += v.2;
        other += v.3;
        // The kill window of a reconnect storm refuses connections by design.
        if !(storm_kill && (*p == P_STORM)) {
            transport += v.4;
        }
    }
    slo(
        &mut slos,
        "modelled traffic gets no 429",
        r429 == 0,
        format!("{r429}"),
    );
    slo(
        &mut slos,
        "no unexpected 5xx / transport errors",
        r5xx == 0 && transport == 0,
        format!("5xx {r5xx}, transport {transport}"),
    );
    slo(
        &mut slos,
        "no other non-2xx",
        other == 0,
        format!("{other}"),
    );
    slo(
        &mut slos,
        "all users set up",
        ctx.setup_failed.load(Relaxed) == 0,
        format!("{} failed", ctx.setup_failed.load(Relaxed)),
    );
    let read_limit = if big { 100.0 } else { 50.0 };
    for r in READ_ROUTES {
        if let Some(p99) = route_p99(P_STEADY, r) {
            slo(
                &mut slos,
                format!("steady {r} p99 < {read_limit} ms"),
                p99 < read_limit,
                format!("{p99:.1} ms"),
            );
        }
    }
    let msg_limit = if big { 500.0 } else { 250.0 };
    if let Some(p99) = route_p99(P_STEADY, "POST /v2/messages") {
        slo(
            &mut slos,
            format!("steady POST /v2/messages p99 < {msg_limit} ms"),
            p99 < msg_limit,
            format!("{p99:.1} ms"),
        );
    }
    if let Some(e2e) = cmds.e2e_us.get(&P_STEADY) {
        let mut v = e2e.clone();
        v.sort_unstable();
        let p99 = pct(&v, 99.0);
        slo(
            &mut slos,
            "steady command e2e p99 < 200 ms",
            p99 < 200.0,
            format!("{p99:.1} ms (n={})", v.len()),
        );
    }
    if !samples.is_empty() {
        let limit_mb = if a.n > 2000 { 384.0 } else { 192.0 };
        let steady_mb = steady_rss as f64 / 1024.0;
        slo(
            &mut slos,
            format!("steady RSS < 70% of {limit_mb} MB"),
            steady_mb < 0.7 * limit_mb,
            format!("{steady_mb:.1} MB"),
        );
        let c = cpu_mean(P_STEADY);
        slo(
            &mut slos,
            "steady CPU < 50% (mean, one core)",
            c < 50.0,
            format!("{c:.1}%"),
        );
        if big && a.scenario != "ramp-steady" {
            let c = cpu_max(P_STORM).max(cpu_max(P_ABUSE));
            slo(
                &mut slos,
                "storm CPU < 85% (max)",
                c < 85.0,
                format!("{c:.1}%"),
            );
        }
    }
    if storm_kill {
        let t = storm["secs_to_99pct"].as_f64();
        slo(
            &mut slos,
            "reconnect: 99% of streams within 90 s",
            t.is_some_and(|t| t <= 90.0),
            format!("{t:?} s"),
        );
    }
    if a.scenario == "abuse" {
        let mut worst = 1.0f64;
        for r in READ_ROUTES.iter().chain(["POST /v2/messages"].iter()) {
            if let (Some(b), Some(x)) = (route_p99(P_STEADY, r), route_p99(P_ABUSE, r)) {
                worst = worst.max(x / b.max(1.0));
            }
        }
        slo(
            &mut slos,
            "abuse: victims p99 <= 2x baseline",
            worst <= 2.0,
            format!("{worst:.2}x"),
        );
        let v = totals.get(&P_ABUSE).copied().unwrap_or_default();
        let err = (v.1 + v.2 + v.3 + v.4) as f64 / (v.0.max(1)) as f64 * 100.0;
        slo(
            &mut slos,
            "abuse: victims errors < 0.5%",
            err < 0.5,
            format!("{err:.2}%"),
        );
        slo(
            &mut slos,
            "abuse: flooding addresses banned",
            abuse.flood_ips_banned == 12,
            format!("{} of 12", abuse.flood_ips_banned),
        );
    }

    let failed: Vec<&Slo> = slos.iter().filter(|s| !s.ok).collect();
    let mut slow_secs = abuse.slow_body_secs.clone();
    slow_secs.sort_by(|a, b| a.total_cmp(b));
    let out = json!({
        "config": {"url": a.url, "n": a.n, "scenario": a.scenario, "steady_secs": a.duration,
                   "ramp_secs_planned": a.ramp, "compress": a.compress, "server_env": a.server_env,
                   "ws_ping_secs": WS_PING.as_secs(),
                   "host": {"os": sh("sw_vers -productVersion").trim(), "cpus": sh("sysctl -n hw.ncpu").trim()}},
        "ramp_secs": ramp_secs,
        "phases": phases,
        "commands": {"accepted": cmds.accepted, "queued": cmds.queued, "received": cmds.received,
                     "lost": lost, "duplicates": cmds.duplicates, "misrouted": cmds.misrouted,
                     "decrypt_failed": cmds.decrypt_failed},
        "streams": {"connects": ctx.stream_connects.load(Relaxed), "drops": ctx.stream_drops.load(Relaxed)},
        "heartbeats_skipped_fixed_server_limit": ctx.heartbeats_skipped.load(Relaxed),
        "push_check": push_check,
        "storm": storm,
        "abuse": {"multi_mac_streams_ok": abuse.multi_mac_ok, "multi_mac_refused": abuse.multi_mac_refused,
                  "flood_ips_banned": abuse.flood_ips_banned, "flood_first_ban_at_secs": abuse.flood_first_ban_secs,
                  "slow_body_outcomes": abuse.slow_body, "slow_body_p50_secs": slow_secs.get(slow_secs.len() / 2)},
        "resources": resources,
        "slo": slos.iter().map(|s| json!({"name": s.name, "ok": s.ok, "value": s.value})).collect::<Vec<_>>(),
        "samples": samples.iter().map(|s| json!([ (s.t * 10.0).round() / 10.0, PHASES[s.phase as usize], s.rss_kb, (s.cpu_pct * 10.0).round() / 10.0, s.fds, s.streams])).collect::<Vec<_>>(),
        "samples_columns": ["t_secs", "phase", "rss_kb", "cpu_pct", "fds", "streams_ready"],
    });
    if let Some(dir) = std::path::Path::new(&a.out).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(&a.out, serde_json::to_string_pretty(&out).unwrap()) {
        eprintln!("cannot write {}: {e}", a.out);
    }

    // Markdown summary.
    println!(
        "\n## Load test: N={} scenario={} ({}x compression)\n",
        a.n, a.scenario, a.compress
    );
    println!("Report: `{}`. Ramp took {ramp_secs:.1} s.\n", a.out);
    println!("| Phase | s | req | req/s | 429 | 5xx | other | transport | cmd e2e p50/p99 ms |");
    println!("|---|---|---|---|---|---|---|---|---|");
    for (name, p) in &phases {
        println!(
            "| {name} | {:.0} | {} | {:.1} | {} | {} | {} | {} | {:.1} / {:.1} |",
            p["secs"].as_f64().unwrap_or(0.0),
            p["requests"],
            p["req_per_sec"].as_f64().unwrap_or(0.0),
            p["status_429"],
            p["status_5xx"],
            p["status_other_error"],
            p["transport_errors"],
            p["command_e2e"]["p50_ms"].as_f64().unwrap_or(0.0),
            p["command_e2e"]["p99_ms"].as_f64().unwrap_or(0.0),
        );
    }
    for (name, p) in &phases {
        println!("\n### {name}\n\n| Route | n | p50 | p95 | p99 | max | statuses |\n|---|---|---|---|---|---|---|");
        for (route, r) in p["routes"].as_object().into_iter().flatten() {
            println!(
                "| {route} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {}{} |",
                r["count"],
                r["p50_ms"].as_f64().unwrap_or(0.0),
                r["p95_ms"].as_f64().unwrap_or(0.0),
                r["p99_ms"].as_f64().unwrap_or(0.0),
                r["max_ms"].as_f64().unwrap_or(0.0),
                r["status"],
                if r["transport_errors"].as_u64().unwrap_or(0) > 0 {
                    format!(" transport={}", r["transport_errors"])
                } else {
                    String::new()
                },
            );
        }
    }
    println!("\nCommands: {}", out["commands"]);
    println!(
        "Streams: {}; heartbeats skipped (fixed server bucket): {}",
        out["streams"], out["heartbeats_skipped_fixed_server_limit"]
    );
    println!("Resources: {}", out["resources"]);
    if a.scenario != "ramp-steady" {
        println!("Storm: {}", out["storm"]);
    }
    if a.scenario == "abuse" {
        println!("Abuse: {}", out["abuse"]);
    }
    println!("\n| SLO | ok | value |\n|---|---|---|");
    for s in &slos {
        println!(
            "| {} | {} | {} |",
            s.name,
            if s.ok { "yes" } else { "**NO**" },
            s.value
        );
    }
    if failed.is_empty() {
        println!("\nAll SLOs met.");
        0
    } else {
        println!("\n{} SLO(s) failed.", failed.len());
        1
    }
}
