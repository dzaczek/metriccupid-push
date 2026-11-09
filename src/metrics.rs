//! Operational metrics for the admin panel: metadata only (alert content is
//! end-to-end encrypted and never seen here).
//!
//! Recording is a short mutex push into bounded in-memory buffers; a task
//! flushes them every [`FLUSH_INTERVAL`] in one SQLite transaction:
//!
//! - `events`: raw rows, kept `ADMIN_EVENTS_RETENTION_DAYS` (and at most
//!   [`MAX_EVENT_ROWS`]). Successful polls are not stored raw (only counted).
//! - `daily_agg`: per-day counters, kept [`AGG_RETENTION_DAYS`].
//! - `client_activity`: last activity, app version and country per device.
//!
//! Client IPs are never stored: only a truncated prefix (/24, /48) and the
//! Cloudflare country. Metrics are only collected while the admin panel is
//! enabled.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use rusqlite::params;

use crate::api::AppState;
use crate::limits::Clock;
use crate::v2::activity::ActivityEvent;
use crate::v2::apns::{ApnsSender, BoxFuture, PushContent, PushError, PushJob, DEVICE_HEADER};
use crate::v2::store::{Store, StoreError};

pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);
pub const AGG_RETENTION_DAYS: u64 = 400;
/// Raw events waiting for the next flush; more are only counted.
pub const MAX_PENDING: usize = 10_000;
/// Raw rows written per flush (a flood of 404s cannot fill the disk).
pub const MAX_RAW_PER_FLUSH: usize = 1_000;
/// Aggregate keys and device entries buffered per flush.
pub const MAX_AGG_KEYS: usize = 50_000;
pub const MAX_CLIENTS: usize = 10_000;
/// Hard cap on the `events` table, enforced by the hourly cleanup.
pub const MAX_EVENT_ROWS: i64 = 1_000_000;
/// API latencies kept in memory for p50 / p95.
pub const LATENCY_SAMPLES: usize = 4096;
/// The client app header (PROTOCOL.md section 5.3).
pub const CLIENT_HEADER: &str = "x-mc-client";

/// Successful polls: counted per day, not stored as raw rows.
const POLL_ROUTES: &[&str] = &["messages.get", "commands.get", "status", "devices.list"];

/// One metadata event. `kind` values: `api`, `push`, `ws_connect`,
/// `ws_disconnect`, `presence`, `licence`, `ban`, `admin_login`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    pub ts: u64,
    pub kind: &'static str,
    pub group_id: Option<String>,
    pub device_id: Option<String>,
    pub route: Option<&'static str>,
    pub status: Option<u16>,
    pub outcome: Option<&'static str>,
    pub detail: Option<String>,
    pub latency_ms: Option<u64>,
    pub duration_s: Option<u64>,
    pub country: Option<String>,
    pub ip_prefix: Option<String>,
    pub app_version: Option<String>,
    pub apns_status: Option<u16>,
    pub apns_reason: Option<String>,
    pub bytes: Option<u64>,
}

impl Event {
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    pub fn group(mut self, g: &str) -> Self {
        self.group_id = Some(g.to_string());
        self
    }

    pub fn route(mut self, r: &'static str) -> Self {
        self.route = Some(r);
        self
    }

    pub fn outcome(mut self, o: &'static str) -> Self {
        self.outcome = Some(o);
        self
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }

    pub fn ip(mut self, ip: IpAddr) -> Self {
        self.ip_prefix = Some(ip_prefix(ip));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AggKey {
    day: i64,
    kind: &'static str,
    route: &'static str,
    status: u16,
    outcome: &'static str,
    group: String,
    country: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct AggVal {
    count: u64,
    latency: u64,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct ClientSeen {
    first: u64,
    last: u64,
    app_version: Option<String>,
    country: Option<String>,
}

#[derive(Default)]
struct Buffer {
    raw: Vec<Event>,
    agg: HashMap<AggKey, AggVal>,
    clients: HashMap<(String, String), ClientSeen>,
}

pub struct Metrics {
    enabled: bool,
    retention_days: u64,
    clock: Arc<dyn Clock>,
    buf: Mutex<Buffer>,
    latencies: Mutex<VecDeque<u32>>,
    dropped: AtomicU64,
    started: Instant,
}

/// `/24` for IPv4, `/48` for IPv6: enough to spot an abusive network, not
/// enough to identify a household.
pub fn ip_prefix(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// `X-MC-Client`, if it is short printable ASCII.
pub fn client_header(h: &HeaderMap) -> Option<String> {
    let v = h.get(CLIENT_HEADER)?.to_str().ok()?.trim();
    (!v.is_empty() && v.len() <= 64 && v.bytes().all(|b| (0x20..0x7f).contains(&b)))
        .then(|| v.to_string())
}

/// Days since the Unix epoch.
pub fn day_of(ts: u64) -> i64 {
    (ts / 86_400) as i64
}

/// `YYYY-MM-DD` (UTC) of a day number.
pub fn day_str(day: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(day * 86_400)
        .map(|t| t.date().to_string())
        .unwrap_or_default()
}

fn keep_raw(e: &Event) -> bool {
    !(e.kind == "api"
        && e.status.is_some_and(|s| (200..300).contains(&s))
        && e.route.is_some_and(|r| POLL_ROUTES.contains(&r)))
}

impl Metrics {
    pub fn new(enabled: bool, retention_days: u64, clock: Arc<dyn Clock>) -> Self {
        Self {
            enabled,
            retention_days,
            clock,
            buf: Mutex::new(Buffer::default()),
            latencies: Mutex::new(VecDeque::with_capacity(LATENCY_SAMPLES)),
            dropped: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Events dropped because a buffer was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Record `e`; `ts` 0 means now. Never blocks on I/O.
    pub fn record(&self, mut e: Event) {
        if !self.enabled {
            return;
        }
        if e.ts == 0 {
            e.ts = self.clock.now();
        }
        if e.kind == "api" {
            if let Some(l) = e.latency_ms {
                let mut q = self.latencies.lock().unwrap_or_else(|p| p.into_inner());
                if q.len() >= LATENCY_SAMPLES {
                    q.pop_front();
                }
                q.push_back(l.min(u64::from(u32::MAX)) as u32);
            }
        }
        let mut b = self.buf.lock().unwrap_or_else(|p| p.into_inner());
        let key = AggKey {
            day: day_of(e.ts),
            kind: e.kind,
            route: e.route.unwrap_or(""),
            status: e.status.unwrap_or(0),
            outcome: e.outcome.unwrap_or(""),
            group: e.group_id.clone().unwrap_or_default(),
            country: e.country.clone().unwrap_or_default(),
        };
        if b.agg.len() < MAX_AGG_KEYS || b.agg.contains_key(&key) {
            let v = b.agg.entry(key).or_default();
            v.count += 1;
            v.latency += e.latency_ms.unwrap_or(0);
            v.bytes += e.bytes.unwrap_or(0);
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(g) = &e.group_id {
            let k = (g.clone(), e.device_id.clone().unwrap_or_default());
            if b.clients.len() < MAX_CLIENTS || b.clients.contains_key(&k) {
                let c = b.clients.entry(k).or_insert_with(|| ClientSeen {
                    first: e.ts,
                    last: e.ts,
                    app_version: None,
                    country: None,
                });
                c.first = c.first.min(e.ts);
                c.last = c.last.max(e.ts);
                if e.app_version.is_some() {
                    c.app_version.clone_from(&e.app_version);
                }
                if e.country.is_some() {
                    c.country.clone_from(&e.country);
                }
            }
        }
        if keep_raw(&e) {
            if b.raw.len() < MAX_PENDING {
                b.raw.push(e);
            } else {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// p50 and p95 of the last [`LATENCY_SAMPLES`] API latencies (ms).
    pub fn latency_percentiles(&self) -> Option<(u32, u32)> {
        let mut v: Vec<u32> = self
            .latencies
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .collect();
        if v.is_empty() {
            return None;
        }
        v.sort_unstable();
        let at = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
        Some((at(0.50), at(0.95)))
    }

    /// Write everything buffered in one transaction.
    pub async fn flush(&self, store: &Store) {
        if !self.enabled {
            return;
        }
        let b = std::mem::take(&mut *self.buf.lock().unwrap_or_else(|p| p.into_inner()));
        if b.raw.is_empty() && b.agg.is_empty() && b.clients.is_empty() {
            return;
        }
        let over = b.raw.len().saturating_sub(MAX_RAW_PER_FLUSH);
        self.dropped.fetch_add(over as u64, Ordering::Relaxed);
        if let Err(e) = store.call(move |c| write_buffer(c, b)).await {
            tracing::error!(error = %e, "metrics flush failed");
        }
    }

    /// Retention: raw events after `ADMIN_EVENTS_RETENTION_DAYS` (and beyond
    /// [`MAX_EVENT_ROWS`]), aggregates after [`AGG_RETENTION_DAYS`], device
    /// activity of deleted groups. Returns raw rows deleted.
    pub async fn cleanup(&self, store: &Store) -> Result<usize, StoreError> {
        let now = self.clock.now();
        let raw_cut = now.saturating_sub(self.retention_days * 86_400) as i64;
        let agg_cut = day_str(day_of(now) - AGG_RETENTION_DAYS as i64);
        store
            .call(move |c| {
                let n = c.execute("DELETE FROM events WHERE ts < ?1", [raw_cut])?;
                let m = c.execute(
                    "DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?1",
                    [MAX_EVENT_ROWS],
                )?;
                c.execute("DELETE FROM daily_agg WHERE day < ?1", [agg_cut])?;
                c.execute(
                    "DELETE FROM client_activity WHERE group_id NOT IN (SELECT group_id FROM groups)",
                    [],
                )?;
                Ok(n + m)
            })
            .await
    }
}

fn write_buffer(c: &mut rusqlite::Connection, b: Buffer) -> Result<(), StoreError> {
    let tx = c.transaction()?;
    {
        let mut ins = tx.prepare_cached(
            "INSERT INTO events (ts, kind, group_id, device_id, route, status, outcome, detail,
                 latency_ms, duration_s, country, ip_prefix, app_version, apns_status, apns_reason, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )?;
        let i64_of = |v: Option<u64>| v.map(|x| x.min(i64::MAX as u64) as i64);
        for e in b.raw.iter().take(MAX_RAW_PER_FLUSH) {
            ins.execute(params![
                e.ts as i64,
                e.kind,
                e.group_id,
                e.device_id,
                e.route,
                e.status,
                e.outcome,
                e.detail,
                i64_of(e.latency_ms),
                i64_of(e.duration_s),
                e.country,
                e.ip_prefix,
                e.app_version,
                e.apns_status,
                e.apns_reason,
                i64_of(e.bytes),
            ])?;
        }
        let mut agg = tx.prepare_cached(
            "INSERT INTO daily_agg (day, kind, route, status, outcome, group_id, country, count, latency_ms_sum, bytes_sum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT (day, kind, route, status, outcome, group_id, country) DO UPDATE SET
                 count = count + ?8, latency_ms_sum = latency_ms_sum + ?9, bytes_sum = bytes_sum + ?10",
        )?;
        for (k, v) in &b.agg {
            agg.execute(params![
                day_str(k.day),
                k.kind,
                k.route,
                k.status,
                k.outcome,
                k.group,
                k.country,
                v.count as i64,
                v.latency as i64,
                v.bytes as i64,
            ])?;
        }
        let mut cl = tx.prepare_cached(
            "INSERT INTO client_activity (group_id, device_id, first_seen, last_seen, app_version, country)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (group_id, device_id) DO UPDATE SET
                 first_seen = MIN(first_seen, ?3), last_seen = MAX(last_seen, ?4),
                 app_version = COALESCE(?5, app_version), country = COALESCE(?6, country)",
        )?;
        for ((g, d), s) in &b.clients {
            cl.execute(params![
                g,
                d,
                s.first as i64,
                s.last as i64,
                s.app_version,
                s.country
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

// ------------------------------------------------------------- recording ---

/// Set by API handlers on their response so [`track`] can record the
/// route, outcome label and (authenticated) group.
#[derive(Debug, Clone)]
pub struct ApiTag {
    pub route: &'static str,
    pub outcome: &'static str,
    pub group: Option<String>,
}

/// Middleware on the public router: one `api` event per request.
pub async fn track(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let metrics = state.metrics().clone();
    if !metrics.enabled() || req.uri().path() == "/healthz" {
        return next.run(req).await;
    }
    let started = Instant::now();
    let headers = req.headers();
    let ip = state.client_ip(peer, headers);
    let country = state.client_country(peer, headers);
    let app_version = client_header(headers);
    let device = headers
        .get(DEVICE_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|d| crate::v2::is_id128(d))
        .map(str::to_string);
    let bytes = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    let response = next.run(req).await;
    let tag = response.extensions().get::<ApiTag>();
    let group = tag.and_then(|t| t.group.clone());
    metrics.record(Event {
        kind: "api",
        // The device id is signed, so it is only kept for authenticated requests.
        device_id: group.as_ref().and(device),
        group_id: group,
        route: Some(tag.map_or("unmatched", |t| t.route)),
        status: Some(response.status().as_u16()),
        outcome: tag.map(|t| t.outcome),
        latency_ms: Some(started.elapsed().as_millis() as u64),
        country,
        ip_prefix: Some(ip_prefix(ip)),
        app_version,
        bytes,
        ..Event::default()
    });
    response
}

/// Push type label: `alert`, `result`, `presence`, `liveactivity`, `start`.
pub fn push_type(job: &PushJob) -> &'static str {
    match &job.content {
        PushContent::Sealed(m) => m.t.as_str(),
        PushContent::Presence(_) => "presence",
        PushContent::Activity(n) if n.event == ActivityEvent::Start => "start",
        PushContent::Activity(_) => "liveactivity",
    }
}

/// Wraps the APNs sender: one `push` event per push, whatever the path
/// (fan-out, presence, Live Activity, gateway).
pub struct MeteredSender {
    pub inner: Arc<dyn ApnsSender>,
    pub metrics: Arc<Metrics>,
    /// `direct`, `gateway` or `mock`.
    pub via: &'static str,
}

impl ApnsSender for MeteredSender {
    fn send<'a>(&'a self, job: &'a PushJob) -> BoxFuture<'a, Result<(), PushError>> {
        Box::pin(async move {
            let started = Instant::now();
            let r = self.inner.send(job).await;
            if self.metrics.enabled() {
                let (outcome, status, reason) = match &r {
                    Ok(()) => ("sent", None, None),
                    Err(PushError::Unregistered) => ("unregistered", Some(410), None),
                    Err(PushError::Rejected { status, reason }) => (
                        "failed",
                        Some(*status),
                        Some(reason.chars().take(64).collect()),
                    ),
                    Err(PushError::Transport) => ("failed", None, Some("transport".to_string())),
                };
                self.metrics.record(Event {
                    kind: "push",
                    group_id: Some(job.group_id.clone()),
                    route: Some(push_type(job)),
                    outcome: Some(outcome),
                    detail: Some(format!("{}/{}", self.via, job.env.as_str())),
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    apns_status: status,
                    apns_reason: reason,
                    ..Event::default()
                });
            }
            r
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(u64);
    impl Clock for Fixed {
        fn now(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn prefixes_truncate() {
        assert_eq!(ip_prefix("203.0.113.77".parse().unwrap()), "203.0.113.0/24");
        assert_eq!(
            ip_prefix("2001:db8:abcd:12::1".parse().unwrap()),
            "2001:db8:abcd::/48"
        );
        assert_eq!(
            ip_prefix("::ffff:198.51.100.9".parse().unwrap()),
            "198.51.100.0/24"
        );
    }

    #[test]
    fn day_strings() {
        assert_eq!(day_str(day_of(1_794_787_200)), "2026-11-16");
        assert_eq!(day_str(0), "1970-01-01");
    }

    #[test]
    fn client_header_sanitized() {
        let mut h = HeaderMap::new();
        assert_eq!(client_header(&h), None);
        h.insert(
            CLIENT_HEADER,
            "MetricCupid-Mac/1.32.0 (151)".parse().unwrap(),
        );
        assert_eq!(
            client_header(&h).as_deref(),
            Some("MetricCupid-Mac/1.32.0 (151)")
        );
        h.insert(CLIENT_HEADER, "x".repeat(65).parse().unwrap());
        assert_eq!(client_header(&h), None);
    }

    #[test]
    fn polls_are_counted_not_stored_and_buffers_are_bounded() {
        let m = Metrics::new(true, 30, Arc::new(Fixed(1000)));
        let poll = Event {
            kind: "api",
            route: Some("messages.get"),
            status: Some(200),
            latency_ms: Some(3),
            ..Event::default()
        };
        m.record(poll.clone());
        m.record(Event {
            status: Some(401),
            ..poll.clone()
        });
        {
            let b = m.buf.lock().unwrap();
            assert_eq!(b.raw.len(), 1, "only the 401 is raw");
            assert_eq!(b.agg.len(), 2);
        }
        for _ in 0..(MAX_PENDING + 10) {
            m.record(Event::new("ban"));
        }
        assert_eq!(m.buf.lock().unwrap().raw.len(), MAX_PENDING);
        assert!(m.dropped() >= 10);
        assert_eq!(m.latency_percentiles(), Some((3, 3)));

        let off = Metrics::new(false, 30, Arc::new(Fixed(1000)));
        off.record(poll);
        assert!(off.buf.lock().unwrap().agg.is_empty(), "disabled: no-op");
    }
}
