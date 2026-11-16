//! `GET /v2/stream`: WebSocket delivery of queued commands to Mac devices.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;

use super::apns::OfflineReason;
use super::store::{self, MAX_COMMANDS};
use crate::api::AppState;
use crate::limits::ip_key;

/// Default `WS_MAX_STREAMS`: concurrent streams per server.
pub const MAX_STREAMS: usize = 1024;
/// Default `WS_MAX_MACS_PER_GROUP`.
pub const MAX_MACS_PER_GROUP: u32 = 3;
/// Default `WS_MAX_PER_IP`.
pub const MAX_PER_IP: u32 = 20;
/// Frames buffered per stream; when full the stream is closed (1013) so the
/// Mac reconnects and gets the backlog from the queue.
pub const STREAM_BUFFER: usize = 64;
/// Largest frame accepted from a client (acks are tiny).
pub const MAX_CLIENT_FRAME: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandFrame {
    pub cursor: u64,
    pub id: String,
    pub sealed: String,
}

impl CommandFrame {
    fn to_json(&self) -> String {
        json!({
            "type": "command",
            "id": self.id,
            "sealed": self.sealed,
            "cursor": self.cursor,
        })
        .to_string()
    }
}

struct Conn {
    id: u64,
    tx: mpsc::Sender<CommandFrame>,
    /// Rate-limit key of the client IP.
    ip: IpAddr,
    /// Set when the hub dropped the stream because its buffer was full.
    overflow: Arc<AtomicBool>,
}

#[derive(Default)]
struct Inner {
    groups: HashMap<String, HashMap<String, Conn>>,
    per_ip: HashMap<IpAddr, u32>,
}

impl Inner {
    fn ip_count(&self, ip: IpAddr) -> u32 {
        self.per_ip.get(&ip).copied().unwrap_or(0)
    }

    fn ip_dec(&mut self, ip: IpAddr) {
        if let Some(n) = self.per_ip.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_ip.remove(&ip);
            }
        }
    }
}

/// Live streams by group and device. One stream per device: a new
/// connection replaces the old one (whose channel then closes). Quotas:
/// streams per server, Mac streams per group and streams per client IP; a
/// replacement of a device's own stream is exempt from the first two.
pub struct Hub {
    inner: Mutex<Inner>,
    next_id: AtomicU64,
    /// Open streams, kept next to the map so `len` never scans it.
    count: AtomicUsize,
    /// `WS_MAX_STREAMS` (live).
    pub max_streams: AtomicU32,
    /// `WS_MAX_MACS_PER_GROUP` (live).
    pub max_macs_per_group: AtomicU32,
    /// `WS_MAX_PER_IP` (live).
    pub max_per_ip: AtomicU32,
}

impl Default for Hub {
    fn default() -> Self {
        Self::with_limits(MAX_STREAMS as u32, MAX_MACS_PER_GROUP, MAX_PER_IP)
    }
}

/// Why a stream was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubFull {
    /// `WS_MAX_STREAMS` reached.
    Server,
    /// The group has `WS_MAX_MACS_PER_GROUP` streams.
    Group,
    /// The client IP has `WS_MAX_PER_IP` streams.
    Ip,
}

impl HubFull {
    pub fn code(self) -> &'static str {
        match self {
            HubFull::Server => "too_many_streams",
            HubFull::Group => "too_many_group_streams",
            HubFull::Ip => "too_many_ip_streams",
        }
    }
}

/// A registered stream: its id, its frames, and the overflow flag (the hub
/// closed it because the buffer was full).
pub struct Registration {
    pub id: u64,
    pub rx: mpsc::Receiver<CommandFrame>,
    pub overflow: Arc<AtomicBool>,
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(max_streams: u32, max_macs_per_group: u32, max_per_ip: u32) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            next_id: AtomicU64::new(0),
            count: AtomicUsize::new(0),
            max_streams: AtomicU32::new(max_streams),
            max_macs_per_group: AtomicU32::new(max_macs_per_group),
            max_per_ip: AtomicU32::new(max_per_ip),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn check(&self, inner: &Inner, group: &str, device: &str, ip: IpAddr) -> Result<(), HubFull> {
        let over_ip = || inner.ip_count(ip) >= self.max_per_ip.load(Ordering::Relaxed);
        let g = inner.groups.get(group);
        if let Some(old) = g.and_then(|g| g.get(device)) {
            // Replacing the device's own stream frees its slot: only a move
            // to another IP is checked.
            return if old.ip != ip && over_ip() {
                Err(HubFull::Ip)
            } else {
                Ok(())
            };
        }
        if self.count.load(Ordering::Relaxed) >= self.max_streams.load(Ordering::Relaxed) as usize {
            return Err(HubFull::Server);
        }
        if g.map_or(0, HashMap::len) >= self.max_macs_per_group.load(Ordering::Relaxed) as usize {
            return Err(HubFull::Group);
        }
        if over_ip() {
            return Err(HubFull::Ip);
        }
        Ok(())
    }

    /// Whether [`Hub::register`] would accept this stream now (checked
    /// before the upgrade, so a refused stream gets an HTTP error).
    pub fn can_register(&self, group: &str, device: &str, ip: IpAddr) -> Result<(), HubFull> {
        self.check(&self.lock(), group, device, ip_key(ip))
    }

    pub fn register(&self, group: &str, device: &str, ip: IpAddr) -> Result<Registration, HubFull> {
        let ip = ip_key(ip);
        let mut inner = self.lock();
        self.check(&inner, group, device, ip)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        let overflow = Arc::new(AtomicBool::new(false));
        let old = inner.groups.entry(group.to_string()).or_default().insert(
            device.to_string(),
            Conn {
                id,
                tx,
                ip,
                overflow: overflow.clone(),
            },
        );
        match old {
            Some(old) => inner.ip_dec(old.ip),
            None => {
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }
        *inner.per_ip.entry(ip).or_default() += 1;
        Ok(Registration { id, rx, overflow })
    }

    /// Remove `device` of `group` if `keep` allows; keeps the counters right.
    fn remove_where(
        &self,
        inner: &mut Inner,
        group: &str,
        device: &str,
        keep: impl Fn(&Conn) -> bool,
    ) {
        let Some(g) = inner.groups.get_mut(group) else {
            return;
        };
        let removed = match g.get(device) {
            Some(c) if !keep(c) => g.remove(device),
            _ => None,
        };
        if g.is_empty() {
            inner.groups.remove(group);
        }
        if let Some(c) = removed {
            self.count.fetch_sub(1, Ordering::Relaxed);
            inner.ip_dec(c.ip);
        }
    }

    /// Remove the registration if it still belongs to connection `id`.
    pub fn unregister(&self, group: &str, device: &str, id: u64) {
        let mut inner = self.lock();
        self.remove_where(&mut inner, group, device, |c| c.id != id);
    }

    /// Drop a device's stream (device deleted).
    pub fn remove_device(&self, group: &str, device: &str) {
        let mut inner = self.lock();
        self.remove_where(&mut inner, group, device, |_| false);
    }

    /// Drop every stream of the group (suspended); returns how many. Each
    /// one sees its channel close and ends with a close frame.
    pub fn remove_group(&self, group: &str) -> usize {
        let mut inner = self.lock();
        let Some(g) = inner.groups.remove(group) else {
            return 0;
        };
        self.count.fetch_sub(g.len(), Ordering::Relaxed);
        for c in g.values() {
            inner.ip_dec(c.ip);
        }
        g.len()
    }

    /// Hand `frame` to every live stream of the group; `true` if at least one
    /// took it. A stream whose buffer is full is dropped and told so (it
    /// closes with 1013): the Mac reconnects and gets the command from the
    /// queue instead of missing it for the rest of the session.
    pub fn deliver(&self, group: &str, frame: &CommandFrame) -> bool {
        let mut inner = self.lock();
        let Some(g) = inner.groups.get(group) else {
            return false;
        };
        let mut delivered = false;
        let mut full = Vec::new();
        for (device, c) in g {
            match c.tx.try_send(frame.clone()) {
                Ok(()) => delivered = true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    c.overflow.store(true, Ordering::Relaxed);
                    full.push((device.clone(), c.id));
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
        for (device, id) in full {
            self.remove_where(&mut inner, group, &device, |c| c.id != id);
        }
        delivered
    }

    pub fn is_online(&self, group: &str, device: &str) -> bool {
        self.lock()
            .groups
            .get(group)
            .is_some_and(|g| g.get(device).is_some_and(|c| !c.tx.is_closed()))
    }

    /// Whether any Mac stream of the group is live.
    pub fn group_online(&self, group: &str) -> bool {
        self.lock()
            .groups
            .get(group)
            .is_some_and(|g| g.values().any(|c| !c.tx.is_closed()))
    }

    /// Open streams (an atomic counter: no lock, no scan).
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum ClientFrame {
    Ack {
        cursor: u64,
    },
    /// The Mac is going offline on purpose (PROTOCOL.md, "Presence").
    Bye {
        reason: ByeReason,
    },
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum ByeReason {
    Quit,
    Disabled,
    Sleep,
}

impl From<ByeReason> for OfflineReason {
    fn from(r: ByeReason) -> Self {
        match r {
            ByeReason::Quit => OfflineReason::Quit,
            ByeReason::Disabled => OfflineReason::Disabled,
            ByeReason::Sleep => OfflineReason::Sleep,
        }
    }
}

/// `last_seen` is written to the database at most this often per stream.
const TOUCH_EVERY_SECS: u64 = 10;

async fn touch(state: &AppState, group: &str, device: &str, now: u64) {
    let (g, d) = (group.to_string(), device.to_string());
    if let Err(e) = state
        .v2()
        .store
        .call(move |c| store::touch_device(c, &g, &d, now))
        .await
    {
        tracing::error!(error = %e, "stream: cannot record last_seen");
    }
}

/// Serve one stream, then record presence: last_seen, and an offline notice
/// when it was the group's last Mac stream.
pub async fn run(
    socket: WebSocket,
    state: Arc<AppState>,
    group: String,
    device: String,
    reg: Registration,
) {
    let Registration {
        id: conn_id,
        rx,
        overflow,
    } = reg;
    let v2 = state.v2();
    let now = state.now();
    let metrics = state.metrics();
    let mut ev = crate::metrics::Event::new("ws_connect").group(&group);
    ev.device_id = Some(device.clone());
    metrics.record(ev);
    touch(&state, &group, &device, now).await;
    if let Some(note) = v2.presence.connected(&group, now) {
        let (st, g) = (state.clone(), group.clone());
        tokio::spawn(async move { super::push_presence(&st, &g, note).await });
    }

    let (last_seen, bye, reason) = serve(socket, &state, &group, &device, rx, &overflow).await;
    let mut ev = crate::metrics::Event::new("ws_disconnect")
        .group(&group)
        .outcome(reason);
    ev.device_id = Some(device.clone());
    ev.duration_s = Some(state.now().saturating_sub(now));
    metrics.record(ev);

    v2.hub.unregister(&group, &device, conn_id);
    let last_mac = !v2.hub.group_online(&group);
    if last_mac {
        v2.presence
            .disconnected(&group, bye.map(Into::into), last_seen, state.now());
    }
    touch(&state, &group, &device, last_seen).await;
    if last_mac && bye.is_some() {
        super::presence_tick(&state).await;
    }
}

async fn close(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await;
}

/// Serve one authenticated stream until it closes, is replaced, or goes idle.
/// Returns when the server last heard from the Mac, the `bye` reason, if any,
/// and why the stream ended.
async fn serve(
    mut socket: WebSocket,
    state: &Arc<AppState>,
    group: &str,
    device: &str,
    mut rx: mpsc::Receiver<CommandFrame>,
    overflow: &AtomicBool,
) -> (u64, Option<ByeReason>, &'static str) {
    let v2 = state.v2();
    let ping_every = v2.ws_ping;
    // No frame (pong included) for two ping intervals: the peer is gone.
    let idle_after = ping_every * 2 + Duration::from_secs(5);

    // Registration happened before this load, so a command posted in between
    // can arrive both here and on `rx`; `sent` filters that duplicate.
    let now = state.now();
    let mut seen = now;
    let mut touched = now;
    let g = group.to_string();
    let pending = v2
        .store
        .call(move |c| store::commands_since(c, &g, 0, now, MAX_COMMANDS))
        .await;
    let mut sent = HashSet::new();
    match pending {
        Ok((cmds, _)) => {
            for c in cmds {
                let f = CommandFrame {
                    cursor: c.cursor,
                    id: c.id,
                    sealed: c.sealed,
                };
                if socket
                    .send(Message::Text(f.to_json().into()))
                    .await
                    .is_err()
                {
                    return (seen, None, "send_failed");
                }
                sent.insert(f.cursor);
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "stream: cannot load pending commands");
            close(&mut socket, 1011, "storage error").await;
            return (seen, None, "storage_error");
        }
    }

    // Backlog sent and the stream is registered: from now on new commands
    // arrive live (and `POST /v2/commands` reports `delivered`).
    let ready = json!({ "type": "ready" }).to_string();
    if socket.send(Message::Text(ready.into())).await.is_err() {
        return (seen, None, "send_failed");
    }

    let mut ping = tokio::time::interval(ping_every);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let mut last_rx = Instant::now();
    let mut bye = None;
    let reason = loop {
        tokio::select! {
            frame = rx.recv() => match frame {
                Some(f) => {
                    if sent.remove(&f.cursor) {
                        continue;
                    }
                    if socket.send(Message::Text(f.to_json().into())).await.is_err() {
                        break "send_failed";
                    }
                }
                None if overflow.load(Ordering::Relaxed) => {
                    // Buffer was full: reconnecting replays the queue.
                    close(&mut socket, 1013, "backlog").await;
                    break "overflow";
                }
                None => {
                    close(&mut socket, 1000, "replaced").await;
                    break "replaced";
                }
            },
            msg = socket.recv() => {
                if matches!(msg, Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_) | Message::Close(_)))) {
                    last_rx = Instant::now();
                    seen = state.now();
                    if seen.saturating_sub(touched) >= TOUCH_EVERY_SECS {
                        touched = seen;
                        touch(state, group, device, seen).await;
                    }
                }
                match msg {
                    Some(Ok(Message::Text(t))) => match serde_json::from_str(t.as_str()) {
                        Ok(ClientFrame::Ack { cursor }) => {
                            let g = group.to_string();
                            if let Err(e) = v2.store.call(move |c| store::ack_command(c, &g, cursor)).await {
                                tracing::error!(error = %e, "stream: ack failed");
                            }
                        }
                        Ok(ClientFrame::Bye { reason }) => {
                            bye = Some(reason);
                            close(&mut socket, 1000, "bye").await;
                            break "bye";
                        }
                        Err(_) => {
                            close(&mut socket, 1008, "invalid frame").await;
                            break "invalid_frame";
                        }
                    },
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Binary(_))) => {
                        close(&mut socket, 1003, "text frames only").await;
                        break "binary_frame";
                    }
                    Some(Ok(Message::Close(_))) | None => break "closed",
                    Some(Err(_)) => break "error",
                }
            },
            _ = ping.tick() => {
                if last_rx.elapsed() > idle_after {
                    close(&mut socket, 1001, "idle").await;
                    break "idle";
                }
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break "send_failed";
                }
            }
        }
    };
    tracing::info!(group = %group, reason, "stream closed");
    (seen, bye, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(cursor: u64) -> CommandFrame {
        CommandFrame {
            cursor,
            id: format!("c{cursor}"),
            sealed: "AAAA".into(),
        }
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, n])
    }

    #[test]
    fn deliver_replace_unregister() {
        let hub = Hub::new();
        assert!(!hub.deliver("g", &frame(1)));
        let mut r1 = hub.register("g", "mac", ip(1)).unwrap();
        assert!(hub.deliver("g", &frame(1)));
        assert_eq!(r1.rx.try_recv().unwrap(), frame(1));
        // A second connection for the same device replaces the first.
        let mut r2 = hub.register("g", "mac", ip(1)).unwrap();
        assert!(r1.rx.try_recv().is_err());
        assert!(hub.deliver("g", &frame(2)));
        assert_eq!(r2.rx.try_recv().unwrap(), frame(2));
        assert_eq!(hub.len(), 1);
        // The old connection's cleanup must not remove the new one.
        hub.unregister("g", "mac", r1.id);
        assert!(hub.is_online("g", "mac"));
        hub.unregister("g", "mac", r2.id);
        assert!(hub.is_empty());
    }

    #[test]
    fn remove_device_closes_channel() {
        let hub = Hub::new();
        let mut r = hub.register("g", "mac", ip(1)).unwrap();
        hub.remove_device("g", "mac");
        assert!(matches!(
            r.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        assert!(hub.is_empty());
    }

    /// Lead #4: 1024 slots held by 103 groups (10 Macs each, from many IPs)
    /// refuse a new group, but every registered device can still reconnect.
    #[test]
    fn full_hub_refuses_new_streams_but_not_replacements() {
        let hub = Hub::with_limits(1024, 10, 20);
        let mut n = 0;
        'fill: for g in 0..103 {
            for d in 0..10 {
                if n == 1024 {
                    break 'fill;
                }
                let addr = IpAddr::from([10, 0, (n / 16) as u8, (n % 16) as u8]);
                hub.register(&format!("g{g}"), &format!("m{d}"), addr)
                    .unwrap();
                n += 1;
            }
        }
        assert_eq!(hub.len(), 1024);
        assert_eq!(
            hub.register("new", "mac", ip(1)).err(),
            Some(HubFull::Server)
        );
        assert_eq!(hub.can_register("new", "mac", ip(1)), Err(HubFull::Server));
        // A device replacing its own stream always fits.
        let addr = IpAddr::from([10, 0, 0, 0]);
        assert_eq!(hub.can_register("g0", "m0", addr), Ok(()));
        assert!(hub.register("g0", "m0", addr).is_ok());
        assert_eq!(hub.len(), 1024, "replacement keeps the count");
        hub.remove_group("g1");
        assert_eq!(hub.len(), 1014);
        assert!(hub.register("new", "mac", ip(1)).is_ok());
    }

    #[test]
    fn per_group_and_per_ip_quotas() {
        let hub = Hub::with_limits(100, 3, 4);
        for d in 0..3 {
            hub.register("g", &format!("m{d}"), ip(d)).unwrap();
        }
        // The fourth Mac of a group is refused; the others reconnect fine.
        assert_eq!(hub.register("g", "m3", ip(9)).err(), Some(HubFull::Group));
        assert!(hub.register("g", "m0", ip(0)).is_ok());
        // Four streams from one IP (other groups), then the fifth is refused.
        for g in 0..3 {
            hub.register(&format!("h{g}"), "mac", ip(7)).unwrap();
        }
        hub.register("g", "m1", ip(7)).unwrap(); // moved to ip 7: 4 there now
        assert_eq!(hub.register("h9", "mac", ip(7)).err(), Some(HubFull::Ip));
        // Moving a stream to a full IP is refused, staying on it is not.
        assert_eq!(hub.register("g", "m2", ip(7)).err(), Some(HubFull::Ip));
        assert!(hub.register("g", "m1", ip(7)).is_ok());
        // IPv6 is counted per /64.
        let hub = Hub::with_limits(100, 3, 1);
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::2".parse().unwrap();
        hub.register("g", "m0", a).unwrap();
        assert_eq!(hub.register("h", "m0", b).err(), Some(HubFull::Ip));
        // Freed slots are counted down again.
        hub.remove_device("g", "m0");
        assert!(hub.register("h", "m0", b).is_ok());
    }

    #[test]
    fn full_buffer_drops_the_stream_with_overflow_flag() {
        let hub = Hub::new();
        let mut r = hub.register("g", "mac", ip(1)).unwrap();
        for c in 0..STREAM_BUFFER as u64 {
            assert!(hub.deliver("g", &frame(c)));
        }
        assert!(!hub.deliver("g", &frame(999)), "full: not delivered");
        assert!(r.overflow.load(Ordering::Relaxed));
        assert!(!hub.is_online("g", "mac"));
        assert!(hub.is_empty());
        // The buffered frames are still received, then the channel ends.
        for c in 0..STREAM_BUFFER as u64 {
            assert_eq!(r.rx.try_recv().unwrap(), frame(c));
        }
        assert!(matches!(
            r.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
    }
}
