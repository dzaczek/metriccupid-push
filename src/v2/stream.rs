//! `GET /v2/stream`: WebSocket delivery of queued commands to Mac devices.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;

use super::apns::OfflineReason;
use super::store::{self, MAX_COMMANDS};
use crate::api::AppState;

/// Max concurrent streams per server.
pub const MAX_STREAMS: usize = 1024;
/// Frames buffered per stream before `deliver` reports the stream as busy.
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
}

/// Live streams by group and device. One stream per device: a new
/// connection replaces the old one (whose channel then closes).
#[derive(Default)]
pub struct Hub {
    inner: Mutex<HashMap<String, HashMap<String, Conn>>>,
    next_id: AtomicU64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct HubFull;

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, HashMap<String, Conn>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn register(
        &self,
        group: &str,
        device: &str,
    ) -> Result<(u64, mpsc::Receiver<CommandFrame>), HubFull> {
        let mut map = self.lock();
        let replacing = map.get(group).is_some_and(|g| g.contains_key(device));
        let total: usize = map.values().map(HashMap::len).sum();
        if !replacing && total >= MAX_STREAMS {
            return Err(HubFull);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        map.entry(group.to_string())
            .or_default()
            .insert(device.to_string(), Conn { id, tx });
        Ok((id, rx))
    }

    /// Remove the registration if it still belongs to connection `id`.
    pub fn unregister(&self, group: &str, device: &str, id: u64) {
        let mut map = self.lock();
        if let Some(g) = map.get_mut(group) {
            if g.get(device).is_some_and(|c| c.id == id) {
                g.remove(device);
            }
            if g.is_empty() {
                map.remove(group);
            }
        }
    }

    /// Drop a device's stream (device deleted).
    pub fn remove_device(&self, group: &str, device: &str) {
        let mut map = self.lock();
        if let Some(g) = map.get_mut(group) {
            g.remove(device);
            if g.is_empty() {
                map.remove(group);
            }
        }
    }

    /// Hand `frame` to every live stream of the group; `true` if at least one took it.
    pub fn deliver(&self, group: &str, frame: &CommandFrame) -> bool {
        let map = self.lock();
        let Some(g) = map.get(group) else {
            return false;
        };
        let mut delivered = false;
        for c in g.values() {
            delivered |= c.tx.try_send(frame.clone()).is_ok();
        }
        delivered
    }

    pub fn is_online(&self, group: &str, device: &str) -> bool {
        self.lock()
            .get(group)
            .is_some_and(|g| g.get(device).is_some_and(|c| !c.tx.is_closed()))
    }

    /// Whether any Mac stream of the group is live.
    pub fn group_online(&self, group: &str) -> bool {
        self.lock()
            .get(group)
            .is_some_and(|g| g.values().any(|c| !c.tx.is_closed()))
    }

    pub fn len(&self) -> usize {
        self.lock().values().map(HashMap::len).sum()
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
    conn_id: u64,
    rx: mpsc::Receiver<CommandFrame>,
) {
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

    let (last_seen, bye, reason) = serve(socket, &state, &group, &device, rx).await;
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

    #[test]
    fn deliver_replace_unregister() {
        let hub = Hub::new();
        assert!(!hub.deliver("g", &frame(1)));
        let (id1, mut rx1) = hub.register("g", "mac").unwrap();
        assert!(hub.deliver("g", &frame(1)));
        assert_eq!(rx1.try_recv().unwrap(), frame(1));
        // A second connection for the same device replaces the first.
        let (id2, mut rx2) = hub.register("g", "mac").unwrap();
        assert!(rx1.try_recv().is_err());
        assert!(hub.deliver("g", &frame(2)));
        assert_eq!(rx2.try_recv().unwrap(), frame(2));
        // The old connection's cleanup must not remove the new one.
        hub.unregister("g", "mac", id1);
        assert!(hub.is_online("g", "mac"));
        hub.unregister("g", "mac", id2);
        assert!(hub.is_empty());
    }

    #[test]
    fn remove_device_closes_channel() {
        let hub = Hub::new();
        let (_, mut rx) = hub.register("g", "mac").unwrap();
        hub.remove_device("g", "mac");
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
    }
}
