//! Mac presence per group (PROTOCOL.md, "Presence"): when the last Mac stream
//! of a group goes away and stays away, the group's phones get one "offline"
//! push; when a Mac comes back after that, one "back online" push.
//!
//! State is in memory only. After a server restart no offline notice is
//! pending and none has been sent, so a Mac that reconnects is not announced.

use std::collections::HashMap;
use std::sync::Mutex;

use super::apns::{OfflineReason, PresenceNote};

#[derive(Debug, Clone, Copy)]
struct Pending {
    due: u64,
    reason: OfflineReason,
    since: u64,
}

#[derive(Debug, Default)]
struct GroupState {
    /// The last presence push sent to the group was "offline".
    notified_offline: bool,
    /// An offline push waiting for its grace period to pass.
    pending: Option<Pending>,
}

pub struct Presence {
    grace: u64,
    inner: Mutex<HashMap<String, GroupState>>,
}

impl Presence {
    /// `grace`: seconds a dropped stream (no `bye`) may stay down before the
    /// offline push.
    pub fn new(grace: u64) -> Self {
        Self {
            grace,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, GroupState>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A Mac stream of `group` is up: cancel a pending offline push and
    /// return the "back online" notice if the phones were told it was offline.
    pub fn connected(&self, group: &str, now: u64) -> Option<PresenceNote> {
        let g = self.lock().remove(group)?;
        g.notified_offline
            .then_some(PresenceNote::Online { since: now })
    }

    /// The group has no Mac stream left. `bye` is the reason the Mac gave
    /// (offline immediately), `None` a lost connection (offline after the
    /// grace period). `since` is when the server last heard from the Mac.
    pub fn disconnected(&self, group: &str, bye: Option<OfflineReason>, since: u64, now: u64) {
        let mut map = self.lock();
        let g = map.entry(group.to_string()).or_default();
        if g.notified_offline {
            return;
        }
        let (reason, due) = match bye {
            Some(r) => (r, now),
            None => (OfflineReason::Lost, now.saturating_add(self.grace)),
        };
        let since = g.pending.map_or(since, |p| p.since.min(since));
        g.pending = Some(Pending { due, reason, since });
    }

    /// Offline notices due at `now`, marked as sent. Groups for which
    /// `online` is true (a Mac reconnected in a race) are dropped instead.
    pub fn due(&self, now: u64, online: impl Fn(&str) -> bool) -> Vec<(String, PresenceNote)> {
        let mut map = self.lock();
        let mut out = Vec::new();
        for (group, g) in map.iter_mut() {
            let Some(p) = g.pending else { continue };
            if online(group) {
                g.pending = None;
            } else if p.due <= now {
                g.pending = None;
                g.notified_offline = true;
                out.push((
                    group.clone(),
                    PresenceNote::Offline {
                        reason: p.reason,
                        since: p.since,
                    },
                ));
            }
        }
        map.retain(|_, g| g.notified_offline || g.pending.is_some());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFF: fn(&str) -> bool = |_| false;

    #[test]
    fn lost_connection_waits_for_grace_and_reconnect_cancels() {
        let p = Presence::new(120);
        p.disconnected("g", None, 95, 100);
        assert!(p.due(219, OFF).is_empty());
        assert_eq!(p.connected("g", 150), None, "reconnect within grace");
        assert!(p.due(1000, OFF).is_empty());

        p.disconnected("g", None, 95, 100);
        assert_eq!(
            p.due(220, OFF),
            vec![(
                "g".to_string(),
                PresenceNote::Offline {
                    reason: OfflineReason::Lost,
                    since: 95
                }
            )]
        );
        assert!(p.due(10_000, OFF).is_empty(), "sent once");
    }

    #[test]
    fn bye_is_immediate_and_no_duplicates() {
        let p = Presence::new(120);
        p.disconnected("g", Some(OfflineReason::Quit), 100, 100);
        assert_eq!(p.due(100, OFF).len(), 1);
        // Another disconnect while already announced offline: nothing.
        p.disconnected("g", Some(OfflineReason::Sleep), 101, 101);
        assert!(p.due(200, OFF).is_empty());
        assert_eq!(
            p.connected("g", 300),
            Some(PresenceNote::Online { since: 300 })
        );
        assert_eq!(p.connected("g", 301), None, "back online sent once");
    }

    #[test]
    fn bye_overrides_pending_lost_and_online_race_drops() {
        let p = Presence::new(120);
        p.disconnected("g", None, 90, 100);
        p.disconnected("g", Some(OfflineReason::Sleep), 100, 105);
        assert_eq!(
            p.due(105, OFF),
            vec![(
                "g".to_string(),
                PresenceNote::Offline {
                    reason: OfflineReason::Sleep,
                    since: 90
                }
            )]
        );
        let q = Presence::new(0);
        q.disconnected("h", None, 1, 1);
        assert!(q.due(5, |_| true).is_empty());
        assert!(q.due(5, OFF).is_empty(), "pending dropped");
    }
}
