//! Live Activities (PROTOCOL.md, "Live Activity"): the iPhone's Dynamic Island
//! and Lock Screen card show the group's alert counts.
//!
//! ActivityKit applies `content-state` itself, without the Notification
//! Service Extension, so it travels in **plaintext**: by default counts only;
//! up to [`MAX_LINES`] short lines when the user turns host names on, on the
//! Mac. The server keeps the latest state per group in memory, coalesces
//! updates (at most one push per [`COALESCE_SECS`]) because Apple budgets
//! Live Activity updates, and re-sends it with `mac_online: false` when the
//! Mac goes offline (presence).

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Appended to `APNS_TOPIC` for `apns-push-type: liveactivity`.
pub const TOPIC_SUFFIX: &str = ".push-type.liveactivity";
/// The Swift type of the activity, for push-to-start (`attributes-type`).
pub const ATTRIBUTES_TYPE: &str = "AlertsActivityAttributes";
/// Lines of host / service text the Mac may add (host names setting).
pub const MAX_LINES: usize = 4;
/// Characters per line.
pub const MAX_LINE_CHARS: usize = 40;
/// Largest alert count accepted per severity.
pub const MAX_COUNT: u32 = 100_000;
/// Minimum seconds between two pushes of one group's activity.
pub const COALESCE_SECS: u64 = 5;
/// iOS ends a Live Activity after 8 h. A token registered longer ago than
/// this belongs to an ended activity; a push-to-start is not repeated within
/// this time either (the started activity may not have registered its token).
pub const ACTIVITY_MAX_SECS: u64 = 8 * 3600;
/// `stale_secs` bounds.
pub const MIN_STALE_SECS: u64 = 60;
pub const MAX_STALE_SECS: u64 = 12 * 3600;
/// Live Activity pushes expire after this long.
pub const ACTIVITY_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LineSeverity {
    Critical,
    Warning,
    Unknown,
    Info,
}

/// One "severity + host / service" line (host names setting only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityLine {
    pub severity: LineSeverity,
    pub text: String,
}

/// The `content-state` of `AlertsActivityAttributes`, exactly as sent to
/// APNs. `updated_at` is when the server received the state from the Mac.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentState {
    pub critical: u32,
    pub warning: u32,
    pub unknown: u32,
    pub mac_online: bool,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<ActivityLine>,
}

impl ContentState {
    /// Counts within bounds; at most [`MAX_LINES`] lines of 1..=40 characters
    /// without control characters.
    pub fn validate(&self) -> Result<(), &'static str> {
        if [self.critical, self.warning, self.unknown]
            .iter()
            .any(|&n| n > MAX_COUNT)
        {
            return Err("counts must be at most 100000");
        }
        if self.lines.len() > MAX_LINES {
            return Err("at most 4 lines");
        }
        let line_ok = |l: &ActivityLine| {
            let n = l.text.chars().count();
            (1..=MAX_LINE_CHARS).contains(&n) && !l.text.chars().any(char::is_control)
        };
        if !self.lines.iter().all(line_ok) {
            return Err("each line text must be 1 to 40 characters without control characters");
        }
        Ok(())
    }

    /// `relevance-score`: the worst severity first if the phone shows several.
    pub fn relevance(&self) -> u32 {
        if self.critical > 0 {
            100
        } else if self.warning > 0 {
            50
        } else {
            10
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActivityEvent {
    Start,
    Update,
    End,
}

impl ActivityEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            ActivityEvent::Start => "start",
            ActivityEvent::Update => "update",
            ActivityEvent::End => "end",
        }
    }
}

/// One Live Activity push (also the `activity` of a gateway job).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityNote {
    pub event: ActivityEvent,
    /// `aps.timestamp`: ActivityKit ignores pushes older than the last one.
    pub timestamp: u64,
    pub state: ContentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_date: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dismissal_date: Option<u64>,
}

/// Fixed text of the push-to-start alert (counts only).
pub fn start_alert_body(s: &ContentState) -> String {
    match s.critical {
        1 => "1 critical alert".to_string(),
        n => format!("{n} critical alerts"),
    }
}

/// Build the APNs payload of a Live Activity push (PROTOCOL.md, "Live Activity").
pub fn build_activity_payload(n: &ActivityNote) -> String {
    let mut aps = json!({
        "timestamp": n.timestamp,
        "event": n.event.as_str(),
        "content-state": n.state,
        "relevance-score": n.state.relevance(),
    });
    if let Some(s) = n.stale_date {
        aps["stale-date"] = json!(s);
    }
    if let Some(d) = n.dismissal_date {
        aps["dismissal-date"] = json!(d);
    }
    if n.event == ActivityEvent::Start {
        aps["attributes-type"] = json!(ATTRIBUTES_TYPE);
        aps["attributes"] = json!({});
        aps["alert"] = json!({ "title": "MetricCupid", "body": start_alert_body(&n.state) });
    }
    json!({ "aps": aps }).to_string()
}

/// A push the caller should send now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub note: ActivityNote,
    /// The critical count went up since the last push: `apns-priority` 10.
    pub raise: bool,
}

#[derive(Debug, Default)]
struct GroupActivity {
    /// Latest content-state (with the presence `mac_online` applied).
    state: Option<ContentState>,
    stale_secs: Option<u64>,
    /// `end` sticks until it is sent.
    event: Option<ActivityEvent>,
    pending: bool,
    last_sent: Option<u64>,
    last_ts: u64,
    sent_critical: u32,
    /// device id -> when the server last sent it a push-to-start.
    started: HashMap<String, u64>,
}

/// Latest state and coalescing per group. In memory only: after a restart
/// the next state from the Mac (at most 15 min later, heartbeat) restores it.
#[derive(Default)]
pub struct Activities {
    inner: Mutex<HashMap<String, GroupActivity>>,
}

impl Activities {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, GroupActivity>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new state from the Mac. `Some` = push it now; `None` = coalesced, the
    /// periodic [`Activities::due`] sends the latest state later. `end` is
    /// never delayed.
    pub fn offer(
        &self,
        group: &str,
        event: ActivityEvent,
        state: ContentState,
        stale_secs: Option<u64>,
        now: u64,
    ) -> Option<Batch> {
        let mut map = self.lock();
        let g = map.entry(group.to_string()).or_default();
        g.state = Some(state);
        g.stale_secs = stale_secs;
        if event == ActivityEvent::End || g.event != Some(ActivityEvent::End) {
            g.event = Some(event);
        }
        g.pending = true;
        let due =
            event == ActivityEvent::End || g.last_sent.map_or(true, |t| now >= t + COALESCE_SECS);
        due.then(|| take(g, now))
    }

    /// Seconds until a coalesced state of `group` is sent.
    pub fn send_in(&self, group: &str, now: u64) -> u64 {
        self.lock()
            .get(group)
            .and_then(|g| g.last_sent)
            .map_or(0, |t| (t + COALESCE_SECS).saturating_sub(now))
    }

    /// Coalesced states whose interval has passed.
    pub fn due(&self, now: u64) -> Vec<(String, Batch)> {
        let mut map = self.lock();
        map.iter_mut()
            .filter(|(_, g)| g.pending && g.last_sent.map_or(true, |t| now >= t + COALESCE_SECS))
            .map(|(k, g)| (k.clone(), take(g, now)))
            .collect()
    }

    /// The Mac went offline or came back (presence): re-send the latest state
    /// with `mac_online` changed. Same coalescing as [`Activities::offer`].
    pub fn presence(&self, group: &str, online: bool, now: u64) -> Option<Batch> {
        let mut map = self.lock();
        let g = map.get_mut(group)?;
        let s = g.state.as_mut()?;
        if s.mac_online == online || g.event == Some(ActivityEvent::End) && !g.pending {
            return None;
        }
        s.mac_online = online;
        g.pending = true;
        g.event.get_or_insert(ActivityEvent::Update);
        g.last_sent
            .map_or(true, |t| now >= t + COALESCE_SECS)
            .then(|| take(g, now))
    }

    /// Whether `device` may get a push-to-start now (none in the last 8 h);
    /// records it if so.
    pub fn may_start(&self, group: &str, device: &str, now: u64) -> bool {
        let mut map = self.lock();
        let g = map.entry(group.to_string()).or_default();
        g.started
            .retain(|_, t| now.saturating_sub(*t) < ACTIVITY_MAX_SECS);
        if g.started.contains_key(device) {
            return false;
        }
        g.started.insert(device.to_string(), now);
        true
    }

    /// The device registered an activity token: its activity is running.
    pub fn token_registered(&self, group: &str, device: &str) {
        if let Some(g) = self.lock().get_mut(group) {
            g.started.remove(device);
        }
    }

    /// Latest state of `group` (tests, diagnostics).
    pub fn latest(&self, group: &str) -> Option<ContentState> {
        self.lock().get(group).and_then(|g| g.state.clone())
    }
}

fn take(g: &mut GroupActivity, now: u64) -> Batch {
    let state = g.state.clone().unwrap_or_else(|| ContentState {
        critical: 0,
        warning: 0,
        unknown: 0,
        mac_online: true,
        updated_at: now,
        lines: Vec::new(),
    });
    let event = g.event.take().unwrap_or(ActivityEvent::Update);
    let timestamp = now.max(g.last_ts + 1);
    g.last_ts = timestamp;
    g.last_sent = Some(now);
    g.pending = false;
    let raise = state.critical > g.sent_critical;
    g.sent_critical = state.critical;
    let ended = event == ActivityEvent::End;
    if ended {
        // Nothing to update until the phone starts a new activity.
        g.sent_critical = 0;
    }
    Batch {
        note: ActivityNote {
            event,
            timestamp,
            stale_date: (!ended).then_some(g.stale_secs).flatten().map(|s| now + s),
            dismissal_date: ended.then_some(now),
            state,
        },
        raise,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn st(critical: u32, warning: u32) -> ContentState {
        ContentState {
            critical,
            warning,
            unknown: 0,
            mac_online: true,
            updated_at: 1,
            lines: Vec::new(),
        }
    }

    #[test]
    fn validation() {
        assert!(st(1, 2).validate().is_ok());
        assert!(st(MAX_COUNT + 1, 0).validate().is_err());
        let line = |t: &str| ActivityLine {
            severity: LineSeverity::Critical,
            text: t.into(),
        };
        let mut s = st(1, 0);
        s.lines = vec![line("web01 · disk"); 4];
        assert!(s.validate().is_ok());
        s.lines.push(line("x"));
        assert!(s.validate().is_err(), "5 lines");
        s.lines = vec![line(&"é".repeat(40))];
        assert!(s.validate().is_ok(), "40 characters, not bytes");
        s.lines = vec![line(&"a".repeat(41))];
        assert!(s.validate().is_err());
        s.lines = vec![line("")];
        assert!(s.validate().is_err());
        s.lines = vec![line("a\nb")];
        assert!(s.validate().is_err());
    }

    #[test]
    fn payload_shape() {
        let mut s = st(2, 3);
        s.lines = vec![ActivityLine {
            severity: LineSeverity::Warning,
            text: "db1 · load".into(),
        }];
        let n = ActivityNote {
            event: ActivityEvent::Update,
            timestamp: 100,
            state: s,
            stale_date: Some(160),
            dismissal_date: None,
        };
        let p: Value = serde_json::from_str(&build_activity_payload(&n)).unwrap();
        assert_eq!(
            p,
            json!({"aps": {
                "timestamp": 100, "event": "update", "relevance-score": 100, "stale-date": 160,
                "content-state": {"critical": 2, "warning": 3, "unknown": 0, "mac_online": true,
                                  "updated_at": 1, "lines": [{"severity": "warning", "text": "db1 · load"}]}
            }})
        );
        let start = ActivityNote {
            event: ActivityEvent::Start,
            stale_date: None,
            state: st(1, 0),
            ..n
        };
        let p: Value = serde_json::from_str(&build_activity_payload(&start)).unwrap();
        assert_eq!(p["aps"]["attributes-type"], "AlertsActivityAttributes");
        assert_eq!(p["aps"]["attributes"], json!({}));
        assert_eq!(p["aps"]["alert"]["body"], "1 critical alert");
        assert!(
            p["aps"]["content-state"].get("lines").is_none(),
            "no lines key without lines"
        );
    }

    #[test]
    fn coalescing_keeps_latest_and_raise_flags_critical_increase() {
        let a = Activities::new();
        let b = a
            .offer("g", ActivityEvent::Update, st(1, 0), Some(600), 100)
            .unwrap();
        assert!(b.raise);
        assert_eq!(b.note.timestamp, 100);
        assert_eq!(b.note.stale_date, Some(700));
        // Within 5 s: coalesced; only the latest is sent.
        assert!(a
            .offer("g", ActivityEvent::Update, st(1, 1), None, 101)
            .is_none());
        assert!(a
            .offer("g", ActivityEvent::Update, st(0, 2), None, 102)
            .is_none());
        assert_eq!(a.send_in("g", 102), 3);
        assert!(a.due(104).is_empty());
        let due = a.due(105);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1.note.state, st(0, 2));
        assert!(!due[0].1.raise, "critical went down");
        assert!(a.due(200).is_empty(), "sent once");
        // End is never delayed and clears the stale date.
        let e = a
            .offer("g", ActivityEvent::End, st(0, 0), Some(600), 106)
            .unwrap();
        assert_eq!(e.note.event, ActivityEvent::End);
        assert_eq!(e.note.dismissal_date, Some(106));
        assert_eq!(e.note.stale_date, None);
        assert_eq!(e.note.timestamp, 106);
    }

    #[test]
    fn end_sticks_while_coalesced_and_timestamps_increase() {
        let a = Activities::new();
        a.offer("g", ActivityEvent::Update, st(1, 0), None, 100);
        let e = a
            .offer("g", ActivityEvent::End, st(1, 0), None, 100)
            .unwrap();
        assert_eq!(e.note.timestamp, 101, "strictly after the previous push");
    }

    #[test]
    fn presence_resends_latest_with_mac_offline() {
        let a = Activities::new();
        assert!(a.presence("g", false, 100).is_none(), "no state yet");
        a.offer("g", ActivityEvent::Update, st(2, 0), None, 100);
        assert!(
            a.presence("g", false, 102).is_none(),
            "coalesced behind the update"
        );
        let due = a.due(105);
        assert!(!due[0].1.note.state.mac_online);
        assert_eq!(due[0].1.note.state.critical, 2);
        assert!(a.presence("g", false, 200).is_none(), "already offline");
        let back = a.presence("g", true, 300).unwrap();
        assert!(back.note.state.mac_online);
        assert!(!back.raise);
    }

    #[test]
    fn push_to_start_once_per_activity_lifetime() {
        let a = Activities::new();
        assert!(a.may_start("g", "p", 0));
        assert!(!a.may_start("g", "p", 100));
        assert!(a.may_start("g", "q", 100), "per device");
        a.token_registered("g", "q");
        assert!(a.may_start("g", "q", 101), "its activity registered");
        assert!(a.may_start("g", "p", ACTIVITY_MAX_SECS));
    }
}
