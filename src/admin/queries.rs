//! Read-only queries for the admin panel (run on the reader connection).

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::metrics::{day_of, day_str};
use crate::v2::store::StoreError;

type R<T> = Result<T, StoreError>;

/// The last `n` days as `YYYY-MM-DD`, oldest first, ending today.
pub fn days_back(now: u64, n: i64) -> Vec<String> {
    let today = day_of(now);
    (0..n).rev().map(|i| day_str(today - i)).collect()
}

fn since_day(now: u64, n: i64) -> String {
    day_str(day_of(now) - (n - 1))
}

fn u(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Count {
    pub key: String,
    pub count: u64,
}

fn counts(c: &Connection, sql: &str, p: impl rusqlite::Params) -> R<Vec<Count>> {
    let mut st = c.prepare(sql)?;
    let rows = st.query_map(p, |r| {
        Ok(Count {
            key: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            count: u(r.get(1)?),
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// `(day, values...)` series with every day present (zeros filled in).
#[derive(Debug, Clone, Serialize)]
pub struct Series {
    pub names: Vec<&'static str>,
    pub points: Vec<(String, Vec<u64>)>,
}

impl Series {
    fn new(names: &[&'static str], labels: Vec<String>) -> Self {
        let n = names.len();
        Self {
            names: names.to_vec(),
            points: labels.into_iter().map(|d| (d, vec![0; n])).collect(),
        }
    }

    fn add(&mut self, label: &str, idx: usize, v: u64) {
        if let Some(p) = self.points.iter_mut().find(|p| p.0 == label) {
            p.1[idx] += v;
        }
    }

    pub fn total(&self, idx: usize) -> u64 {
        self.points.iter().map(|p| p.1[idx]).sum()
    }
}

/// Fill `series` from `SELECT day, key, SUM(count)` rows; `pick` maps a key
/// to a series index.
fn fill(
    c: &Connection,
    series: &mut Series,
    sql: &str,
    p: impl rusqlite::Params,
    pick: impl Fn(&str) -> Option<usize>,
) -> R<()> {
    let mut st = c.prepare(sql)?;
    let rows = st.query_map(p, |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, u(r.get(2)?)))
    })?;
    for row in rows {
        let (day, key, n) = row?;
        if let Some(i) = pick(&key) {
            series.add(&day, i, n);
        }
    }
    Ok(())
}

// -------------------------------------------------------------- overview ---

#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub groups_total: u64,
    pub active_24h: u64,
    pub active_7d: u64,
    pub active_30d: u64,
    pub new_groups: Series,
    pub devices_by_kind: Vec<Count>,
    pub licences: Vec<Count>,
    pub unlicensed_groups: u64,
    pub pushes_hourly: Series,
    pub pushes_daily: Series,
    pub traffic_daily: Series,
    pub http_daily: Series,
    pub top_countries: Vec<Count>,
    pub apns_reasons: Vec<Count>,
    pub pushes_by_route: Vec<Count>,
    pub ws_sessions_7d: u64,
    /// Snapshots stored in the last 30 days, and their sealed bytes.
    pub snapshots_30d: u64,
    pub snapshot_bytes_30d: u64,
    pub ws_median_secs_7d: Option<u64>,
    pub event_rows: u64,
}

pub fn active_since(c: &Connection, since: u64) -> R<u64> {
    Ok(u(c.query_row(
        "SELECT COUNT(DISTINCT a.group_id) FROM client_activity a
         JOIN groups g ON g.group_id = a.group_id WHERE a.last_seen >= ?1",
        [since as i64],
        |r| r.get(0),
    )?))
}

pub fn overview(c: &Connection, now: u64) -> R<Overview> {
    let one = |sql: &str| -> R<u64> { Ok(u(c.query_row(sql, [], |r| r.get(0))?)) };
    let d30 = since_day(now, 30);
    let days30 = days_back(now, 30);

    let mut new_groups = Series::new(&["groups"], days30.clone());
    fill(
        c,
        &mut new_groups,
        "SELECT date(created_at, 'unixepoch'), '', COUNT(*) FROM groups
         WHERE created_at >= ?1 GROUP BY 1",
        [(now - 30 * 86_400) as i64],
        |_| Some(0),
    )?;

    // Pushes per hour (48 h) from raw events.
    let hour0 = now / 3600 - 47;
    let hours: Vec<String> = (0..48).map(|i| ((hour0 + i) * 3600).to_string()).collect();
    let mut pushes_hourly = Series::new(&["sent", "failed", "unregistered"], hours);
    fill(
        c,
        &mut pushes_hourly,
        "SELECT CAST((ts / 3600) * 3600 AS TEXT), outcome, COUNT(*) FROM events
         WHERE kind = 'push' AND ts >= ?1 GROUP BY 1, 2",
        [(hour0 * 3600) as i64],
        outcome_idx,
    )?;

    let mut pushes_daily = Series::new(&["sent", "failed", "unregistered"], days30.clone());
    fill(
        c,
        &mut pushes_daily,
        "SELECT day, outcome, SUM(count) FROM daily_agg
         WHERE kind = 'push' AND day >= ?1 GROUP BY 1, 2",
        [&d30],
        outcome_idx,
    )?;

    let mut traffic_daily = Series::new(&["messages", "commands", "activity"], days30.clone());
    fill(
        c,
        &mut traffic_daily,
        "SELECT day, route, SUM(count) FROM daily_agg
         WHERE kind = 'api' AND status BETWEEN 200 AND 299 AND day >= ?1
           AND route IN ('messages.post', 'commands.post', 'activity.state')
         GROUP BY 1, 2",
        [&d30],
        |k| match k {
            "messages.post" => Some(0),
            "commands.post" => Some(1),
            _ => Some(2),
        },
    )?;

    let d14 = since_day(now, 14);
    let mut http_daily = Series::new(&["2xx/3xx", "4xx", "429", "5xx"], days_back(now, 14));
    fill(
        c,
        &mut http_daily,
        "SELECT day, CAST(status AS TEXT), SUM(count) FROM daily_agg
         WHERE kind = 'api' AND day >= ?1 GROUP BY 1, 2",
        [&d14],
        |k| {
            let s: u16 = k.parse().ok()?;
            Some(match s {
                429 => 2,
                500.. => 3,
                400.. => 1,
                _ => 0,
            })
        },
    )?;

    let ws: Vec<i64> = {
        let mut st = c.prepare(
            "SELECT duration_s FROM events WHERE kind = 'ws_disconnect' AND ts >= ?1
             AND duration_s IS NOT NULL ORDER BY duration_s",
        )?;
        let rows = st.query_map([(now - 7 * 86_400) as i64], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };

    let (snapshots_30d, snapshot_bytes_30d): (i64, i64) = c.query_row(
        "SELECT COALESCE(SUM(count), 0), COALESCE(SUM(bytes_sum), 0) FROM daily_agg
         WHERE kind = 'snapshot' AND outcome = 'stored' AND day >= ?1",
        [&d30],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    Ok(Overview {
        snapshots_30d: u(snapshots_30d),
        snapshot_bytes_30d: u(snapshot_bytes_30d),
        groups_total: one("SELECT COUNT(*) FROM groups")?,
        active_24h: active_since(c, now - 86_400)?,
        active_7d: active_since(c, now - 7 * 86_400)?,
        active_30d: active_since(c, now - 30 * 86_400)?,
        new_groups,
        devices_by_kind: counts(
            c,
            "SELECT kind, COUNT(*) FROM devices GROUP BY kind ORDER BY kind",
            [],
        )?,
        licences: counts(
            c,
            "SELECT tier || ' / ' || environment, COUNT(*) FROM group_licences
             GROUP BY 1 ORDER BY 2 DESC",
            [],
        )?,
        unlicensed_groups: one(
            "SELECT COUNT(*) FROM groups WHERE group_id NOT IN (SELECT group_id FROM group_licences)",
        )?,
        pushes_hourly,
        pushes_daily,
        traffic_daily,
        http_daily,
        top_countries: counts(
            c,
            "SELECT country, SUM(count) FROM daily_agg WHERE kind = 'api' AND country != ''
             AND day >= ?1 GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
            [&d30],
        )?,
        apns_reasons: apns_reasons(c, now)?,
        pushes_by_route: counts(
            c,
            "SELECT route || ' ' || outcome, SUM(count) FROM daily_agg WHERE kind = 'push'
             AND day >= ?1 GROUP BY 1 ORDER BY 2 DESC",
            [&d30],
        )?,
        ws_sessions_7d: ws.len() as u64,
        ws_median_secs_7d: ws.get(ws.len() / 2).map(|v| u(*v)),
        event_rows: one("SELECT COUNT(*) FROM events")?,
    })
}

fn outcome_idx(k: &str) -> Option<usize> {
    match k {
        "sent" => Some(0),
        "failed" => Some(1),
        "unregistered" => Some(2),
        _ => None,
    }
}

fn apns_reasons(c: &Connection, now: u64) -> R<Vec<Count>> {
    counts(
        c,
        "SELECT COALESCE(CAST(apns_status AS TEXT), '-') || ' ' || COALESCE(apns_reason, outcome),
                COUNT(*)
         FROM events WHERE kind = 'push' AND outcome != 'sent' AND ts >= ?1
         GROUP BY 1 ORDER BY 2 DESC LIMIT 20",
        [(now - 30 * 86_400) as i64],
    )
}

// ---------------------------------------------------------------- groups ---

#[derive(Debug, Clone, Serialize)]
pub struct GroupRow {
    pub group_id: String,
    pub created_at: u64,
    pub macs: u64,
    pub phones: u64,
    pub tier: Option<String>,
    pub environment: Option<String>,
    pub last_active: Option<u64>,
    pub country: Option<String>,
    pub requests_30d: u64,
    pub pushes_30d: u64,
}

/// Groups-list filter and sort, from the query string.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct GroupFilter {
    /// `24h`, `7d`, `30d` or `inactive` (nothing in 30 days).
    pub active: String,
    /// `none`, `licensed`, or a tier such as `founder`.
    pub licence: String,
    /// Two-letter country.
    pub country: String,
    /// Group id prefix.
    pub q: String,
    /// `created` (default), `last_active`, `requests`, `pushes`, `devices`.
    pub sort: String,
    /// `asc` or `desc` (default).
    pub order: String,
}

pub const MAX_GROUP_ROWS: usize = 500;

pub fn groups(c: &Connection, now: u64, f: &GroupFilter) -> R<Vec<GroupRow>> {
    let d30 = since_day(now, 30);
    let mut st = c.prepare(
        "SELECT g.group_id, g.created_at,
            (SELECT COUNT(*) FROM devices d WHERE d.group_id = g.group_id AND d.kind = 'mac'),
            (SELECT COUNT(*) FROM devices d WHERE d.group_id = g.group_id AND d.kind = 'ios'),
            l.tier, l.environment,
            (SELECT MAX(a.last_seen) FROM client_activity a WHERE a.group_id = g.group_id),
            (SELECT a.country FROM client_activity a WHERE a.group_id = g.group_id
                AND a.country IS NOT NULL ORDER BY a.last_seen DESC LIMIT 1),
            (SELECT COALESCE(SUM(x.count), 0) FROM daily_agg x
                WHERE x.group_id = g.group_id AND x.day >= ?1 AND x.kind = 'api'),
            (SELECT COALESCE(SUM(x.count), 0) FROM daily_agg x
                WHERE x.group_id = g.group_id AND x.day >= ?1 AND x.kind = 'push')
         FROM groups g LEFT JOIN group_licences l ON l.group_id = g.group_id",
    )?;
    let rows = st.query_map([&d30], |r| {
        Ok(GroupRow {
            group_id: r.get(0)?,
            created_at: u(r.get(1)?),
            macs: u(r.get(2)?),
            phones: u(r.get(3)?),
            tier: r.get(4)?,
            environment: r.get(5)?,
            last_active: r.get::<_, Option<i64>>(6)?.map(u),
            country: r.get(7)?,
            requests_30d: u(r.get(8)?),
            pushes_30d: u(r.get(9)?),
        })
    })?;
    let mut out: Vec<GroupRow> = rows.collect::<Result<_, _>>()?;
    let window = match f.active.as_str() {
        "24h" => Some(86_400),
        "7d" => Some(7 * 86_400),
        "30d" | "inactive" => Some(30 * 86_400),
        _ => None,
    };
    out.retain(|g| {
        let recent = |w: u64| g.last_active.is_some_and(|t| t + w >= now);
        let active_ok = match (f.active.as_str(), window) {
            ("inactive", Some(w)) => !recent(w),
            (_, Some(w)) => recent(w),
            _ => true,
        };
        let licence_ok = match f.licence.as_str() {
            "" => true,
            "none" => g.tier.is_none(),
            "licensed" => g.tier.is_some(),
            t => g.tier.as_deref() == Some(t),
        };
        let country_ok =
            f.country.is_empty() || g.country.as_deref() == Some(&f.country.to_ascii_uppercase());
        active_ok && licence_ok && country_ok && g.group_id.starts_with(f.q.trim())
    });
    match f.sort.as_str() {
        "last_active" => out.sort_by_key(|g| g.last_active),
        "requests" => out.sort_by_key(|g| g.requests_30d),
        "pushes" => out.sort_by_key(|g| g.pushes_30d),
        "devices" => out.sort_by_key(|g| g.macs + g.phones),
        _ => out.sort_by_key(|g| g.created_at),
    }
    if f.order != "asc" {
        out.reverse();
    }
    out.truncate(MAX_GROUP_ROWS);
    Ok(out)
}

// ---------------------------------------------------------- group detail ---

#[derive(Debug, Clone, Serialize)]
pub struct DeviceRow {
    pub device_id: String,
    pub kind: String,
    pub name: String,
    pub apns_env: String,
    pub has_token: bool,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_seen: Option<u64>,
    pub last_active: Option<u64>,
    pub app_version: Option<String>,
    pub country: Option<String>,
    /// Macs: a live stream right now (filled in by the handler).
    pub online: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenceRow {
    pub tier: String,
    pub environment: String,
    pub original_purchase_date: Option<u64>,
    pub original_application_version: Option<String>,
    pub original_platform: Option<String>,
    pub attached_at: u64,
    pub verified_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventRow {
    pub ts: u64,
    pub kind: String,
    pub device_id: Option<String>,
    pub route: Option<String>,
    pub status: Option<u16>,
    pub outcome: Option<String>,
    pub detail: Option<String>,
    pub latency_ms: Option<u64>,
    pub duration_s: Option<u64>,
    pub country: Option<String>,
    pub ip_prefix: Option<String>,
    pub app_version: Option<String>,
    pub apns_status: Option<u16>,
    pub apns_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionRow {
    pub app_version: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub events: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupDetail {
    pub group_id: String,
    pub created_at: u64,
    pub devices: Vec<DeviceRow>,
    pub licence: Option<LicenceRow>,
    pub mailbox_messages: u64,
    pub queued_commands: u64,
    pub activity_daily: Series,
    pub app_versions: Vec<VersionRow>,
    pub recent_events: Vec<EventRow>,
}

const EVENT_COLS: &str = "ts, kind, device_id, route, status, outcome, detail, latency_ms,
    duration_s, country, ip_prefix, app_version, apns_status, apns_reason";

fn row_event(r: &rusqlite::Row<'_>) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        ts: u(r.get(0)?),
        kind: r.get(1)?,
        device_id: r.get(2)?,
        route: r.get(3)?,
        status: r.get(4)?,
        outcome: r.get(5)?,
        detail: r.get(6)?,
        latency_ms: r.get::<_, Option<i64>>(7)?.map(u),
        duration_s: r.get::<_, Option<i64>>(8)?.map(u),
        country: r.get(9)?,
        ip_prefix: r.get(10)?,
        app_version: r.get(11)?,
        apns_status: r.get(12)?,
        apns_reason: r.get(13)?,
    })
}

fn events(c: &Connection, filter: &str, p: impl rusqlite::Params) -> R<Vec<EventRow>> {
    let mut st = c.prepare(&format!(
        "SELECT {EVENT_COLS} FROM events WHERE {filter} ORDER BY ts DESC, id DESC LIMIT 100"
    ))?;
    let rows = st.query_map(p, row_event)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn group_detail(c: &Connection, now: u64, gid: &str) -> R<Option<GroupDetail>> {
    let Some(created_at) = c
        .query_row(
            "SELECT created_at FROM groups WHERE group_id = ?1",
            [gid],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let mut st = c.prepare(
        "SELECT d.device_id, d.kind, d.name, d.apns_env, d.apns_token IS NOT NULL, d.created_at,
                d.updated_at, d.last_seen, a.last_seen, a.app_version, a.country
         FROM devices d LEFT JOIN client_activity a
           ON a.group_id = d.group_id AND a.device_id = d.device_id
         WHERE d.group_id = ?1 ORDER BY d.kind, d.created_at",
    )?;
    let devices = st
        .query_map([gid], |r| {
            Ok(DeviceRow {
                device_id: r.get(0)?,
                kind: r.get(1)?,
                name: r.get(2)?,
                apns_env: r.get(3)?,
                has_token: r.get(4)?,
                created_at: u(r.get(5)?),
                updated_at: u(r.get(6)?),
                last_seen: r.get::<_, Option<i64>>(7)?.map(u),
                last_active: r.get::<_, Option<i64>>(8)?.map(u),
                app_version: r.get(9)?,
                country: r.get(10)?,
                online: None,
            })
        })?
        .collect::<Result<_, _>>()?;
    let licence = c
        .query_row(
            "SELECT tier, environment, original_purchase_date, original_application_version,
                    original_platform, attached_at, verified_at
             FROM group_licences WHERE group_id = ?1",
            [gid],
            |r| {
                Ok(LicenceRow {
                    tier: r.get(0)?,
                    environment: r.get(1)?,
                    original_purchase_date: r.get::<_, Option<i64>>(2)?.map(u),
                    original_application_version: r.get(3)?,
                    original_platform: r.get(4)?,
                    attached_at: u(r.get(5)?),
                    verified_at: u(r.get(6)?),
                })
            },
        )
        .optional()?;
    let count = |sql: &str| -> R<u64> { Ok(u(c.query_row(sql, [gid], |r| r.get(0))?)) };
    let mut activity_daily = Series::new(
        &["messages", "commands", "activity", "pushes", "other"],
        days_back(now, 30),
    );
    fill(
        c,
        &mut activity_daily,
        "SELECT day, CASE WHEN kind = 'push' THEN 'push' ELSE route END, SUM(count)
         FROM daily_agg WHERE group_id = ?1 AND day >= ?2 AND kind IN ('api', 'push')
         GROUP BY 1, 2",
        params![gid, since_day(now, 30)],
        |k| {
            Some(match k {
                "messages.post" => 0,
                "commands.post" => 1,
                "activity.state" => 2,
                "push" => 3,
                _ => 4,
            })
        },
    )?;
    let mut st = c.prepare(
        "SELECT app_version, MIN(ts), MAX(ts), COUNT(*) FROM events
         WHERE group_id = ?1 AND app_version IS NOT NULL GROUP BY 1 ORDER BY 3 DESC",
    )?;
    let app_versions = st
        .query_map([gid], |r| {
            Ok(VersionRow {
                app_version: r.get(0)?,
                first_seen: u(r.get(1)?),
                last_seen: u(r.get(2)?),
                events: u(r.get(3)?),
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(Some(GroupDetail {
        group_id: gid.to_string(),
        created_at: u(created_at),
        devices,
        licence,
        mailbox_messages: count("SELECT COUNT(*) FROM messages WHERE group_id = ?1")?,
        queued_commands: count("SELECT COUNT(*) FROM commands WHERE group_id = ?1")?,
        activity_daily,
        app_versions,
        recent_events: events(c, "group_id = ?1", [gid])?,
    }))
}

// ---------------------------------------------------------------- pushes ---

#[derive(Debug, Clone, Serialize)]
pub struct Pushes {
    pub daily: Series,
    pub by_type: Vec<Count>,
    pub by_via_env: Vec<Count>,
    pub reasons: Vec<Count>,
    pub unregistered_daily: Series,
    pub recent_failures: Vec<EventRow>,
}

pub const PUSH_TYPES: [&str; 5] = ["alert", "result", "presence", "liveactivity", "start"];

pub fn pushes(c: &Connection, now: u64) -> R<Pushes> {
    let d30 = since_day(now, 30);
    let mut daily = Series::new(&PUSH_TYPES, days_back(now, 30));
    fill(
        c,
        &mut daily,
        "SELECT day, route, SUM(count) FROM daily_agg WHERE kind = 'push' AND day >= ?1
         GROUP BY 1, 2",
        [&d30],
        |k| PUSH_TYPES.iter().position(|t| *t == k),
    )?;
    let mut unregistered_daily = Series::new(&["unregistered"], days_back(now, 30));
    fill(
        c,
        &mut unregistered_daily,
        "SELECT day, '', SUM(count) FROM daily_agg WHERE kind = 'push' AND outcome = 'unregistered'
         AND day >= ?1 GROUP BY 1",
        [&d30],
        |_| Some(0),
    )?;
    Ok(Pushes {
        daily,
        by_type: counts(
            c,
            "SELECT route || ' ' || outcome, SUM(count) FROM daily_agg WHERE kind = 'push'
             AND day >= ?1 GROUP BY 1 ORDER BY 2 DESC",
            [&d30],
        )?,
        by_via_env: counts(
            c,
            "SELECT detail, COUNT(*) FROM events WHERE kind = 'push' AND ts >= ?1
             GROUP BY 1 ORDER BY 2 DESC",
            [(now - 30 * 86_400) as i64],
        )?,
        reasons: apns_reasons(c, now)?,
        unregistered_daily,
        recent_failures: events(c, "kind = 'push' AND outcome != 'sent'", [])?,
    })
}

// -------------------------------------------------------------- security ---

#[derive(Debug, Clone, Serialize)]
pub struct Security {
    pub daily: Series,
    pub rate_limits: Vec<Count>,
    pub auth_failures_by_route: Vec<Count>,
    pub top_prefixes: Vec<Count>,
    pub top_countries: Vec<Count>,
    pub bans: Vec<EventRow>,
    pub admin_logins: Vec<EventRow>,
    pub licence_outcomes: Vec<Count>,
}

pub fn security(c: &Connection, now: u64) -> R<Security> {
    let d30 = since_day(now, 30);
    let t30 = (now - 30 * 86_400) as i64;
    let mut daily = Series::new(
        &[
            "401",
            "429",
            "404 unmatched",
            "bans",
            "admin login fail",
            "admin denied",
        ],
        days_back(now, 30),
    );
    fill(
        c,
        &mut daily,
        "SELECT day,
            CASE WHEN kind = 'ban' THEN 'ban'
                 WHEN kind = 'admin_login' THEN 'admin'
                 WHEN kind = 'admin_denied' THEN 'denied'
                 WHEN route = 'unmatched' THEN 'unmatched'
                 ELSE CAST(status AS TEXT) END,
            SUM(count)
         FROM daily_agg WHERE day >= ?1 AND (
            (kind = 'api' AND (status IN (401, 429) OR route = 'unmatched'))
            OR kind IN ('ban', 'admin_denied') OR (kind = 'admin_login' AND outcome != 'ok'))
         GROUP BY 1, 2",
        [&d30],
        |k| {
            Some(match k {
                "401" => 0,
                "429" => 1,
                "unmatched" => 2,
                "ban" => 3,
                "admin" => 4,
                "denied" => 5,
                _ => return None,
            })
        },
    )?;
    Ok(Security {
        daily,
        rate_limits: counts(
            c,
            "SELECT route || ' ' || outcome, SUM(count) FROM daily_agg
             WHERE kind = 'api' AND status = 429 AND day >= ?1 GROUP BY 1 ORDER BY 2 DESC LIMIT 20",
            [&d30],
        )?,
        auth_failures_by_route: counts(
            c,
            "SELECT route, SUM(count) FROM daily_agg WHERE kind = 'api' AND status = 401
             AND day >= ?1 GROUP BY 1 ORDER BY 2 DESC LIMIT 20",
            [&d30],
        )?,
        top_prefixes: counts(
            c,
            "SELECT ip_prefix || COALESCE(' ' || country, ''), COUNT(*) FROM events
             WHERE ts >= ?1 AND ip_prefix IS NOT NULL
               AND (status IN (401, 429) OR kind IN ('ban', 'admin_login', 'admin_denied')
                    OR route = 'unmatched')
             GROUP BY 1 ORDER BY 2 DESC LIMIT 20",
            [t30],
        )?,
        top_countries: counts(
            c,
            "SELECT country, SUM(count) FROM daily_agg WHERE day >= ?1 AND country != ''
               AND ((kind = 'api' AND (status IN (401, 429) OR route = 'unmatched'))
                    OR kind IN ('admin_login', 'admin_denied'))
             GROUP BY 1 ORDER BY 2 DESC LIMIT 20",
            [&d30],
        )?,
        bans: events(c, "kind = 'ban' AND ts >= ?1", [t30])?,
        admin_logins: events(c, "kind = 'admin_login'", [])?,
        licence_outcomes: counts(
            c,
            "SELECT route || ' ' || outcome, SUM(count) FROM daily_agg
             WHERE kind = 'licence' AND day >= ?1 GROUP BY 1 ORDER BY 2 DESC",
            [&d30],
        )?,
    })
}

// ------------------------------------------------------------------- CSV ---

pub const MAX_CSV_ROWS: i64 = 200_000;

/// `daily_agg` as CSV, newest day first.
pub fn daily_csv(c: &Connection) -> R<String> {
    let mut out = String::from(
        "day,kind,route,status,outcome,group_id,country,count,latency_ms_sum,bytes_sum\n",
    );
    let mut st = c.prepare(
        "SELECT day, kind, route, status, outcome, group_id, country, count, latency_ms_sum, bytes_sum
         FROM daily_agg ORDER BY day DESC, kind, route, status, outcome, group_id LIMIT ?1",
    )?;
    let mut rows = st.query([MAX_CSV_ROWS])?;
    while let Some(r) = rows.next()? {
        let field = |s: String| -> String {
            // No spreadsheet formulas (a group id may start with `-`).
            let s = if s.starts_with(['=', '+', '-', '@']) {
                format!("'{s}")
            } else {
                s
            };
            if s.contains([',', '"', '\n']) {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s
            }
        };
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            field(r.get(0)?),
            field(r.get(1)?),
            field(r.get(2)?),
            r.get::<_, i64>(3)?,
            field(r.get(4)?),
            field(r.get(5)?),
            field(r.get(6)?),
            r.get::<_, i64>(7)?,
            r.get::<_, i64>(8)?,
            r.get::<_, i64>(9)?,
        ));
    }
    Ok(out)
}
