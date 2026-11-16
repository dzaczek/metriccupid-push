//! Operator controls set from the admin panel: manual IP bans, group
//! suspensions, purchase revocations and live limit overrides, plus the
//! admin audit log. Persisted in the aux tables (`store::AUX_SCHEMA`, so
//! `user_version` stays 6 and a 0.2.0 / 0.2.1 binary still opens the
//! database) and mirrored in memory, so request paths never query SQLite
//! for them.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::RwLock;

use ipnet::IpNet;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::v2::store::StoreError;

type R<T> = Result<T, StoreError>;

/// Manual bans kept at once.
pub const MAX_MANUAL_BANS: usize = 1000;
pub const BAN_MIN_SECS: u64 = 15 * 60;
pub const BAN_MAX_SECS: u64 = 30 * 86_400;
/// Shortest prefix a manual ban may cover.
pub const MIN_V4_PREFIX: u8 = 16;
pub const MIN_V6_PREFIX: u8 = 32;
/// Longer IPv6 prefixes are widened to this.
pub const MAX_V6_PREFIX: u8 = 64;
/// Bans broader than these always need a fresh authenticator code.
pub const NARROW_V4_PREFIX: u8 = 24;
pub const NARROW_V6_PREFIX: u8 = 48;
/// Audit rows are kept this long, and at most this many.
pub const AUDIT_RETENTION_SECS: u64 = 90 * 86_400;
pub const AUDIT_MAX_ROWS: i64 = 100_000;
pub const MAX_REASON_CHARS: usize = 200;
/// Longest purchase id accepted by the revoke form.
pub const MAX_TX_LEN: usize = 128;

// ------------------------------------------------------------ validation ---

/// An IP or CIDR prefix for a manual ban: IPv4 /16 or longer, IPv6 /32 or
/// longer, host bits cleared. IPv6 is normalised to at most a /64 (one host
/// usually controls a whole /64, like `limits::ip_key`). IPv4-mapped IPv6 is
/// refused (requests are matched on the canonical address).
pub fn parse_ban_target(s: &str) -> Result<IpNet, &'static str> {
    let s = s.trim();
    if s.is_empty() || s.len() > 64 {
        return Err("Enter an IP address or a CIDR prefix.");
    }
    let net = match s.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => match s.parse::<IpAddr>() {
            Ok(ip) => IpNet::from(ip),
            Err(_) => return Err("Not an IP address or CIDR prefix."),
        },
    };
    match net {
        IpNet::V4(n) if n.prefix_len() < MIN_V4_PREFIX => {
            Err("IPv4 prefixes must be /16 or longer.")
        }
        IpNet::V6(n) if n.addr().to_ipv4_mapped().is_some() => {
            Err("Use the IPv4 form of an IPv4-mapped address.")
        }
        IpNet::V6(n) if n.prefix_len() < MIN_V6_PREFIX => {
            Err("IPv6 prefixes must be /32 or longer.")
        }
        IpNet::V6(n) if n.prefix_len() > MAX_V6_PREFIX => Ok(IpNet::V6(
            ipnet::Ipv6Net::new(n.addr(), MAX_V6_PREFIX)
                .expect("valid prefix length")
                .trunc(),
        )),
        n => Ok(n.trunc()),
    }
}

/// `<n>m`, `<n>h` or `<n>d`, between 15 minutes and 30 days.
pub fn parse_duration(s: &str) -> Result<u64, &'static str> {
    const BAD: &str = "Duration must be 15m to 30d (e.g. 15m, 6h, 7d).";
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86_400)
    } else {
        return Err(BAD);
    };
    if num.is_empty() || num.len() > 5 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BAD);
    }
    let secs = num.parse::<u64>().map_err(|_| BAD)? * mult;
    if (BAN_MIN_SECS..=BAN_MAX_SECS).contains(&secs) {
        Ok(secs)
    } else {
        Err(BAD)
    }
}

/// A required free-text reason: 1..=200 characters, no control characters.
pub fn parse_reason(s: &str) -> Result<String, &'static str> {
    let s = s.trim();
    let n = s.chars().count();
    if n == 0 || n > MAX_REASON_CHARS || s.chars().any(char::is_control) {
        return Err("Reason must be 1 to 200 characters without control characters.");
    }
    Ok(s.to_string())
}

/// An App Store purchase id (`appTransactionId`, or the server's
/// `sha256:<hex>` fallback): 1..=128 of `[A-Za-z0-9._:-]`.
pub fn parse_tx(s: &str) -> Result<String, &'static str> {
    let s = s.trim();
    let ok = (1..=MAX_TX_LEN).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if ok {
        Ok(s.to_string())
    } else {
        Err("Purchase id must be 1 to 128 characters of A-Z a-z 0-9 . _ : -")
    }
}

/// Short stable fingerprint shown instead of a purchase id or APNs token:
/// the first 12 hex digits of its SHA-256.
pub fn fingerprint(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))[..12].to_string()
}

// ----------------------------------------------------------- live limits ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    Number,
    /// 0 = false, 1 = true.
    Switch,
}

/// A limit the panel may override without a restart, with the hard range
/// an override must stay in.
#[derive(Debug)]
pub struct LimitKey {
    pub key: &'static str,
    pub min: u32,
    pub max: u32,
    pub kind: LimitKind,
    pub help: &'static str,
}

const fn num(key: &'static str, min: u32, max: u32, help: &'static str) -> LimitKey {
    LimitKey {
        key,
        min,
        max,
        kind: LimitKind::Number,
        help,
    }
}

const fn switch(key: &'static str, help: &'static str) -> LimitKey {
    LimitKey {
        key,
        min: 0,
        max: 1,
        kind: LimitKind::Switch,
        help,
    }
}

pub const LIMIT_KEYS: &[LimitKey] = &[
    num(
        "RATE_GLOBAL_PER_SEC",
        20,
        10_000,
        "Hosted global bucket, requests per second (every route except the gateway push)",
    ),
    num(
        "RATE_GLOBAL_BURST",
        20,
        100_000,
        "Hosted global bucket, burst",
    ),
    num(
        "RATE_IP_PER_SEC",
        1,
        1_000,
        "Per client IP (IPv6 /64), requests per second",
    ),
    num("RATE_IP_BURST", 1, 10_000, "Per client IP, burst"),
    num(
        "RATE_ANON_GLOBAL_PER_SEC",
        1,
        10_000,
        "Anonymous bucket, per second: group registrations and failed authentications",
    ),
    num(
        "RATE_ANON_GLOBAL_BURST",
        1,
        100_000,
        "Anonymous bucket, burst",
    ),
    num(
        "RATE_GROUP_PER_SEC",
        1,
        1_000,
        "Per group, signed requests per second (all routes together)",
    ),
    num(
        "RATE_GROUP_BURST",
        10,
        10_000,
        "Per group, signed requests, burst (at least 10: a phone sends several at once)",
    ),
    num(
        "WS_MAX_STREAMS",
        16,
        100_000,
        "Open Mac streams on the server (new streams beyond: 503)",
    ),
    num(
        "WS_MAX_MACS_PER_GROUP",
        1,
        10,
        "Open Mac streams per group (a reconnect replacing its own stream always fits)",
    ),
    num(
        "WS_MAX_PER_IP",
        1,
        10_000,
        "Open Mac streams per client IP (IPv6 /64)",
    ),
    num(
        "RATE_V2_GATEWAY_PER_SEC",
        1,
        1_000,
        "Gateway pushes per group per second (licensed groups: twice)",
    ),
    num(
        "RATE_V2_GATEWAY_BURST",
        1,
        10_000,
        "Gateway pushes per group, burst (licensed: twice)",
    ),
    num(
        "GATEWAY_GROUP_PER_HOUR",
        1,
        100_000,
        "Gateway pushes per group per hour (licensed: twice)",
    ),
    num(
        "GATEWAY_GROUP_BURST",
        1,
        10_000,
        "Gateway pushes per group, hourly burst (licensed: twice)",
    ),
    num(
        "GATEWAY_GLOBAL_PER_SEC",
        1,
        10_000,
        "All gateway pushes together, per second",
    ),
    num(
        "GATEWAY_GLOBAL_BURST",
        1,
        100_000,
        "All gateway pushes, burst",
    ),
    num(
        "GATEWAY_MAX_TOKENS_PER_GROUP",
        1,
        1_000,
        "Distinct APNs tokens per gateway group",
    ),
    num(
        "GATEWAY_MAX_GROUPS",
        1,
        1_000_000,
        "Gateway groups in total (new registrations beyond: 503)",
    ),
    switch(
        "GATEWAY_OPEN",
        "Kill switch: off refuses every gateway registration and push",
    ),
    switch(
        "GATEWAY_REQUIRE_LICENCE",
        "Strict gateway: registrations and pushes need a gateway licence",
    ),
];

/// Keys whose change always needs a fresh authenticator code (no step-up
/// window): the gateway switches and the server-wide buckets and caps.
pub fn limit_needs_fresh(key: &str) -> bool {
    matches!(
        key,
        "GATEWAY_OPEN"
            | "GATEWAY_REQUIRE_LICENCE"
            | "RATE_GLOBAL_PER_SEC"
            | "RATE_GLOBAL_BURST"
            | "RATE_ANON_GLOBAL_PER_SEC"
            | "RATE_ANON_GLOBAL_BURST"
            | "WS_MAX_STREAMS"
    )
}

pub fn limit_key(key: &str) -> Option<&'static LimitKey> {
    LIMIT_KEYS.iter().find(|k| k.key == key)
}

/// The configured (environment / default) value of every live key.
fn config_values(c: &Config) -> HashMap<&'static str, u32> {
    let (l, v) = (&c.limits, &c.v2);
    HashMap::from([
        ("RATE_GLOBAL_PER_SEC", l.global.per_sec.get()),
        ("RATE_GLOBAL_BURST", l.global.burst.get()),
        ("RATE_IP_PER_SEC", l.per_ip.per_sec.get()),
        ("RATE_IP_BURST", l.per_ip.burst.get()),
        ("RATE_ANON_GLOBAL_PER_SEC", l.anon_global.per_sec.get()),
        ("RATE_ANON_GLOBAL_BURST", l.anon_global.burst.get()),
        ("RATE_GROUP_PER_SEC", v.rate_group.per_sec.get()),
        ("RATE_GROUP_BURST", v.rate_group.burst.get()),
        ("WS_MAX_STREAMS", v.ws_max_streams),
        ("WS_MAX_MACS_PER_GROUP", v.ws_max_macs_per_group),
        ("WS_MAX_PER_IP", v.ws_max_per_ip),
        ("RATE_V2_GATEWAY_PER_SEC", v.rate_gateway.per_sec.get()),
        ("RATE_V2_GATEWAY_BURST", v.rate_gateway.burst.get()),
        (
            "GATEWAY_GROUP_PER_HOUR",
            v.gateway_group_hourly.per_hour.get(),
        ),
        ("GATEWAY_GROUP_BURST", v.gateway_group_hourly.burst.get()),
        ("GATEWAY_GLOBAL_PER_SEC", v.gateway_global.per_sec.get()),
        ("GATEWAY_GLOBAL_BURST", v.gateway_global.burst.get()),
        (
            "GATEWAY_MAX_TOKENS_PER_GROUP",
            v.gateway_max_tokens_per_group,
        ),
        ("GATEWAY_MAX_GROUPS", v.gateway_max_groups),
        ("GATEWAY_OPEN", u32::from(v.gateway_open)),
        (
            "GATEWAY_REQUIRE_LICENCE",
            u32::from(v.gateway_require_licence),
        ),
    ])
}

// --------------------------------------------------------------- memory ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualBan {
    pub net: IpNet,
    pub until: u64,
    pub reason: String,
    pub created_at: u64,
    pub actor: String,
}

/// In-memory mirror of the panel's controls (see the module docs).
pub struct Controls {
    bans: RwLock<Vec<ManualBan>>,
    suspended: RwLock<HashSet<String>>,
    base: HashMap<&'static str, u32>,
    overrides: RwLock<HashMap<&'static str, u32>>,
}

fn rd<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| e.into_inner())
}

fn wr<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| e.into_inner())
}

/// What [`Controls::load`] found besides the bans and suspensions.
pub struct Loaded {
    pub revoked: Vec<String>,
    /// Valid overrides only (unknown keys or out-of-range values skipped).
    pub overrides: Vec<&'static str>,
}

impl Controls {
    pub fn new(config: &Config) -> Self {
        Self {
            bans: RwLock::new(Vec::new()),
            suspended: RwLock::new(HashSet::new()),
            base: config_values(config),
            overrides: RwLock::new(HashMap::new()),
        }
    }

    /// Read the persisted controls (at startup).
    pub fn load(&self, c: &Connection, now: u64) -> R<Loaded> {
        let mut st = c.prepare(
            "SELECT net, until, reason, created_at, actor FROM manual_bans WHERE until > ?1
             ORDER BY until DESC LIMIT ?2",
        )?;
        let bans: Vec<ManualBan> = st
            .query_map(params![now as i64, MAX_MANUAL_BANS as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?
            .filter_map(|row| {
                let (net, until, reason, created_at, actor) = row.ok()?;
                Some(ManualBan {
                    net: net.parse().ok()?,
                    until: u64::try_from(until).ok()?,
                    reason,
                    created_at: u64::try_from(created_at).unwrap_or(0),
                    actor,
                })
            })
            .collect();
        *wr(&self.bans) = bans;

        let mut st = c.prepare("SELECT group_id FROM group_suspensions")?;
        let set = st
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<HashSet<_>, _>>()?;
        *wr(&self.suspended) = set;

        let mut st = c.prepare("SELECT app_transaction_id FROM revoked_licences")?;
        let revoked = st
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        let mut st = c.prepare("SELECT key, value FROM limit_overrides")?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut ov = wr(&self.overrides);
        ov.clear();
        let mut applied = Vec::new();
        for (k, v) in rows {
            match (limit_key(&k), u32::try_from(v)) {
                (Some(lk), Ok(v)) if (lk.min..=lk.max).contains(&v) => {
                    ov.insert(lk.key, v);
                    applied.push(lk.key);
                }
                _ => tracing::warn!(key = %k, "ignoring invalid limit override"),
            }
        }
        Ok(Loaded {
            revoked,
            overrides: applied,
        })
    }

    /// Seconds left if a manual ban covers `ip` (canonical form) at `now`.
    pub fn banned_for(&self, ip: IpAddr, now: u64) -> Option<u64> {
        let ip = ip.to_canonical();
        rd(&self.bans)
            .iter()
            .filter(|b| b.until > now && b.net.contains(&ip))
            .map(|b| b.until - now)
            .max()
    }

    /// Active manual bans, longest first.
    pub fn bans(&self, now: u64) -> Vec<ManualBan> {
        let mut v: Vec<_> = rd(&self.bans)
            .iter()
            .filter(|b| b.until > now)
            .cloned()
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.until));
        v
    }

    pub fn ban_count(&self, now: u64) -> usize {
        rd(&self.bans).iter().filter(|b| b.until > now).count()
    }

    /// Add or replace the ban on `b.net`.
    pub fn put_ban(&self, b: ManualBan) {
        let mut v = wr(&self.bans);
        v.retain(|x| x.net != b.net);
        v.push(b);
    }

    pub fn remove_ban(&self, net: &IpNet) -> bool {
        let mut v = wr(&self.bans);
        let n = v.len();
        v.retain(|x| &x.net != net);
        v.len() != n
    }

    pub fn cleanup(&self, now: u64) {
        wr(&self.bans).retain(|b| b.until > now);
    }

    pub fn is_suspended(&self, group: &str) -> bool {
        rd(&self.suspended).contains(group)
    }

    pub fn set_suspended(&self, group: &str, suspended: bool) {
        let mut s = wr(&self.suspended);
        if suspended {
            s.insert(group.to_string());
        } else {
            s.remove(group);
        }
    }

    pub fn suspended_count(&self) -> usize {
        rd(&self.suspended).len()
    }

    /// The configured value of a live key.
    pub fn base(&self, key: &str) -> u32 {
        self.base.get(key).copied().unwrap_or(0)
    }

    pub fn override_of(&self, key: &str) -> Option<u32> {
        rd(&self.overrides).get(key).copied()
    }

    /// The override if any, else the configured value.
    pub fn effective(&self, key: &str) -> u32 {
        self.override_of(key).unwrap_or_else(|| self.base(key))
    }

    /// Set (`Some`) or clear the override of a known key.
    pub fn set_override(&self, key: &'static LimitKey, value: Option<u32>) {
        let mut ov = wr(&self.overrides);
        match value {
            Some(v) => ov.insert(key.key, v),
            None => ov.remove(key.key),
        };
    }
}

// ------------------------------------------------------------- database ---

pub fn put_ban(c: &Connection, b: &ManualBan) -> R<()> {
    c.execute(
        "INSERT INTO manual_bans (net, until, reason, created_at, actor) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (net) DO UPDATE SET until = ?2, reason = ?3, created_at = ?4, actor = ?5",
        params![
            b.net.to_string(),
            b.until as i64,
            b.reason,
            b.created_at as i64,
            b.actor
        ],
    )?;
    Ok(())
}

pub fn delete_ban(c: &Connection, net: &IpNet) -> R<bool> {
    Ok(c.execute("DELETE FROM manual_bans WHERE net = ?1", [net.to_string()])? > 0)
}

/// `None` if the group does not exist, else whether it was newly suspended.
pub fn suspend(
    c: &Connection,
    group_id: &str,
    now: u64,
    reason: &str,
    actor: &str,
) -> R<Option<bool>> {
    let exists = c
        .query_row(
            "SELECT 1 FROM groups WHERE group_id = ?1",
            [group_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Ok(None);
    }
    let n = c.execute(
        "INSERT OR IGNORE INTO group_suspensions (group_id, suspended_at, reason, actor)
         VALUES (?1, ?2, ?3, ?4)",
        params![group_id, now as i64, reason, actor],
    )?;
    Ok(Some(n > 0))
}

pub fn unsuspend(c: &Connection, group_id: &str) -> R<bool> {
    Ok(c.execute(
        "DELETE FROM group_suspensions WHERE group_id = ?1",
        [group_id],
    )? > 0)
}

/// Whether the purchase was newly revoked.
pub fn revoke(c: &Connection, tx: &str, now: u64, reason: &str, actor: &str) -> R<bool> {
    Ok(c.execute(
        "INSERT OR IGNORE INTO revoked_licences (app_transaction_id, revoked_at, reason, actor)
         VALUES (?1, ?2, ?3, ?4)",
        params![tx, now as i64, reason, actor],
    )? > 0)
}

/// The panel-revoked purchase whose [`fingerprint`] is `fp`, if any.
pub fn revoked_by_fingerprint(c: &Connection, fp: &str) -> R<Option<String>> {
    let mut st = c.prepare("SELECT app_transaction_id FROM revoked_licences")?;
    let ids = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids.into_iter().find(|t| fingerprint(t) == fp))
}

pub fn restore(c: &Connection, tx: &str) -> R<bool> {
    Ok(c.execute(
        "DELETE FROM revoked_licences WHERE app_transaction_id = ?1",
        [tx],
    )? > 0)
}

pub fn put_override(c: &Connection, key: &str, value: u32, now: u64, actor: &str) -> R<()> {
    c.execute(
        "INSERT INTO limit_overrides (key, value, updated_at, actor) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (key) DO UPDATE SET value = ?2, updated_at = ?3, actor = ?4",
        params![key, i64::from(value), now as i64, actor],
    )?;
    Ok(())
}

pub fn delete_override(c: &Connection, key: &str) -> R<bool> {
    Ok(c.execute("DELETE FROM limit_overrides WHERE key = ?1", [key])? > 0)
}

/// Unbind the token of `group_id` whose [`fingerprint`] is `fp`; whether
/// there was one.
pub fn unbind_gateway_token(c: &Connection, group_id: &str, fp: &str) -> R<bool> {
    let mut st = c.prepare("SELECT token FROM gateway_tokens WHERE group_id = ?1")?;
    let tokens = st
        .query_map([group_id], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let Some(t) = tokens.into_iter().find(|t| fingerprint(t) == fp) else {
        return Ok(false);
    };
    c.execute(
        "DELETE FROM gateway_tokens WHERE token = ?1 AND group_id = ?2",
        [&t, group_id],
    )?;
    Ok(true)
}

/// Remove `group_id` from the gateway: its membership and token bindings.
/// Returns (was a member, tokens unbound).
pub fn remove_gateway_group(c: &Connection, group_id: &str) -> R<(bool, usize)> {
    let tokens = c.execute("DELETE FROM gateway_tokens WHERE group_id = ?1", [group_id])?;
    let member = c.execute("DELETE FROM gateway_groups WHERE group_id = ?1", [group_id])? > 0;
    Ok((member, tokens))
}

/// One admin audit log row. Never secrets, full purchase ids or tokens.
#[derive(Debug, Clone)]
pub struct Audit {
    pub ts: u64,
    pub actor: String,
    /// The admin's network (/24 or /48), like every other stored IP.
    pub ip_prefix: String,
    pub action: &'static str,
    pub target: Option<String>,
    pub detail: Option<String>,
    /// `ok`, `noop`, `totp_failed`, `totp_reused`, `locked`, `invalid`.
    pub outcome: &'static str,
}

/// Whether a ban on `net` is broad enough to need a fresh code (shorter
/// than IPv4 /24 or IPv6 /48).
pub fn is_broad_ban(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => n.prefix_len() < NARROW_V4_PREFIX,
        IpNet::V6(n) => n.prefix_len() < NARROW_V6_PREFIX,
    }
}

/// Retention: drop audit rows older than [`AUDIT_RETENTION_SECS`] and all
/// but the newest `max_rows`. Returns the rows removed. Run by the storage
/// cleanup only; the panel never deletes audit rows.
pub fn prune_audit(c: &Connection, now: u64, max_rows: i64) -> R<usize> {
    let old = c.execute(
        "DELETE FROM admin_audit WHERE ts <= ?1",
        [now.saturating_sub(AUDIT_RETENTION_SECS) as i64],
    )?;
    let over = c.execute(
        "DELETE FROM admin_audit WHERE id <= (SELECT id FROM admin_audit ORDER BY id DESC LIMIT 1 OFFSET ?1)",
        [max_rows],
    )?;
    Ok(old + over)
}

/// Append to the audit log. There is no update or delete path from the
/// panel.
pub fn audit(c: &Connection, a: &Audit) -> R<()> {
    c.execute(
        "INSERT INTO admin_audit (ts, actor, ip_prefix, action, target, detail, outcome)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            a.ts as i64,
            a.actor,
            a.ip_prefix,
            a.action,
            a.target,
            a.detail,
            a.outcome
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_targets() {
        assert_eq!(
            parse_ban_target("192.0.2.7").unwrap().to_string(),
            "192.0.2.7/32"
        );
        assert_eq!(
            parse_ban_target(" 192.0.2.7/24 ").unwrap().to_string(),
            "192.0.2.0/24",
            "host bits cleared"
        );
        assert!(parse_ban_target("10.0.0.0/16").is_ok());
        assert!(parse_ban_target("10.0.0.0/15").is_err());
        assert!(parse_ban_target("0.0.0.0/0").is_err());
        assert_eq!(
            parse_ban_target("2001:db8:1::5/48").unwrap().to_string(),
            "2001:db8:1::/48"
        );
        assert!(parse_ban_target("2001:db8::/32").is_ok());
        // IPv6 is banned per /64 at most, like the automatic bans.
        for long in [
            "2001:db8:1:2::5",
            "2001:db8:1:2:aaaa::1/128",
            "2001:db8:1:2::/80",
        ] {
            assert_eq!(
                parse_ban_target(long).unwrap().to_string(),
                "2001:db8:1:2::/64",
                "{long}"
            );
        }
        assert!(is_broad_ban(&parse_ban_target("192.0.2.0/23").unwrap()));
        assert!(!is_broad_ban(&parse_ban_target("192.0.2.0/24").unwrap()));
        assert!(is_broad_ban(&parse_ban_target("2001:db8::/47").unwrap()));
        assert!(!is_broad_ban(&parse_ban_target("2001:db8::/48").unwrap()));
        assert!(!is_broad_ban(&parse_ban_target("2001:db8::1").unwrap()));
        assert!(parse_ban_target("2001:db8::/31").is_err());
        assert!(parse_ban_target("::/0").is_err());
        assert!(parse_ban_target("::ffff:192.0.2.7").is_err());
        assert!(parse_ban_target("").is_err());
        assert!(parse_ban_target("example.com").is_err());
        assert!(parse_ban_target("192.0.2.300").is_err());
        assert!(parse_ban_target(&"1".repeat(100)).is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("15m"), Ok(900));
        assert_eq!(parse_duration("6h"), Ok(21_600));
        assert_eq!(parse_duration("30d"), Ok(30 * 86_400));
        for bad in [
            "14m",
            "31d",
            "0d",
            "",
            "d",
            "1w",
            "-1h",
            "1.5h",
            "99999999d",
            "1 h",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reasons_and_purchase_ids() {
        assert_eq!(parse_reason("  abuse "), Ok("abuse".into()));
        assert!(parse_reason("").is_err());
        assert!(parse_reason("a\nb").is_err());
        assert!(parse_reason(&"x".repeat(201)).is_err());
        assert!(parse_reason(&"ż".repeat(200)).is_ok(), "chars, not bytes");
        assert!(parse_tx("2000000123456789").is_ok());
        assert!(parse_tx("sha256:abc").is_ok());
        assert!(parse_tx("a b").is_err());
        assert!(parse_tx("<x>").is_err());
        assert!(parse_tx(&"1".repeat(129)).is_err());
        assert_eq!(fingerprint("x").len(), 12);
        assert_ne!(fingerprint("x"), fingerprint("y"));
    }

    #[test]
    fn limit_keys_are_unique_and_bounded() {
        let mut seen = HashSet::new();
        for k in LIMIT_KEYS {
            assert!(seen.insert(k.key), "{}", k.key);
            assert!(k.min <= k.max);
            if k.kind == LimitKind::Number {
                assert!(k.min >= 1, "{}: a zero rate would panic governor", k.key);
            }
        }
        let c = Config::from_lookup(|k| match k {
            "APNS_MODE" => Some("mock".into()),
            _ => None,
        })
        .unwrap();
        let base = config_values(&c);
        for k in LIMIT_KEYS {
            assert!(base.contains_key(k.key), "{} has a config value", k.key);
        }
    }

    #[test]
    fn tables_keep_user_version_6_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::v2::store::Store::open(dir.path()).unwrap();
        let cfg = Config::from_lookup(|k| match k {
            "APNS_MODE" => Some("mock".into()),
            _ => None,
        })
        .unwrap();
        store
            .blocking(|c| {
                crate::v2::store::create_group(c, "g", &[1; 32], 0)?;
                assert_eq!(suspend(c, "g", 5, "r", "a")?, Some(true));
                assert_eq!(suspend(c, "g", 6, "r", "a")?, Some(false));
                assert_eq!(suspend(c, "nope", 6, "r", "a")?, None);
                put_ban(
                    c,
                    &ManualBan {
                        net: parse_ban_target("192.0.2.0/24").unwrap(),
                        until: 1000,
                        reason: "r".into(),
                        created_at: 0,
                        actor: "a".into(),
                    },
                )?;
                assert!(revoke(c, "tx", 0, "r", "a")?);
                put_override(c, "RATE_IP_BURST", 7, 0, "a")?;
                put_override(c, "NOT_A_KEY", 7, 0, "a")?;
                put_override(c, "GATEWAY_OPEN", 9, 0, "a")?;
                Ok(())
            })
            .unwrap();
        let ctl = Controls::new(&cfg);
        let loaded = store.blocking(|c| ctl.load(c, 10)).unwrap();
        assert!(ctl.is_suspended("g"));
        assert_eq!(ctl.ban_count(10), 1);
        assert_eq!(loaded.revoked, ["tx"]);
        assert_eq!(loaded.overrides, ["RATE_IP_BURST"], "invalid rows skipped");
        assert_eq!(ctl.effective("RATE_IP_BURST"), 7);
        // Rollback safety: still schema version 6, and deleting the group
        // (as 0.2.0 would) cascades into the suspension.
        store
            .blocking(|c| {
                let v: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
                assert_eq!(v, 6);
                crate::v2::store::delete_group(c, "g")?;
                let n: i64 =
                    c.query_row("SELECT COUNT(*) FROM group_suspensions", [], |r| r.get(0))?;
                assert_eq!(n, 0);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn audit_retention_by_age_and_count() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::v2::store::Store::open(dir.path()).unwrap();
        let row = |ts| Audit {
            ts,
            actor: "a".into(),
            ip_prefix: "192.0.2.0/24".into(),
            action: "x",
            target: None,
            detail: None,
            outcome: "ok",
        };
        let now = 200 * 86_400;
        store
            .blocking(|c| {
                audit(c, &row(now - AUDIT_RETENTION_SECS - 1))?;
                for i in 0..5 {
                    audit(c, &row(now - 10 + i))?;
                }
                assert_eq!(prune_audit(c, now, 3)?, 3, "1 too old, 2 over the cap");
                let ts: Vec<i64> = c
                    .prepare("SELECT ts FROM admin_audit ORDER BY id")?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                let now = now as i64;
                assert_eq!(ts, [now - 8, now - 7, now - 6], "the newest are kept");
                assert_eq!(prune_audit(c, now as u64, 3)?, 0);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn manual_bans_match_prefixes_and_expire() {
        let c = Config::from_lookup(|k| match k {
            "APNS_MODE" => Some("mock".into()),
            _ => None,
        })
        .unwrap();
        let ctl = Controls::new(&c);
        let ban = |net: &str, until| ManualBan {
            net: parse_ban_target(net).unwrap(),
            until,
            reason: "r".into(),
            created_at: 0,
            actor: "a".into(),
        };
        ctl.put_ban(ban("192.0.2.0/24", 100));
        ctl.put_ban(ban("2001:db8::/32", 50));
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(ctl.banned_for(ip("192.0.2.9"), 10), Some(90));
        assert_eq!(
            ctl.banned_for(ip("::ffff:192.0.2.9"), 10),
            Some(90),
            "mapped form"
        );
        assert_eq!(ctl.banned_for(ip("192.0.3.9"), 10), None);
        assert_eq!(ctl.banned_for(ip("2001:db8:5::1"), 10), Some(40));
        // A /64 ban matches every address of that /64, i.e. its ip_key.
        ctl.put_ban(ban("2001:db9:1:2::7", 30));
        for a in ["2001:db9:1:2::7", "2001:db9:1:2:ffff::1"] {
            assert_eq!(ctl.banned_for(ip(a), 10), Some(20), "{a}");
            assert_eq!(ctl.banned_for(crate::limits::ip_key(ip(a)), 10), Some(20));
        }
        assert_eq!(ctl.banned_for(ip("2001:db9:1:3::7"), 10), None);
        assert_eq!(ctl.banned_for(ip("192.0.2.9"), 100), None, "expired");
        // Replacing keeps one entry per prefix.
        ctl.put_ban(ban("192.0.2.0/24", 200));
        assert_eq!(ctl.bans(10).len(), 3);
        assert!(ctl.remove_ban(&parse_ban_target("192.0.2.0/24").unwrap()));
        assert_eq!(ctl.banned_for(ip("192.0.2.9"), 10), None);
        ctl.cleanup(60);
        assert_eq!(ctl.ban_count(0), 0);
    }
}
