//! Abuse protection: rate limits (governor), auth-failure bans, and a bounded
//! expiring set used for replay protection and dedup.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use governor::clock::{Clock as _, DefaultClock};
use governor::{DefaultDirectRateLimiter, DefaultKeyedRateLimiter, Quota, RateLimiter};

use crate::config::{HourlyRate, Limits, Rate, V2Config};

/// Wall clock in unix seconds. Injectable so tests control time.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Max distinct IPs tracked by the auth-failure ban map.
pub const MAX_BAN_ENTRIES: usize = 100_000;

/// Rate-limit key for an IP: IPv4 as-is, IPv6 collapsed to its /64, because
/// a single host usually controls a whole /64.
pub fn ip_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::from([s[0], s[1], s[2], s[3], 0, 0, 0, 0])
        }
        v4 => v4,
    }
}

/// A set of keys that expire after `ttl` and never exceeds `cap` entries
/// (the oldest entry is evicted first).
pub struct ExpiringSet<K> {
    ttl: u64,
    cap: usize,
    map: HashMap<K, u64>,
    order: VecDeque<(K, u64)>,
}

impl<K: Eq + Hash + Clone> ExpiringSet<K> {
    pub fn new(ttl: Duration, cap: usize) -> Self {
        Self {
            ttl: ttl.as_secs(),
            cap: cap.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Insert `key` if it is not present (or expired). Returns `false` if it
    /// was already present.
    pub fn insert_if_absent(&mut self, key: K, now: u64) -> bool {
        self.purge(now);
        if self.map.contains_key(&key) {
            return false;
        }
        while self.map.len() >= self.cap {
            self.pop_oldest();
        }
        self.map.insert(key.clone(), now);
        self.order.push_back((key, now));
        true
    }

    /// Like [`ExpiringSet::insert_if_absent`], but fail closed: when the set
    /// is full of live entries, nothing is evicted and `Err(SetFull)` is
    /// returned (the replay cache must not forget a signature that is still
    /// valid).
    pub fn try_insert(&mut self, key: K, now: u64) -> Result<bool, SetFull> {
        self.purge(now);
        if self.map.contains_key(&key) {
            return Ok(false);
        }
        if self.map.len() >= self.cap {
            return Err(SetFull);
        }
        self.map.insert(key.clone(), now);
        self.order.push_back((key, now));
        Ok(true)
    }

    /// `key` is present and not expired.
    pub fn contains(&mut self, key: &K, now: u64) -> bool {
        self.purge(now);
        self.map.contains_key(key)
    }

    pub fn remove(&mut self, key: &K) {
        // The stale `order` entry is skipped later because its timestamp no
        // longer matches the map.
        self.map.remove(key);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drop expired entries.
    pub fn purge(&mut self, now: u64) {
        while let Some((_, at)) = self.order.front() {
            if now.saturating_sub(*at) < self.ttl {
                break;
            }
            self.pop_oldest();
        }
    }

    fn pop_oldest(&mut self) {
        if let Some((k, at)) = self.order.pop_front() {
            if self.map.get(&k) == Some(&at) {
                self.map.remove(&k);
            }
        }
    }
}

/// [`ExpiringSet::try_insert`] found the set full of live entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetFull;

#[derive(Debug, Clone, Copy)]
struct FailureEntry {
    window_start: u64,
    failures: u32,
    banned_until: u64,
    /// Rate-limited answers (`record_abuse`) in the window starting here.
    abuse_start: u64,
    abused: u32,
}

/// Bans an IP for `duration` after `threshold` auth failures within `window`,
/// and for the abuse duration after `abuse.threshold` rate-limited answers
/// within the abuse window (sustained flooding without any auth failure).
pub struct AuthBans {
    threshold: u32,
    window: u64,
    duration: u64,
    abuse: AbuseRule,
    map: Mutex<HashMap<IpAddr, FailureEntry>>,
}

/// `AUTH_ABUSE_*`: rate-limited answers per IP key that start a ban.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbuseRule {
    pub threshold: u32,
    pub window: u64,
    pub duration: u64,
}

impl Default for AbuseRule {
    fn default() -> Self {
        Self {
            threshold: 100,
            window: 60,
            duration: 300,
        }
    }
}

impl AuthBans {
    pub fn new(threshold: u32, window: Duration, duration: Duration) -> Self {
        Self::with_abuse(threshold, window, duration, AbuseRule::default())
    }

    pub fn with_abuse(
        threshold: u32,
        window: Duration,
        duration: Duration,
        abuse: AbuseRule,
    ) -> Self {
        Self {
            threshold,
            window: window.as_secs(),
            duration: duration.as_secs(),
            abuse,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// The entry for `key`, unless the map is full of live entries.
    fn entry<'a>(
        &self,
        map: &'a mut HashMap<IpAddr, FailureEntry>,
        key: IpAddr,
        now: u64,
    ) -> Option<&'a mut FailureEntry> {
        if map.len() >= MAX_BAN_ENTRIES && !map.contains_key(&key) {
            Self::cleanup_locked(map, now, self.window.max(self.abuse.window));
            if map.len() >= MAX_BAN_ENTRIES {
                // Map full of live entries: stop tracking new IPs rather than
                // grow without bound. Rate limits still apply.
                return None;
            }
        }
        Some(map.entry(key).or_insert(FailureEntry {
            window_start: now,
            failures: 0,
            banned_until: 0,
            abuse_start: now,
            abused: 0,
        }))
    }

    /// Record one rate-limited answer (429) for `key`; returns `true` if it
    /// started a ban. A client that keeps hammering after being told to back
    /// off is banned like one that keeps failing authentication.
    pub fn record_abuse(&self, key: IpAddr, now: u64) -> bool {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let rule = self.abuse;
        let Some(e) = self.entry(&mut map, key, now) else {
            return false;
        };
        if e.banned_until > now {
            return false;
        }
        if now.saturating_sub(e.abuse_start) >= rule.window {
            e.abuse_start = now;
            e.abused = 0;
        }
        e.abused = e.abused.saturating_add(1);
        if e.abused >= rule.threshold {
            e.banned_until = now + rule.duration;
            e.abused = 0;
            e.abuse_start = now;
            return true;
        }
        false
    }

    /// Seconds remaining on a ban for `key`, if banned.
    pub fn banned_for(&self, key: IpAddr, now: u64) -> Option<u64> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&key)
            .filter(|e| e.banned_until > now)
            .map(|e| e.banned_until - now)
    }

    /// Record one auth failure; returns `true` if this failure started a ban.
    pub fn record_failure(&self, key: IpAddr, now: u64) -> bool {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let Some(e) = self.entry(&mut map, key, now) else {
            return false;
        };
        if now.saturating_sub(e.window_start) >= self.window {
            e.window_start = now;
            e.failures = 0;
        }
        e.failures = e.failures.saturating_add(1);
        if e.failures >= self.threshold && e.banned_until <= now {
            e.banned_until = now + self.duration;
            e.failures = 0;
            e.window_start = now;
            return true;
        }
        false
    }

    pub fn cleanup(&self, now: u64) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        Self::cleanup_locked(&mut map, now, self.window.max(self.abuse.window));
    }

    /// Keys banned at `now` with the seconds left, longest first.
    pub fn active(&self, now: u64) -> Vec<(IpAddr, u64)> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = map
            .iter()
            .filter(|(_, e)| e.banned_until > now)
            .map(|(k, e)| (*k, e.banned_until - now))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// Lift the ban on `key` and forget its failures; `true` if it was banned.
    pub fn unban(&self, key: IpAddr, now: u64) -> bool {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(&key).is_some_and(|e| e.banned_until > now)
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn cleanup_locked(map: &mut HashMap<IpAddr, FailureEntry>, now: u64, window: u64) {
        map.retain(|_, e| {
            e.banned_until > now
                || now.saturating_sub(e.window_start) < window
                || now.saturating_sub(e.abuse_start) < window
        });
        map.shrink_to_fit();
    }
}

fn quota(r: Rate) -> Quota {
    Quota::per_second(r.per_sec).allow_burst(r.burst)
}

/// A value replaced as a whole at runtime (admin live limits): readers get
/// the current `Arc`, a writer swaps in a freshly built one. A replaced
/// limiter starts with full buckets.
pub struct Live<T>(RwLock<Arc<T>>);

impl<T> Live<T> {
    pub fn new(v: T) -> Self {
        Self(RwLock::new(Arc::new(v)))
    }

    pub fn get(&self) -> Arc<T> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set(&self, v: T) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(v);
    }
}

/// Global, per-IP and per-secret token buckets.
pub struct RateLimits {
    /// Authenticated requests (`RATE_GLOBAL_*`): v2 checks it only after the
    /// signature verified, so anonymous floods cannot drain it.
    global: Live<DefaultDirectRateLimiter>,
    /// Anonymous work (`RATE_ANON_GLOBAL_*`): `POST /v2/groups` and requests
    /// that failed authentication.
    anon: Live<DefaultDirectRateLimiter>,
    /// All pre-signature work of signed routes (`RATE_PRE_AUTH_*`): a cheap
    /// ceiling on group-key lookups and HMAC checks, before either.
    pre_auth: Live<DefaultDirectRateLimiter>,
    per_ip: Live<DefaultKeyedRateLimiter<IpAddr>>,
    per_secret: Vec<DefaultDirectRateLimiter>,
}

/// A rejected request; the value is the suggested `Retry-After` in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryAfter(pub u64);

fn retry_after(nu: governor::NotUntil<governor::clock::QuantaInstant>) -> RetryAfter {
    let wait = nu.wait_time_from(DefaultClock::default().now());
    RetryAfter((wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1))
}

impl RateLimits {
    pub fn new(limits: &Limits, secret_count: usize) -> Self {
        Self {
            global: Live::new(RateLimiter::direct(quota(limits.global))),
            anon: Live::new(RateLimiter::direct(quota(limits.anon_global))),
            pre_auth: Live::new(RateLimiter::direct(quota(limits.pre_auth))),
            per_ip: Live::new(RateLimiter::keyed(quota(limits.per_ip))),
            per_secret: (0..secret_count)
                .map(|_| RateLimiter::direct(quota(limits.per_secret)))
                .collect(),
        }
    }

    pub fn check_ip(&self, key: IpAddr) -> Result<(), RetryAfter> {
        self.per_ip.get().check_key(&key).map_err(retry_after)
    }

    pub fn check_global(&self) -> Result<(), RetryAfter> {
        self.global.get().check().map_err(retry_after)
    }

    pub fn check_anon(&self) -> Result<(), RetryAfter> {
        self.anon.get().check().map_err(retry_after)
    }

    pub fn check_pre_auth(&self) -> Result<(), RetryAfter> {
        self.pre_auth.get().check().map_err(retry_after)
    }

    /// Replace the pre-auth bucket (`RATE_PRE_AUTH_*` live override).
    pub fn set_pre_auth(&self, r: Rate) {
        self.pre_auth.set(RateLimiter::direct(quota(r)));
    }

    /// Replace the anonymous bucket (`RATE_ANON_GLOBAL_*` live override).
    pub fn set_anon(&self, r: Rate) {
        self.anon.set(RateLimiter::direct(quota(r)));
    }

    /// Replace the per-IP buckets (`RATE_IP_*` live override).
    pub fn set_per_ip(&self, r: Rate) {
        self.per_ip.set(RateLimiter::keyed(quota(r)));
    }

    /// Replace the global bucket (`RATE_GLOBAL_*` live override).
    pub fn set_global(&self, r: Rate) {
        self.global.set(RateLimiter::direct(quota(r)));
    }

    pub fn check_secret(&self, index: usize) -> Result<(), RetryAfter> {
        match self.per_secret.get(index) {
            Some(l) => l.check().map_err(retry_after),
            None => Ok(()),
        }
    }

    /// Drop per-IP buckets that are back to full (equivalent to unseen).
    pub fn cleanup(&self) {
        let l = self.per_ip.get();
        l.retain_recent();
        l.shrink_to_fit();
    }

    pub fn tracked_ips(&self) -> usize {
        self.per_ip.get().len()
    }
}

/// v2 limits: per-group buckets for messages, commands and gateway pushes,
/// and a per-IP bucket for group registration.
pub struct V2Limits {
    messages: DefaultKeyedRateLimiter<String>,
    commands: DefaultKeyedRateLimiter<String>,
    /// Per-group gateway buckets per second: `[unlicensed, licensed]`;
    /// licensed groups get twice the rate and burst.
    gateway: Live<[DefaultKeyedRateLimiter<String>; 2]>,
    /// The same per hour (`GATEWAY_GROUP_*`).
    gateway_hourly: Live<[DefaultKeyedRateLimiter<String>; 2]>,
    /// All gateway pushes together (`GATEWAY_GLOBAL_*`).
    gateway_global: Live<DefaultDirectRateLimiter>,
    /// Token re-bindings per gateway group (10 per day).
    gateway_rebind: DefaultKeyedRateLimiter<String>,
    activity: DefaultKeyedRateLimiter<String>,
    snapshot: DefaultKeyedRateLimiter<String>,
    heartbeat: DefaultKeyedRateLimiter<String>,
    groups: DefaultKeyedRateLimiter<IpAddr>,
    /// Every signed request of a group (`RATE_GROUP_*`).
    per_group: Live<DefaultKeyedRateLimiter<String>>,
    /// "Back online" presence pushes per group ([`presence_quota`]).
    presence: DefaultKeyedRateLimiter<String>,
    /// "Mac offline" presence pushes per group ([`presence_offline_quota`]).
    presence_offline: DefaultKeyedRateLimiter<String>,
    /// Attaches of licences with a fallback purchase id, per client IP.
    fallback_attach: DefaultKeyedRateLimiter<IpAddr>,
}

/// "Back online" (silent) presence pushes per group: 6 per hour, burst 6.
/// Beyond that the state still changes but no push is sent (a connect / bye
/// loop must not page the phones without limit).
pub fn presence_quota() -> Quota {
    let n = std::num::NonZeroU32::new(6).expect("non-zero");
    Quota::per_hour(n).allow_burst(n)
}

/// "Mac offline" (critical) presence pushes per group: 12 per hour, burst
/// 12, a bucket of its own so online notices never use it up. An offline
/// notice beyond it is not dropped but retried on the next presence tick.
pub fn presence_offline_quota() -> Quota {
    let n = std::num::NonZeroU32::new(12).expect("non-zero");
    Quota::per_hour(n).allow_burst(n)
}

/// Licence attaches with a fallback purchase id per client IP and day.
pub const FALLBACK_ATTACHES_PER_DAY: u32 = 10;

/// One per 2.4 h, burst 10.
pub fn fallback_attach_quota() -> Quota {
    let n = std::num::NonZeroU32::new(FALLBACK_ATTACHES_PER_DAY).expect("non-zero");
    Quota::with_period(Duration::from_secs(86_400 / u64::from(n.get())))
        .expect("non-zero period")
        .allow_burst(n)
}

/// `POST /v2/activity-state` per group: one per 5 s, burst 10 (the server
/// coalesces on top of this; Apple budgets Live Activity updates).
pub fn activity_quota() -> Quota {
    Quota::with_period(Duration::from_secs(5))
        .expect("non-zero period")
        .allow_burst(std::num::NonZeroU32::new(10).expect("non-zero"))
}

/// `POST /v2/snapshot` per group: one per 5 s, burst 5 (a snapshot can be
/// 192 KB; the Mac sends at most one per 10 s plus a 5-min heartbeat).
pub fn snapshot_quota() -> Quota {
    Quota::with_period(Duration::from_secs(5))
        .expect("non-zero period")
        .allow_burst(std::num::NonZeroU32::new(5).expect("non-zero"))
}

/// `POST /v2/heartbeat` per group: one per 10 min, burst 3. Apple throttles
/// background pushes to a few per hour anyway; the Mac sends one per 15 min.
pub fn heartbeat_quota() -> Quota {
    Quota::with_period(Duration::from_secs(600))
        .expect("non-zero period")
        .allow_burst(std::num::NonZeroU32::new(3).expect("non-zero"))
}

fn hourly(r: HourlyRate) -> Quota {
    Quota::per_hour(r.per_hour).allow_burst(r.burst)
}

/// Re-bindings of idle gateway tokens to another group, per group and day.
pub const GATEWAY_REBINDS_PER_DAY: u32 = 10;

/// One re-binding per 2.4 h, burst 10: at most 10 per day.
pub fn gateway_rebind_quota() -> Quota {
    let n = std::num::NonZeroU32::new(GATEWAY_REBINDS_PER_DAY).expect("non-zero");
    Quota::with_period(Duration::from_secs(86_400 / u64::from(n.get())))
        .expect("non-zero period")
        .allow_burst(n)
}

fn double(n: std::num::NonZeroU32) -> std::num::NonZeroU32 {
    n.saturating_mul(std::num::NonZeroU32::new(2).expect("non-zero"))
}

fn gateway_pair(r: Rate) -> [DefaultKeyedRateLimiter<String>; 2] {
    [
        RateLimiter::keyed(quota(r)),
        RateLimiter::keyed(quota(Rate {
            per_sec: double(r.per_sec),
            burst: double(r.burst),
        })),
    ]
}

fn gateway_hourly_pair(r: HourlyRate) -> [DefaultKeyedRateLimiter<String>; 2] {
    [
        RateLimiter::keyed(hourly(r)),
        RateLimiter::keyed(hourly(HourlyRate {
            per_hour: double(r.per_hour),
            burst: double(r.burst),
        })),
    ]
}

impl V2Limits {
    pub fn new(c: &V2Config) -> Self {
        Self {
            messages: RateLimiter::keyed(quota(c.rate_messages)),
            commands: RateLimiter::keyed(quota(c.rate_commands)),
            gateway: Live::new(gateway_pair(c.rate_gateway)),
            gateway_hourly: Live::new(gateway_hourly_pair(c.gateway_group_hourly)),
            gateway_global: Live::new(RateLimiter::direct(quota(c.gateway_global))),
            gateway_rebind: RateLimiter::keyed(gateway_rebind_quota()),
            activity: RateLimiter::keyed(activity_quota()),
            snapshot: RateLimiter::keyed(snapshot_quota()),
            heartbeat: RateLimiter::keyed(heartbeat_quota()),
            groups: RateLimiter::keyed(hourly(c.rate_groups)),
            per_group: Live::new(RateLimiter::keyed(quota(c.rate_group))),
            presence: RateLimiter::keyed(presence_quota()),
            presence_offline: RateLimiter::keyed(presence_offline_quota()),
            fallback_attach: RateLimiter::keyed(fallback_attach_quota()),
        }
    }

    /// The group's bucket over all signed routes (after the signature).
    pub fn check_group(&self, group: &str) -> Result<(), RetryAfter> {
        self.per_group
            .get()
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    /// Replace the per-group buckets (`RATE_GROUP_*` live override).
    pub fn set_group(&self, r: Rate) {
        self.per_group.set(RateLimiter::keyed(quota(r)));
    }

    /// One more "back online" presence push for `group`.
    pub fn check_presence(&self, group: &str) -> Result<(), RetryAfter> {
        self.presence
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    /// One more "Mac offline" presence push for `group`.
    pub fn check_presence_offline(&self, group: &str) -> Result<(), RetryAfter> {
        self.presence_offline
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    /// One more attach of a fallback-id licence from `ip` (an IP key).
    pub fn check_fallback_attach(&self, ip: IpAddr) -> Result<(), RetryAfter> {
        self.fallback_attach.check_key(&ip).map_err(retry_after)
    }

    pub fn check_messages(&self, group: &str) -> Result<(), RetryAfter> {
        self.messages
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    pub fn check_commands(&self, group: &str) -> Result<(), RetryAfter> {
        self.commands
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    /// Per-group gateway buckets: per second, then per hour; licensed
    /// groups get twice both.
    pub fn check_gateway(&self, group: &str, licensed: bool) -> Result<(), RetryAfter> {
        let key = group.to_string();
        let i = usize::from(licensed);
        self.gateway.get()[i].check_key(&key).map_err(retry_after)?;
        self.gateway_hourly.get()[i]
            .check_key(&key)
            .map_err(retry_after)
    }

    /// The gateway's own global bucket.
    pub fn check_gateway_global(&self) -> Result<(), RetryAfter> {
        self.gateway_global.get().check().map_err(retry_after)
    }

    /// Replace the per-group gateway buckets (`RATE_V2_GATEWAY_*`).
    pub fn set_gateway(&self, r: Rate) {
        self.gateway.set(gateway_pair(r));
    }

    /// Replace the hourly per-group gateway buckets (`GATEWAY_GROUP_*`).
    pub fn set_gateway_hourly(&self, r: HourlyRate) {
        self.gateway_hourly.set(gateway_hourly_pair(r));
    }

    /// Replace the shared gateway bucket (`GATEWAY_GLOBAL_*`).
    pub fn set_gateway_global(&self, r: Rate) {
        self.gateway_global.set(RateLimiter::direct(quota(r)));
    }

    /// One more re-binding of an idle token to `group`.
    pub fn check_gateway_rebind(&self, group: &str) -> Result<(), RetryAfter> {
        self.gateway_rebind
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    pub fn check_activity(&self, group: &str) -> Result<(), RetryAfter> {
        self.activity
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    pub fn check_snapshot(&self, group: &str) -> Result<(), RetryAfter> {
        self.snapshot
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    pub fn check_heartbeat(&self, group: &str) -> Result<(), RetryAfter> {
        self.heartbeat
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    pub fn check_group_registration(&self, ip: IpAddr) -> Result<(), RetryAfter> {
        self.groups.check_key(&ip).map_err(retry_after)
    }

    pub fn cleanup(&self) {
        let (gw, gwh, pg) = (
            self.gateway.get(),
            self.gateway_hourly.get(),
            self.per_group.get(),
        );
        for l in [
            &*pg,
            &self.presence,
            &self.presence_offline,
            &self.messages,
            &self.commands,
            &gw[0],
            &gw[1],
            &gwh[0],
            &gwh[1],
            &self.gateway_rebind,
            &self.activity,
            &self.snapshot,
            &self.heartbeat,
        ] {
            l.retain_recent();
            l.shrink_to_fit();
        }
        for l in [&self.groups, &self.fallback_attach] {
            l.retain_recent();
            l.shrink_to_fit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    #[test]
    fn ipv6_keyed_by_slash_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
        assert_ne!(ip_key(a), ip_key(c));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(ip_key(mapped), "192.0.2.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn expiring_set_ttl_and_cap() {
        let mut s = ExpiringSet::new(Duration::from_secs(10), 2);
        assert!(s.insert_if_absent("a", 0));
        assert!(!s.insert_if_absent("a", 5));
        assert!(s.insert_if_absent("a", 10), "expired after ttl");
        assert!(s.insert_if_absent("b", 11));
        assert!(s.insert_if_absent("c", 12));
        assert_eq!(s.len(), 2, "cap evicts oldest");
        assert!(s.insert_if_absent("a", 12), "a was evicted");
        s.remove(&"a");
        assert!(s.insert_if_absent("a", 13));
        s.purge(100);
        assert!(s.is_empty());
    }

    #[test]
    fn ban_after_threshold() {
        let bans = AuthBans::new(3, Duration::from_secs(60), Duration::from_secs(100));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(!bans.record_failure(ip, 0));
        assert!(!bans.record_failure(ip, 1));
        assert_eq!(bans.banned_for(ip, 2), None);
        assert!(bans.record_failure(ip, 2));
        assert_eq!(bans.banned_for(ip, 2), Some(100));
        assert_eq!(bans.banned_for(ip, 101), Some(1));
        assert_eq!(bans.banned_for(ip, 102), None);
        bans.cleanup(1000);
        assert!(bans.is_empty());
    }

    #[test]
    fn active_bans_and_unban() {
        let bans = AuthBans::new(1, Duration::from_secs(60), Duration::from_secs(100));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        bans.record_failure(a, 0);
        bans.record_failure(b, 50);
        assert_eq!(bans.active(60), vec![(b, 90), (a, 40)], "longest first");
        assert!(bans.unban(a, 60));
        assert!(!bans.unban(a, 60), "already lifted");
        assert_eq!(bans.banned_for(a, 60), None);
        assert_eq!(bans.active(200), vec![], "expired");
        assert!(!bans.unban(b, 200), "expired ban is not lifted");
    }

    #[test]
    fn live_limiters_are_replaced_without_restart() {
        let r = |p, b| Rate {
            per_sec: nz(p),
            burst: nz(b),
        };
        let limits = Limits {
            global: r(100, 100),
            per_ip: r(1, 1),
            per_secret: r(1, 1),
            ban_threshold: 10,
            ban_window: Duration::from_secs(900),
            ban_duration: Duration::from_secs(900),
            anon_global: r(100, 100),
            pre_auth: r(100, 100),
            abuse: AbuseRule::default(),
            replay_cap: 10,
        };
        let rl = RateLimits::new(&limits, 0);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(rl.check_ip(ip).is_ok());
        assert!(rl.check_ip(ip).is_err());
        rl.set_per_ip(r(1, 3));
        for _ in 0..3 {
            assert!(rl.check_ip(ip).is_ok(), "new bucket, burst 3");
        }
        assert!(rl.check_ip(ip).is_err());
        rl.set_global(r(1, 1));
        assert!(rl.check_global().is_ok());
        assert!(rl.check_global().is_err());

        let c = crate::config::Config::from_lookup(|k| match k {
            "APNS_MODE" => Some("mock".into()),
            "RATE_V2_GATEWAY_BURST" => Some("1".into()),
            _ => None,
        })
        .unwrap();
        let v2 = V2Limits::new(&c.v2);
        assert!(v2.check_gateway("g", false).is_ok());
        assert!(v2.check_gateway("g", false).is_err());
        assert!(v2.check_gateway("g", true).is_ok(), "licensed: burst 2");
        v2.set_gateway(r(1, 5));
        for _ in 0..5 {
            assert!(v2.check_gateway("g", false).is_ok());
        }
        assert!(v2.check_gateway("g", false).is_err());
        v2.set_gateway_hourly(HourlyRate {
            per_hour: nz(1),
            burst: nz(1),
        });
        assert!(v2.check_gateway("h", false).is_ok());
        assert!(v2.check_gateway("h", false).is_err(), "hourly bucket");
        v2.set_gateway_global(r(1, 1));
        assert!(v2.check_gateway_global().is_ok());
        assert!(v2.check_gateway_global().is_err());
    }

    #[test]
    fn expiring_set_try_insert_fails_closed() {
        let mut s = ExpiringSet::new(Duration::from_secs(10), 2);
        assert_eq!(s.try_insert("a", 0), Ok(true));
        assert_eq!(s.try_insert("a", 1), Ok(false));
        assert_eq!(s.try_insert("b", 1), Ok(true));
        assert_eq!(
            s.try_insert("c", 2),
            Err(SetFull),
            "nothing live is evicted"
        );
        assert_eq!(s.try_insert("a", 3), Ok(false), "a still remembered");
        assert_eq!(s.try_insert("c", 10), Ok(true), "a expired, room again");
    }

    /// Lead #5: sustained rate-limited answers ban the IP like auth failures.
    #[test]
    fn abuse_bans_after_threshold_within_window() {
        let rule = AbuseRule {
            threshold: 100,
            window: 60,
            duration: 900,
        };
        let bans =
            AuthBans::with_abuse(10, Duration::from_secs(900), Duration::from_secs(900), rule);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        for i in 0..99 {
            assert!(!bans.record_abuse(ip, i / 2));
        }
        assert_eq!(bans.banned_for(ip, 50), None);
        assert!(bans.record_abuse(ip, 50), "100th within 60 s");
        assert_eq!(bans.banned_for(ip, 50), Some(900));
        assert!(!bans.record_abuse(ip, 51), "already banned");
        // Spread out over more than the window: no ban.
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        for i in 0..200 {
            assert!(!bans.record_abuse(other, i * 2), "{i}");
        }
        // Auth-failure counting is separate.
        assert!(!bans.record_failure(other, 400));
        bans.cleanup(10_000);
        assert!(bans.is_empty());
    }

    #[test]
    fn group_presence_and_fallback_buckets() {
        let c = crate::config::Config::from_lookup(|k| match k {
            "APNS_MODE" => Some("mock".into()),
            "RATE_GROUP_BURST" => Some("2".into()),
            _ => None,
        })
        .unwrap();
        let v2 = V2Limits::new(&c.v2);
        assert!(v2.check_group("g").is_ok());
        assert!(v2.check_group("g").is_ok());
        assert!(v2.check_group("g").is_err());
        assert!(v2.check_group("h").is_ok(), "per group");
        v2.set_group(Rate {
            per_sec: nz(1),
            burst: nz(3),
        });
        assert!(v2.check_group("g").is_ok(), "replaced: full bucket");
        for _ in 0..6 {
            assert!(v2.check_presence("g").is_ok());
        }
        assert!(v2.check_presence("g").is_err(), "6 per hour");
        for _ in 0..12 {
            assert!(v2.check_presence_offline("g").is_ok(), "own bucket");
        }
        assert!(v2.check_presence_offline("g").is_err(), "12 per hour");
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..FALLBACK_ATTACHES_PER_DAY {
            assert!(v2.check_fallback_attach(ip).is_ok());
        }
        assert!(v2.check_fallback_attach(ip).is_err());
        let rl = RateLimits::new(&c.limits, 0);
        for _ in 0..60 {
            assert!(rl.check_anon().is_ok());
        }
        assert!(rl.check_anon().is_err(), "anonymous burst 60");
        assert!(
            rl.check_global().is_ok(),
            "the authenticated bucket is separate"
        );
    }

    #[test]
    fn ban_window_resets() {
        let bans = AuthBans::new(3, Duration::from_secs(60), Duration::from_secs(100));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        bans.record_failure(ip, 0);
        bans.record_failure(ip, 1);
        assert!(
            !bans.record_failure(ip, 61),
            "old failures fell out of the window"
        );
        assert_eq!(bans.banned_for(ip, 61), None);
    }

    #[test]
    fn rate_limits() {
        let r = Rate {
            per_sec: nz(1),
            burst: nz(2),
        };
        let limits = Limits {
            global: Rate {
                per_sec: nz(100),
                burst: nz(100),
            },
            per_ip: r,
            per_secret: r,
            ban_threshold: 10,
            ban_window: Duration::from_secs(900),
            ban_duration: Duration::from_secs(900),
            anon_global: r,
            pre_auth: r,
            abuse: AbuseRule::default(),
            replay_cap: 10,
        };
        let rl = RateLimits::new(&limits, 1);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(rl.check_ip(ip).is_ok());
        assert!(rl.check_ip(ip).is_ok());
        let ra = rl.check_ip(ip).unwrap_err();
        assert!(ra.0 >= 1);
        assert!(rl.check_ip(other).is_ok(), "per-IP buckets are independent");
        assert!(rl.check_secret(0).is_ok());
        assert!(rl.check_secret(0).is_ok());
        assert!(rl.check_secret(0).is_err());
        assert!(rl.check_global().is_ok());
        assert_eq!(rl.tracked_ips(), 2);
    }
}
