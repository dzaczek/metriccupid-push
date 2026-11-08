//! Abuse protection: rate limits (governor), auth-failure bans, and a bounded
//! expiring set used for replay protection and dedup.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
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

#[derive(Debug, Clone, Copy)]
struct FailureEntry {
    window_start: u64,
    failures: u32,
    banned_until: u64,
}

/// Bans an IP for `duration` after `threshold` auth failures within `window`.
pub struct AuthBans {
    threshold: u32,
    window: u64,
    duration: u64,
    map: Mutex<HashMap<IpAddr, FailureEntry>>,
}

impl AuthBans {
    pub fn new(threshold: u32, window: Duration, duration: Duration) -> Self {
        Self {
            threshold,
            window: window.as_secs(),
            duration: duration.as_secs(),
            map: Mutex::new(HashMap::new()),
        }
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
        if map.len() >= MAX_BAN_ENTRIES && !map.contains_key(&key) {
            Self::cleanup_locked(&mut map, now, self.window);
            if map.len() >= MAX_BAN_ENTRIES {
                // Map full of live entries: stop tracking new IPs rather than
                // grow without bound. Rate limits still apply.
                return false;
            }
        }
        let e = map.entry(key).or_insert(FailureEntry {
            window_start: now,
            failures: 0,
            banned_until: 0,
        });
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
        Self::cleanup_locked(&mut map, now, self.window);
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn cleanup_locked(map: &mut HashMap<IpAddr, FailureEntry>, now: u64, window: u64) {
        map.retain(|_, e| e.banned_until > now || now.saturating_sub(e.window_start) < window);
        map.shrink_to_fit();
    }
}

fn quota(r: Rate) -> Quota {
    Quota::per_second(r.per_sec).allow_burst(r.burst)
}

/// Global, per-IP and per-secret token buckets.
pub struct RateLimits {
    global: DefaultDirectRateLimiter,
    per_ip: DefaultKeyedRateLimiter<IpAddr>,
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
            global: RateLimiter::direct(quota(limits.global)),
            per_ip: RateLimiter::keyed(quota(limits.per_ip)),
            per_secret: (0..secret_count)
                .map(|_| RateLimiter::direct(quota(limits.per_secret)))
                .collect(),
        }
    }

    pub fn check_ip(&self, key: IpAddr) -> Result<(), RetryAfter> {
        self.per_ip.check_key(&key).map_err(retry_after)
    }

    pub fn check_global(&self) -> Result<(), RetryAfter> {
        self.global.check().map_err(retry_after)
    }

    pub fn check_secret(&self, index: usize) -> Result<(), RetryAfter> {
        match self.per_secret.get(index) {
            Some(l) => l.check().map_err(retry_after),
            None => Ok(()),
        }
    }

    /// Drop per-IP buckets that are back to full (equivalent to unseen).
    pub fn cleanup(&self) {
        self.per_ip.retain_recent();
        self.per_ip.shrink_to_fit();
    }

    pub fn tracked_ips(&self) -> usize {
        self.per_ip.len()
    }
}

/// v2 limits: per-group buckets for messages, commands and gateway pushes,
/// and a per-IP bucket for group registration.
pub struct V2Limits {
    messages: DefaultKeyedRateLimiter<String>,
    commands: DefaultKeyedRateLimiter<String>,
    gateway: DefaultKeyedRateLimiter<String>,
    groups: DefaultKeyedRateLimiter<IpAddr>,
}

fn hourly(r: HourlyRate) -> Quota {
    Quota::per_hour(r.per_hour).allow_burst(r.burst)
}

impl V2Limits {
    pub fn new(c: &V2Config) -> Self {
        Self {
            messages: RateLimiter::keyed(quota(c.rate_messages)),
            commands: RateLimiter::keyed(quota(c.rate_commands)),
            gateway: RateLimiter::keyed(quota(c.rate_gateway)),
            groups: RateLimiter::keyed(hourly(c.rate_groups)),
        }
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

    pub fn check_gateway(&self, group: &str) -> Result<(), RetryAfter> {
        self.gateway
            .check_key(&group.to_string())
            .map_err(retry_after)
    }

    pub fn check_group_registration(&self, ip: IpAddr) -> Result<(), RetryAfter> {
        self.groups.check_key(&ip).map_err(retry_after)
    }

    pub fn cleanup(&self) {
        for l in [&self.messages, &self.commands, &self.gateway] {
            l.retain_recent();
            l.shrink_to_fit();
        }
        self.groups.retain_recent();
        self.groups.shrink_to_fit();
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
