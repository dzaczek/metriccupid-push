//! Admin authentication primitives: base32, TOTP (RFC 6238), argon2id
//! password check, server-side sessions with CSRF tokens, login lockout.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Duration;

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::limits::{ip_key, AuthBans};

// ---------------------------------------------------------------- base32 ---

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, upper case, no padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decode base32; case-insensitive, spaces and `=` padding ignored.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !matches!(c, b' ' | b'=' | b'-')) {
        let v = B32.iter().position(|&x| x == c.to_ascii_uppercase())? as u32;
        buf = ((buf << 5) | v) & 0xFFFF;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// ------------------------------------------------------------------ TOTP ---

pub const TOTP_STEP: u64 = 30;
pub const TOTP_DIGITS: u32 = 6;

/// HOTP (RFC 4226) with HMAC-SHA-1 for counter `step`, `digits` long.
pub fn hotp(secret: &[u8], step: u64, digits: u32) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let h = tag.as_ref();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    let code = bin % 10u32.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

/// The 6-digit TOTP code at Unix time `now`.
pub fn totp(secret: &[u8], now: u64) -> String {
    hotp(secret, now / TOTP_STEP, TOTP_DIGITS)
}

/// The time step `code` matches at `now` (±1 step), compared in constant time.
pub fn totp_match(secret: &[u8], code: &str, now: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let step = now / TOTP_STEP;
    let mut found = None;
    // Check every candidate so timing does not depend on which one matched.
    for s in [step.saturating_sub(1), step, step + 1] {
        let ok: bool = hotp(secret, s, TOTP_DIGITS)
            .as_bytes()
            .ct_eq(code.as_bytes())
            .into();
        if ok && found.is_none() {
            found = Some(s);
        }
    }
    found
}

/// `otpauth://` URI for authenticator apps.
pub fn otpauth_uri(issuer: &str, user: &str, secret_b32: &str) -> String {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    format!(
        "otpauth://totp/{}:{}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}",
        enc(issuer),
        enc(user),
        enc(issuer)
    )
}

// -------------------------------------------------------------- password ---

/// Verify `password` against an argon2id PHC string (CPU and memory heavy:
/// call it on the blocking pool).
pub fn verify_password(phc: &str, password: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(h) => Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok(),
        Err(_) => false,
    }
}

/// Constant-time string equality that does not leak the length either.
pub fn ct_str_eq(a: &str, b: &str) -> bool {
    let (ha, hb) = (Sha256::digest(a.as_bytes()), Sha256::digest(b.as_bytes()));
    ha.ct_eq(&hb).into()
}

/// 32 random bytes, lowercase hex (256-bit token).
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    SystemRandom::new()
        .fill(&mut b)
        .expect("system RNG is available");
    hex::encode(b)
}

// -------------------------------------------------------------- sessions ---

/// Pre-login sessions (carry only the login form's CSRF token) live this long.
pub const PRE_SESSION_SECS: u64 = 600;
/// Max sessions held in memory (logged-in and pre-login together).
pub const MAX_SESSIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub csrf: String,
    pub authed: bool,
    pub created: u64,
    pub expires: u64,
}

/// In-memory sessions keyed by the cookie token. Lost on restart (everyone
/// logs in again), which is fine for a single admin.
pub struct Sessions {
    ttl: u64,
    map: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl: ttl_secs,
            map: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn insert(&self, s: Session, now: u64) -> String {
        let mut map = self.lock();
        map.retain(|_, s| s.expires > now);
        while map.len() >= MAX_SESSIONS {
            // Evict pre-login sessions first, then the oldest.
            let victim = map
                .iter()
                .min_by_key(|(_, s)| (s.authed, s.created))
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => map.remove(&k),
                None => break,
            };
        }
        let token = random_token();
        map.insert(token.clone(), s);
        token
    }

    /// A pre-login session for the login form. Returns (cookie token, csrf).
    pub fn create_pre(&self, now: u64) -> (String, String) {
        let csrf = random_token();
        let token = self.insert(
            Session {
                csrf: csrf.clone(),
                authed: false,
                created: now,
                expires: now + PRE_SESSION_SECS,
            },
            now,
        );
        (token, csrf)
    }

    /// A new logged-in session (a fresh token: no session fixation).
    pub fn create_authed(&self, now: u64) -> String {
        self.insert(
            Session {
                csrf: random_token(),
                authed: true,
                created: now,
                expires: now + self.ttl,
            },
            now,
        )
    }

    /// The live session for `token`, if any.
    pub fn get(&self, token: &str, now: u64) -> Option<Session> {
        let mut map = self.lock();
        match map.get(token) {
            Some(s) if s.expires > now => Some(s.clone()),
            Some(_) => {
                map.remove(token);
                None
            }
            None => None,
        }
    }

    pub fn remove(&self, token: &str) {
        self.lock().remove(token);
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn cleanup(&self, now: u64) {
        self.lock().retain(|_, s| s.expires > now);
    }
}

/// Constant-time CSRF check.
pub fn csrf_ok(session: &Session, submitted: &str) -> bool {
    !submitted.is_empty() && ct_str_eq(&session.csrf, submitted)
}

// --------------------------------------------------------------- lockout ---

pub const LOCKOUT_WINDOW: Duration = Duration::from_secs(900);
pub const LOCKOUT_DURATION: Duration = Duration::from_secs(900);
pub const LOCKOUT_PER_IP: u32 = 5;
pub const LOCKOUT_GLOBAL: u32 = 20;

/// Login brute-force protection: 5 failures per IP (IPv6 /64) in 15 min, or
/// 20 in total, lock logins for 15 min.
pub struct Lockout {
    per_ip: AuthBans,
    global: AuthBans,
}

const GLOBAL_KEY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

impl Default for Lockout {
    fn default() -> Self {
        Self {
            per_ip: AuthBans::new(LOCKOUT_PER_IP, LOCKOUT_WINDOW, LOCKOUT_DURATION),
            global: AuthBans::new(LOCKOUT_GLOBAL, LOCKOUT_WINDOW, LOCKOUT_DURATION),
        }
    }
}

impl Lockout {
    /// Seconds left if logins from `ip` are locked.
    pub fn locked_for(&self, ip: IpAddr, now: u64) -> Option<u64> {
        self.per_ip
            .banned_for(ip_key(ip), now)
            .or_else(|| self.global.banned_for(GLOBAL_KEY, now))
    }

    /// Record a failure; `true` if it started a lockout.
    pub fn failure(&self, ip: IpAddr, now: u64) -> bool {
        let a = self.per_ip.record_failure(ip_key(ip), now);
        let b = self.global.record_failure(GLOBAL_KEY, now);
        a || b
    }

    pub fn cleanup(&self, now: u64) {
        self.per_ip.cleanup(now);
        self.global.cleanup(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip_and_rfc4648_vectors() {
        for (raw, enc) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(raw.as_bytes()), enc);
            assert_eq!(base32_decode(enc).unwrap(), raw.as_bytes());
        }
        assert_eq!(base32_decode("mzxw 6ytb oi==").unwrap(), b"foobar");
        assert!(base32_decode("MZ1W").is_none(), "1 is not base32");
    }

    /// RFC 6238 appendix B, SHA-1 (8 digits there; 6 digits are the last 6).
    #[test]
    fn totp_rfc6238_vectors() {
        let secret = b"12345678901234567890";
        for (t, code8) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(hotp(secret, t / 30, 8), code8, "t={t}");
            assert_eq!(totp(secret, t), &code8[2..], "t={t}");
        }
    }

    #[test]
    fn totp_window_is_plus_minus_one_step() {
        let secret = b"12345678901234567890";
        let now = 1_111_111_111;
        let step = now / 30;
        let code = totp(secret, now);
        assert_eq!(totp_match(secret, &code, now), Some(step));
        assert_eq!(totp_match(secret, &code, now + 30), Some(step));
        assert_eq!(totp_match(secret, &code, now - 30), Some(step));
        assert_eq!(totp_match(secret, &code, now + 60), None);
        assert_eq!(totp_match(secret, "12345", now), None);
        assert_eq!(totp_match(secret, "abcdef", now), None);
    }

    #[test]
    fn otpauth_uri_format() {
        let u = otpauth_uri("MetricCupid Push", "admin", "JBSWY3DP");
        assert_eq!(
            u,
            "otpauth://totp/MetricCupid%20Push:admin?secret=JBSWY3DP&issuer=MetricCupid%20Push&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn argon2_verify() {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::encode_b64(&[7u8; 16]).unwrap();
        let params = argon2::Params::new(8, 1, 1, None).unwrap();
        let a = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let phc = a
            .hash_password(b"correct horse", &salt)
            .unwrap()
            .to_string();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password(&phc, "correct horse"));
        assert!(!verify_password(&phc, "correct horsE"));
        assert!(!verify_password("not a hash", "correct horse"));
    }

    #[test]
    fn sessions_expire_and_rotate() {
        let s = Sessions::new(3600);
        let (pre, csrf) = s.create_pre(100);
        let pre_s = s.get(&pre, 100).unwrap();
        assert!(!pre_s.authed);
        assert!(csrf_ok(&pre_s, &csrf));
        assert!(!csrf_ok(&pre_s, ""));
        assert!(!csrf_ok(&pre_s, &random_token()));
        assert!(s.get(&pre, 100 + PRE_SESSION_SECS).is_none(), "pre expires");

        let t = s.create_authed(1000);
        assert_ne!(t, pre);
        assert!(s.get(&t, 1000 + 3599).unwrap().authed);
        assert!(s.get(&t, 1000 + 3600).is_none(), "absolute expiry");
        assert!(s.get(&t, 1000).is_none(), "expired session removed");
        let t2 = s.create_authed(1000);
        s.remove(&t2);
        assert!(s.get(&t2, 1000).is_none(), "logout");
        assert!(s.get("nope", 1000).is_none());
    }

    #[test]
    fn sessions_are_bounded() {
        let s = Sessions::new(3600);
        let keep = s.create_authed(1);
        for i in 0..(MAX_SESSIONS * 2) {
            s.create_pre(2 + i as u64);
        }
        assert!(s.len() <= MAX_SESSIONS);
        assert!(
            s.get(&keep, 10).is_some(),
            "logged-in session outlives pre-login ones"
        );
    }

    #[test]
    fn lockout_per_ip_and_global() {
        let l = Lockout::default();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..LOCKOUT_PER_IP - 1 {
            assert!(!l.failure(a, 100));
        }
        assert!(l.locked_for(a, 100).is_none());
        assert!(l.failure(a, 100));
        assert_eq!(l.locked_for(a, 100), Some(900));
        assert!(l.locked_for(b, 100).is_none(), "other IP unaffected");
        assert!(l.locked_for(a, 1000).is_none(), "lockout ends");

        // Many IPs, few failures each: the global limit trips.
        let g = Lockout::default();
        for i in 0..LOCKOUT_GLOBAL {
            g.failure(IpAddr::from([198, 51, 100, i as u8]), 10);
        }
        assert!(g.locked_for(b, 10).is_some());
    }

    #[test]
    fn ct_eq_strings() {
        assert!(ct_str_eq("admin", "admin"));
        assert!(!ct_str_eq("admin", "admin2"));
        assert!(!ct_str_eq("", "x"));
    }
}
