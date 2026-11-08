//! HMAC request signing.
//!
//! v1: signature = lowercase_hex(HMAC-SHA256(secret, "{ts}\n{METHOD}\n{path}\n{raw body}"))
//! v2: signature = lowercase_hex(HMAC-SHA256(auth_key,
//!         "{ts}\n{METHOD}\n{target}\n{group_id}\n{device_id}\n{raw body}"))
//! sent as `X-MC-Timestamp: <unix seconds>` and `X-MC-Signature: <hex>`.

use std::sync::Mutex;
use std::time::Duration;

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config::Secret;
use crate::limits::ExpiringSet;

pub const TIMESTAMP_HEADER: &str = "x-mc-timestamp";
pub const SIGNATURE_HEADER: &str = "x-mc-signature";
/// Max allowed |now - ts|.
pub const MAX_SKEW_SECS: u64 = 300;
/// A signature stays valid for at most 2 * MAX_SKEW_SECS, so remembering it
/// that long is enough to stop every replay.
pub const REPLAY_TTL: Duration = Duration::from_secs(2 * MAX_SKEW_SECS);
pub const REPLAY_CAP: usize = 100_000;

type HmacSha256 = Hmac<Sha256>;

fn mac(secret: &[u8], ts: &str, method: &str, path: &str, body: &[u8]) -> [u8; 32] {
    // HMAC accepts keys of any length; this cannot fail.
    let mut m = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    m.update(ts.as_bytes());
    m.update(b"\n");
    m.update(method.as_bytes());
    m.update(b"\n");
    m.update(path.as_bytes());
    m.update(b"\n");
    m.update(body);
    m.finalize().into_bytes().into()
}

fn mac_v2(
    key: &[u8],
    ts: &str,
    method: &str,
    target: &str,
    group: &str,
    device: &str,
    body: &[u8],
) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    for part in [ts, method, target, group, device] {
        m.update(part.as_bytes());
        m.update(b"\n");
    }
    m.update(body);
    m.finalize().into_bytes().into()
}

/// v2 signature (PROTOCOL.md): binds the group and device ids, so identical
/// requests from two devices never share a signature. `device` is empty for
/// requests without `X-MC-Device` (gateway push).
pub fn sign_v2(
    key: &[u8],
    ts: &str,
    method: &str,
    target: &str,
    group: &str,
    device: &str,
    body: &[u8],
) -> String {
    hex::encode(mac_v2(key, ts, method, target, group, device, body))
}

/// Compute the lowercase hex signature for a request.
pub fn sign(secret: &[u8], ts: &str, method: &str, path: &str, body: &[u8]) -> String {
    hex::encode(mac(secret, ts, method, path, body))
}

/// Why auth failed. Only used for logs; clients always get a generic 401.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    MissingHeaders,
    BadTimestamp,
    StaleTimestamp,
    BadSignature,
    Replay,
}

impl AuthError {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthError::MissingHeaders => "missing_headers",
            AuthError::BadTimestamp => "bad_timestamp",
            AuthError::StaleTimestamp => "stale_timestamp",
            AuthError::BadSignature => "bad_signature",
            AuthError::Replay => "replay",
        }
    }
}

pub struct Authenticator {
    secrets: Vec<Secret>,
    replay: Mutex<ExpiringSet<[u8; 32]>>,
}

impl Authenticator {
    pub fn new(secrets: Vec<Secret>) -> Self {
        Self {
            secrets,
            replay: Mutex::new(ExpiringSet::new(REPLAY_TTL, REPLAY_CAP)),
        }
    }

    /// Verify a request; on success returns the index of the matching secret.
    pub fn verify(
        &self,
        now: u64,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<usize, AuthError> {
        let (ts, provided) = parse_headers(now, headers)?;

        // Check every secret (no early exit) with a constant-time compare.
        let mut matched = None;
        for (i, secret) in self.secrets.iter().enumerate() {
            let expected = mac(secret.as_bytes(), ts, method, path, body);
            if bool::from(expected.ct_eq(&provided)) && matched.is_none() {
                matched = Some(i);
            }
        }
        let index = matched.ok_or(AuthError::BadSignature)?;
        self.remember(provided, now)?;
        Ok(index)
    }

    /// Verify a v2 request signed with the group's `auth_key`.
    /// Shares the replay cache with [`Authenticator::verify`].
    #[allow(clippy::too_many_arguments)]
    pub fn verify_v2(
        &self,
        now: u64,
        key: &[u8],
        method: &str,
        target: &str,
        group: &str,
        device: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<(), AuthError> {
        let (ts, provided) = parse_headers(now, headers)?;
        let expected = mac_v2(key, ts, method, target, group, device, body);
        if !bool::from(expected.ct_eq(&provided)) {
            return Err(AuthError::BadSignature);
        }
        self.remember(provided, now)
    }

    /// Only remember signatures that verified, so unauthenticated traffic
    /// cannot fill the cache.
    fn remember(&self, sig: [u8; 32], now: u64) -> Result<(), AuthError> {
        let mut replay = self.replay.lock().unwrap_or_else(|e| e.into_inner());
        if !replay.insert_if_absent(sig, now) {
            return Err(AuthError::Replay);
        }
        Ok(())
    }

    pub fn cleanup(&self, now: u64) {
        self.replay
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .purge(now);
    }
}

/// Check presence and format of the timestamp and signature headers.
fn parse_headers(now: u64, headers: &HeaderMap) -> Result<(&str, [u8; 32]), AuthError> {
    let ts = headers.get(TIMESTAMP_HEADER).and_then(|v| v.to_str().ok());
    let sig = headers.get(SIGNATURE_HEADER).and_then(|v| v.to_str().ok());
    let (Some(ts), Some(sig)) = (ts, sig) else {
        return Err(AuthError::MissingHeaders);
    };

    if ts.is_empty() || ts.len() > 12 || !ts.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AuthError::BadTimestamp);
    }
    let ts_num: u64 = ts.parse().map_err(|_| AuthError::BadTimestamp)?;
    if now.abs_diff(ts_num) > MAX_SKEW_SECS {
        return Err(AuthError::StaleTimestamp);
    }

    if sig.len() != 64 || !sig.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(AuthError::BadSignature);
    }
    let mut provided = [0u8; 32];
    hex::decode_to_slice(sig, &mut provided).map_err(|_| AuthError::BadSignature)?;
    Ok((ts, provided))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::http::HeaderValue;

    const SECRET: &str = "test-secret-0123456789abcdef0123456789";
    const BODY: &str = r#"{"title":"t","message":"m","priority":0}"#;
    const VECTOR: &str = "defa640d01d4dacbfb3044a69adaee459908302676876b7ad847840e49ea89e1";

    /// Shared test vector: the MetricCupid Swift client must produce the same value.
    #[test]
    fn shared_test_vector() {
        assert_eq!(
            sign(
                SECRET.as_bytes(),
                "1700000000",
                "POST",
                "/v1/notify",
                BODY.as_bytes()
            ),
            VECTOR
        );
    }

    fn secrets(list: &str) -> Vec<Secret> {
        Config::from_lookup(|k| match k {
            "PUSHOVER_APP_TOKEN" | "PUSHOVER_USER_KEY" => Some("x".into()),
            "RELAY_SECRETS" => Some(list.into()),
            _ => None,
        })
        .unwrap()
        .secrets
    }

    fn headers(ts: &str, sig: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(TIMESTAMP_HEADER, HeaderValue::from_str(ts).unwrap());
        h.insert(SIGNATURE_HEADER, HeaderValue::from_str(sig).unwrap());
        h
    }

    fn verify(a: &Authenticator, now: u64, h: &HeaderMap) -> Result<usize, AuthError> {
        a.verify(now, "POST", "/v1/notify", h, BODY.as_bytes())
    }

    #[test]
    fn accepts_vector_then_rejects_replay() {
        let a = Authenticator::new(secrets(SECRET));
        let h = headers("1700000000", VECTOR);
        assert_eq!(verify(&a, 1_700_000_000, &h), Ok(0));
        assert_eq!(verify(&a, 1_700_000_010, &h), Err(AuthError::Replay));
    }

    #[test]
    fn second_secret_for_rotation() {
        let a = Authenticator::new(secrets(&format!(
            "new-secret-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,{SECRET}"
        )));
        assert_eq!(
            verify(&a, 1_700_000_000, &headers("1700000000", VECTOR)),
            Ok(1)
        );
    }

    #[test]
    fn rejections() {
        let a = Authenticator::new(secrets(SECRET));
        let now = 1_700_000_000;
        assert_eq!(
            verify(&a, now, &HeaderMap::new()),
            Err(AuthError::MissingHeaders)
        );
        assert_eq!(
            verify(&a, now, &headers("-5", VECTOR)),
            Err(AuthError::BadTimestamp)
        );
        assert_eq!(
            verify(&a, now, &headers("17e8", VECTOR)),
            Err(AuthError::BadTimestamp)
        );
        assert_eq!(
            verify(&a, now + 301, &headers("1700000000", VECTOR)),
            Err(AuthError::StaleTimestamp)
        );
        assert_eq!(
            verify(&a, now - 301, &headers("1700000000", VECTOR)),
            Err(AuthError::StaleTimestamp)
        );
        assert_eq!(
            verify(&a, now, &headers("1700000000", &VECTOR.to_uppercase())),
            Err(AuthError::BadSignature)
        );
        assert_eq!(
            verify(&a, now, &headers("1700000000", &"0".repeat(64))),
            Err(AuthError::BadSignature)
        );
        // Same signature, different body/path/method.
        let h = headers("1700000000", VECTOR);
        assert_eq!(
            a.verify(now, "POST", "/v1/notify", &h, b"{}"),
            Err(AuthError::BadSignature)
        );
        assert_eq!(
            a.verify(now, "POST", "/v1/other", &h, BODY.as_bytes()),
            Err(AuthError::BadSignature)
        );
        assert_eq!(
            a.verify(now, "PUT", "/v1/notify", &h, BODY.as_bytes()),
            Err(AuthError::BadSignature)
        );
        // Failures did not poison the replay cache.
        assert_eq!(verify(&a, now + 300, &h), Ok(0));
    }

    #[test]
    fn verify_v2_binds_group_and_device_and_shares_replay_cache() {
        let a = Authenticator::new(Vec::new());
        let key = [7u8; 32];
        let sig = sign_v2(&key, "1700000000", "GET", "/v2/stream", "g", "d1", b"");
        let h = headers("1700000000", &sig);
        let now = 1_700_000_000;
        let v =
            |k: &[u8], g: &str, d: &str| a.verify_v2(now, k, "GET", "/v2/stream", g, d, &h, b"");
        assert_eq!(v(&[8u8; 32], "g", "d1"), Err(AuthError::BadSignature));
        assert_eq!(
            v(&key, "g", "d2"),
            Err(AuthError::BadSignature),
            "device bound"
        );
        assert_eq!(
            v(&key, "h", "d1"),
            Err(AuthError::BadSignature),
            "group bound"
        );
        assert_eq!(v(&key, "g", "d1"), Ok(()));
        assert_eq!(v(&key, "g", "d1"), Err(AuthError::Replay));
        // Another device's identical request has a different signature.
        assert_ne!(
            sig,
            sign_v2(&key, "1700000000", "GET", "/v2/stream", "g", "d2", b"")
        );
    }
}
