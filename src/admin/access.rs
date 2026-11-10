//! Cloudflare Access JWT check for the admin panel (`ADMIN_CF_ACCESS_TEAM`,
//! `ADMIN_CF_ACCESS_AUD`), defence in depth behind the Access application.
//!
//! Per Cloudflare's "Validate JWTs" guide
//! (<https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/>):
//! the token arrives in the `Cf-Access-Jwt-Assertion` header (browsers also
//! carry it in the `CF_Authorization` cookie, which "is not guaranteed to be
//! passed", so the header wins); it is RS256, signed by a key published at
//! `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` (JWKS `keys`,
//! matched by `kid`; keys rotate every 6 weeks and the previous one stays
//! valid for 7 days, so keys are fetched, never hard-coded); `iss` must be
//! the team domain and `aud` the application's AUD tag. `exp` / `nbf` /
//! `iat` are checked here too, with 60 s leeway.
//!
//! Keys are cached in memory, refreshed hourly and on an unknown `kid`, with
//! at most one fetch per minute. No keys (fetch failed): every admin request
//! is refused. Tokens are never logged.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde::Deserialize;

use crate::config::CfAccessConfig;

pub const HEADER: &str = "cf-access-jwt-assertion";
pub const COOKIE: &str = "CF_Authorization";
pub const LEEWAY_SECS: u64 = 60;
/// Scheduled JWKS refresh.
pub const REFRESH_SECS: u64 = 3600;
/// At most one JWKS fetch per this many seconds (unknown `kid`, retries).
pub const MIN_FETCH_INTERVAL_SECS: u64 = 60;
const MAX_TOKEN_LEN: usize = 8 * 1024;
const MAX_JWKS_BYTES: usize = 64 * 1024;

/// Why a request was refused; the label goes to the security events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    Missing,
    Malformed,
    UnknownKey,
    Signature,
    Issuer,
    Audience,
    Expired,
    NotYetValid,
}

impl AccessError {
    pub fn label(self) -> &'static str {
        match self {
            Self::Missing => "cf_access_missing",
            Self::Malformed => "cf_access_malformed",
            Self::UnknownKey => "cf_access_unknown_key",
            Self::Signature => "cf_access_signature",
            Self::Issuer => "cf_access_issuer",
            Self::Audience => "cf_access_audience",
            Self::Expired => "cf_access_expired",
            Self::NotYetValid => "cf_access_not_yet_valid",
        }
    }
}

/// A verified Access token: only the e-mail is kept.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    pub email: Option<String>,
}

struct RsaKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

#[derive(Default)]
struct Keys {
    by_kid: HashMap<String, Arc<RsaKey>>,
    fetched_at: Option<u64>,
    last_attempt: Option<u64>,
}

pub struct AccessVerifier {
    issuer: String,
    auds: Vec<String>,
    certs_url: String,
    http: reqwest::Client,
    keys: RwLock<Keys>,
    /// One fetch at a time; waiters then see the fresh keys.
    fetch_gate: tokio::sync::Mutex<()>,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Aud {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    aud: Option<Aud>,
    iss: Option<String>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    kty: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

fn b64url(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// Big-endian integer without leading zero bytes, as ring expects.
fn unsigned(mut v: Vec<u8>) -> Vec<u8> {
    let zeros = v.iter().take_while(|b| **b == 0).count();
    v.drain(..zeros);
    v
}

fn parse_jwks(body: &[u8]) -> Result<HashMap<String, Arc<RsaKey>>, String> {
    let jwks: Jwks = serde_json::from_slice(body).map_err(|e| format!("invalid JWKS: {e}"))?;
    let mut out = HashMap::new();
    for k in jwks.keys {
        if k.kid.is_empty()
            || k.kty != "RSA"
            || k.alg.as_deref().is_some_and(|a| a != "RS256")
            || k.use_.as_deref().is_some_and(|u| u != "sig")
        {
            continue;
        }
        let (Some(n), Some(e)) = (b64url(&k.n), b64url(&k.e)) else {
            continue;
        };
        let (n, e) = (unsigned(n), unsigned(e));
        if n.is_empty() || e.is_empty() {
            continue;
        }
        out.insert(k.kid, Arc::new(RsaKey { n, e }));
    }
    if out.is_empty() {
        return Err("JWKS has no usable RS256 keys".into());
    }
    Ok(out)
}

/// The Access token of a request: header first, else the cookie.
pub fn token(h: &HeaderMap) -> Option<&str> {
    if let Some(v) = h.get(HEADER).and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v);
        }
    }
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, v)| *k == COOKIE && !v.is_empty())
        .map(|(_, v)| v)
}

impl AccessVerifier {
    pub fn new(cfg: &CfAccessConfig) -> Result<Self, String> {
        Self::with_certs_url(cfg, cfg.certs_url())
    }

    /// Keys from another URL (tests serve a mock JWKS); `iss` is unchanged.
    pub fn with_certs_url(cfg: &CfAccessConfig, certs_url: String) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("metriccupid-push/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("cannot build HTTP client: {e}"))?;
        Ok(Self {
            issuer: cfg.issuer(),
            auds: cfg.auds.clone(),
            certs_url,
            http,
            keys: RwLock::new(Keys::default()),
            fetch_gate: tokio::sync::Mutex::new(()),
        })
    }

    fn key(&self, kid: &str) -> Option<Arc<RsaKey>> {
        let k = self.keys.read().unwrap_or_else(|e| e.into_inner());
        k.by_kid.get(kid).cloned()
    }

    /// Number of cached keys.
    pub fn key_count(&self) -> usize {
        let k = self.keys.read().unwrap_or_else(|e| e.into_inner());
        k.by_kid.len()
    }

    /// Fetch the JWKS, at most once per `MIN_FETCH_INTERVAL_SECS`. With
    /// `due_only`, only when the keys are older than `REFRESH_SECS` (or
    /// missing). Returns `true` when keys were fetched. On failure the old
    /// keys stay in use.
    pub async fn refresh(&self, now: u64, due_only: bool) -> bool {
        let _gate = self.fetch_gate.lock().await;
        {
            let mut k = self.keys.write().unwrap_or_else(|e| e.into_inner());
            if due_only && k.fetched_at.is_some_and(|t| now < t + REFRESH_SECS) {
                return false;
            }
            if k.last_attempt
                .is_some_and(|t| now < t + MIN_FETCH_INTERVAL_SECS)
            {
                return false;
            }
            k.last_attempt = Some(now);
        }
        match self.fetch().await {
            Ok(keys) => {
                let n = keys.len();
                let mut k = self.keys.write().unwrap_or_else(|e| e.into_inner());
                k.by_kid = keys;
                k.fetched_at = Some(now);
                tracing::debug!(keys = n, "admin: Cloudflare Access keys refreshed");
                true
            }
            Err(e) => {
                tracing::error!(url = %self.certs_url, error = %e, "admin: cannot fetch Cloudflare Access keys");
                false
            }
        }
    }

    async fn fetch(&self) -> Result<HashMap<String, Arc<RsaKey>>, String> {
        let resp = self
            .http
            .get(&self.certs_url)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if body.len() > MAX_JWKS_BYTES {
            return Err("JWKS too large".into());
        }
        parse_jwks(&body)
    }

    /// Verify an Access token at `now` (unix seconds).
    pub async fn verify(&self, token: &str, now: u64) -> Result<Identity, AccessError> {
        use AccessError::*;
        if token.len() > MAX_TOKEN_LEN {
            return Err(Malformed);
        }
        let mut parts = token.split('.');
        let (Some(h64), Some(p64), Some(s64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Malformed);
        };
        let header: JwtHeader = b64url(h64)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(Malformed)?;
        if header.alg != "RS256" || header.kid.is_empty() {
            return Err(Malformed);
        }
        let sig = b64url(s64).ok_or(Malformed)?;
        let key = match self.key(&header.kid) {
            Some(k) => k,
            None => {
                // Rotation (or no keys yet): one rate-limited refresh.
                self.refresh(now, false).await;
                self.key(&header.kid).ok_or(UnknownKey)?
            }
        };
        let signing_input = &token[..h64.len() + 1 + p64.len()];
        RsaPublicKeyComponents {
            n: &key.n,
            e: &key.e,
        }
        .verify(&RSA_PKCS1_2048_8192_SHA256, signing_input.as_bytes(), &sig)
        .map_err(|_| Signature)?;

        let claims: Claims = b64url(p64)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(Malformed)?;
        if claims.iss.as_deref() != Some(self.issuer.as_str()) {
            return Err(Issuer);
        }
        let aud_ok = match &claims.aud {
            Some(Aud::One(a)) => self.auds.contains(a),
            Some(Aud::Many(v)) => v.iter().any(|a| self.auds.contains(a)),
            None => false,
        };
        if !aud_ok {
            return Err(Audience);
        }
        match claims.exp {
            Some(exp) if now < exp.saturating_add(LEEWAY_SECS) => {}
            _ => return Err(Expired),
        }
        let latest = now.saturating_add(LEEWAY_SECS);
        if claims.nbf.is_some_and(|t| t > latest) || claims.iat.is_some_and(|t| t > latest) {
            return Err(NotYetValid);
        }
        let email = claims
            .email
            .filter(|e| e.len() <= 254 && !e.is_empty() && !e.chars().any(char::is_control));
        Ok(Identity { email })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_header_wins_over_cookie() {
        let mut h = HeaderMap::new();
        assert_eq!(token(&h), None);
        h.insert(
            header::COOKIE,
            "a=1; CF_Authorization=cookie.tok.en; b=2".parse().unwrap(),
        );
        assert_eq!(token(&h), Some("cookie.tok.en"));
        h.insert(HEADER, "header.tok.en".parse().unwrap());
        assert_eq!(token(&h), Some("header.tok.en"));
    }

    #[test]
    fn jwks_skips_unusable_keys() {
        let body = br#"{"keys":[
            {"kid":"a","kty":"RSA","alg":"RS256","use":"sig","n":"AQAB","e":"AQAB"},
            {"kid":"b","kty":"EC","n":"AQAB","e":"AQAB"},
            {"kid":"c","kty":"RSA","alg":"RS512","n":"AQAB","e":"AQAB"},
            {"kty":"RSA","n":"AQAB","e":"AQAB"},
            {"kid":"d","kty":"RSA","n":"!!","e":"AQAB"}
        ],"public_cert":{},"public_certs":[]}"#;
        let k = parse_jwks(body).unwrap();
        assert_eq!(k.keys().collect::<Vec<_>>(), vec!["a"]);
        assert!(parse_jwks(br#"{"keys":[]}"#).is_err());
        assert!(parse_jwks(b"nope").is_err());
        assert_eq!(unsigned(vec![0, 0, 1, 0]), vec![1, 0]);
    }
}
