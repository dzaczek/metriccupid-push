//! Reference v2 client used by the tests and `examples/smoke.rs`: key
//! derivation, sealing and request signing exactly as PROTOCOL.md specifies.
#![allow(dead_code)]

pub mod licence;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const SALT: &[u8] = b"metriccupid-push-v2";

#[derive(Clone)]
pub struct Keys {
    pub enc: [u8; 32],
    pub auth: [u8; 32],
    pub collapse: [u8; 32],
}

pub fn derive(group_key: &[u8; 32]) -> Keys {
    let hk = Hkdf::<Sha256>::new(Some(SALT), group_key);
    let out = |info: &[u8]| {
        let mut k = [0u8; 32];
        hk.expand(info, &mut k)
            .expect("32 bytes is a valid HKDF length");
        k
    };
    Keys {
        enc: out(b"enc"),
        auth: out(b"auth"),
        collapse: out(b"collapse"),
    }
}

pub fn aad(group_id: &str, kind: &str, id: &str) -> String {
    format!("{group_id}|{kind}|{id}")
}

/// ChaCha20-Poly1305, combined format nonce(12) | ciphertext | tag(16), base64.
pub fn seal(enc: &[u8; 32], nonce: &[u8; 12], aad: &str, plaintext: &[u8]) -> String {
    let cipher = ChaCha20Poly1305::new(enc.into());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .expect("encryption cannot fail");
    let mut out = nonce.to_vec();
    out.extend(ct);
    STANDARD.encode(out)
}

pub fn open(enc: &[u8; 32], aad: &str, sealed: &str) -> Option<Vec<u8>> {
    let raw = STANDARD.decode(sealed).ok()?;
    if raw.len() < 28 {
        return None;
    }
    let (nonce, ct) = raw.split_at(12);
    ChaCha20Poly1305::new(enc.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: aad.as_bytes(),
            },
        )
        .ok()
}

pub fn collapse_id(collapse_key: &[u8; 32], alert_id: &str) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(collapse_key).unwrap();
    m.update(alert_id.as_bytes());
    URL_SAFE_NO_PAD.encode(&m.finalize().into_bytes()[..16])
}

pub fn id128(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode([seed; 16])
}

/// Signed-request client for one device of one group.
#[derive(Clone)]
pub struct Client {
    pub base: String,
    pub http: reqwest::Client,
    pub group_id: String,
    pub device_id: String,
    pub keys: Keys,
    pub now: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub nonce: Arc<AtomicU64>,
}

pub struct Resp {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub json: serde_json::Value,
}

impl Client {
    pub fn new(
        base: &str,
        group_id: &str,
        device_id: &str,
        keys: Keys,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            group_id: group_id.into(),
            device_id: device_id.into(),
            keys,
            now,
            nonce: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn as_device(&self, device_id: &str) -> Self {
        let mut c = self.clone();
        c.device_id = device_id.into();
        c
    }

    /// Headers for a signed request to `target` (path plus optional query).
    pub fn signed_headers(&self, method: &str, target: &str, body: &[u8]) -> Vec<(String, String)> {
        let ts = (self.now)().to_string();
        let sig = metriccupid_push::auth::sign_v2(
            &self.keys.auth,
            &ts,
            method,
            target,
            &self.group_id,
            &self.device_id,
            body,
        );
        vec![
            ("x-mc-timestamp".into(), ts),
            ("x-mc-signature".into(), sig),
            ("x-mc-group".into(), self.group_id.clone()),
            ("x-mc-device".into(), self.device_id.clone()),
        ]
    }

    /// GETs get a unique `n` query parameter so two identical polls in the
    /// same second do not collide in the replay cache (PROTOCOL.md).
    pub fn get_target(&self, path_and_query: &str) -> String {
        let n = self.nonce.fetch_add(1, Ordering::Relaxed);
        let sep = if path_and_query.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{path_and_query}{sep}n={n}")
    }

    pub async fn send(&self, method: &str, target: &str, body: &str) -> Resp {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut req = self
            .http
            .request(m, format!("{}{target}", self.base))
            .body(body.to_string());
        if !body.is_empty() {
            req = req.header("content-type", "application/json");
        }
        for (k, v) in self.signed_headers(method, target, body.as_bytes()) {
            req = req.header(k, v);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap();
        Resp {
            status,
            headers,
            json: serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
        }
    }

    pub async fn get(&self, path: &str) -> Resp {
        let t = self.get_target(path);
        self.send("GET", &t, "").await
    }

    pub async fn post(&self, path: &str, body: &serde_json::Value) -> Resp {
        self.send("POST", path, &body.to_string()).await
    }

    pub async fn create_group(&self) -> Resp {
        self.create_group_with(serde_json::json!({})).await
    }

    /// `POST /v2/groups` with extra fields (e.g. `licence`).
    pub async fn create_group_with(&self, extra: serde_json::Value) -> Resp {
        let mut body = serde_json::json!({
            "group_id": self.group_id,
            "auth_key": STANDARD.encode(self.keys.auth),
        });
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        let resp = self
            .http
            .post(format!("{}/v2/groups", self.base))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap();
        Resp {
            status,
            headers,
            json: serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
        }
    }

    pub async fn register(&self, kind: &str, name: &str, token: Option<&str>) -> Resp {
        let mut body = serde_json::json!({ "kind": kind, "name": name, "apns_env": "sandbox" });
        if let Some(t) = token {
            body["apns_token"] = serde_json::json!(t);
        }
        let path = format!("/v2/devices/{}", self.device_id);
        self.send("PUT", &path, &body.to_string()).await
    }

    /// Seal a v2 plaintext object for this group.
    pub fn seal_json(
        &self,
        kind: &str,
        id: &str,
        plaintext: &serde_json::Value,
        nonce: [u8; 12],
    ) -> String {
        seal(
            &self.keys.enc,
            &nonce,
            &aad(&self.group_id, kind, id),
            plaintext.to_string().as_bytes(),
        )
    }

    pub fn ws_url(&self) -> String {
        format!("{}/v2/stream", self.base.replacen("http", "ws", 1))
    }
}
