//! End-to-end tests: real TCP server + wiremock standing in for Pushover.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use metriccupid_push::auth::sign;
use metriccupid_push::client_ip::ClientIpResolver;
use metriccupid_push::config::Config;
use metriccupid_push::limits::Clock;
use metriccupid_push::{serve, AppState};
use serde_json::Value;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET: &str = "test-secret-0123456789abcdef0123456789";
const T0: u64 = 1_700_000_000;

struct TestClock(AtomicU64);

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Relay {
    _data: tempfile::TempDir,
    base: String,
    pushover: MockServer,
    clock: Arc<TestClock>,
    http: reqwest::Client,
}

async fn relay(overrides: &[(&str, &str)]) -> Relay {
    let pushover = MockServer::start().await;
    let data = tempfile::tempdir().unwrap();
    let mut env: HashMap<String, String> = HashMap::from([
        ("PUSHOVER_APP_TOKEN".into(), "apptoken123".into()),
        ("PUSHOVER_USER_KEY".into(), "userkey456".into()),
        ("RELAY_SECRETS".into(), SECRET.into()),
        (
            "PUSHOVER_API_URL".into(),
            format!("{}/1/messages.json", pushover.uri()),
        ),
        ("DATA_DIR".into(), data.path().display().to_string()),
    ]);
    for (k, v) in overrides {
        env.insert(k.to_string(), v.to_string());
    }
    let config = Config::from_lookup(|k| env.get(k).cloned()).expect("valid test config");
    let clock = Arc::new(TestClock(AtomicU64::new(T0)));
    let resolver = ClientIpResolver::from_config(&config.trust_proxy).await;
    let state = Arc::new(AppState::new(&config, resolver, clock.clone()).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, state, std::future::pending()));
    Relay {
        _data: data,
        base,
        pushover,
        clock,
        http: reqwest::Client::new(),
    }
}

async fn mock_ok(r: &Relay, expect: u64) {
    Mock::given(method("POST"))
        .and(path("/1/messages.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"status":1,"request":"abc"}"#))
        .expect(expect)
        .mount(&r.pushover)
        .await;
}

struct Resp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    json: Value,
}

impl Relay {
    async fn post_with(&self, body: &str, ts: u64, sig: Option<String>) -> Resp {
        let mut req = self
            .http
            .post(format!("{}/v1/notify", self.base))
            .header("content-type", "application/json")
            .header("x-mc-timestamp", ts.to_string())
            .body(body.to_string());
        if let Some(sig) = sig {
            req = req.header("x-mc-signature", sig);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap();
        Resp {
            status,
            headers,
            json: serde_json::from_str(&text).unwrap_or(Value::String(text)),
        }
    }

    async fn post(&self, body: &str) -> Resp {
        let ts = self.clock.now();
        let sig = sign(
            SECRET.as_bytes(),
            &ts.to_string(),
            "POST",
            "/v1/notify",
            body.as_bytes(),
        );
        self.post_with(body, ts, Some(sig)).await
    }

    async fn get(&self, p: &str) -> (u16, String) {
        let resp = self
            .http
            .get(format!("{}{p}", self.base))
            .send()
            .await
            .unwrap();
        (resp.status().as_u16(), resp.text().await.unwrap())
    }
}

#[tokio::test]
async fn valid_request_is_forwarded_with_form_fields() {
    let r = relay(&[]).await;
    Mock::given(method("POST"))
        .and(path("/1/messages.json"))
        .and(body_string_contains("token=apptoken123"))
        .and(body_string_contains("user=userkey456"))
        .and(body_string_contains("title=Disk+full"))
        .and(body_string_contains("message=web01%3A+%2Fvar+at+99%25"))
        .and(body_string_contains("priority=1"))
        .and(body_string_contains(
            "url=https%3A%2F%2Fmon.example%2Fh%2Fweb01",
        ))
        .and(body_string_contains("sound=siren"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"status":1}"#))
        .expect(1)
        .mount(&r.pushover)
        .await;
    let res = r
        .post(r#"{"title":"Disk full","message":"web01: /var at 99%","priority":1,"url":"https://mon.example/h/web01","sound":"siren"}"#)
        .await;
    assert_eq!(res.status, 200, "{:?}", res.json);
    assert_eq!(res.json["status"], "sent");
}

#[tokio::test]
async fn emergency_adds_retry_and_expire_when_allowed() {
    let r = relay(&[("ALLOW_EMERGENCY", "true")]).await;
    Mock::given(method("POST"))
        .and(body_string_contains("priority=2"))
        .and(body_string_contains("retry=60"))
        .and(body_string_contains("expire=3600"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"status":1}"#))
        .expect(1)
        .mount(&r.pushover)
        .await;
    assert_eq!(r.post(r#"{"message":"m","priority":2}"#).await.status, 200);
}

#[tokio::test]
async fn bad_signature_is_401() {
    let r = relay(&[]).await;
    mock_ok(&r, 0).await;
    let body = r#"{"message":"m"}"#;
    let wrong = sign(
        b"wrong-secret-wrong-secret-wrong-secret",
        &T0.to_string(),
        "POST",
        "/v1/notify",
        body.as_bytes(),
    );
    let res = r.post_with(body, T0, Some(wrong)).await;
    assert_eq!(res.status, 401);
    assert_eq!(res.json, serde_json::json!({"error": "unauthorized"}));
    // Missing signature is the same generic 401.
    let res = r.post_with(body, T0, None).await;
    assert_eq!(res.status, 401);
    assert_eq!(res.json, serde_json::json!({"error": "unauthorized"}));
}

#[tokio::test]
async fn stale_timestamp_is_401() {
    let r = relay(&[]).await;
    mock_ok(&r, 0).await;
    let body = r#"{"message":"m"}"#;
    let ts = T0 - 301;
    let sig = sign(
        SECRET.as_bytes(),
        &ts.to_string(),
        "POST",
        "/v1/notify",
        body.as_bytes(),
    );
    assert_eq!(r.post_with(body, ts, Some(sig)).await.status, 401);
}

#[tokio::test]
async fn replay_is_401() {
    let r = relay(&[]).await;
    mock_ok(&r, 1).await;
    let body = r#"{"message":"m"}"#;
    let sig = sign(
        SECRET.as_bytes(),
        &T0.to_string(),
        "POST",
        "/v1/notify",
        body.as_bytes(),
    );
    assert_eq!(r.post_with(body, T0, Some(sig.clone())).await.status, 200);
    r.clock.0.store(T0 + 60, Ordering::SeqCst);
    assert_eq!(r.post_with(body, T0, Some(sig)).await.status, 401);
}

#[tokio::test]
async fn oversize_body_is_413() {
    let r = relay(&[]).await;
    mock_ok(&r, 0).await;
    let body = format!(r#"{{"message":"{}"}}"#, "a".repeat(9000));
    assert_eq!(r.post(&body).await.status, 413);
}

#[tokio::test]
async fn unknown_field_is_400() {
    let r = relay(&[]).await;
    mock_ok(&r, 0).await;
    let res = r.post(r#"{"message":"m","token":"steal"}"#).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.json["error"], "invalid_request");
    let res = r.post(r#"{"message":"m","priority":7}"#).await;
    assert_eq!(res.status, 400);
}

#[tokio::test]
async fn emergency_disallowed_is_403() {
    let r = relay(&[]).await;
    mock_ok(&r, 0).await;
    let res = r.post(r#"{"message":"m","priority":2}"#).await;
    assert_eq!(res.status, 403);
    assert_eq!(res.json["error"], "emergency_not_allowed");
}

#[tokio::test]
async fn dedup_second_call_is_deduplicated() {
    let r = relay(&[]).await;
    mock_ok(&r, 1).await;
    let a = r.post(r#"{"message":"m","dedup_key":"web01/disk"}"#).await;
    assert_eq!(a.json["status"], "sent");
    // Different body (different signature), same dedup_key.
    let b = r
        .post(r#"{"message":"m again","dedup_key":"web01/disk"}"#)
        .await;
    assert_eq!(b.status, 200);
    assert_eq!(b.json["status"], "deduplicated");
}

#[tokio::test]
async fn dedup_expires_after_window() {
    let r = relay(&[("DEDUP_WINDOW_SECS", "60")]).await;
    mock_ok(&r, 2).await;
    assert_eq!(
        r.post(r#"{"message":"m","dedup_key":"k"}"#).await.json["status"],
        "sent"
    );
    r.clock.0.store(T0 + 61, Ordering::SeqCst);
    assert_eq!(
        r.post(r#"{"message":"m","dedup_key":"k"}"#).await.json["status"],
        "sent"
    );
}

#[tokio::test]
async fn upstream_failure_is_502_and_releases_dedup() {
    let r = relay(&[]).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(2)
        .mount(&r.pushover)
        .await;
    let body = r#"{"message":"m","dedup_key":"k"}"#;
    let res = r.post(body).await;
    assert_eq!(res.status, 502);
    assert_eq!(res.json["error"], "upstream_error");
    // Retry with the same dedup_key reaches upstream again.
    r.clock.0.store(T0 + 1, Ordering::SeqCst);
    assert_eq!(r.post(body).await.status, 502);
}

#[tokio::test]
async fn per_ip_rate_limit_is_429() {
    let r = relay(&[("RATE_IP_PER_SEC", "1"), ("RATE_IP_BURST", "2")]).await;
    mock_ok(&r, 2).await;
    assert_eq!(r.post(r#"{"message":"1"}"#).await.status, 200);
    assert_eq!(r.post(r#"{"message":"2"}"#).await.status, 200);
    let res = r.post(r#"{"message":"3"}"#).await;
    assert_eq!(res.status, 429);
    assert_eq!(res.json["error"], "rate_limited");
    let retry: u64 = res.headers["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry >= 1);
}

#[tokio::test]
async fn per_secret_rate_limit_is_429() {
    let r = relay(&[("RATE_SECRET_PER_SEC", "1"), ("RATE_SECRET_BURST", "1")]).await;
    mock_ok(&r, 1).await;
    assert_eq!(r.post(r#"{"message":"1"}"#).await.status, 200);
    assert_eq!(r.post(r#"{"message":"2"}"#).await.status, 429);
}

#[tokio::test]
async fn global_rate_limit_is_429() {
    let r = relay(&[("RATE_GLOBAL_PER_SEC", "1"), ("RATE_GLOBAL_BURST", "1")]).await;
    mock_ok(&r, 1).await;
    assert_eq!(r.post(r#"{"message":"1"}"#).await.status, 200);
    assert_eq!(r.post(r#"{"message":"2"}"#).await.status, 429);
}

#[tokio::test]
async fn repeated_auth_failures_ban_the_ip() {
    let r = relay(&[("AUTH_BAN_THRESHOLD", "3"), ("AUTH_BAN_SECS", "900")]).await;
    mock_ok(&r, 1).await;
    for _ in 0..3 {
        assert_eq!(
            r.post_with(r#"{"message":"m"}"#, T0, Some("0".repeat(64)))
                .await
                .status,
            401
        );
    }
    // Even a correctly signed request is refused while banned.
    let res = r.post(r#"{"message":"m"}"#).await;
    assert_eq!(res.status, 429);
    assert_eq!(res.headers["retry-after"], "900");
    // Ban expires.
    r.clock.0.store(T0 + 901, Ordering::SeqCst);
    assert_eq!(r.post(r#"{"message":"m"}"#).await.status, 200);
}

#[tokio::test]
async fn quota_guard_blocks_low_priority() {
    let r = relay(&[("QUOTA_RESERVE", "500")]).await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Limit-App-Remaining", "100")
                .set_body_string(r#"{"status":1}"#),
        )
        .expect(2)
        .mount(&r.pushover)
        .await;
    // Quota unknown before the first response: passes and learns remaining=100.
    assert_eq!(r.post(r#"{"message":"first"}"#).await.status, 200);
    let res = r.post(r#"{"message":"normal","priority":0}"#).await;
    assert_eq!(res.status, 503);
    assert_eq!(res.json["error"], "quota_reserve");
    // High priority still goes through.
    assert_eq!(
        r.post(r#"{"message":"high","priority":1}"#).await.status,
        200
    );
}

#[tokio::test]
async fn hosted_mode_is_501() {
    // v2 needs an APNs mode in hosted mode; v1 behaviour is unchanged.
    let r = relay(&[("MODE", "hosted"), ("APNS_MODE", "mock")]).await;
    mock_ok(&r, 0).await;
    let res = r.post(r#"{"message":"m"}"#).await;
    assert_eq!(res.status, 501);
    assert_eq!(res.json["error"], "hosted mode not available yet");
}

#[tokio::test]
async fn healthz_and_unknown_routes() {
    let r = relay(&[]).await;
    assert_eq!(r.get("/healthz").await, (200, "ok".to_string()));
    assert_eq!(r.get("/").await.0, 404);
    assert_eq!(r.get("/v1/notify").await.0, 404);
    assert_eq!(r.get("/metrics").await.0, 404);
    let resp = r
        .http
        .post(format!("{}/healthz", r.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn spoofed_cf_header_does_not_bypass_ip_limit() {
    // Peer is 127.0.0.1 (not Cloudflare), so CF-Connecting-IP must be ignored
    // and all requests share one per-IP bucket.
    let r = relay(&[
        ("TRUST_PROXY", "cloudflare"),
        ("RATE_IP_PER_SEC", "1"),
        ("RATE_IP_BURST", "1"),
    ])
    .await;
    let send = |ip: &'static str| {
        r.http
            .post(format!("{}/v1/notify", r.base))
            .header("cf-connecting-ip", ip)
            .body("{}")
            .send()
    };
    assert_eq!(send("198.51.100.1").await.unwrap().status().as_u16(), 401);
    assert_eq!(send("198.51.100.2").await.unwrap().status().as_u16(), 429);
}
