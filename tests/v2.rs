//! v2 end-to-end tests: real TCP server, mock APNs, fake clock, temp SQLite.

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use common::{derive, id128, Client, Keys};
use futures_util::{SinkExt, StreamExt};
use metriccupid_push::client_ip::ClientIpResolver;
use metriccupid_push::config::Config;
use metriccupid_push::limits::Clock;
use metriccupid_push::v2::apns::MockApns;
use metriccupid_push::v2::store;
use metriccupid_push::{serve, AppState};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const T0: u64 = 1_700_000_000;
const TOKEN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct TestClock(AtomicU64);

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Server {
    base: String,
    clock: Arc<TestClock>,
    state: Arc<AppState>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl Server {
    fn mock(&self) -> Arc<MockApns> {
        self.state.mock_apns().expect("APNS_MODE=mock")
    }

    fn set_time(&self, t: u64) {
        self.clock.0.store(t, Ordering::SeqCst);
    }

    fn now_fn(&self) -> Arc<dyn Fn() -> u64 + Send + Sync> {
        let c = self.clock.clone();
        Arc::new(move || c.now())
    }

    /// Group `seed`: a client for its Mac (device seed+1) with fresh keys.
    fn group(&self, seed: u8) -> Client {
        let keys = derive(&[seed; 32]);
        Client::new(
            &self.base,
            &id128(seed),
            &id128(seed.wrapping_add(1)),
            keys,
            self.now_fn(),
        )
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}

async fn server_at(data: &Path, overrides: &[(&str, &str)], clock: Arc<TestClock>) -> Server {
    let mut env: HashMap<String, String> = HashMap::from([
        ("APNS_MODE".into(), "mock".into()),
        ("DATA_DIR".into(), data.display().to_string()),
        // Tests make many requests from 127.0.0.1.
        ("RATE_IP_PER_SEC".into(), "1000".into()),
        ("RATE_IP_BURST".into(), "10000".into()),
        ("RATE_GLOBAL_PER_SEC".into(), "1000".into()),
        ("RATE_GLOBAL_BURST".into(), "10000".into()),
        ("RATE_V2_GROUPS_BURST".into(), "20".into()),
        ("RATE_V2_MESSAGES_BURST".into(), "100".into()),
        ("RATE_V2_COMMANDS_BURST".into(), "100".into()),
    ]);
    for (k, v) in overrides {
        env.insert(k.to_string(), v.to_string());
    }
    let config = Config::from_lookup(|k| env.get(k).cloned()).expect("valid test config");
    let resolver = ClientIpResolver::from_config(&config.trust_proxy).await;
    let state = Arc::new(
        AppState::new_with_licence_root(
            &config,
            resolver,
            clock.clone(),
            common::licence::CHAIN.root.clone(),
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(serve(listener, state.clone(), async move {
        let _ = rx.await;
    }));
    Server {
        base,
        clock,
        state,
        shutdown: Some(tx),
        task: Some(task),
    }
}

async fn server(overrides: &[(&str, &str)]) -> (tempfile::TempDir, Server) {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(T0)));
    let s = server_at(dir.path(), overrides, clock).await;
    (dir, s)
}

/// Group with a registered Mac and iPhone; returns (mac, phone).
async fn setup(s: &Server, seed: u8) -> (Client, Client) {
    let mac = s.group(seed);
    assert_eq!(mac.create_group().await.status, 201);
    assert_eq!(mac.register("mac", "MacBook", None).await.status, 201);
    let phone = mac.as_device(&id128(seed.wrapping_add(2)));
    assert_eq!(
        phone.register("ios", "iPhone", Some(TOKEN_A)).await.status,
        201
    );
    (mac, phone)
}

fn alert_body(mac: &Client, id: &str, urgency: &str, plaintext_len: usize) -> Value {
    let pt = json!({
        "v": 1, "type": "alert", "id": id, "ts": T0,
        "alert_id": "icinga:web01!disk", "title": "web01: Disk full", "host": "web01",
        "service": "disk", "severity": "critical", "source": "icinga",
        "summary": "x".repeat(plaintext_len), "state": "firing", "actions": ["ack", "mute"],
    });
    json!({
        "id": id,
        "type": "alert",
        "sealed": mac.seal_json("alert", id, &pt, [1; 12]),
        "collapse_id": common::collapse_id(&mac.keys.collapse, "icinga:web01!disk"),
        "urgency": urgency,
        "ttl_secs": 3600,
    })
}

fn command_body(phone: &Client, id: &str) -> Value {
    let pt = json!({
        "v": 1, "type": "command", "id": id, "ts": T0,
        "action": "ack", "alert_id": "icinga:web01!disk",
    });
    json!({ "id": id, "sealed": phone.seal_json("command", id, &pt, [2; 12]) })
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open a signed stream; Err(status) if the upgrade was refused.
async fn open_ws(c: &Client) -> Result<Ws, u16> {
    let mut req = c.ws_url().into_client_request().unwrap();
    for (k, v) in c.signed_headers("GET", "/v2/stream", b"") {
        req.headers_mut().insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(&v).unwrap(),
        );
    }
    match tokio_tungstenite::connect_async(req).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
        Err(e) => panic!("ws connect: {e}"),
    }
}

/// Next text frame as JSON (skipping pings), with a timeout.
async fn next_json(ws: &mut Ws) -> Value {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("frame within 5 s")
            .expect("stream open")
            .expect("valid frame");
        match msg {
            WsMessage::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            other => panic!("unexpected frame {other:?}"),
        }
    }
}

async fn wait_ready(ws: &mut Ws) -> Vec<Value> {
    let mut backlog = Vec::new();
    loop {
        let f = next_json(ws).await;
        if f["type"] == "ready" {
            return backlog;
        }
        backlog.push(f);
    }
}

async fn counts(s: &Server, group: &str) -> (usize, usize) {
    let g = group.to_string();
    s.state
        .v2()
        .store
        .call(move |c| store::counts(c, &g))
        .await
        .unwrap()
}

// ------------------------------------------------------------------ groups

#[tokio::test]
async fn group_create_exists_conflict_and_validation() {
    let (_d, s) = server(&[]).await;
    let c = s.group(1);
    let r = c.create_group().await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    assert_eq!(r.json["status"], "created");
    let r = c.create_group().await;
    assert_eq!((r.status, r.json["status"].as_str()), (200, Some("exists")));

    let mut other = c.clone();
    other.keys = derive(&[99; 32]);
    let r = other.create_group().await;
    assert_eq!(r.status, 409);
    assert_eq!(r.json["error"], "group_exists");

    let http = reqwest::Client::new();
    for body in [
        json!({"group_id": "short", "auth_key": STANDARD.encode([0u8; 32])}),
        json!({"group_id": id128(5), "auth_key": STANDARD.encode([0u8; 31])}),
        json!({"group_id": id128(5), "auth_key": STANDARD.encode([0u8; 32]), "extra": 1}),
    ] {
        let r = http
            .post(format!("{}/v2/groups", s.base))
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400);
    }
}

#[tokio::test]
async fn hosted_registration_needs_licence() {
    let (_d, s) = server(&[("MODE", "hosted")]).await;
    let r = s.group(1).create_group().await;
    assert_eq!(r.status, 402);
    assert_eq!(r.json["error"], "licence_required");

    let (_d, s) = server(&[("MODE", "hosted"), ("HOSTED_OPEN_REGISTRATION", "true")]).await;
    assert_eq!(s.group(1).create_group().await.status, 201);
}

#[tokio::test]
async fn group_registration_is_rate_limited_per_ip() {
    let (_d, s) = server(&[("RATE_V2_GROUPS_BURST", "2")]).await;
    assert_eq!(s.group(1).create_group().await.status, 201);
    assert_eq!(s.group(2).create_group().await.status, 201);
    let r = s.group(3).create_group().await;
    assert_eq!(r.status, 429);
    assert!(r.headers.contains_key("retry-after"));
}

// ----------------------------------------------------------------- devices

#[tokio::test]
async fn device_register_list_delete_and_cap() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 10).await;
    let r = mac.register("mac", "MacBook Pro", None).await;
    assert_eq!(
        (r.status, r.json["status"].as_str()),
        (200, Some("updated"))
    );

    let r = mac.get("/v2/devices").await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let list = r.json["devices"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert!(
        !r.json.to_string().contains(TOKEN_A),
        "tokens are never returned"
    );
    let ios = list.iter().find(|d| d["kind"] == "ios").unwrap();
    assert_eq!(ios["has_token"], true);
    assert_eq!(ios["apns_env"], "sandbox");
    let m = list.iter().find(|d| d["kind"] == "mac").unwrap();
    assert_eq!(m["name"], "MacBook Pro");
    assert_eq!(m["online"], false);

    // Validation.
    let path = format!("/v2/devices/{}", id128(200));
    let r = mac.send("PUT", &path, r#"{"kind":"mac","name":"x"}"#).await;
    assert_eq!(r.status, 400, "header must match path");
    let r = mac.register("mac", "x", Some(TOKEN_A)).await;
    assert_eq!(r.status, 400, "token only for ios");
    let r = phone.register("ios", "x", Some("nothex")).await;
    assert_eq!(r.status, 400);
    let r = phone.register("watch", "x", None).await;
    assert_eq!(r.status, 400);
    let r = phone.register("ios", &"n".repeat(65), None).await;
    assert_eq!(r.status, 400);

    // Cap: 10 devices per group.
    for i in 0..8u8 {
        let d = mac.as_device(&id128(100 + i));
        assert_eq!(d.register("ios", "extra", None).await.status, 201);
    }
    let r = mac
        .as_device(&id128(150))
        .register("ios", "one too many", None)
        .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.json["error"], "device_limit");

    // Delete, then the deleted device is unknown.
    let path = format!("/v2/devices/{}", phone.device_id);
    assert_eq!(mac.send("DELETE", &path, "").await.status, 204);
    s.set_time(T0 + 1);
    assert_eq!(mac.send("DELETE", &path, "").await.status, 404);
    let r = phone.get("/v2/devices").await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json["error"], "unknown_device");
}

// ---------------------------------------------------------------- messages

#[tokio::test]
async fn message_fans_out_to_apns_with_expected_payload() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 20).await;
    phone
        .as_device(&id128(25))
        .register("ios", "iPad", Some(TOKEN_B))
        .await;

    let body = alert_body(&mac, "msg-1", "critical", 50);
    let r = mac.post("/v2/messages", &body).await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["status"], "stored");
    assert_eq!(r.json["pushed"], 2);
    assert_eq!(r.json["cursor"], 1);

    let pushes = s.mock().pushes();
    assert_eq!(pushes.len(), 2);
    let mut tokens: Vec<_> = pushes.iter().map(|p| p.device_token.as_str()).collect();
    tokens.sort();
    assert_eq!(tokens, vec![TOKEN_A, TOKEN_B]);
    let p = &pushes[0];
    assert_eq!(p.priority, 10);
    assert_eq!(p.push_type, "alert");
    assert_eq!(p.expiration, T0 + 3600);
    assert_eq!(p.collapse_id.as_deref(), body["collapse_id"].as_str());
    assert_eq!(serde_json::to_value(p.env).unwrap(), "sandbox");
    assert_eq!(
        p.payload,
        json!({
            "aps": {
                "alert": {"title": "MetricCupid", "body": "New alert"},
                "mutable-content": 1,
                "category": "MC_ALERT",
                "sound": "default",
                "interruption-level": "time-sensitive",
                "thread-id": "mc"
            },
            "mc": {"id": "msg-1", "t": "alert", "s": body["sealed"]}
        })
    );
    // The phone (NSE) can decrypt what APNs delivered.
    let sealed = p.payload["mc"]["s"].as_str().unwrap();
    let pt = common::open(
        &phone.keys.enc,
        &common::aad(&phone.group_id, "alert", "msg-1"),
        sealed,
    )
    .unwrap();
    let pt: Value = serde_json::from_slice(&pt).unwrap();
    assert_eq!(pt["host"], "web01");

    // Retry with the same id (re-signed a second later): no second push.
    s.set_time(T0 + 1);
    let r = mac.post("/v2/messages", &body).await;
    assert_eq!(
        (r.json["status"].as_str(), r.json["cursor"].as_u64()),
        (Some("duplicate"), Some(1))
    );
    assert_eq!(s.mock().pushes().len(), 2);

    // A silent result: MC_RESULT, priority 5, no sound.
    s.mock().clear();
    let pt = json!({"v":1,"type":"result","id":"res-1","ts":T0,"command_id":"c","alert_id":"a","ok":true,"message":"ok"});
    let r = mac
        .post(
            "/v2/messages",
            &json!({"id":"res-1","type":"result","sealed":mac.seal_json("result","res-1",&pt,[3;12]),"urgency":"silent","ttl_secs":0}),
        )
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let p = &s.mock().pushes()[0];
    assert_eq!(p.priority, 5);
    assert_eq!(p.expiration, 0);
    assert_eq!(p.payload["aps"]["category"], "MC_RESULT");
    assert_eq!(p.payload["aps"]["alert"]["body"], "Command result");
    assert!(p.payload["aps"].get("sound").is_none());
    assert!(p.payload["aps"].get("interruption-level").is_none());

    // Mailbox: the phone polls with a cursor.
    let r = phone.get("/v2/messages?since=0").await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let msgs = r.json["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0]["id"], "msg-1");
    assert_eq!(msgs[0]["urgency"], "critical");
    assert_eq!(msgs[1]["type"], "result");
    assert_eq!(r.json["cursor"], 2);
    assert_eq!(r.json["more"], false);
    let r = phone.get("/v2/messages?since=2").await;
    assert_eq!(r.json["messages"].as_array().unwrap().len(), 0);
    assert_eq!(r.json["cursor"], 2);
}

#[tokio::test]
async fn message_validation_and_sender_kind() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 30).await;
    // Only Macs send messages.
    let r = phone
        .post("/v2/messages", &alert_body(&mac, "m", "normal", 10))
        .await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (403, Some("wrong_device_kind"))
    );

    let mut b = alert_body(&mac, "m", "normal", 10);
    b["urgency"] = json!("loud");
    assert_eq!(mac.post("/v2/messages", &b).await.status, 400);
    let mut b = alert_body(&mac, "m", "normal", 10);
    b["ttl_secs"] = json!(86_401);
    assert_eq!(mac.post("/v2/messages", &b).await.status, 400);
    let mut b = alert_body(&mac, "m", "normal", 10);
    b["sealed"] = json!("AAAA");
    assert_eq!(
        mac.post("/v2/messages", &b).await.status,
        400,
        "shorter than nonce+tag"
    );
    let mut b = alert_body(&mac, "m", "normal", 10);
    b["collapse_id"] = json!("x".repeat(65));
    assert_eq!(mac.post("/v2/messages", &b).await.status, 400);
    let mut b = alert_body(&mac, "bad id!", "normal", 10);
    b["id"] = json!("bad id!");
    assert_eq!(mac.post("/v2/messages", &b).await.status, 400);
}

#[tokio::test]
async fn oversized_apns_payload_is_413() {
    let (_d, s) = server(&[]).await;
    let (mac, _phone) = setup(&s, 40).await;
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "big", "normal", 3200))
        .await;
    assert_eq!(r.status, 413, "{:?}", r.json);
    assert_eq!(r.json["error"], "payload_too_large");
    assert!(s.mock().pushes().is_empty());
    assert_eq!(counts(&s, &mac.group_id).await.0, 0, "not stored either");
    // About 2.5 KB of plaintext fits.
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "ok", "normal", 2300))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    // Over the 16 KB v2 body limit.
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "huge", "normal", 13_000))
        .await;
    assert_eq!(r.status, 413);
}

#[tokio::test]
async fn unregistered_token_is_removed() {
    let (_d, s) = server(&[]).await;
    let (mac, _phone) = setup(&s, 50).await;
    s.mock().mark_unregistered(TOKEN_A);
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "m1", "normal", 10))
        .await;
    assert_eq!(r.json["unregistered"], 1, "{:?}", r.json);
    assert_eq!(r.json["pushed"], 0);
    let r = mac.get("/v2/devices").await;
    let ios = r.json["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["kind"] == "ios")
        .cloned()
        .unwrap();
    assert_eq!(ios["has_token"], false);
    // No more pushes to the dead token.
    s.mock().clear();
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "m2", "normal", 10))
        .await;
    assert_eq!(r.json["pushed"], 0);
    assert!(s.mock().pushes().is_empty());
}

// ---------------------------------------------------------------- commands

#[tokio::test]
async fn command_is_delivered_over_websocket_and_acked() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 60).await;
    let mut ws = open_ws(&mac).await.expect("upgrade");
    assert!(wait_ready(&mut ws).await.is_empty());

    let r = mac.get("/v2/devices").await;
    let m = r.json["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["kind"] == "mac")
        .cloned()
        .unwrap();
    assert_eq!(m["online"], true);

    let body = command_body(&phone, "cmd-1");
    let r = phone.post("/v2/commands", &body).await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["delivered"], true);
    assert_eq!(r.json["status"], "delivered");

    let f = next_json(&mut ws).await;
    assert_eq!(f["type"], "command");
    assert_eq!(f["id"], "cmd-1");
    assert_eq!(f["sealed"], body["sealed"]);
    let cursor = f["cursor"].as_u64().unwrap();
    let pt = common::open(
        &mac.keys.enc,
        &common::aad(&mac.group_id, "command", "cmd-1"),
        f["sealed"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&pt).unwrap()["action"],
        "ack"
    );

    ws.send(WsMessage::Text(
        json!({"type": "ack", "cursor": cursor}).to_string().into(),
    ))
    .await
    .unwrap();
    // The ack is processed asynchronously.
    for _ in 0..50 {
        if counts(&s, &mac.group_id).await.1 == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(counts(&s, &mac.group_id).await.1, 0);

    // Only Macs may open a stream; only phones send commands.
    assert_eq!(open_ws(&phone).await.err(), Some(403));
    let r = mac.post("/v2/commands", &command_body(&mac, "c2")).await;
    assert_eq!(r.status, 403);

    // An invalid frame closes the stream.
    ws.send(WsMessage::Text("{\"type\":\"hello\"}".into()))
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(m)) = ws.next().await {
            if let WsMessage::Close(f) = m {
                return f.map(|f| u16::from(f.code));
            }
        }
        None
    })
    .await
    .unwrap();
    assert_eq!(closed, Some(1008));
}

#[tokio::test]
async fn command_is_queued_without_stream_then_polled_or_streamed() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 70).await;
    let r = phone
        .post("/v2/commands", &command_body(&phone, "q-1"))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["delivered"], false);
    assert_eq!(r.json["status"], "queued");
    s.set_time(T0 + 1);
    let r = phone
        .post("/v2/commands", &command_body(&phone, "q-1"))
        .await;
    assert_eq!(r.json["status"], "duplicate");

    // Poll fallback.
    let r = mac.get("/v2/commands?since=0").await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let cmds = r.json["commands"].as_array().unwrap();
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0]["id"], "q-1");
    let cursor = cmds[0]["cursor"].as_u64().unwrap();
    assert_eq!(
        phone.get("/v2/commands?since=0").await.status,
        403,
        "phones do not poll commands"
    );
    let r = mac
        .post("/v2/commands/ack", &json!({"cursor": cursor}))
        .await;
    assert_eq!(r.json["removed"], true);
    s.set_time(T0 + 2);
    let r = mac
        .post("/v2/commands/ack", &json!({"cursor": cursor}))
        .await;
    assert_eq!(r.json["removed"], false);
    assert!(mac.get("/v2/commands?since=0").await.json["commands"]
        .as_array()
        .unwrap()
        .is_empty());

    // Queued commands are sent as backlog when the Mac connects.
    phone
        .post("/v2/commands", &command_body(&phone, "q-2"))
        .await;
    phone
        .post("/v2/commands", &command_body(&phone, "q-3"))
        .await;
    let mut ws = open_ws(&mac).await.unwrap();
    let backlog = wait_ready(&mut ws).await;
    let ids: Vec<_> = backlog.iter().map(|f| f["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["q-2", "q-3"]);
}

#[tokio::test]
async fn new_stream_replaces_old_and_device_delete_closes_it() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 80).await;
    let mut ws1 = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws1).await;
    s.set_time(T0 + 1); // new signature for the second upgrade
    let mut ws2 = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws2).await;
    // The first stream is closed by the server.
    let first = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws1.next().await {
                Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => return true,
                _ => continue,
            }
        }
    })
    .await
    .unwrap();
    assert!(first);
    let r = phone.post("/v2/commands", &command_body(&phone, "x")).await;
    assert_eq!(r.json["delivered"], true);
    assert_eq!(next_json(&mut ws2).await["id"], "x");

    let path = format!("/v2/devices/{}", mac.device_id);
    assert_eq!(phone.send("DELETE", &path, "").await.status, 204);
    let gone = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws2.next().await {
                Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => return true,
                _ => continue,
            }
        }
    })
    .await
    .unwrap();
    assert!(gone);
}

// -------------------------------------------------------------------- auth

#[tokio::test]
async fn auth_failures() {
    let (_d, s) = server(&[("AUTH_BAN_THRESHOLD", "100")]).await;
    let (mac, _phone) = setup(&s, 90).await;

    let mut wrong = mac.clone();
    wrong.keys = derive(&[1; 32]);
    let r = wrong.get("/v2/devices").await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json, json!({"error": "unauthorized"}));

    let unknown = s.group(200);
    assert_eq!(
        unknown.get("/v2/devices").await.status,
        401,
        "unknown group"
    );

    let mut bad_device = mac.clone();
    bad_device.device_id = "not-an-id".into();
    assert_eq!(bad_device.get("/v2/devices").await.status, 401);

    // Missing headers.
    let r = reqwest::get(format!("{}/v2/devices", s.base))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // Stale timestamp.
    let mut stale = mac.clone();
    stale.now = Arc::new(|| T0 - 301);
    assert_eq!(stale.get("/v2/devices").await.status, 401);

    // Replay of an identical signed request.
    let body = alert_body(&mac, "r1", "normal", 10).to_string();
    let headers = mac.signed_headers("POST", "/v2/messages", body.as_bytes());
    let send = || {
        let mut req = reqwest::Client::new()
            .post(format!("{}/v2/messages", s.base))
            .body(body.clone());
        for (k, v) in &headers {
            req = req.header(k, v);
        }
        req.send()
    };
    assert_eq!(send().await.unwrap().status().as_u16(), 200);
    assert_eq!(send().await.unwrap().status().as_u16(), 401);

    // Signature covers the query string.
    let ts = T0.to_string();
    let sig = metriccupid_push::auth::sign_v2(
        &mac.keys.auth,
        &ts,
        "GET",
        "/v2/messages?since=0",
        &mac.group_id,
        &mac.device_id,
        b"",
    );
    let r = reqwest::Client::new()
        .get(format!("{}/v2/messages?since=5", s.base))
        .header("x-mc-timestamp", &ts)
        .header("x-mc-signature", sig)
        .header("x-mc-group", &mac.group_id)
        .header("x-mc-device", &mac.device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // Unsigned WebSocket upgrade.
    let req = mac.ws_url().into_client_request().unwrap();
    match tokio_tungstenite::connect_async(req).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => assert_eq!(r.status().as_u16(), 401),
        other => panic!("expected 401, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn repeated_v2_auth_failures_ban_the_ip() {
    let (_d, s) = server(&[("AUTH_BAN_THRESHOLD", "3")]).await;
    let (mac, _phone) = setup(&s, 95).await;
    let mut wrong = mac.clone();
    wrong.keys = derive(&[1; 32]);
    for _ in 0..3 {
        assert_eq!(wrong.get("/v2/devices").await.status, 401);
    }
    let r = mac.get("/v2/devices").await;
    assert_eq!(r.status, 429, "banned even with a valid signature");
    assert_eq!(
        mac.create_group().await.status,
        429,
        "unauthenticated routes too"
    );
}

// ------------------------------------------------------------- rate limits

#[tokio::test]
async fn per_group_rate_limits() {
    let (_d, s) = server(&[
        ("RATE_V2_MESSAGES_PER_SEC", "1"),
        ("RATE_V2_MESSAGES_BURST", "2"),
        ("RATE_V2_COMMANDS_PER_SEC", "1"),
        ("RATE_V2_COMMANDS_BURST", "1"),
    ])
    .await;
    let (mac, phone) = setup(&s, 100).await;
    let (other, _) = setup(&s, 110).await;
    for i in 0..2 {
        let r = mac
            .post(
                "/v2/messages",
                &alert_body(&mac, &format!("m{i}"), "normal", 10),
            )
            .await;
        assert_eq!(r.status, 200);
    }
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "m2", "normal", 10))
        .await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (429, Some("rate_limited"))
    );
    assert!(r.headers.contains_key("retry-after"));
    // Other groups have their own bucket.
    let r = other
        .post("/v2/messages", &alert_body(&other, "m0", "normal", 10))
        .await;
    assert_eq!(r.status, 200);

    assert_eq!(
        phone
            .post("/v2/commands", &command_body(&phone, "c0"))
            .await
            .status,
        200
    );
    assert_eq!(
        phone
            .post("/v2/commands", &command_body(&phone, "c1"))
            .await
            .status,
        429
    );
}

// --------------------------------------------------------------- retention

#[tokio::test]
async fn retention_cleanup() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 120).await;
    mac.post("/v2/messages", &alert_body(&mac, "m1", "normal", 10))
        .await;
    phone
        .post("/v2/commands", &command_body(&phone, "c1"))
        .await;
    assert_eq!(counts(&s, &mac.group_id).await, (1, 1));

    // Commands live 1 h.
    s.set_time(T0 + 3601);
    assert!(mac.get("/v2/commands?since=0").await.json["commands"]
        .as_array()
        .unwrap()
        .is_empty());
    s.state.cleanup_storage().await;
    assert_eq!(counts(&s, &mac.group_id).await, (1, 0));

    // Messages live 24 h.
    s.set_time(T0 + 86_400);
    assert!(phone.get("/v2/messages?since=0").await.json["messages"]
        .as_array()
        .unwrap()
        .is_empty());
    s.state.cleanup_storage().await;
    assert_eq!(counts(&s, &mac.group_id).await, (0, 0));
}

#[tokio::test]
async fn data_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(T0)));
    let s = server_at(dir.path(), &[], clock.clone()).await;
    let (mac, phone) = setup(&s, 130).await;
    mac.post("/v2/messages", &alert_body(&mac, "persist", "normal", 10))
        .await;
    phone
        .post("/v2/commands", &command_body(&phone, "persist-cmd"))
        .await;
    s.stop().await;

    clock.0.store(T0 + 10, Ordering::SeqCst);
    let s = server_at(dir.path(), &[], clock).await;
    let mac = Client {
        base: s.base.clone(),
        ..mac
    };
    let phone = Client {
        base: s.base.clone(),
        ..phone
    };
    // Group key, devices, mailbox and queue are all still there.
    let r = mac.get("/v2/devices").await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["devices"].as_array().unwrap().len(), 2);
    let r = phone.get("/v2/messages?since=0").await;
    assert_eq!(r.json["messages"][0]["id"], "persist");
    let r = mac.get("/v2/commands?since=0").await;
    assert_eq!(r.json["commands"][0]["id"], "persist-cmd");
    // Cursors continue instead of restarting.
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "after", "normal", 10))
        .await;
    assert_eq!(r.json["cursor"], 2);
    assert_eq!(s.mock().pushes().len(), 1);
}

// ----------------------------------------------------------------- gateway

#[tokio::test]
async fn self_hosted_server_pushes_through_hosted_gateway() {
    let (_d1, hosted) = server(&[
        ("MODE", "hosted"),
        ("HOSTED_OPEN_REGISTRATION", "true"),
        ("GATEWAY_OPEN", "true"),
    ])
    .await;
    let (_d2, selfhosted) =
        server(&[("APNS_MODE", "gateway"), ("GATEWAY_URL", &hosted.base)]).await;

    // Group creation is forwarded, so the gateway knows the group's auth_key.
    let (mac, _phone) = setup(&selfhosted, 140).await;
    let k = mac.group_id.clone();
    let key = hosted
        .state
        .v2()
        .store
        .call(move |c| store::group_key(c, &k))
        .await
        .unwrap();
    assert_eq!(key, Some(mac.keys.auth));

    let body = alert_body(&mac, "gw-1", "critical", 20);
    let r = mac.post("/v2/messages", &body).await;
    assert_eq!(r.json["pushed"], 1, "{:?}", r.json);
    let pushes = hosted.mock().pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].device_token, TOKEN_A);
    assert_eq!(
        pushes[0].collapse_id.as_deref(),
        body["collapse_id"].as_str()
    );
    assert_eq!(pushes[0].payload["mc"]["s"], body["sealed"]);
    assert_eq!(
        pushes[0].payload["aps"]["interruption-level"],
        "time-sensitive"
    );
    assert_eq!(pushes[0].expiration, T0 + 3600);
    // The gateway stored nothing: it never saw a message or device.
    assert_eq!(counts(&hosted, &mac.group_id).await, (0, 0));

    // 410 from the gateway removes the token on the self-hosted server.
    hosted.mock().mark_unregistered(TOKEN_A);
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "gw-2", "normal", 20))
        .await;
    assert_eq!(r.json["unregistered"], 1, "{:?}", r.json);

    // The gateway endpoint does not exist on a self-hosted server, and
    // the debug endpoint only exists with APNS_MODE=mock.
    let r = reqwest::Client::new()
        .post(format!("{}/v2/gateway/push", selfhosted.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let r = reqwest::get(format!("{}/v2/debug/pushes", selfhosted.base))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let text = reqwest::get(format!("{}/v2/debug/pushes", hosted.base))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["pushes"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn gateway_rejects_unknown_groups_licence_and_rate() {
    let (_d1, hosted) = server(&[
        ("MODE", "hosted"),
        ("RATE_V2_GATEWAY_BURST", "2"),
        ("GATEWAY_OPEN", "true"),
    ])
    .await;
    let (_d2, selfhosted) =
        server(&[("APNS_MODE", "gateway"), ("GATEWAY_URL", &hosted.base)]).await;
    // Hosted requires licences, but a self-hosted server's forwarded
    // registration (`gateway: true`) needs none: self-hosting is free.
    let r = selfhosted.group(150).create_group().await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    // Claiming `gateway` directly gives a group that cannot send.
    let direct = hosted.group(155);
    assert_eq!(
        direct
            .create_group_with(json!({"gateway": true}))
            .await
            .status,
        201
    );
    assert_eq!(direct.register("mac", "Mac", None).await.status, 201);
    let r = direct
        .post("/v2/messages", &alert_body(&direct, "x1", "normal", 10))
        .await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (402, Some("licence_required"))
    );

    // Direct gateway calls: unknown group -> 401.
    let c = Client::new(
        &hosted.base,
        &id128(160),
        &id128(161),
        Keys {
            ..derive(&[160; 32])
        },
        hosted.now_fn(),
    );
    let job = json!({
        "device_token": TOKEN_A, "env": "sandbox",
        "message": {"id": "j1", "t": "alert", "s": STANDARD.encode([0u8; 40])},
        "urgency": "normal", "expiration": 0,
    });
    // (Gateway jobs are signed with an empty device line.)
    let c = Client {
        device_id: String::new(),
        ..c
    };
    assert_eq!(c.post("/v2/gateway/push", &job).await.status, 401);

    // Registered group (directly in the hosted store), arbitrary aps is refused.
    let (g, key) = (c.group_id.clone(), c.keys.auth);
    hosted
        .state
        .v2()
        .store
        .call(move |conn| store::create_group(conn, &g, &key, T0))
        .await
        .unwrap();
    let mut evil = job.clone();
    evil["payload"] = json!({"aps": {"alert": "Your account is locked"}});
    assert_eq!(c.post("/v2/gateway/push", &evil).await.status, 400);
    assert_eq!(c.post("/v2/gateway/push", &job).await.status, 200);
    let mut j2 = job.clone();
    j2["message"]["id"] = json!("j2");
    assert_eq!(
        c.post("/v2/gateway/push", &j2).await.status,
        429,
        "per-group gateway limit"
    );
}

#[tokio::test]
async fn v1_route_is_404_when_v1_is_not_configured() {
    let (_d, s) = server(&[]).await;
    let r = reqwest::Client::new()
        .post(format!("{}/v1/notify", s.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}

// ------------------------------------------------------------ direct APNs

/// Throwaway P-256 key (same as the unit test in src/v2/apns.rs).
const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgK3+wXOj+qYgmDXHT
dXDtSfYRru5XrivdGSaIelKtBIihRANCAATny1mZsG6/AJ9r8YVdLlKrMJ4CpQzB
qH5wknmWfGBuaGI8bgJl7LXE1/fX2hgWgqlvm8qTWphAY+IOe7CMedwq
-----END PRIVATE KEY-----";

#[tokio::test]
async fn direct_sender_speaks_http2_to_apns() {
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let apple = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/3/device/{TOKEN_A}")))
        .and(header("apns-topic", "cat.sysop.MetricCupid"))
        .and(header("apns-push-type", "alert"))
        .and(header("apns-priority", "10"))
        .and(header("apns-expiration", (T0 + 3600).to_string().as_str()))
        .and(header_exists("apns-collapse-id"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&apple)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/3/device/{TOKEN_B}")))
        .respond_with(ResponseTemplate::new(410).set_body_string(r#"{"reason":"Unregistered"}"#))
        .expect(1)
        .mount(&apple)
        .await;

    let (_d, s) = server(&[
        ("APNS_MODE", "direct"),
        ("APNS_KEY_P8", TEST_P8),
        ("APNS_KEY_ID", "ABCDE12345"),
        ("APNS_TEAM_ID", "TEAM123456"),
        ("APNS_SANDBOX_URL", &apple.uri()),
        ("APNS_PRODUCTION_URL", "http://127.0.0.1:1"),
    ])
    .await;
    let (mac, phone) = setup(&s, 170).await;
    phone
        .as_device(&id128(175))
        .register("ios", "iPad", Some(TOKEN_B))
        .await;
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "d-1", "critical", 20))
        .await;
    assert_eq!(r.json["pushed"], 1, "{:?}", r.json);
    assert_eq!(r.json["unregistered"], 1, "{:?}", r.json);

    let reqs = apple.received_requests().await.unwrap();
    let ok = reqs
        .iter()
        .find(|r| r.url.path().ends_with(TOKEN_A))
        .unwrap();
    // The client uses HTTP/2 prior knowledge only, so this exchange was h2.
    let auth = ok.headers.get("authorization").unwrap().to_str().unwrap();
    let jwt = auth.strip_prefix("bearer ").unwrap();
    assert_eq!(jwt.split('.').count(), 3);
    let body: Value = serde_json::from_slice(&ok.body).unwrap();
    assert_eq!(body["aps"]["category"], "MC_ALERT");
    assert_eq!(body["mc"]["id"], "d-1");
}

// ---------------------------------------------------------------- presence

/// Wait until the group has no live Mac stream (the server saw the close).
async fn wait_offline(s: &Server, group: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while s.state.v2().hub.group_online(group) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stream closed within 5 s");
}

async fn wait_pushes(s: &Server, n: usize) -> Vec<metriccupid_push::v2::apns::RecordedPush> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let p = s.mock().pushes();
            if p.len() >= n {
                return p;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("pushes within 5 s")
}

async fn tick(s: &Server) {
    metriccupid_push::v2::presence_tick(&s.state).await;
}

#[tokio::test]
async fn status_reports_mac_presence_and_last_seen() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 155).await;
    let r = phone.get("/v2/status").await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(
        r.json,
        json!({"mac_online": false, "mac_last_seen": null,
               "macs": [{"device_id": mac.device_id, "online": false, "last_seen": null}],
               "licence": null, "licence_required": false, "licence_grace_until": null})
    );

    s.set_time(T0 + 10);
    let mut ws = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws).await;
    let r = phone.get("/v2/status").await;
    assert_eq!(r.json["mac_online"], true);
    assert_eq!(r.json["mac_last_seen"], T0 + 10);
    let r = mac.get("/v2/devices").await;
    let d = &r.json["devices"][0];
    assert_eq!(
        (d["online"].clone(), d["last_seen"].clone()),
        (json!(true), json!(T0 + 10))
    );
    assert!(r.json["devices"][1].get("last_seen").is_none(), "Macs only");

    s.set_time(T0 + 20);
    ws.send(WsMessage::Text(r#"{"type":"bye","reason":"sleep"}"#.into()))
        .await
        .unwrap();
    wait_offline(&s, &mac.group_id).await;
    let r = phone.get("/v2/status").await;
    assert_eq!(r.json["mac_online"], false);
    assert_eq!(r.json["mac_last_seen"], T0 + 20);
    // Only registered devices may ask.
    let stranger = mac.as_device(&id128(9));
    assert_eq!(stranger.get("/v2/status").await.status, 403);
}

#[tokio::test]
async fn bye_pushes_offline_immediately_then_back_online_replaces_it() {
    let (_d, s) = server(&[]).await;
    let (mac, _phone) = setup(&s, 160).await;
    let mut ws = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws).await;
    assert!(
        s.mock().pushes().is_empty(),
        "first connect is not announced"
    );

    ws.send(WsMessage::Text(r#"{"type":"bye","reason":"quit"}"#.into()))
        .await
        .unwrap();
    let pushes = wait_pushes(&s, 1).await;
    let p = &pushes[0];
    assert_eq!(p.device_token, TOKEN_A);
    assert_eq!(p.collapse_id.as_deref(), Some("mc-presence"));
    assert_eq!(p.priority, 10);
    assert_eq!(p.expiration, T0 + 3600);
    assert_eq!(
        p.payload,
        json!({
            "aps": {
                "alert": {"title": "MetricCupid is offline on your Mac",
                          "body": "MetricCupid was quit. Alerts won't reach this iPhone until it's back."},
                "category": "MC_PRESENCE",
                "thread-id": "mc-presence",
                "sound": "default",
                "interruption-level": "time-sensitive"
            },
            "mc_presence": {"state": "offline", "reason": "quit", "since": T0}
        })
    );
    // The server closed the stream with 1000 "bye".
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(WsMessage::Close(Some(f)))) => return f.reason.to_string(),
                Some(Ok(_)) => continue,
                _ => return String::new(),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(closed, "bye");
    tick(&s).await;
    assert_eq!(s.mock().pushes().len(), 1, "no second offline push");

    s.set_time(T0 + 600);
    let mut ws = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws).await;
    let pushes = wait_pushes(&s, 2).await;
    let p = &pushes[1];
    assert_eq!(
        p.collapse_id.as_deref(),
        Some("mc-presence"),
        "replaces the offline one"
    );
    assert_eq!(p.priority, 5);
    assert_eq!(p.payload["aps"]["interruption-level"], "passive");
    assert!(p.payload["aps"].get("sound").is_none());
    assert_eq!(
        p.payload["aps"]["alert"]["title"],
        "MetricCupid is back online"
    );
    assert_eq!(
        p.payload["mc_presence"],
        json!({"state": "online", "since": T0 + 600})
    );

    // Replacing the stream (reconnect) while online: nothing new.
    s.set_time(T0 + 601);
    let mut ws2 = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws2).await;
    tick(&s).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(s.mock().pushes().len(), 2);
    drop(ws);
}

#[tokio::test]
async fn dropped_stream_pushes_after_grace_unless_it_reconnects() {
    let (_d, s) = server(&[]).await;
    let (mac, _phone) = setup(&s, 165).await;

    // Reconnect within the grace period: no push.
    let mut ws = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws).await;
    ws.close(None).await.unwrap();
    wait_offline(&s, &mac.group_id).await;
    s.set_time(T0 + 60);
    tick(&s).await;
    let mut ws = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws).await;
    s.set_time(T0 + 1000);
    tick(&s).await;
    assert!(s.mock().pushes().is_empty(), "flap within grace is silent");

    // Lost for longer than MAC_OFFLINE_GRACE_SECS (120): one push.
    ws.close(None).await.unwrap();
    wait_offline(&s, &mac.group_id).await;
    s.set_time(T0 + 1119);
    tick(&s).await;
    assert!(s.mock().pushes().is_empty(), "still within grace");
    s.set_time(T0 + 1120);
    tick(&s).await;
    let pushes = s.mock().pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(
        pushes[0].payload["mc_presence"],
        json!({"state": "offline", "reason": "lost", "since": T0 + 1000})
    );
    assert_eq!(
        pushes[0].payload["aps"]["alert"]["body"],
        "The connection to your Mac was lost. Alerts won't reach this iPhone until it's back."
    );
    s.set_time(T0 + 5000);
    tick(&s).await;
    assert_eq!(s.mock().pushes().len(), 1, "no duplicates");
}

#[tokio::test]
async fn second_mac_keeps_the_group_online_and_bad_bye_is_rejected() {
    let (_d, s) = server(&[("MAC_OFFLINE_GRACE_SECS", "0")]).await;
    let (mac, _phone) = setup(&s, 175).await;
    let mac2 = mac.as_device(&id128(179));
    assert_eq!(mac2.register("mac", "Mac mini", None).await.status, 201);
    let mut a = open_ws(&mac).await.unwrap();
    wait_ready(&mut a).await;
    let mut b = open_ws(&mac2).await.unwrap();
    wait_ready(&mut b).await;
    a.send(WsMessage::Text(r#"{"type":"bye","reason":"quit"}"#.into()))
        .await
        .unwrap();
    s.set_time(T0 + 10);
    tick(&s).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(s.mock().pushes().is_empty(), "another Mac is still online");

    // An unknown reason is an invalid frame: closed, treated as lost (grace 0).
    b.send(WsMessage::Text(r#"{"type":"bye","reason":"lost"}"#.into()))
        .await
        .unwrap();
    wait_offline(&s, &mac.group_id).await;
    tick(&s).await;
    let pushes = s.mock().pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].payload["mc_presence"]["reason"], "lost");
}

#[tokio::test]
async fn presence_goes_through_the_gateway() {
    let (_d1, hosted) = server(&[
        ("MODE", "hosted"),
        ("HOSTED_OPEN_REGISTRATION", "true"),
        ("GATEWAY_OPEN", "true"),
    ])
    .await;
    let (_d2, selfhosted) =
        server(&[("APNS_MODE", "gateway"), ("GATEWAY_URL", &hosted.base)]).await;
    let (mac, _phone) = setup(&selfhosted, 150).await;
    let mut ws = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws).await;
    ws.send(WsMessage::Text(
        r#"{"type":"bye","reason":"disabled"}"#.into(),
    ))
    .await
    .unwrap();
    let pushes = wait_pushes(&hosted, 1).await;
    assert_eq!(pushes[0].collapse_id.as_deref(), Some("mc-presence"));
    assert_eq!(pushes[0].payload["mc_presence"]["reason"], "disabled");
    assert_eq!(pushes[0].payload["aps"]["category"], "MC_PRESENCE");

    // The gateway accepts exactly one of message / presence.
    let body =
        json!({"device_token": TOKEN_A, "env": "sandbox", "urgency": "normal", "expiration": 0});
    let gw = Client::new(
        &hosted.base,
        &mac.group_id,
        "",
        mac.keys.clone(),
        hosted.now_fn(),
    );
    let r = gw.post("/v2/gateway/push", &body).await;
    assert_eq!(r.status, 400, "{:?}", r.json);
}

// ------------------------------------------------------------ live activity

const ACT_A: &str =
    "acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac";
const START_A: &str =
    "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d";

fn activity_pushes(s: &Server) -> Vec<metriccupid_push::v2::apns::RecordedPush> {
    s.mock()
        .pushes()
        .into_iter()
        .filter(|p| p.push_type == "liveactivity")
        .collect()
}

async fn put_token(phone: &Client, suffix: &str, token: &str, started_at: Option<u64>) -> u16 {
    let mut body = json!({"push_token": token, "apns_env": "sandbox"});
    if let Some(t) = started_at {
        body["started_at"] = json!(t);
    }
    let path = format!("/v2/activities/{}{suffix}", phone.device_id);
    phone.send("PUT", &path, &body.to_string()).await.status
}

fn activity_state(critical: u32, warning: u32) -> Value {
    json!({"event": "update", "state": {"critical": critical, "warning": warning, "unknown": 0}})
}

#[tokio::test]
async fn activity_token_endpoints_auth_and_validation() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 200).await;
    assert_eq!(put_token(&phone, "", ACT_A, None).await, 201);
    // A byte-identical request in the same second would be a replay (5.1).
    s.set_time(T0 + 1);
    assert_eq!(put_token(&phone, "", ACT_A, None).await, 200, "replace");
    assert_eq!(put_token(&phone, "/start-token", START_A, None).await, 201);
    assert_eq!(put_token(&phone, "", "abc", None).await, 400);
    assert_eq!(put_token(&phone, "", &"g".repeat(64), None).await, 400);
    // Macs don't have activities; a phone registers only itself.
    let path = format!("/v2/activities/{}", mac.device_id);
    let body = json!({"push_token": ACT_A}).to_string();
    assert_eq!(mac.send("PUT", &path, &body).await.status, 403);
    assert_eq!(phone.send("PUT", &path, &body).await.status, 400);
    let stranger = phone.as_device(&id128(209));
    assert_eq!(put_token(&stranger, "", ACT_A, None).await, 403);
    let mut forged = phone.clone();
    forged.keys = derive(&[99; 32]);
    assert_eq!(put_token(&forged, "", ACT_A, None).await, 401);
    let unknown = json!({"push_token": ACT_A, "extra": 1}).to_string();
    let own = format!("/v2/activities/{}", phone.device_id);
    assert_eq!(phone.send("PUT", &own, &unknown).await.status, 400);

    assert_eq!(phone.send("DELETE", &own, "").await.status, 204);
    s.set_time(T0 + 2);
    assert_eq!(phone.send("DELETE", &own, "").await.status, 404);
    let start = format!("{own}/start-token");
    assert_eq!(phone.send("DELETE", &start, "").await.status, 204);

    // Deleting the device drops its activity tokens.
    s.set_time(T0 + 3);
    assert_eq!(put_token(&phone, "", ACT_A, None).await, 201);
    assert_eq!(
        mac.send("DELETE", &format!("/v2/devices/{}", phone.device_id), "")
            .await
            .status,
        204
    );
    let g = mac.group_id.clone();
    let left = s
        .state
        .v2()
        .store
        .call(move |c| store::activity_tokens(c, &g))
        .await
        .unwrap();
    assert!(left.is_empty());
}

#[tokio::test]
async fn activity_state_pushes_liveactivity_payload() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 210).await;
    assert_eq!(put_token(&phone, "", ACT_A, None).await, 201);
    let body = json!({"event": "update", "stale_secs": 2400, "state": {
        "critical": 2, "warning": 3, "unknown": 1, "mac_online": true,
        "lines": [{"severity": "critical", "text": "web01 · disk"}]}});
    let r = mac.post("/v2/activity-state", &body).await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(
        r.json,
        json!({"status": "sent", "pushed": 1, "started": 0, "failed": 0, "unregistered": 0})
    );
    let pushes = activity_pushes(&s);
    assert_eq!(pushes.len(), 1);
    let p = &pushes[0];
    assert_eq!(p.device_token, ACT_A);
    assert_eq!(p.topic_suffix, ".push-type.liveactivity");
    assert_eq!(p.priority, 10, "critical went up");
    assert_eq!(p.expiration, T0 + 3600);
    assert_eq!(p.collapse_id, None);
    assert_eq!(
        p.payload,
        json!({"aps": {
            "timestamp": T0, "event": "update", "relevance-score": 100, "stale-date": T0 + 2400,
            "content-state": {"critical": 2, "warning": 3, "unknown": 1, "mac_online": true,
                              "updated_at": T0,
                              "lines": [{"severity": "critical", "text": "web01 · disk"}]}}})
    );
    // Normal alert pushes are unchanged.
    mac.post("/v2/messages", &alert_body(&mac, "a-1", "normal", 10))
        .await;
    let alert = s.mock().pushes().into_iter().last().unwrap();
    assert_eq!((alert.push_type, alert.topic_suffix), ("alert", ""));

    // Only Macs post state; validation.
    assert_eq!(
        phone
            .post("/v2/activity-state", &activity_state(1, 0))
            .await
            .status,
        403
    );
    let mut bad = activity_state(1, 0);
    bad["event"] = json!("start");
    assert_eq!(mac.post("/v2/activity-state", &bad).await.status, 400);
    let mut bad = activity_state(1, 0);
    bad["state"]["lines"] = json!(vec![json!({"severity": "warning", "text": "x"}); 5]);
    assert_eq!(mac.post("/v2/activity-state", &bad).await.status, 400);
    let mut bad = activity_state(1, 0);
    bad["state"]["lines"] = json!([{"severity": "warning", "text": "x".repeat(41)}]);
    assert_eq!(mac.post("/v2/activity-state", &bad).await.status, 400);
    let mut bad = activity_state(1, 0);
    bad["stale_secs"] = json!(10);
    assert_eq!(mac.post("/v2/activity-state", &bad).await.status, 400);
    let mut bad = activity_state(1, 0);
    bad["state"]["host"] = json!("web01");
    assert_eq!(mac.post("/v2/activity-state", &bad).await.status, 400);
    assert_eq!(activity_pushes(&s).len(), 1, "nothing else was pushed");
}

#[tokio::test]
async fn activity_updates_are_coalesced_and_rate_limited() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 220).await;
    put_token(&phone, "", ACT_A, None).await;
    let r = mac.post("/v2/activity-state", &activity_state(3, 0)).await;
    assert_eq!(r.json["status"], "sent");
    s.set_time(T0 + 1);
    let r = mac.post("/v2/activity-state", &activity_state(3, 1)).await;
    assert_eq!(
        r.json,
        json!({"status": "coalesced", "send_in": 4}),
        "{:?}",
        r.json
    );
    s.set_time(T0 + 2);
    mac.post("/v2/activity-state", &activity_state(1, 4)).await;
    metriccupid_push::v2::activity_tick(&s.state).await;
    assert_eq!(activity_pushes(&s).len(), 1, "not due yet");
    s.set_time(T0 + 5);
    metriccupid_push::v2::activity_tick(&s.state).await;
    let pushes = activity_pushes(&s);
    assert_eq!(pushes.len(), 2, "one push for both coalesced states");
    let cs = &pushes[1].payload["aps"]["content-state"];
    assert_eq!(
        (cs["critical"].clone(), cs["warning"].clone()),
        (json!(1), json!(4))
    );
    assert_eq!(
        cs["updated_at"],
        T0 + 2,
        "when the Mac sent the latest state"
    );
    assert_eq!(pushes[1].payload["aps"]["timestamp"], T0 + 5);
    assert_eq!(pushes[1].priority, 5, "routine update");
    metriccupid_push::v2::activity_tick(&s.state).await;
    assert_eq!(activity_pushes(&s).len(), 2, "sent once");

    // Per group: burst 10, then one per 5 s (3 used above).
    for i in 0..7 {
        let r = mac.post("/v2/activity-state", &activity_state(i, 0)).await;
        assert_eq!(r.status, 200, "{i}: {:?}", r.json);
    }
    let r = mac.post("/v2/activity-state", &activity_state(9, 0)).await;
    assert_eq!(r.status, 429);
    assert!(r.headers.contains_key("retry-after"));
}

#[tokio::test]
async fn activity_end_dismisses_and_forgets_tokens() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 230).await;
    put_token(&phone, "", ACT_A, None).await;
    mac.post("/v2/activity-state", &activity_state(1, 0)).await;
    // `end` is never coalesced.
    let mut end = activity_state(0, 0);
    end["event"] = json!("end");
    let r = mac.post("/v2/activity-state", &end).await;
    assert_eq!(r.json["pushed"], 1, "{:?}", r.json);
    let p = activity_pushes(&s).pop().unwrap();
    assert_eq!(p.payload["aps"]["event"], "end");
    assert_eq!(p.payload["aps"]["dismissal-date"], T0);
    assert_eq!(p.payload["aps"]["timestamp"], T0 + 1, "after the update");
    assert!(p.payload["aps"].get("stale-date").is_none());
    assert_eq!(p.priority, 10);
    s.set_time(T0 + 10);
    let r = mac.post("/v2/activity-state", &activity_state(1, 0)).await;
    assert_eq!(r.json["pushed"], 0, "ended activity's token was dropped");
}

#[tokio::test]
async fn mac_offline_and_back_update_the_activity() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 240).await;
    put_token(&phone, "", ACT_A, None).await;
    let mut ws = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws).await;
    mac.post("/v2/activity-state", &activity_state(2, 1)).await;
    s.set_time(T0 + 10);
    ws.send(WsMessage::Text(r#"{"type":"bye","reason":"quit"}"#.into()))
        .await
        .unwrap();
    // Presence alert + activity update.
    let pushes = wait_pushes(&s, 3).await;
    assert!(pushes
        .iter()
        .any(|p| p.payload.get("mc_presence").is_some()));
    let a = activity_pushes(&s).pop().unwrap();
    let cs = &a.payload["aps"]["content-state"];
    assert_eq!(cs["mac_online"], false);
    assert_eq!(cs["critical"], 2, "last known counts kept");
    assert_eq!(cs["updated_at"], T0);
    assert_eq!(a.priority, 5);

    s.set_time(T0 + 20);
    let mut ws = open_ws(&mac).await.unwrap();
    wait_ready(&mut ws).await;
    let pushes = wait_pushes(&s, 5).await;
    let a = pushes
        .iter()
        .rev()
        .find(|p| p.push_type == "liveactivity")
        .unwrap();
    assert_eq!(a.payload["aps"]["content-state"]["mac_online"], true);
}

#[tokio::test]
async fn push_to_start_when_critical_and_no_running_activity() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 250).await;
    assert_eq!(put_token(&phone, "/start-token", START_A, None).await, 201);
    let r = mac.post("/v2/activity-state", &activity_state(0, 3)).await;
    assert_eq!(r.json["started"], 0, "nothing critical");
    s.set_time(T0 + 5);
    let r = mac.post("/v2/activity-state", &activity_state(1, 3)).await;
    assert_eq!(r.json["started"], 1, "{:?}", r.json);
    let p = activity_pushes(&s).pop().unwrap();
    assert_eq!(p.device_token, START_A);
    assert_eq!(p.priority, 10);
    let aps = &p.payload["aps"];
    assert_eq!(aps["event"], "start");
    assert_eq!(aps["attributes-type"], "AlertsActivityAttributes");
    assert_eq!(aps["attributes"], json!({}));
    assert_eq!(
        aps["alert"],
        json!({"title": "MetricCupid", "body": "1 critical alert"})
    );
    assert_eq!(aps["content-state"]["critical"], 1);
    // Not again while that activity may be running.
    s.set_time(T0 + 10);
    let r = mac.post("/v2/activity-state", &activity_state(2, 3)).await;
    assert_eq!(
        (r.json["started"].clone(), r.json["pushed"].clone()),
        (json!(0), json!(0))
    );
    // The started activity registers its token: it gets the updates.
    assert_eq!(put_token(&phone, "", ACT_A, Some(T0 + 5)).await, 201);
    s.set_time(T0 + 15);
    let r = mac.post("/v2/activity-state", &activity_state(2, 4)).await;
    assert_eq!(
        (r.json["started"].clone(), r.json["pushed"].clone()),
        (json!(0), json!(1))
    );
    // iOS ends activities after 8 h: the token is dropped, a new one is started.
    s.set_time(T0 + 5 + 8 * 3600);
    let r = mac.post("/v2/activity-state", &activity_state(2, 5)).await;
    assert_eq!(
        (r.json["started"].clone(), r.json["pushed"].clone()),
        (json!(1), json!(0))
    );
}

#[tokio::test]
async fn unregistered_activity_token_is_removed() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 15).await;
    put_token(&phone, "", ACT_A, None).await;
    s.mock().mark_unregistered(ACT_A);
    let r = mac.post("/v2/activity-state", &activity_state(1, 0)).await;
    assert_eq!(r.json["unregistered"], 1, "{:?}", r.json);
    let g = mac.group_id.clone();
    let left = s
        .state
        .v2()
        .store
        .call(move |c| store::activity_tokens(c, &g))
        .await
        .unwrap();
    assert!(left.is_empty());
}

#[tokio::test]
async fn summary_is_stored_not_pushed_and_only_the_newest_kept() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 25).await;
    let summary = |id: &str| {
        let pt = json!({"v": 1, "type": "summary", "id": id, "ts": T0, "critical": 1, "warning": 0,
                        "unknown": 0, "top": []});
        json!({"id": id, "type": "summary", "sealed": mac.seal_json("summary", id, &pt, [3; 12]),
               "urgency": "silent", "ttl_secs": 86400})
    };
    let r = mac.post("/v2/messages", &summary("s-1")).await;
    assert_eq!(r.json["status"], "stored", "{:?}", r.json);
    assert_eq!(r.json["pushed"], 0);
    mac.post("/v2/messages", &summary("s-2")).await;
    assert!(s.mock().pushes().is_empty());
    let r = phone.get("/v2/messages?since=0").await;
    let msgs = r.json["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        (msgs[0]["id"].clone(), msgs[0]["type"].clone()),
        (json!("s-2"), json!("summary"))
    );
}

#[tokio::test]
async fn activity_goes_through_the_gateway() {
    let (_d1, hosted) = server(&[
        ("MODE", "hosted"),
        ("HOSTED_OPEN_REGISTRATION", "true"),
        ("GATEWAY_OPEN", "true"),
    ])
    .await;
    let (_d2, selfhosted) =
        server(&[("APNS_MODE", "gateway"), ("GATEWAY_URL", &hosted.base)]).await;
    let (mac, phone) = setup(&selfhosted, 35).await;
    put_token(&phone, "", ACT_A, None).await;
    let r = mac.post("/v2/activity-state", &activity_state(1, 2)).await;
    assert_eq!(r.json["pushed"], 1, "{:?}", r.json);
    let p = activity_pushes(&hosted).pop().unwrap();
    assert_eq!(p.device_token, ACT_A);
    assert_eq!(p.topic_suffix, ".push-type.liveactivity");
    assert_eq!(p.priority, 10);
    assert_eq!(p.payload["aps"]["content-state"]["warning"], 2);

    // The gateway validates the activity like the server does.
    let gw = Client::new(
        &hosted.base,
        &mac.group_id,
        "",
        mac.keys.clone(),
        hosted.now_fn(),
    );
    let state = json!({"critical": 1, "warning": 0, "unknown": 0, "mac_online": true,
                       "updated_at": T0, "lines": vec![json!({"severity": "critical", "text": "x"}); 5]});
    let job = json!({"device_token": ACT_A, "env": "sandbox", "urgency": "silent", "expiration": 0,
                     "activity": {"event": "update", "timestamp": T0, "state": state}});
    assert_eq!(gw.post("/v2/gateway/push", &job).await.status, 400);
    let mut far = job.clone();
    far["activity"]["state"]["lines"] = json!([]);
    far["activity"]["timestamp"] = json!(T0 + 2 * 86_400);
    assert_eq!(gw.post("/v2/gateway/push", &far).await.status, 400);
    // A summary is never pushed, so the gateway refuses one.
    let summary = json!({"device_token": TOKEN_A, "env": "sandbox", "urgency": "silent", "expiration": 0,
                         "message": {"id": "s", "t": "summary", "s": STANDARD.encode([0u8; 28])}});
    assert_eq!(gw.post("/v2/gateway/push", &summary).await.status, 400);
}

#[tokio::test]
async fn direct_sender_uses_liveactivity_topic_and_push_type() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let apple = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/3/device/{ACT_A}")))
        .and(header(
            "apns-topic",
            "cat.sysop.MetricCupid.push-type.liveactivity",
        ))
        .and(header("apns-push-type", "liveactivity"))
        .and(header("apns-priority", "10"))
        .and(header("apns-expiration", (T0 + 3600).to_string().as_str()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&apple)
        .await;
    let (_d, s) = server(&[
        ("APNS_MODE", "direct"),
        ("APNS_KEY_P8", TEST_P8),
        ("APNS_KEY_ID", "ABCDE12345"),
        ("APNS_TEAM_ID", "TEAM123456"),
        ("APNS_SANDBOX_URL", &apple.uri()),
        ("APNS_PRODUCTION_URL", "http://127.0.0.1:1"),
    ])
    .await;
    let (mac, phone) = setup(&s, 45).await;
    put_token(&phone, "", ACT_A, None).await;
    let r = mac.post("/v2/activity-state", &activity_state(1, 0)).await;
    assert_eq!(r.json["pushed"], 1, "{:?}", r.json);
    let reqs = apple.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(body["aps"]["event"], "update");
    assert!(body.get("mc").is_none(), "no sealed envelope");
}

// ---------------------------------------------------------------- licences

const HOSTED: &[(&str, &str)] = &[("MODE", "hosted"), ("LICENCE_MODE", "app_transaction")];

fn lic(id: &str) -> Value {
    common::licence::licence(id, T0)
}

#[tokio::test]
async fn hosted_group_needs_a_valid_licence() {
    let (_d, s) = server(HOSTED).await;
    let mac = s.group(10);
    let r = mac.create_group().await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (402, Some("licence_required"))
    );

    let r = mac
        .create_group_with(json!({"licence": {"kind": "subscription", "jws": "x"}}))
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(
        r.json,
        json!({"error": "licence_invalid", "reason": "unsupported_kind"})
    );
    let r = mac
        .create_group_with(json!({"licence": {"kind": "app_transaction", "jws": "a.b.c"}}))
        .await;
    assert_eq!(
        (r.status, r.json["reason"].as_str()),
        (403, Some("malformed"))
    );
    let other = common::licence::Chain::build(&Default::default());
    let foreign = other.sign(&common::licence::app_transaction("1", T0));
    let r = mac
        .create_group_with(json!({"licence": {"kind": "app_transaction", "jws": foreign}}))
        .await;
    assert_eq!(
        (r.status, r.json["reason"].as_str()),
        (403, Some("untrusted_root"))
    );
    assert!(
        !r.json.to_string().contains(&foreign[..20]),
        "never echoes the JWS"
    );

    let r = mac
        .create_group_with(json!({"licence": lic("p-200")}))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    assert_eq!(
        r.json["licence"],
        json!({"tier": "founder", "environment": "production", "verified_at": T0})
    );
    // Idempotent retry with the licence.
    let r = mac
        .create_group_with(json!({"licence": lic("p-200")}))
        .await;
    assert_eq!((r.status, r.json["status"].as_str()), (200, Some("exists")));

    assert_eq!(mac.register("mac", "Mac", None).await.status, 201);
    let r = mac.get("/v2/status").await;
    assert_eq!(r.json["licence"]["tier"], "founder");
    assert_eq!(r.json["licence_required"], false);
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "m1", "normal", 10))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
}

#[tokio::test]
async fn one_purchase_links_at_most_three_groups_and_delete_frees_one() {
    let (_d, s) = server(HOSTED).await;
    for seed in [20, 23, 26] {
        let r = s
            .group(seed)
            .create_group_with(json!({"licence": lic("shared")}))
            .await;
        assert_eq!(r.status, 201, "{:?}", r.json);
    }
    let fourth = s.group(29);
    let r = fourth
        .create_group_with(json!({"licence": lic("shared")}))
        .await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (403, Some("licence_in_use"))
    );
    let g = fourth.group_id.clone();
    let key = s
        .state
        .v2()
        .store
        .call(move |c| store::group_key(c, &g))
        .await
        .unwrap();
    assert_eq!(key, None, "the refused group was not created");
    // Another purchase is fine.
    assert_eq!(
        s.group(32)
            .create_group_with(json!({"licence": lic("other")}))
            .await
            .status,
        201
    );

    // DELETE /v2/groups: Macs only, signed, removes everything.
    let first = s.group(20);
    assert_eq!(first.register("mac", "Mac", None).await.status, 201);
    let phone = first.as_device(&id128(22));
    assert_eq!(
        phone.register("ios", "iPhone", Some(TOKEN_A)).await.status,
        201
    );
    let mut ws = open_ws(&first).await.unwrap();
    wait_ready(&mut ws).await;
    assert_eq!(phone.send("DELETE", "/v2/groups", "").await.status, 403);
    assert_eq!(first.send("DELETE", "/v2/groups", "").await.status, 204);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match ws.next().await {
                    None | Some(Err(_)) | Some(Ok(WsMessage::Close(_))) => break,
                    _ => {}
                }
            }
        })
        .await
        .is_ok(),
        "stream closed"
    );
    assert_eq!(first.get("/v2/status").await.status, 401, "group is gone");

    let r = fourth
        .create_group_with(json!({"licence": lic("shared")}))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
}

/// A group created during the open beta, without a licence.
async fn beta_group(s: &Server, seed: u8) -> (Client, Client) {
    let mac = s.group(seed);
    let (g, key) = (mac.group_id.clone(), mac.keys.auth);
    s.state
        .v2()
        .store
        .call(move |c| store::create_group(c, &g, &key, T0))
        .await
        .unwrap();
    assert_eq!(mac.register("mac", "Mac", None).await.status, 201);
    let phone = mac.as_device(&id128(seed.wrapping_add(2)));
    assert_eq!(
        phone.register("ios", "iPhone", Some(TOKEN_A)).await.status,
        201
    );
    (mac, phone)
}

#[tokio::test]
async fn unlicensed_group_can_read_but_not_send_until_put_licence() {
    let (_d, s) = server(HOSTED).await;
    let (mac, phone) = beta_group(&s, 40).await;

    let r = phone.get("/v2/status").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json["licence"], Value::Null);
    assert_eq!(r.json["licence_required"], true);
    assert_eq!(mac.get("/v2/messages").await.status, 200);
    let mut ws = open_ws(&mac).await.expect("stream still works");
    wait_ready(&mut ws).await;

    let r = mac
        .post("/v2/messages", &alert_body(&mac, "u1", "critical", 10))
        .await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (402, Some("licence_required"))
    );
    let r = phone
        .post("/v2/commands", &command_body(&phone, "c1"))
        .await;
    assert_eq!(r.status, 402);
    let r = mac
        .post(
            "/v2/activity-state",
            &json!({"event": "update", "state": {"critical": 1, "warning": 0, "unknown": 0}}),
        )
        .await;
    assert_eq!(r.status, 402);
    assert!(s.mock().pushes().is_empty());

    let r = mac
        .send(
            "PUT",
            "/v2/licence",
            &json!({"kind": "app_transaction", "jws": "x"}).to_string(),
        )
        .await;
    assert_eq!(
        (r.status, r.json["reason"].as_str()),
        (403, Some("malformed"))
    );
    let r = mac
        .send("PUT", "/v2/licence", &lic("p-230").to_string())
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["status"], "attached");
    assert_eq!(r.json["licence"]["tier"], "founder");
    s.set_time(T0 + 5);
    let r = mac
        .send("PUT", "/v2/licence", &lic("p-230").to_string())
        .await;
    assert_eq!(r.json["status"], "refreshed");
    assert_eq!(
        phone.get("/v2/status").await.json["licence"]["verified_at"],
        T0 + 5
    );

    let r = mac
        .post("/v2/messages", &alert_body(&mac, "u2", "critical", 10))
        .await;
    assert_eq!(r.json["pushed"], 1, "{:?}", r.json);
    assert_eq!(
        phone
            .post("/v2/commands", &command_body(&phone, "c2"))
            .await
            .status,
        200
    );

    // The cap applies to PUT too.
    for seed in [43, 46] {
        let (m, _) = beta_group(&s, seed).await;
        assert_eq!(
            m.send("PUT", "/v2/licence", &lic("p-230").to_string())
                .await
                .status,
            200
        );
    }
    let (m, _) = beta_group(&s, 49).await;
    let r = m
        .send("PUT", "/v2/licence", &lic("p-230").to_string())
        .await;
    assert_eq!(
        (r.status, r.json["error"].as_str()),
        (403, Some("licence_in_use"))
    );
}

#[tokio::test]
async fn grace_period_lets_beta_groups_send_until_it_ends() {
    let grace = T0 + 3600;
    let until = "2023-11-14T23:13:20Z"; // T0 + 3600
    assert_eq!(metriccupid_push::config::parse_rfc3339(until), Some(grace));
    let (_d, s) = server(&[
        ("MODE", "hosted"),
        ("LICENCE_MODE", "app_transaction"),
        ("LICENCE_GRACE_UNTIL", until),
    ])
    .await;
    // New groups still need a licence during the grace period.
    assert_eq!(s.group(50).create_group().await.status, 402);
    let (mac, _phone) = beta_group(&s, 52).await;
    let r = mac.get("/v2/status").await;
    assert_eq!(r.json["licence_required"], false);
    assert_eq!(r.json["licence_grace_until"], grace);
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "g1", "normal", 10))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);

    s.set_time(grace);
    assert_eq!(mac.get("/v2/status").await.json["licence_required"], true);
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "g2", "normal", 10))
        .await;
    assert_eq!(r.status, 402);
}

#[tokio::test]
async fn open_mode_accepts_any_group_and_records_valid_licences() {
    let (_d, s) = server(&[("MODE", "hosted"), ("HOSTED_OPEN_REGISTRATION", "true")]).await;
    let r = s.group(60).create_group().await;
    assert_eq!(r.status, 201);
    assert_eq!(r.json["licence"], Value::Null);
    let r = s
        .group(62)
        .create_group_with(json!({"licence": {"kind": "app_transaction", "jws": "a.b.c"}}))
        .await;
    assert_eq!(r.status, 201, "a bad licence does not block the open beta");
    assert_eq!(r.json["licence"], Value::Null);
    let mac = s.group(64);
    let r = mac
        .create_group_with(json!({"licence": lic("p-254")}))
        .await;
    assert_eq!(r.json["licence"]["tier"], "founder");
    assert_eq!(mac.register("mac", "Mac", None).await.status, 201);
    let r = mac.get("/v2/status").await;
    assert_eq!(r.json["licence"]["tier"], "founder");
    assert_eq!(r.json["licence_required"], false);
    assert_eq!(r.json["licence_grace_until"], Value::Null);
    let (beta, _) = beta_group(&s, 66).await;
    assert_eq!(beta.get("/v2/status").await.json["licence_required"], false);
    let r = beta
        .post("/v2/messages", &alert_body(&beta, "o1", "normal", 10))
        .await;
    assert_eq!(r.status, 200);
    // PUT /v2/licence works in open mode, so beta groups can attach early.
    let r = beta
        .send("PUT", "/v2/licence", &lic("p-256").to_string())
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
}

#[tokio::test]
async fn self_hosted_never_requires_a_licence() {
    let (_d, s) = server(&[]).await;
    let (mac, _phone) = setup(&s, 70).await;
    let r = mac.get("/v2/status").await;
    assert_eq!(r.json["licence"], Value::Null);
    assert_eq!(r.json["licence_required"], false);
    let r = mac
        .post("/v2/messages", &alert_body(&mac, "s1", "normal", 10))
        .await;
    assert_eq!(r.status, 200);
    // Not even a broken licence is looked at; PUT /v2/licence does not exist.
    let r = s
        .group(72)
        .create_group_with(json!({"licence": {"kind": "app_transaction", "jws": "x"}}))
        .await;
    assert_eq!(r.status, 201);
    assert_eq!(
        mac.send("PUT", "/v2/licence", &lic("x").to_string())
            .await
            .status,
        404
    );
}

#[tokio::test]
async fn sandbox_transactions_follow_licence_allow_sandbox() {
    let sandbox = || {
        let mut p = common::licence::app_transaction("tf-1", T0);
        p["receiptType"] = json!("Sandbox");
        json!({"kind": "app_transaction", "jws": common::licence::CHAIN.sign(&p)})
    };
    let (_d, s) = server(HOSTED).await;
    let r = s
        .group(80)
        .create_group_with(json!({"licence": sandbox()}))
        .await;
    assert_eq!(r.json["licence"]["environment"], "sandbox", "{:?}", r.json);
    let (_d, s) = server(&[
        ("MODE", "hosted"),
        ("LICENCE_MODE", "app_transaction"),
        ("LICENCE_ALLOW_SANDBOX", "false"),
    ])
    .await;
    let r = s
        .group(82)
        .create_group_with(json!({"licence": sandbox()}))
        .await;
    assert_eq!(
        (r.status, r.json["reason"].as_str()),
        (403, Some("environment"))
    );
}

#[tokio::test]
async fn licences_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(T0)));
    let s = server_at(dir.path(), HOSTED, clock.clone()).await;
    let mac = s.group(90);
    assert_eq!(
        mac.create_group_with(json!({"licence": lic("p-280")}))
            .await
            .status,
        201
    );
    s.stop().await;
    let s = server_at(dir.path(), HOSTED, clock).await;
    let mac = Client {
        base: s.base.clone(),
        ..mac
    };
    assert_eq!(mac.register("mac", "Mac", None).await.status, 201);
    assert_eq!(
        mac.get("/v2/status").await.json["licence"]["tier"],
        "founder"
    );
}

fn snapshot_body(mac: &Client, id: &str, items: usize) -> Value {
    let pt = json!({"v": 1, "type": "snapshot", "id": id, "ts": T0, "compressed": true,
                    "items": "x".repeat(items)});
    json!({"id": id, "sealed": mac.seal_json("snapshot", id, &pt, [4; 12])})
}

#[tokio::test]
async fn snapshot_replaces_is_never_pushed_nor_in_the_mailbox() {
    let (_d, s) = server(&[]).await;
    let (mac, phone) = setup(&s, 27).await;
    let r = phone.get("/v2/snapshot").await;
    assert_eq!(r.status, 204, "{:?}", r.json);

    // 100 KB of sealed data: far above the 16 KB of the other routes.
    let r = mac
        .post("/v2/snapshot", &snapshot_body(&mac, "snap-1", 100_000))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["status"], "stored");
    let r = mac
        .post("/v2/snapshot", &snapshot_body(&mac, "snap-1", 10))
        .await;
    assert_eq!(r.json["status"], "duplicate");
    let r = mac
        .post("/v2/snapshot", &snapshot_body(&mac, "snap-2", 10))
        .await;
    assert_eq!(r.json["status"], "stored");
    assert!(s.mock().pushes().is_empty());

    let r = phone.get("/v2/snapshot").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json["id"], "snap-2");
    assert_eq!(r.json["ts"], T0);
    let sealed = r.json["sealed"].as_str().unwrap();
    let pt = common::open(
        &mac.keys.enc,
        &common::aad(&mac.group_id, "snapshot", "snap-2"),
        sealed,
    )
    .expect("opens with the snapshot AAD");
    let pt: Value = serde_json::from_slice(&pt).unwrap();
    assert_eq!(pt["type"], "snapshot");
    // The Mac may read it too.
    assert_eq!(mac.get("/v2/snapshot").await.status, 200);

    let r = phone.get("/v2/messages?since=0").await;
    assert!(r.json["messages"].as_array().unwrap().is_empty());
    // `snapshot` is not a mailbox type.
    let r = mac
        .post(
            "/v2/messages",
            &json!({"id": "x", "type": "snapshot", "sealed": mac.seal_json("snapshot", "x", &json!({}), [5; 12]),
                    "urgency": "silent"}),
        )
        .await;
    assert_eq!(r.status, 400);
}

#[tokio::test]
async fn snapshot_validation_size_and_sender_kind() {
    let (_d, s) = server(&[("V2_SNAPSHOT_MAX_BYTES", "32768")]).await;
    let (mac, phone) = setup(&s, 29).await;
    // Phones cannot post snapshots.
    let r = phone
        .post("/v2/snapshot", &snapshot_body(&phone, "p", 10))
        .await;
    assert_eq!(r.status, 403);
    let r = mac
        .post("/v2/snapshot", &json!({"id": "bad id", "sealed": "AAAA"}))
        .await;
    assert_eq!(r.status, 400);
    let r = mac
        .post("/v2/snapshot", &json!({"id": "a", "sealed": "not base64!"}))
        .await;
    assert_eq!(r.status, 400);
    let r = mac
        .post(
            "/v2/snapshot",
            &json!({"id": "a", "sealed": "AAAA", "extra": 1}),
        )
        .await;
    assert_eq!(r.status, 400);
    // Above V2_SNAPSHOT_MAX_BYTES but within the body limit: 413 from the handler.
    let r = mac
        .post("/v2/snapshot", &snapshot_body(&mac, "big", 24_900))
        .await;
    assert_eq!(r.status, 413, "{:?}", r.json);
    // Far above the body limit: 413 from the body limit layer.
    let r = mac
        .post("/v2/snapshot", &snapshot_body(&mac, "huge", 60_000))
        .await;
    assert_eq!(r.status, 413);
    // The larger limit applies only to this route.
    let mut big = alert_body(&mac, "a-big", "normal", 10);
    big["sealed"] =
        json!(mac.seal_json("alert", "a-big", &json!({"x": "y".repeat(20_000)}), [6; 12]));
    assert_eq!(mac.post("/v2/messages", &big).await.status, 413);
}

#[tokio::test]
async fn snapshot_posts_are_rate_limited_per_group() {
    let (_d, s) = server(&[]).await;
    let (mac, _phone) = setup(&s, 31).await;
    for i in 0..5 {
        let r = mac
            .post("/v2/snapshot", &snapshot_body(&mac, &format!("r-{i}"), 10))
            .await;
        assert_eq!(r.status, 200, "burst {i}: {:?}", r.json);
    }
    let r = mac
        .post("/v2/snapshot", &snapshot_body(&mac, "r-5", 10))
        .await;
    assert_eq!(r.status, 429);
    assert!(r.headers.get("retry-after").is_some());
    // Another group has its own bucket.
    let (other, _) = setup(&s, 33).await;
    let r = other
        .post("/v2/snapshot", &snapshot_body(&other, "o-1", 10))
        .await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn closed_gateway_refuses_registrations_and_pushes() {
    // GATEWAY_OPEN defaults to false: the hosted server relays for nobody.
    let (_d1, hosted) = server(&[("MODE", "hosted"), ("HOSTED_OPEN_REGISTRATION", "true")]).await;
    let (_d2, selfhosted) =
        server(&[("APNS_MODE", "gateway"), ("GATEWAY_URL", &hosted.base)]).await;
    // The self-hosted server forwards the registration; the gateway refuses it.
    let r = selfhosted.group(170).create_group().await;
    assert_ne!(r.status, 201, "{:?}", r.json);
    // A direct `gateway: true` registration is refused too.
    let direct = hosted.group(171);
    let r = direct
        .create_group_with(serde_json::json!({ "gateway": true }))
        .await;
    assert_eq!(r.status, 403, "{:?}", r.json);
    assert_eq!(r.json["error"], "gateway_closed");
}
