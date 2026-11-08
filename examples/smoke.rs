//! Smoke test against a running server with `APNS_MODE=mock`:
//!
//!   SMOKE_URL=http://127.0.0.1:8080 cargo run --example smoke
//!
//! Creates a fresh group, registers a Mac and an iPhone, opens the Mac's
//! WebSocket, sends an alert (checks the mock push), sends a command from
//! the phone (checks it arrives on the WebSocket, decrypts it, acks it) and
//! sends the result back. Exits non-zero on the first failure.

#[path = "../tests/common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message;

fn check(ok: bool, what: &str, detail: &Value) {
    if ok {
        println!("ok   {what}");
    } else {
        eprintln!("FAIL {what}: {detail}");
        std::process::exit(1);
    }
}

/// Non-cryptographic uniqueness is enough for a smoke test.
fn seed_bytes(label: &str) -> [u8; 32] {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    Sha256::digest(format!("{label}{t}{}", std::process::id())).into()
}

fn id_from(label: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&seed_bytes(label)[..16])
}

async fn next_text(
    ws: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return serde_json::from_str(t.as_str()).unwrap(),
            Ok(Some(Ok(_))) => continue,
            other => {
                eprintln!("FAIL websocket frame: {other:?}");
                std::process::exit(1);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let base = std::env::var("SMOKE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let keys = common::derive(&seed_bytes("group"));
    let mac = common::Client::new(&base, &id_from("gid"), &id_from("mac"), keys, now);
    let phone = mac.as_device(&id_from("ios"));
    let token = hex::encode(seed_bytes("token"));
    println!("server {base}, group {}", mac.group_id);

    let r = mac.create_group().await;
    check(r.status == 201, "create group", &r.json);
    let r = mac.register("mac", "Smoke Mac", None).await;
    check(r.status == 201, "register mac", &r.json);
    let r = phone.register("ios", "Smoke iPhone", Some(&token)).await;
    check(r.status == 201, "register ios", &r.json);
    let r = mac.get("/v2/devices").await;
    check(
        r.json["devices"].as_array().map(Vec::len) == Some(2),
        "list devices",
        &r.json,
    );

    // Mac opens its stream.
    let mut req = mac.ws_url().into_client_request().unwrap();
    for (k, v) in mac.signed_headers("GET", "/v2/stream", b"") {
        req.headers_mut().insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(&v).unwrap(),
        );
    }
    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .unwrap_or_else(|e| {
            eprintln!("FAIL open websocket: {e}");
            std::process::exit(1);
        });
    let f = next_text(&mut ws).await;
    check(f["type"] == "ready", "websocket ready", &f);

    // Mac -> phones: alert.
    let alert_id = "icinga:smoke01!ping";
    let msg_id = id_from("msg");
    let pt = json!({
        "v": 1, "type": "alert", "id": msg_id, "ts": (mac.now)(), "alert_id": alert_id,
        "title": "smoke01: PING CRITICAL", "host": "smoke01", "service": "ping",
        "severity": "critical", "source": "icinga", "summary": "Packet loss 100%",
        "state": "firing", "actions": ["ack", "mute", "open"],
    });
    let collapse = common::collapse_id(&mac.keys.collapse, alert_id);
    let sealed = mac.seal_json(
        "alert",
        &msg_id,
        &pt,
        seed_bytes("n1")[..12].try_into().unwrap(),
    );
    let r = mac
        .post(
            "/v2/messages",
            &json!({
                "id": msg_id, "type": "alert", "sealed": sealed,
                "collapse_id": collapse, "urgency": "critical", "ttl_secs": 3600,
            }),
        )
        .await;
    check(
        r.status == 200 && r.json["pushed"] == 1,
        "post alert, 1 push",
        &r.json,
    );

    let text = reqwest::get(format!("{base}/v2/debug/pushes"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let pushes: Value = serde_json::from_str(&text).unwrap();
    let push = pushes["pushes"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .rev()
                .find(|p| p["device_token"] == token.as_str())
                .cloned()
        })
        .unwrap_or(Value::Null);
    check(
        push["payload"]["aps"]["category"] == "MC_ALERT"
            && push["payload"]["mc"]["s"] == sealed.as_str()
            && push["collapse_id"] == collapse.as_str(),
        "mock push payload",
        &push,
    );
    let opened = common::open(
        &phone.keys.enc,
        &common::aad(&phone.group_id, "alert", &msg_id),
        &sealed,
    );
    check(opened.is_some(), "phone decrypts the alert", &push);

    // Phone -> Mac: command.
    let cmd_id = id_from("cmd");
    let pt = json!({"v": 1, "type": "command", "id": cmd_id, "ts": (mac.now)(), "action": "mute", "alert_id": alert_id, "duration_secs": 3600});
    let csealed = phone.seal_json(
        "command",
        &cmd_id,
        &pt,
        seed_bytes("n2")[..12].try_into().unwrap(),
    );
    let r = phone
        .post("/v2/commands", &json!({"id": cmd_id, "sealed": csealed}))
        .await;
    check(
        r.json["delivered"] == true,
        "post command, delivered to live stream",
        &r.json,
    );
    let f = next_text(&mut ws).await;
    check(
        f["type"] == "command" && f["id"] == cmd_id.as_str(),
        "command on websocket",
        &f,
    );
    let plain = common::open(
        &mac.keys.enc,
        &common::aad(&mac.group_id, "command", &cmd_id),
        f["sealed"].as_str().unwrap_or(""),
    )
    .and_then(|p| serde_json::from_slice::<Value>(&p).ok())
    .unwrap_or(Value::Null);
    check(
        plain["action"] == "mute",
        "mac decrypts the command",
        &plain,
    );
    ws.send(Message::Text(
        json!({"type": "ack", "cursor": f["cursor"]})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();

    // Mac -> phones: result, same collapse id so it replaces the alert.
    let res_id = id_from("res");
    let pt = json!({"v": 1, "type": "result", "id": res_id, "ts": (mac.now)(), "command_id": cmd_id, "alert_id": alert_id, "ok": true, "message": "Muted for 1 h"});
    let rsealed = mac.seal_json(
        "result",
        &res_id,
        &pt,
        seed_bytes("n3")[..12].try_into().unwrap(),
    );
    let r = mac
        .post("/v2/messages", &json!({"id": res_id, "type": "result", "sealed": rsealed, "collapse_id": collapse, "urgency": "normal", "ttl_secs": 3600}))
        .await;
    check(r.json["pushed"] == 1, "post result", &r.json);

    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = mac.get("/v2/commands?since=0").await;
    check(
        r.json["commands"].as_array().map(Vec::is_empty) == Some(true),
        "ack removed the command",
        &r.json,
    );
    let r = phone.get("/v2/messages?since=0").await;
    check(
        r.json["messages"].as_array().map(Vec::len) == Some(2),
        "phone mailbox has alert + result",
        &r.json,
    );
    println!("smoke test passed");
}
