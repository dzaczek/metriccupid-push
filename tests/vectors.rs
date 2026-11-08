//! Asserts test-vectors/v2.json, which the Swift Mac and iOS apps also use.

mod common;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use metriccupid_push::auth::{sign_v2, Authenticator};
use serde_json::Value;

fn vectors() -> Value {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/v2.json"))
        .unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn hex32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn key_derivation() {
    let v = vectors();
    let k = common::derive(&hex32(&v["keys"]["group_key_hex"]));
    assert_eq!(k.enc, hex32(&v["keys"]["enc_key_hex"]));
    assert_eq!(k.auth, hex32(&v["keys"]["auth_key_hex"]));
    assert_eq!(k.collapse, hex32(&v["keys"]["collapse_key_hex"]));
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(k.auth),
        s(&v["keys"]["auth_key_base64"])
    );
}

#[test]
fn ids_and_collapse_id() {
    let v = vectors();
    let gid = s(&v["ids"]["group_id"]);
    assert!(metriccupid_push::v2::is_id128(gid));
    assert!(metriccupid_push::v2::is_id128(
        s(&v["ids"]["mac_device_id"])
    ));
    assert!(metriccupid_push::v2::is_id128(
        s(&v["ids"]["ios_device_id"])
    ));
    let k = common::derive(&hex32(&v["keys"]["group_key_hex"]));
    assert_eq!(
        common::collapse_id(&k.collapse, s(&v["collapse_id"]["alert_id_utf8"])),
        s(&v["collapse_id"]["collapse_id"])
    );
}

#[test]
fn seal_and_open() {
    let v = vectors();
    let k = common::derive(&hex32(&v["keys"]["group_key_hex"]));
    let gid = s(&v["ids"]["group_id"]);
    for case in v["seal"].as_array().unwrap() {
        let aad = common::aad(gid, s(&case["type"]), s(&case["msg_id"]));
        assert_eq!(aad, s(&case["aad_utf8"]));
        let nonce: [u8; 12] = hex::decode(s(&case["nonce_hex"]))
            .unwrap()
            .try_into()
            .unwrap();
        let pt = s(&case["plaintext_utf8"]);
        let sealed = common::seal(&k.enc, &nonce, &aad, pt.as_bytes());
        assert_eq!(sealed, s(&case["sealed_base64"]), "{}", case["name"]);
        assert_eq!(common::open(&k.enc, &aad, &sealed).unwrap(), pt.as_bytes());
        // Wrong AAD (e.g. a ciphertext moved to another type or id) fails.
        assert!(common::open(&k.enc, &format!("{aad}x"), &sealed).is_none());
        // Plaintext envelope fields.
        let p: Value = serde_json::from_str(pt).unwrap();
        assert_eq!(p["v"], 1);
        assert_eq!(p["type"], case["type"]);
        assert_eq!(p["id"], case["msg_id"]);
        // A sealed box is a valid `sealed` for the server.
        assert!(metriccupid_push::v2::is_sealed(&sealed, 16 * 1024));
    }
}

#[test]
fn signed_requests_match_and_verify() {
    let v = vectors();
    let auth = hex32(&v["keys"]["auth_key_hex"]);
    let a = Authenticator::new(Vec::new());
    for req in v["signed_requests"].as_array().unwrap() {
        let body = s(&req["body_utf8"]).as_bytes();
        let ts = s(&req["timestamp"]);
        let (group, device) = (s(&req["group_id"]), s(&req["device_id"]));
        let expected = format!(
            "{ts}\n{}\n{}\n{group}\n{device}\n{}",
            s(&req["method"]),
            s(&req["target"]),
            s(&req["body_utf8"])
        );
        assert_eq!(expected, s(&req["string_to_sign_utf8"]));
        let sig = sign_v2(
            &auth,
            ts,
            s(&req["method"]),
            s(&req["target"]),
            group,
            device,
            body,
        );
        assert_eq!(sig, s(&req["headers"]["X-MC-Signature"]), "{}", req["name"]);

        let mut h = HeaderMap::new();
        for (k, val) in req["headers"].as_object().unwrap() {
            h.insert(
                HeaderName::from_bytes(k.to_ascii_lowercase().as_bytes()).unwrap(),
                HeaderValue::from_str(s(val)).unwrap(),
            );
        }
        let now: u64 = ts.parse().unwrap();
        a.verify_v2(
            now,
            &auth,
            s(&req["method"]),
            s(&req["target"]),
            group,
            device,
            &h,
            body,
        )
        .unwrap();
    }
}

#[test]
fn post_message_body_is_valid_for_the_server() {
    let v = vectors();
    let req = &v["signed_requests"][0];
    let body: Value = serde_json::from_str(s(&req["body_utf8"])).unwrap();
    assert_eq!(body["sealed"], v["seal"][0]["sealed_base64"]);
    assert_eq!(body["collapse_id"], v["collapse_id"]["collapse_id"]);
}
