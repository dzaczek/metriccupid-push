//! App Store `AppTransaction` verification against an Apple-like test chain.

mod common;

use common::licence::{app_transaction, Chain, Opts, CHAIN};
use metriccupid_push::v2::licence::{fallback_id, AppTransactionVerifier, LicenceError};
use serde_json::{json, Value};

const T0: u64 = 1_700_000_000;

fn verifier() -> AppTransactionVerifier {
    AppTransactionVerifier::with_root(CHAIN.root.clone(), true)
}

fn with(mut p: Value, edits: Value) -> Value {
    for (k, v) in edits.as_object().unwrap() {
        if v.is_null() {
            p.as_object_mut().unwrap().remove(k);
        } else {
            p[k] = v.clone();
        }
    }
    p
}

#[test]
fn valid_production_transaction() {
    let l = verifier()
        .verify(&CHAIN.sign(&app_transaction("700000123", T0)))
        .unwrap();
    assert_eq!(
        (l.kind, l.tier, l.environment),
        ("app_transaction", "founder", "production")
    );
    assert_eq!(l.app_transaction_id, "700000123");
    assert_eq!(l.original_purchase_date, Some(1_690_000_000_000));
    assert_eq!(l.original_application_version.as_deref(), Some("120"));
    assert_eq!(l.original_platform.as_deref(), Some("macOS"));
    assert_eq!(l.signed_date, T0 * 1000);
}

#[test]
fn sandbox_is_allowed_only_when_configured_and_xcode_never() {
    let sandbox = with(
        app_transaction("1", T0),
        json!({"receiptType": "Sandbox", "appAppleId": null}),
    );
    let jws = CHAIN.sign(&sandbox);
    assert_eq!(verifier().verify(&jws).unwrap().environment, "sandbox");
    let strict = AppTransactionVerifier::with_root(CHAIN.root.clone(), false);
    assert_eq!(strict.verify(&jws), Err(LicenceError::Environment));
    let xcode = with(app_transaction("1", T0), json!({"receiptType": "Xcode"}));
    assert_eq!(
        verifier().verify(&CHAIN.sign(&xcode)),
        Err(LicenceError::Environment)
    );
    let none = with(app_transaction("1", T0), json!({"receiptType": null}));
    assert_eq!(
        verifier().verify(&CHAIN.sign(&none)),
        Err(LicenceError::Environment)
    );
}

#[test]
fn bundle_and_app_id_are_checked() {
    let other = with(
        app_transaction("1", T0),
        json!({"bundleId": "com.example.Other"}),
    );
    assert_eq!(
        verifier().verify(&CHAIN.sign(&other)),
        Err(LicenceError::WrongBundle)
    );
    let wrong_app = with(app_transaction("1", T0), json!({"appAppleId": 1234}));
    assert_eq!(
        verifier().verify(&CHAIN.sign(&wrong_app)),
        Err(LicenceError::WrongApp)
    );
    // Production without an app id is accepted (StoreKit omits it at times).
    let no_app = with(app_transaction("1", T0), json!({"appAppleId": null}));
    assert!(verifier().verify(&CHAIN.sign(&no_app)).is_ok());
}

#[test]
fn missing_transaction_id_falls_back_to_a_hash() {
    let p = with(app_transaction("1", T0), json!({"appTransactionId": null}));
    let l = verifier().verify(&CHAIN.sign(&p)).unwrap();
    assert_eq!(
        l.app_transaction_id,
        fallback_id(Some(1_690_000_000_000), Some(6_757_280_443), Some("macOS"))
    );
}

#[test]
fn certificates_are_checked_at_signed_date_not_now() {
    // The leaf is valid 2023-01-01 .. 2024-06-01.
    let ok = CHAIN.sign(&app_transaction("1", T0));
    assert!(
        verifier().verify(&ok).is_ok(),
        "valid at signedDate, whatever today is"
    );
    let later = CHAIN.sign(&app_transaction("1", 1_750_000_000)); // 2025
    assert_eq!(
        verifier().verify(&later),
        Err(LicenceError::CertificateExpired)
    );
    let earlier = CHAIN.sign(&app_transaction("1", 1_600_000_000)); // 2020
    assert_eq!(
        verifier().verify(&earlier),
        Err(LicenceError::CertificateExpired)
    );
    // Older payloads without signedDate use receiptCreationDate.
    let p = with(app_transaction("1", T0), json!({"signedDate": null}));
    assert!(verifier().verify(&CHAIN.sign(&p)).is_ok());
    let p = with(
        app_transaction("1", T0),
        json!({"signedDate": null, "receiptCreationDate": null}),
    );
    assert_eq!(
        verifier().verify(&CHAIN.sign(&p)),
        Err(LicenceError::Malformed)
    );
}

#[test]
fn root_must_be_the_pinned_one() {
    let other = Chain::build(&Opts::default());
    let jws = other.sign(&app_transaction("1", T0));
    assert_eq!(verifier().verify(&jws), Err(LicenceError::UntrustedRoot));
    // Our root at the end of someone else's chain: signatures do not match.
    let mixed = other.sign_x5c(
        &app_transaction("1", T0),
        [&other.leaf, &other.intermediate, &CHAIN.root],
    );
    assert_eq!(verifier().verify(&mixed), Err(LicenceError::Chain));
    // The production verifier trusts only Apple's root.
    assert_eq!(
        AppTransactionVerifier::apple(true).verify(&CHAIN.sign(&app_transaction("1", T0))),
        Err(LicenceError::UntrustedRoot)
    );
}

#[test]
fn apple_marker_oids_and_ca_flag_are_required() {
    for (opts, want) in [
        (
            Opts {
                leaf_oid: false,
                ..Opts::default()
            },
            LicenceError::NotApple,
        ),
        (
            Opts {
                intermediate_oid: false,
                ..Opts::default()
            },
            LicenceError::NotApple,
        ),
        (
            Opts {
                intermediate_ca: false,
                ..Opts::default()
            },
            LicenceError::Chain,
        ),
    ] {
        let chain = Chain::build(&opts);
        let v = AppTransactionVerifier::with_root(chain.root.clone(), true);
        assert_eq!(v.verify(&chain.sign(&app_transaction("1", T0))), Err(want));
    }
}

#[test]
fn tampering_breaks_the_signature() {
    let jws = CHAIN.sign(&app_transaction("1", T0));
    let parts: Vec<&str> = jws.split('.').collect();
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let forged = URL_SAFE_NO_PAD.encode(app_transaction("2", T0).to_string());
    let tampered = format!("{}.{}.{}", parts[0], forged, parts[2]);
    assert_eq!(verifier().verify(&tampered), Err(LicenceError::Signature));
    // Leaf and intermediate swapped: the chain does not link.
    let swapped = CHAIN.sign_x5c(
        &app_transaction("1", T0),
        [&CHAIN.intermediate, &CHAIN.leaf, &CHAIN.root],
    );
    assert_eq!(verifier().verify(&swapped), Err(LicenceError::Chain));
}
