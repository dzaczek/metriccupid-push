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

// ---------------------------------------------------------------------------
// Release-readiness pins: what a legitimate Production AppTransaction may look
// like. Each of these must keep verifying; a regression here would refuse
// paying users (see the Mac app's v1.25.0–1.25.3 appID incident).

#[test]
fn production_with_newer_or_optional_fields_is_accepted() {
    // Fields Apple added later or sends only sometimes: they are ignored, so a
    // refunded purchase (revocationDate), a preorder, an Apple Business /
    // School copy (storeType) or a new field never turns into `malformed`.
    let p = with(
        app_transaction("1", T0),
        json!({
            "revocationDate": 1_700_000_000_000u64,
            "revocationReason": 0,
            "preorderDate": 1_680_000_000_000u64,
            "storeType": "ENTERPRISE",
            "appVersionId": 123_456_789u64,
            "someFutureField": {"nested": [1, 2, 3]},
        }),
    );
    let l = verifier().verify(&CHAIN.sign(&p)).unwrap();
    assert_eq!(l.environment, "production");
}

#[test]
fn production_without_app_id_or_transaction_id_or_platform_is_accepted() {
    // The worst case seen in the wild: no appAppleId (Mac app v1.25.4 fix),
    // no appTransactionId and no originalPlatform (transactions cached before
    // Apple added them). Bundle id + Apple's signature identify the app.
    let p = with(
        app_transaction("1", T0),
        json!({"appAppleId": null, "appTransactionId": null, "originalPlatform": null}),
    );
    let l = verifier().verify(&CHAIN.sign(&p)).unwrap();
    assert_eq!(l.environment, "production");
    assert_eq!(
        l.app_transaction_id,
        fallback_id(Some(1_690_000_000_000), None, None)
    );
    // An empty or non-printable appTransactionId is treated as missing too.
    for bad in ["", "a b", "\u{7f}"] {
        let p = with(app_transaction(bad, T0), json!({}));
        let l = verifier().verify(&CHAIN.sign(&p)).unwrap();
        assert!(l.app_transaction_id.starts_with("sha256:"), "{bad:?}");
    }
}

#[test]
fn environment_from_the_environment_key_when_receipt_type_is_absent() {
    let p = with(
        app_transaction("1", T0),
        json!({"receiptType": null, "environment": "Production"}),
    );
    assert_eq!(
        verifier().verify(&CHAIN.sign(&p)).unwrap().environment,
        "production"
    );
}

#[test]
fn environment_casing_matches_apples_library() {
    // Apple documents and sends `Production` / `Sandbox`; its App Store Server
    // Library decodes receiptType as a case-sensitive enum, and so do we. If
    // this ever has to change, change it on purpose.
    for value in ["production", "PRODUCTION", "Production "] {
        let p = with(app_transaction("1", T0), json!({ "receiptType": value }));
        assert_eq!(
            verifier().verify(&CHAIN.sign(&p)),
            Err(LicenceError::Environment),
            "{value:?}"
        );
    }
}

#[test]
fn chain_must_have_exactly_three_certificates_like_apples_library() {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    let jws = CHAIN.sign(&app_transaction("1", T0));
    let parts: Vec<&str> = jws.split('.').collect();
    let x5c = |certs: &[&[u8]]| {
        let h = json!({"alg": "ES256", "x5c": certs.iter().map(|c| STANDARD.encode(c)).collect::<Vec<_>>()});
        URL_SAFE_NO_PAD.encode(h.to_string())
    };
    for certs in [
        vec![
            &CHAIN.leaf[..],
            &CHAIN.intermediate,
            &CHAIN.intermediate,
            &CHAIN.root,
        ],
        vec![&CHAIN.leaf[..], &CHAIN.intermediate],
    ] {
        let forged = format!("{}.{}.{}", x5c(&certs), parts[1], parts[2]);
        assert_eq!(verifier().verify(&forged), Err(LicenceError::Malformed));
    }
}

#[test]
fn sandbox_fallback_ids_collide_across_testers() {
    // Known limitation, pinned so it is not forgotten: sandbox (TestFlight)
    // transactions carry synthetic values (originalPurchaseDate is always
    // 2013-08-01, appAppleId absent), so without appTransactionId every tester
    // maps to the same purchase id and shares one LICENCE_MAX_GROUPS budget.
    let tester = |platform: &str| {
        with(
            app_transaction("1", T0),
            json!({
                "receiptType": "Sandbox",
                "appAppleId": null,
                "appTransactionId": null,
                "originalPurchaseDate": 1_375_340_400_000u64,
                "originalApplicationVersion": "1.0",
                "originalPlatform": platform,
            }),
        )
    };
    let a = verifier().verify(&CHAIN.sign(&tester("iOS"))).unwrap();
    let b = verifier().verify(&CHAIN.sign(&tester("iOS"))).unwrap();
    assert_eq!(a.environment, "sandbox");
    assert_eq!(a.app_transaction_id, b.app_transaction_id);
}
