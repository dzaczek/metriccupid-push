//! An Apple-like certificate chain built at test time (rcgen) and JWS signing,
//! since Apple-signed `AppTransaction`s cannot be produced by tests.
//!
//! Structure mirrors Apple's: root and intermediate are P-384 and sign with
//! ECDSA-SHA384, the leaf is P-256 and signs the JWS with ES256; the
//! intermediate carries 1.2.840.113635.100.6.2.1, the leaf 1.2.840.113635.100.6.11.1.

use std::sync::LazyLock;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer,
    KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};

pub const OID_LEAF: &[u64] = &[1, 2, 840, 113635, 100, 6, 11, 1];
pub const OID_INTERMEDIATE: &[u64] = &[1, 2, 840, 113635, 100, 6, 2, 1];

/// The chain every test server trusts (`AppState::new_with_licence_root`).
pub static CHAIN: LazyLock<Chain> = LazyLock::new(|| Chain::build(&Opts::default()));

pub struct Opts {
    pub leaf_oid: bool,
    pub intermediate_oid: bool,
    pub intermediate_ca: bool,
    /// Leaf validity, (y, m, d) inclusive range.
    pub leaf_from: (i32, u8, u8),
    pub leaf_until: (i32, u8, u8),
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            leaf_oid: true,
            intermediate_oid: true,
            intermediate_ca: true,
            // T0 in the tests is 2023-11-14.
            leaf_from: (2023, 1, 1),
            leaf_until: (2024, 6, 1),
        }
    }
}

pub struct Chain {
    pub root: Vec<u8>,
    pub intermediate: Vec<u8>,
    pub leaf: Vec<u8>,
    leaf_pkcs8: Vec<u8>,
}

fn params(cn: &str, from: (i32, u8, u8), until: (i32, u8, u8)) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.distinguished_name
        .push(DnType::OrganizationName, "Test Apple Inc.");
    p.not_before = date_time_ymd(from.0, from.1, from.2);
    p.not_after = date_time_ymd(until.0, until.1, until.2);
    p
}

fn marker(oid: &[u64]) -> CustomExtension {
    // Apple's marker extensions carry ASN.1 NULL.
    CustomExtension::from_oid_content(oid, vec![0x05, 0x00])
}

impl Chain {
    pub fn build(o: &Opts) -> Self {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut rp = params("Test Root CA - G3", (2014, 1, 1), (2039, 1, 1));
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = rp.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(rp, root_key);

        let int_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut ip = params("Test WWDR CA - G6", (2020, 1, 1), (2030, 1, 1));
        if o.intermediate_ca {
            ip.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        }
        if o.intermediate_oid {
            ip.custom_extensions.push(marker(OID_INTERMEDIATE));
        }
        let intermediate = ip.signed_by(&int_key, &root_issuer).unwrap();
        let int_issuer = Issuer::new(ip, int_key);

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut lp = params(
            "Test Prod ECC Mac App Store Receipt Signing",
            o.leaf_from,
            o.leaf_until,
        );
        if o.leaf_oid {
            lp.custom_extensions.push(marker(OID_LEAF));
        }
        let leaf = lp.signed_by(&leaf_key, &int_issuer).unwrap();

        Self {
            root: root.der().to_vec(),
            intermediate: intermediate.der().to_vec(),
            leaf: leaf.der().to_vec(),
            leaf_pkcs8: leaf_key.serialize_der(),
        }
    }

    /// Compact JWS of `payload` with x5c = [leaf, intermediate, root].
    pub fn sign(&self, payload: &Value) -> String {
        self.sign_x5c(payload, [&self.leaf, &self.intermediate, &self.root])
    }

    pub fn sign_x5c(&self, payload: &Value, x5c: [&[u8]; 3]) -> String {
        let header = json!({
            "alg": "ES256",
            "x5c": x5c.iter().map(|c| STANDARD.encode(c)).collect::<Vec<_>>(),
        });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        );
        let rng = SystemRandom::new();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.leaf_pkcs8, &rng)
                .unwrap();
        let sig = key.sign(&rng, input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }
}

/// A production AppTransaction payload for MetricCupid, signed at `signed_s`.
pub fn app_transaction(transaction_id: &str, signed_s: u64) -> Value {
    json!({
        "receiptType": "Production",
        "appAppleId": 6757280443u64,
        "bundleId": "cat.sysop.MetricCupid",
        "applicationVersion": "140",
        "receiptCreationDate": (signed_s - 60) * 1000,
        "originalPurchaseDate": 1_690_000_000_000u64,
        "originalApplicationVersion": "120",
        "deviceVerification": "AAAA",
        "deviceVerificationNonce": "00000000-0000-0000-0000-000000000000",
        "appTransactionId": transaction_id,
        "originalPlatform": "macOS",
        "signedDate": signed_s * 1000,
    })
}

/// `{"kind": "app_transaction", "jws": ...}` for purchase `transaction_id`.
pub fn licence(transaction_id: &str, signed_s: u64) -> Value {
    json!({ "kind": "app_transaction", "jws": CHAIN.sign(&app_transaction(transaction_id, signed_s)) })
}
