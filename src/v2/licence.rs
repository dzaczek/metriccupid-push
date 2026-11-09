//! App Store licences for the hosted service (PROTOCOL.md section 13).
//!
//! Model A: owning the MetricCupid app is the licence. The Mac sends StoreKit 2's
//! `AppTransaction.jwsRepresentation`; the server checks it the way Apple's App
//! Store Server Library does (x5c chain to Apple Root CA - G3, validity at the
//! transaction's `signedDate`, Apple marker OIDs, ES256 signature) and then the
//! payload (bundle id, app id, environment).
//!
//! Every licence verified today is tier `founder`; the tier is stored per group
//! so that a later subscription model can add `free` / `pro` without touching
//! the founders.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;

use crate::config::LicenceMode;

/// Apple Root CA - G3, DER, from https://www.apple.com/certificateauthority/.
/// SHA-256 pinned in the tests below.
pub const APPLE_ROOT_CA_G3: &[u8] = include_bytes!("certs/AppleRootCA-G3.cer");
pub const BUNDLE_ID: &str = "cat.sysop.MetricCupid";
pub const APP_APPLE_ID: u64 = 6_757_280_443;
/// The only licence kind today.
pub const KIND_APP_TRANSACTION: &str = "app_transaction";
/// Tier of every model-A licence (an App Store purchase of the app).
pub const TIER_FOUNDER: &str = "founder";
/// Longest accepted JWS (Apple's are about 4 to 6 KB).
pub const MAX_JWS_LEN: usize = 12 * 1024;

/// Apple marker extension of the receipt-signing leaf certificate.
const OID_LEAF: &str = "1.2.840.113635.100.6.11.1";
/// Apple marker extension of the WWDR intermediate certificate.
const OID_INTERMEDIATE: &str = "1.2.840.113635.100.6.2.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";

/// Why a licence was refused. `code()` is returned to the client as `reason`;
/// it never contains any part of the JWS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenceError {
    /// `kind` is not `app_transaction`.
    UnsupportedKind,
    /// Not a compact JWS with the expected header and payload.
    Malformed,
    /// Certificate chain broken: bad certificate, signature, name or CA flag.
    Chain,
    /// The chain does not end in Apple Root CA - G3.
    UntrustedRoot,
    /// A certificate was not valid at the transaction's `signedDate`.
    CertificateExpired,
    /// The leaf or intermediate lacks Apple's marker extension.
    NotApple,
    /// The JWS signature does not verify with the leaf key.
    Signature,
    /// Issued for another bundle id.
    WrongBundle,
    /// Production transaction for another App Store app id.
    WrongApp,
    /// `Xcode`, unknown, or `Sandbox` while `LICENCE_ALLOW_SANDBOX=false`.
    Environment,
}

impl LicenceError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedKind => "unsupported_kind",
            Self::Malformed => "malformed",
            Self::Chain => "chain",
            Self::UntrustedRoot => "untrusted_root",
            Self::CertificateExpired => "certificate_expired",
            Self::NotApple => "not_apple",
            Self::Signature => "signature",
            Self::WrongBundle => "wrong_bundle",
            Self::WrongApp => "wrong_app",
            Self::Environment => "environment",
        }
    }
}

/// A verified App Store purchase of the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLicence {
    pub kind: &'static str,
    pub tier: &'static str,
    /// `production` or `sandbox` (TestFlight).
    pub environment: &'static str,
    /// `appTransactionId`, or `sha256:<hex>` of
    /// `"{originalPurchaseDate}|{appAppleId}|{originalPlatform}"` when Apple did
    /// not include one (older OS versions). One id per purchase (per Apple ID
    /// and app), the same on every device of that Apple ID.
    pub app_transaction_id: String,
    /// Milliseconds since 1970, as Apple sends it.
    pub original_purchase_date: Option<u64>,
    pub original_application_version: Option<String>,
    pub original_platform: Option<String>,
    /// Milliseconds since 1970.
    pub signed_date: u64,
}

/// The `licence` object of `POST /v2/groups` and the body of `PUT /v2/licence`.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct LicenceReq {
    pub kind: String,
    pub jws: String,
}

/// What the hosted service requires (built from `LICENCE_*`).
pub struct LicencePolicy {
    pub mode: LicenceMode,
    pub verifier: AppTransactionVerifier,
    pub max_groups: u32,
    pub grace_until: Option<u64>,
    /// `GATEWAY_OPEN`: whether this (hosted) server relays APNs for
    /// self-hosted servers. Closed by default so nobody uses the operator's
    /// APNs key and quota without being let in explicitly.
    pub gateway_open: bool,
}

impl LicencePolicy {
    /// `POST /v2/groups` needs a licence (except gateway registrations).
    pub fn required_for_new_groups(&self) -> bool {
        self.mode == LicenceMode::AppTransaction
    }

    /// Unlicensed groups are refused from sending at `now` (grace over).
    pub fn enforced(&self, now: u64) -> bool {
        self.mode == LicenceMode::AppTransaction && self.grace_until.map_or(true, |g| now >= g)
    }

    pub fn verify(&self, req: &LicenceReq) -> Result<VerifiedLicence, LicenceError> {
        if req.kind != KIND_APP_TRANSACTION {
            return Err(LicenceError::UnsupportedKind);
        }
        self.verifier.verify(&req.jws)
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    x5c: Vec<String>,
}

/// JWSAppTransactionDecodedPayload; unknown fields are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    bundle_id: Option<String>,
    receipt_type: Option<String>,
    environment: Option<String>,
    app_apple_id: Option<u64>,
    app_transaction_id: Option<String>,
    original_purchase_date: Option<f64>,
    original_application_version: Option<String>,
    original_platform: Option<String>,
    signed_date: Option<f64>,
    receipt_creation_date: Option<f64>,
}

/// Verifies `AppTransaction` JWS against a pinned root (Apple's in production).
pub struct AppTransactionVerifier {
    root: Vec<u8>,
    allow_sandbox: bool,
}

impl AppTransactionVerifier {
    /// Production verifier: Apple Root CA - G3.
    pub fn apple(allow_sandbox: bool) -> Self {
        Self::with_root(APPLE_ROOT_CA_G3.to_vec(), allow_sandbox)
    }

    /// Verifier pinned to another root (tests build an Apple-like chain).
    pub fn with_root(root_der: Vec<u8>, allow_sandbox: bool) -> Self {
        Self {
            root: root_der,
            allow_sandbox,
        }
    }

    pub fn verify(&self, jws: &str) -> Result<VerifiedLicence, LicenceError> {
        use LicenceError::*;
        if jws.len() > MAX_JWS_LEN {
            return Err(Malformed);
        }
        let mut parts = jws.split('.');
        let (Some(h64), Some(p64), Some(s64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Malformed);
        };
        let b64 = |s: &str| URL_SAFE_NO_PAD.decode(s).map_err(|_| Malformed);
        let header: Header = serde_json::from_slice(&b64(h64)?).map_err(|_| Malformed)?;
        let payload: Payload = serde_json::from_slice(&b64(p64)?).map_err(|_| Malformed)?;
        let sig = b64(s64)?;
        if header.alg != "ES256" || header.x5c.len() != 3 {
            return Err(Malformed);
        }
        let ders: Vec<Vec<u8>> = header
            .x5c
            .iter()
            .map(|c| STANDARD.decode(c).map_err(|_| Malformed))
            .collect::<Result<_, _>>()?;
        // Apple validates at signedDate (receiptCreationDate for older
        // payloads), so a later certificate rotation does not void purchases.
        let signed_ms = payload
            .signed_date
            .or(payload.receipt_creation_date)
            .filter(|d| d.is_finite() && *d > 0.0)
            .ok_or(Malformed)? as u64;

        if ders[2] != self.root {
            return Err(UntrustedRoot);
        }
        let leaf = parse_cert(&ders[0])?;
        let intermediate = parse_cert(&ders[1])?;
        let root = parse_cert(&ders[2])?;

        verify_issued(&intermediate, &root)?;
        verify_issued(&leaf, &intermediate)?;
        if !intermediate.is_ca() {
            return Err(Chain);
        }
        let at = (signed_ms / 1000) as i64;
        for c in [&leaf, &intermediate, &root] {
            let v = c.validity();
            if at < v.not_before.timestamp() || at > v.not_after.timestamp() {
                return Err(CertificateExpired);
            }
        }
        if !has_extension(&leaf, OID_LEAF) || !has_extension(&intermediate, OID_INTERMEDIATE) {
            return Err(NotApple);
        }

        // JWS ES256: raw r||s over "header.payload" with the leaf's P-256 key.
        let (curve, point) = ec_key(&leaf)?;
        if curve != OID_P256 {
            return Err(Chain);
        }
        let signing_input = &jws[..h64.len() + 1 + p64.len()];
        UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
            .verify(signing_input.as_bytes(), &sig)
            .map_err(|_| Signature)?;

        // Payload: only now is it known to come from Apple.
        if payload.bundle_id.as_deref() != Some(BUNDLE_ID) {
            return Err(WrongBundle);
        }
        let environment = match payload
            .receipt_type
            .as_deref()
            .or(payload.environment.as_deref())
        {
            Some("Production") => "production",
            Some("Sandbox") if self.allow_sandbox => "sandbox",
            _ => return Err(Environment),
        };
        // A production transaction for another app id is refused. One without
        // an app id is accepted: StoreKit has been seen to omit it on real App
        // Store installs (see the Mac app's PurchaseVerifier), and bundle id +
        // Apple's signature already pin the app.
        if environment == "production" && payload.app_apple_id.is_some_and(|id| id != APP_APPLE_ID)
        {
            return Err(WrongApp);
        }
        let original_purchase_date = payload
            .original_purchase_date
            .filter(|d| d.is_finite() && *d >= 0.0)
            .map(|d| d as u64);
        let app_transaction_id = match payload
            .app_transaction_id
            .filter(|s| (1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic()))
        {
            Some(id) => id,
            None => fallback_id(
                original_purchase_date,
                payload.app_apple_id,
                payload.original_platform.as_deref(),
            ),
        };
        Ok(VerifiedLicence {
            kind: KIND_APP_TRANSACTION,
            tier: TIER_FOUNDER,
            environment,
            app_transaction_id,
            original_purchase_date,
            original_application_version: payload
                .original_application_version
                .map(|v| v.chars().take(64).collect()),
            original_platform: payload
                .original_platform
                .map(|v| v.chars().take(32).collect()),
            signed_date: signed_ms,
        })
    }
}

/// Stand-in purchase id when `appTransactionId` is missing.
pub fn fallback_id(
    purchase_ms: Option<u64>,
    app_id: Option<u64>,
    platform: Option<&str>,
) -> String {
    let input = format!(
        "{}|{}|{}",
        purchase_ms.unwrap_or(0),
        app_id.unwrap_or(0),
        platform.unwrap_or("")
    );
    format!("sha256:{}", hex::encode(Sha256::digest(input.as_bytes())))
}

fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, LicenceError> {
    match x509_parser::parse_x509_certificate(der) {
        Ok((&[], cert)) => Ok(cert),
        _ => Err(LicenceError::Chain),
    }
}

fn has_extension(cert: &X509Certificate<'_>, oid: &str) -> bool {
    cert.extensions()
        .iter()
        .any(|e| e.oid.to_id_string() == oid)
}

/// (curve OID, uncompressed point) of an EC public key.
fn ec_key<'a>(cert: &'a X509Certificate<'_>) -> Result<(String, &'a [u8]), LicenceError> {
    let spki = cert.public_key();
    if spki.algorithm.algorithm.to_id_string() != OID_EC_PUBLIC_KEY {
        return Err(LicenceError::Chain);
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| o.to_id_string())
        .ok_or(LicenceError::Chain)?;
    Ok((curve, spki.subject_public_key.as_ref()))
}

/// `child` names `issuer` as its issuer and carries a valid ECDSA signature by
/// the issuer's key (P-384 / SHA-384 in Apple's chain).
fn verify_issued(
    child: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), LicenceError> {
    if child.issuer().as_raw() != issuer.subject().as_raw() {
        return Err(LicenceError::Chain);
    }
    let (curve, point) = ec_key(issuer)?;
    let alg: &'static dyn VerificationAlgorithm = match (
        curve.as_str(),
        child.signature_algorithm.algorithm.to_id_string().as_str(),
    ) {
        (OID_P384, OID_ECDSA_SHA384) => &signature::ECDSA_P384_SHA384_ASN1,
        (OID_P384, OID_ECDSA_SHA256) => &signature::ECDSA_P384_SHA256_ASN1,
        (OID_P256, OID_ECDSA_SHA256) => &signature::ECDSA_P256_SHA256_ASN1,
        (OID_P256, OID_ECDSA_SHA384) => &signature::ECDSA_P256_SHA384_ASN1,
        _ => return Err(LicenceError::Chain),
    };
    UnparsedPublicKey::new(alg, point)
        .verify(
            child.tbs_certificate.as_ref(),
            child.signature_value.as_ref(),
        )
        .map_err(|_| LicenceError::Chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Apple publishes this fingerprint next to the certificate.
    #[test]
    fn embedded_root_is_apple_root_ca_g3() {
        assert_eq!(
            hex::encode(Sha256::digest(APPLE_ROOT_CA_G3)),
            "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"
        );
        let cert = parse_cert(APPLE_ROOT_CA_G3).unwrap();
        assert!(cert.subject().to_string().contains("Apple Root CA - G3"));
        assert_eq!(ec_key(&cert).unwrap().0, OID_P384);
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        let v = AppTransactionVerifier::apple(true);
        for jws in [
            "",
            "a.b",
            "a.b.c.d",
            "!!.!!.!!",
            &"a".repeat(MAX_JWS_LEN + 1),
        ] {
            assert_eq!(v.verify(jws), Err(LicenceError::Malformed), "{jws:.20}");
        }
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","x5c":["AA==","AA==","AA=="]}"#);
        let p = URL_SAFE_NO_PAD.encode(br#"{"signedDate":1700000000000}"#);
        assert_eq!(
            v.verify(&format!("{h}.{p}.AA")),
            Err(LicenceError::UntrustedRoot)
        );
    }

    #[test]
    fn fallback_id_is_stable_and_prefixed() {
        let a = fallback_id(Some(1), Some(2), Some("macOS"));
        assert_eq!(a, fallback_id(Some(1), Some(2), Some("macOS")));
        assert_ne!(a, fallback_id(Some(1), Some(2), Some("iOS")));
        assert!(a.starts_with("sha256:") && a.len() == 7 + 64);
    }
}
