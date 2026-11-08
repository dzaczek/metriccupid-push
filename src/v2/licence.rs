//! Licence check for group registration in `MODE=hosted`.

/// Decides whether a new group may be registered on the hosted service.
///
/// TODO(stage 3): verify an App Store signed transaction (JWS) passed in the
/// `licence` field of `POST /v2/groups`: check the x5c chain up to Apple's
/// root CA, bundle id, product id and expiry, and bind the group to the
/// original transaction id for quotas.
pub trait Licence: Send + Sync + 'static {
    fn allows(&self, licence: Option<&str>) -> bool;
}

/// Stub: allows everything when `HOSTED_OPEN_REGISTRATION=true`, nothing otherwise.
pub struct OpenRegistration {
    pub open: bool,
}

impl Licence for OpenRegistration {
    fn allows(&self, _licence: Option<&str>) -> bool {
        self.open
    }
}
