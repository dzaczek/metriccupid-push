//! Management pages and actions: bans, gateway, group suspension, licence
//! revocation, live limits and the audit log.
//!
//! Every action is a POST that passes, in order:
//! 1. [`gate`]: an authenticated session (else the login redirect), the
//!    session's CSRF token (else `403`) and the panel-wide action rate limit;
//! 2. input validation (refused input never uses up a code);
//! 3. [`authorize`]: the login lockout, then step-up. A fresh TOTP code (one
//!    not used before for a login or an action) opens a step-up window on the
//!    server session ([`STEPUP_SECS`], [`STEPUP_ACTIONS`] actions, bound to
//!    the session, the admin's /24 or /48 and the Cloudflare Access identity);
//!    inside it the code may be left empty. Some actions always need a fresh
//!    code ([`Need::Fresh`]). Refused codes count toward the login lockout.
//!
//! The change and its audit row (with `stepup=fresh|window`) are written in
//! one transaction before the in-memory state changes, so an action whose
//! audit row cannot be written does not happen.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use rusqlite::Connection;
use serde::Deserialize;

use super::access::Identity;
use super::auth::{csrf_ok, totp_match, Session, STEPUP_ACTIONS, STEPUP_SECS};
use super::pages::{self, GatewayQuotas, LimitRow};
use super::queries;
use super::{need_page, not_found_response, page, session, AdminState, ClientIp};
use crate::controls::{self, Audit, LimitKind, ManualBan, LIMIT_KEYS};
use crate::limits::ip_key;
use crate::metrics::ip_prefix;
use crate::v2::store::StoreError;

/// Panel actions per minute (all admins together).
pub const ACTIONS_PER_MINUTE: u32 = 30;

const CODE_ERROR: &str =
    "Wrong or already used authenticator code. Wait for the next code and try again.";

/// What an action needs after the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    /// A fresh code, or an open step-up window.
    Window,
    /// Always a fresh code.
    Fresh,
}

/// A request that passed [`gate`].
pub(super) struct Gate {
    sess: Session,
    token: String,
    ip: IpAddr,
    /// The admin user, plus the Cloudflare Access e-mail when known.
    name: String,
    email: Option<String>,
    /// `/24` or `/48` of the admin.
    network: String,
    /// `fresh` or `window` once [`authorize`] passed.
    stepup: Option<&'static str>,
}

impl Gate {
    fn audit(&self, now: u64, action: &'static str) -> Audit {
        Audit {
            ts: now,
            actor: self.name.clone(),
            ip_prefix: self.network.clone(),
            action,
            target: None,
            detail: None,
            outcome: "ok",
        }
    }
}

/// The outcome page of an action.
fn done(
    s: &AdminState,
    sess: &Session,
    status: StatusCode,
    ok: bool,
    msg: &str,
    back: &str,
) -> Response {
    let title = if ok { "Done" } else { "Refused" };
    let mut r = page(
        s,
        title,
        "",
        sess,
        back,
        None,
        false,
        &pages::result(ok, msg, back),
    );
    *r.status_mut() = status;
    r
}

/// Append an audit row on its own (refusals). Best effort: the action it
/// describes did not happen.
async fn write_audit(s: &AdminState, a: Audit) {
    if let Err(e) = s.app.v2().store.call(move |c| controls::audit(c, &a)).await {
        tracing::error!(error = %e, "admin: cannot write audit row");
    }
}

/// Session, CSRF token and action rate limit.
fn gate(
    s: &AdminState,
    headers: &HeaderMap,
    ip: IpAddr,
    identity: &Identity,
    csrf: &str,
    back: &str,
) -> Result<Gate, Response> {
    let (token, sess) = match session(s, headers) {
        Some((t, sess)) if sess.authed => (t, sess),
        _ => return Err(Redirect::to("/admin/login").into_response()),
    };
    if !csrf_ok(&sess, csrf) {
        return Err((StatusCode::FORBIDDEN, "invalid CSRF token").into_response());
    }
    if s.actions.check().is_err() {
        return Err(done(
            s,
            &sess,
            StatusCode::TOO_MANY_REQUESTS,
            false,
            "Too many actions. Try again in a minute.",
            back,
        ));
    }
    let email = identity.email.clone();
    Ok(Gate {
        name: match email.as_deref() {
            Some(m) => format!("{} ({m})", s.cfg.user),
            None => s.cfg.user.clone(),
        },
        email,
        network: ip_prefix(ip),
        sess,
        token,
        ip,
        stepup: None,
    })
}

/// Lockout, then a fresh code or (for [`Need::Window`]) the step-up window.
async fn authorize(
    s: &AdminState,
    g: &mut Gate,
    action: &'static str,
    code: &str,
    need: Need,
    back: &str,
) -> Result<(), Response> {
    let now = s.now();
    let refuse = |g: &Gate, status, msg: &str| done(s, &g.sess, status, false, msg, back);
    if s.lockout.locked_for(g.ip, now).is_some() {
        write_audit(
            s,
            Audit {
                outcome: "locked",
                ..g.audit(now, action)
            },
        )
        .await;
        return Err(refuse(
            g,
            StatusCode::TOO_MANY_REQUESTS,
            "Too many wrong codes. Try again later.",
        ));
    }
    let code = code.trim();
    if code.is_empty() {
        if need == Need::Window {
            if let Some(sess) = s
                .sessions
                .use_stepup(&g.token, now, &g.network, g.email.as_deref())
            {
                g.sess = sess;
                g.stepup = Some("window");
                return Ok(());
            }
        }
        write_audit(
            s,
            Audit {
                outcome: "stepup_required",
                ..g.audit(now, action)
            },
        )
        .await;
        let msg = match need {
            Need::Fresh => "This action always needs a fresh authenticator code.",
            Need::Window => "Enter your authenticator code (no step-up window is open).",
        };
        return Err(refuse(g, StatusCode::UNAUTHORIZED, msg));
    }
    let step = if code.len() <= 16 {
        totp_match(&s.cfg.totp_secret, code, now)
    } else {
        None
    };
    let fresh = {
        let mut last = s.last_totp_step.lock().unwrap_or_else(|e| e.into_inner());
        match step {
            Some(st) if st > *last => {
                *last = st;
                true
            }
            _ => false,
        }
    };
    if !fresh {
        s.lockout.failure(g.ip, now);
        let outcome = if step.is_none() {
            "totp_failed"
        } else {
            "totp_reused"
        };
        tracing::warn!(network = %g.network, action, outcome, "admin action refused");
        write_audit(
            s,
            Audit {
                outcome,
                ..g.audit(now, action)
            },
        )
        .await;
        return Err(refuse(g, StatusCode::UNAUTHORIZED, CODE_ERROR));
    }
    if let Some(sess) = s
        .sessions
        .open_stepup(&g.token, now, &g.network, g.email.as_deref())
    {
        g.sess = sess;
    }
    g.stepup = Some("fresh");
    Ok(())
}

/// Run `f` and append `audit` (with the outcome `f` returns and the step-up
/// kind) in one transaction on the API's connection.
async fn commit<T, F>(
    s: &AdminState,
    g: &Gate,
    back: &str,
    audit: Audit,
    f: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<(T, &'static str), StoreError> + Send + 'static,
{
    let stepup = format!("stepup={}", g.stepup.unwrap_or("none"));
    let detail = Some(match audit.detail {
        Some(ref d) => format!("{d}; {stepup}"),
        None => stepup,
    });
    let r = s
        .app
        .v2()
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let (v, outcome) = f(&tx)?;
            controls::audit(
                &tx,
                &Audit {
                    outcome,
                    detail,
                    ..audit
                },
            )?;
            tx.commit()?;
            Ok(v)
        })
        .await;
    r.map_err(|e| {
        tracing::error!(error = %e, "admin action failed");
        done(
            s,
            &g.sess,
            StatusCode::INTERNAL_SERVER_ERROR,
            false,
            "Storage error; nothing was changed.",
            back,
        )
    })
}

/// A refused input: audited without the submitted text; no code is used.
async fn invalid(
    s: &AdminState,
    g: &Gate,
    action: &'static str,
    msg: &'static str,
    back: &str,
) -> Response {
    write_audit(
        s,
        Audit {
            outcome: "invalid",
            detail: Some(msg.to_string()),
            ..g.audit(s.now(), action)
        },
    )
    .await;
    done(s, &g.sess, StatusCode::BAD_REQUEST, false, msg, back)
}

macro_rules! tri {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(r) => return r,
        }
    };
}

fn is_fingerprint(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The step-up window, for result messages.
fn window_note(g: &Gate) -> String {
    match g.stepup {
        Some("fresh") => format!(
            " Step-up open for {} min or {STEPUP_ACTIONS} actions.",
            STEPUP_SECS / 60
        ),
        _ => String::new(),
    }
}

// ----------------------------------------------------------------- bans ---

pub(super) async fn bans_page(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let now = s.now();
    let manual = s.app.controls().bans(now);
    let auto = s.app.auth_bans().active(now);
    page(
        &s,
        "Bans",
        "bans",
        &sess,
        "/admin/bans",
        None,
        false,
        &pages::bans(now, &manual, &auto, &sess.csrf),
    )
}

#[derive(Deserialize)]
pub(super) struct BanForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    duration: String,
    #[serde(default)]
    reason: String,
}

pub(super) async fn ban_add(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Form(f): Form<BanForm>,
) -> Response {
    const ACTION: &str = "ban.add";
    let back = "/admin/bans";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, back));
    let net = match controls::parse_ban_target(&f.target) {
        Ok(n) => n,
        Err(m) => return invalid(&s, &g, ACTION, m, back).await,
    };
    let secs = match controls::parse_duration(&f.duration) {
        Ok(d) => d,
        Err(m) => return invalid(&s, &g, ACTION, m, back).await,
    };
    let reason = match controls::parse_reason(&f.reason) {
        Ok(r) => r,
        Err(m) => return invalid(&s, &g, ACTION, m, back).await,
    };
    let now = s.now();
    let ctl = s.app.controls();
    let replacing = ctl.bans(now).iter().any(|b| b.net == net);
    if !replacing && ctl.ban_count(now) >= controls::MAX_MANUAL_BANS {
        return invalid(
            &s,
            &g,
            ACTION,
            "Too many manual bans (1000); lift some first.",
            back,
        )
        .await;
    }
    let need = if controls::is_broad_ban(&net) {
        Need::Fresh
    } else {
        Need::Window
    };
    tri!(authorize(&s, &mut g, ACTION, &f.totp, need, back).await);
    let now = s.now();
    let ban = ManualBan {
        net,
        until: now + secs,
        reason: reason.clone(),
        created_at: now,
        actor: g.name.clone(),
    };
    let audit = Audit {
        target: Some(net.to_string()),
        detail: Some(format!("{} {reason}", pages::fmt_dur(secs))),
        ..g.audit(now, ACTION)
    };
    let b = ban.clone();
    tri!(
        commit(&s, &g, back, audit, move |c| Ok((
            controls::put_ban(c, &b)?,
            "ok"
        )))
        .await
    );
    ctl.put_ban(ban);
    tracing::warn!(prefix = %net, secs, "admin: manual ban");
    done(
        &s,
        &g.sess,
        StatusCode::OK,
        true,
        &format!(
            "Banned {net} for {}.{}",
            pages::fmt_dur(secs),
            window_note(&g)
        ),
        back,
    )
}

#[derive(Deserialize)]
pub(super) struct TargetForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    target: String,
}

pub(super) async fn ban_remove(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Form(f): Form<TargetForm>,
) -> Response {
    const ACTION: &str = "ban.remove";
    let back = "/admin/bans";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, back));
    // Same normalisation as `ban.add`, so the stored prefix is found.
    let net = match controls::parse_ban_target(&f.target) {
        Ok(n) => n,
        Err(m) => return invalid(&s, &g, ACTION, m, back).await,
    };
    tri!(authorize(&s, &mut g, ACTION, &f.totp, Need::Window, back).await);
    let audit = Audit {
        target: Some(net.to_string()),
        ..g.audit(s.now(), ACTION)
    };
    let removed = tri!(
        commit(&s, &g, back, audit, move |c| {
            let r = controls::delete_ban(c, &net)?;
            Ok((r, if r { "ok" } else { "noop" }))
        })
        .await
    );
    let removed = s.app.controls().remove_ban(&net) || removed;
    let msg = if removed {
        format!("Lifted the ban on {net}.{}", window_note(&g))
    } else {
        format!("{net} was not banned.")
    };
    done(&s, &g.sess, StatusCode::OK, true, &msg, back)
}

/// Lift an automatic (auth-failure) ban, keyed like the bans themselves
/// (IPv4 address, IPv6 /64). The audit row keeps the /24 or /48 only, like
/// every other stored client address, and is written first.
pub(super) async fn unban(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Form(f): Form<TargetForm>,
) -> Response {
    const ACTION: &str = "ban.unban";
    let back = "/admin/bans";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, back));
    let Ok(target) = f.target.trim().parse::<IpAddr>() else {
        return invalid(&s, &g, ACTION, "Not an IP address.", back).await;
    };
    tri!(authorize(&s, &mut g, ACTION, &f.totp, Need::Window, back).await);
    let now = s.now();
    let key = ip_key(target);
    let banned = s.app.auth_bans().banned_for(key, now).is_some();
    let audit = Audit {
        target: Some(ip_prefix(key)),
        ..g.audit(now, ACTION)
    };
    // Fail closed: nothing is lifted unless the audit row is stored.
    tri!(
        commit(&s, &g, back, audit, move |_| Ok((
            (),
            if banned { "ok" } else { "noop" }
        )))
        .await
    );
    let lifted = s.app.auth_bans().unban(key, now);
    let msg = if lifted {
        format!("Lifted the automatic ban on {key}.{}", window_note(&g))
    } else {
        format!("{key} was not banned.")
    };
    done(&s, &g.sess, StatusCode::OK, true, &msg, back)
}

// -------------------------------------------------------------- gateway ---

fn quotas(s: &AdminState) -> GatewayQuotas {
    let c = s.app.controls();
    let p = &s.app.v2().licence;
    GatewayQuotas {
        open: p.gateway_open(),
        require_licence: p.gateway_require_licence(),
        per_hour: c.effective("GATEWAY_GROUP_PER_HOUR"),
        max_tokens: p.gateway_max_tokens_per_group(),
        max_groups: p.gateway_max_groups(),
    }
}

fn effective_licence(s: &AdminState, r: &mut queries::GatewayRow) {
    let p = &s.app.v2().licence;
    r.licensed = r.licensed_flag
        && !r
            .app_transaction_id
            .as_deref()
            .is_some_and(|t| p.is_tx_revoked(t));
}

pub(super) async fn gateway_page(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let now = s.now();
    let mut g = tri!(s.query(move |c| queries::gateway(c, now)).await);
    for r in &mut g.rows {
        effective_licence(&s, r);
    }
    page(
        &s,
        "Gateway",
        "gateway",
        &sess,
        "/admin/gateway",
        None,
        false,
        &pages::gateway(now, &g, &quotas(&s)),
    )
}

pub(super) async fn gateway_group_page(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let sess = tri!(need_page(&s, &headers));
    if !crate::v2::is_id128(&id) {
        return not_found_response();
    }
    let now = s.now();
    let path = format!("/admin/gateway/{id}");
    let Some(mut d) = tri!(s.query(move |c| queries::gateway_detail(c, now, &id)).await) else {
        return not_found_response();
    };
    effective_licence(&s, &mut d.row);
    page(
        &s,
        "Gateway group",
        "gateway",
        &sess,
        &path,
        None,
        false,
        &pages::gateway_detail(now, &d, &quotas(&s), &sess.csrf),
    )
}

#[derive(Deserialize)]
pub(super) struct TokenForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    token: String,
}

pub(super) async fn gateway_unbind(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<TokenForm>,
) -> Response {
    const ACTION: &str = "gateway.unbind";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, "/admin/gateway"));
    // The path id is checked only after the session (no pre-auth oracle).
    if !crate::v2::is_id128(&id) {
        return not_found_response();
    }
    let back = format!("/admin/gateway/{id}");
    let fp = f.token.trim().to_string();
    if !is_fingerprint(&fp) {
        return invalid(&s, &g, ACTION, "Not a token fingerprint.", &back).await;
    }
    tri!(authorize(&s, &mut g, ACTION, &f.totp, Need::Window, &back).await);
    let audit = Audit {
        target: Some(id.clone()),
        detail: Some(format!("token {fp}")),
        ..g.audit(s.now(), ACTION)
    };
    let gid = id.clone();
    let found = tri!(
        commit(&s, &g, &back, audit, move |c| {
            let r = controls::unbind_gateway_token(c, &gid, &fp)?;
            Ok((r, if r { "ok" } else { "noop" }))
        })
        .await
    );
    let msg = if found {
        format!(
            "Token unbound: it may now be bound by another gateway group.{}",
            window_note(&g)
        )
    } else {
        "No such token bound to this group.".to_string()
    };
    done(&s, &g.sess, StatusCode::OK, found, &msg, &back)
}

#[derive(Deserialize)]
pub(super) struct CodeForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
}

/// Remove a group from the gateway: a reset (membership and bindings), not a
/// block; the group may register again. Suspension is the block.
pub(super) async fn gateway_remove(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<CodeForm>,
) -> Response {
    const ACTION: &str = "gateway.remove";
    let back = "/admin/gateway";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, back));
    if !crate::v2::is_id128(&id) {
        return not_found_response();
    }
    tri!(authorize(&s, &mut g, ACTION, &f.totp, Need::Window, back).await);
    let audit = Audit {
        target: Some(id.clone()),
        ..g.audit(s.now(), ACTION)
    };
    let gid = id.clone();
    let (member, tokens) = tri!(
        commit(&s, &g, back, audit, move |c| {
            let r = controls::remove_gateway_group(c, &gid)?;
            Ok((r, if r.0 { "ok" } else { "noop" }))
        })
        .await
    );
    let msg = if member {
        format!(
            "Removed {id} from the gateway; {tokens} tokens unbound. It can register again: suspend the group to keep it out.{}",
            window_note(&g)
        )
    } else {
        format!("{id} was not a gateway group.")
    };
    done(&s, &g.sess, StatusCode::OK, member, &msg, back)
}

// --------------------------------------------------------------- groups ---

#[derive(Deserialize)]
pub(super) struct ReasonForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    reason: String,
}

pub(super) async fn group_suspend(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<ReasonForm>,
) -> Response {
    const ACTION: &str = "group.suspend";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, "/admin/groups"));
    if !crate::v2::is_id128(&id) {
        return not_found_response();
    }
    let back = format!("/admin/groups/{id}");
    let reason = match controls::parse_reason(&f.reason) {
        Ok(r) => r,
        Err(m) => return invalid(&s, &g, ACTION, m, &back).await,
    };
    tri!(authorize(&s, &mut g, ACTION, &f.totp, Need::Window, &back).await);
    let now = s.now();
    let audit = Audit {
        target: Some(id.clone()),
        detail: Some(reason.clone()),
        ..g.audit(now, ACTION)
    };
    let (gid, name) = (id.clone(), g.name.clone());
    let r = tri!(
        commit(&s, &g, &back, audit, move |c| {
            let r = controls::suspend(c, &gid, now, &reason, &name)?;
            Ok((
                r,
                match r {
                    Some(true) => "ok",
                    Some(false) => "noop",
                    None => "not_found",
                },
            ))
        })
        .await
    );
    if r.is_none() {
        return done(
            &s,
            &g.sess,
            StatusCode::NOT_FOUND,
            false,
            "No such group.",
            &back,
        );
    }
    // Flag first, then drop the streams: a stream registering meanwhile
    // sees the flag (see `open_stream`).
    s.app.controls().set_suspended(&id, true);
    let closed = s.app.v2().hub.remove_group(&id);
    tracing::warn!(group = %id, streams = closed, "admin: group suspended");
    done(
        &s,
        &g.sess,
        StatusCode::OK,
        true,
        &format!(
            "Suspended {id}; closed {closed} streams.{}",
            window_note(&g)
        ),
        &back,
    )
}

pub(super) async fn group_unsuspend(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<CodeForm>,
) -> Response {
    const ACTION: &str = "group.unsuspend";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, "/admin/groups"));
    if !crate::v2::is_id128(&id) {
        return not_found_response();
    }
    let back = format!("/admin/groups/{id}");
    tri!(authorize(&s, &mut g, ACTION, &f.totp, Need::Window, &back).await);
    let audit = Audit {
        target: Some(id.clone()),
        ..g.audit(s.now(), ACTION)
    };
    let gid = id.clone();
    let was = tri!(
        commit(&s, &g, &back, audit, move |c| {
            let r = controls::unsuspend(c, &gid)?;
            Ok((r, if r { "ok" } else { "noop" }))
        })
        .await
    );
    s.app.controls().set_suspended(&id, false);
    let msg = if was {
        format!("{id} is active again.{}", window_note(&g))
    } else {
        format!("{id} was not suspended.")
    };
    done(&s, &g.sess, StatusCode::OK, true, &msg, &back)
}

// ------------------------------------------------------------- licences ---

pub(super) async fn licences_page(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let mut config: Vec<String> = s.app.v2().licence.revoked.0.iter().cloned().collect();
    config.sort();
    let (rows, config) = tri!(
        s.query(move |c| Ok((
            queries::revoked_licences(c)?,
            queries::attached_counts(c, &config)?
        )))
        .await
    );
    page(
        &s,
        "Licences",
        "licences",
        &sess,
        "/admin/licences",
        None,
        false,
        &pages::licences(&rows, &config, &sess.csrf),
    )
}

#[derive(Deserialize)]
pub(super) struct RevokeForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    tx: String,
    #[serde(default)]
    reason: String,
}

pub(super) async fn licence_revoke(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Form(f): Form<RevokeForm>,
) -> Response {
    const ACTION: &str = "licence.revoke";
    let back = "/admin/licences";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, back));
    let tx = match controls::parse_tx(&f.tx) {
        Ok(t) => t,
        Err(m) => return invalid(&s, &g, ACTION, m, back).await,
    };
    let reason = match controls::parse_reason(&f.reason) {
        Ok(r) => r,
        Err(m) => return invalid(&s, &g, ACTION, m, back).await,
    };
    tri!(authorize(&s, &mut g, ACTION, &f.totp, Need::Fresh, back).await);
    let now = s.now();
    let fp = controls::fingerprint(&tx);
    let audit = Audit {
        target: Some(fp.clone()),
        detail: Some(reason.clone()),
        ..g.audit(now, ACTION)
    };
    let (t, name) = (tx.clone(), g.name.clone());
    let attached = tri!(
        commit(&s, &g, back, audit, move |c| {
            let new = controls::revoke(c, &t, now, &reason, &name)?;
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM group_licences WHERE app_transaction_id = ?1",
                [&t],
                |r| r.get(0),
            )?;
            Ok((n, if new { "ok" } else { "noop" }))
        })
        .await
    );
    s.app.v2().licence.set_revoked(&tx, true);
    // Never log the purchase id itself.
    tracing::warn!(purchase = %fp, groups = attached, "admin: licence revoked");
    done(
        &s,
        &g.sess,
        StatusCode::OK,
        true,
        &format!(
            "Revoked purchase {fp}; {attached} attached groups are now unlicensed.{}",
            window_note(&g)
        ),
        back,
    )
}

#[derive(Deserialize)]
pub(super) struct FpForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    fp: String,
}

pub(super) async fn licence_restore(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Form(f): Form<FpForm>,
) -> Response {
    const ACTION: &str = "licence.restore";
    let back = "/admin/licences";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, back));
    let fp = f.fp.trim().to_string();
    if !is_fingerprint(&fp) {
        return invalid(&s, &g, ACTION, "Not a purchase fingerprint.", back).await;
    }
    tri!(authorize(&s, &mut g, ACTION, &f.totp, Need::Fresh, back).await);
    let audit = Audit {
        target: Some(fp.clone()),
        ..g.audit(s.now(), ACTION)
    };
    let f2 = fp.clone();
    let tx = tri!(
        commit(&s, &g, back, audit, move |c| {
            match controls::revoked_by_fingerprint(c, &f2)? {
                Some(t) => {
                    controls::restore(c, &t)?;
                    Ok((Some(t), "ok"))
                }
                None => Ok((None, "noop")),
            }
        })
        .await
    );
    let Some(tx) = tx else {
        return done(
            &s,
            &g.sess,
            StatusCode::NOT_FOUND,
            false,
            "No panel revocation with this fingerprint.",
            back,
        );
    };
    let policy = &s.app.v2().licence;
    policy.set_revoked(&tx, false);
    let msg = if policy.is_tx_revoked(&tx) {
        format!("Restored {fp} in the panel, but LICENCE_REVOKED_TX still revokes it.")
    } else {
        format!("Restored purchase {fp}.{}", window_note(&g))
    };
    done(&s, &g.sess, StatusCode::OK, true, &msg, back)
}

// --------------------------------------------------------------- limits ---

pub(super) async fn limits_page(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let c = s.app.controls();
    let rows: Vec<LimitRow> = LIMIT_KEYS
        .iter()
        .map(|k| LimitRow {
            key: k.key,
            config: c.base(k.key),
            overridden: c.override_of(k.key),
        })
        .collect();
    page(
        &s,
        "Limits",
        "limits",
        &sess,
        "/admin/limits",
        None,
        false,
        &pages::limits(&rows, &sess.csrf),
    )
}

fn limit_need(key: &str) -> Need {
    if controls::limit_needs_fresh(key) {
        Need::Fresh
    } else {
        Need::Window
    }
}

#[derive(Deserialize)]
pub(super) struct LimitForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
}

pub(super) async fn limit_set(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Form(f): Form<LimitForm>,
) -> Response {
    const ACTION: &str = "limit.set";
    let back = "/admin/limits";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, back));
    let Some(key) = controls::limit_key(&f.key) else {
        return invalid(&s, &g, ACTION, "Unknown limit.", back).await;
    };
    let value = match f.value.trim().parse::<u32>() {
        Ok(v) if (key.min..=key.max).contains(&v) => v,
        _ => return invalid(&s, &g, ACTION, "Value outside the allowed range.", back).await,
    };
    tri!(authorize(&s, &mut g, ACTION, &f.totp, limit_need(key.key), back).await);
    let now = s.now();
    let ctl = s.app.controls();
    let old = ctl.effective(key.key);
    let audit = Audit {
        target: Some(key.key.to_string()),
        detail: Some(format!("{old} -> {value}")),
        ..g.audit(now, ACTION)
    };
    let (k, name) = (key.key, g.name.clone());
    tri!(
        commit(&s, &g, back, audit, move |c| Ok((
            controls::put_override(c, k, value, now, &name)?,
            "ok"
        )))
        .await
    );
    ctl.set_override(key, Some(value));
    s.app.apply_limit(key.key);
    tracing::warn!(key = key.key, old, value, "admin: limit override");
    let shown = match key.kind {
        LimitKind::Switch => (value != 0).to_string(),
        LimitKind::Number => value.to_string(),
    };
    done(
        &s,
        &g.sess,
        StatusCode::OK,
        true,
        &format!("{} is now {shown}.{}", key.key, window_note(&g)),
        back,
    )
}

#[derive(Deserialize)]
pub(super) struct KeyForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    key: String,
}

pub(super) async fn limit_reset(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Form(f): Form<KeyForm>,
) -> Response {
    const ACTION: &str = "limit.reset";
    let back = "/admin/limits";
    let mut g = tri!(gate(&s, &headers, ip, &identity, &f.csrf, back));
    let Some(key) = controls::limit_key(&f.key) else {
        return invalid(&s, &g, ACTION, "Unknown limit.", back).await;
    };
    tri!(authorize(&s, &mut g, ACTION, &f.totp, limit_need(key.key), back).await);
    let ctl = s.app.controls();
    let audit = Audit {
        target: Some(key.key.to_string()),
        detail: Some(format!(
            "{} -> {}",
            ctl.effective(key.key),
            ctl.base(key.key)
        )),
        ..g.audit(s.now(), ACTION)
    };
    let k = key.key;
    tri!(
        commit(&s, &g, back, audit, move |c| {
            let r = controls::delete_override(c, k)?;
            Ok(((), if r { "ok" } else { "noop" }))
        })
        .await
    );
    ctl.set_override(key, None);
    s.app.apply_limit(key.key);
    done(
        &s,
        &g.sess,
        StatusCode::OK,
        true,
        &format!(
            "{} is back to its configured value.{}",
            key.key,
            window_note(&g)
        ),
        back,
    )
}

// ---------------------------------------------------------------- audit ---

pub(super) async fn audit_page(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let rows = tri!(s.query(queries::audit_log).await);
    page(
        &s,
        "Audit log",
        "audit",
        &sess,
        "/admin/audit",
        None,
        false,
        &pages::audit(s.now(), &rows),
    )
}
