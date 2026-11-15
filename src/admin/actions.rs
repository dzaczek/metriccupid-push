//! Management pages and actions: bans, gateway, group suspension, licence
//! revocation, live limits and the audit log.
//!
//! Every action is a POST that passes, in order: an authenticated session
//! (else the login redirect), the session's CSRF token (else `403`), the
//! panel-wide action rate limit, the login lockout, and a fresh TOTP code
//! (step-up; a code already used for a login or an action is refused).
//! Refused codes count toward the login lockout. The change and its audit
//! row are written in one transaction; the in-memory state is updated after.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use rusqlite::Connection;
use serde::Deserialize;

use super::access::Identity;
use super::auth::{csrf_ok, totp_match, Session};
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

/// Who did it: the admin user, plus the Cloudflare Access e-mail when known.
pub(super) struct Actor {
    name: String,
    prefix: String,
}

impl Actor {
    fn audit(&self, now: u64, action: &'static str) -> Audit {
        Audit {
            ts: now,
            actor: self.name.clone(),
            ip_prefix: self.prefix.clone(),
            action,
            target: None,
            detail: None,
            outcome: "ok",
        }
    }
}

/// The outcome page of an action.
fn done(sess: &Session, status: StatusCode, ok: bool, msg: &str, back: &str) -> Response {
    let title = if ok { "Done" } else { "Refused" };
    let mut r = page(
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

async fn write_audit(s: &AdminState, a: Audit) {
    if let Err(e) = s.app.v2().store.call(move |c| controls::audit(c, &a)).await {
        tracing::error!(error = %e, "admin: cannot write audit row");
    }
}

/// Session, CSRF, rate limit, lockout and step-up code for one action.
#[allow(clippy::too_many_arguments)]
async fn step_up(
    s: &AdminState,
    headers: &HeaderMap,
    ip: IpAddr,
    identity: &Identity,
    action: &'static str,
    csrf: &str,
    code: &str,
    back: &str,
) -> Result<(Session, Actor), Response> {
    let sess = match session(s, headers) {
        Some((_, sess)) if sess.authed => sess,
        _ => return Err(Redirect::to("/admin/login").into_response()),
    };
    if !csrf_ok(&sess, csrf) {
        return Err((StatusCode::FORBIDDEN, "invalid CSRF token").into_response());
    }
    if s.actions.check().is_err() {
        return Err(done(
            &sess,
            StatusCode::TOO_MANY_REQUESTS,
            false,
            "Too many actions. Try again in a minute.",
            back,
        ));
    }
    let now = s.now();
    let actor = Actor {
        name: match identity.email.as_deref() {
            Some(m) => format!("{} ({m})", s.cfg.user),
            None => s.cfg.user.clone(),
        },
        prefix: ip_prefix(ip),
    };
    if s.lockout.locked_for(ip, now).is_some() {
        write_audit(
            s,
            Audit {
                outcome: "locked",
                ..actor.audit(now, action)
            },
        )
        .await;
        return Err(done(
            &sess,
            StatusCode::TOO_MANY_REQUESTS,
            false,
            "Too many wrong codes. Try again later.",
            back,
        ));
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
        s.lockout.failure(ip, now);
        let outcome = if step.is_none() {
            "totp_failed"
        } else {
            "totp_reused"
        };
        tracing::warn!(network = %actor.prefix, action, outcome, "admin action refused");
        write_audit(
            s,
            Audit {
                outcome,
                ..actor.audit(now, action)
            },
        )
        .await;
        return Err(done(
            &sess,
            StatusCode::UNAUTHORIZED,
            false,
            CODE_ERROR,
            back,
        ));
    }
    Ok((sess, actor))
}

/// Run `f` and append `audit` (with the outcome `f` returns) in one
/// transaction on the API's connection.
async fn commit<T, F>(
    s: &AdminState,
    sess: &Session,
    back: &str,
    audit: Audit,
    f: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<(T, &'static str), StoreError> + Send + 'static,
{
    let r = s
        .app
        .v2()
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let (v, outcome) = f(&tx)?;
            controls::audit(&tx, &Audit { outcome, ..audit })?;
            tx.commit()?;
            Ok(v)
        })
        .await;
    r.map_err(|e| {
        tracing::error!(error = %e, "admin action failed");
        done(
            sess,
            StatusCode::INTERNAL_SERVER_ERROR,
            false,
            "Storage error; nothing was changed.",
            back,
        )
    })
}

/// A refused input: audited without the submitted text.
async fn invalid(
    s: &AdminState,
    sess: &Session,
    actor: &Actor,
    action: &'static str,
    msg: &'static str,
    back: &str,
) -> Response {
    write_audit(
        s,
        Audit {
            outcome: "invalid",
            detail: Some(msg.to_string()),
            ..actor.audit(s.now(), action)
        },
    )
    .await;
    done(sess, StatusCode::BAD_REQUEST, false, msg, back)
}

macro_rules! tri {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(r) => return r,
        }
    };
}

/// Path group id: anything that is not a group id is the uniform 404.
fn group_id(id: &str) -> Result<(), Response> {
    if crate::v2::is_id128(id) {
        Ok(())
    } else {
        Err(not_found_response())
    }
}

fn is_fingerprint(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// ----------------------------------------------------------------- bans ---

pub(super) async fn bans_page(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let now = s.now();
    let manual = s.app.controls().bans(now);
    let auto = s.app.auth_bans().active(now);
    page(
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
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, back).await);
    let net = match controls::parse_ban_target(&f.target) {
        Ok(n) => n,
        Err(m) => return invalid(&s, &sess, &actor, ACTION, m, back).await,
    };
    let secs = match controls::parse_duration(&f.duration) {
        Ok(d) => d,
        Err(m) => return invalid(&s, &sess, &actor, ACTION, m, back).await,
    };
    let reason = match controls::parse_reason(&f.reason) {
        Ok(r) => r,
        Err(m) => return invalid(&s, &sess, &actor, ACTION, m, back).await,
    };
    let now = s.now();
    let ctl = s.app.controls();
    let replacing = ctl.bans(now).iter().any(|b| b.net == net);
    if !replacing && ctl.ban_count(now) >= controls::MAX_MANUAL_BANS {
        return invalid(
            &s,
            &sess,
            &actor,
            ACTION,
            "Too many manual bans (1000); lift some first.",
            back,
        )
        .await;
    }
    let ban = ManualBan {
        net,
        until: now + secs,
        reason: reason.clone(),
        created_at: now,
        actor: actor.name.clone(),
    };
    let audit = Audit {
        target: Some(net.to_string()),
        detail: Some(format!("{} {reason}", pages::fmt_dur(secs))),
        ..actor.audit(now, ACTION)
    };
    let b = ban.clone();
    tri!(
        commit(&s, &sess, back, audit, move |c| Ok((
            controls::put_ban(c, &b)?,
            "ok"
        )))
        .await
    );
    ctl.put_ban(ban);
    tracing::warn!(prefix = %net, secs, "admin: manual ban");
    done(
        &sess,
        StatusCode::OK,
        true,
        &format!("Banned {net} for {}.", pages::fmt_dur(secs)),
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
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, back).await);
    let net = match controls::parse_ban_target(&f.target) {
        Ok(n) => n,
        Err(m) => return invalid(&s, &sess, &actor, ACTION, m, back).await,
    };
    let audit = Audit {
        target: Some(net.to_string()),
        ..actor.audit(s.now(), ACTION)
    };
    let removed = tri!(
        commit(&s, &sess, back, audit, move |c| {
            let r = controls::delete_ban(c, &net)?;
            Ok((r, if r { "ok" } else { "noop" }))
        })
        .await
    );
    let removed = s.app.controls().remove_ban(&net) || removed;
    let msg = if removed {
        format!("Lifted the ban on {net}.")
    } else {
        format!("{net} was not banned.")
    };
    done(&sess, StatusCode::OK, true, &msg, back)
}

/// Lift an automatic (auth-failure) ban. The audit row keeps the /24 or
/// /48 only, like every other stored client address.
pub(super) async fn unban(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Form(f): Form<TargetForm>,
) -> Response {
    const ACTION: &str = "ban.unban";
    let back = "/admin/bans";
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, back).await);
    let Ok(target) = f.target.trim().parse::<IpAddr>() else {
        return invalid(&s, &sess, &actor, ACTION, "Not an IP address.", back).await;
    };
    let now = s.now();
    let key = ip_key(target);
    let lifted = s.app.auth_bans().unban(key, now);
    write_audit(
        &s,
        Audit {
            target: Some(ip_prefix(key)),
            outcome: if lifted { "ok" } else { "noop" },
            ..actor.audit(now, ACTION)
        },
    )
    .await;
    let msg = if lifted {
        format!("Lifted the automatic ban on {key}.")
    } else {
        format!("{key} was not banned.")
    };
    done(&sess, StatusCode::OK, true, &msg, back)
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
    tri!(group_id(&id));
    let now = s.now();
    let path = format!("/admin/gateway/{id}");
    let Some(mut d) = tri!(s.query(move |c| queries::gateway_detail(c, now, &id)).await) else {
        return not_found_response();
    };
    effective_licence(&s, &mut d.row);
    page(
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
    tri!(group_id(&id));
    let back = format!("/admin/gateway/{id}");
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, &back).await);
    let fp = f.token.trim().to_string();
    if !is_fingerprint(&fp) {
        return invalid(&s, &sess, &actor, ACTION, "Not a token fingerprint.", &back).await;
    }
    let audit = Audit {
        target: Some(id.clone()),
        detail: Some(format!("token {fp}")),
        ..actor.audit(s.now(), ACTION)
    };
    let g = id.clone();
    let found = tri!(
        commit(&s, &sess, &back, audit, move |c| {
            let r = controls::unbind_gateway_token(c, &g, &fp)?;
            Ok((r, if r { "ok" } else { "noop" }))
        })
        .await
    );
    let msg = if found {
        "Token unbound: it may now be bound by another gateway group."
    } else {
        "No such token bound to this group."
    };
    done(&sess, StatusCode::OK, found, msg, &back)
}

#[derive(Deserialize)]
pub(super) struct CodeForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    totp: String,
}

pub(super) async fn gateway_remove(
    State(s): State<Arc<AdminState>>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<CodeForm>,
) -> Response {
    const ACTION: &str = "gateway.remove";
    tri!(group_id(&id));
    let back = "/admin/gateway";
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, back).await);
    let audit = Audit {
        target: Some(id.clone()),
        ..actor.audit(s.now(), ACTION)
    };
    let g = id.clone();
    let (member, tokens) = tri!(
        commit(&s, &sess, back, audit, move |c| {
            let r = controls::remove_gateway_group(c, &g)?;
            Ok((r, if r.0 { "ok" } else { "noop" }))
        })
        .await
    );
    let msg = if member {
        format!("Removed {id} from the gateway; {tokens} tokens unbound.")
    } else {
        format!("{id} was not a gateway group.")
    };
    done(&sess, StatusCode::OK, member, &msg, back)
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
    tri!(group_id(&id));
    let back = format!("/admin/groups/{id}");
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, &back).await);
    let reason = match controls::parse_reason(&f.reason) {
        Ok(r) => r,
        Err(m) => return invalid(&s, &sess, &actor, ACTION, m, &back).await,
    };
    let now = s.now();
    let audit = Audit {
        target: Some(id.clone()),
        detail: Some(reason.clone()),
        ..actor.audit(now, ACTION)
    };
    let (g, name) = (id.clone(), actor.name.clone());
    let r = tri!(
        commit(&s, &sess, &back, audit, move |c| {
            let r = controls::suspend(c, &g, now, &reason, &name)?;
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
        return done(&sess, StatusCode::NOT_FOUND, false, "No such group.", &back);
    }
    s.app.controls().set_suspended(&id, true);
    let closed = s.app.v2().hub.remove_group(&id);
    tracing::warn!(group = %id, streams = closed, "admin: group suspended");
    done(
        &sess,
        StatusCode::OK,
        true,
        &format!("Suspended {id}; closed {closed} streams."),
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
    tri!(group_id(&id));
    let back = format!("/admin/groups/{id}");
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, &back).await);
    let audit = Audit {
        target: Some(id.clone()),
        ..actor.audit(s.now(), ACTION)
    };
    let g = id.clone();
    let was = tri!(
        commit(&s, &sess, &back, audit, move |c| {
            let r = controls::unsuspend(c, &g)?;
            Ok((r, if r { "ok" } else { "noop" }))
        })
        .await
    );
    s.app.controls().set_suspended(&id, false);
    let msg = if was {
        format!("{id} is active again.")
    } else {
        format!("{id} was not suspended.")
    };
    done(&sess, StatusCode::OK, true, &msg, &back)
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
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, back).await);
    let tx = match controls::parse_tx(&f.tx) {
        Ok(t) => t,
        Err(m) => return invalid(&s, &sess, &actor, ACTION, m, back).await,
    };
    let reason = match controls::parse_reason(&f.reason) {
        Ok(r) => r,
        Err(m) => return invalid(&s, &sess, &actor, ACTION, m, back).await,
    };
    let now = s.now();
    let fp = controls::fingerprint(&tx);
    let audit = Audit {
        target: Some(fp.clone()),
        detail: Some(reason.clone()),
        ..actor.audit(now, ACTION)
    };
    let (t, name) = (tx.clone(), actor.name.clone());
    let attached = tri!(
        commit(&s, &sess, back, audit, move |c| {
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
        &sess,
        StatusCode::OK,
        true,
        &format!("Revoked purchase {fp}; {attached} attached groups are now unlicensed."),
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
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, back).await);
    let fp = f.fp.trim().to_string();
    if !is_fingerprint(&fp) {
        return invalid(
            &s,
            &sess,
            &actor,
            ACTION,
            "Not a purchase fingerprint.",
            back,
        )
        .await;
    }
    let audit = Audit {
        target: Some(fp.clone()),
        ..actor.audit(s.now(), ACTION)
    };
    let f2 = fp.clone();
    let tx = tri!(
        commit(&s, &sess, back, audit, move |c| {
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
            &sess,
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
        format!("Restored purchase {fp}.")
    };
    done(&sess, StatusCode::OK, true, &msg, back)
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
        "Limits",
        "limits",
        &sess,
        "/admin/limits",
        None,
        false,
        &pages::limits(&rows, &sess.csrf),
    )
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
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, back).await);
    let Some(key) = controls::limit_key(&f.key) else {
        return invalid(&s, &sess, &actor, ACTION, "Unknown limit.", back).await;
    };
    let value = match f.value.trim().parse::<u32>() {
        Ok(v) if (key.min..=key.max).contains(&v) => v,
        _ => {
            return invalid(
                &s,
                &sess,
                &actor,
                ACTION,
                "Value outside the allowed range.",
                back,
            )
            .await
        }
    };
    let now = s.now();
    let ctl = s.app.controls();
    let old = ctl.effective(key.key);
    let audit = Audit {
        target: Some(key.key.to_string()),
        detail: Some(format!("{old} -> {value}")),
        ..actor.audit(now, ACTION)
    };
    let (k, name) = (key.key, actor.name.clone());
    tri!(
        commit(&s, &sess, back, audit, move |c| Ok((
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
        &sess,
        StatusCode::OK,
        true,
        &format!("{} is now {shown}.", key.key),
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
    let (sess, actor) =
        tri!(step_up(&s, &headers, ip, &identity, ACTION, &f.csrf, &f.totp, back).await);
    let Some(key) = controls::limit_key(&f.key) else {
        return invalid(&s, &sess, &actor, ACTION, "Unknown limit.", back).await;
    };
    let ctl = s.app.controls();
    let audit = Audit {
        target: Some(key.key.to_string()),
        detail: Some(format!(
            "{} -> {}",
            ctl.effective(key.key),
            ctl.base(key.key)
        )),
        ..actor.audit(s.now(), ACTION)
    };
    let k = key.key;
    tri!(
        commit(&s, &sess, back, audit, move |c| {
            let r = controls::delete_override(c, k)?;
            Ok(((), if r { "ok" } else { "noop" }))
        })
        .await
    );
    ctl.set_override(key, None);
    s.app.apply_limit(key.key);
    done(
        &sess,
        StatusCode::OK,
        true,
        &format!("{} is back to its configured value.", key.key),
        back,
    )
}

// ---------------------------------------------------------------- audit ---

pub(super) async fn audit_page(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let rows = tri!(s.query(queries::audit_log).await);
    page(
        "Audit log",
        "audit",
        &sess,
        "/admin/audit",
        None,
        false,
        &pages::audit(s.now(), &rows),
    )
}
