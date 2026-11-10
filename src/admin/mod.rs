//! Admin analytics panel on its own listener (`ADMIN_BIND`), see README
//! "Admin panel". The public router has no admin routes and this router has
//! no public API routes.
//!
//! Access control, in order: IP allowlist on the real client IP and, when
//! configured, a valid Cloudflare Access JWT (else a plain 404), login with password (argon2id) and TOTP, server-side session
//! cookie, per-session CSRF token on every POST. Every response carries
//! strict security headers. Pages show metadata only.

// Handlers return `Result<_, Response>` where the error is the finished
// response, built on the cold path only.
#![allow(clippy::result_large_err)]

pub mod access;
pub mod auth;
pub mod pages;
pub mod queries;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::limit::ConcurrencyLimitLayer;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use self::access::{AccessVerifier, Identity};
use self::auth::{csrf_ok, ct_str_eq, totp_match, verify_password, Lockout, Session, Sessions};
use self::pages::{Page, Runtime};
use self::queries::GroupFilter;
use crate::api::AppState;
use crate::config::{AdminConfig, ApnsMode, Config, LicenceMode, Mode, TrustProxy};
use crate::metrics::{ip_prefix, Event};
use crate::v2::store::{Store, StoreError};

pub const COOKIE: &str = "mc_admin";
pub const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const LOGIN_ERROR: &str = "Login failed. Check your user, password and code, or try again later.";
const MAX_BODY: usize = 4096;
const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Info {
    mode: &'static str,
    apns_mode: &'static str,
    licence_mode: &'static str,
    licence_grace_until: Option<u64>,
    trust_proxy: &'static str,
}

pub struct AdminState {
    app: Arc<AppState>,
    cfg: AdminConfig,
    sessions: Sessions,
    lockout: Lockout,
    /// Read-only connection: panel queries never hold the API's connection.
    db: Store,
    info: Info,
    /// Last TOTP step accepted: a code cannot be used twice.
    last_totp_step: Mutex<u64>,
    /// argon2 needs ~19 MB per check: one at a time.
    verify_gate: Semaphore,
    /// Cloudflare Access JWT check (`ADMIN_CF_ACCESS_*`).
    access: Option<AccessVerifier>,
}

/// The resolved client IP, set by the allowlist middleware.
#[derive(Clone, Copy)]
struct ClientIp(IpAddr);

impl AdminState {
    pub fn new(app: Arc<AppState>, config: &Config) -> Result<Self, String> {
        Self::build(app, config, None)
    }

    /// Like `new`, but the Cloudflare Access keys come from `certs_url`
    /// (tests serve a mock JWKS). The expected `iss` is unchanged.
    pub fn new_with_access_certs_url(
        app: Arc<AppState>,
        config: &Config,
        certs_url: String,
    ) -> Result<Self, String> {
        Self::build(app, config, Some(certs_url))
    }

    fn build(
        app: Arc<AppState>,
        config: &Config,
        certs_url: Option<String>,
    ) -> Result<Self, String> {
        let cfg = config
            .admin
            .config()
            .ok_or("admin panel is not enabled")?
            .clone();
        let db = app
            .v2()
            .store
            .open_reader()
            .map_err(|e| format!("admin: cannot open database reader: {e}"))?;
        let access = match (&cfg.cf_access, certs_url) {
            (None, _) => None,
            (Some(c), None) => Some(AccessVerifier::new(c)?),
            (Some(c), Some(url)) => Some(AccessVerifier::with_certs_url(c, url)?),
        };
        let v2 = &config.v2;
        Ok(Self {
            access,
            app,
            sessions: Sessions::new(cfg.session_secs),
            lockout: Lockout::default(),
            db,
            info: Info {
                mode: match config.mode {
                    Mode::Hosted => "hosted",
                    Mode::SelfHosted => "selfhosted",
                },
                apns_mode: match v2.apns_mode {
                    ApnsMode::Direct => "direct",
                    ApnsMode::Mock => "mock",
                    ApnsMode::Gateway => "gateway",
                },
                licence_mode: match v2.licence_mode {
                    LicenceMode::Open => "open",
                    LicenceMode::AppTransaction => "app_transaction",
                },
                licence_grace_until: v2.licence_grace_until,
                trust_proxy: match config.trust_proxy {
                    TrustProxy::None => "none",
                    TrustProxy::Cloudflare { .. } => "cloudflare",
                    TrustProxy::Xff(_) => "xff",
                },
            },
            cfg,
            last_totp_step: Mutex::new(0),
            verify_gate: Semaphore::new(1),
        })
    }

    fn now(&self) -> u64 {
        self.app.now()
    }

    fn allowed(&self, ip: IpAddr) -> bool {
        self.cfg.allow_any || self.cfg.allow_ips.iter().any(|n| n.contains(&ip))
    }

    /// Fetch the Cloudflare Access keys if due. `None` when Access is off,
    /// else whether usable keys are cached afterwards.
    pub async fn refresh_access_keys(&self) -> Option<bool> {
        let a = self.access.as_ref()?;
        a.refresh(self.now(), true).await;
        Some(a.key_count() > 0)
    }

    pub fn cleanup(&self) {
        let now = self.now();
        self.sessions.cleanup(now);
        self.lockout.cleanup(now);
    }

    async fn query<R, F>(&self, f: F) -> Result<R, Response>
    where
        R: Send + 'static,
        F: FnOnce(&rusqlite::Connection) -> Result<R, StoreError> + Send + 'static,
    {
        self.db.call(move |c| f(c)).await.map_err(|e| {
            tracing::error!(error = %e, "admin query failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        })
    }

    fn runtime(&self) -> Runtime {
        let m = self.app.metrics();
        let p = m.latency_percentiles();
        let path = self.db.path();
        let size = |p: &std::path::Path| std::fs::metadata(p).map_or(0, |m| m.len());
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        Runtime {
            version: VERSION,
            uptime_secs: m.uptime().as_secs(),
            rss_bytes: rss_bytes(),
            db_bytes: size(path) + size(std::path::Path::new(&wal)),
            macs_online: self.app.v2().hub.len(),
            latency_p50_ms: p.map(|p| p.0),
            latency_p95_ms: p.map(|p| p.1),
            metrics_dropped: m.dropped(),
            admin_sessions: self.sessions.len(),
            mode: self.info.mode,
            apns_mode: self.info.apns_mode,
            licence_mode: self.info.licence_mode,
            licence_grace_until: self.info.licence_grace_until,
            trust_proxy: self.info.trust_proxy,
        }
    }

    fn record_login(
        &self,
        ip: IpAddr,
        country: Option<String>,
        outcome: &'static str,
        detail: &str,
        identity: &Identity,
    ) {
        let mut e = Event::new("admin_login").ip(ip).outcome(outcome);
        // The verified Cloudflare Access e-mail is the only identity kept.
        let detail = match (detail, identity.email.as_deref()) {
            ("", None) => None,
            (d, None) => Some(d.to_string()),
            ("", Some(m)) => Some(m.to_string()),
            (d, Some(m)) => Some(format!("{d} {m}")),
        };
        if let Some(d) = detail {
            e = e.detail(d);
        }
        e.country = country;
        self.app.metrics().record(e);
    }
}

/// Resident set size from `/proc` (Linux); `None` elsewhere.
fn rss_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/admin", get(root))
        .route("/admin/", get(overview_page))
        .route("/admin/login", get(login_form).post(login))
        .route("/admin/logout", post(logout))
        .route("/admin/groups", get(groups_page))
        .route("/admin/groups/{id}", get(group_page))
        .route("/admin/pushes", get(pushes_page))
        .route("/admin/security", get(security_page))
        .route("/admin/api/overview", get(api_overview))
        .route("/admin/api/groups", get(api_groups))
        .route("/admin/api/groups/{id}", get(api_group))
        .route("/admin/api/pushes", get(api_pushes))
        .route("/admin/api/security", get(api_security))
        .route("/admin/export/daily.csv", get(export_csv))
        .route("/admin/style.css", get(style))
        .fallback(not_found)
        .layer(from_fn_with_state(state.clone(), cf_access))
        .layer(from_fn_with_state(state.clone(), allowlist))
        .layer(
            ServiceBuilder::new()
                .layer(from_fn(security_headers))
                .layer(RequestBodyLimitLayer::new(MAX_BODY))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    Duration::from_secs(15),
                ))
                .layer(ConcurrencyLimitLayer::new(8)),
        )
        .with_state(state)
}

/// Serve the admin panel on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    state: Arc<AdminState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Expire sessions and lockouts once a minute; refresh the Cloudflare
/// Access keys when due (hourly, or every minute while none are cached).
pub fn spawn_cleanup(state: Arc<AdminState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            state.cleanup();
            state.refresh_access_keys().await;
        }
    })
}

// ------------------------------------------------------------ middleware ---

/// Same body as the public API's 404: the panel is not revealed.
fn not_found_response() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response()
}

async fn not_found() -> Response {
    not_found_response()
}

async fn allowlist(
    State(s): State<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let ip = s.app.client_ip(peer, req.headers());
    if !s.allowed(ip) {
        tracing::debug!(client_ip = %ip, "admin: not in ADMIN_ALLOW_IPS");
        let mut e = Event::new("admin_denied").ip(ip);
        e.country = s.app.client_country(peer, req.headers());
        s.app.metrics().record(e);
        return not_found_response();
    }
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

/// Cloudflare Access JWT (after the allowlist): missing or invalid is the
/// same plain 404.
async fn cf_access(
    State(s): State<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let identity = match &s.access {
        None => Identity::default(),
        Some(v) => {
            let res = match access::token(req.headers()) {
                None => Err(access::AccessError::Missing),
                Some(t) => v.verify(t, s.now()).await,
            };
            match res {
                Ok(id) => id,
                Err(e) => {
                    let ip = req
                        .extensions()
                        .get::<ClientIp>()
                        .map_or_else(|| s.app.client_ip(peer, req.headers()), |c| c.0);
                    tracing::debug!(client_ip = %ip, reason = e.label(), "admin: Cloudflare Access check failed");
                    let mut ev = Event::new("admin_denied").ip(ip).detail(e.label());
                    ev.country = s.app.client_country(peer, req.headers());
                    s.app.metrics().record(ev);
                    return not_found_response();
                }
            }
        }
    };
    req.extensions_mut().insert(identity);
    next.run(req).await
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    for (k, v) in [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (
            header::HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
    ] {
        h.insert(k, HeaderValue::from_static(v));
    }
    r
}

// --------------------------------------------------------------- session ---

fn cookie_token(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn set_cookie(token: &str, max_age: u64) -> (header::HeaderName, String) {
    (
        header::SET_COOKIE,
        format!("{COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"),
    )
}

fn session(s: &AdminState, h: &HeaderMap) -> Option<(String, Session)> {
    let t = cookie_token(h)?;
    let sess = s.sessions.get(&t, s.now())?;
    Some((t, sess))
}

/// The logged-in session, or a redirect to the login page.
fn need_page(s: &AdminState, h: &HeaderMap) -> Result<Session, Response> {
    match session(s, h) {
        Some((_, sess)) if sess.authed => Ok(sess),
        _ => Err(Redirect::to("/admin/login").into_response()),
    }
}

/// The logged-in session, or `401` (JSON / CSV routes).
fn need_api(s: &AdminState, h: &HeaderMap) -> Result<Session, Response> {
    match session(s, h) {
        Some((_, sess)) if sess.authed => Ok(sess),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response()),
    }
}

fn wants_refresh(q: &HashMap<String, String>) -> bool {
    q.get("refresh").is_some_and(|v| v == "1")
}

// ----------------------------------------------------------------- login ---

async fn root() -> Redirect {
    Redirect::to("/admin/")
}

async fn style() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        pages::STYLE_CSS,
    )
        .into_response()
}

fn login_page(
    status: StatusCode,
    error: Option<&str>,
    csrf: &str,
    cookie: Option<(header::HeaderName, String)>,
) -> Response {
    let page = Page {
        title: "Log in",
        nav: "",
        csrf: None,
        path: "/admin/login",
        json: None,
        refresh: false,
        version: VERSION,
    };
    let html = Html(pages::layout(&page, &pages::login(error, csrf)));
    match cookie {
        Some(c) => (status, [c], html).into_response(),
        None => (status, html).into_response(),
    }
}

fn fresh_login(s: &AdminState, status: StatusCode, error: Option<&str>) -> Response {
    let (token, csrf) = s.sessions.create_pre(s.now());
    login_page(
        status,
        error,
        &csrf,
        Some(set_cookie(&token, auth::PRE_SESSION_SECS)),
    )
}

async fn login_form(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    match session(&s, &headers) {
        Some((_, sess)) if sess.authed => Redirect::to("/admin/").into_response(),
        Some((_, sess)) => login_page(StatusCode::OK, None, &sess.csrf, None),
        None => fresh_login(&s, StatusCode::OK, None),
    }
}

#[derive(Deserialize)]
struct LoginForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    totp: String,
}

async fn login(
    State(s): State<Arc<AdminState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    axum::Extension(identity): axum::Extension<Identity>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let now = s.now();
    let country = s.app.client_country(peer, &headers);
    // CSRF first: the form must come from a page this server rendered.
    let Some((pre_token, pre)) = session(&s, &headers).filter(|(_, p)| csrf_ok(p, &form.csrf))
    else {
        s.record_login(ip, country, "csrf", "", &identity);
        return fresh_login(
            &s,
            StatusCode::FORBIDDEN,
            Some("Your session expired. Please try again."),
        );
    };
    let fail = |outcome: &'static str, detail: &str| {
        s.record_login(ip, country.clone(), outcome, detail, &identity);
        login_page(StatusCode::UNAUTHORIZED, Some(LOGIN_ERROR), &pre.csrf, None)
    };
    // Locked out: refuse before any expensive work, with the same message.
    if s.lockout.locked_for(ip, now).is_some() {
        return fail("locked", "");
    }
    if form.user.len() > 64 || form.password.len() > 256 || form.totp.len() > 16 {
        s.lockout.failure(ip, now);
        return fail("fail", "too_long");
    }
    // Always run both checks so timing does not reveal which one failed.
    let user_ok = ct_str_eq(&form.user, &s.cfg.user);
    let password_ok = {
        let _permit = s.verify_gate.acquire().await;
        let (phc, pw) = (s.cfg.password_hash.clone(), form.password);
        tokio::task::spawn_blocking(move || verify_password(&phc, &pw))
            .await
            .unwrap_or(false)
    };
    let step = totp_match(&s.cfg.totp_secret, &form.totp, now);
    let fresh_step = {
        let mut last = s.last_totp_step.lock().unwrap_or_else(|e| e.into_inner());
        match step {
            Some(st) if user_ok && password_ok && st > *last => {
                *last = st;
                true
            }
            _ => false,
        }
    };
    if !(user_ok && password_ok && fresh_step) {
        let started_lockout = s.lockout.failure(ip, now);
        let reason = if !(user_ok && password_ok) {
            "credentials"
        } else if step.is_none() {
            "totp"
        } else {
            "totp_reused"
        };
        tracing::warn!(network = %ip_prefix(ip), reason, lockout = started_lockout, "admin login failed");
        return fail("fail", reason);
    }
    s.sessions.remove(&pre_token);
    let token = s.sessions.create_authed(now);
    s.record_login(ip, country, "ok", "", &identity);
    tracing::info!(network = %ip_prefix(ip), "admin login");
    (
        StatusCode::SEE_OTHER,
        [
            set_cookie(&token, s.cfg.session_secs),
            (header::LOCATION, "/admin/".to_string()),
        ],
    )
        .into_response()
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

async fn logout(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    match session(&s, &headers) {
        Some((token, sess)) if csrf_ok(&sess, &form.csrf) => {
            s.sessions.remove(&token);
            (
                StatusCode::SEE_OTHER,
                [
                    set_cookie("", 0),
                    (header::LOCATION, "/admin/login".to_string()),
                ],
            )
                .into_response()
        }
        _ => (StatusCode::FORBIDDEN, "invalid CSRF token").into_response(),
    }
}

// ----------------------------------------------------------------- pages ---

fn page(
    title: &str,
    nav: &str,
    sess: &Session,
    path: &str,
    json: Option<&str>,
    refresh: bool,
    body: &str,
) -> Response {
    let p = Page {
        title,
        nav,
        csrf: Some(&sess.csrf),
        path,
        json,
        refresh,
        version: VERSION,
    };
    Html(pages::layout(&p, body)).into_response()
}

macro_rules! tri {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(r) => return r,
        }
    };
}

async fn overview_page(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let now = s.now();
    let o = tri!(s.query(move |c| queries::overview(c, now)).await);
    let body = pages::overview(now, &o, &s.runtime());
    page(
        "Overview",
        "overview",
        &sess,
        "/admin/",
        Some("/admin/api/overview"),
        wants_refresh(&q),
        &body,
    )
}

async fn groups_page(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(f): Query<GroupFilter>,
) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let now = s.now();
    let f2 = f.clone();
    let rows = tri!(s.query(move |c| queries::groups(c, now, &f2)).await);
    page(
        "Groups",
        "groups",
        &sess,
        "/admin/groups",
        Some("/admin/api/groups"),
        false,
        &pages::groups(now, &rows, &f),
    )
}

async fn load_group(s: &AdminState, id: String) -> Result<queries::GroupDetail, Response> {
    if !crate::v2::is_id128(&id) {
        return Err(not_found_response());
    }
    let now = s.now();
    let mut g = s
        .query(move |c| queries::group_detail(c, now, &id))
        .await?
        .ok_or_else(not_found_response)?;
    let hub = &s.app.v2().hub;
    for d in &mut g.devices {
        if d.kind == "mac" {
            d.online = Some(hub.is_online(&g.group_id, &d.device_id));
        }
    }
    Ok(g)
}

async fn group_page(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let g = tri!(load_group(&s, id).await);
    let path = format!("/admin/groups/{}", g.group_id);
    let json = format!("/admin/api/groups/{}", g.group_id);
    page(
        "Group",
        "groups",
        &sess,
        &path,
        Some(&json),
        wants_refresh(&q),
        &pages::group_detail(s.now(), &g),
    )
}

async fn pushes_page(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let now = s.now();
    let p = tri!(s.query(move |c| queries::pushes(c, now)).await);
    let body = pages::pushes(now, &p, s.info.apns_mode);
    page(
        "Pushes and APNs",
        "pushes",
        &sess,
        "/admin/pushes",
        Some("/admin/api/pushes"),
        wants_refresh(&q),
        &body,
    )
}

async fn security_page(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sess = tri!(need_page(&s, &headers));
    let now = s.now();
    let sec = tri!(s.query(move |c| queries::security(c, now)).await);
    let body = pages::security(now, &sec, s.sessions.len());
    page(
        "Security",
        "security",
        &sess,
        "/admin/security",
        Some("/admin/api/security"),
        wants_refresh(&q),
        &body,
    )
}

// ------------------------------------------------------------------ JSON ---

async fn api_overview(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    tri!(need_api(&s, &headers));
    let now = s.now();
    let o = tri!(s.query(move |c| queries::overview(c, now)).await);
    Json(json!({ "now": now, "overview": o, "runtime": s.runtime() })).into_response()
}

async fn api_groups(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(f): Query<GroupFilter>,
) -> Response {
    tri!(need_api(&s, &headers));
    let now = s.now();
    let rows = tri!(s.query(move |c| queries::groups(c, now, &f)).await);
    Json(json!({ "now": now, "groups": rows })).into_response()
}

async fn api_group(
    State(s): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    tri!(need_api(&s, &headers));
    let g = tri!(load_group(&s, id).await);
    Json(json!({ "now": s.now(), "group": g })).into_response()
}

async fn api_pushes(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    tri!(need_api(&s, &headers));
    let now = s.now();
    let p = tri!(s.query(move |c| queries::pushes(c, now)).await);
    Json(json!({ "now": now, "pushes": p })).into_response()
}

async fn api_security(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    tri!(need_api(&s, &headers));
    let now = s.now();
    let sec = tri!(s.query(move |c| queries::security(c, now)).await);
    Json(json!({ "now": now, "security": sec, "admin_sessions": s.sessions.len() })).into_response()
}

async fn export_csv(State(s): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    tri!(need_api(&s, &headers));
    let csv = tri!(s.query(queries::daily_csv).await);
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"metriccupid-daily.csv\"",
            ),
        ],
        csv,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parsing() {
        let t = "a".repeat(64);
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("x=1; {COOKIE}={t}; y=2").parse().unwrap(),
        );
        assert_eq!(cookie_token(&h), Some(t));
        h.insert(header::COOKIE, format!("{COOKIE}=short").parse().unwrap());
        assert_eq!(cookie_token(&h), None);
        assert_eq!(cookie_token(&HeaderMap::new()), None);
    }

    #[test]
    fn cookie_attributes() {
        let (_, v) = set_cookie("abc", 60);
        for attr in [
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
            "Path=/",
            "Max-Age=60",
        ] {
            assert!(v.contains(attr), "{v}");
        }
    }
}
