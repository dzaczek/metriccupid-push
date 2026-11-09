//! Admin panel end-to-end: real public + admin listeners, mock APNs, fake
//! clock, temp SQLite.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use argon2::password_hash::{PasswordHasher, SaltString};
use common::{derive, id128, Client};
use metriccupid_push::admin::{self, auth::totp, AdminState};
use metriccupid_push::client_ip::ClientIpResolver;
use metriccupid_push::config::Config;
use metriccupid_push::limits::Clock;
use metriccupid_push::{serve, AppState};
use serde_json::{json, Value};

const T0: u64 = 1_700_000_000;
const PASSWORD: &str = "correct horse battery";
const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SECRET: &[u8] = b"12345678901234567890";
const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct TestClock(AtomicU64);

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Cheap argon2id parameters: the server verifies with whatever the hash says.
fn test_hash() -> String {
    let salt = SaltString::encode_b64(&[9u8; 16]).unwrap();
    let params = argon2::Params::new(8, 1, 1, None).unwrap();
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password(PASSWORD.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

struct Servers {
    _dir: tempfile::TempDir,
    public: String,
    admin: String,
    clock: Arc<TestClock>,
    state: Arc<AppState>,
    http: reqwest::Client,
}

impl Servers {
    fn set_time(&self, t: u64) {
        self.clock.0.store(t, Ordering::SeqCst);
    }

    fn mac(&self, seed: u8) -> Client {
        let c = self.clock.clone();
        let mut mac = Client::new(
            &self.public,
            &id128(seed),
            &id128(seed + 1),
            derive(&[seed; 32]),
            Arc::new(move || c.now()),
        );
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            "x-mc-client",
            "MetricCupid-Mac/1.32.0 (151)".parse().unwrap(),
        );
        mac.http = reqwest::Client::builder()
            .default_headers(h)
            .build()
            .unwrap();
        mac
    }

    async fn flush(&self) {
        self.state.metrics().flush(&self.state.v2().store).await;
    }

    async fn db<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut rusqlite::Connection) -> R + Send + 'static,
    ) -> R {
        self.state.v2().store.call(move |c| Ok(f(c))).await.unwrap()
    }

    async fn get(
        &self,
        path: &str,
        cookie: Option<&str>,
    ) -> (u16, reqwest::header::HeaderMap, String) {
        let mut r = self.http.get(format!("{}{path}", self.admin));
        if let Some(c) = cookie {
            r = r.header("cookie", format!("mc_admin={c}"));
        }
        let resp = r.send().await.unwrap();
        let (s, h) = (resp.status().as_u16(), resp.headers().clone());
        (s, h, resp.text().await.unwrap())
    }

    async fn post_form(
        &self,
        path: &str,
        cookie: Option<&str>,
        fields: &[(&str, &str)],
    ) -> (u16, reqwest::header::HeaderMap, String) {
        let body: Vec<String> = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", form_enc(v)))
            .collect();
        let mut r = self
            .http
            .post(format!("{}{path}", self.admin))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.join("&"));
        if let Some(c) = cookie {
            r = r.header("cookie", format!("mc_admin={c}"));
        }
        let resp = r.send().await.unwrap();
        let (s, h) = (resp.status().as_u16(), resp.headers().clone());
        (s, h, resp.text().await.unwrap())
    }

    /// GET the login form: (pre-session cookie, csrf).
    async fn login_form(&self) -> (String, String) {
        let (status, h, html) = self.get("/admin/login", None).await;
        assert_eq!(status, 200, "{html}");
        (set_cookie(&h).expect("pre-session cookie"), csrf(&html))
    }

    /// Full login at the current time; returns the session cookie.
    async fn login(&self) -> String {
        let (pre, csrf) = self.login_form().await;
        let code = totp(SECRET, self.clock.now());
        let (status, h, body) = self
            .post_form(
                "/admin/login",
                Some(&pre),
                &[
                    ("csrf", &csrf),
                    ("user", "admin"),
                    ("password", PASSWORD),
                    ("totp", &code),
                ],
            )
            .await;
        assert_eq!(status, 303, "{body}");
        assert_eq!(h["location"], "/admin/");
        let token = set_cookie(&h).unwrap();
        assert_ne!(token, pre, "session id rotated at login");
        token
    }
}

fn form_enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => (b as char).to_string(),
            b' ' => "+".into(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn set_cookie(h: &reqwest::header::HeaderMap) -> Option<String> {
    let v = h.get("set-cookie")?.to_str().ok()?;
    let tok = v.strip_prefix("mc_admin=")?.split(';').next()?;
    (!tok.is_empty()).then(|| tok.to_string())
}

fn csrf(html: &str) -> String {
    let at = html.find(r#"name="csrf" value=""#).expect("csrf field") + 19;
    html[at..].split('"').next().unwrap().to_string()
}

async fn servers(overrides: &[(&str, &str)]) -> Servers {
    let dir = tempfile::tempdir().unwrap();
    let hash = test_hash();
    let mut env: HashMap<String, String> = HashMap::from([
        ("APNS_MODE".into(), "mock".into()),
        ("DATA_DIR".into(), dir.path().display().to_string()),
        ("RATE_IP_PER_SEC".into(), "1000".into()),
        ("RATE_IP_BURST".into(), "10000".into()),
        ("RATE_GLOBAL_PER_SEC".into(), "1000".into()),
        ("RATE_GLOBAL_BURST".into(), "10000".into()),
        ("ADMIN_BIND".into(), "127.0.0.1:0".into()),
        ("ADMIN_USER".into(), "admin".into()),
        ("ADMIN_PASSWORD_HASH".into(), hash),
        ("ADMIN_TOTP_SECRET".into(), SECRET_B32.into()),
        ("ADMIN_ALLOW_IPS".into(), "127.0.0.1/32".into()),
    ]);
    for (k, v) in overrides {
        env.insert(k.to_string(), v.to_string());
    }
    let config = Config::from_lookup(|k| env.get(k).cloned()).expect("valid test config");
    let clock = Arc::new(TestClock(AtomicU64::new(T0)));
    let resolver = ClientIpResolver::from_config(&config.trust_proxy).await;
    let state = Arc::new(AppState::new(&config, resolver, clock.clone()).unwrap());
    let admin_state = Arc::new(AdminState::new(state.clone(), &config).expect("admin on"));

    let pl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let al = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public = format!("http://{}", pl.local_addr().unwrap());
    let admin = format!("http://{}", al.local_addr().unwrap());
    tokio::spawn(serve(pl, state.clone(), std::future::pending()));
    tokio::spawn(admin::serve(al, admin_state, std::future::pending()));
    Servers {
        _dir: dir,
        public,
        admin,
        clock,
        state,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

fn assert_security_headers(h: &reqwest::header::HeaderMap) {
    assert_eq!(h["content-security-policy"], admin::CSP);
    assert!(
        admin::CSP.contains("default-src 'none'") && admin::CSP.contains("frame-ancestors 'none'")
    );
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn outside_allowlist_is_a_plain_404_and_spoofed_cf_header_is_ignored() {
    // Allow 10.0.0.0/8 only; requests come from 127.0.0.1.
    let s = servers(&[
        ("ADMIN_ALLOW_IPS", "10.0.0.0/8"),
        ("TRUST_PROXY", "cloudflare"),
    ])
    .await;
    for path in ["/admin/login", "/admin/", "/admin/style.css", "/nope", "/"] {
        let resp = s
            .http
            .get(format!("{}{path}", s.admin))
            // 127.0.0.1 is not a Cloudflare address: this header is ignored.
            .header("cf-connecting-ip", "10.1.2.3")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "{path}");
        assert_security_headers(resp.headers());
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({ "error": "not_found" }),
            "same body as the public API"
        );
    }
    let r = s.post_form("/admin/login", None, &[("csrf", "x")]).await;
    assert_eq!(r.0, 404);

    // With the cloudflared network trusted, CF-Connecting-IP is the client.
    let t = servers(&[
        ("ADMIN_ALLOW_IPS", "10.0.0.0/8"),
        ("TRUST_PROXY", "cloudflare"),
        ("CF_IPS_EXTRA", "127.0.0.1/32"),
    ])
    .await;
    let ok = t
        .http
        .get(format!("{}/admin/login", t.admin))
        .header("cf-connecting-ip", "10.1.2.3")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_security_headers(ok.headers());
    let no_header = t.get("/admin/login", None).await;
    assert_eq!(no_header.0, 404, "the proxy itself is not allowed");
}

#[tokio::test]
async fn login_flow_totp_csrf_logout() {
    let s = servers(&[]).await;
    let (status, h, _) = s.get("/admin/", None).await;
    assert_eq!(
        (status, h["location"].to_str().unwrap()),
        (303, "/admin/login")
    );
    assert_security_headers(&h);
    assert_eq!(s.get("/admin/api/overview", None).await.0, 401);
    assert_eq!(s.get("/admin/export/daily.csv", None).await.0, 401);

    let (pre, token) = s.login_form().await;
    let (_, h, _) = s.get("/admin/login", Some(&pre)).await;
    assert!(h.get("set-cookie").is_none(), "pre-session reused");
    let good = totp(SECRET, T0);
    let wrong = if good == "000000" { "000001" } else { "000000" };

    // Wrong TOTP: uniform error.
    let (status, _, html) = s
        .post_form(
            "/admin/login",
            Some(&pre),
            &[
                ("csrf", &token),
                ("user", "admin"),
                ("password", PASSWORD),
                ("totp", wrong),
            ],
        )
        .await;
    assert_eq!(status, 401);
    assert!(html.contains("Login failed"));
    // Wrong password, same message.
    let (status, _, html2) = s
        .post_form(
            "/admin/login",
            Some(&pre),
            &[
                ("csrf", &token),
                ("user", "admin"),
                ("password", "nope"),
                ("totp", &good),
            ],
        )
        .await;
    assert_eq!(status, 401);
    assert!(html2.contains("Login failed"));
    // Missing / wrong CSRF or no session: 403, nothing checked.
    for (cookie, c) in [
        (Some(pre.as_str()), ""),
        (Some(pre.as_str()), "deadbeef"),
        (None, token.as_str()),
    ] {
        let r = s
            .post_form(
                "/admin/login",
                cookie,
                &[
                    ("csrf", c),
                    ("user", "admin"),
                    ("password", PASSWORD),
                    ("totp", &good),
                ],
            )
            .await;
        assert_eq!(r.0, 403);
    }

    // Correct: 303, new session cookie with the right attributes.
    let (status, h, _) = s
        .post_form(
            "/admin/login",
            Some(&pre),
            &[
                ("csrf", &token),
                ("user", "admin"),
                ("password", PASSWORD),
                ("totp", &good),
            ],
        )
        .await;
    assert_eq!(status, 303);
    let cookie_line = h["set-cookie"].to_str().unwrap().to_string();
    for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(cookie_line.contains(attr), "{cookie_line}");
    }
    let session = set_cookie(&h).unwrap();
    let (status, _, html) = s.get("/admin/", Some(&session)).await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains("Overview"));
    assert!(!html.contains("<script"), "no JavaScript");
    assert!(!html.contains("style=\""), "no inline styles (CSP)");
    assert_eq!(
        s.get("/admin/", Some(&pre)).await.0,
        303,
        "pre-session is gone"
    );

    // Logout needs the session's CSRF token.
    let csrf_s = csrf(&html);
    assert_eq!(
        s.post_form("/admin/logout", Some(&session), &[]).await.0,
        403
    );
    assert_eq!(
        s.post_form("/admin/logout", Some(&session), &[("csrf", &token)])
            .await
            .0,
        403
    );
    let (status, h, _) = s
        .post_form("/admin/logout", Some(&session), &[("csrf", &csrf_s)])
        .await;
    assert_eq!(status, 303);
    assert!(h["set-cookie"].to_str().unwrap().contains("Max-Age=0"));
    assert_eq!(s.get("/admin/", Some(&session)).await.0, 303, "logged out");

    // The same TOTP code cannot be used twice, even within its window.
    let (pre2, token2) = s.login_form().await;
    let r = s
        .post_form(
            "/admin/login",
            Some(&pre2),
            &[
                ("csrf", &token2),
                ("user", "admin"),
                ("password", PASSWORD),
                ("totp", &good),
            ],
        )
        .await;
    assert_eq!(r.0, 401, "TOTP replay");
    s.set_time(T0 + 30);
    let session2 = s.login().await;

    // Sessions expire (ADMIN_SESSION_HOURS, default 12).
    s.set_time(T0 + 30 + 12 * 3600);
    assert_eq!(s.get("/admin/", Some(&session2)).await.0, 303);
}

#[tokio::test]
async fn login_lockout_after_five_failures() {
    let s = servers(&[]).await;
    let (pre, token) = s.login_form().await;
    for _ in 0..5 {
        let r = s
            .post_form(
                "/admin/login",
                Some(&pre),
                &[
                    ("csrf", &token),
                    ("user", "admin"),
                    ("password", "wrong"),
                    ("totp", "123456"),
                ],
            )
            .await;
        assert_eq!(r.0, 401);
    }
    // Correct credentials are refused while locked, with the same message.
    let good = totp(SECRET, T0);
    let (status, _, html) = s
        .post_form(
            "/admin/login",
            Some(&pre),
            &[
                ("csrf", &token),
                ("user", "admin"),
                ("password", PASSWORD),
                ("totp", &good),
            ],
        )
        .await;
    assert_eq!(status, 401);
    assert!(html.contains("Login failed"));
    s.set_time(T0 + 901);
    s.login().await;

    s.flush().await;
    let outcomes: Vec<String> = s
        .db(|c| {
            let mut st = c
                .prepare("SELECT outcome FROM events WHERE kind = 'admin_login' ORDER BY id")
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        })
        .await;
    assert_eq!(
        outcomes,
        ["fail", "fail", "fail", "fail", "fail", "locked", "ok"]
    );
}

#[tokio::test]
async fn public_and_admin_routers_are_separate() {
    let s = servers(&[]).await;
    for path in [
        "/admin/",
        "/admin/login",
        "/admin/api/overview",
        "/admin/style.css",
        "/admin/export/daily.csv",
    ] {
        let r = reqwest::get(format!("{}{path}", s.public)).await.unwrap();
        assert_eq!(r.status(), 404, "public {path}");
        assert!(r.headers().get("content-security-policy").is_none());
    }
    let r = s
        .http
        .post(format!("{}/admin/login", s.public))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    for path in ["/healthz", "/v2/status", "/v2/debug/pushes", "/v1/notify"] {
        assert_eq!(s.get(path, None).await.0, 404, "admin {path}");
    }
    assert_eq!(
        reqwest::get(format!("{}/healthz", s.public))
            .await
            .unwrap()
            .status(),
        200
    );
}

#[tokio::test]
async fn metrics_recorded_and_pages_render_with_seeded_data() {
    let s = servers(&[]).await;
    let mac = s.mac(10);
    assert_eq!(mac.create_group().await.status, 201);
    assert_eq!(mac.register("mac", "Test MacBook", None).await.status, 201);
    let phone = mac.as_device(&id128(12));
    assert_eq!(
        phone
            .register("ios", "Test iPhone", Some(TOKEN))
            .await
            .status,
        201
    );
    let pt = json!({"v": 1, "type": "alert", "id": "m1", "ts": T0});
    let r = mac
        .post(
            "/v2/messages",
            &json!({
                "id": "m1", "type": "alert", "urgency": "critical",
                "sealed": mac.seal_json("alert", "m1", &pt, [1; 12]),
            }),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json["pushed"], 1);
    // A few polls and an auth failure.
    assert_eq!(phone.get("/v2/messages?since=0").await.status, 200);
    let mut bad = mac.clone();
    bad.keys.auth = [0; 32];
    assert_eq!(bad.get("/v2/status").await.status, 401);
    s.flush().await;

    let gid = mac.group_id.clone();
    let (push, api, poll_raw, agg_polls, version, unauthorized) = s
        .db(move |c| {
            let one = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap() };
            (
                one("SELECT COUNT(*) FROM events WHERE kind = 'push' AND route = 'alert' AND outcome = 'sent'"),
                one("SELECT COUNT(*) FROM events WHERE kind = 'api' AND route = 'messages.post' AND status = 200 AND outcome = 'stored' AND app_version = 'MetricCupid-Mac/1.32.0 (151)'"),
                one("SELECT COUNT(*) FROM events WHERE route = 'messages.get'"),
                one("SELECT SUM(count) FROM daily_agg WHERE route = 'messages.get' AND status = 200"),
                c.query_row(
                    "SELECT app_version FROM client_activity WHERE group_id = ?1 AND device_id = ?2",
                    [&gid, &id128(11)],
                    |r| r.get::<_, String>(0),
                )
                .unwrap(),
                one("SELECT COUNT(*) FROM events WHERE status = 401 AND group_id IS NULL AND ip_prefix = '127.0.0.0/24'"),
            )
        })
        .await;
    assert_eq!(push, 1, "mock APNs push recorded");
    assert_eq!(api, 1, "message post recorded with the client header");
    assert_eq!(poll_raw, 0, "successful polls are not stored raw");
    assert_eq!(agg_polls, 1, "but they are counted");
    assert_eq!(version, "MetricCupid-Mac/1.32.0 (151)");
    assert_eq!(
        unauthorized, 1,
        "401 kept, without group, with a truncated IP"
    );
    let full_ips: i64 = s
        .db(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM events WHERE ip_prefix LIKE '%.1'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await;
    assert_eq!(full_ips, 0, "no full IPs stored");

    let session = s.login().await;
    for (path, needle) in [
        ("/admin/", "Pushes per day"),
        ("/admin/groups", mac.group_id.as_str()),
        (
            "/admin/groups?active=24h&licence=none&sort=requests&order=asc",
            mac.group_id.as_str(),
        ),
        (&format!("/admin/groups/{}", mac.group_id), "Test MacBook"),
        (
            &format!("/admin/groups/{}", mac.group_id),
            "MetricCupid-Mac/1.32.0 (151)",
        ),
        ("/admin/pushes", "alert sent"),
        ("/admin/security", "Admin logins"),
        ("/admin/?refresh=1", "http-equiv=\"refresh\""),
    ] {
        let (status, h, html) = s.get(path, Some(&session)).await;
        assert_eq!(status, 200, "{path}");
        assert_security_headers(&h);
        assert!(html.contains(needle), "{path} should contain {needle}");
    }
    let (status, _, html) = s.get("/admin/groups?active=inactive", Some(&session)).await;
    assert_eq!(status, 200);
    assert!(!html.contains(&mac.group_id), "filter applies");
    assert_eq!(
        s.get("/admin/groups/not-a-group", Some(&session)).await.0,
        404
    );
    assert_eq!(
        s.get(&format!("/admin/groups/{}", id128(99)), Some(&session))
            .await
            .0,
        404
    );

    let (status, _, body) = s.get("/admin/api/overview", Some(&session)).await;
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["overview"]["groups_total"], 1);
    assert_eq!(v["overview"]["active_24h"], 1);
    assert_eq!(v["runtime"]["apns_mode"], "mock");
    let (_, _, body) = s
        .get(
            &format!("/admin/api/groups/{}", mac.group_id),
            Some(&session),
        )
        .await;
    let g: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(g["group"]["devices"].as_array().unwrap().len(), 2);
    for p in [
        "/admin/api/groups",
        "/admin/api/pushes",
        "/admin/api/security",
    ] {
        assert_eq!(s.get(p, Some(&session)).await.0, 200, "{p}");
    }
    let (status, h, csv) = s.get("/admin/export/daily.csv", Some(&session)).await;
    assert_eq!(status, 200);
    assert!(h["content-type"].to_str().unwrap().starts_with("text/csv"));
    assert!(csv.starts_with("day,kind,route,status,outcome,group_id,country,count"));
    assert!(csv.contains(",push,alert,0,sent,"));
}

#[tokio::test]
async fn retention_cleanup_with_fake_clock() {
    let s = servers(&[("ADMIN_EVENTS_RETENTION_DAYS", "30")]).await;
    let mac = s.mac(20);
    assert_eq!(mac.create_group().await.status, 201);
    s.flush().await;
    let count =
        |sql: &'static str| s.db(move |c| c.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap());
    assert!(count("SELECT COUNT(*) FROM events").await > 0);

    let m = s.state.metrics().clone();
    let store = s.state.v2().store.clone();
    s.set_time(T0 + 29 * 86_400);
    assert_eq!(m.cleanup(&store).await.unwrap(), 0, "inside retention");
    s.set_time(T0 + 31 * 86_400);
    assert!(m.cleanup(&store).await.unwrap() > 0);
    assert_eq!(
        count("SELECT COUNT(*) FROM events").await,
        0,
        "raw events gone"
    );
    assert!(
        count("SELECT COUNT(*) FROM daily_agg").await > 0,
        "aggregates kept"
    );
    s.set_time(T0 + 402 * 86_400);
    m.cleanup(&store).await.unwrap();
    assert_eq!(
        count("SELECT COUNT(*) FROM daily_agg").await,
        0,
        "aggregates gone after 400 days"
    );
}

#[tokio::test]
async fn no_metrics_without_admin_panel() {
    let dir = tempfile::tempdir().unwrap();
    let env: HashMap<&str, String> = HashMap::from([
        ("APNS_MODE", "mock".to_string()),
        ("DATA_DIR", dir.path().display().to_string()),
    ]);
    let config = Config::from_lookup(|k| env.get(k).cloned()).unwrap();
    let clock = Arc::new(TestClock(AtomicU64::new(T0)));
    let state = Arc::new(AppState::new(&config, ClientIpResolver::Peer, clock.clone()).unwrap());
    assert!(!state.metrics().enabled());
    assert!(AdminState::new(state.clone(), &config).is_err());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(serve(l, state.clone(), std::future::pending()));
    let c = clock.clone();
    let mac = Client::new(
        &base,
        &id128(30),
        &id128(31),
        derive(&[30; 32]),
        Arc::new(move || c.now()),
    );
    assert_eq!(mac.create_group().await.status, 201);
    state.metrics().flush(&state.v2().store).await;
    let n: i64 = state
        .v2()
        .store
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn snapshot_posts_counted_with_the_client_header() {
    let s = servers(&[]).await;
    let mut mac = s.mac(40);
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        "x-mc-client",
        "MetricCupid-Mac/1.33.0 (153)".parse().unwrap(),
    );
    mac.http = reqwest::Client::builder()
        .default_headers(h)
        .build()
        .unwrap();
    assert_eq!(mac.create_group().await.status, 201);
    assert_eq!(mac.register("mac", "Test MacBook", None).await.status, 201);
    let pt =
        json!({"v": 1, "type": "snapshot", "id": "s1", "ts": T0, "compressed": true, "items": ""});
    let sealed = mac.seal_json("snapshot", "s1", &pt, [1; 12]);
    let len = sealed.len() as i64;
    let r = mac
        .post("/v2/snapshot", &json!({"id": "s1", "sealed": sealed}))
        .await;
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(mac.get("/v2/snapshot").await.status, 200);
    s.flush().await;
    let gid = mac.group_id.clone();
    let (posts, bytes, version, gets_raw) = s
        .db(move |c| {
            let one = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap() };
            (
                one("SELECT SUM(count) FROM daily_agg WHERE kind = 'snapshot' AND outcome = 'stored'"),
                one("SELECT SUM(bytes_sum) FROM daily_agg WHERE kind = 'snapshot'"),
                c.query_row(
                    "SELECT app_version FROM client_activity WHERE group_id = ?1 AND device_id = ?2",
                    [&gid, &id128(41)],
                    |r| r.get::<_, String>(0),
                )
                .unwrap(),
                one("SELECT COUNT(*) FROM events WHERE route = 'snapshot.get'"),
            )
        })
        .await;
    assert_eq!(posts, 1);
    assert_eq!(bytes, len);
    assert_eq!(version, "MetricCupid-Mac/1.33.0 (153)");
    assert_eq!(gets_raw, 0, "successful snapshot reads are only counted");
    let session = s.login().await;
    let (_, _, body) = s.get("/admin/api/overview", Some(&session)).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["overview"]["snapshots_30d"], 1);
    let (_, _, html) = s.get("/admin/", Some(&session)).await;
    assert!(html.contains("Snapshots (30 d)"));
}

#[tokio::test]
async fn licence_refusal_reasons_are_visible_on_the_security_page() {
    let s = servers(&[("MODE", "hosted"), ("LICENCE_MODE", "app_transaction")]).await;
    let mac = s.mac(30);
    let r = mac
        .create_group_with(json!({"licence": {"kind": "app_transaction", "jws": "a.b.c"}}))
        .await;
    assert_eq!(
        (r.status, r.json["reason"].as_str()),
        (403, Some("malformed"))
    );
    s.flush().await;

    let session = s.login().await;
    let (status, _, html) = s.get("/admin/security", Some(&session)).await;
    assert_eq!(status, 200);
    assert!(html.contains("Licence results by reason"), "reason table");
    assert!(html.contains("groups invalid malformed"), "reason counted");
    assert!(
        html.contains("Recent licence verifications"),
        "recent table"
    );
    let (_, _, body) = s.get("/admin/api/security", Some(&session)).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["security"]["licence_reasons"][0]["count"], 1, "{v}");
    assert!(body.contains("groups invalid malformed"));
}
