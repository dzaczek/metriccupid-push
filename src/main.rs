#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use metriccupid_push::admin::{self, AdminState};
use metriccupid_push::client_ip::ClientIpResolver;
use metriccupid_push::config::{
    AdminSetting, ApnsMode, Config, LicenceMode, LogFormat, Mode, TrustProxy,
};
use metriccupid_push::limits::SystemClock;
use metriccupid_push::{
    serve, spawn_activities, spawn_cleanup, spawn_metrics, spawn_presence, AppState,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => run(),
        Some("--healthcheck") => healthcheck(),
        Some("admin-setup") => admin_setup(&args[1..]),
        Some("--version" | "-V") => {
            println!("metriccupid-push {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(_) => {
            eprintln!("usage: metriccupid-push [--healthcheck | --version | admin-setup [--user NAME]]\nconfiguration is read from the environment, see README.md");
            ExitCode::from(2)
        }
    }
}

/// GET /healthz on the local listener; exit 0 on HTTP 200. Used by the
/// container healthcheck (distroless has no shell or curl).
fn healthcheck() -> ExitCode {
    let bind: SocketAddr = std::env::var("BIND")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8080)));
    let ip = match bind.ip() {
        IpAddr::V4(v) if v.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v) if v.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    let addr = SocketAddr::new(ip, bind.port());
    let timeout = Duration::from_secs(3);
    let check = || -> std::io::Result<bool> {
        let mut s = TcpStream::connect_timeout(&addr, timeout)?;
        s.set_read_timeout(Some(timeout))?;
        s.set_write_timeout(Some(timeout))?;
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf)?;
        Ok(buf[..n].starts_with(b"HTTP/1.1 200"))
    };
    match check() {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

fn run() -> ExitCode {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::from(2);
        }
    };
    init_tracing(&config);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(async_main(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn async_main(config: Config) -> Result<(), String> {
    let resolver = ClientIpResolver::from_config(&config.trust_proxy).await;
    let state = Arc::new(AppState::new(&config, resolver, Arc::new(SystemClock))?);
    spawn_cleanup(state.clone());
    spawn_presence(state.clone());
    spawn_activities(state.clone());
    spawn_metrics(state.clone());

    // One shutdown signal for both listeners.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop_tx.send(true);
    });
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|v| *v).await;
    };

    let admin_task = match &config.admin {
        AdminSetting::Off => None,
        AdminSetting::Refused(e) => {
            tracing::error!("admin panel NOT started: {e}");
            None
        }
        AdminSetting::On(a) => match start_admin(&state, &config, a.bind).await {
            Err(e) => {
                tracing::error!("admin panel NOT started: {e}");
                None
            }
            Ok((admin_state, listener)) => {
                tracing::info!(
                    bind = %a.bind,
                    allow_ips = a.allow_ips.len(),
                    allow_any = a.allow_any,
                    cf_access = a.cf_access.is_some(),
                    "admin panel listening"
                );
                match (&a.cf_access, a.allow_any, a.allow_any_without_access) {
                    (Some(c), _, _) => {
                        tracing::info!(team = %c.team_domain, auds = c.auds.len(), "admin: Cloudflare Access JWT required");
                        if admin_state.refresh_access_keys().await != Some(true) {
                            tracing::error!("admin: no Cloudflare Access keys; every admin request gets 404 until they can be fetched (retried every minute)");
                        }
                    }
                    (None, true, Some(true)) => tracing::warn!(
                        "SECURITY: ADMIN_ALLOW_ANY=true and ADMIN_ALLOW_ANY_WITHOUT_ACCESS=true: the admin login is reachable from any IP WITHOUT Cloudflare Access verification"
                    ),
                    (None, true, _) => tracing::warn!(
                        "SECURITY: ADMIN_ALLOW_ANY=true without Cloudflare Access verification: the admin login is reachable from any IP. Set ADMIN_CF_ACCESS_TEAM and ADMIN_CF_ACCESS_AUD, or ADMIN_ALLOW_ANY_WITHOUT_ACCESS=true to accept this explicitly (=false refuses to start the panel)"
                    ),
                    (None, false, _) => {}
                }
                admin::spawn_cleanup(admin_state.clone());
                Some(tokio::spawn(admin::serve(
                    listener,
                    admin_state,
                    stopped(stop_rx.clone()),
                )))
            }
        },
    };

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|e| format!("cannot bind {}: {e}", config.bind))?;
    let trust_proxy = match &config.trust_proxy {
        TrustProxy::None => "none",
        TrustProxy::Cloudflare { .. } => "cloudflare",
        TrustProxy::Xff(_) => "xff",
    };
    let apns_mode = match config.v2.apns_mode {
        ApnsMode::Direct => "direct",
        ApnsMode::Mock => "mock",
        ApnsMode::Gateway => "gateway",
    };
    if config.v2.apns_mode == ApnsMode::Mock {
        tracing::warn!(
            "APNS_MODE=mock: no real pushes, GET /v2/debug/pushes is open. Development only."
        );
    }
    tracing::info!(
        bind = %config.bind,
        mode = if config.mode == Mode::Hosted { "hosted" } else { "selfhosted" },
        trust_proxy,
        v1 = config.v1_enabled,
        secrets = config.secrets.len(),
        allow_emergency = config.allow_emergency,
        apns_mode,
        licence = match config.v2.licence_mode {
            LicenceMode::Open => "open",
            LicenceMode::AppTransaction => "app_transaction",
        },
        licence_grace_until = config.v2.licence_grace_until,
        data_dir = %config.v2.data_dir.display(),
        version = env!("CARGO_PKG_VERSION"),
        "metriccupid-push listening"
    );
    serve(listener, state.clone(), stopped(stop_rx))
        .await
        .map_err(|e| format!("server error: {e}"))?;
    if let Some(t) = admin_task {
        let _ = t.await;
    }
    // Keep the last few seconds of metrics.
    state.metrics().flush(&state.v2().store).await;
    tracing::info!("shut down");
    Ok(())
}

async fn start_admin(
    state: &Arc<AppState>,
    config: &Config,
    bind: SocketAddr,
) -> Result<(Arc<AdminState>, tokio::net::TcpListener), String> {
    let admin_state = Arc::new(AdminState::new(state.clone(), config)?);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("cannot bind ADMIN_BIND {bind}: {e}"))?;
    Ok((admin_state, listener))
}

/// `admin-setup [--user NAME]`: read a password (prompt without echo on a
/// terminal, else the first line of stdin) and print the admin variables.
fn admin_setup(args: &[String]) -> ExitCode {
    use std::io::{BufRead, IsTerminal};

    use argon2::password_hash::{PasswordHasher, SaltString};
    use ring::rand::{SecureRandom, SystemRandom};

    let user = match args {
        [] => "admin".to_string(),
        [flag, name] if flag == "--user" && !name.trim().is_empty() => name.trim().to_string(),
        _ => {
            eprintln!("usage: metriccupid-push admin-setup [--user NAME]");
            return ExitCode::from(2);
        }
    };
    let read_line = || -> Option<String> {
        let mut s = String::new();
        std::io::stdin().lock().read_line(&mut s).ok()?;
        Some(s.trim_end_matches(['\r', '\n']).to_string())
    };
    let tty = std::io::stdin().is_terminal();
    let prompt = |label: &str| -> Option<String> {
        eprint!("{label}");
        let _ = std::io::stderr().flush();
        // No dependency for hidden input: let stty switch echo off.
        let echo = |on: bool| {
            let _ = std::process::Command::new("stty")
                .arg(if on { "echo" } else { "-echo" })
                .stdin(std::process::Stdio::inherit())
                .status();
        };
        echo(false);
        let line = read_line();
        echo(true);
        eprintln!();
        line
    };
    let password = if tty {
        let (Some(a), Some(b)) = (prompt("Admin password: "), prompt("Repeat: ")) else {
            return ExitCode::FAILURE;
        };
        if a != b {
            eprintln!("passwords do not match");
            return ExitCode::FAILURE;
        }
        a
    } else {
        match read_line() {
            Some(p) => p,
            None => return ExitCode::FAILURE,
        }
    };
    if password.chars().count() < 12 {
        eprintln!("use at least 12 characters");
        return ExitCode::FAILURE;
    }
    let rng = SystemRandom::new();
    let (mut salt, mut secret) = ([0u8; 16], [0u8; 20]);
    if rng.fill(&mut salt).is_err() || rng.fill(&mut secret).is_err() {
        eprintln!("system RNG unavailable");
        return ExitCode::FAILURE;
    }
    let hash = SaltString::encode_b64(&salt)
        .map_err(|e| e.to_string())
        .and_then(|salt| {
            // argon2id v19, m=19 MiB, t=2, p=1 (OWASP recommendation).
            argon2::Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|e| e.to_string())
        });
    let hash = match hash {
        Ok(h) => h,
        Err(e) => {
            eprintln!("cannot hash password: {e}");
            return ExitCode::FAILURE;
        }
    };
    let b32 = admin::auth::base32_encode(&secret);
    let uri = admin::auth::otpauth_uri("MetricCupid Push", &user, &b32);
    println!("# Admin panel credentials (README, \"Admin panel\"). Single quotes keep the");
    println!("# `$` literal in Docker Compose env files; drop them for `docker run --env-file`.");
    println!("ADMIN_USER={user}");
    println!("ADMIN_PASSWORD_HASH='{hash}'");
    println!("ADMIN_TOTP_SECRET={b32}");
    println!();
    println!("# Add this to your authenticator app (as a QR code: qrencode -t ansiutf8 '<uri>'):");
    println!("{uri}");
    ExitCode::SUCCESS
}

fn init_tracing(config: &Config) {
    let builder = tracing_subscriber::fmt().with_max_level(config.log_level);
    match config.log_format {
        LogFormat::Json => builder.json().init(),
        LogFormat::Text => builder.init(),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
