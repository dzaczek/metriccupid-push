#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use metriccupid_push::client_ip::ClientIpResolver;
use metriccupid_push::config::{Config, LogFormat, Mode, TrustProxy};
use metriccupid_push::limits::SystemClock;
use metriccupid_push::{serve, spawn_cleanup, AppState};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => run(),
        Some("--healthcheck") => healthcheck(),
        Some("--version" | "-V") => {
            println!("metriccupid-push {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(_) => {
            eprintln!("usage: metriccupid-push [--healthcheck | --version]\nconfiguration is read from the environment, see README.md");
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

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|e| format!("cannot bind {}: {e}", config.bind))?;
    let trust_proxy = match &config.trust_proxy {
        TrustProxy::None => "none",
        TrustProxy::Cloudflare { .. } => "cloudflare",
        TrustProxy::Xff(_) => "xff",
    };
    tracing::info!(
        bind = %config.bind,
        mode = if config.mode == Mode::Hosted { "hosted" } else { "selfhosted" },
        trust_proxy,
        secrets = config.secrets.len(),
        allow_emergency = config.allow_emergency,
        version = env!("CARGO_PKG_VERSION"),
        "metriccupid-push listening"
    );
    serve(listener, state, shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))?;
    tracing::info!("shut down");
    Ok(())
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
