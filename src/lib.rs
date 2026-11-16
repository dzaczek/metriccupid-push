//! MetricCupid Push: a signed HTTP relay from the MetricCupid macOS app to the
//! Pushover API (v1) and an end-to-end encrypted mailbox + APNs sender for
//! two-way Mac <-> iPhone communication (v2, see PROTOCOL.md).
#![forbid(unsafe_code)]

pub mod admin;
pub mod api;
pub mod auth;
pub mod client_ip;
pub mod config;
pub mod controls;
pub mod limits;
pub mod metrics;
pub mod pushover;
pub mod v2;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

pub use api::{router, AppState};

/// How often bounded maps are swept for expired entries.
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// Spawn the periodic cleanup task.
pub fn spawn_cleanup(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CLEANUP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            state.cleanup();
            state.cleanup_storage().await;
        }
    })
}

/// How often pending Mac-offline notices are checked.
pub const PRESENCE_INTERVAL: Duration = Duration::from_secs(5);

/// Spawn the task that sends Mac-offline notices after their grace period.
pub fn spawn_presence(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PRESENCE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            v2::presence_tick(&state).await;
        }
    })
}

/// How often coalesced Live Activity states are flushed.
pub const ACTIVITY_INTERVAL: Duration = Duration::from_secs(1);

/// Spawn the task that sends coalesced Live Activity updates.
pub fn spawn_activities(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(ACTIVITY_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            v2::activity_tick(&state).await;
        }
    })
}

/// Spawn the metrics tasks (admin panel enabled only): flush the buffers
/// every few seconds, apply retention hourly.
pub fn spawn_metrics(state: Arc<AppState>) -> Option<tokio::task::JoinHandle<()>> {
    if !state.metrics().enabled() {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut flush = tokio::time::interval(metrics::FLUSH_INTERVAL);
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut cleanup = tokio::time::interval(metrics::CLEANUP_INTERVAL);
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = flush.tick() => state.metrics().flush(&state.v2().store).await,
                _ = cleanup.tick() => match state.metrics().cleanup(&state.v2().store).await {
                    Ok(n) if n > 0 => tracing::debug!(events = n, "metrics retention cleanup"),
                    Ok(_) => {}
                    Err(e) => tracing::error!(error = %e, "metrics retention cleanup failed"),
                },
            }
        }
    }))
}

/// TCP keepalive on accepted connections: idle time before the first probe,
/// and the interval between probes (half-open peers are dropped instead of
/// holding a connection slot forever).
pub const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
pub const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Connections per TCP peer (rate-limit key, IPv6 /64), shared with the
/// [`LimitedIo`]s that release them.
type PeerCounts = Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>;

/// A listener that holds one of `MAX_CONNECTIONS` permits per open
/// connection (WebSocket streams included). At the cap it stops accepting,
/// so new clients wait in the kernel backlog instead of exhausting file
/// descriptors and memory. A TCP peer (IPv6 per /64) may hold at most
/// `MAX_CONNECTIONS_PER_IP`; further connections from it are closed at
/// once. Trusted proxies are exempt: behind cloudflared or a reverse proxy
/// every connection comes from the proxy's address, and the per-client
/// limits then apply to the forwarded client IP instead.
pub struct LimitedListener {
    inner: TcpListener,
    permits: Arc<tokio::sync::Semaphore>,
    per_peer: PeerCounts,
    max_per_peer: usize,
    exempt: Box<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>,
}

impl LimitedListener {
    pub fn new(
        inner: TcpListener,
        max_connections: usize,
        max_per_peer: usize,
        exempt: impl Fn(std::net::IpAddr) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner,
            permits: Arc::new(tokio::sync::Semaphore::new(max_connections.max(1))),
            per_peer: Default::default(),
            max_per_peer: max_per_peer.max(1),
            exempt: Box::new(exempt),
        }
    }

    /// Connection slots currently free.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }

    /// Accept the next connection that fits both caps.
    pub async fn accept(&mut self) -> (LimitedIo, SocketAddr) {
        loop {
            let permit = self
                .permits
                .clone()
                .acquire_owned()
                .await
                .expect("the connection semaphore is never closed");
            let (io, addr) = match self.inner.accept().await {
                Ok(c) => c,
                // Back off on errors such as EMFILE instead of spinning.
                Err(e) => {
                    tracing::error!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let peer = addr.ip().to_canonical();
            let slot = if (self.exempt)(peer) {
                None
            } else {
                let key = limits::ip_key(peer);
                let mut map = self.per_peer.lock().unwrap_or_else(|e| e.into_inner());
                let n = map.entry(key).or_default();
                if *n >= self.max_per_peer {
                    drop(map);
                    tracing::debug!(peer = %peer, "connection refused: MAX_CONNECTIONS_PER_IP");
                    continue; // drops `io`: the connection is closed
                }
                *n += 1;
                Some((self.per_peer.clone(), key))
            };
            set_keepalive(&io);
            return (
                LimitedIo {
                    io,
                    _permit: permit,
                    slot,
                },
                addr,
            );
        }
    }
}

/// An accepted connection and its permit and per-peer slot (released when
/// it closes).
pub struct LimitedIo {
    io: tokio::net::TcpStream,
    _permit: tokio::sync::OwnedSemaphorePermit,
    slot: Option<(PeerCounts, std::net::IpAddr)>,
}

impl Drop for LimitedIo {
    fn drop(&mut self) {
        if let Some((map, key)) = &self.slot {
            let mut map = map.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = map.get_mut(key) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(key);
                }
            }
        }
    }
}

impl tokio::io::AsyncRead for LimitedIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for LimitedIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

fn set_keepalive(io: &tokio::net::TcpStream) {
    let ka = socket2::TcpKeepalive::new().with_time(TCP_KEEPALIVE_IDLE);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let ka = ka.with_interval(TCP_KEEPALIVE_INTERVAL);
    if let Err(e) = socket2::SockRef::from(io).set_tcp_keepalive(&ka) {
        tracing::debug!(error = %e, "cannot set TCP keepalive");
    }
}

/// Serve the API on `listener` until `shutdown` resolves: HTTP/1.1 with
/// WebSocket upgrades, at most `MAX_CONNECTIONS` open connections
/// (`MAX_CONNECTIONS_PER_IP` per untrusted peer), and complete request
/// headers within `HEADER_READ_TIMEOUT_SECS` (slowloris). On shutdown, open
/// connections finish their current request; upgraded streams end with the
/// process.
pub async fn serve(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tower::ServiceExt;

    let exempt_state = state.clone();
    let mut listener = LimitedListener::new(
        listener,
        state.max_connections(),
        state.max_connections_per_ip(),
        move |ip| exempt_state.is_trusted_proxy(ip),
    );
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(state.header_read_timeout());
    let app = router(state);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (io, addr) = tokio::select! {
            c = listener.accept() => c,
            _ = &mut shutdown => break,
        };
        // `ConnectInfo<SocketAddr>` for the extractors, like
        // `into_make_service_with_connect_info`.
        let svc =
            app.clone()
                .map_request(move |req: axum::http::Request<hyper::body::Incoming>| {
                    let mut req = req.map(axum::body::Body::new);
                    req.extensions_mut()
                        .insert(axum::extract::ConnectInfo(addr));
                    req
                });
        let svc = hyper_util::service::TowerToHyperService::new(svc);
        let conn = http.serve_connection(TokioIo::new(io), svc).with_upgrades();
        let mut stop = stop_rx.clone();
        tokio::spawn(async move {
            let mut conn = std::pin::pin!(conn);
            tokio::select! {
                r = conn.as_mut() => {
                    if let Err(e) = r {
                        tracing::trace!(error = %e, "connection ended");
                    }
                    return;
                }
                _ = stop.wait_for(|v| *v) => conn.as_mut().graceful_shutdown(),
            }
            let _ = conn.await;
        });
    }
    let _ = stop_tx.send(true);
    // Give in-flight requests a moment, like axum's graceful shutdown.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while stop_tx.receiver_count() > 1 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}
