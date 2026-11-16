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

/// A listener that holds one of `MAX_CONNECTIONS` permits per open
/// connection (WebSocket streams included). At the cap it stops accepting,
/// so new clients wait in the kernel backlog instead of exhausting file
/// descriptors and memory.
pub struct LimitedListener {
    inner: TcpListener,
    permits: Arc<tokio::sync::Semaphore>,
}

impl LimitedListener {
    pub fn new(inner: TcpListener, max_connections: usize) -> Self {
        Self {
            inner,
            permits: Arc::new(tokio::sync::Semaphore::new(max_connections.max(1))),
        }
    }

    /// Connection slots currently free.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// An accepted connection and its permit (released when it closes).
pub struct LimitedIo {
    io: tokio::net::TcpStream,
    _permit: tokio::sync::OwnedSemaphorePermit,
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

impl axum::serve::Listener for LimitedListener {
    type Io = LimitedIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("the connection semaphore is never closed");
        loop {
            match self.inner.accept().await {
                Ok((io, addr)) => {
                    set_keepalive(&io);
                    return (
                        LimitedIo {
                            io,
                            _permit: permit,
                        },
                        addr,
                    );
                }
                // Like axum's own listener: back off on errors such as
                // EMFILE instead of spinning.
                Err(e) => {
                    tracing::error!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Serve the API on `listener` until `shutdown` resolves, with at most
/// `MAX_CONNECTIONS` open connections.
pub async fn serve(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    use axum::serve::ListenerExt;
    let listener = LimitedListener::new(listener, state.max_connections());
    axum::serve(
        // `tap_io` gives the wrapped listener axum's `ConnectInfo<SocketAddr>`.
        listener.tap_io(|_| {}),
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}
