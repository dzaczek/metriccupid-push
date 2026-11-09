//! MetricCupid Push: a signed HTTP relay from the MetricCupid macOS app to the
//! Pushover API (v1) and an end-to-end encrypted mailbox + APNs sender for
//! two-way Mac <-> iPhone communication (v2, see PROTOCOL.md).
#![forbid(unsafe_code)]

pub mod api;
pub mod auth;
pub mod client_ip;
pub mod config;
pub mod limits;
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

/// Serve the API on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}
