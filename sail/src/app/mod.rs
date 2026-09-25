use std::sync::Arc;

use tokio::sync::RwLock;

pub mod dispatcher;
pub mod dns;
pub mod healthcheck;
pub mod inbound;
pub mod instance;
pub mod logger;
pub mod nat_manager;
pub mod outbound;
pub mod router;
pub mod stat_manager;

#[cfg(feature = "api")]
pub mod api;

pub mod fake_dns;

pub mod dns_client {
    pub use super::dns::*;
}

/// The DNS client of an instance. A reload replaces it whole; readers take
/// the current one without locking.
pub type SyncDnsClient = Arc<arc_swap::ArcSwap<dns::DnsClient>>;

/// The routing of an instance, replaced whole on reload.
pub type SyncRouter = Arc<arc_swap::ArcSwap<router::Router>>;

/// The outbounds of an instance, replaced whole on reload.
pub type SyncOutboundManager = Arc<arc_swap::ArcSwap<outbound::manager::OutboundManager>>;

pub type SyncStatManager = Arc<RwLock<stat_manager::StatManager>>;
