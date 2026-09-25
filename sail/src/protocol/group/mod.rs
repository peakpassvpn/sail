//! Outbounds that are built out of other outbounds.

#[cfg(any(feature = "inbound-chain", feature = "outbound-chain"))]
pub mod chain;
#[cfg(feature = "outbound-failover")]
pub mod failover;
#[cfg(feature = "outbound-select")]
mod interrupt;
#[cfg(feature = "outbound-select")]
pub mod selector;
#[cfg(feature = "outbound-static")]
pub mod r#static;
#[cfg(feature = "outbound-tryall")]
pub mod tryall;
