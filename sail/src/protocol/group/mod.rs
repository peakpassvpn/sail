//! Outbounds that are built out of other outbounds.

#[cfg(any(feature = "inbound-chain", feature = "outbound-chain"))]
pub mod chain;
#[cfg(feature = "outbound-fallback")]
pub mod fallback;
#[cfg(any(
    feature = "outbound-urltest",
    feature = "outbound-load-balance",
    feature = "outbound-fallback"
))]
mod health;
#[cfg(feature = "outbound-select")]
mod interrupt;
#[cfg(feature = "outbound-load-balance")]
pub mod load_balance;
#[cfg(feature = "outbound-select")]
pub mod selector;
#[cfg(feature = "outbound-tryall")]
pub mod tryall;
#[cfg(feature = "outbound-urltest")]
pub mod urltest;
