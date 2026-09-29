//! Outbounds that are built out of other outbounds.

#[cfg(any(feature = "inbound-chain", feature = "outbound-chain"))]
pub mod chain;
#[cfg(any(feature = "outbound-load-balance", feature = "outbound-smart"))]
mod domain;
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
#[cfg(any(
    feature = "outbound-select",
    feature = "outbound-urltest",
    feature = "outbound-fallback",
    feature = "outbound-load-balance",
    feature = "outbound-smart",
    feature = "outbound-provider"
))]
pub mod members;
#[cfg(any(
    feature = "outbound-select",
    feature = "outbound-urltest",
    feature = "outbound-fallback",
    feature = "outbound-load-balance",
    feature = "outbound-smart",
    feature = "outbound-provider"
))]
pub mod merge;
#[cfg(feature = "outbound-select")]
pub mod selector;
#[cfg(feature = "outbound-smart")]
pub mod smart;
#[cfg(feature = "outbound-tryall")]
pub mod tryall;
#[cfg(feature = "outbound-urltest")]
pub mod urltest;
