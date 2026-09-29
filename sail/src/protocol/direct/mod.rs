//! `direct`: the outbound connects to the destination itself; the inbound
//! takes connections and datagrams sent to its listener, and routes them
//! to the listener's address, or to the one it overrides that with.

#[cfg(feature = "inbound-direct")]
pub mod inbound;
#[cfg(feature = "outbound-direct")]
pub mod outbound;
