//! QUIC: the glue everything on quinn shares, and the quic transport.

mod common;

pub use common::*;

#[cfg(feature = "inbound-quic")]
pub mod inbound;
#[cfg(feature = "outbound-quic")]
pub mod outbound;
