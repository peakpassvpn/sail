//! QUIC: the glue everything on quinn shares, and the quic transport.

mod common;
mod detour;

pub use common::*;
pub use detour::DetourSocket;

#[cfg(feature = "inbound-quic")]
pub mod inbound;
#[cfg(feature = "outbound-quic")]
pub mod outbound;
