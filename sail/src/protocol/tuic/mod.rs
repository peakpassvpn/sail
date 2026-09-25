//! TUIC v5: TCP and UDP relayed over one QUIC connection.
//!
//! See <https://github.com/tuic-protocol/tuic/blob/dev/SPEC.md>. The
//! options follow sing-box's `tuic` inbound and outbound.

mod common;
mod frag;
mod proto;

#[cfg(feature = "inbound-tuic")]
pub mod inbound;
#[cfg(feature = "outbound-tuic")]
pub mod outbound;
