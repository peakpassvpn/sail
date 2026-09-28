//! TUIC v5: TCP and UDP relayed over one QUIC connection.
//!
//! See <https://github.com/tuic-protocol/tuic/blob/dev/SPEC.md>. The
//! options follow sing-box's `tuic` inbound and outbound.

#[cfg(any(feature = "inbound-tuic", feature = "outbound-tuic"))]
mod common;
#[cfg(any(feature = "inbound-tuic", feature = "outbound-tuic"))]
mod frag;
#[cfg_attr(feature = "fuzzing", allow(dead_code))]
mod proto;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_decode(data: &[u8]) {
    let _ = std::hint::black_box(proto::decode_address(data));
    let _ = std::hint::black_box(proto::decode_datagram(bytes::Bytes::copy_from_slice(data)));
}

#[cfg(feature = "inbound-tuic")]
pub mod inbound;
#[cfg(feature = "outbound-tuic")]
pub mod outbound;

#[cfg(all(test, feature = "inbound-tuic", feature = "outbound-tuic"))]
mod tests;
