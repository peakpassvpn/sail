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

/// Fuzzing (sail::fuzzing): the wire a TUIC peer sends, and its packets'
/// fragments through a reassembler, which holds a bounded number.
#[cfg(all(
    feature = "fuzzing",
    any(feature = "inbound-tuic", feature = "outbound-tuic")
))]
pub(crate) fn fuzz(data: &[u8]) {
    use crate::transport::quic::{FragmentBudget, MAX_FRAGMENT_BYTES};
    let mut reassembler = frag::Reassembler::new(
        4,
        std::time::Duration::from_secs(1),
        FragmentBudget::new(MAX_FRAGMENT_BYTES),
    );
    let now = std::time::Instant::now();
    for (header, payload) in proto::fuzz(data) {
        let _ = reassembler.feed(header, payload, now);
    }
}

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
