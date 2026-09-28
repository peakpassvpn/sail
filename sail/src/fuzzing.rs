//! Pure, bounded-by-the-caller parser entry points for cargo-fuzz.
//!
//! This module exists only with the `fuzzing` feature and deliberately does
//! not perform file, network, or runtime I/O.

use crate::config::rule_set::{ClashBehavior, RuleSetFormat};
use crate::sniff::{DatagramSniff, Protocols};

/// Parse a source-format sing-box rule-set.
pub fn rule_set_source(data: &[u8]) {
    let _ = std::hint::black_box(crate::app::router::rule_set::RuleSet::read(
        data,
        RuleSetFormat::Source,
        None,
    ));
}

/// Parse a binary sing-box rule-set (`.srs`).
pub fn rule_set_binary(data: &[u8]) {
    let _ = std::hint::black_box(crate::app::router::rule_set::RuleSet::read(
        data,
        RuleSetFormat::Binary,
        None,
    ));
}

/// Parse Mihomo's binary rule-set (`.mrs`), of domains and of IP ranges.
pub fn rule_set_mrs(data: &[u8]) {
    for behavior in [ClashBehavior::Domain, ClashBehavior::Ipcidr] {
        let _ = std::hint::black_box(crate::app::router::rule_set::RuleSet::read(
            data,
            RuleSetFormat::Mrs,
            Some(behavior),
        ));
    }
}

/// Exercise both DNS-over-datagram and DNS-over-stream framing parsers.
pub fn dns_message(data: &[u8]) {
    let _ = std::hint::black_box(crate::sniff::dns::query(data));
    let _ = std::hint::black_box(crate::sniff::dns::stream_query(data));
}

/// Exercise all stream and datagram traffic sniffers.
pub fn sniff(data: &[u8]) {
    let _ = std::hint::black_box(crate::sniff::sniff_stream(Protocols::ALL, data));
    let mut datagram = DatagramSniff::new(Protocols::ALL);
    let _ = std::hint::black_box(datagram.feed(data));
    let _ = std::hint::black_box(datagram.settle());
}

/// Exercise synchronous TUIC and XUDP inbound wire decoders.
pub fn inbound_protocol(data: &[u8]) {
    crate::protocol::tuic::fuzz_decode(data);
    let _ = std::hint::black_box(crate::protocol::vmess::xudp::parse_addr_port(data));
}
