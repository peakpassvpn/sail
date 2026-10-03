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
        &Default::default(),
    ));
}

/// Parse a binary sing-box rule-set (`.srs`).
pub fn rule_set_binary(data: &[u8]) {
    let _ = std::hint::black_box(crate::app::router::rule_set::RuleSet::read(
        data,
        RuleSetFormat::Binary,
        None,
        &Default::default(),
    ));
}

/// Parse Mihomo's binary rule-set (`.mrs`), of domains and of IP ranges.
pub fn rule_set_mrs(data: &[u8]) {
    for behavior in [ClashBehavior::Domain, ClashBehavior::Ipcidr] {
        let _ = std::hint::black_box(crate::app::router::rule_set::RuleSet::read(
            data,
            RuleSetFormat::Mrs,
            Some(behavior),
            &Default::default(),
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

/// Read DHCP lease files, which the neighbor table takes from other
/// programs: the content as each format the file's name can select, then
/// a lookup by a host name read from it.
pub fn dhcp_leases(data: &[u8]) {
    use crate::net::neighbor::lease;
    for name in [
        "/var/db/dhcpd_leases",
        "/var/lib/kea/kea-leases4.csv",
        "/var/lib/kea/kea-leases6.csv",
        "/var/lib/dhcp/dhcpd.leases",
        "/tmp/dhcp.leases",
    ] {
        let mut leases = lease::Leases::default();
        // At time 0 no lease has expired, so every line is read through.
        lease::parse_lease_file(name, data, 0, &mut leases);
        if let Some(hostname) = leases.ip_to_hostname.values().next() {
            let _ = std::hint::black_box(lease::addresses_by_hostname(
                hostname,
                &leases.ip_to_hostname,
                &leases.mac_to_hostname,
                &leases.ip_to_mac,
                &leases.ip_to_mac,
            ));
        }
    }
}

/// Exercise synchronous TUIC and XUDP inbound wire decoders.
pub fn inbound_protocol(data: &[u8]) {
    crate::protocol::tuic::fuzz_decode(data);
    let _ = std::hint::black_box(crate::protocol::vmess::xudp::parse_addr_port(data));
}
