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

/// A Linux TUN's virtio-net header of one packet, written with offload.
#[cfg(all(target_os = "linux", feature = "inbound-tun"))]
pub fn tun_vnet_header(data: &[u8]) {
    crate::protocol::tun::fuzz_vnet_header(data);
}

/// A Linux TUN's batch of TCP segments, coalesced flow by flow.
#[cfg(all(target_os = "linux", feature = "inbound-tun"))]
pub fn tun_coalesce(data: &[u8]) {
    crate::protocol::tun::fuzz_coalesce(data);
}

/// AnyTLS: a pushed padding scheme, and a session's frames at each end.
#[cfg(any(feature = "inbound-anytls", feature = "outbound-anytls"))]
pub fn anytls(data: &[u8]) {
    crate::protocol::anytls::fuzz(data);
}

/// Hysteria2: the authentication's HTTP/3, TCP requests and responses, UDP
/// messages and their fragments, and salamander.
#[cfg(any(feature = "inbound-hysteria2", feature = "outbound-hysteria2"))]
pub fn hysteria2(data: &[u8]) {
    crate::protocol::hysteria2::fuzz(data);
}

/// TUIC: addresses, commands, packets and their fragments.
#[cfg(any(feature = "inbound-tuic", feature = "outbound-tuic"))]
pub fn tuic(data: &[u8]) {
    crate::protocol::tuic::fuzz(data);
}

/// ShadowTLS v3: the handshake's records and the HMAC-framed data.
#[cfg(any(feature = "inbound-shadowtls", feature = "outbound-shadowtls"))]
pub fn shadowtls(data: &[u8]) {
    crate::protocol::shadowtls::fuzz(data);
}

/// VLESS: the request, the response header, UDP packets, and vision.
#[cfg(any(feature = "inbound-vless", feature = "outbound-vless"))]
pub fn vless(data: &[u8]) {
    crate::protocol::vless::fuzz(data);
}

/// What a host pushes and answers through the C ABI, read without an
/// instance: the network it is on (`sail_set_network_state`), and who
/// opened a connection (the platform's `find_connection_owner`).
pub fn host_json(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = std::hint::black_box(crate::net::network::NetworkState::from_json(text));
    }
    let _ = std::hint::black_box(serde_json::from_slice::<
        crate::runtime::platform::ConnectionOwner,
    >(data));
}
