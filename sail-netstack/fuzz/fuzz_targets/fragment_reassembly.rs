#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use sail_netstack::{
    emit_udp_packet, fragment_outbound_ip_packet, parse_ip_packet, parse_udp_datagram,
    BudgetProfile, FragmentReassembler, ResourceKind, ResourceLedger,
};
use libfuzzer_sys::fuzz_target;

const MAX_PAYLOAD_LEN: usize = 2_048;
const MIN_PAYLOAD_LEN: usize = 96;

fn checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks_exact(2) {
        sum = sum.saturating_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

fn mutate_fragment_offset(fragment: &mut [u8], selector: u16) {
    match fragment.first().map(|version| version >> 4) {
        Some(4) if fragment.len() >= 20 => {
            let header_len = usize::from(fragment[0] & 0x0f) * 4;
            if header_len > fragment.len() {
                return;
            }
            let offset_and_more = selector & 0x3fff;
            fragment[6..8].copy_from_slice(&offset_and_more.to_be_bytes());
            fragment[10..12].fill(0);
            let checksum = checksum(&fragment[..header_len]);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        Some(6) if fragment.len() >= 48 && fragment[6] == 44 => {
            let offset_and_more = selector & 0xfff9;
            fragment[42..44].copy_from_slice(&offset_and_more.to_be_bytes());
        }
        _ => {}
    }
}

fn exercise_fragments(packet: &[u8], mtu: usize, identification: u32, selectors: &[u8]) {
    let Ok(mut fragments) = fragment_outbound_ip_packet(packet, mtu, identification) else {
        return;
    };
    if fragments.len() < 2 {
        return;
    }
    let control = selectors.first().copied().unwrap_or_default();
    if control & 1 != 0 {
        fragments.reverse();
    }
    if control & 2 != 0 {
        let duplicate = usize::from(control) % fragments.len();
        fragments.insert(duplicate, fragments[duplicate].clone());
    }
    if control & 4 != 0 && fragments.len() > 1 {
        let dropped = usize::from(control.rotate_right(3)) % fragments.len();
        fragments.remove(dropped);
    }
    if control & 8 != 0 && !fragments.is_empty() {
        let mutated = usize::from(control.rotate_left(2)) % fragments.len();
        let selector = u16::from_be_bytes([
            selectors.get(1).copied().unwrap_or_default(),
            selectors.get(2).copied().unwrap_or_default(),
        ]);
        mutate_fragment_offset(&mut fragments[mutated], selector);
    }
    if control & 16 != 0 && fragments.len() > 1 {
        let amount = usize::from(control.rotate_left(4)) % fragments.len();
        fragments.rotate_left(amount);
    }

    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).expect("valid fuzz budget");
    let mut reassembler = FragmentReassembler::new(Arc::clone(&ledger), 1_000);
    for (now_ms, fragment) in fragments.iter().enumerate() {
        let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);
        if let Ok(Some(reassembled)) = reassembler.ingest(fragment, now_ms) {
            if let Ok(ip) = parse_ip_packet(&reassembled, true) {
                let _ = parse_udp_datagram(ip, true);
            }
        }
    }
    reassembler.clear();
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.used(ResourceKind::Fragments), 0);
    assert_eq!(snapshot.used(ResourceKind::FragmentBytes), 0);
    assert_eq!(snapshot.used(ResourceKind::MetadataBytes), 0);
}

fuzz_target!(|data: &[u8]| {
    let payload_len = data.len().clamp(MIN_PAYLOAD_LEN, MAX_PAYLOAD_LEN);
    let mut payload = vec![0_u8; payload_len];
    let copied = data.len().min(payload.len());
    payload[..copied].copy_from_slice(&data[..copied]);
    let selector = data.first().copied().unwrap_or_default();
    let identification = u32::from_be_bytes([
        selector,
        data.get(1).copied().unwrap_or_default(),
        data.get(2).copied().unwrap_or_default(),
        data.get(3).copied().unwrap_or_default(),
    ]);

    let ipv4 = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 40_000)),
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 53)),
        &payload,
        64,
        u16::from_be_bytes(
            identification.to_be_bytes()[2..]
                .try_into()
                .expect("two bytes"),
        ),
    )
    .expect("bounded IPv4 UDP packet");
    exercise_fragments(&ipv4, 68, identification, data);

    let ipv6 = emit_udp_packet(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 53)),
        &payload,
        64,
        0,
    )
    .expect("bounded IPv6 UDP packet");
    exercise_fragments(&ipv6, 80, identification, data);
});
