use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use sail_netstack::{
    emit_udp_packet, parse_ip_packet, parse_udp_datagram, BudgetProfile, FragmentError,
    FragmentReassembler, ResourceKind, ResourceLedger,
};

fn checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap()
}

fn ipv4_fragment(packet: &[u8], offset: usize, length: usize, more: bool) -> Vec<u8> {
    let mut fragment = packet[..20].to_vec();
    fragment.extend_from_slice(&packet[20 + offset..20 + offset + length]);
    let total_len = u16::try_from(fragment.len()).unwrap();
    fragment[2..4].copy_from_slice(&total_len.to_be_bytes());
    let mut bits = u16::try_from(offset / 8).unwrap();
    if more {
        bits |= 0x2000;
    }
    fragment[6..8].copy_from_slice(&bits.to_be_bytes());
    fragment[10..12].copy_from_slice(&0_u16.to_be_bytes());
    let checksum = checksum(&fragment[..20]);
    fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
    fragment
}

fn ipv6_fragment(packet: &[u8], offset: usize, length: usize, more: bool) -> Vec<u8> {
    let mut fragment = packet[..40].to_vec();
    fragment[6] = 44;
    fragment.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 7]);
    let bits = (u16::try_from(offset / 8).unwrap() << 3) | u16::from(more);
    fragment[42..44].copy_from_slice(&bits.to_be_bytes());
    fragment.extend_from_slice(&packet[40 + offset..40 + offset + length]);
    let payload_len = u16::try_from(fragment.len() - 40).unwrap();
    fragment[4..6].copy_from_slice(&payload_len.to_be_bytes());
    fragment
}

fn ipv4_fragment_with_header_len(
    header_len: usize,
    offset: usize,
    payload_len: usize,
    more: bool,
    identification: u16,
) -> Vec<u8> {
    let mut fragment = vec![0_u8; header_len + payload_len];
    fragment[0] = 0x40 | u8::try_from(header_len / 4).unwrap();
    let total_len = u16::try_from(fragment.len()).unwrap();
    fragment[2..4].copy_from_slice(&total_len.to_be_bytes());
    fragment[4..6].copy_from_slice(&identification.to_be_bytes());
    let mut bits = u16::try_from(offset / 8).unwrap();
    if more {
        bits |= 0x2000;
    }
    fragment[6..8].copy_from_slice(&bits.to_be_bytes());
    fragment[8] = 64;
    fragment[9] = 17;
    fragment[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    fragment[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
    let header_checksum = checksum(&fragment[..header_len]);
    fragment[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    fragment
}

fn oversized_ipv6_tail_fragment() -> Vec<u8> {
    let mut fragment = vec![0_u8; 64];
    fragment[0] = 0x60;
    fragment[4..6].copy_from_slice(&24_u16.to_be_bytes());
    fragment[6] = 60;
    fragment[7] = 64;
    fragment[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    fragment[24..40].copy_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
    fragment[40] = 44;
    fragment[41] = 0;
    fragment[48] = 17;
    let offset_bits = u16::try_from(65_520_usize).unwrap();
    fragment[50..52].copy_from_slice(&offset_bits.to_be_bytes());
    fragment[52..56].copy_from_slice(&7_u32.to_be_bytes());
    fragment
}

fn assert_releases_fragment_budget(ledger: &ResourceLedger) {
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.used[ResourceKind::FragmentBytes as usize], 0);
    assert_eq!(snapshot.used[ResourceKind::Fragments as usize], 0);
}

#[test]
fn ipv4_fragments_reassemble_out_of_order_before_udp_delivery() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 1_000);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40_000)),
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        b"abcdefghijklmnopqrstuvwx",
        64,
        9,
    )
    .unwrap();
    let payload_len = packet.len() - 20;
    let first = ipv4_fragment(&packet, 0, 16, true);
    let second = ipv4_fragment(&packet, 16, payload_len - 16, false);
    assert!(table.ingest(&second, 1).unwrap().is_none());
    let rebuilt = table.ingest(&first, 2).unwrap().unwrap();
    let datagram = parse_udp_datagram(parse_ip_packet(&rebuilt, true).unwrap(), true).unwrap();
    assert_eq!(datagram.payload, b"abcdefghijklmnopqrstuvwx");
    assert_eq!(table.stats().completed_datagrams, 1);
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn ipv6_fragments_reassemble_and_remove_the_fragment_header() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 1_000);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 53)),
        b"abcdefghijklmnopqrstuvwx",
        64,
        0,
    )
    .unwrap();
    let payload_len = packet.len() - 40;
    let mut first = ipv6_fragment(&packet, 0, 16, true);
    let mut second = ipv6_fragment(&packet, 16, payload_len - 16, false);
    first[41] = 0xff;
    first[43] |= 0x06;
    second[41] = 0xff;
    second[43] |= 0x06;
    assert!(table.ingest(&first, 1).unwrap().is_none());
    let rebuilt = table.ingest(&second, 2).unwrap().unwrap();
    assert_eq!(rebuilt[6], 17);
    let datagram = parse_udp_datagram(parse_ip_packet(&rebuilt, true).unwrap(), true).unwrap();
    assert_eq!(datagram.payload, b"abcdefghijklmnopqrstuvwx");
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn ipv6_atomic_fragment_is_treated_as_an_unfragmented_datagram() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 1_000);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 53)),
        b"atomic",
        64,
        0,
    )
    .unwrap();
    let atomic = ipv6_fragment(&packet, 0, packet.len() - 40, false);
    let passed = table.ingest(&atomic, 1).unwrap().unwrap();
    let datagram = parse_udp_datagram(parse_ip_packet(&passed, true).unwrap(), true).unwrap();
    assert_eq!(datagram.payload, b"atomic");
    assert_eq!(table.stats().active_datagrams, 0);
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn fragments_that_cannot_fit_the_ip_length_field_are_rejected_before_budgeting() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 1_000);

    let ipv4 = ipv4_fragment_with_header_len(20, 65_512, 8, false, 31);
    assert!(matches!(
        table.ingest(&ipv4, 1),
        Err(FragmentError::Malformed(
            "reassembled IP datagram is too large"
        ))
    ));
    let ipv6 = oversized_ipv6_tail_fragment();
    assert!(matches!(
        table.ingest(&ipv6, 2),
        Err(FragmentError::Malformed(
            "reassembled IP datagram is too large"
        ))
    ));
    assert_eq!(table.stats().active_datagrams, 0);
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn late_ipv4_first_fragment_revalidates_the_known_final_length() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 1_000);
    let tail = ipv4_fragment_with_header_len(20, 65_496, 16, false, 32);
    assert!(table.ingest(&tail, 1).unwrap().is_none());

    let first_with_options = ipv4_fragment_with_header_len(24, 0, 8, true, 32);
    assert!(matches!(
        table.ingest(&first_with_options, 2),
        Err(FragmentError::Malformed(
            "fragment conflicts with established datagram bounds"
        ))
    ));
    assert_eq!(table.stats().active_datagrams, 0);
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn overlap_discards_the_entire_datagram_and_releases_credit() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 1_000);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        SocketAddr::from((Ipv4Addr::BROADCAST, 2)),
        b"abcdefghijklmnopqrstuvwx",
        64,
        11,
    )
    .unwrap();
    let first = ipv4_fragment(&packet, 0, 16, true);
    let overlap = ipv4_fragment(&packet, 8, 16, false);
    assert!(table.ingest(&first, 1).unwrap().is_none());
    assert!(matches!(
        table.ingest(&overlap, 2),
        Err(FragmentError::Overlap)
    ));
    assert_eq!(table.stats().active_datagrams, 0);
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn timeout_and_clear_release_every_fragment_lease() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 100);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        SocketAddr::from((Ipv4Addr::BROADCAST, 2)),
        b"abcdefghijklmnopqrstuvwx",
        64,
        12,
    )
    .unwrap();
    let first = ipv4_fragment(&packet, 0, 16, true);
    table.ingest(&first, 1).unwrap();
    assert_eq!(table.advance_time(101).unwrap(), 0);
    assert_eq!(table.advance_time(110).unwrap(), 1);
    assert_releases_fragment_budget(&ledger);
    assert_eq!(table.stats().expired_datagrams, 1);
}

#[test]
fn timeout_quotes_only_initial_ipv4_and_ipv6_fragments() {
    let cases = [
        {
            let packet = emit_udp_packet(
                SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40_000)),
                SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
                b"abcdefghijklmnopqrstuvwx",
                64,
                21,
            )
            .unwrap();
            ipv4_fragment(&packet, 0, 16, true)
        },
        {
            let packet = emit_udp_packet(
                SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 53)),
                b"abcdefghijklmnopqrstuvwx",
                64,
                0,
            )
            .unwrap();
            ipv6_fragment(&packet, 0, 16, true)
        },
    ];
    for first in cases {
        let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
        let mut table = FragmentReassembler::new(Arc::clone(&ledger), 100);
        assert!(table.ingest(&first, 0).unwrap().is_none());
        let expired = table
            .advance_time_under_pressure_with_quotes(100, 1, 1)
            .unwrap();
        assert_eq!(expired.expired_datagrams, 1);
        assert_eq!(expired.invoking_packets, vec![first]);
        assert_releases_fragment_budget(&ledger);
    }

    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40_000)),
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        b"abcdefghijklmnopqrstuvwx",
        64,
        22,
    )
    .unwrap();
    let non_initial = ipv4_fragment(&packet, 8, 16, true);
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 100);
    assert!(table.ingest(&non_initial, 0).unwrap().is_none());
    let expired = table
        .advance_time_under_pressure_with_quotes(100, 1, 1)
        .unwrap();
    assert_eq!(expired.expired_datagrams, 1);
    assert!(expired.invoking_packets.is_empty());
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn pressure_divisor_shortens_fragment_retention() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 100);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        SocketAddr::from((Ipv4Addr::BROADCAST, 2)),
        b"abcdefghijklmnopqrstuvwx",
        64,
        13,
    )
    .unwrap();
    let first = ipv4_fragment(&packet, 0, 16, true);
    table.ingest(&first, 0).unwrap();
    assert_eq!(table.advance_time_under_pressure(24, 4).unwrap(), 0);
    assert_eq!(table.advance_time_under_pressure(25, 4).unwrap(), 0);
    assert_eq!(table.advance_time_under_pressure(30, 4).unwrap(), 1);
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn pressure_recovery_extends_incomplete_fragment_deadlines_again() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 100);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        SocketAddr::from((Ipv4Addr::BROADCAST, 2)),
        b"abcdefghijklmnopqrstuvwx",
        64,
        14,
    )
    .unwrap();
    let first = ipv4_fragment(&packet, 0, 16, true);

    table.ingest(&first, 0).unwrap();
    assert_eq!(table.advance_time_under_pressure(10, 4).unwrap(), 0);
    assert_eq!(table.advance_time_under_pressure(20, 1).unwrap(), 0);
    assert_eq!(table.advance_time(30).unwrap(), 0);
    assert_eq!(table.advance_time(100).unwrap(), 1);
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn completed_datagram_cancels_its_old_expiry_before_key_reuse() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 100);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        SocketAddr::from((Ipv4Addr::BROADCAST, 2)),
        b"abcdefghijklmnopqrstuvwx",
        64,
        15,
    )
    .unwrap();
    let first = ipv4_fragment(&packet, 0, 16, true);
    let second = ipv4_fragment(&packet, 16, packet.len() - 20 - 16, false);

    assert!(table.ingest(&first, 0).unwrap().is_none());
    let rebuilt = table.ingest(&second, 1).unwrap().unwrap();
    let datagram = parse_udp_datagram(parse_ip_packet(&rebuilt, true).unwrap(), true).unwrap();
    assert_eq!(datagram.payload, b"abcdefghijklmnopqrstuvwx");
    assert!(table.ingest(&first, 2).unwrap().is_none());
    assert_eq!(table.advance_time(100).unwrap(), 0);
    assert_eq!(table.stats().active_datagrams, 1);
    assert_eq!(table.advance_time(110).unwrap(), 1);
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn budget_pressure_evicts_the_oldest_datagram_and_completes_the_newer_one() {
    let mut budget = BudgetProfile::Router.budget();
    budget.max_fragments = 2;
    budget.fragment_bytes = 32;
    let ledger = ResourceLedger::new(budget).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 1_000);
    let first_packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        SocketAddr::from((Ipv4Addr::BROADCAST, 2)),
        b"abcdefghijklmnopqrstuvwx",
        64,
        21,
    )
    .unwrap();
    let second_packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 3)),
        SocketAddr::from((Ipv4Addr::BROADCAST, 4)),
        b"zyxwvutsrqponmlkjihgfedc",
        64,
        22,
    )
    .unwrap();
    let first_head = ipv4_fragment(&first_packet, 0, 16, true);
    let second_head = ipv4_fragment(&second_packet, 0, 16, true);
    let second_tail = ipv4_fragment(&second_packet, 16, second_packet.len() - 20 - 16, false);

    assert!(table.ingest(&first_head, 1).unwrap().is_none());
    assert!(table.ingest(&second_head, 1).unwrap().is_none());
    let rebuilt = table.ingest(&second_tail, 2).unwrap().unwrap();
    let datagram = parse_udp_datagram(parse_ip_packet(&rebuilt, true).unwrap(), true).unwrap();
    assert_eq!(datagram.payload, b"zyxwvutsrqponmlkjihgfedc");
    assert_eq!(table.stats().evicted_datagrams, 1);
    assert_eq!(table.stats().completed_datagrams, 1);
    assert_eq!(table.stats().active_datagrams, 0);
    assert_eq!(table.advance_time(1_100).unwrap(), 0);
    assert_releases_fragment_budget(&ledger);
}

#[test]
fn randomized_fragment_inputs_never_leak_after_clear() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = FragmentReassembler::new(Arc::clone(&ledger), 1_000);
    let mut random = 0xbb67_ae85_84ca_a73b_u64;

    for case in 0..4_096_u64 {
        random = xorshift64(random);
        let length = usize::try_from(random % 1_537).unwrap();
        let mut packet = vec![0_u8; length];
        for byte in &mut packet {
            random = xorshift64(random);
            *byte = random.to_le_bytes()[3];
        }
        let _ = table.ingest(&packet, case);

        if case % 64 == 63 {
            table.clear();
            assert_eq!(table.stats().active_datagrams, 0);
            assert_eq!(table.stats().buffered_fragments, 0);
            assert_releases_fragment_budget(&ledger);
        }
    }

    table.clear();
    assert_releases_fragment_budget(&ledger);
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value << 13;
    value ^= value >> 7;
    value ^ (value << 17)
}
