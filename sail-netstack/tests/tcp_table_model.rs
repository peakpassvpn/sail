use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use sail_netstack::{
    emit_tcp_segment, emit_tcp_segment_with_options, parse_ip_packet, parse_tcp_segment,
    AcceptOverflowPolicy, BudgetProfile, NetworkGeneration, ResourceKind, ResourceLedger,
    SendControl, SeqNumber, TcpEvent, TcpFlags, TcpTable, TcpTableConfig, TcpTableError,
    TimerEvent,
};

fn endpoints(offset: u8) -> (SocketAddr, SocketAddr) {
    (
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, offset), 40_000 + u16::from(offset))),
        SocketAddr::from((Ipv4Addr::new(10, 0, 1, 1), 443)),
    )
}

fn ipv6_endpoints(offset: u16) -> (SocketAddr, SocketAddr) {
    (
        SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, offset), 40_000)),
        SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1), 443)),
    )
}

fn packet(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    payload: &[u8],
) -> Vec<u8> {
    emit_tcp_segment(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(acknowledgment),
            flags,
            window: 32_000,
        },
        payload,
        64,
        1,
    )
    .unwrap()
}

fn packet_with_window(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    emit_tcp_segment(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(acknowledgment),
            flags,
            window,
        },
        payload,
        64,
        1,
    )
    .unwrap()
}

fn packet_with_options(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    options: &[u8],
) -> Vec<u8> {
    packet_with_options_and_payload(
        source,
        destination,
        sequence,
        acknowledgment,
        flags,
        options,
        &[],
    )
}

fn packet_with_options_and_payload(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    emit_tcp_segment_with_options(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(acknowledgment),
            flags,
            window: 32_000,
        },
        options,
        payload,
        64,
        1,
    )
    .unwrap()
}

fn rewrite_ipv4_tcp_checksum(packet: &mut [u8]) {
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let (ip_header, tcp) = packet.split_at_mut(header_len);
    tcp[16..18].fill(0);
    let mut sum = u32::from(6_u16) + u32::try_from(tcp.len()).unwrap();
    for bytes in ip_header[12..20].as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*bytes));
    }
    let (chunks, remainder) = tcp.as_chunks::<2>();
    for bytes in chunks {
        sum += u32::from(u16::from_be_bytes(*bytes));
    }
    if let Some(&byte) = remainder.first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    tcp[16..18].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
}

fn assert_silent_tcp_drop(
    table: &mut TcpTable,
    source: SocketAddr,
    destination: SocketAddr,
    flags: TcpFlags,
) {
    let ingress = table
        .ingest(&packet(source, destination, 100, 200, flags, &[]))
        .unwrap();
    assert_eq!(ingress, sail_netstack::TcpIngress::default());
}

#[test]
fn invalid_tcp_endpoints_are_silently_dropped_before_flow_admission() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let valid_source = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40_000));
    let valid_destination = SocketAddr::from((Ipv4Addr::new(10, 0, 1, 1), 443));
    let invalid_pairs = [
        (
            SocketAddr::from((Ipv4Addr::new(0, 1, 2, 3), 40_000)),
            valid_destination,
        ),
        (
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000)),
            valid_destination,
        ),
        (
            SocketAddr::from((Ipv4Addr::new(224, 0, 0, 1), 40_000)),
            valid_destination,
        ),
        (
            SocketAddr::from((Ipv4Addr::new(240, 0, 0, 1), 40_000)),
            valid_destination,
        ),
        (valid_source, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443))),
        (
            valid_source,
            SocketAddr::from((Ipv4Addr::new(224, 0, 0, 1), 443)),
        ),
        (valid_source, SocketAddr::from((Ipv4Addr::BROADCAST, 443))),
        (
            valid_source,
            SocketAddr::from((Ipv4Addr::new(240, 0, 0, 1), 443)),
        ),
    ];
    for (source, destination) in invalid_pairs {
        assert_silent_tcp_drop(&mut table, source, destination, TcpFlags::SYN);
    }

    let ipv6_unicast = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
    let ipv6_multicast = "ff02::1".parse::<Ipv6Addr>().unwrap();
    for (source, destination) in [
        (
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 40_000)),
            SocketAddr::from((ipv6_unicast, 443)),
        ),
        (
            SocketAddr::from((ipv6_multicast, 40_000)),
            SocketAddr::from((ipv6_unicast, 443)),
        ),
        (
            SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 443)),
        ),
        (
            SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
            SocketAddr::from((ipv6_multicast, 443)),
        ),
    ] {
        assert_silent_tcp_drop(&mut table, source, destination, TcpFlags::SYN);
    }
    assert_silent_tcp_drop(
        &mut table,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000)),
        valid_destination,
        TcpFlags::ACK,
    );
    assert_eq!(table.stats().invalid_address_drops, 13);
    assert_eq!(table.stats().stateless_resets_sent, 0);
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(table.stats().created_flows, 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::TcpFlows), 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::SynReceived), 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::TcpPayloadBytes), 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::MetadataBytes), 0);

    let ipv6_loopback = packet(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 40_000)),
        SocketAddr::from((ipv6_unicast, 443)),
        100,
        0,
        TcpFlags::SYN,
        &[],
    );
    assert_eq!(table.ingest(&ipv6_loopback).unwrap().outgoing.len(), 1);
    assert_eq!(table.stats().created_flows, 1);
}

#[test]
fn reserved_bits_do_not_block_a_checksum_valid_handshake() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(39);
    let mut syn = packet(source, destination, 100, 0, TcpFlags::SYN, &[]);
    syn[32] |= 0x0f;
    rewrite_ipv4_tcp_checksum(&mut syn);

    let ingress = table.ingest(&syn).unwrap();

    assert_eq!(ingress.outgoing.len(), 1);
    assert_eq!(table.stats().created_flows, 1);
    assert_eq!(table.stats().malformed_packets, 0);
    assert_eq!(ingress.outgoing[0][32] & 0x0f, 0);
}

#[test]
fn pure_ack_timestamp_does_not_advance_paws_recent_value() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(38);

    let mut syn_options = vec![8, 10];
    syn_options.extend_from_slice(&100_u32.to_be_bytes());
    syn_options.extend_from_slice(&0_u32.to_be_bytes());
    syn_options.extend_from_slice(&[1, 1]);
    let syn = packet_with_options(source, destination, 100, 0, TcpFlags::SYN, &syn_options);
    let syn_ack = table.ingest_with_policy_at(&syn, true, 1_000).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let mut handshake_ack_options = vec![8, 10];
    handshake_ack_options.extend_from_slice(&101_u32.to_be_bytes());
    handshake_ack_options.extend_from_slice(&1_000_u32.to_be_bytes());
    handshake_ack_options.extend_from_slice(&[1, 1]);
    let handshake_ack = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &handshake_ack_options,
    );
    let accepted = table
        .ingest_with_policy_at(&handshake_ack, true, 1_100)
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();

    let mut pure_ack_options = vec![8, 10];
    pure_ack_options.extend_from_slice(&300_u32.to_be_bytes());
    pure_ack_options.extend_from_slice(&1_000_u32.to_be_bytes());
    pure_ack_options.extend_from_slice(&[1, 1]);
    let pure_ack = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &pure_ack_options,
    );
    table.ingest_with_policy_at(&pure_ack, true, 1_200).unwrap();

    let mut data_options = vec![8, 10];
    data_options.extend_from_slice(&200_u32.to_be_bytes());
    data_options.extend_from_slice(&1_000_u32.to_be_bytes());
    data_options.extend_from_slice(&[1, 1]);
    let data = packet_with_options_and_payload(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &data_options,
        b"x",
    );
    let ingress = table.ingest_with_policy_at(&data, true, 1_300).unwrap();
    assert_eq!(ingress.events, vec![TcpEvent::Readable { token, bytes: 1 }]);
}

#[test]
fn plain_tcp_samples_rtt_and_karn_ignores_retransmitted_data() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(47);
    let syn = packet(source, destination, 100, 0, TcpFlags::SYN, &[]);
    let syn_ack = table.ingest_with_policy_at(&syn, true, 1_000).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let accepted = table
        .ingest_with_policy_at(
            &packet(source, destination, 101, server_next, TcpFlags::ACK, &[]),
            true,
            3_000,
        )
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected handshake events: {events:?}"),
    };
    table.accept(token).unwrap();

    let sent = table.write(token, b"first").unwrap();
    assert_eq!(sent.timers[0].after_ms, 6_000);
    let timeout = table
        .on_timer_at(token, TimerEvent::Retransmission, 9_000)
        .unwrap();
    assert_eq!(timeout.timers[0].after_ms, 12_000);
    assert_eq!(
        parse_tcp_segment(parse_ip_packet(&timeout.outgoing[0], true).unwrap(), true)
            .unwrap()
            .payload,
        b"first"
    );

    let mut unnegotiated_timestamp = vec![8, 10];
    unnegotiated_timestamp.extend_from_slice(&1_u32.to_be_bytes());
    unnegotiated_timestamp.extend_from_slice(&11_999_u32.to_be_bytes());
    unnegotiated_timestamp.extend_from_slice(&[1, 1]);
    table
        .ingest_with_policy_at(
            &packet_with_options(
                source,
                destination,
                101,
                server_next.wrapping_add(5),
                TcpFlags::ACK,
                &unnegotiated_timestamp,
            ),
            true,
            12_000,
        )
        .unwrap();
    let next = table.write(token, b"next").unwrap();
    assert_eq!(next.timers[0].after_ms, 12_000);
    table
        .ingest_with_policy_at(
            &packet(
                source,
                destination,
                101,
                server_next.wrapping_add(9),
                TcpFlags::ACK,
                &[],
            ),
            true,
            14_000,
        )
        .unwrap();
    let fresh = table.write(token, b"fresh").unwrap();
    assert_eq!(fresh.timers[0].after_ms, 5_000);
}

#[test]
fn paws_recent_value_expires_after_long_idle_period() {
    const PAWS_IDLE_INVALIDATION_MS: u64 = 24 * 24 * 60 * 60 * 1_000;

    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(39);

    let mut syn_options = vec![8, 10];
    syn_options.extend_from_slice(&100_u32.to_be_bytes());
    syn_options.extend_from_slice(&0_u32.to_be_bytes());
    syn_options.extend_from_slice(&[1, 1]);
    let syn = packet_with_options(source, destination, 100, 0, TcpFlags::SYN, &syn_options);
    let syn_ack = table.ingest_with_policy_at(&syn, true, 1_000).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let mut handshake_ack_options = vec![8, 10];
    handshake_ack_options.extend_from_slice(&101_u32.to_be_bytes());
    handshake_ack_options.extend_from_slice(&1_000_u32.to_be_bytes());
    handshake_ack_options.extend_from_slice(&[1, 1]);
    let handshake_ack = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &handshake_ack_options,
    );
    let accepted = table
        .ingest_with_policy_at(&handshake_ack, true, 1_100)
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();

    let mut old_data_options = vec![8, 10];
    old_data_options.extend_from_slice(&99_u32.to_be_bytes());
    old_data_options.extend_from_slice(&1_000_u32.to_be_bytes());
    old_data_options.extend_from_slice(&[1, 1]);
    let old_data = packet_with_options_and_payload(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &old_data_options,
        b"x",
    );
    let rejected = table.ingest_with_policy_at(&old_data, true, 1_200).unwrap();
    assert_eq!(rejected.outgoing.len(), 1);
    assert!(rejected.events.is_empty());

    let after_idle = 1_000 + PAWS_IDLE_INVALIDATION_MS + 1;
    let ingress = table
        .ingest_with_policy_at(&old_data, true, after_idle)
        .unwrap();
    assert_eq!(ingress.events, vec![TcpEvent::Readable { token, bytes: 1 }]);
}

fn handshake(
    table: &mut TcpTable,
    source: SocketAddr,
    destination: SocketAddr,
) -> (sail_netstack::TcpFlowToken, u32) {
    let syn = packet(source, destination, 100, 0, TcpFlags::SYN, &[]);
    let syn_result = table.ingest(&syn).unwrap();
    assert_eq!(syn_result.outgoing.len(), 1);
    assert_eq!(syn_result.timers.len(), 1);
    let syn_ack = parse_tcp_segment(
        parse_ip_packet(&syn_result.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let ack = packet(source, destination, 101, server_next, TcpFlags::ACK, &[]);
    let result = table.ingest(&ack).unwrap();
    let token = match result.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected handshake events: {events:?}"),
    };
    (token, server_next)
}

fn zero_window_handshake(
    table: &mut TcpTable,
    source: SocketAddr,
    destination: SocketAddr,
) -> (sail_netstack::TcpFlowToken, u32) {
    let syn = packet(source, destination, 100, 0, TcpFlags::SYN, &[]);
    let syn_result = table.ingest(&syn).unwrap();
    let syn_ack = parse_tcp_segment(
        parse_ip_packet(&syn_result.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let ack = packet_with_window(source, destination, 101, server_next, TcpFlags::ACK, 0, &[]);
    let accepted = table.ingest(&ack).unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected handshake events: {events:?}"),
    };
    table.accept(token).unwrap();
    (token, server_next)
}

fn sack_handshake(
    table: &mut TcpTable,
    source: SocketAddr,
    destination: SocketAddr,
) -> (sail_netstack::TcpFlowToken, u32) {
    let syn = packet_with_options(source, destination, 100, 0, TcpFlags::SYN, &[4, 2, 1, 1]);
    let syn_ack = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let accepted = table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();
    (token, server_next)
}

#[test]
fn zero_window_send_is_budgeted_probed_and_flushed_after_window_update() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig {
            persist_initial_ms: 10,
            persist_max_ms: 40,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(20);
    let (token, server_next) = zero_window_handshake(&mut table, source, destination);

    let buffered = table.write(token, b"hello").unwrap();
    assert!(buffered.outgoing.is_empty());
    assert_eq!(buffered.timers.len(), 1);
    assert_eq!(buffered.timers[0].event, TimerEvent::Persist);
    assert_eq!(buffered.timers[0].after_ms, 10);
    assert_eq!(table.stats().send_buffered_bytes, 5);
    assert_eq!(table.stats().zero_window_writes, 1);
    assert!(matches!(
        table.write(token, b"blocked"),
        Err(TcpTableError::State(
            sail_netstack::TcpError::SendWindowExceeded
        ))
    ));

    let first_probe = table.on_timer(token, TimerEvent::Persist).unwrap();
    let probe = parse_tcp_segment(
        parse_ip_packet(&first_probe.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(probe.meta.sequence, SeqNumber::new(server_next));
    assert_eq!(probe.payload, b"h");
    assert_eq!(first_probe.timers[0].after_ms, 20);
    assert_eq!(table.stats().persist_probes, 1);
    let second_probe = table.on_timer(token, TimerEvent::Persist).unwrap();
    assert_eq!(second_probe.timers[0].after_ms, 40);

    let partial_window =
        packet_with_window(source, destination, 101, server_next, TcpFlags::ACK, 3, &[]);
    let first_send = table.ingest(&partial_window).unwrap();
    assert_eq!(first_send.outgoing.len(), 1);
    let first = parse_tcp_segment(
        parse_ip_packet(&first_send.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(first.payload, b"hel");
    assert!(first_send
        .timers
        .iter()
        .any(|timer| timer.event == TimerEvent::Persist && timer.after_ms == 10));

    let reopened = packet_with_window(
        source,
        destination,
        101,
        server_next.wrapping_add(3),
        TcpFlags::ACK,
        32_000,
        &[],
    );
    let second_send = table.ingest(&reopened).unwrap();
    assert_eq!(second_send.outgoing.len(), 1);
    let second = parse_tcp_segment(
        parse_ip_packet(&second_send.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        second.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(3))
    );
    assert_eq!(second.payload, b"lo");
    assert!(second_send
        .cancelled_timers
        .iter()
        .any(|timer| timer.event == TimerEvent::Persist));

    let final_ack = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(5),
        TcpFlags::ACK,
        &[],
    );
    table.ingest(&final_ack).unwrap();
    assert_eq!(table.stats().send_buffered_bytes, 0);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::TcpPayloadBytes as usize],
        TcpTableConfig::default().receive_credit_bytes
    );
    assert!(table
        .on_timer(token, TimerEvent::Persist)
        .unwrap()
        .outgoing
        .is_empty());
}

#[test]
fn zero_receive_window_data_cannot_ack_outbound_payload() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 5,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(54);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    assert_eq!(table.write(token, b"sent").unwrap().outgoing.len(), 1);
    let fill = packet(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        b"hello",
    );
    assert_eq!(
        table.ingest(&fill).unwrap().events,
        [TcpEvent::Readable { token, bytes: 5 }]
    );

    // At a zero receive window, a segment consuming sequence space is not
    // acceptable. Its ACK and window fields must therefore not update sender
    // state, even though its sequence equals RCV.NXT.
    let unacceptable = packet_with_window(
        source,
        destination,
        106,
        server_next.wrapping_add(4),
        TcpFlags::ACK,
        0,
        b"x",
    );
    let rejected = table.ingest(&unacceptable).unwrap();
    assert!(rejected.events.is_empty());
    assert_eq!(rejected.outgoing.len(), 1);
    let defensive_ack =
        parse_tcp_segment(parse_ip_packet(&rejected.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(defensive_ack.meta.acknowledgment, Some(SeqNumber::new(106)));
    assert_eq!(table.stats().send_buffered_bytes, 4);

    // A pure ACK at RCV.NXT is acceptable with a zero receive window and can
    // acknowledge the same bytes.
    let valid_ack = packet(
        source,
        destination,
        106,
        server_next.wrapping_add(4),
        TcpFlags::ACK,
        &[],
    );
    table.ingest(&valid_ack).unwrap();
    assert_eq!(table.stats().send_buffered_bytes, 0);
}

#[test]
fn write_capacity_tracks_the_live_peer_window() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(21);

    let syn = packet(source, destination, 100, 0, TcpFlags::SYN, &[]);
    let syn_result = table.ingest(&syn).unwrap();
    let syn_ack = parse_tcp_segment(
        parse_ip_packet(&syn_result.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let accepted = table
        .ingest(&packet_with_window(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            3,
            &[],
        ))
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected handshake events: {events:?}"),
    };
    table.accept(token).unwrap();

    assert_eq!(table.write_capacity(token).unwrap(), 3);
    let sent = table.write(token, b"abc").unwrap();
    assert_eq!(sent.outgoing.len(), 1);
    assert_eq!(table.write_capacity(token).unwrap(), 0);

    table
        .ingest(&packet_with_window(
            source,
            destination,
            101,
            server_next.wrapping_add(3),
            TcpFlags::ACK,
            7,
            &[],
        ))
        .unwrap();
    assert_eq!(table.write_capacity(token).unwrap(), 7);
}

#[test]
fn abort_releases_a_persist_buffer() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(21);
    let (token, _) = zero_window_handshake(&mut table, source, destination);
    table.write(token, b"held").unwrap();
    assert!(matches!(
        table.close(token),
        Err(TcpTableError::State(
            sail_netstack::TcpError::SendOutstanding
        ))
    ));
    let aborted = table.abort(token).unwrap();
    assert!(aborted.events.contains(&TcpEvent::Closed(token)));
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn write_after_close_is_rejected_even_into_a_zero_window() {
    // Found by fuzz target tcp_table: the persist buffer accepted a write
    // after the local FIN and later probed that byte beyond the FIN.
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(22);
    let (token, server_next) = zero_window_handshake(&mut table, source, destination);
    let closed = table.close(token).unwrap();
    let fin = parse_tcp_segment(parse_ip_packet(&closed.outgoing[0], true).unwrap(), true).unwrap();
    assert!(fin.meta.flags.contains(TcpFlags::FIN));
    assert_eq!(fin.meta.sequence, SeqNumber::new(server_next));

    assert!(matches!(
        table.write(token, b"late"),
        Err(TcpTableError::State(
            sail_netstack::TcpError::InvalidSendState
        ))
    ));
    assert_eq!(table.stats().zero_window_writes, 0);
    let persist = table.on_timer(token, TimerEvent::Persist).unwrap();
    assert!(persist.outgoing.is_empty());
    table.abort(token).unwrap();
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn keepalive_is_opt_in_resets_on_peer_activity_and_closes_after_probe_budget() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            keepalive_idle_ms: Some(10),
            keepalive_interval_ms: 5,
            keepalive_max_probes: 2,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(22);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let first = table.on_timer(token, TimerEvent::Keepalive).unwrap();
    let probe =
        parse_tcp_segment(parse_ip_packet(&first.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        probe.meta.sequence,
        SeqNumber::new(server_next.wrapping_sub(1))
    );
    assert!(probe.payload.is_empty());
    assert_eq!(first.timers[0].after_ms, 5);
    assert_eq!(table.stats().keepalive_probes, 1);

    let response = packet(source, destination, 101, server_next, TcpFlags::ACK, &[]);
    let activity = table.ingest(&response).unwrap();
    assert!(activity
        .timers
        .iter()
        .any(|timer| timer.event == TimerEvent::Keepalive && timer.after_ms == 10));

    table.on_timer(token, TimerEvent::Keepalive).unwrap();
    table.on_timer(token, TimerEvent::Keepalive).unwrap();
    let timeout = table.on_timer(token, TimerEvent::Keepalive).unwrap();
    assert!(timeout.events.contains(&TcpEvent::Closed(token)));
    assert_eq!(table.stats().keepalive_probes, 3);
    assert_eq!(table.stats().keepalive_timeouts, 1);
    assert_eq!(table.stats().active_flows, 0);
}

#[test]
fn nagle_holds_one_small_write_until_all_flight_data_is_acked() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 100,
            nagle_enabled: true,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(23);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let first = table.write(token, b"first").unwrap();
    assert_eq!(first.outgoing.len(), 1);
    let held = table.write(token, b"tiny").unwrap();
    assert!(held.outgoing.is_empty());
    assert!(held.timers.is_empty());
    assert_eq!(table.stats().send_buffered_bytes, 9);
    assert_eq!(table.stats().nagle_buffered_writes, 1);

    let partial_ack = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(2),
        TcpFlags::ACK,
        &[],
    );
    assert!(table.ingest(&partial_ack).unwrap().outgoing.is_empty());

    let full_ack = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(5),
        TcpFlags::ACK,
        &[],
    );
    let released = table.ingest(&full_ack).unwrap();
    assert_eq!(released.outgoing.len(), 1);
    let segment =
        parse_tcp_segment(parse_ip_packet(&released.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        segment.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(5))
    );
    assert_eq!(segment.payload, b"tiny");
    assert!(!released
        .cancelled_timers
        .iter()
        .any(|timer| timer.event == TimerEvent::Persist));
}

#[test]
fn retransmission_budget_closes_and_releases_an_unresponsive_flow() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_retransmission_timeouts: 2,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(27);
    let (token, _) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();
    table.write(token, b"unanswered").unwrap();

    assert_eq!(
        table
            .on_timer(token, TimerEvent::Retransmission)
            .unwrap()
            .outgoing
            .len(),
        1
    );
    assert_eq!(
        table
            .on_timer(token, TimerEvent::Retransmission)
            .unwrap()
            .outgoing
            .len(),
        1
    );
    let failed = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    assert!(failed.events.contains(&TcpEvent::Closed(token)));
    assert_eq!(table.stats().retransmission_timeouts, 2);
    assert_eq!(table.stats().retransmission_failures, 1);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn repeated_rto_falls_back_to_minimum_ipv4_mtu_and_resegments_in_flight_data() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 1_400,
            black_hole_rto_threshold: Some(2),
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(28);
    let syn = packet_with_options(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
        &[2, 4, 0x05, 0x78],
    );
    let syn_ack = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let accepted = table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();
    assert_eq!(table.write_limit(token).unwrap(), 1_400);
    assert_eq!(table.write(token, &[7; 1_400]).unwrap().outgoing.len(), 1);

    let first = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let first =
        parse_tcp_segment(parse_ip_packet(&first.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(first.payload.len(), 1_400);

    let fallback = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let fallback =
        parse_tcp_segment(parse_ip_packet(&fallback.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(fallback.payload.len(), 536);
    assert_eq!(table.write_limit(token).unwrap(), 536);
    assert_eq!(table.stats().black_hole_mtu_fallbacks, 1);

    let acknowledged_prefix = table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next.wrapping_add(536),
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let next = parse_tcp_segment(
        parse_ip_packet(&acknowledged_prefix.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        next.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(536))
    );
    assert_eq!(next.payload.len(), 536);
}

#[test]
fn black_hole_mtu_fallback_can_be_disabled() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 1_400,
            black_hole_rto_threshold: None,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(29);
    let syn = packet_with_options(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
        &[2, 4, 0x05, 0x78],
    );
    let syn_ack = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let accepted = table
        .ingest(&packet(
            source,
            destination,
            101,
            syn_ack.meta.sequence.wrapping_add(1).get(),
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();
    table.write(token, &[9; 1_400]).unwrap();
    table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let second = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let second =
        parse_tcp_segment(parse_ip_packet(&second.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(second.payload.len(), 1_400);
    assert_eq!(table.write_limit(token).unwrap(), 1_400);
    assert_eq!(table.stats().black_hole_mtu_fallbacks, 0);
}

#[test]
fn repeated_rto_uses_the_ipv6_minimum_mtu_payload_ceiling() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 1_400,
            black_hole_rto_threshold: Some(2),
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = ipv6_endpoints(1);
    let syn = packet_with_options(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
        &[2, 4, 0x05, 0x78],
    );
    let syn_ack = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let accepted = table
        .ingest(&packet(
            source,
            destination,
            101,
            syn_ack.meta.sequence.wrapping_add(1).get(),
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();
    table.write(token, &[3; 1_400]).unwrap();
    table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let fallback = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let fallback =
        parse_tcp_segment(parse_ip_packet(&fallback.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(fallback.payload.len(), 1_220);
    assert_eq!(table.write_limit(token).unwrap(), 1_220);
    assert_eq!(table.stats().black_hole_mtu_fallbacks, 1);
}

#[test]
fn challenge_ack_rate_limit_refills_on_monotonic_time() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            challenge_ack_burst: 1,
            challenge_ack_refill_ms: 100,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(28);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let invalid_rst = |sequence| {
        packet(
            source,
            destination,
            sequence,
            server_next,
            TcpFlags::RST,
            &[],
        )
    };
    assert!(table
        .ingest_with_policy_at(&invalid_rst(50_000), true, 0)
        .unwrap()
        .outgoing
        .is_empty());
    assert_eq!(table.stats().challenge_acks_sent, 0);
    assert_eq!(table.stats().challenge_acks_rate_limited, 0);
    assert_eq!(
        table
            .ingest_with_policy_at(&invalid_rst(102), true, 0)
            .unwrap()
            .outgoing
            .len(),
        1
    );
    assert!(table
        .ingest_with_policy_at(&invalid_rst(103), true, 0)
        .unwrap()
        .outgoing
        .is_empty());
    assert_eq!(
        table
            .ingest_with_policy_at(&invalid_rst(104), true, 100)
            .unwrap()
            .outgoing
            .len(),
        1
    );
    assert_eq!(table.stats().challenge_acks_sent, 2);
    assert_eq!(table.stats().challenge_acks_rate_limited, 1);
}

#[test]
fn defensive_ack_limiter_bounds_unacceptable_segment_responses() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            defensive_ack_burst: 2,
            defensive_ack_refill_ms: 10,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(43);
    let (_token, server_next) = handshake(&mut table, source, destination);
    let unacceptable = packet(source, destination, 50_000, server_next, TcpFlags::ACK, &[]);
    for _ in 0..2 {
        assert_eq!(
            table
                .ingest_with_policy_at(&unacceptable, true, 0)
                .unwrap()
                .outgoing
                .len(),
            1
        );
    }
    assert!(table
        .ingest_with_policy_at(&unacceptable, true, 0)
        .unwrap()
        .outgoing
        .is_empty());
    assert_eq!(table.stats().defensive_acks_sent, 2);
    assert_eq!(table.stats().defensive_acks_rate_limited, 1);
    assert_eq!(
        table
            .ingest_with_policy_at(&unacceptable, true, 10)
            .unwrap()
            .outgoing
            .len(),
        1
    );
    assert_eq!(table.stats().defensive_acks_sent, 3);
}

#[test]
fn handshake_reserves_credit_before_advertising_and_bounds_accept_queue() {
    let mut budget = BudgetProfile::Router.budget();
    budget.max_accept_queue = 1;
    let ledger = ResourceLedger::new(budget).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(7),
        TcpTableConfig {
            receive_credit_bytes: 1_024,
            ..TcpTableConfig::default()
        },
    );

    let (source1, destination) = endpoints(1);
    let (token1, _) = handshake(&mut table, source1, destination);
    let (source2, _) = endpoints(2);
    let syn2 = packet(source2, destination, 100, 0, TcpFlags::SYN, &[]);
    let syn2_result = table.ingest(&syn2).unwrap();
    let parsed = parse_tcp_segment(
        parse_ip_packet(&syn2_result.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(parsed.meta.window, 1_024);
    let ack2 = packet(
        source2,
        destination,
        101,
        parsed.meta.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
        &[],
    );
    let dropped = table.ingest(&ack2).unwrap();
    assert_eq!(dropped, sail_netstack::TcpIngress::default());
    assert_eq!(table.stats().syn_received, 1);
    assert_eq!(table.stats().accept_queue, 1);
    assert_eq!(table.stats().peak_active_flows, 2);
    assert_eq!(table.stats().peak_syn_received, 1);
    assert_eq!(table.stats().peak_accept_queue, 1);
    assert_eq!(table.stats().accept_overflow_drops, 1);

    table.accept(token1).unwrap();
    assert!(matches!(
        table.ingest(&ack2).unwrap().events.as_slice(),
        [TcpEvent::Accepted(_)]
    ));
    assert_eq!(table.reclaim_oldest_syn_received(), None);
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.used[ResourceKind::TcpFlows as usize], 2);
    assert_eq!(snapshot.used[ResourceKind::TcpPayloadBytes as usize], 2_048);
}

#[test]
fn accept_queue_reject_policy_resets_and_reclaims_embryonic_flow() {
    let mut budget = BudgetProfile::Router.budget();
    budget.max_accept_queue = 1;
    let ledger = ResourceLedger::new(budget).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(7),
        TcpTableConfig {
            receive_credit_bytes: 1_024,
            accept_overflow_policy: AcceptOverflowPolicy::RejectWithReset,
            stateless_reset_burst: 1,
            stateless_reset_refill_ms: 1_000,
            ..TcpTableConfig::default()
        },
    );

    let (source1, destination) = endpoints(3);
    handshake(&mut table, source1, destination);
    let (source2, _) = endpoints(4);
    let syn = packet(source2, destination, 100, 0, TcpFlags::SYN, &[]);
    let syn_result = table.ingest(&syn).unwrap();
    let retransmission = syn_result.timers[0];
    let syn_ack = parse_tcp_segment(
        parse_ip_packet(&syn_result.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    let ack = packet(
        source2,
        destination,
        101,
        syn_ack.meta.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
        &[],
    );

    let rejected = table.ingest(&ack).unwrap();
    assert!(rejected.events.is_empty());
    assert_eq!(rejected.outgoing.len(), 1);
    let reset =
        parse_tcp_segment(parse_ip_packet(&rejected.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(reset.meta.flags, TcpFlags::RST);
    assert_eq!(rejected.cancelled_timers.len(), 1);
    assert_eq!(rejected.cancelled_timers[0].token, retransmission.token);
    assert_eq!(
        rejected.cancelled_timers[0].event,
        TimerEvent::Retransmission
    );

    let stats = table.stats();
    assert_eq!(stats.active_flows, 1);
    assert_eq!(stats.syn_received, 0);
    assert_eq!(stats.accept_queue, 1);
    assert_eq!(stats.accept_overflow_rejections, 1);
    assert_eq!(stats.stateless_resets_sent, 1);

    let (source3, _) = endpoints(5);
    let rate_limited_syn = packet(source3, destination, 300, 0, TcpFlags::SYN, &[]);
    let rate_limited_syn_result = table.ingest(&rate_limited_syn).unwrap();
    let rate_limited_syn_ack = parse_tcp_segment(
        parse_ip_packet(&rate_limited_syn_result.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    let ack3 = packet(
        source3,
        destination,
        301,
        rate_limited_syn_ack.meta.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
        &[],
    );
    let rate_limited = table.ingest(&ack3).unwrap();
    assert!(rate_limited.outgoing.is_empty());
    assert_eq!(rate_limited.cancelled_timers.len(), 1);
    let stats = table.stats();
    assert_eq!(stats.accept_overflow_rejections, 2);
    assert_eq!(stats.stateless_resets_sent, 1);
    assert_eq!(stats.stateless_resets_rate_limited, 1);
    assert_eq!(stats.active_flows, 1);
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.used[ResourceKind::TcpFlows as usize], 1);
    assert_eq!(snapshot.used[ResourceKind::SynReceived as usize], 0);
    assert_eq!(snapshot.used[ResourceKind::TcpPayloadBytes as usize], 1_024);
}

#[test]
fn payload_is_buffered_with_reserved_credit_and_read_reopens_window() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 8,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(3);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let data = packet(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        b"abcdefgh",
    );
    let result = table.ingest(&data).unwrap();
    assert_eq!(result.events, [TcpEvent::Readable { token, bytes: 8 }]);
    assert!(result.outgoing.is_empty());
    assert_eq!(result.timers[0].event, TimerEvent::DelayedAck);
    assert_eq!(table.stats().buffered_bytes, 8);

    let read = table.read(token, 3).unwrap();
    assert_eq!(read.bytes, b"abc");
    assert!(read.outgoing.is_empty());
    assert!(read.cancelled_timers.is_empty());

    let read = table.read(token, 1).unwrap();
    assert_eq!(read.bytes, b"d");
    let window_update =
        parse_tcp_segment(parse_ip_packet(&read.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(window_update.meta.window, 4);
    assert_eq!(read.cancelled_timers[0].event, TimerEvent::DelayedAck);
    assert_eq!(table.read(token, 99).unwrap().bytes, b"efgh");
    assert_eq!(table.stats().buffered_bytes, 0);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        512
    );
}

#[test]
fn received_prefix_is_trimmed_while_new_suffix_and_fin_are_accepted() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(42);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let first = table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            b"abcd",
        ))
        .unwrap();
    assert_eq!(first.events, [TcpEvent::Readable { token, bytes: 4 }]);

    let overlap = table
        .ingest(&packet(
            source,
            destination,
            103,
            server_next,
            TcpFlags::ACK.union(TcpFlags::FIN),
            b"cdef",
        ))
        .unwrap();
    assert_eq!(
        overlap.events,
        [
            TcpEvent::Readable { token, bytes: 2 },
            TcpEvent::PeerHalfClosed(token),
        ]
    );
    assert_eq!(overlap.outgoing.len(), 1);
    let acknowledgment =
        parse_tcp_segment(parse_ip_packet(&overlap.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        acknowledgment.meta.acknowledgment,
        Some(SeqNumber::new(108))
    );
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"abcdef");
}

#[test]
fn receive_window_trims_both_edges_without_normalizing_rst_sequence() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 4,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(43);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let spoofed_rst = packet(
        source,
        destination,
        99,
        server_next,
        TcpFlags::RST.union(TcpFlags::ACK),
        b"xxab",
    );
    let ignored = table.ingest(&spoofed_rst).unwrap();
    assert!(ignored.events.is_empty());
    assert!(ignored.outgoing.is_empty());

    let spanning = packet(
        source,
        destination,
        99,
        server_next,
        TcpFlags::ACK.union(TcpFlags::FIN),
        b"xxabcdef",
    );
    let received = table.ingest(&spanning).unwrap();
    assert_eq!(received.events, [TcpEvent::Readable { token, bytes: 4 }]);
    assert!(!received.events.contains(&TcpEvent::PeerHalfClosed(token)));
    assert_eq!(received.timers[0].event, TimerEvent::DelayedAck);

    let delayed_ack = table.on_timer(token, TimerEvent::DelayedAck).unwrap();
    let acknowledgment = parse_tcp_segment(
        parse_ip_packet(&delayed_ack.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        acknowledgment.meta.acknowledgment,
        Some(SeqNumber::new(105))
    );
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"abcd");
}

#[test]
fn delayed_ack_timer_emits_ack_for_a_single_segment() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(30);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();
    let first = table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            b"a",
        ))
        .unwrap();
    assert!(first.outgoing.is_empty());
    assert_eq!(first.timers[0].event, TimerEvent::DelayedAck);

    let expired = table.on_timer(token, TimerEvent::DelayedAck).unwrap();
    let ack =
        parse_tcp_segment(parse_ip_packet(&expired.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(ack.meta.acknowledgment, Some(SeqNumber::new(102)));
}

#[test]
fn second_in_order_segment_cancels_delay_and_acks_both() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(31);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();
    table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            b"a",
        ))
        .unwrap();
    let second = table
        .ingest(&packet(
            source,
            destination,
            102,
            server_next,
            TcpFlags::ACK,
            b"b",
        ))
        .unwrap();
    assert_eq!(second.cancelled_timers[0].event, TimerEvent::DelayedAck);
    let ack = parse_tcp_segment(parse_ip_packet(&second.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(ack.meta.acknowledgment, Some(SeqNumber::new(103)));
}

#[test]
fn reset_invalidates_tokens_and_releases_all_flow_resources() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(4);
    let (token, _) = handshake(&mut table, source, destination);
    table.reset_network(NetworkGeneration::new(2));
    assert!(matches!(table.abort(token), Err(TcpTableError::StaleToken)));
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.used[ResourceKind::TcpFlows as usize], 0);
    assert_eq!(snapshot.used[ResourceKind::TcpPayloadBytes as usize], 0);
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(table.stats().peak_active_flows, 1);
    assert_eq!(table.stats().peak_syn_received, 1);
    assert_eq!(table.stats().peak_accept_queue, 1);
}

#[test]
fn close_and_exact_rst_release_flow_resources() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(5);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();
    let rst = packet(source, destination, 101, server_next, TcpFlags::RST, &[]);
    assert_eq!(
        table.ingest(&rst).unwrap().events,
        [TcpEvent::Closed(token)]
    );
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(ledger.snapshot().used[ResourceKind::TcpFlows as usize], 0);
}

#[test]
fn oversized_final_ack_cannot_partially_complete_handshake() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 4,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(6);
    let syn_result = table
        .ingest(&packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
        .unwrap();
    let syn_ack = parse_tcp_segment(
        parse_ip_packet(&syn_result.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let oversized = packet(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        b"12345",
    );
    assert!(matches!(
        table.ingest(&oversized),
        Err(TcpTableError::State(
            sail_netstack::TcpError::ReceiveCreditExceeded
        ))
    ));
    assert_eq!(table.stats().syn_received, 1);
    assert_eq!(table.stats().accept_queue, 0);

    let valid = packet(source, destination, 101, server_next, TcpFlags::ACK, &[]);
    assert!(matches!(
        table.ingest(&valid).unwrap().events.as_slice(),
        [TcpEvent::Accepted(_)]
    ));
}

#[test]
fn invalid_final_ack_is_reset_without_releasing_syn_received() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(59);
    let opened = table
        .ingest(&packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
        .unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&opened.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let invalid_ack = server_next.wrapping_add(1);

    let rejected = table
        .ingest(&packet(
            source,
            destination,
            101,
            invalid_ack,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let reset =
        parse_tcp_segment(parse_ip_packet(&rejected.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(reset.meta.flags, TcpFlags::RST);
    assert_eq!(reset.meta.sequence, SeqNumber::new(invalid_ack));
    assert_eq!(table.stats().syn_received, 1);
    assert_eq!(table.stats().accept_queue, 0);

    let valid = table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    assert!(matches!(valid.events.as_slice(), [TcpEvent::Accepted(_)]));
}

#[test]
fn invalid_initial_segments_do_not_consume_budget() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(7);
    let invalid = packet(
        source,
        destination,
        100,
        5,
        TcpFlags::SYN.union(TcpFlags::ACK),
        &[],
    );
    assert_eq!(table.ingest(&invalid).unwrap().outgoing.len(), 1);
    assert_eq!(ledger.snapshot().total_bytes, 0);
    assert_eq!(table.stats().active_flows, 0);

    let mut tight = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(2),
        TcpTableConfig {
            receive_credit_bytes: 4,
            ..TcpTableConfig::default()
        },
    );
    let oversized_syn_data = packet(source, destination, 200, 0, TcpFlags::SYN, b"12345");
    assert!(matches!(
        tight.ingest(&oversized_syn_data),
        Err(TcpTableError::State(
            sail_netstack::TcpError::ReceiveCreditExceeded
        ))
    ));
    assert_eq!(ledger.snapshot().total_bytes, 0);
    assert_eq!(tight.stats().active_flows, 0);
}

#[test]
fn initial_syn_data_and_fin_are_queued_until_the_exact_final_ack() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(48);
    let syn_fin = packet(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN.union(TcpFlags::FIN),
        b"abc",
    );
    let opened = table.ingest(&syn_fin).unwrap();
    assert_eq!(table.stats().buffered_bytes, 3);
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&opened.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(syn_ack.meta.acknowledgment, Some(SeqNumber::new(101)));
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let completed = table
        .ingest(&packet(
            source,
            destination,
            105,
            server_next,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let token = match completed.events.as_slice() {
        [TcpEvent::Accepted(connection), TcpEvent::Readable { token, bytes: 3 }, TcpEvent::PeerHalfClosed(half_closed)] =>
        {
            assert_eq!(connection.token, *token);
            assert_eq!(connection.token, *half_closed);
            *token
        }
        events => panic!("unexpected queued FIN events: {events:?}"),
    };
    let acknowledgment =
        parse_tcp_segment(parse_ip_packet(&completed.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        acknowledgment.meta.acknowledgment,
        Some(SeqNumber::new(105))
    );
    table.accept(token).unwrap();
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"abc");
    assert_eq!(table.stats().buffered_bytes, 0);

    let close = table.close(token).unwrap();
    assert!(
        parse_tcp_segment(parse_ip_packet(&close.outgoing[0], true).unwrap(), true)
            .unwrap()
            .meta
            .flags
            .contains(TcpFlags::FIN)
    );
    let closed = table
        .ingest(&packet(
            source,
            destination,
            105,
            server_next.wrapping_add(1),
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    assert_eq!(closed.events, [TcpEvent::Closed(token)]);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn final_handshake_ack_payload_follows_queued_syn_payload_exactly_once() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(58);
    let syn = packet(source, destination, 100, 0, TcpFlags::SYN, b"abc");
    let opened = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&opened.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let completed = table
        .ingest(&packet(
            source,
            destination,
            104,
            server_next,
            TcpFlags::ACK.union(TcpFlags::FIN),
            b"def",
        ))
        .unwrap();
    let token = match completed.events.as_slice() {
        [TcpEvent::Accepted(connection), TcpEvent::Readable { token, bytes: 3 }, TcpEvent::Readable {
            token: current,
            bytes: 3,
        }, TcpEvent::PeerHalfClosed(half_closed)] => {
            assert_eq!(connection.token, *token);
            assert_eq!(connection.token, *current);
            assert_eq!(connection.token, *half_closed);
            *token
        }
        events => panic!("unexpected handshake payload events: {events:?}"),
    };
    table.accept(token).unwrap();
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"abcdef");
    assert_eq!(table.stats().buffered_bytes, 0);
}

#[test]
fn combined_syn_and_final_ack_payload_cannot_overcommit_receive_credit() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 4,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(60);
    let syn = packet(source, destination, 100, 0, TcpFlags::SYN, b"abc");
    let opened = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&opened.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let oversized = packet(source, destination, 104, server_next, TcpFlags::ACK, b"de");
    assert!(matches!(
        table.ingest(&oversized),
        Err(TcpTableError::State(
            sail_netstack::TcpError::ReceiveCreditExceeded
        ))
    ));
    assert_eq!(table.stats().syn_received, 1);
    assert_eq!(table.stats().accept_queue, 0);
    assert_eq!(table.stats().buffered_bytes, 3);

    let completed = table
        .ingest(&packet(
            source,
            destination,
            104,
            server_next,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let token = match completed.events.as_slice() {
        [TcpEvent::Accepted(connection), TcpEvent::Readable { token, bytes: 3 }] => {
            assert_eq!(connection.token, *token);
            *token
        }
        events => panic!("unexpected recovery events: {events:?}"),
    };
    table.accept(token).unwrap();
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"abc");
}

#[test]
fn pre_handshake_overlap_trims_queued_syn_payload_and_preserves_new_suffix() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(61);
    let opened = table
        .ingest(&packet(source, destination, 100, 0, TcpFlags::SYN, b"abc"))
        .unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&opened.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let overlapping = table
        .ingest(&packet(
            source,
            destination,
            102,
            server_next,
            TcpFlags::ACK,
            b"bcX",
        ))
        .unwrap();
    assert!(
        overlapping.events.is_empty(),
        "unexpected pre-handshake events: {:?}",
        overlapping.events
    );
    assert_eq!(table.stats().syn_received, 1);

    let completed = table
        .ingest(&packet(
            source,
            destination,
            104,
            server_next,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let token = match completed.events.as_slice() {
        [TcpEvent::Accepted(connection), TcpEvent::Readable { token, bytes: 3 }, TcpEvent::Readable {
            token: current,
            bytes: 1,
        }] => {
            assert_eq!(connection.token, *token);
            assert_eq!(connection.token, *current);
            *token
        }
        events => panic!("unexpected overlapping handshake events: {events:?}"),
    };
    table.accept(token).unwrap();
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"abcX");
    assert_eq!(table.stats().buffered_bytes, 0);
}

#[test]
fn pre_handshake_overlap_preserves_fin_after_queued_syn_payload() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(62);
    let opened = table
        .ingest(&packet(source, destination, 100, 0, TcpFlags::SYN, b"abc"))
        .unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&opened.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let overlapping = table
        .ingest(&packet(
            source,
            destination,
            102,
            server_next,
            TcpFlags::ACK.union(TcpFlags::FIN),
            b"bc",
        ))
        .unwrap();
    assert!(overlapping.events.is_empty());
    assert_eq!(table.stats().syn_received, 1);

    let completed = table
        .ingest(&packet(
            source,
            destination,
            104,
            server_next,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let token = match completed.events.as_slice() {
        [TcpEvent::Accepted(connection), TcpEvent::Readable { token, bytes: 3 }, TcpEvent::PeerHalfClosed(half_closed)] =>
        {
            assert_eq!(connection.token, *token);
            assert_eq!(connection.token, *half_closed);
            *token
        }
        events => panic!("unexpected overlapping FIN events: {events:?}"),
    };
    table.accept(token).unwrap();
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"abc");
    assert_eq!(table.stats().buffered_bytes, 0);
}

#[test]
fn unknown_segments_receive_stateless_resets_without_creating_flows() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(29);

    let ack = packet(source, destination, 100, 777, TcpFlags::ACK, &[]);
    let reset = table.ingest(&ack).unwrap();
    let reset =
        parse_tcp_segment(parse_ip_packet(&reset.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(reset.meta.flags, TcpFlags::RST);
    assert_eq!(reset.meta.sequence, SeqNumber::new(777));
    assert_eq!(reset.meta.acknowledgment, None);

    let data = packet(source, destination, 100, 0, TcpFlags::default(), b"abc");
    let reset = table.ingest(&data).unwrap();
    let reset =
        parse_tcp_segment(parse_ip_packet(&reset.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(reset.meta.flags, TcpFlags::RST.union(TcpFlags::ACK));
    assert_eq!(reset.meta.sequence, SeqNumber::new(0));
    assert_eq!(reset.meta.acknowledgment, Some(SeqNumber::new(103)));

    let rst = packet(source, destination, 100, 0, TcpFlags::RST, &[]);
    assert!(table.ingest(&rst).unwrap().outgoing.is_empty());
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(table.stats().stateless_resets_sent, 2);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn timestamped_unknown_segment_receives_timestamped_reset() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(57);
    let mut options = vec![8, 10];
    options.extend_from_slice(&1_234_u32.to_be_bytes());
    options.extend_from_slice(&5_678_u32.to_be_bytes());
    options.extend_from_slice(&[1, 1]);
    let ack = packet_with_options(source, destination, 100, 777, TcpFlags::ACK, &options);

    let reset = table.ingest(&ack).unwrap();
    let reset =
        parse_tcp_segment(parse_ip_packet(&reset.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(reset.meta.flags, TcpFlags::RST);
    assert_eq!(reset.meta.sequence, SeqNumber::new(777));
    assert_eq!(reset.options.timestamps, Some((0, 1_234)));
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn syn_limiter_drops_before_flow_or_receive_credit_admission_and_refills() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig {
            syn_burst: 2,
            syn_refill_ms: 10,
            ..TcpTableConfig::default()
        },
    );
    for index in 0..2 {
        let (source, destination) = endpoints(40 + index);
        let syn = packet(source, destination, 100, 0, TcpFlags::SYN, &[]);
        assert_eq!(
            table
                .ingest_with_policy_at(&syn, true, 0)
                .unwrap()
                .outgoing
                .len(),
            1
        );
    }
    let before = ledger.snapshot();
    let (source, destination) = endpoints(42);
    let limited = packet(source, destination, 100, 0, TcpFlags::SYN, &[]);
    assert!(table
        .ingest_with_policy_at(&limited, true, 0)
        .unwrap()
        .outgoing
        .is_empty());
    assert_eq!(ledger.snapshot().used, before.used);
    assert_eq!(table.stats().syns_rate_limited, 1);
    assert_eq!(table.stats().active_flows, 2);

    assert_eq!(
        table
            .ingest_with_policy_at(&limited, true, 10)
            .unwrap()
            .outgoing
            .len(),
        1
    );
    assert_eq!(table.stats().active_flows, 3);
}

#[test]
fn pressure_reclaims_syn_received_in_creation_order_without_leaks() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (first_source, destination) = endpoints(30);
    let (second_source, _) = endpoints(31);
    let first = table
        .ingest(&packet(
            first_source,
            destination,
            100,
            0,
            TcpFlags::SYN,
            &[],
        ))
        .unwrap();
    let second = table
        .ingest(&packet(
            second_source,
            destination,
            200,
            0,
            TcpFlags::SYN,
            &[],
        ))
        .unwrap();
    let first_token = first.timers[0].token;
    let second_token = second.timers[0].token;

    assert_eq!(table.reclaim_oldest_syn_received(), Some(first_token));
    assert_eq!(table.reclaim_oldest_syn_received(), Some(second_token));
    assert_eq!(table.reclaim_oldest_syn_received(), None);
    assert_eq!(table.stats().pressure_reclaimed_syns, 2);
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(table.stats().syn_received, 0);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn time_wait_releases_full_tcb_credit_and_uses_its_own_hard_slot() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 1_024,
            time_wait_ms: 30_000,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(8);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();
    let close = table.close(token).unwrap();
    assert_eq!(close.outgoing.len(), 1);

    let ack = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(1),
        TcpFlags::ACK,
        &[],
    );
    table.ingest(&ack).unwrap();
    let fin = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(1),
        TcpFlags::ACK.union(TcpFlags::FIN),
        &[],
    );
    let result = table.ingest(&fin).unwrap();
    assert_eq!(result.timers[0].event, TimerEvent::TimeWaitExpired);
    assert_eq!(result.timers[0].after_ms, 30_000);
    assert_eq!(table.stats().time_wait, 1);
    assert_eq!(table.stats().peak_active_flows, 1);
    assert_eq!(table.stats().peak_time_wait, 1);
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.used[ResourceKind::TcpFlows as usize], 0);
    assert_eq!(snapshot.used[ResourceKind::TcpPayloadBytes as usize], 0);
    assert_eq!(snapshot.used[ResourceKind::TimeWait as usize], 1);

    let forged_fin = packet(
        source,
        destination,
        50_000,
        server_next.wrapping_add(1),
        TcpFlags::ACK.union(TcpFlags::FIN),
        &[],
    );
    let forged = table.ingest(&forged_fin).unwrap();
    assert_eq!(forged.outgoing.len(), 1);
    assert!(forged.timers.is_empty());

    let reset_fin = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(1),
        TcpFlags::RST.union(TcpFlags::FIN),
        &[],
    );
    let ignored = table.ingest(&reset_fin).unwrap();
    assert!(ignored.outgoing.is_empty());
    assert!(ignored.timers.is_empty());

    let retransmitted = table.ingest(&fin).unwrap();
    assert_eq!(retransmitted.outgoing.len(), 1);
    assert_eq!(retransmitted.timers.len(), 1);
    assert_eq!(retransmitted.timers[0].event, TimerEvent::TimeWaitExpired);
    assert_eq!(retransmitted.timers[0].after_ms, 30_000);

    assert_eq!(
        table
            .on_timer(token, TimerEvent::TimeWaitExpired)
            .unwrap()
            .events,
        [TcpEvent::Closed(token)]
    );
    assert_eq!(ledger.snapshot().used[ResourceKind::TimeWait as usize], 0);
    assert_eq!(table.stats().active_flows, 0);
}

#[test]
fn close_rto_retransmits_unacknowledged_payload_before_fin() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(46);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    table.write(token, b"data").unwrap();
    let close = table.close(token).unwrap();
    let fin = parse_tcp_segment(parse_ip_packet(&close.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        fin.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(4))
    );
    assert!(fin.meta.flags.contains(TcpFlags::FIN));

    let data_timeout = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let retransmitted = parse_tcp_segment(
        parse_ip_packet(&data_timeout.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(retransmitted.meta.sequence, SeqNumber::new(server_next));
    assert_eq!(retransmitted.payload, b"data");
    assert!(!retransmitted.meta.flags.contains(TcpFlags::FIN));

    table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next.wrapping_add(4),
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let fin_timeout = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let retransmitted_fin = parse_tcp_segment(
        parse_ip_packet(&fin_timeout.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        retransmitted_fin.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(4))
    );
    assert!(retransmitted_fin.meta.flags.contains(TcpFlags::FIN));
    assert!(retransmitted_fin.payload.is_empty());
}

#[test]
fn time_wait_reuses_metadata_and_evicts_the_oldest_slot_deterministically() {
    let enter_time_wait = |table: &mut TcpTable, source: SocketAddr, destination: SocketAddr| {
        let (token, server_next) = handshake(table, source, destination);
        table.accept(token).unwrap();
        table.close(token).unwrap();
        table
            .ingest(&packet(
                source,
                destination,
                101,
                server_next.wrapping_add(1),
                TcpFlags::ACK,
                &[],
            ))
            .unwrap();
        let entered = table
            .ingest(&packet(
                source,
                destination,
                101,
                server_next.wrapping_add(1),
                TcpFlags::ACK.union(TcpFlags::FIN),
                &[],
            ))
            .unwrap();
        (token, entered)
    };

    let mut tight_metadata = BudgetProfile::Router.budget();
    tight_metadata.metadata_bytes = 512;
    tight_metadata.max_time_wait = 1;
    let ledger = ResourceLedger::new(tight_metadata).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(45);
    enter_time_wait(&mut table, source, destination);
    assert_eq!(table.stats().time_wait, 1);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        128
    );

    let mut one_slot = BudgetProfile::Router.budget();
    one_slot.max_time_wait = 1;
    let ledger = ResourceLedger::new(one_slot).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(2),
        TcpTableConfig::default(),
    );
    let (first_source, first_destination) = endpoints(46);
    let (first, _) = enter_time_wait(&mut table, first_source, first_destination);
    let (second_source, second_destination) = endpoints(47);
    let (second, replacement) = enter_time_wait(&mut table, second_source, second_destination);
    assert_eq!(table.stats().time_wait, 1);
    assert_eq!(table.stats().time_wait_evictions, 1);
    assert_eq!(replacement.cancelled_timers.len(), 1);
    assert_eq!(replacement.cancelled_timers[0].token, first);
    // The evicted flow's owner must learn that it is gone.
    assert!(replacement.events.contains(&TcpEvent::Closed(first)));
    assert_eq!(
        replacement.cancelled_timers[0].event,
        TimerEvent::TimeWaitExpired
    );
    assert!(matches!(
        table.on_timer(first, TimerEvent::TimeWaitExpired),
        Err(TcpTableError::StaleToken)
    ));
    assert_eq!(
        table
            .on_timer(second, TimerEvent::TimeWaitExpired)
            .unwrap()
            .events,
        [TcpEvent::Closed(second)]
    );
    assert_eq!(ledger.snapshot().used[ResourceKind::TimeWait as usize], 0);
}

#[test]
fn pipelined_payload_is_budgeted_retransmitted_and_released_as_acked() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 1_024,
            max_segment_payload_bytes: 100,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(9);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let sent = table.write(token, b"reply").unwrap();
    let segment =
        parse_tcp_segment(parse_ip_packet(&sent.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(segment.source, destination);
    assert_eq!(segment.destination, source);
    assert_eq!(segment.meta.sequence, SeqNumber::new(server_next));
    assert_eq!(segment.payload, b"reply");
    assert_eq!(sent.timers[0].event, TimerEvent::Retransmission);
    assert_eq!(table.stats().send_buffered_bytes, 5);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::TcpPayloadBytes as usize],
        1_029
    );
    let pipelined = table.write(token, b"blocked").unwrap();
    let second =
        parse_tcp_segment(parse_ip_packet(&pipelined.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        second.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(5))
    );
    assert_eq!(second.payload, b"blocked");
    assert_eq!(table.stats().send_buffered_bytes, 12);

    let partial_ack = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(2),
        TcpFlags::ACK,
        &[],
    );
    table.ingest(&partial_ack).unwrap();
    assert_eq!(table.stats().send_buffered_bytes, 10);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::TcpPayloadBytes as usize],
        1_034
    );

    let retransmit = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let retransmitted = parse_tcp_segment(
        parse_ip_packet(&retransmit.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        retransmitted.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(2))
    );
    assert_eq!(retransmitted.payload, b"ply");

    let ack = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(5),
        TcpFlags::ACK,
        &[],
    );
    table.ingest(&ack).unwrap();
    assert_eq!(table.stats().send_buffered_bytes, 7);
    let retransmit = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let retransmitted = parse_tcp_segment(
        parse_ip_packet(&retransmit.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        retransmitted.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(5))
    );
    assert_eq!(retransmitted.payload, b"blocked");

    let final_ack = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(12),
        TcpFlags::ACK,
        &[],
    );
    table.ingest(&final_ack).unwrap();
    assert_eq!(table.stats().send_buffered_bytes, 0);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::TcpPayloadBytes as usize],
        1_024
    );
    assert!(table
        .on_timer(token, TimerEvent::Retransmission)
        .unwrap()
        .outgoing
        .is_empty());
}

#[test]
fn duplicate_acks_wake_a_blocked_writer_for_limited_transmit() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 8_000,
            max_segment_payload_bytes: 1_000,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(22);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let full = [0_u8; 536];
    for _ in 0..7 {
        table.write(token, &full).unwrap();
    }
    table.write(token, &[0_u8; 248]).unwrap();
    assert_eq!(table.write_capacity(token).unwrap(), 0);

    let duplicate = packet(source, destination, 101, server_next, TcpFlags::ACK, &[]);
    let first = table.ingest(&duplicate).unwrap();
    assert_eq!(table.write_capacity(token).unwrap(), 536);
    assert_eq!(first.events, [TcpEvent::Writable(token)]);
    table.write(token, &[1_u8; 536]).unwrap();
    table.write(token, &[2_u8; 464]).unwrap();
    assert_eq!(table.write_capacity(token).unwrap(), 0);

    let second = table.ingest(&duplicate).unwrap();
    assert_eq!(second.events, [TcpEvent::Writable(token)]);
    assert_eq!(table.write_capacity(token).unwrap(), 536);
}

#[test]
fn peer_mss_bounds_the_connection_and_every_application_write() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 100,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(10);
    let syn = emit_tcp_segment_with_options(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(100),
            acknowledgment: SeqNumber::new(0),
            flags: TcpFlags::SYN,
            window: 32_000,
        },
        &[2, 4, 0, 4],
        &[],
        64,
        1,
    )
    .unwrap();
    let syn_ack = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let ack = packet(
        source,
        destination,
        101,
        syn_ack.meta.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
        &[],
    );
    let accepted = table.ingest(&ack).unwrap();
    let connection = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => *connection,
        events => panic!("unexpected events: {events:?}"),
    };
    assert_eq!(connection.max_segment_payload_bytes, 4);
    table.accept(connection.token).unwrap();
    assert!(matches!(
        table.write(connection.token, b"12345"),
        Err(TcpTableError::PayloadTooLarge)
    ));
    assert_eq!(
        table
            .write(connection.token, b"1234")
            .unwrap()
            .outgoing
            .len(),
        1
    );
}

#[test]
fn learned_path_mtu_lowers_future_tcp_write_ceiling() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 1_000,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(12);
    let (token, _) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();
    assert_eq!(table.write_limit(token).unwrap(), 536);

    assert!(table.lower_path_mtu(destination, source, 100));
    assert_eq!(table.write_limit(token).unwrap(), 60);
    assert!(matches!(
        table.write(token, &[0; 61]),
        Err(TcpTableError::PayloadTooLarge)
    ));
    assert_eq!(table.write(token, &[0; 60]).unwrap().outgoing.len(), 1);
}

#[test]
fn learned_path_mtu_resegments_an_outstanding_chunk_across_acks() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 1_000,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(13);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();
    assert_eq!(table.write(token, &[5; 100]).unwrap().outgoing.len(), 1);
    assert!(table.lower_path_mtu(destination, source, 100));

    let retransmit = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let first = parse_tcp_segment(
        parse_ip_packet(&retransmit.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(first.payload.len(), 60);

    let ack = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(60),
        TcpFlags::ACK,
        &[],
    );
    let continuation = table.ingest(&ack).unwrap();
    assert_eq!(continuation.outgoing.len(), 1);
    let second = parse_tcp_segment(
        parse_ip_packet(&continuation.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(second.payload.len(), 40);
    assert_eq!(
        second.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(60))
    );
}

#[test]
fn negotiated_sack_skips_received_segments_during_fast_retransmit() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 100,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(11);
    let syn = packet_with_options(source, destination, 100, 0, TcpFlags::SYN, &[4, 2, 1, 1]);
    let syn_ack = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    assert!(syn_ack.options.sack_permitted);
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let accepted = table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();
    table.write(token, b"aaaa").unwrap();
    table.write(token, b"bbbb").unwrap();
    table.write(token, b"cccc").unwrap();

    let cumulative = server_next.wrapping_add(4);
    table
        .ingest(&packet(
            source,
            destination,
            101,
            cumulative,
            TcpFlags::ACK,
            &[],
        ))
        .unwrap();
    let sack_left = server_next.wrapping_add(8);
    let sack_right = server_next.wrapping_add(12);
    let mut options = vec![5, 10];
    options.extend_from_slice(&sack_left.to_be_bytes());
    options.extend_from_slice(&sack_right.to_be_bytes());
    options.extend_from_slice(&[1, 1]);
    let duplicate = packet_with_options(
        source,
        destination,
        101,
        cumulative,
        TcpFlags::ACK,
        &options,
    );
    assert!(table.ingest(&duplicate).unwrap().outgoing.is_empty());
    assert!(table.ingest(&duplicate).unwrap().outgoing.is_empty());
    let retransmit = table.ingest(&duplicate).unwrap();
    let retransmit = parse_tcp_segment(
        parse_ip_packet(&retransmit.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(retransmit.meta.sequence, SeqNumber::new(cumulative));
    assert_eq!(retransmit.payload, b"bbbb");
}

#[test]
fn out_of_window_sack_cannot_split_or_mark_the_send_queue() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints(48);
    let (token, server_next) = sack_handshake(&mut table, source, destination);
    table.write(token, b"abcdefgh").unwrap();
    let metadata_before = ledger.snapshot().used[ResourceKind::MetadataBytes as usize];

    let mut options = vec![5, 10];
    options.extend_from_slice(&server_next.wrapping_add(2).to_be_bytes());
    options.extend_from_slice(&server_next.wrapping_add(6).to_be_bytes());
    options.extend_from_slice(&[1, 1]);
    let outside_window = packet_with_options(
        source,
        destination,
        100,
        server_next,
        TcpFlags::ACK,
        &options,
    );
    let rejected = table.ingest(&outside_window).unwrap();
    assert_eq!(rejected.outgoing.len(), 1);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        metadata_before
    );

    let timeout = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    let retransmitted =
        parse_tcp_segment(parse_ip_packet(&timeout.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(retransmitted.meta.sequence, SeqNumber::new(server_next));
    assert_eq!(retransmitted.payload, b"abcdefgh");
}

#[test]
fn sack_scoreboard_infers_loss_before_three_duplicate_acks() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 100,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(24);
    let (token, server_next) = sack_handshake(&mut table, source, destination);
    for payload in [b"aaaa", b"bbbb", b"cccc", b"dddd"] {
        table.write(token, payload).unwrap();
    }

    let mut options = vec![5, 26];
    for (left, right) in [(4_u32, 8_u32), (8, 12), (12, 16)] {
        options.extend_from_slice(&server_next.wrapping_add(left).to_be_bytes());
        options.extend_from_slice(&server_next.wrapping_add(right).to_be_bytes());
    }
    options.extend_from_slice(&[1, 1]);
    let loss = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &options,
    );
    let recovery = table.ingest(&loss).unwrap();
    assert_eq!(recovery.outgoing.len(), 1);
    let retransmit =
        parse_tcp_segment(parse_ip_packet(&recovery.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(retransmit.meta.sequence, SeqNumber::new(server_next));
    assert_eq!(retransmit.payload, b"aaaa");
    assert_eq!(table.stats().sack_recovery_events, 1);
}

#[test]
fn sack_recovery_uses_pipe_nextseg_and_one_rescue_after_ack_progress() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 200,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(26);
    let (token, server_next) = sack_handshake(&mut table, source, destination);
    for byte in 0_u8..6 {
        table.write(token, &[byte; 100]).unwrap();
    }

    let sack_left = server_next.wrapping_add(300);
    let sack_right = server_next.wrapping_add(600);
    let mut options = vec![5, 10];
    options.extend_from_slice(&sack_left.to_be_bytes());
    options.extend_from_slice(&sack_right.to_be_bytes());
    options.extend_from_slice(&[1, 1]);
    let loss = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &options,
    );
    let recovery = table.ingest(&loss).unwrap();
    assert_eq!(recovery.outgoing.len(), 3);
    for (index, packet) in recovery.outgoing.iter().enumerate() {
        let segment = parse_tcp_segment(parse_ip_packet(packet, true).unwrap(), true).unwrap();
        assert_eq!(
            segment.meta.sequence,
            SeqNumber::new(
                server_next.wrapping_add(u32::try_from(index.saturating_mul(100)).unwrap())
            )
        );
        assert_eq!(segment.payload, &[u8::try_from(index).unwrap(); 100]);
    }
    assert_eq!(table.stats().sack_retransmitted_segments, 3);
    assert_eq!(table.stats().sack_rescue_segments, 0);

    let partial_ack = packet_with_options(
        source,
        destination,
        101,
        server_next.wrapping_add(100),
        TcpFlags::ACK,
        &options,
    );
    let rescue = table.ingest(&partial_ack).unwrap();
    assert_eq!(rescue.outgoing.len(), 1);
    let rescue =
        parse_tcp_segment(parse_ip_packet(&rescue.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        rescue.meta.sequence,
        SeqNumber::new(server_next.wrapping_add(200))
    );
    assert_eq!(rescue.payload, &[2; 100]);
    assert_eq!(table.stats().sack_retransmitted_segments, 4);
    assert_eq!(table.stats().sack_rescue_segments, 1);

    assert!(table.ingest(&partial_ack).unwrap().outgoing.is_empty());
    assert_eq!(table.stats().sack_rescue_segments, 1);
}

#[test]
fn partial_sack_blocks_split_chunks_into_exact_unsacked_ranges() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 200,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(27);
    let (token, server_next) = sack_handshake(&mut table, source, destination);
    let payload = (0_u8..200).collect::<Vec<_>>();
    table.write(token, &payload).unwrap();

    let mut options = vec![5, 26];
    for (left, right) in [(50_u32, 75_u32), (100, 125), (150, 175)] {
        options.extend_from_slice(&server_next.wrapping_add(left).to_be_bytes());
        options.extend_from_slice(&server_next.wrapping_add(right).to_be_bytes());
    }
    options.extend_from_slice(&[1, 1]);
    let recovery = table
        .ingest(&packet_with_options(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            &options,
        ))
        .unwrap();
    assert_eq!(recovery.outgoing.len(), 3);
    for (packet, (start, end)) in
        recovery
            .outgoing
            .iter()
            .zip([(0_usize, 50_usize), (75, 100), (125, 150)])
    {
        let segment = parse_tcp_segment(parse_ip_packet(packet, true).unwrap(), true).unwrap();
        assert_eq!(
            segment.meta.sequence,
            SeqNumber::new(server_next.wrapping_add(u32::try_from(start).unwrap()))
        );
        assert_eq!(segment.payload, &payload[start..end]);
    }
    assert_eq!(table.stats().send_buffered_bytes, payload.len());

    let final_ack = packet(
        source,
        destination,
        101,
        server_next.wrapping_add(u32::try_from(payload.len()).unwrap()),
        TcpFlags::ACK,
        &[],
    );
    table.ingest(&final_ack).unwrap();
    assert_eq!(table.stats().send_buffered_bytes, 0);
}

#[test]
fn sack_split_budget_failure_does_not_partially_advance_ack_state() {
    let mut budget = BudgetProfile::Router.budget();
    budget.metadata_bytes = 512 + 64;
    let ledger = ResourceLedger::new(budget).unwrap();
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 200,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(49);
    let (token, server_next) = sack_handshake(&mut table, source, destination);
    let payload = (0_u8..200).collect::<Vec<_>>();
    table.write(token, &payload).unwrap();
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        576
    );

    let mut options = vec![5, 10];
    options.extend_from_slice(&server_next.wrapping_add(100).to_be_bytes());
    options.extend_from_slice(&server_next.wrapping_add(125).to_be_bytes());
    options.extend_from_slice(&[1, 1]);
    let ack_with_sack = packet_with_options(
        source,
        destination,
        101,
        server_next.wrapping_add(50),
        TcpFlags::ACK,
        &options,
    );
    assert!(matches!(
        table.ingest(&ack_with_sack),
        Err(TcpTableError::Budget(_))
    ));
    assert_eq!(table.stats().send_buffered_bytes, payload.len());
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        576
    );

    let timeout = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    assert_eq!(timeout.outgoing.len(), 1);
    let retransmit =
        parse_tcp_segment(parse_ip_packet(&timeout.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(retransmit.meta.sequence, SeqNumber::new(server_next));
    assert_eq!(retransmit.payload, payload);
}

#[test]
fn invalid_sack_blocks_do_not_turn_newreno_retransmit_into_sack_recovery() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(50);
    let (token, server_next) = sack_handshake(&mut table, source, destination);
    table.write(token, b"payload").unwrap();

    let mut options = vec![5, 10];
    options.extend_from_slice(&server_next.wrapping_add(1_000).to_be_bytes());
    options.extend_from_slice(&server_next.wrapping_add(1_010).to_be_bytes());
    options.extend_from_slice(&[1, 1]);
    let duplicate_ack = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &options,
    );
    assert!(table.ingest(&duplicate_ack).unwrap().outgoing.is_empty());
    assert!(table.ingest(&duplicate_ack).unwrap().outgoing.is_empty());
    let retransmit = table.ingest(&duplicate_ack).unwrap();
    assert_eq!(retransmit.outgoing.len(), 1);
    let segment = parse_tcp_segment(
        parse_ip_packet(&retransmit.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(segment.meta.sequence, SeqNumber::new(server_next));
    assert_eq!(segment.payload, b"payload");
    assert_eq!(table.stats().sack_recovery_events, 0);
    assert_eq!(table.stats().sack_retransmitted_segments, 0);
}

#[test]
fn retransmission_timeout_clears_sack_scoreboard_for_receiver_reneging() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 100,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(25);
    let (token, server_next) = sack_handshake(&mut table, source, destination);
    table.write(token, b"aaaa").unwrap();
    table.write(token, b"bbbb").unwrap();

    let mut options = vec![5, 10];
    options.extend_from_slice(&server_next.to_be_bytes());
    options.extend_from_slice(&server_next.wrapping_add(8).to_be_bytes());
    options.extend_from_slice(&[1, 1]);
    let sack_all = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &options,
    );
    assert!(table.ingest(&sack_all).unwrap().outgoing.is_empty());

    let timeout = table.on_timer(token, TimerEvent::Retransmission).unwrap();
    assert_eq!(timeout.outgoing.len(), 1);
    let retransmit =
        parse_tcp_segment(parse_ip_packet(&timeout.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(retransmit.meta.sequence, SeqNumber::new(server_next));
    assert_eq!(retransmit.payload, b"aaaa");
}

#[test]
fn out_of_order_receive_is_sacked_deduplicated_and_promoted_in_order() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 1_024,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(26);
    let (token, server_next) = sack_handshake(&mut table, source, destination);

    let tail = packet(
        source,
        destination,
        106,
        server_next,
        TcpFlags::ACK,
        b"world",
    );
    let out_of_order = table.ingest(&tail).unwrap();
    assert!(out_of_order.events.is_empty());
    assert_eq!(out_of_order.outgoing.len(), 1);
    let sack_ack = parse_tcp_segment(
        parse_ip_packet(&out_of_order.outgoing[0], true).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(sack_ack.meta.acknowledgment, Some(SeqNumber::new(101)));
    assert_eq!(
        sack_ack.options.sack_blocks[0],
        Some(sail_netstack::SackBlock {
            left: SeqNumber::new(106),
            right: SeqNumber::new(111),
        })
    );
    assert_eq!(table.stats().buffered_bytes, 5);

    table.ingest(&tail).unwrap();
    assert_eq!(table.stats().buffered_bytes, 5);

    let head = packet(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK.union(TcpFlags::FIN),
        b"helloworld!",
    );
    let promoted = table.ingest(&head).unwrap();
    assert_eq!(
        promoted.events,
        [
            TcpEvent::Readable { token, bytes: 5 },
            TcpEvent::Readable { token, bytes: 5 }
        ]
    );
    assert!(!promoted.events.contains(&TcpEvent::PeerHalfClosed(token)));
    assert_eq!(promoted.outgoing.len(), 1);
    let cumulative =
        parse_tcp_segment(parse_ip_packet(&promoted.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(cumulative.meta.acknowledgment, Some(SeqNumber::new(111)));
    assert!(cumulative.options.sack_blocks.iter().all(Option::is_none));
    assert_eq!(table.read(token, 10).unwrap().bytes, b"helloworld");
}

#[test]
fn sack_reports_the_most_recent_out_of_order_block_first() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(65);
    let (_token, server_next) = sack_handshake(&mut table, source, destination);

    table
        .ingest(&packet(
            source,
            destination,
            106,
            server_next,
            TcpFlags::ACK,
            b"fg",
        ))
        .unwrap();
    let recent = table
        .ingest(&packet(
            source,
            destination,
            110,
            server_next,
            TcpFlags::ACK,
            b"jk",
        ))
        .unwrap();
    let acknowledgment =
        parse_tcp_segment(parse_ip_packet(&recent.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        acknowledgment.options.sack_blocks[..2],
        [
            Some(sail_netstack::SackBlock {
                left: SeqNumber::new(110),
                right: SeqNumber::new(112),
            }),
            Some(sail_netstack::SackBlock {
                left: SeqNumber::new(106),
                right: SeqNumber::new(108),
            }),
        ]
    );
}

#[test]
fn duplicate_out_of_order_segment_refreshes_the_first_sack_block() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(66);
    let (_token, server_next) = sack_handshake(&mut table, source, destination);
    let first = packet(source, destination, 106, server_next, TcpFlags::ACK, b"fg");
    table.ingest(&first).unwrap();
    table
        .ingest(&packet(
            source,
            destination,
            110,
            server_next,
            TcpFlags::ACK,
            b"jk",
        ))
        .unwrap();

    let duplicate = table.ingest(&first).unwrap();
    let acknowledgment =
        parse_tcp_segment(parse_ip_packet(&duplicate.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        acknowledgment.options.sack_blocks[..2],
        [
            Some(sail_netstack::SackBlock {
                left: SeqNumber::new(106),
                right: SeqNumber::new(108),
            }),
            Some(sail_netstack::SackBlock {
                left: SeqNumber::new(110),
                right: SeqNumber::new(112),
            }),
        ]
    );
    assert_eq!(table.stats().buffered_bytes, 4);
}

#[test]
fn partially_overlapping_out_of_order_segment_retains_novel_prefix() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(63);
    let (token, server_next) = sack_handshake(&mut table, source, destination);

    table
        .ingest(&packet(
            source,
            destination,
            105,
            server_next,
            TcpFlags::ACK,
            b"efg",
        ))
        .unwrap();
    let bridged = table
        .ingest(&packet(
            source,
            destination,
            103,
            server_next,
            TcpFlags::ACK,
            b"cdef",
        ))
        .unwrap();
    let acknowledgment =
        parse_tcp_segment(parse_ip_packet(&bridged.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        acknowledgment.options.sack_blocks[0],
        Some(sail_netstack::SackBlock {
            left: SeqNumber::new(103),
            right: SeqNumber::new(108),
        })
    );
    assert_eq!(table.stats().buffered_bytes, 5);

    let completed = table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            b"ab",
        ))
        .unwrap();
    assert_eq!(
        completed.events,
        [
            TcpEvent::Readable { token, bytes: 2 },
            TcpEvent::Readable { token, bytes: 2 },
            TcpEvent::Readable { token, bytes: 3 },
        ]
    );
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"abcdefg");
}

#[test]
fn partially_overlapping_out_of_order_segment_retains_novel_suffix() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(64);
    let (token, server_next) = sack_handshake(&mut table, source, destination);
    table
        .ingest(&packet(
            source,
            destination,
            103,
            server_next,
            TcpFlags::ACK,
            b"cd",
        ))
        .unwrap();
    let extended = table
        .ingest(&packet(
            source,
            destination,
            104,
            server_next,
            TcpFlags::ACK,
            b"def",
        ))
        .unwrap();
    let acknowledgment =
        parse_tcp_segment(parse_ip_packet(&extended.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        acknowledgment.options.sack_blocks[0],
        Some(sail_netstack::SackBlock {
            left: SeqNumber::new(103),
            right: SeqNumber::new(107),
        })
    );
    let completed = table
        .ingest(&packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            b"ab",
        ))
        .unwrap();
    assert_eq!(
        completed.events,
        [
            TcpEvent::Readable { token, bytes: 2 },
            TcpEvent::Readable { token, bytes: 2 },
            TcpEvent::Readable { token, bytes: 2 },
        ]
    );
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"abcdef");
}

#[test]
fn out_of_order_fin_is_applied_when_the_receive_gap_closes() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(44);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let tail = packet(
        source,
        destination,
        106,
        server_next,
        TcpFlags::ACK.union(TcpFlags::FIN),
        b"world",
    );
    let queued = table.ingest(&tail).unwrap();
    assert!(queued.events.is_empty());

    let head = packet(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        b"hello",
    );
    let promoted = table.ingest(&head).unwrap();
    assert_eq!(
        promoted.events,
        [
            TcpEvent::Readable { token, bytes: 5 },
            TcpEvent::Readable { token, bytes: 5 },
            TcpEvent::PeerHalfClosed(token),
        ]
    );
    assert_eq!(promoted.outgoing.len(), 1);
    let acknowledgment =
        parse_tcp_segment(parse_ip_packet(&promoted.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        acknowledgment.meta.acknowledgment,
        Some(SeqNumber::new(112))
    );
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"helloworld");
}

#[test]
fn unacceptable_fin_never_becomes_a_deferred_receive_boundary() {
    fn exercise(fin_sequence: u32, fin_ack_delta: u32, receive_credit_bytes: usize, offset: u8) {
        let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
        let mut table = TcpTable::new(
            ledger,
            NetworkGeneration::new(1),
            TcpTableConfig {
                receive_credit_bytes,
                ..TcpTableConfig::default()
            },
        );
        let (source, destination) = endpoints(offset);
        let (token, server_next) = handshake(&mut table, source, destination);
        table.accept(token).unwrap();

        let rejected_fin = packet(
            source,
            destination,
            fin_sequence,
            server_next.wrapping_add(fin_ack_delta),
            TcpFlags::ACK.union(TcpFlags::FIN),
            &[],
        );
        assert!(table.ingest(&rejected_fin).unwrap().events.is_empty());

        let head = packet(
            source,
            destination,
            101,
            server_next,
            TcpFlags::ACK,
            b"hello",
        );
        let delivered = table.ingest(&head).unwrap();
        assert_eq!(delivered.events, [TcpEvent::Readable { token, bytes: 5 }]);
        assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"hello");
    }

    // A FIN exactly at the right edge is outside the receive window.
    exercise(106, 0, 5, 51);
    // A FIN in the window is still inadmissible when its ACK is beyond SND.NXT.
    exercise(106, 1, 8, 52);
}

#[test]
fn earlier_out_of_order_fin_truncates_queued_data_and_closes_the_receive_stream() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(46);
    let (token, server_next) = handshake(&mut table, source, destination);
    table.accept(token).unwrap();

    let tail = packet(
        source,
        destination,
        106,
        server_next,
        TcpFlags::ACK,
        b"world!",
    );
    table.ingest(&tail).unwrap();
    assert_eq!(table.stats().buffered_bytes, 6);

    let earlier_fin = packet(
        source,
        destination,
        109,
        server_next,
        TcpFlags::ACK.union(TcpFlags::FIN),
        &[],
    );
    table.ingest(&earlier_fin).unwrap();
    assert_eq!(table.stats().buffered_bytes, 3);

    let head = packet(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        b"hello",
    );
    let promoted = table.ingest(&head).unwrap();
    assert_eq!(
        promoted.events,
        [
            TcpEvent::Readable { token, bytes: 5 },
            TcpEvent::Readable { token, bytes: 3 },
            TcpEvent::PeerHalfClosed(token),
        ]
    );
    let acknowledgment =
        parse_tcp_segment(parse_ip_packet(&promoted.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        acknowledgment.meta.acknowledgment,
        Some(SeqNumber::new(110))
    );
    assert_eq!(table.read(token, usize::MAX).unwrap().bytes, b"hellowor");

    let after_fin = packet(source, destination, 110, server_next, TcpFlags::ACK, b"bad");
    let rejected = table.ingest(&after_fin).unwrap();
    assert!(rejected.events.is_empty());
    assert_eq!(rejected.outgoing.len(), 1);
    assert_eq!(table.stats().buffered_bytes, 0);
}

#[test]
fn negotiated_window_scaling_applies_in_both_directions() {
    let ledger = ResourceLedger::new(BudgetProfile::Desktop.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 256 * 1024,
            max_segment_payload_bytes: 1_000,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(12);
    let syn = packet_with_options(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
        &[2, 4, 0x05, 0xb4, 3, 3, 7, 1],
    );
    let syn_ack = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(syn_ack.options.maximum_segment_size, Some(1_000));
    assert_eq!(syn_ack.options.window_scale, Some(3));
    // RFC 7323 2.2: the SYN-ACK window is never scaled, so 256 KiB of credit
    // is offered as the largest unscaled value.
    assert_eq!(syn_ack.meta.window, u32::from(u16::MAX));

    let ack = emit_tcp_segment(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(101),
            acknowledgment: syn_ack.meta.sequence.wrapping_add(1),
            flags: TcpFlags::ACK,
            window: 100,
        },
        &[],
        64,
        2,
    )
    .unwrap();
    let accepted = table.ingest(&ack).unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();
    assert_eq!(table.write(token, &[7; 1_000]).unwrap().outgoing.len(), 1);
}

#[test]
fn scaled_receive_window_never_accepts_unadvertised_remainder() {
    let ledger = ResourceLedger::new(BudgetProfile::Desktop.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            receive_credit_bytes: 65_537,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(56);
    let syn = packet_with_options(source, destination, 100, 0, TcpFlags::SYN, &[3, 3, 1, 1]);
    let syn_ack = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(syn_ack.options.window_scale, Some(1));
    // Unscaled in the SYN-ACK (RFC 7323 2.2), capped at 16 bits.
    assert_eq!(syn_ack.meta.window, u32::from(u16::MAX));
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let ack = packet(source, destination, 101, server_next, TcpFlags::ACK, &[]);
    let accepted = table.ingest(&ack).unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();

    let at_unadvertised_edge = packet(
        source,
        destination,
        101 + 65_536,
        server_next,
        TcpFlags::ACK,
        &[7],
    );
    let rejected = table.ingest(&at_unadvertised_edge).unwrap();
    assert!(rejected.events.is_empty());
    assert_eq!(rejected.outgoing.len(), 1);
    let acknowledgment =
        parse_tcp_segment(parse_ip_packet(&rejected.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(
        acknowledgment.meta.acknowledgment,
        Some(SeqNumber::new(101))
    );
    assert_eq!(table.stats().buffered_bytes, 0);
}

#[test]
fn oversized_peer_window_scale_is_clamped_and_observable() {
    let ledger = ResourceLedger::new(BudgetProfile::Desktop.budget()).unwrap();
    let mut table = TcpTable::new(
        ledger,
        NetworkGeneration::new(1),
        TcpTableConfig {
            max_segment_payload_bytes: 20_000,
            ..TcpTableConfig::default()
        },
    );
    let (source, destination) = endpoints(55);
    let syn = packet_with_options(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
        &[2, 4, 0x4e, 0x20, 3, 3, u8::MAX, 1],
    );
    let syn_ack = table.ingest(&syn).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let ack = emit_tcp_segment(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(101),
            acknowledgment: syn_ack.meta.sequence.wrapping_add(1),
            flags: TcpFlags::ACK,
            window: 1,
        },
        &[],
        64,
        2,
    )
    .unwrap();
    let accepted = table.ingest(&ack).unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();

    assert_eq!(table.write_capacity(token).unwrap(), 1 << 14);
    assert_eq!(table.stats().window_scale_clamps, 1);
}

#[test]
fn timestamps_echo_and_paws_rejects_old_segments() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(13);
    let mut syn_options = vec![8, 10];
    syn_options.extend_from_slice(&100_u32.to_be_bytes());
    syn_options.extend_from_slice(&0_u32.to_be_bytes());
    syn_options.extend_from_slice(&[1, 1]);
    let syn = packet_with_options(source, destination, 100, 0, TcpFlags::SYN, &syn_options);
    let syn_ack = table.ingest_with_policy_at(&syn, true, 1_000).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(syn_ack.options.timestamps, Some((1_000, 100)));
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let mut ack_options = vec![8, 10];
    ack_options.extend_from_slice(&101_u32.to_be_bytes());
    ack_options.extend_from_slice(&1_000_u32.to_be_bytes());
    ack_options.extend_from_slice(&[1, 1]);
    let ack = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &ack_options,
    );
    let accepted = table.ingest_with_policy_at(&ack, true, 1_100).unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();

    let missing = packet(source, destination, 101, server_next, TcpFlags::ACK, &[]);
    assert_eq!(
        table.ingest_with_policy_at(&missing, true, 1_150).unwrap(),
        sail_netstack::TcpIngress::default()
    );
    assert_eq!(table.stats().timestamp_missing_drops, 1);

    let mut stale_options = vec![8, 10];
    stale_options.extend_from_slice(&99_u32.to_be_bytes());
    stale_options.extend_from_slice(&1_000_u32.to_be_bytes());
    stale_options.extend_from_slice(&[1, 1]);
    let stale = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &stale_options,
    );
    let paws = table.ingest_with_policy_at(&stale, true, 1_200).unwrap();
    assert_eq!(paws.outgoing.len(), 1);
    let paws_ack =
        parse_tcp_segment(parse_ip_packet(&paws.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(paws_ack.meta.acknowledgment, Some(SeqNumber::new(101)));
    assert_eq!(paws_ack.options.timestamps, Some((1_200, 100)));
    assert_eq!(table.stats().paws_rejections, 1);
    assert_eq!(table.stats().defensive_acks_sent, 1);

    let sent = table.write(token, b"timestamped").unwrap();
    let sent = parse_tcp_segment(parse_ip_packet(&sent.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(sent.options.timestamps, Some((1_200, 100)));

    let mut data_ack_options = vec![8, 10];
    data_ack_options.extend_from_slice(&102_u32.to_be_bytes());
    data_ack_options.extend_from_slice(&1_200_u32.to_be_bytes());
    data_ack_options.extend_from_slice(&[1, 1]);
    let data_ack = packet_with_options(
        source,
        destination,
        101,
        server_next.wrapping_add(11),
        TcpFlags::ACK,
        &data_ack_options,
    );
    table.ingest_with_policy_at(&data_ack, true, 3_200).unwrap();
    assert!(matches!(
        table.ingest_with_policy_at(&data_ack, true, 3_199),
        Err(TcpTableError::ClockWentBackwards)
    ));
    let next = table.write(token, b"x").unwrap();
    assert_eq!(next.timers[0].after_ms, 2_385);
}

#[test]
fn forged_timestamp_echo_cannot_poison_the_rto_estimator() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    let (source, destination) = endpoints(47);

    let mut syn_options = vec![8, 10];
    syn_options.extend_from_slice(&100_u32.to_be_bytes());
    syn_options.extend_from_slice(&0_u32.to_be_bytes());
    syn_options.extend_from_slice(&[1, 1]);
    let syn = packet_with_options(source, destination, 100, 0, TcpFlags::SYN, &syn_options);
    let syn_ack = table.ingest_with_policy_at(&syn, true, 1_000).unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();

    let mut handshake_options = vec![8, 10];
    handshake_options.extend_from_slice(&101_u32.to_be_bytes());
    handshake_options.extend_from_slice(&1_000_u32.to_be_bytes());
    handshake_options.extend_from_slice(&[1, 1]);
    let handshake_ack = packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &handshake_options,
    );
    let accepted = table
        .ingest_with_policy_at(&handshake_ack, true, 1_100)
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();

    let sent = table.write(token, b"x").unwrap();
    assert_eq!(sent.timers[0].after_ms, 1_000);
    let sent = parse_tcp_segment(parse_ip_packet(&sent.outgoing[0], true).unwrap(), true).unwrap();
    assert_eq!(sent.options.timestamps, Some((1_100, 100)));

    let mut forged_options = vec![8, 10];
    forged_options.extend_from_slice(&101_u32.to_be_bytes());
    forged_options.extend_from_slice(&u32::MAX.to_be_bytes());
    forged_options.extend_from_slice(&[1, 1]);
    let forged_ack = packet_with_options(
        source,
        destination,
        101,
        server_next.wrapping_add(1),
        TcpFlags::ACK,
        &forged_options,
    );
    table
        .ingest_with_policy_at(&forged_ack, true, 1_200)
        .unwrap();

    let next = table.write(token, b"y").unwrap();
    assert_eq!(next.timers[0].after_ms, 1_000);
}
