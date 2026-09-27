use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use futures::executor::block_on;
use sail_netstack::{
    emit_icmp_error, emit_tcp_segment, emit_tcp_segment_with_options, emit_udp_packet,
    parse_icmp_packet, parse_ip_packet, parse_tcp_segment, parse_udp_datagram,
    AcceptOverflowPolicy, BudgetProfile, ChecksumCapabilities, FragmentReassembler, IcmpErrorKind,
    IcmpMessage, NetworkGeneration, Packet, PacketBatch, PacketCapabilities, PacketIo, PacketToken,
    PressureLevel, ResourceKind, ResourceLedger, RunnerConfig, RunnerError, RunnerState,
    SendControl, SeqNumber, SingleShardRunner, StackStats, TcpEvent, TcpFlags, TcpSegmentMeta,
    TraceKind, UdpError, MAX_DEBUG_TRACE_EVENTS, TCP_MAX_HEADER_BYTES,
};

#[derive(Debug)]
enum IoPlan {
    Count(usize),
    Error(io::ErrorKind),
}

#[derive(Debug)]
struct RecvPlan {
    packets: Vec<Packet>,
    reported: usize,
}

#[derive(Debug)]
struct MockIo {
    capabilities: PacketCapabilities,
    recv: VecDeque<Result<RecvPlan, io::ErrorKind>>,
    send: VecDeque<IoPlan>,
    recv_pending_once: bool,
    send_pending_once: bool,
    sent_tokens: Arc<Mutex<Vec<PacketToken>>>,
    sent_payloads: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MockIo {
    fn new(max_batch: usize) -> (Self, Arc<Mutex<Vec<PacketToken>>>) {
        let sent_tokens = Arc::new(Mutex::new(Vec::new()));
        let sent_payloads = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                capabilities: PacketCapabilities {
                    max_batch,
                    queue_count: 1,
                    headroom: 4,
                    vectored: max_batch > 1,
                    rx_checksum: ChecksumCapabilities::default(),
                    tx_checksum: ChecksumCapabilities::default(),
                    gso: None,
                },
                recv: VecDeque::new(),
                send: VecDeque::new(),
                recv_pending_once: false,
                send_pending_once: false,
                sent_tokens: Arc::clone(&sent_tokens),
                sent_payloads,
            },
            sent_tokens,
        )
    }

    fn push_recv(&mut self, payloads: Vec<Vec<u8>>) {
        let packets = payloads
            .into_iter()
            .enumerate()
            .map(|(index, payload)| {
                Packet::from_payload(PacketToken::new(u64::try_from(index).unwrap()), 0, &payload)
            })
            .collect::<Vec<_>>();
        self.recv.push_back(Ok(RecvPlan {
            reported: packets.len(),
            packets,
        }));
    }

    fn would_block_recv(&mut self) {
        self.recv.push_back(Err(io::ErrorKind::WouldBlock));
    }

    fn sent_payloads(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
        Arc::clone(&self.sent_payloads)
    }
}

impl PacketIo for MockIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        if std::mem::take(&mut self.recv_pending_once) {
            pending_once().await;
        }
        match self
            .recv
            .pop_front()
            .unwrap_or(Err(io::ErrorKind::WouldBlock))
        {
            Ok(plan) => {
                for packet in plan.packets {
                    out.push(packet)
                        .map_err(|_| io::Error::other("mock overflow"))?;
                }
                Ok(plan.reported)
            }
            Err(kind) => Err(io::Error::from(kind)),
        }
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        if std::mem::take(&mut self.send_pending_once) {
            pending_once().await;
        }
        match self
            .send
            .pop_front()
            .unwrap_or(IoPlan::Count(packets.len()))
        {
            IoPlan::Count(count) => {
                self.sent_tokens
                    .lock()
                    .unwrap()
                    .extend(packets.iter().take(count).map(Packet::token));
                self.sent_payloads.lock().unwrap().extend(
                    packets
                        .iter()
                        .take(count)
                        .map(|packet| packet.payload().to_vec()),
                );
                Ok(count)
            }
            IoPlan::Error(kind) => Err(io::Error::from(kind)),
        }
    }

    fn capabilities(&self) -> PacketCapabilities {
        self.capabilities
    }
}

async fn pending_once() {
    let mut pending = true;
    poll_fn(|context| {
        if std::mem::take(&mut pending) {
            context.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
}

fn udp_packet(source_port: u16, payload: &[u8]) -> Vec<u8> {
    emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(10, 7, 7, 2), source_port)),
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        payload,
        64,
        source_port,
    )
    .unwrap()
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*chunk));
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
    let checksum = ipv4_checksum(&fragment[..20]);
    fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
    fragment
}

fn icmpv4_echo_request(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0_u8; 28 + payload.len()];
    let packet_len = u16::try_from(packet.len()).unwrap();
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&[10, 7, 7, 2]);
    packet[16..20].copy_from_slice(&[10, 7, 7, 1]);
    let ip_checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet[20] = 8;
    packet[24..26].copy_from_slice(&0x1234_u16.to_be_bytes());
    packet[26..28].copy_from_slice(&7_u16.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let icmp_checksum = ipv4_checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    packet
}

fn unsupported_ipv4_packet() -> Vec<u8> {
    let mut packet = udp_packet(40_000, b"unknown");
    packet[9] = 99;
    packet[10..12].fill(0);
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn unsupported_ipv6_packet_after_destination_options() -> Vec<u8> {
    let wire = emit_udp_packet(
        SocketAddr::from(("fd00::2".parse::<Ipv6Addr>().unwrap(), 40_000)),
        SocketAddr::from(("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 53)),
        b"unknown protocol",
        64,
        0,
    )
    .unwrap();
    let mut packet = Vec::with_capacity(wire.len() + 8);
    packet.extend_from_slice(&wire[..40]);
    packet[4..6].copy_from_slice(&u16::try_from(wire.len() - 40 + 8).unwrap().to_be_bytes());
    packet[6] = 60;
    packet.extend_from_slice(&[99, 0, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&wire[40..]);
    packet
}

fn ipv6_unknown_option_packet(kind: u8) -> Vec<u8> {
    let wire = emit_udp_packet(
        SocketAddr::from(("fd00::2".parse::<Ipv6Addr>().unwrap(), 40_000)),
        SocketAddr::from(("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 53)),
        b"unknown option",
        64,
        0,
    )
    .unwrap();
    let mut packet = Vec::with_capacity(wire.len() + 8);
    packet.extend_from_slice(&wire[..40]);
    packet[4..6].copy_from_slice(&u16::try_from(wire.len() - 40 + 8).unwrap().to_be_bytes());
    packet[6] = 60;
    packet.extend_from_slice(&[17, 0, kind, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&wire[40..]);
    packet
}

fn ipv6_unrecognized_routing_packet() -> Vec<u8> {
    let wire = emit_udp_packet(
        SocketAddr::from(("fd00::2".parse::<Ipv6Addr>().unwrap(), 40_000)),
        SocketAddr::from(("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 53)),
        b"unknown routing type",
        64,
        0,
    )
    .unwrap();
    let mut packet = Vec::with_capacity(wire.len() + 8);
    packet.extend_from_slice(&wire[..40]);
    packet[4..6].copy_from_slice(&u16::try_from(wire.len() - 40 + 8).unwrap().to_be_bytes());
    packet[6] = 43;
    packet.extend_from_slice(&[17, 0, 255, 1, 0, 0, 0, 0]);
    packet.extend_from_slice(&wire[40..]);
    packet
}

fn ipv6_no_next_header_packet(trailing: &[u8]) -> Vec<u8> {
    let mut packet = vec![0_u8; 40 + trailing.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(trailing.len()).unwrap().to_be_bytes());
    packet[6] = 59;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
    packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    packet[40..].copy_from_slice(trailing);
    packet
}

fn ipv6_extension_no_next_header_packet(trailing: &[u8]) -> Vec<u8> {
    let mut packet = ipv6_no_next_header_packet(trailing);
    packet.splice(40..40, [59, 0, 0, 0, 0, 0, 0, 0]);
    packet[4..6].copy_from_slice(&u16::try_from(8 + trailing.len()).unwrap().to_be_bytes());
    packet[6] = 60;
    packet
}

fn ipv6_nonleading_hop_by_hop_packet() -> Vec<u8> {
    let wire = emit_udp_packet(
        SocketAddr::from(("fd00::2".parse::<Ipv6Addr>().unwrap(), 40_000)),
        SocketAddr::from(("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 53)),
        b"bad extension order",
        64,
        0,
    )
    .unwrap();
    let mut packet = Vec::with_capacity(wire.len() + 16);
    packet.extend_from_slice(&wire[..40]);
    packet[4..6].copy_from_slice(&u16::try_from(wire.len() - 40 + 16).unwrap().to_be_bytes());
    packet[6] = 60;
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&wire[40..]);
    packet
}

fn runner(io: MockIo) -> (SingleShardRunner<MockIo>, Arc<ResourceLedger>) {
    runner_with_config(io, &deterministic_runner_config())
}

fn deterministic_runner_config() -> RunnerConfig {
    let mut config = RunnerConfig::default();
    // Protocol tests assert packet/state transitions, not host CPU speed.
    // Scheduler time-budget behavior has dedicated model coverage.
    config.scheduler.max_time_per_round = Duration::from_secs(30);
    config
}

fn runner_with_config(
    io: MockIo,
    config: &RunnerConfig,
) -> (SingleShardRunner<MockIo>, Arc<ResourceLedger>) {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut config = *config;
    if config.scheduler.max_time_per_round
        == sail_netstack::SchedulerConfig::default().max_time_per_round
    {
        // Keep protocol assertions deterministic under slow emulators. The
        // scheduler model has separate coverage for the real time budget.
        config.scheduler.max_time_per_round = Duration::from_secs(30);
    }
    let runner = SingleShardRunner::new(io, Arc::clone(&ledger), config).unwrap();
    (runner, ledger)
}

#[test]
fn debug_trace_is_disabled_by_default() {
    let (mut io, _) = MockIo::new(1);
    io.push_recv(vec![udp_packet(10, b"trace-off")]);
    let (mut runner, _) = runner(io);

    block_on(runner.step(1)).unwrap();
    assert!(runner.trace_snapshot().events.is_empty());
    assert_eq!(runner.trace_snapshot().overwritten_events, 0);
}

#[test]
fn debug_trace_is_bounded_ordered_and_clearable() {
    let (mut io, _) = MockIo::new(1);
    io.push_recv(vec![udp_packet(10, b"trace-on")]);
    let config = RunnerConfig {
        debug_trace_capacity: 3,
        ..deterministic_runner_config()
    };
    let (mut runner, _) = runner_with_config(io, &config);

    block_on(runner.step(1)).unwrap();
    runner.update_mtu(1_400).unwrap();
    runner.reset_network(NetworkGeneration::new(2));

    let trace = runner.trace_snapshot();
    assert_eq!(trace.events.len(), 3);
    assert_eq!(trace.overwritten_events, 2);
    assert_eq!(trace.events[0].sequence + 1, trace.events[1].sequence);
    assert_eq!(trace.events[1].sequence + 1, trace.events[2].sequence);
    assert!(matches!(
        trace.events[0].kind,
        TraceKind::SchedulerRound {
            packets: 1,
            bytes: _
        }
    ));
    assert_eq!(trace.events[1].kind, TraceKind::MtuChanged { mtu: 1_400 });
    assert_eq!(
        trace.events[2].kind,
        TraceKind::NetworkReset { generation: 2 }
    );

    runner.clear_trace();
    let cleared = runner.trace_snapshot();
    assert!(cleared.events.is_empty());
    assert_eq!(cleared.overwritten_events, 0);
}

#[test]
fn debug_trace_capacity_has_a_hard_limit() {
    let (io, _) = MockIo::new(1);
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let config = RunnerConfig {
        debug_trace_capacity: MAX_DEBUG_TRACE_EVENTS + 1,
        ..deterministic_runner_config()
    };
    assert!(matches!(
        SingleShardRunner::new(io, ledger, config),
        Err(RunnerError::InvalidConfig(_))
    ));
}

#[test]
fn runner_answers_icmpv4_echo_with_valid_wire_packet() {
    let (mut io, _) = MockIo::new(1);
    let sent = io.sent_payloads();
    io.push_recv(vec![icmpv4_echo_request(b"ping")]);
    let (mut runner, _) = runner(io);

    let first = block_on(runner.step(1)).unwrap();
    assert_eq!(first.processed_packets, 1);
    assert_eq!(runner.pending_tx(), 1);
    assert_eq!(runner.stats_snapshot().icmp_echo_replies, 1);
    block_on(runner.step(2)).unwrap();

    let sent = sent.lock().unwrap();
    let ip = parse_ip_packet(&sent[0], true).unwrap();
    let icmp = parse_icmp_packet(ip, true).unwrap();
    assert_eq!(ip.source, "10.7.7.1".parse::<IpAddr>().unwrap());
    assert_eq!(ip.destination, "10.7.7.2".parse::<IpAddr>().unwrap());
    assert_eq!(icmp.payload, b"ping");
    assert!(matches!(
        icmp.message,
        IcmpMessage::EchoReply {
            identifier: 0x1234,
            sequence: 7
        }
    ));
}

#[test]
fn runner_reports_unsupported_ip_protocols_with_exact_kinds_and_pointer() {
    let (mut io, _) = MockIo::new(2);
    let sent = io.sent_payloads();
    io.push_recv(vec![
        unsupported_ipv4_packet(),
        unsupported_ipv6_packet_after_destination_options(),
    ]);
    let (mut runner, _) = runner(io);

    block_on(runner.step(1)).unwrap();
    block_on(runner.step(2)).unwrap();
    let sent = sent.lock().unwrap();
    let ipv4 = parse_ip_packet(&sent[0], true).unwrap();
    assert_eq!(
        parse_icmp_packet(ipv4, true).unwrap().message,
        IcmpMessage::DestinationUnreachable { code: 2 }
    );
    let ipv6 = parse_ip_packet(&sent[1], true).unwrap();
    assert_eq!(
        parse_icmp_packet(ipv6, true).unwrap().message,
        IcmpMessage::ParameterProblem {
            code: 1,
            pointer: 40
        }
    );
    assert_eq!(runner.stats_snapshot().icmp_errors_sent, 2);
}

#[test]
fn runner_reports_unknown_ipv6_option_with_exact_pointer() {
    let (mut io, _) = MockIo::new(1);
    let sent = io.sent_payloads();
    let invoking = ipv6_unknown_option_packet(0x80);
    io.push_recv(vec![invoking.clone()]);
    let (mut runner, _) = runner(io);

    let first = block_on(runner.step(1)).unwrap();
    assert_eq!(first.dropped_packets, 1);
    assert_eq!(runner.pending_tx(), 1);
    block_on(runner.step(2)).unwrap();

    let sent = sent.lock().unwrap();
    let ip = parse_ip_packet(&sent[0], true).unwrap();
    let icmp = parse_icmp_packet(ip, true).unwrap();
    assert_eq!(
        icmp.message,
        IcmpMessage::ParameterProblem {
            code: 2,
            pointer: 42
        }
    );
    assert_eq!(icmp.payload, invoking.as_slice());
    let stats = runner.stats_snapshot();
    assert_eq!(stats.icmp_errors_sent, 1);
    assert_eq!(stats.dropped_packets, 1);
    assert_eq!(stats.dropped_wire_packets, 1);
}

#[test]
fn runner_reports_unrecognized_ipv6_routing_type_with_exact_pointer() {
    let (mut io, _) = MockIo::new(1);
    let sent = io.sent_payloads();
    let invoking = ipv6_unrecognized_routing_packet();
    io.push_recv(vec![invoking.clone()]);
    let (mut runner, _) = runner(io);

    let first = block_on(runner.step(1)).unwrap();
    assert_eq!(first.dropped_packets, 1);
    assert_eq!(runner.pending_tx(), 1);
    block_on(runner.step(2)).unwrap();

    let sent = sent.lock().unwrap();
    let ip = parse_ip_packet(&sent[0], true).unwrap();
    let icmp = parse_icmp_packet(ip, true).unwrap();
    assert_eq!(
        icmp.message,
        IcmpMessage::ParameterProblem {
            code: 0,
            pointer: 42
        }
    );
    assert_eq!(icmp.payload, invoking.as_slice());
    assert_eq!(runner.stats_snapshot().icmp_errors_sent, 1);
}

#[test]
fn runner_silently_ignores_ipv6_no_next_header_and_trailing_octets() {
    let (mut io, _) = MockIo::new(2);
    let sent = io.sent_payloads();
    io.push_recv(vec![
        ipv6_no_next_header_packet(b"must be ignored"),
        ipv6_extension_no_next_header_packet(b"also ignored"),
    ]);
    let (mut runner, _) = runner(io);

    let outcome = block_on(runner.step(1)).unwrap();
    assert_eq!(outcome.dropped_packets, 2);
    assert_eq!(runner.pending_tx(), 0);
    assert!(sent.lock().unwrap().is_empty());
    let stats = runner.stats_snapshot();
    assert_eq!(stats.icmp_errors_sent, 0);
    assert_eq!(stats.dropped_policy_packets, 2);
}

#[test]
fn runner_reports_nonleading_ipv6_hop_by_hop_pointer() {
    let (mut io, _) = MockIo::new(1);
    let sent = io.sent_payloads();
    let invoking = ipv6_nonleading_hop_by_hop_packet();
    io.push_recv(vec![invoking.clone()]);
    let (mut runner, _) = runner(io);

    let first = block_on(runner.step(1)).unwrap();
    assert_eq!(first.dropped_packets, 1);
    assert_eq!(runner.pending_tx(), 1);
    block_on(runner.step(2)).unwrap();

    let sent = sent.lock().unwrap();
    let ip = parse_ip_packet(&sent[0], true).unwrap();
    let icmp = parse_icmp_packet(ip, true).unwrap();
    assert_eq!(
        icmp.message,
        IcmpMessage::ParameterProblem {
            code: 1,
            pointer: 40
        }
    );
    assert_eq!(icmp.payload, invoking.as_slice());
    assert_eq!(runner.stats_snapshot().icmp_errors_sent, 1);
}

#[test]
fn runner_emits_time_exceeded_when_initial_fragment_expires() {
    let (mut io, _) = MockIo::new(1);
    let sent = io.sent_payloads();
    let packet = udp_packet(40_000, b"fragment timeout payload");
    let first = ipv4_fragment(&packet, 0, 16, true);
    io.push_recv(vec![first.clone()]);
    let config = RunnerConfig {
        fragment_timeout_ms: 20,
        ..deterministic_runner_config()
    };
    let (mut runner, ledger) = runner_with_config(io, &config);

    block_on(runner.step(0)).unwrap();
    assert_eq!(runner.stats_snapshot().fragment_datagrams, 1);
    let outcome = block_on(runner.step(20)).unwrap();
    assert_eq!(outcome.sent_packets, 1);

    let sent = sent.lock().unwrap();
    let ip = parse_ip_packet(&sent[0], true).unwrap();
    let icmp = parse_icmp_packet(ip, true).unwrap();
    assert_eq!(icmp.message, IcmpMessage::TimeExceeded { code: 1 });
    assert_eq!(icmp.payload, first);
    let stats = runner.stats_snapshot();
    assert_eq!(stats.expired_reassemblies, 1);
    assert_eq!(stats.icmp_errors_sent, 1);
    assert_eq!(stats.fragment_datagrams, 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::Fragments), 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::FragmentBytes), 0);
}

#[test]
fn icmp_error_limiter_is_independent_and_refills_on_virtual_time() {
    let (mut io, _) = MockIo::new(2);
    io.push_recv(vec![unsupported_ipv4_packet(), unsupported_ipv4_packet()]);
    io.push_recv(vec![unsupported_ipv4_packet()]);
    let config = RunnerConfig {
        icmp_error_burst: 1,
        icmp_error_refill_ms: 1_000,
        ..deterministic_runner_config()
    };
    let (mut runner, _) = runner_with_config(io, &config);

    let first = block_on(runner.step(1)).unwrap();
    assert_eq!(first.processed_packets, 2);
    assert_eq!(runner.pending_tx(), 1);
    assert_eq!(runner.stats_snapshot().icmp_errors_sent, 1);
    assert_eq!(runner.stats_snapshot().icmp_errors_rate_limited, 1);

    block_on(runner.step(1_001)).unwrap();
    assert_eq!(runner.pending_tx(), 1);
    assert_eq!(runner.stats_snapshot().icmp_errors_sent, 2);
    assert_eq!(runner.stats_snapshot().icmp_errors_rate_limited, 1);
}

#[test]
fn icmp_echo_limiter_is_independent_and_refills_on_virtual_time() {
    let (mut io, _) = MockIo::new(2);
    io.push_recv(vec![icmpv4_echo_request(b"aa"), icmpv4_echo_request(b"bb")]);
    io.push_recv(vec![icmpv4_echo_request(b"cc")]);
    let config = RunnerConfig {
        icmp_echo_burst: 1,
        icmp_echo_refill_ms: 1_000,
        ..deterministic_runner_config()
    };
    let (mut runner, _) = runner_with_config(io, &config);

    let first = block_on(runner.step(1)).unwrap();
    assert_eq!(first.processed_packets, 2);
    assert_eq!(runner.pending_tx(), 1);
    assert_eq!(runner.stats_snapshot().icmp_echo_replies, 1);
    assert_eq!(runner.stats_snapshot().icmp_echo_rate_limited, 1);

    block_on(runner.step(1_001)).unwrap();
    assert_eq!(runner.pending_tx(), 1);
    assert_eq!(runner.stats_snapshot().icmp_echo_replies, 2);
    assert_eq!(runner.stats_snapshot().icmp_echo_rate_limited, 1);
}

#[test]
fn runner_takes_packets_over_its_mtu_and_refuses_those_over_its_buffer() {
    let (mut io, _) = MockIo::new(1);
    let sent = io.sent_payloads();
    // Past the MTU, which bounds only what the stack sends; then past the
    // largest packet it has room for.
    io.push_recv(vec![udp_packet(40_000, &vec![7; 600])]);
    io.push_recv(vec![udp_packet(40_001, &vec![7; 800])]);
    let config = RunnerConfig {
        mtu: 576,
        max_packet_size: 700,
        tcp: sail_netstack::TcpTableConfig {
            max_segment_payload_bytes: 576 - TCP_MAX_HEADER_BYTES,
            ..sail_netstack::TcpTableConfig::default()
        },
        ..deterministic_runner_config()
    };
    let (mut runner, _) = runner_with_config(io, &config);

    let taken = block_on(runner.step(1)).unwrap();
    assert_eq!(taken.dropped_packets, 0);
    assert_eq!(taken.datagrams.len(), 1);
    assert_eq!(taken.datagrams[0].payload.to_vec(), vec![7; 600]);

    let refused = block_on(runner.step(2)).unwrap();
    assert_eq!(refused.dropped_packets, 1);
    block_on(runner.step(3)).unwrap();
    let sent = sent.lock().unwrap();
    let ip = parse_ip_packet(&sent[0], true).unwrap();
    assert_eq!(
        parse_icmp_packet(ip, true).unwrap().message,
        IcmpMessage::PacketTooBig { mtu: 576 }
    );
}

#[test]
fn max_batch_one_udp_round_trip_is_budgeted() {
    let (mut io, sent_tokens) = MockIo::new(1);
    io.push_recv(vec![udp_packet(40_000, b"query")]);
    io.would_block_recv();
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut runner =
        SingleShardRunner::new(io, Arc::clone(&ledger), deterministic_runner_config()).unwrap();
    let outcome = block_on(runner.step(1)).unwrap();
    assert_eq!(outcome.datagrams.len(), 1);
    let ingress = &outcome.datagrams[0];
    let remote = ingress.destination;
    let token = ingress.token;
    drop(outcome);
    runner.queue_udp_reply(token, remote, b"answer", 2).unwrap();
    assert!(ledger.snapshot().used(ResourceKind::PacketBytes) > 0);
    let sent = block_on(runner.step(3)).unwrap();
    assert_eq!(sent.sent_packets, 1);
    assert!(sent.would_block);
    assert_eq!(runner.pending_tx(), 0);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::PacketBytes as usize],
        0
    );
    assert_eq!(sent_tokens.lock().unwrap().len(), 1);
}

#[test]
fn packet_io_repolls_after_pending_are_observable_per_direction() {
    let (mut io, _) = MockIo::new(1);
    io.recv_pending_once = true;
    io.send_pending_once = true;
    io.push_recv(vec![udp_packet(40_001, b"wake")]);
    let (mut runner, _) = runner(io);

    let received = block_on(runner.step(1)).unwrap();
    let datagram = &received.datagrams[0];
    let token = datagram.token;
    let remote = datagram.destination;
    drop(received);
    assert_eq!(runner.stats_snapshot().rx_io_wakeups, 1);
    assert_eq!(runner.stats_snapshot().tx_io_wakeups, 0);

    runner.queue_udp_reply(token, remote, b"ready", 2).unwrap();
    let sent = block_on(runner.step(3)).unwrap();
    assert_eq!(sent.sent_packets, 1);
    let stats = runner.stats_snapshot();
    assert_eq!(stats.rx_io_wakeups, 1);
    assert_eq!(stats.tx_io_wakeups, 1);
}

#[test]
fn runner_step_expires_idle_udp_flows_without_external_clock_calls() {
    let (mut io, _) = MockIo::new(1);
    io.push_recv(vec![udp_packet(40_000, b"query")]);
    io.would_block_recv();
    let (mut runner, ledger) = runner(io);
    let ingress = block_on(runner.step(1)).unwrap();
    assert_eq!(ingress.datagrams.len(), 1);
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 1);

    let outcome = block_on(runner.step(60_001)).unwrap();
    assert!(outcome.would_block);
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 1);

    let outcome = block_on(runner.step(60_010)).unwrap();
    assert!(outcome.would_block);
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 0);
}

#[test]
fn critical_pressure_rejects_new_tcp_and_udp_flows_before_admission() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 7, 7, 2), 40_100));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 7, 7, 1), 443));
    let (mut io, _) = MockIo::new(2);
    io.push_recv(vec![
        udp_packet(40_000, b"query"),
        tcp_packet(source, destination, 100, 0, TcpFlags::SYN),
    ]);
    let budget = BudgetProfile::Mobile.budget();
    let ledger = ResourceLedger::new(budget).unwrap();
    let _pressure_lease = ledger
        .try_acquire(
            ResourceKind::MetadataBytes,
            budget.metadata_bytes.saturating_mul(850).div_ceil(1_000),
        )
        .unwrap();
    let mut runner =
        SingleShardRunner::new(io, Arc::clone(&ledger), deterministic_runner_config()).unwrap();

    let outcome = block_on(runner.step(1)).unwrap();
    assert!(outcome.datagrams.is_empty());
    assert!(outcome.tcp_events.is_empty());
    assert_eq!(outcome.dropped_packets, 2);
    let stats = runner.stats_snapshot();
    assert_eq!(stats.pressure_rejected_new_flows, 2);
    assert_eq!(stats.dropped_policy_packets, 2);
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.used[ResourceKind::TcpFlows as usize], 0);
    assert_eq!(snapshot.used[ResourceKind::UdpFlows as usize], 0);
}

#[test]
fn entering_critical_pressure_reclaims_syn_received_and_cancels_its_timer() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 7, 7, 2), 40_101));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 7, 7, 1), 443));
    let (mut io, _) = MockIo::new(1);
    io.push_recv(vec![tcp_packet(source, destination, 100, 0, TcpFlags::SYN)]);
    let budget = BudgetProfile::Mobile.budget();
    let ledger = ResourceLedger::new(budget).unwrap();
    let mut runner =
        SingleShardRunner::new(io, Arc::clone(&ledger), deterministic_runner_config()).unwrap();

    block_on(runner.step(1)).unwrap();
    assert_eq!(runner.pending_tcp_timers(), 1);
    assert_eq!(runner.stats_snapshot().tcp_syn_received, 1);
    let current_metadata = ledger.snapshot().used(ResourceKind::MetadataBytes);
    let critical_total = budget.metadata_bytes.saturating_mul(850).div_ceil(1_000);
    let pressure_lease = ledger
        .try_acquire(
            ResourceKind::MetadataBytes,
            critical_total - current_metadata,
        )
        .unwrap();

    block_on(runner.step(2)).unwrap();
    assert_eq!(runner.pending_tcp_timers(), 0);
    let stats = runner.stats_snapshot();
    assert_eq!(stats.tcp_active_flows, 0);
    assert_eq!(stats.tcp_syn_received, 0);
    assert_eq!(stats.tcp_peak_active_flows, 1);
    assert_eq!(stats.tcp_peak_syn_received, 1);
    assert_eq!(stats.tcp_pressure_reclaimed_syns, 1);
    assert_eq!(ledger.snapshot().used(ResourceKind::TcpFlows), 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::SynReceived), 0);

    drop(pressure_lease);
    runner.abort();
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn every_observed_pressure_transition_is_counted_and_traced() {
    let (io, _) = MockIo::new(1);
    let budget = BudgetProfile::Mobile.budget();
    let ledger = ResourceLedger::new(budget).unwrap();
    let config = RunnerConfig {
        debug_trace_capacity: 8,
        ..deterministic_runner_config()
    };
    let mut runner = SingleShardRunner::new(io, Arc::clone(&ledger), config).unwrap();
    let constrained_total = budget.metadata_bytes.saturating_mul(700).div_ceil(1_000);
    let critical_total = budget.metadata_bytes.saturating_mul(850).div_ceil(1_000);

    let constrained = ledger
        .try_acquire(ResourceKind::MetadataBytes, constrained_total)
        .unwrap();
    block_on(runner.step(1)).unwrap();
    let critical = ledger
        .try_acquire(
            ResourceKind::MetadataBytes,
            critical_total - constrained_total,
        )
        .unwrap();
    block_on(runner.step(2)).unwrap();
    let exhausted = ledger
        .try_acquire(
            ResourceKind::MetadataBytes,
            budget.metadata_bytes - critical_total,
        )
        .unwrap();
    block_on(runner.step(3)).unwrap();

    drop(exhausted);
    block_on(runner.step(4)).unwrap();
    drop(critical);
    block_on(runner.step(5)).unwrap();
    drop(constrained);
    block_on(runner.step(6)).unwrap();

    let stats = runner.stats_snapshot();
    assert_eq!(stats.resources.pressure, PressureLevel::Normal);
    assert_eq!(stats.pressure_transitions, 6);
    assert_eq!(stats.pressure_constrained_entries, 2);
    assert_eq!(stats.pressure_critical_entries, 2);
    assert_eq!(stats.pressure_exhausted_entries, 1);
    let changes = runner
        .trace_snapshot()
        .events
        .into_iter()
        .filter(|event| matches!(event.kind, TraceKind::PressureChanged { .. }))
        .count();
    assert_eq!(changes, 6);
}

#[test]
fn critical_pressure_keeps_existing_udp_flows_serviceable() {
    let packet = udp_packet(40_000, b"query");
    let (mut io, _) = MockIo::new(1);
    io.push_recv(vec![packet.clone()]);
    io.push_recv(vec![packet]);
    let budget = BudgetProfile::Mobile.budget();
    let ledger = ResourceLedger::new(budget).unwrap();
    let mut runner =
        SingleShardRunner::new(io, Arc::clone(&ledger), deterministic_runner_config()).unwrap();

    let first = block_on(runner.step(1)).unwrap();
    assert_eq!(first.datagrams.len(), 1);
    let _pressure_lease = ledger
        .try_acquire(
            ResourceKind::MetadataBytes,
            budget.metadata_bytes.saturating_mul(850).div_ceil(1_000),
        )
        .unwrap();
    let second = block_on(runner.step(2)).unwrap();
    assert_eq!(second.datagrams.len(), 1);
    assert_eq!(runner.stats_snapshot().pressure_rejected_new_flows, 0);
}

#[test]
fn fragmented_udp_creates_no_flow_until_reassembly_completes() {
    let packet = udp_packet(40_001, b"abcdefghijklmnopqrstuvwx");
    let payload_len = packet.len() - 20;
    let first = ipv4_fragment(&packet, 0, 16, true);
    let second = ipv4_fragment(&packet, 16, payload_len - 16, false);
    let (mut io, _) = MockIo::new(1);
    io.push_recv(vec![second]);
    io.push_recv(vec![first]);
    let (mut runner, ledger) = runner(io);

    let incomplete = block_on(runner.step(1)).unwrap();
    assert!(incomplete.datagrams.is_empty());
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 0);
    assert_eq!(ledger.snapshot().used[ResourceKind::Fragments as usize], 1);

    let complete = block_on(runner.step(2)).unwrap();
    assert_eq!(complete.datagrams.len(), 1);
    assert_eq!(
        complete.datagrams[0].payload.to_vec(),
        b"abcdefghijklmnopqrstuvwx"
    );
    assert_eq!(ledger.snapshot().used[ResourceKind::Fragments as usize], 0);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::FragmentBytes as usize],
        0
    );
}

#[test]
fn fragment_limiter_drops_before_reassembly_budget_admission() {
    let first = ipv4_fragment(&udp_packet(30_001, b"first-fragment-payload"), 0, 16, true);
    let second = ipv4_fragment(&udp_packet(30_002, b"second-fragment-data"), 0, 16, true);
    let (mut io, _) = MockIo::new(2);
    io.push_recv(vec![first, second]);
    let config = RunnerConfig {
        fragment_burst: 1,
        fragment_refill_ms: 100,
        ..deterministic_runner_config()
    };
    let (mut runner, ledger) = runner_with_config(io, &config);

    let received = block_on(runner.step(0)).unwrap();
    assert_eq!(received.received_packets, 2);
    assert_eq!(received.dropped_packets, 1);
    let stats = runner.stats_snapshot();
    assert_eq!(stats.dropped_packets, 1);
    assert_eq!(stats.dropped_rate_limited_packets, 1);
    assert_eq!(stats.fragment_packets_rate_limited, 1);
    assert_eq!(stats.fragment_datagrams, 1);
    assert_eq!(ledger.snapshot().used[ResourceKind::Fragments as usize], 1);
    runner.abort();
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn partial_send_retains_budgeted_suffix_until_next_step() {
    let (mut io, sent_tokens) = MockIo::new(4);
    io.push_recv(vec![udp_packet(10, b"a"), udp_packet(11, b"b")]);
    io.send.push_back(IoPlan::Count(1));
    io.send.push_back(IoPlan::Count(1));
    io.would_block_recv();
    let (mut runner, ledger) = runner(io);
    let received = block_on(runner.step(1)).unwrap();
    for datagram in &received.datagrams {
        runner
            .queue_udp_reply(datagram.token, datagram.destination, b"reply", 2)
            .unwrap();
    }
    drop(received);
    let first = block_on(runner.step(3)).unwrap();
    assert_eq!(first.sent_packets, 1);
    assert_eq!(runner.pending_tx(), 1);
    assert!(ledger.snapshot().used[ResourceKind::PacketBytes as usize] > 0);
    let second = block_on(runner.step(4)).unwrap();
    assert_eq!(second.sent_packets, 1);
    assert!(second.would_block);
    assert_eq!(runner.pending_tx(), 0);
    let stats = runner.stats_snapshot();
    assert_eq!(stats.partial_sends, 1);
    assert_eq!(stats.rx_batches, 1);
    assert_eq!(stats.rx_batch_packets, 2);
    assert_eq!(stats.rx_batch_max, 2);
    assert_eq!(stats.tx_batches, 2);
    assert_eq!(stats.tx_batch_packets, 2);
    assert_eq!(stats.tx_batch_max, 1);
    assert_eq!(stats.udp_active_flows, 2);
    assert_eq!(stats.udp_peak_active_flows, 2);
    assert_eq!(stats.udp_created_flows, 2);
    assert!(stats.scheduler_rounds > 0);
    assert!(stats.scheduler_packets >= 2);
    assert_eq!(stats.scheduler_control_packets_processed, 0);
    assert!(stats.scheduler_active_flow_visits >= 2);
    assert_eq!(sent_tokens.lock().unwrap().len(), 2);
}

#[test]
fn would_block_preserves_tx_and_abort_releases_every_lease() {
    let (mut io, _) = MockIo::new(1);
    io.push_recv(vec![udp_packet(10, b"request")]);
    io.send.push_back(IoPlan::Error(io::ErrorKind::WouldBlock));
    let (mut runner, ledger) = runner(io);
    let received = block_on(runner.step(1)).unwrap();
    let datagram = &received.datagrams[0];
    runner
        .queue_udp_reply(datagram.token, datagram.destination, b"reply", 2)
        .unwrap();
    drop(received);
    let blocked = block_on(runner.step(3)).unwrap();
    assert!(blocked.would_block);
    assert_eq!(runner.pending_tx(), 1);
    runner.abort();
    assert_eq!(runner.state(), RunnerState::Closed);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn permanent_io_error_fails_runner_and_releases_state() {
    let (mut io, _) = MockIo::new(1);
    io.recv.push_back(Err(io::ErrorKind::BrokenPipe));
    let (mut runner, ledger) = runner(io);
    assert!(matches!(block_on(runner.step(1)), Err(RunnerError::Io(_))));
    assert_eq!(runner.state(), RunnerState::Failed);
    assert_eq!(runner.stats_snapshot().runner_failures, 1);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn draining_accepts_existing_flow_but_rejects_new_flow_then_closes() {
    let (mut io, _) = MockIo::new(2);
    io.push_recv(vec![udp_packet(10, b"first")]);
    io.push_recv(vec![udp_packet(10, b"existing"), udp_packet(11, b"new")]);
    let (mut runner, ledger) = runner(io);
    drop(block_on(runner.step(1)).unwrap());
    runner.shutdown(10);
    assert_eq!(runner.stats_snapshot().shutdowns, 1);
    let draining = block_on(runner.step(2)).unwrap();
    assert_eq!(draining.datagrams.len(), 1);
    assert_eq!(draining.dropped_packets, 1);
    drop(draining);
    let closed = block_on(runner.step(10)).unwrap();
    assert!(closed.datagrams.is_empty());
    assert_eq!(runner.state(), RunnerState::Closed);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn invalid_platform_count_is_a_runner_failure() {
    let (mut io, _) = MockIo::new(2);
    io.recv.push_back(Ok(RecvPlan {
        packets: vec![Packet::from_payload(
            PacketToken::new(1),
            0,
            &udp_packet(10, b"x"),
        )],
        reported: 2,
    }));
    let (mut runner, _) = runner(io);
    assert!(matches!(
        block_on(runner.step(1)),
        Err(RunnerError::InvalidIoReport(_))
    ));
    assert_eq!(runner.state(), RunnerState::Failed);
}

#[test]
fn network_reset_invalidates_reply_token() {
    let (mut io, _) = MockIo::new(1);
    io.push_recv(vec![udp_packet(10, b"x")]);
    let (mut runner, _) = runner(io);
    runner.update_mtu(1_400).unwrap();
    assert!(runner.update_mtu(1_200).is_err());
    let received = block_on(runner.step(1)).unwrap();
    let token = received.datagrams[0].token;
    let source = received.datagrams[0].destination;
    drop(received);
    runner
        .queue_udp_reply(token, source, b"queued-before-reset", 2)
        .unwrap();
    assert_eq!(runner.pending_tx(), 1);
    runner.reset_network(NetworkGeneration::new(1));
    assert_eq!(runner.pending_tx(), 0);
    let stats = runner.stats_snapshot();
    assert_eq!(stats.network_resets, 1);
    assert_eq!(stats.mtu_changes, 1);
    assert_eq!(stats.udp_active_flows, 0);
    assert_eq!(stats.udp_peak_active_flows, 1);
    assert_eq!(stats.udp_created_flows, 1);
    assert!(matches!(
        runner.queue_udp_reply(token, source, b"reply", 2),
        Err(RunnerError::Udp(UdpError::StaleToken))
    ));
}

#[test]
fn aggregate_stats_sum_current_gauges_and_shard_local_high_watermarks() {
    let (mut first_io, _) = MockIo::new(1);
    first_io.push_recv(vec![udp_packet(20, b"first")]);
    let (mut second_io, _) = MockIo::new(2);
    second_io.push_recv(vec![udp_packet(21, b"second"), udp_packet(22, b"third")]);
    let (mut first, first_ledger) = runner(first_io);
    let (mut second, _) = runner(second_io);

    block_on(first.step(1)).unwrap();
    block_on(second.step(1)).unwrap();
    let aggregate = StackStats::aggregate(
        [first.stats_snapshot(), second.stats_snapshot()],
        first_ledger.snapshot(),
    )
    .unwrap();
    assert_eq!(aggregate.udp_active_flows, 3);
    assert_eq!(aggregate.udp_peak_active_flows, 3);

    first.reset_network(NetworkGeneration::new(1));
    second.reset_network(NetworkGeneration::new(1));
    let aggregate = StackStats::aggregate(
        [first.stats_snapshot(), second.stats_snapshot()],
        first_ledger.snapshot(),
    )
    .unwrap();
    assert_eq!(aggregate.udp_active_flows, 0);
    assert_eq!(aggregate.udp_peak_active_flows, 3);
}

#[test]
fn oversized_udp_reply_is_atomically_fragmented_and_reassembles() {
    let (mut io, _) = MockIo::new(1);
    let sent = io.sent_payloads();
    io.push_recv(vec![udp_packet(10, b"x")]);
    let (mut runner, ledger) = runner(io);
    let received = block_on(runner.step(1)).unwrap();
    let token = received.datagrams[0].token;
    let source = received.datagrams[0].destination;
    drop(received);
    let payload = vec![0_u8; 1_500];
    runner.queue_udp_reply(token, source, &payload, 2).unwrap();
    assert_eq!(runner.pending_tx(), 2);
    assert_eq!(runner.stats_snapshot().outbound_fragments, 2);
    block_on(runner.step(2)).unwrap();
    block_on(runner.step(3)).unwrap();

    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|packet| packet.len() <= 1_500));
    let mut reassembler = FragmentReassembler::new(ledger, 30_000);
    let mut complete_wire = None;
    for fragment in sent.iter() {
        if let Some(packet) = reassembler.ingest(fragment, 4).unwrap() {
            complete_wire = Some(packet);
        }
    }
    let wire = complete_wire.unwrap();
    let datagram = parse_udp_datagram(parse_ip_packet(&wire, true).unwrap(), true).unwrap();
    assert_eq!(datagram.payload, payload);
}

#[test]
fn fragmented_udp_reply_admission_never_queues_a_partial_datagram() {
    let (mut io, _) = MockIo::new(1);
    io.push_recv(vec![udp_packet(10, b"x")]);
    let config = RunnerConfig {
        scheduler: sail_netstack::SchedulerConfig {
            max_queued_packets: 1,
            ..sail_netstack::SchedulerConfig::default()
        },
        ..deterministic_runner_config()
    };
    let (mut runner, _) = runner_with_config(io, &config);
    let received = block_on(runner.step(1)).unwrap();
    let token = received.datagrams[0].token;
    let source = received.datagrams[0].destination;
    drop(received);

    assert!(matches!(
        runner.queue_udp_reply(token, source, &[0; 1_500], 2),
        Err(RunnerError::TxQueueFull)
    ));
    assert_eq!(runner.pending_tx(), 0);
    assert_eq!(runner.stats_snapshot().outbound_fragments, 0);
}

#[test]
fn authenticated_packet_too_big_lowers_udp_fragment_size() {
    let (mut io, _) = MockIo::new(2);
    let request = udp_packet(40_000, b"request");
    let quoted_reply = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        SocketAddr::from((Ipv4Addr::new(10, 7, 7, 2), 40_000)),
        &[3; 1_300],
        64,
        7,
    )
    .unwrap();
    let too_big = emit_icmp_error(
        &quoted_reply,
        IcmpErrorKind::PacketTooBig { mtu: 1_200 },
        64,
    )
    .unwrap();
    io.push_recv(vec![request]);
    io.push_recv(vec![too_big]);
    let (mut runner, _) = runner(io);

    let received = block_on(runner.step(1)).unwrap();
    let token = received.datagrams[0].token;
    let source = received.datagrams[0].destination;
    drop(received);
    block_on(runner.step(2)).unwrap();
    assert_eq!(runner.stats_snapshot().pmtu_entries, 1);
    assert_eq!(runner.stats_snapshot().pmtu_learned, 1);

    runner
        .queue_udp_reply(token, source, &[9; 1_300], 3)
        .unwrap();
    assert_eq!(runner.pending_tx(), 2);
    assert_eq!(runner.stats_snapshot().outbound_fragments, 2);
}

#[test]
fn old_style_zero_mtu_feedback_uses_an_ipv4_plateau() {
    let (mut io, _) = MockIo::new(2);
    let request = udp_packet(40_000, b"request");
    let quoted_reply = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        SocketAddr::from((Ipv4Addr::new(10, 7, 7, 2), 40_000)),
        &[3; 1_472],
        64,
        7,
    )
    .unwrap();
    let too_big =
        emit_icmp_error(&quoted_reply, IcmpErrorKind::PacketTooBig { mtu: 0 }, 64).unwrap();
    io.push_recv(vec![request]);
    io.push_recv(vec![too_big]);
    let (mut runner, _) = runner(io);

    let received = block_on(runner.step(1)).unwrap();
    let token = received.datagrams[0].token;
    let source = received.datagrams[0].destination;
    drop(received);
    block_on(runner.step(2)).unwrap();
    assert_eq!(runner.stats_snapshot().pmtu_learned, 1);

    runner
        .queue_udp_reply(token, source, &[9; 1_000], 3)
        .unwrap();
    assert_eq!(runner.pending_tx(), 2);
    assert_eq!(runner.stats_snapshot().outbound_fragments, 2);
}

#[test]
fn packet_too_big_for_unmatched_udp_quote_cannot_poison_pmtu() {
    let (mut io, _) = MockIo::new(2);
    let request = udp_packet(40_000, b"request");
    let unrelated_reply = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 54)),
        SocketAddr::from((Ipv4Addr::new(10, 7, 7, 2), 40_000)),
        &[3; 1_300],
        64,
        7,
    )
    .unwrap();
    let too_big = emit_icmp_error(
        &unrelated_reply,
        IcmpErrorKind::PacketTooBig { mtu: 1_200 },
        64,
    )
    .unwrap();
    io.push_recv(vec![request]);
    io.push_recv(vec![too_big]);
    let (mut runner, _) = runner(io);

    let received = block_on(runner.step(1)).unwrap();
    let token = received.datagrams[0].token;
    let source = received.datagrams[0].destination;
    drop(received);
    block_on(runner.step(2)).unwrap();
    let stats = runner.stats_snapshot();
    assert_eq!(stats.pmtu_entries, 0);
    assert_eq!(stats.pmtu_learned, 0);
    assert_eq!(stats.pmtu_rejected, 1);

    runner
        .queue_udp_reply(token, source, &[9; 1_300], 3)
        .unwrap();
    assert_eq!(runner.pending_tx(), 1);
    assert_eq!(runner.stats_snapshot().outbound_fragments, 0);
}

#[test]
fn runner_persists_budgeted_rx_work_across_bounded_rounds() {
    let (mut io, _) = MockIo::new(2);
    io.push_recv(vec![udp_packet(10, b"one"), udp_packet(11, b"two")]);
    let config = RunnerConfig {
        scheduler: sail_netstack::SchedulerConfig {
            max_packets_per_round: 1,
            max_control_packets: 1,
            max_bytes_per_round: 65_535,
            max_time_per_round: Duration::from_secs(1),
            ..sail_netstack::SchedulerConfig::default()
        },
        ..deterministic_runner_config()
    };
    let (mut runner, ledger) = runner_with_config(io, &config);

    let first = block_on(runner.step(1)).unwrap();
    assert_eq!(first.received_packets, 2);
    assert_eq!(first.processed_packets, 1);
    assert_eq!(first.datagrams.len(), 1);
    assert_eq!(runner.pending_rx(), 1);
    assert!(ledger.snapshot().used[ResourceKind::PacketBytes as usize] > 0);
    drop(first);

    let second = block_on(runner.step(2)).unwrap();
    assert_eq!(second.received_packets, 0);
    assert_eq!(second.processed_packets, 1);
    assert_eq!(second.datagrams.len(), 1);
    assert_eq!(runner.pending_rx(), 0);
    drop(second);
    runner.abort();
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[derive(Debug)]
struct DynamicIo {
    recv: Arc<Mutex<VecDeque<Vec<u8>>>>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    max_batch: usize,
}

impl PacketIo for DynamicIo {
    fn recv(
        &mut self,
        out: &mut PacketBatch,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send {
        std::future::ready((|| -> io::Result<usize> {
            let mut recv = self.recv.lock().unwrap();
            if recv.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let mut count = 0;
            while count < self.max_batch {
                let Some(bytes) = recv.pop_front() else {
                    break;
                };
                out.push(Packet::from_payload(
                    PacketToken::new(u64::try_from(count).unwrap()),
                    0,
                    &bytes,
                ))
                .map_err(|_| io::Error::other("dynamic mock overflow"))?;
                count += 1;
            }
            Ok(count)
        })())
    }

    fn send(
        &mut self,
        packets: &PacketBatch,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send {
        std::future::ready({
            self.sent
                .lock()
                .unwrap()
                .extend(packets.iter().map(|packet| packet.payload().to_vec()));
            Ok(packets.len())
        })
    }

    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: self.max_batch,
            queue_count: 1,
            headroom: 4,
            vectored: false,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}

fn tcp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
) -> Vec<u8> {
    emit_tcp_segment(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(acknowledgment),
            flags,
            window: 4_096,
        },
        &[],
        64,
        1,
    )
    .unwrap()
}

fn tcp_packet_with_window(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    window: u16,
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
        &[],
        64,
        1,
    )
    .unwrap()
}

fn tcp_packet_with_options(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    options: &[u8],
) -> Vec<u8> {
    emit_tcp_segment_with_options(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(acknowledgment),
            flags,
            window: 4_096,
        },
        options,
        &[],
        64,
        1,
    )
    .unwrap()
}

fn last_sent_tcp(sent: &Arc<Mutex<Vec<Vec<u8>>>>) -> (TcpSegmentMeta, Vec<u8>) {
    let packet = sent.lock().unwrap().last().unwrap().clone();
    let segment = parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true).unwrap();
    (segment.meta, segment.payload.to_vec())
}

#[test]
fn max_batch_one_tcp_handshake_emits_control_and_accept_event() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 1, 0, 2), 40_000));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 1, 0, 1), 443));
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 1,
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut runner =
        SingleShardRunner::new(io, Arc::clone(&ledger), deterministic_runner_config()).unwrap();

    let syn = block_on(runner.step(1)).unwrap();
    assert_eq!(syn.processed_packets, 1);
    assert!(syn.tcp_events.is_empty());
    assert_eq!(syn.tcp_timers.len(), 1);
    assert_eq!(runner.pending_tcp_timers(), 1);
    assert_eq!(runner.pending_tx(), 1);
    assert!(ledger.snapshot().used(ResourceKind::ControlPacketBytes) > 0);

    let flushed = block_on(runner.step(2)).unwrap();
    assert_eq!(flushed.sent_packets, 1);
    assert!(flushed.would_block);
    let (syn_ack, _) = last_sent_tcp(&sent);
    assert!(syn_ack.flags.contains(TcpFlags::SYN));
    assert!(syn_ack.flags.contains(TcpFlags::ACK));

    recv.lock().unwrap().push_back(tcp_packet(
        source,
        destination,
        101,
        syn_ack.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
    ));
    let accepted = block_on(runner.step(3)).unwrap();
    let token = match accepted.tcp_events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected TCP events: {events:?}"),
    };
    assert_eq!(runner.pending_tcp_timers(), 0);
    runner.accept_tcp(token).unwrap();
    assert_eq!(ledger.snapshot().used[ResourceKind::TcpFlows as usize], 1);

    recv.lock().unwrap().push_back(
        emit_tcp_segment(
            source,
            destination,
            SendControl {
                sequence: SeqNumber::new(101),
                acknowledgment: SeqNumber::new(syn_ack.sequence.wrapping_add(1).get()),
                flags: TcpFlags::ACK,
                window: 4_096,
            },
            b"hello",
            64,
            2,
        )
        .unwrap(),
    );
    let readable = block_on(runner.step(4)).unwrap();
    assert_eq!(
        readable.tcp_events,
        [TcpEvent::Readable { token, bytes: 5 }]
    );
    assert_eq!(runner.read_tcp(token, 5).unwrap(), b"hello");

    let write = runner.write_tcp(token, b"world").unwrap();
    assert_eq!(write.timers.len(), 1);
    assert_eq!(runner.pending_tcp_timers(), 1);
    // The outbound payload carries the delayed ACK; receiver SWS avoidance
    // therefore needs only this one packet rather than a tiny window update.
    assert_eq!(runner.pending_tx(), 1);
    let flushed = block_on(runner.step(5)).unwrap();
    assert_eq!(flushed.sent_packets, 1);
    assert_eq!(last_sent_tcp(&sent).1, b"world");

    let retransmission = block_on(runner.step(1_000)).unwrap();
    assert_eq!(retransmission.sent_packets, 1);
    assert_eq!(retransmission.tcp_timers.len(), 1);
    assert_eq!(last_sent_tcp(&sent).1, b"world");

    recv.lock().unwrap().push_back(tcp_packet(
        source,
        destination,
        106,
        syn_ack.sequence.wrapping_add(6).get(),
        TcpFlags::ACK,
    ));
    block_on(runner.step(1_001)).unwrap();
    assert_eq!(
        ledger.snapshot().used[ResourceKind::TcpPayloadBytes as usize],
        RunnerConfig::default().tcp.receive_credit_bytes
    );
    assert_eq!(runner.pending_tcp_timers(), 0);
    let sent_before_stale_deadline = sent.lock().unwrap().len();
    let stale = block_on(runner.step(3_000)).unwrap();
    assert_eq!(stale.sent_packets, 0);
    assert_eq!(sent.lock().unwrap().len(), sent_before_stale_deadline);

    runner.abort();
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn runner_emits_timestamped_ack_for_paws_rejection_without_failing() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 1, 0, 3), 40_001));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 1, 0, 1), 443));
    let mut syn_options = vec![8, 10];
    syn_options.extend_from_slice(&100_u32.to_be_bytes());
    syn_options.extend_from_slice(&0_u32.to_be_bytes());
    syn_options.extend_from_slice(&[1, 1]);
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet_with_options(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
        &syn_options,
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 1,
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut runner = SingleShardRunner::new(io, ledger, deterministic_runner_config()).unwrap();

    block_on(runner.step(1_000)).unwrap();
    block_on(runner.step(1_001)).unwrap();
    let (syn_ack, syn_ack_timestamp) = {
        let packet = sent.lock().unwrap().last().unwrap().clone();
        let segment = parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true).unwrap();
        (segment.meta, segment.options.timestamps.unwrap().0)
    };
    let server_next = syn_ack.sequence.wrapping_add(1).get();

    let mut ack_options = vec![8, 10];
    ack_options.extend_from_slice(&101_u32.to_be_bytes());
    ack_options.extend_from_slice(&syn_ack_timestamp.to_be_bytes());
    ack_options.extend_from_slice(&[1, 1]);
    recv.lock().unwrap().push_back(tcp_packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &ack_options,
    ));
    let accepted = block_on(runner.step(1_100)).unwrap();
    let token = match accepted.tcp_events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected TCP events: {events:?}"),
    };
    runner.accept_tcp(token).unwrap();

    let mut stale_options = vec![8, 10];
    stale_options.extend_from_slice(&99_u32.to_be_bytes());
    stale_options.extend_from_slice(&syn_ack_timestamp.to_be_bytes());
    stale_options.extend_from_slice(&[1, 1]);
    recv.lock().unwrap().push_back(tcp_packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &stale_options,
    ));
    let rejected = block_on(runner.step(1_200)).unwrap();
    assert!(rejected.tcp_events.is_empty());
    assert_eq!(runner.state(), RunnerState::Running);
    assert_eq!(runner.pending_tx(), 1);
    let stats = runner.stats_snapshot();
    assert_eq!(stats.tcp_paws_rejections, 1);
    assert_eq!(stats.tcp_timestamp_missing_drops, 0);
    assert_eq!(stats.tcp_defensive_acks_sent, 1);

    block_on(runner.step(1_201)).unwrap();
    let packet = sent.lock().unwrap().last().unwrap().clone();
    let paws_ack = parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true).unwrap();
    assert_eq!(paws_ack.meta.acknowledgment, Some(SeqNumber::new(101)));
    // Our clock ran 200 ms since the SYN-ACK, from the flow's own offset.
    let (value, echo) = paws_ack.options.timestamps.unwrap();
    assert_eq!(value.wrapping_sub(syn_ack_timestamp), 200);
    assert_eq!(echo, 100);
}

#[test]
fn runner_rejects_accept_overflow_and_cancels_embryonic_timer() {
    let source1 = SocketAddr::from((Ipv4Addr::new(10, 1, 0, 2), 40_000));
    let source2 = SocketAddr::from((Ipv4Addr::new(10, 1, 0, 3), 40_001));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 1, 0, 1), 443));
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet(
        source1,
        destination,
        100,
        0,
        TcpFlags::SYN,
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 2,
    };
    let mut budget = BudgetProfile::Mobile.budget();
    budget.max_accept_queue = 1;
    let ledger = ResourceLedger::new(budget).unwrap();
    let config = RunnerConfig {
        tcp: sail_netstack::TcpTableConfig {
            accept_overflow_policy: AcceptOverflowPolicy::RejectWithReset,
            ..sail_netstack::TcpTableConfig::default()
        },
        ..deterministic_runner_config()
    };
    let mut runner = SingleShardRunner::new(io, Arc::clone(&ledger), config).unwrap();

    block_on(runner.step(1)).unwrap();
    block_on(runner.step(2)).unwrap();
    let (syn_ack1, _) = last_sent_tcp(&sent);
    recv.lock()
        .unwrap()
        .push_back(tcp_packet(source2, destination, 200, 0, TcpFlags::SYN));
    block_on(runner.step(3)).unwrap();
    block_on(runner.step(4)).unwrap();
    let (syn_ack2, _) = last_sent_tcp(&sent);
    recv.lock().unwrap().push_back(tcp_packet(
        source1,
        destination,
        101,
        syn_ack1.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
    ));
    recv.lock().unwrap().push_back(tcp_packet(
        source2,
        destination,
        201,
        syn_ack2.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
    ));
    let overflow = block_on(runner.step(5)).unwrap();
    assert!(matches!(
        overflow.tcp_events.as_slice(),
        [TcpEvent::Accepted(_)]
    ));
    assert_eq!(overflow.tcp_cancelled_timers.len(), 2);
    assert_eq!(runner.pending_tcp_timers(), 0);
    assert_eq!(runner.stats_snapshot().tcp_accept_overflow_rejections, 1);
    assert_eq!(runner.stats_snapshot().tcp_active_flows, 1);
    assert_eq!(ledger.snapshot().used[ResourceKind::TcpFlows as usize], 1);

    block_on(runner.step(6)).unwrap();
    let sent_before_deadline = sent.lock().unwrap().len();
    let (reset, _) = last_sent_tcp(&sent);
    assert_eq!(reset.flags, TcpFlags::RST);
    block_on(runner.step(5_000)).unwrap();
    assert_eq!(sent.lock().unwrap().len(), sent_before_deadline);
}

#[test]
fn runner_queues_multiple_sack_recovery_packets_with_batch_size_one() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 2, 0, 2), 40_001));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 2, 0, 1), 443));
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet_with_options(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
        &[4, 2, 1, 1],
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 1,
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut config = deterministic_runner_config();
    config.tcp.max_segment_payload_bytes = 200;
    let mut runner = SingleShardRunner::new(io, ledger, config).unwrap();

    block_on(runner.step(1)).unwrap();
    block_on(runner.step(2)).unwrap();
    let (syn_ack, _) = last_sent_tcp(&sent);
    let server_next = syn_ack.sequence.wrapping_add(1).get();
    recv.lock().unwrap().push_back(tcp_packet(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
    ));
    let accepted = block_on(runner.step(3)).unwrap();
    let token = match accepted.tcp_events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected TCP events: {events:?}"),
    };
    runner.accept_tcp(token).unwrap();
    for byte in 0_u8..6 {
        runner.write_tcp(token, &[byte; 100]).unwrap();
    }
    for now_ms in 4..10 {
        assert_eq!(block_on(runner.step(now_ms)).unwrap().sent_packets, 1);
    }

    let sack_left = server_next.wrapping_add(300);
    let sack_right = server_next.wrapping_add(600);
    let mut options = vec![5, 10];
    options.extend_from_slice(&sack_left.to_be_bytes());
    options.extend_from_slice(&sack_right.to_be_bytes());
    options.extend_from_slice(&[1, 1]);
    recv.lock().unwrap().push_back(tcp_packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &options,
    ));
    let recovery = block_on(runner.step(10)).unwrap();
    assert_eq!(recovery.processed_packets, 1);
    assert_eq!(runner.pending_tx(), 3);
    assert_eq!(runner.stats_snapshot().tcp_sack_retransmitted_segments, 3);
    assert_eq!(block_on(runner.step(11)).unwrap().sent_packets, 1);
    assert_eq!(runner.pending_tx(), 2);
}

#[test]
fn runner_schedules_persist_probe_and_cancels_it_when_window_reopens() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 1, 1, 2), 40_001));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 1, 1, 1), 443));
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 1,
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let config = RunnerConfig {
        tcp: sail_netstack::TcpTableConfig {
            persist_initial_ms: 10,
            persist_max_ms: 40,
            ..sail_netstack::TcpTableConfig::default()
        },
        ..deterministic_runner_config()
    };
    let mut runner = SingleShardRunner::new(io, ledger, config).unwrap();

    block_on(runner.step(1)).unwrap();
    block_on(runner.step(2)).unwrap();
    let (syn_ack, _) = last_sent_tcp(&sent);
    let server_next = syn_ack.sequence.wrapping_add(1).get();
    recv.lock().unwrap().push_back(tcp_packet_with_window(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        0,
    ));
    let accepted = block_on(runner.step(3)).unwrap();
    let token = match accepted.tcp_events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected TCP events: {events:?}"),
    };
    runner.accept_tcp(token).unwrap();

    let buffered = runner.write_tcp(token, b"world").unwrap();
    assert!(buffered.outgoing.is_empty());
    assert_eq!(runner.pending_tx(), 0);
    assert_eq!(runner.pending_tcp_timers(), 1);

    let probe = block_on(runner.step(13)).unwrap();
    assert_eq!(probe.sent_packets, 1);
    assert_eq!(last_sent_tcp(&sent).1, b"w");
    assert_eq!(runner.pending_tcp_timers(), 1);
    assert_eq!(runner.stats_snapshot().tcp_zero_window_writes, 1);
    assert_eq!(runner.stats_snapshot().tcp_persist_probes, 1);

    recv.lock().unwrap().push_back(tcp_packet_with_window(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        4_096,
    ));
    block_on(runner.step(14)).unwrap();
    assert_eq!(runner.pending_tcp_timers(), 1);
    let flushed = block_on(runner.step(15)).unwrap();
    assert_eq!(flushed.sent_packets, 1);
    assert_eq!(last_sent_tcp(&sent).1, b"world");
}

#[test]
fn runner_keepalive_probe_times_out_an_unresponsive_idle_flow() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 1, 2, 2), 40_002));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 1, 2, 1), 443));
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 1,
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let config = RunnerConfig {
        tcp: sail_netstack::TcpTableConfig {
            keepalive_idle_ms: Some(10),
            keepalive_interval_ms: 5,
            keepalive_max_probes: 1,
            ..sail_netstack::TcpTableConfig::default()
        },
        ..deterministic_runner_config()
    };
    let mut runner = SingleShardRunner::new(io, Arc::clone(&ledger), config).unwrap();

    block_on(runner.step(1)).unwrap();
    block_on(runner.step(2)).unwrap();
    let (syn_ack, _) = last_sent_tcp(&sent);
    recv.lock().unwrap().push_back(tcp_packet(
        source,
        destination,
        101,
        syn_ack.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
    ));
    let accepted = block_on(runner.step(3)).unwrap();
    let token = match accepted.tcp_events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected TCP events: {events:?}"),
    };
    runner.accept_tcp(token).unwrap();
    assert_eq!(runner.pending_tcp_timers(), 1);

    let probe = block_on(runner.step(20)).unwrap();
    assert_eq!(probe.sent_packets, 1);
    let (probe, payload) = last_sent_tcp(&sent);
    assert_eq!(
        probe.sequence,
        syn_ack.sequence.wrapping_add(1).wrapping_add(usize::MAX)
    );
    assert!(payload.is_empty());
    assert_eq!(runner.stats_snapshot().tcp_keepalive_probes, 1);

    let timeout = block_on(runner.step(30)).unwrap();
    assert!(timeout.tcp_events.contains(&TcpEvent::Closed(token)));
    assert_eq!(runner.pending_tcp_timers(), 0);
    assert_eq!(runner.stats_snapshot().tcp_keepalive_timeouts, 1);
    assert_eq!(ledger.snapshot().used[ResourceKind::TcpFlows as usize], 0);
}

/// A device that is idle between the packets a test queues: `recv` stays
/// pending, as a real TUN does, instead of failing with `WouldBlock`.
struct IdleIo(DynamicIo);

impl PacketIo for IdleIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        if self.0.recv.lock().unwrap().is_empty() {
            return poll_fn(|_| Poll::Pending).await;
        }
        self.0.recv(out).await
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        self.0.send(packets).await
    }

    fn capabilities(&self) -> PacketCapabilities {
        self.0.capabilities()
    }
}

#[test]
fn a_timer_event_survives_a_step_dropped_while_the_device_is_idle() {
    // Found by the kernel soak: adapters drop a step on every timer tick,
    // and a step that fired a timer and then waited on an idle device lost
    // the timer's events, so the adapter never forgot the closed flow.
    use futures::FutureExt;

    let source = SocketAddr::from((Ipv4Addr::new(10, 1, 2, 3), 40_003));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 1, 2, 1), 443));
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = IdleIo(DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 1,
    });
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let config = RunnerConfig {
        tcp: sail_netstack::TcpTableConfig {
            keepalive_idle_ms: Some(10),
            keepalive_interval_ms: 5,
            keepalive_max_probes: 1,
            ..sail_netstack::TcpTableConfig::default()
        },
        ..deterministic_runner_config()
    };
    let mut runner = SingleShardRunner::new(io, Arc::clone(&ledger), config).unwrap();

    for now in 1..=3 {
        let _ = runner.step(now).now_or_never();
    }
    let (syn_ack, _) = last_sent_tcp(&sent);
    recv.lock().unwrap().push_back(tcp_packet(
        source,
        destination,
        101,
        syn_ack.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
    ));
    let mut handshake = Vec::new();
    for now in 4..=6 {
        if let Some(outcome) = runner.step(now).now_or_never() {
            handshake.extend(outcome.unwrap().tcp_events);
        }
    }
    let token = match handshake.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected TCP events: {events:?}"),
    };
    runner.accept_tcp(token).unwrap();
    // The first poll sends the keepalive probe and then waits on the idle
    // device; the probe was already handed over.
    let _ = runner.step(20).now_or_never();
    assert_eq!(runner.stats_snapshot().tcp_keepalive_probes, 1);

    // The keepalive timeout closes the flow. Poll each step once and drop
    // it, as an adapter racing a timer tick does.
    let mut events = Vec::new();
    for now in [30, 31, 32] {
        if let Some(outcome) = runner.step(now).now_or_never() {
            events.extend(outcome.unwrap().tcp_events);
        }
    }
    assert!(events.contains(&TcpEvent::Closed(token)), "{events:?}");
    assert_eq!(ledger.snapshot().used[ResourceKind::TcpFlows as usize], 0);
}

#[test]
fn authenticated_packet_too_big_lowers_live_tcp_write_limit() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 3, 0, 2), 40_000));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 3, 0, 1), 443));
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 1,
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut runner = SingleShardRunner::new(io, ledger, deterministic_runner_config()).unwrap();

    block_on(runner.step(1)).unwrap();
    block_on(runner.step(2)).unwrap();
    let (syn_ack, _) = last_sent_tcp(&sent);
    recv.lock().unwrap().push_back(tcp_packet(
        source,
        destination,
        101,
        syn_ack.sequence.wrapping_add(1).get(),
        TcpFlags::ACK,
    ));
    let accepted = block_on(runner.step(3)).unwrap();
    let token = match accepted.tcp_events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected TCP events: {events:?}"),
    };
    runner.accept_tcp(token).unwrap();
    assert_eq!(runner.tcp_write_limit(token).unwrap(), 536);

    let quoted = tcp_packet(
        destination,
        source,
        syn_ack.sequence.get(),
        101,
        TcpFlags::ACK,
    );
    let too_big = emit_icmp_error(&quoted, IcmpErrorKind::PacketTooBig { mtu: 100 }, 64).unwrap();
    recv.lock().unwrap().push_back(too_big);
    block_on(runner.step(4)).unwrap();

    assert_eq!(runner.stats_snapshot().pmtu_learned, 1);
    assert_eq!(runner.tcp_write_limit(token).unwrap(), 60);
}

#[test]
fn tcp_state_does_not_advance_when_control_packet_credit_is_unavailable() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 2, 0, 2), 40_000));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 2, 0, 1), 443));
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
    )])));
    let io = DynamicIo {
        recv,
        sent: Arc::new(Mutex::new(Vec::new())),
        max_batch: 1,
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut runner =
        SingleShardRunner::new(io, Arc::clone(&ledger), deterministic_runner_config()).unwrap();
    let reservation = ledger
        .try_acquire(
            ResourceKind::ControlPacketBytes,
            ledger.budget().control_packet_bytes,
        )
        .unwrap();

    let outcome = block_on(runner.step(1)).unwrap();
    assert_eq!(outcome.dropped_packets, 1);
    assert!(outcome.tcp_events.is_empty());
    assert_eq!(runner.pending_tx(), 0);
    let snapshot = ledger.snapshot();
    assert_eq!(runner.stats_snapshot().dropped_resource_packets, 1);
    assert_eq!(snapshot.used[ResourceKind::TcpFlows as usize], 0);
    assert_eq!(snapshot.used[ResourceKind::SynReceived as usize], 0);
    assert_eq!(snapshot.used[ResourceKind::PacketBytes as usize], 0);
    assert_eq!(
        snapshot.used[ResourceKind::ControlPacketBytes as usize],
        ledger.budget().control_packet_bytes
    );
    drop(reservation);
}

#[test]
fn exhausted_data_packet_pool_preserves_existing_tcp_control_progress() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 2, 1, 2), 40_000));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 2, 1, 1), 443));
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 1,
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut runner =
        SingleShardRunner::new(io, Arc::clone(&ledger), deterministic_runner_config()).unwrap();

    block_on(runner.step(1)).unwrap();
    block_on(runner.step(2)).unwrap();
    let (syn_ack, _) = last_sent_tcp(&sent);
    let server_next = syn_ack.sequence.wrapping_add(1).get();
    recv.lock().unwrap().push_back(tcp_packet(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
    ));
    let accepted = block_on(runner.step(3)).unwrap();
    let token = match accepted.tcp_events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected TCP events: {events:?}"),
    };
    runner.accept_tcp(token).unwrap();

    let reservation = ledger
        .try_acquire(ResourceKind::PacketBytes, ledger.budget().packet_bytes)
        .unwrap();
    recv.lock().unwrap().push_back(tcp_packet(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK.union(TcpFlags::FIN),
    ));
    let half_close = block_on(runner.step(4)).unwrap();
    assert!(half_close
        .tcp_events
        .contains(&TcpEvent::PeerHalfClosed(token)));
    assert_eq!(runner.pending_tx(), 1);
    assert!(ledger.snapshot().used(ResourceKind::ControlPacketBytes) > 0);

    let send_outcome = block_on(runner.step(5)).unwrap();
    assert_eq!(send_outcome.sent_packets, 1);
    let (ack, payload) = last_sent_tcp(&sent);
    assert!(ack.flags.contains(TcpFlags::ACK));
    assert!(payload.is_empty());
    assert_eq!(
        ledger.snapshot().used(ResourceKind::PacketBytes),
        ledger.budget().packet_bytes
    );
    drop(reservation);
}

/// A segment of ours carries up to 40 option bytes, timestamps and SACK
/// blocks, so on IPv6 a full one needs 100 bytes of headers. With room for
/// only 84, a full write failed once the connection had SACK blocks to
/// report, and the application saw the connection die.
#[test]
fn a_full_segment_with_sack_blocks_fits_the_mtu_on_ipv6() {
    let source = SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 40_000));
    let destination = SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 443));
    let mtu = 1_284;
    let mut config = deterministic_runner_config();
    config.mtu = mtu;
    config.tcp.max_segment_payload_bytes = mtu - TCP_MAX_HEADER_BYTES;
    let timestamps = |value: u32, echo: u32| {
        let mut options = vec![1, 1, 8, 10];
        options.extend_from_slice(&value.to_be_bytes());
        options.extend_from_slice(&echo.to_be_bytes());
        options
    };
    // MSS 1440, SACK permitted, timestamps, window scale 7.
    let mut syn_options = vec![2, 4, 0x05, 0xa0, 4, 2];
    syn_options.extend_from_slice(&timestamps(100, 0)[2..]);
    syn_options.extend_from_slice(&[1, 3, 3, 7]);
    let recv = Arc::new(Mutex::new(VecDeque::from([tcp_packet_with_options(
        source,
        destination,
        100,
        0,
        TcpFlags::SYN,
        &syn_options,
    )])));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let io = DynamicIo {
        recv: Arc::clone(&recv),
        sent: Arc::clone(&sent),
        max_batch: 8,
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut runner = SingleShardRunner::new(io, ledger, config).unwrap();
    block_on(runner.step(1_000)).unwrap();
    block_on(runner.step(1_001)).unwrap();
    let packet = sent.lock().unwrap().last().unwrap().clone();
    let syn_ack = parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true).unwrap();
    let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
    let echo = syn_ack.options.timestamps.unwrap().0;

    recv.lock().unwrap().push_back(tcp_packet_with_options(
        source,
        destination,
        101,
        server_next,
        TcpFlags::ACK,
        &timestamps(101, echo),
    ));
    let accepted = block_on(runner.step(1_010)).unwrap();
    block_on(runner.step(1_011)).unwrap();
    let token = match accepted.tcp_events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected TCP events: {events:?}"),
    };
    runner.accept_tcp(token).unwrap();

    // Three segments past a hole: our segments now report three SACK blocks.
    for (index, gap) in [20_u32, 40, 60].into_iter().enumerate() {
        let segment = emit_tcp_segment_with_options(
            source,
            destination,
            SendControl {
                sequence: SeqNumber::new(101 + gap),
                acknowledgment: SeqNumber::new(server_next),
                flags: TcpFlags::ACK,
                window: 4_096,
            },
            &timestamps(102 + u32::try_from(index).unwrap(), echo),
            &[7; 10],
            64,
            1,
        )
        .unwrap();
        recv.lock().unwrap().push_back(segment);
        block_on(runner.step(1_020 + 2 * u64::try_from(index).unwrap())).unwrap();
        block_on(runner.step(1_021 + 2 * u64::try_from(index).unwrap())).unwrap();
    }

    let full = vec![0x42; config.tcp.max_segment_payload_bytes];
    runner.write_tcp(token, &full).unwrap();
    block_on(runner.step(1_100)).unwrap();
    block_on(runner.step(1_101)).unwrap();
    let packet = sent.lock().unwrap().last().unwrap().clone();
    assert_eq!(packet.len(), mtu);
    let written = parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true).unwrap();
    assert_eq!(written.payload, full.as_slice());
    assert_eq!(written.options.sack_blocks.iter().flatten().count(), 3);
    assert!(sent
        .lock()
        .unwrap()
        .iter()
        .all(|packet| packet.len() <= mtu));
}
