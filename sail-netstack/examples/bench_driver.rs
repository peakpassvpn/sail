use std::collections::VecDeque;
use std::env;
use std::hint::black_box;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use futures::executor::block_on;
use sail_netstack::{
    emit_tcp_segment, emit_udp_packet, parse_ip_packet, parse_tcp_segment, parse_udp_datagram,
    AppEvent, BudgetProfile, ChecksumCapabilities, FlowId, NetworkGeneration, Packet, PacketBatch,
    PacketCapabilities, PacketIo, PacketToken, ResourceKind, ResourceLedger, Scheduler,
    SchedulerConfig, SendControl, SeqNumber, ShardedPacketIo, ShardedPacketIoControl, TcpAction,
    TcpEvent, TcpFlags, TcpSegmentMeta, TcpTable, TcpTableConfig, TcpTcb, TimerEvent, UdpTable,
    WorkClass,
};

const PAYLOAD_BYTES: usize = 1_200;
const SHARD_PACKETS_PER_FLOW: usize = 16;

#[derive(Debug)]
struct Record {
    workload: &'static str,
    duration_ns: u128,
    packets: u64,
    bytes: u64,
    latencies_ns: Vec<u128>,
    drops: u64,
    retransmits: u64,
    goodput_bytes: u64,
    notes: &'static str,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let workload = arguments
        .next()
        .ok_or("usage: bench_driver <workload> <iterations> <profile>")?;
    let iterations = arguments
        .next()
        .ok_or("missing iterations")?
        .parse::<usize>()
        .map_err(|error| format!("invalid iterations: {error}"))?;
    if iterations == 0 {
        return Err("iterations must be non-zero".to_owned());
    }
    let profile = parse_profile(
        arguments
            .next()
            .ok_or("missing profile (ios-single/router-single/desktop/linux-server)")?
            .as_str(),
    )?;
    let shards = arguments
        .next()
        .map_or(Ok(1), |value| value.parse::<usize>())
        .map_err(|error| format!("invalid shard count: {error}"))?;
    if arguments.next().is_some() {
        return Err("too many arguments".to_owned());
    }

    let record = match workload.as_str() {
        "packet-io" => packet_io(iterations)?,
        "udp-flows" => udp_flows(iterations, profile)?,
        "tcp-bulk-wire" => tcp_bulk_wire(iterations)?,
        "tcp-short-wire" => tcp_short_wire(iterations)?,
        "tcp-connection-churn" => tcp_connection_churn(iterations, profile)?,
        "tcp-loss-recovery" => tcp_loss_recovery(iterations)?,
        "mixed-flow-fairness" => mixed_flow_fairness(iterations)?,
        "shard-routing" => shard_routing(iterations, profile, shards)?,
        "memory-pressure" => memory_pressure(iterations, profile)?,
        _ => return Err(format!("unknown workload: {workload}")),
    };
    emit_record(&record);
    Ok(())
}

fn parse_profile(value: &str) -> Result<BudgetProfile, String> {
    match value {
        "ios-single" => Ok(BudgetProfile::Mobile),
        "router-single" => Ok(BudgetProfile::Router),
        "desktop" => Ok(BudgetProfile::Desktop),
        "linux-server" => Ok(BudgetProfile::Server),
        _ => Err(format!("unknown profile: {value}")),
    }
}

fn endpoints() -> (SocketAddr, SocketAddr) {
    (
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 40_000)),
        SocketAddr::from((Ipv4Addr::new(198, 51, 100, 2), 443)),
    )
}

fn packet_io(iterations: usize) -> Result<Record, String> {
    let (source, destination) = endpoints();
    let payload = vec![0x5a; PAYLOAD_BYTES];
    let packet =
        emit_udp_packet(source, destination, &payload, 64, 1).map_err(|error| error.to_string())?;
    let mut latencies = Vec::with_capacity(iterations);
    let started = Instant::now();
    for _ in 0..iterations {
        let operation = Instant::now();
        let ip = parse_ip_packet(black_box(&packet), true).map_err(|error| error.to_string())?;
        let udp = parse_udp_datagram(ip, true).map_err(|error| error.to_string())?;
        black_box(udp.payload);
        latencies.push(operation.elapsed().as_nanos());
    }
    Ok(record(
        "packet-io",
        started,
        iterations,
        packet.len(),
        latencies,
        (
            0,
            iterations.saturating_mul(payload.len()),
            "IPv4+UDP checksum parse hot path",
        ),
    ))
}

fn udp_flows(iterations: usize, profile: BudgetProfile) -> Result<Record, String> {
    let ledger = ResourceLedger::new(profile.budget()).map_err(|error| error.to_string())?;
    let mut table = UdpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        60_000,
        2_048,
    );
    let (_, destination) = endpoints();
    let payload = [0x33; 64];
    let mut latencies = Vec::with_capacity(iterations);
    let mut packets = 0_usize;
    let mut bytes = 0_usize;
    let mut drops = 0_u64;
    let started = Instant::now();
    for index in 0..iterations {
        let source = unique_source(index)?;
        let packet = emit_udp_packet(source, destination, &payload, 64, 1)
            .map_err(|error| error.to_string())?;
        let operation = Instant::now();
        match table.ingest(
            &packet,
            u64::try_from(index).map_err(|error| error.to_string())?,
        ) {
            Ok(ingress) => {
                black_box(ingress);
                packets += 1;
                bytes += packet.len();
            }
            Err(_) => drops += 1,
        }
        latencies.push(operation.elapsed().as_nanos());
    }
    let snapshot = ledger.snapshot();
    Ok(Record {
        workload: "udp-flows",
        duration_ns: started.elapsed().as_nanos(),
        packets: to_u64(packets),
        bytes: to_u64(bytes),
        latencies_ns: latencies,
        drops,
        retransmits: 0,
        goodput_bytes: to_u64(packets.saturating_mul(payload.len())),
        notes: if snapshot.denied == 0 {
            "unique-flow admission with hard resource accounting"
        } else {
            "unique-flow admission reached a configured hard budget"
        },
    })
}

fn tcp_bulk_wire(iterations: usize) -> Result<Record, String> {
    let (source, destination) = endpoints();
    let payload = vec![0xa5; PAYLOAD_BYTES];
    let control = SendControl {
        sequence: SeqNumber::new(10_000),
        acknowledgment: SeqNumber::new(20_000),
        flags: TcpFlags::ACK,
        window: 32_768,
    };
    let mut latencies = Vec::with_capacity(iterations);
    let mut bytes = 0_usize;
    let started = Instant::now();
    for index in 0..iterations {
        let operation = Instant::now();
        let packet = emit_tcp_segment(
            source,
            destination,
            control,
            black_box(&payload),
            64,
            u16::try_from(index % usize::from(u16::MAX)).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let ip = parse_ip_packet(&packet, true).map_err(|error| error.to_string())?;
        let segment = parse_tcp_segment(ip, true).map_err(|error| error.to_string())?;
        black_box(segment.payload);
        bytes += packet.len();
        latencies.push(operation.elapsed().as_nanos());
    }
    Ok(record(
        "tcp-bulk-wire",
        started,
        iterations,
        bytes / iterations,
        latencies,
        (
            0,
            iterations.saturating_mul(payload.len()),
            "TCP data emit+parse with IPv4 and transport checksums",
        ),
    ))
}

fn tcp_short_wire(iterations: usize) -> Result<Record, String> {
    let (source, destination) = endpoints();
    let controls = [
        SendControl {
            sequence: SeqNumber::new(1_000),
            acknowledgment: SeqNumber::new(0),
            flags: TcpFlags::SYN,
            window: 32_768,
        },
        SendControl {
            sequence: SeqNumber::new(8_000),
            acknowledgment: SeqNumber::new(1_001),
            flags: TcpFlags::SYN.union(TcpFlags::ACK),
            window: 32_768,
        },
        SendControl {
            sequence: SeqNumber::new(1_001),
            acknowledgment: SeqNumber::new(8_001),
            flags: TcpFlags::ACK,
            window: 32_768,
        },
    ];
    let mut latencies = Vec::with_capacity(iterations);
    let mut bytes = 0_usize;
    let started = Instant::now();
    for _ in 0..iterations {
        let operation = Instant::now();
        for control in controls {
            let packet = emit_tcp_segment(source, destination, control, &[], 64, 1)
                .map_err(|error| error.to_string())?;
            let ip = parse_ip_packet(&packet, true).map_err(|error| error.to_string())?;
            black_box(parse_tcp_segment(ip, true).map_err(|error| error.to_string())?);
            bytes += packet.len();
        }
        latencies.push(operation.elapsed().as_nanos());
    }
    Ok(Record {
        workload: "tcp-short-wire",
        duration_ns: started.elapsed().as_nanos(),
        packets: to_u64(iterations.saturating_mul(controls.len())),
        bytes: to_u64(bytes),
        latencies_ns: latencies,
        drops: 0,
        retransmits: 0,
        goodput_bytes: 0,
        notes: "three-segment handshake wire encode+decode",
    })
}

fn tcp_connection_churn(iterations: usize, profile: BudgetProfile) -> Result<Record, String> {
    const MAX_LATENCY_SAMPLES: usize = 100_000;
    const PACKETS_PER_CONNECTION: usize = 7;

    let ledger = ResourceLedger::new(profile.budget()).map_err(|error| error.to_string())?;
    let mut table = TcpTable::new(
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        TcpTableConfig::default(),
    );
    let (source, destination) = endpoints();
    let sample_every = iterations.div_ceil(MAX_LATENCY_SAMPLES).max(1);
    let mut latencies = Vec::with_capacity(iterations.min(MAX_LATENCY_SAMPLES));
    let mut bytes = 0_usize;
    let started = Instant::now();

    for index in 0..iterations {
        let operation = Instant::now();
        bytes = bytes.saturating_add(churn_one_connection(
            &mut table,
            source,
            destination,
            index,
        )?);

        if index % sample_every == 0 {
            latencies.push(operation.elapsed().as_nanos());
        }
        if index % 1_024 == 1_023 {
            ensure_ledger_released(&ledger)?;
        }
    }

    ensure_ledger_released(&ledger)?;
    let stats = table.stats();
    if stats.active_flows != 0
        || stats.time_wait != 0
        || stats.created_flows != to_u64(iterations)
        || stats.closed_flows != to_u64(iterations)
    {
        return Err(format!(
            "TCP churn lifecycle counters did not converge: {stats:?}"
        ));
    }
    Ok(Record {
        workload: "tcp-connection-churn",
        duration_ns: started.elapsed().as_nanos(),
        packets: to_u64(iterations.saturating_mul(PACKETS_PER_CONNECTION)),
        bytes: to_u64(bytes),
        latencies_ns: latencies,
        drops: 0,
        retransmits: 0,
        goodput_bytes: 0,
        notes: "complete handshake, accept, graceful close and TIME-WAIT reclamation; latency sampled at up to 100k connections",
    })
}

fn churn_one_connection(
    table: &mut TcpTable,
    source: SocketAddr,
    destination: SocketAddr,
    index: usize,
) -> Result<usize, String> {
    let now_ms = churn_now_ms(index);
    let client_isn = 100_u32.wrapping_add(u32::try_from(index).unwrap_or(u32::MAX).wrapping_mul(2));
    let syn = tcp_control_packet(
        source,
        destination,
        SeqNumber::new(client_isn),
        SeqNumber::new(0),
        TcpFlags::SYN,
        1,
    )?;
    let syn_result = table
        .ingest_with_policy_at(&syn, true, now_ms)
        .map_err(|error| error.to_string())?;
    let syn_ack_wire = syn_result
        .outgoing
        .first()
        .ok_or("TCP churn SYN did not produce SYN-ACK")?;
    let syn_ack = parse_tcp_segment(
        parse_ip_packet(syn_ack_wire, true).map_err(|error| error.to_string())?,
        true,
    )
    .map_err(|error| error.to_string())?;
    let server_next = syn_ack.meta.sequence.wrapping_add(1);
    let client_next = SeqNumber::new(client_isn).wrapping_add(1);

    let ack = tcp_control_packet(
        source,
        destination,
        client_next,
        server_next,
        TcpFlags::ACK,
        2,
    )?;
    let accepted = table
        .ingest_with_policy_at(&ack, true, now_ms)
        .map_err(|error| error.to_string())?;
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        _ => return Err("TCP churn handshake did not enter accept queue".to_owned()),
    };
    table.accept(token).map_err(|error| error.to_string())?;

    let close = table.close(token).map_err(|error| error.to_string())?;
    let fin_wire = close
        .outgoing
        .first()
        .ok_or("TCP churn close did not produce FIN")?;
    let fin = parse_tcp_segment(
        parse_ip_packet(fin_wire, true).map_err(|error| error.to_string())?,
        true,
    )
    .map_err(|error| error.to_string())?;
    let server_closed = fin.meta.sequence.wrapping_add(1);
    let fin_ack = tcp_control_packet(
        source,
        destination,
        client_next,
        server_closed,
        TcpFlags::ACK,
        3,
    )?;
    table
        .ingest_with_policy_at(&fin_ack, true, now_ms)
        .map_err(|error| error.to_string())?;
    let peer_fin = tcp_control_packet(
        source,
        destination,
        client_next,
        server_closed,
        TcpFlags::ACK.union(TcpFlags::FIN),
        4,
    )?;
    let finished = table
        .ingest_with_policy_at(&peer_fin, true, now_ms)
        .map_err(|error| error.to_string())?;
    let final_ack = finished
        .outgoing
        .first()
        .ok_or("TCP churn peer FIN did not produce ACK")?;
    let expired = table
        .on_timer_at(
            token,
            TimerEvent::TimeWaitExpired,
            now_ms.saturating_add(30_000),
        )
        .map_err(|error| error.to_string())?;
    if expired.events.as_slice() != [TcpEvent::Closed(token)] {
        return Err("TCP churn TIME-WAIT did not close the flow".to_owned());
    }
    Ok([
        syn.len(),
        syn_ack_wire.len(),
        ack.len(),
        fin_wire.len(),
        fin_ack.len(),
        peer_fin.len(),
        final_ack.len(),
    ]
    .into_iter()
    .sum())
}

fn churn_now_ms(index: usize) -> u64 {
    u64::try_from(index.saturating_add(1))
        .unwrap_or(u64::MAX)
        .saturating_mul(30_001)
}

fn tcp_control_packet(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: SeqNumber,
    acknowledgment: SeqNumber,
    flags: TcpFlags,
    identification: u16,
) -> Result<Vec<u8>, String> {
    emit_tcp_segment(
        source,
        destination,
        SendControl {
            sequence,
            acknowledgment,
            flags,
            window: 32_768,
        },
        &[],
        64,
        identification,
    )
    .map_err(|error| error.to_string())
}

fn ensure_ledger_released(ledger: &ResourceLedger) -> Result<(), String> {
    let snapshot = ledger.snapshot();
    if snapshot.total_bytes != 0 || snapshot.used.iter().any(|used| *used != 0) {
        return Err(format!(
            "resource ledger did not return to baseline: {snapshot:?}"
        ));
    }
    Ok(())
}

fn tcp_loss_recovery(iterations: usize) -> Result<Record, String> {
    const MSS: usize = 1_200;
    const FLIGHT_BYTES: usize = 4_380;
    let syn = TcpSegmentMeta {
        sequence: SeqNumber::new(100),
        acknowledgment: None,
        flags: TcpFlags::SYN,
        window: 64_000,
        payload_len: 0,
    };
    let final_ack = TcpSegmentMeta {
        sequence: SeqNumber::new(101),
        acknowledgment: Some(SeqNumber::new(10_001)),
        flags: TcpFlags::ACK,
        window: 64_000,
        payload_len: 0,
    };
    let mut latencies = Vec::with_capacity(iterations);
    let mut retransmits = 0_u64;
    let started = Instant::now();
    for _ in 0..iterations {
        let operation = Instant::now();
        let (mut tcb, _) = TcpTcb::from_syn_with_mss(syn, SeqNumber::new(10_000), 64 * 1_024, MSS)
            .map_err(|error| error.to_string())?;
        black_box(
            tcb.on_segment(final_ack)
                .map_err(|error| error.to_string())?,
        );
        for amount in [MSS, MSS, MSS, FLIGHT_BYTES - 3 * MSS] {
            black_box(
                tcb.on_app_event(AppEvent::Send(amount))
                    .map_err(|error| error.to_string())?,
            );
        }
        for _ in 0..3 {
            let actions = tcb
                .on_segment(final_ack)
                .map_err(|error| error.to_string())?;
            retransmits = retransmits.saturating_add(u64::from(
                actions
                    .iter()
                    .any(|action| matches!(action, TcpAction::RetransmitPayload(_))),
            ));
            black_box(actions);
        }
        latencies.push(operation.elapsed().as_nanos());
    }
    Ok(Record {
        workload: "tcp-loss-recovery",
        duration_ns: started.elapsed().as_nanos(),
        packets: to_u64(iterations.saturating_mul(10)),
        bytes: to_u64(iterations.saturating_mul(FLIGHT_BYTES)),
        latencies_ns: latencies,
        drops: to_u64(iterations),
        retransmits,
        goodput_bytes: to_u64(iterations.saturating_mul(FLIGHT_BYTES)),
        notes: "NewReno core trace: full initial window, three duplicate ACKs, fast retransmit",
    })
}

fn mixed_flow_fairness(iterations: usize) -> Result<Record, String> {
    let config = SchedulerConfig {
        max_time_per_round: std::time::Duration::from_mins(1),
        ..SchedulerConfig::default()
    };
    let mut scheduler = Scheduler::new(config).map_err(|error| error.to_string())?;
    let mut latencies = Vec::with_capacity(iterations);
    let mut packets = 0_usize;
    let mut bytes = 0_usize;
    let started = Instant::now();
    for _ in 0..iterations {
        let operation = Instant::now();
        for flow_index in 0_u64..64 {
            let flow = FlowId::new(flow_index);
            let size = if flow_index % 8 == 0 {
                64
            } else {
                PAYLOAD_BYTES
            };
            scheduler
                .enqueue(WorkClass::Data { flow, weight: 1 }, size, size)
                .map_err(|_| "scheduler admission failed")?;
        }
        let stats = scheduler.run_round(|class, value| {
            black_box((class, value));
        });
        packets += stats.packets;
        bytes += stats.bytes;
        latencies.push(operation.elapsed().as_nanos());
    }
    Ok(Record {
        workload: "mixed-flow-fairness",
        duration_ns: started.elapsed().as_nanos(),
        packets: to_u64(packets),
        bytes: to_u64(bytes),
        latencies_ns: latencies,
        drops: 0,
        retransmits: 0,
        goodput_bytes: to_u64(bytes),
        notes: "64-flow byte-DRR with interleaved 64-byte and 1200-byte packets",
    })
}

fn unique_source(index: usize) -> Result<SocketAddr, String> {
    const PORTS: usize = 64_512;
    let port = 1_024 + u16::try_from(index % PORTS).map_err(|error| error.to_string())?;
    let address_index = index / PORTS;
    let third = u8::try_from(address_index % 256).map_err(|error| error.to_string())?;
    let second = u8::try_from((address_index / 256) % 256).map_err(|error| error.to_string())?;
    Ok(SocketAddr::from((
        Ipv4Addr::new(10, second, third, 1),
        port,
    )))
}

#[derive(Debug)]
struct BenchQueueIo {
    inbound: VecDeque<(PacketToken, Arc<[u8]>)>,
    queue_count: usize,
}

impl PacketIo for BenchQueueIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        let Some((token, wire)) = self.inbound.pop_front() else {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        };
        out.push(Packet::from_payload(token, 0, &wire))
            .map_err(|_| io::Error::other("benchmark packet batch overflow"))?;
        Ok(1)
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        Ok(packets.len())
    }

    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: 1,
            queue_count: self.queue_count,
            headroom: 0,
            vectored: false,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}

struct ShardBenchSetup {
    adapters: Vec<ShardedPacketIo<BenchQueueIo>>,
    control: ShardedPacketIoControl,
    expected: Vec<usize>,
    wire_bytes: usize,
}

fn prepare_shard_bench(
    iterations: usize,
    profile: BudgetProfile,
    shard_count: usize,
) -> Result<ShardBenchSetup, String> {
    let ledger = ResourceLedger::new(profile.budget()).map_err(|error| error.to_string())?;
    let (_, destination) = endpoints();
    let payload = vec![0x6d; PAYLOAD_BYTES];
    let queues = (0..shard_count)
        .map(|_| BenchQueueIo {
            inbound: VecDeque::new(),
            queue_count: shard_count,
        })
        .collect::<Vec<_>>();
    let estimated_wire_bytes = iterations.saturating_mul(PAYLOAD_BYTES + 28);
    let flow_count = iterations.div_ceil(SHARD_PACKETS_PER_FLOW).max(1);
    let config = SchedulerConfig {
        max_time_per_round: Duration::from_mins(1),
        max_queued_packets: iterations.max(1),
        max_queued_bytes: estimated_wire_bytes.max(65_535),
        max_active_flows: flow_count,
        ..SchedulerConfig::default()
    };
    let (mut adapters, control) =
        ShardedPacketIo::group(queues, ledger, NetworkGeneration::new(1), config)
            .map_err(|error| error.to_string())?;
    let mut expected = vec![0_usize; shard_count];
    let mut wire_bytes = 0_usize;
    for flow_index in 0..flow_count {
        let packet = emit_udp_packet(unique_source(flow_index)?, destination, &payload, 64, 1)
            .map_err(|error| error.to_string())?;
        let owner = usize::from(
            control
                .preferred_owner(&packet)
                .map_err(|error| error.to_string())?
                .get(),
        );
        let packet: Arc<[u8]> = packet.into();
        let flow_start = flow_index.saturating_mul(SHARD_PACKETS_PER_FLOW);
        let flow_end = flow_start
            .saturating_add(SHARD_PACKETS_PER_FLOW)
            .min(iterations);
        for index in flow_start..flow_end {
            let input = if shard_count > 1 && index % 10 == 0 {
                (owner + 1) % shard_count
            } else {
                owner
            };
            expected[owner] = expected[owner].saturating_add(1);
            wire_bytes = wire_bytes.saturating_add(packet.len());
            adapters[input].inner_mut().inbound.push_back((
                PacketToken::new(u64::try_from(index).map_err(|error| error.to_string())?),
                Arc::clone(&packet),
            ));
        }
    }
    Ok(ShardBenchSetup {
        adapters,
        control,
        expected,
        wire_bytes,
    })
}

fn shard_routing(
    iterations: usize,
    profile: BudgetProfile,
    shard_count: usize,
) -> Result<Record, String> {
    let setup = prepare_shard_bench(iterations, profile, shard_count)?;
    let started = Instant::now();
    let deadline = started + Duration::from_mins(1);
    let worker_latencies = thread::scope(|scope| {
        let mut workers = Vec::with_capacity(setup.adapters.len());
        for (mut adapter, expected) in setup.adapters.into_iter().zip(setup.expected) {
            workers.push(scope.spawn(move || {
                let mut latencies = Vec::new();
                let mut completed = 0_usize;
                while (completed < expected || !adapter.inner_mut().inbound.is_empty())
                    && Instant::now() < deadline
                {
                    let operation = Instant::now();
                    let mut batch = PacketBatch::with_limit(1);
                    match block_on(adapter.recv(&mut batch)) {
                        Ok(1) => {
                            black_box(batch.pop_front().expect("one packet was reported"));
                            completed += 1;
                            latencies.push(operation.elapsed().as_nanos());
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::yield_now();
                        }
                        Ok(count) => panic!("unexpected benchmark receive count: {count}"),
                        Err(error) => panic!("benchmark receive failed: {error}"),
                    }
                }
                (latencies, completed)
            }));
        }
        workers
            .into_iter()
            .map(|worker| worker.join().expect("shard benchmark worker panicked"))
            .collect::<Vec<_>>()
    });
    let packets = worker_latencies
        .iter()
        .map(|(_, completed)| *completed)
        .sum::<usize>();
    if packets != iterations {
        return Err(format!(
            "sharded PacketIo processed {packets}/{iterations} packets before timeout"
        ));
    }
    let latencies = worker_latencies
        .into_iter()
        .flat_map(|(latencies, _)| latencies)
        .collect();
    let stats = setup.control.stats().map_err(|error| error.to_string())?;
    Ok(Record {
        workload: "shard-routing",
        duration_ns: started.elapsed().as_nanos(),
        packets: to_u64(packets),
        bytes: to_u64(setup.wire_bytes),
        latencies_ns: latencies,
        drops: stats.dropped_packets,
        retransmits: 0,
        goodput_bytes: to_u64(packets.saturating_mul(PAYLOAD_BYTES)),
        notes: "multi-thread ShardedPacketIo, 16 packets/flow, 90% owner affinity and 10% bounded forwarding",
    })
}

fn memory_pressure(iterations: usize, profile: BudgetProfile) -> Result<Record, String> {
    let ledger = ResourceLedger::new(profile.budget()).map_err(|error| error.to_string())?;
    let chunk = 4_096_usize;
    let mut leases = Vec::new();
    let mut latencies = Vec::with_capacity(iterations);
    let mut drops = 0_u64;
    let started = Instant::now();
    for _ in 0..iterations {
        let operation = Instant::now();
        match ledger.try_acquire(ResourceKind::PacketBytes, chunk) {
            Ok(lease) => leases.push(lease),
            Err(_) => drops += 1,
        }
        latencies.push(operation.elapsed().as_nanos());
    }
    let admitted = leases.len();
    let peak = ledger.snapshot().peaks[ResourceKind::PacketBytes as usize];
    drop(leases);
    if ledger.snapshot().total_bytes != 0 {
        return Err("resource leases did not return to baseline".to_owned());
    }
    Ok(Record {
        workload: "memory-pressure",
        duration_ns: started.elapsed().as_nanos(),
        packets: to_u64(admitted),
        bytes: to_u64(peak),
        latencies_ns: latencies,
        drops,
        retransmits: 0,
        goodput_bytes: 0,
        notes: "packet-byte budget admission through exhaustion and full release",
    })
}

fn record(
    workload: &'static str,
    started: Instant,
    iterations: usize,
    packet_bytes: usize,
    latencies_ns: Vec<u128>,
    result: (u64, usize, &'static str),
) -> Record {
    let (drops, goodput_bytes, notes) = result;
    Record {
        workload,
        duration_ns: started.elapsed().as_nanos(),
        packets: to_u64(iterations),
        bytes: to_u64(iterations.saturating_mul(packet_bytes)),
        latencies_ns,
        drops,
        retransmits: 0,
        goodput_bytes: to_u64(goodput_bytes),
        notes,
    }
}

fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn percentile(mut samples: Vec<u128>, numerator: usize, denominator: usize) -> u128 {
    samples.sort_unstable();
    let index = samples
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .saturating_sub(1)
        .min(samples.len() - 1);
    samples[index]
}

fn emit_record(record: &Record) {
    let p50 = percentile(record.latencies_ns.clone(), 50, 100);
    let p99 = percentile(record.latencies_ns.clone(), 99, 100);
    println!(
        "workload={}\tduration_ns={}\tpackets={}\tbytes={}\tp50_ns={}\tp99_ns={}\tdrops={}\tretransmits={}\tgoodput_bytes={}\tnotes={}",
        record.workload,
        record.duration_ns,
        record.packets,
        record.bytes,
        p50,
        p99,
        record.drops,
        record.retransmits,
        record.goodput_bytes,
        record.notes
    );
}
