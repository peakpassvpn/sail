use std::collections::VecDeque;
use std::future::{poll_fn, Future};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;

use futures::executor::block_on;
use futures::task::{waker, ArcWake};
use sail_netstack::{
    classify_packet, emit_tcp_segment, emit_udp_packet, fragment_outbound_ip_packet, BudgetProfile,
    ChecksumCapabilities, IpEndpoint, NetworkGeneration, Packet, PacketBatch, PacketCapabilities,
    PacketIo, PacketToken, ResourceBudget, ResourceKind, ResourceLedger, RunnerConfig, RunnerError,
    SchedulerConfig, SendControl, SeqNumber, ShardId, ShardedPacketIo, SingleShardRunner, TcpFlags,
    TransportProtocol,
};

#[derive(Clone, Debug)]
struct QueueHandle(Arc<Mutex<VecDeque<Vec<u8>>>>);

impl QueueHandle {
    fn inject(&self, packet: Vec<u8>) {
        self.0.lock().unwrap().push_back(packet);
    }
}

#[derive(Debug)]
struct QueueIo {
    inbound: QueueHandle,
    queue_count: usize,
    next_token: u64,
}

#[derive(Debug, Default)]
struct PendingState {
    inbound: VecDeque<Vec<u8>>,
    waker: Option<Waker>,
}

#[derive(Clone, Debug)]
struct PendingHandle(Arc<Mutex<PendingState>>);

impl PendingHandle {
    fn inject(&self, packet: Vec<u8>) {
        let wake = {
            let mut state = self.0.lock().unwrap();
            state.inbound.push_back(packet);
            state.waker.take()
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

#[derive(Debug)]
struct PendingQueueIo {
    state: PendingHandle,
    queue_count: usize,
    next_token: u64,
}

impl PendingQueueIo {
    fn new(queue_count: usize) -> (Self, PendingHandle) {
        let state = PendingHandle(Arc::new(Mutex::new(PendingState::default())));
        (
            Self {
                state: state.clone(),
                queue_count,
                next_token: 0,
            },
            state,
        )
    }
}

impl PacketIo for PendingQueueIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        poll_fn(|context| {
            let mut state = self.state.0.lock().unwrap();
            if let Some(payload) = state.inbound.pop_front() {
                out.push(Packet::from_payload(
                    PacketToken::new(self.next_token),
                    0,
                    &payload,
                ))
                .unwrap();
                self.next_token = self.next_token.wrapping_add(1);
                Poll::Ready(Ok(1))
            } else {
                state.waker = Some(context.waker().clone());
                Poll::Pending
            }
        })
        .await
    }

    fn send(
        &mut self,
        packets: &PacketBatch,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send {
        std::future::ready(Ok(packets.len()))
    }

    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: 8,
            queue_count: self.queue_count,
            headroom: 0,
            vectored: true,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}

#[derive(Debug, Default)]
struct WakeCounter(AtomicUsize);

impl ArcWake for WakeCounter {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl QueueIo {
    fn new(queue_count: usize) -> (Self, QueueHandle) {
        let handle = QueueHandle(Arc::new(Mutex::new(VecDeque::new())));
        (
            Self {
                inbound: handle.clone(),
                queue_count,
                next_token: 0,
            },
            handle,
        )
    }
}

impl PacketIo for QueueIo {
    fn recv(
        &mut self,
        out: &mut PacketBatch,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send {
        std::future::ready({
            let mut inbound = self.inbound.0.lock().unwrap();
            let mut received = 0;
            while out.len() < out.limit() {
                let Some(payload) = inbound.pop_front() else {
                    break;
                };
                out.push(Packet::from_payload(
                    PacketToken::new(self.next_token),
                    0,
                    &payload,
                ))
                .unwrap();
                self.next_token = self.next_token.wrapping_add(1);
                received += 1;
            }
            if received == 0 {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                Ok(received)
            }
        })
    }

    fn send(
        &mut self,
        packets: &PacketBatch,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send {
        std::future::ready(Ok(packets.len()))
    }

    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: 8,
            queue_count: self.queue_count,
            headroom: 0,
            vectored: true,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}

fn udp(payload: &[u8]) -> Vec<u8> {
    emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40_000)),
        SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)),
        payload,
        64,
        1,
    )
    .unwrap()
}

fn tcp_ack() -> Vec<u8> {
    emit_tcp_segment(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40_000)),
        SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 443)),
        SendControl {
            sequence: SeqNumber::new(101),
            acknowledgment: SeqNumber::new(201),
            flags: TcpFlags::ACK,
            window: 32_000,
        },
        &[],
        64,
        1,
    )
    .unwrap()
}

fn receive(io: &mut impl PacketIo) -> io::Result<PacketBatch> {
    let mut batch = PacketBatch::with_limit(8);
    block_on(io.recv(&mut batch)).map(|_| batch)
}

#[test]
fn mismatched_platform_queue_forwards_only_to_the_stable_owner() {
    let (first, first_input) = QueueIo::new(2);
    let (second, second_input) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        Arc::clone(&ledger),
        NetworkGeneration::new(7),
        SchedulerConfig::default(),
    )
    .unwrap();
    assert_eq!(adapters[0].capabilities().queue_count, 1);
    assert_eq!(adapters[1].capabilities().queue_count, 1);

    first_input.inject(udp(b"first"));
    let first_result = receive(&mut adapters[0]);
    let owner = usize::from(first_result.is_err());
    if owner == 1 {
        assert_eq!(first_result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(receive(&mut adapters[1]).unwrap().len(), 1);
    }

    let second_wire = udp(b"second");
    if owner == 0 {
        second_input.inject(second_wire.clone());
        assert_eq!(
            receive(&mut adapters[1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    } else {
        first_input.inject(second_wire.clone());
        assert_eq!(
            receive(&mut adapters[0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    assert_eq!(
        ledger.snapshot().used[sail_netstack::ResourceKind::PacketBytes as usize],
        second_wire.len()
    );
    let mut delivered = receive(&mut adapters[owner]).unwrap();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered.pop_front().unwrap().payload(), second_wire);
    assert_eq!(
        ledger.snapshot().used[sail_netstack::ResourceKind::PacketBytes as usize],
        0
    );

    let stats = control.stats().unwrap();
    assert_eq!(stats.directory_entries, 1);
    assert!(stats.forwarded_routes >= 1);
    assert_eq!(stats.queued_packets, 0);
    assert!(stats.drained_packets >= 1);
}

#[test]
fn flow_directory_stays_bounded_across_many_short_flows() {
    // Found by the 24-hour kernel soak: closed flows never leave the
    // directory, which grew without bound until metadata pressure.
    let (first, first_input) = QueueIo::new(2);
    let (second, _) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let scheduler = SchedulerConfig {
        max_active_flows: 64,
        ..SchedulerConfig::default()
    };
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        scheduler,
    )
    .unwrap();
    let mut delivered = 0_usize;
    for port in 0..4_096_u16 {
        let wire = emit_udp_packet(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 10_000 + port)),
            SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)),
            b"short",
            64,
            1,
        )
        .unwrap();
        first_input.inject(wire);
        for adapter in &mut adapters {
            if let Ok(batch) = receive(adapter) {
                delivered += batch.len();
            }
        }
    }
    assert_eq!(delivered, 4_096);
    let stats = control.stats().unwrap();
    assert!(stats.directory_entries <= 64, "{stats:?}");
    assert_eq!(stats.pressure_cache_reclaims, 0);
    let metadata = ledger
        .snapshot()
        .used(sail_netstack::ResourceKind::MetadataBytes);
    assert!(metadata <= 3 * 64 * 64, "metadata grew to {metadata} bytes");
}

#[test]
fn fragment_classifier_keeps_every_piece_on_one_synthetic_flow() {
    let wire = udp(&vec![0x5a; 256]);
    let fragments = fragment_outbound_ip_packet(&wire, 80, 0x1234_5678).unwrap();
    assert!(fragments.len() > 2);
    let generation = NetworkGeneration::new(9);
    let first = classify_packet(&fragments[0], generation).unwrap();
    assert!(matches!(
        first.endpoint.protocol,
        TransportProtocol::Fragment(17)
    ));
    assert!(fragments
        .iter()
        .all(|fragment| classify_packet(fragment, generation).unwrap() == first));
}

#[test]
fn group_accepts_platform_handles_that_each_report_one_local_queue() {
    let (first, _) = QueueIo::new(1);
    let (second, _) = QueueIo::new(1);
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        ledger,
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    assert_eq!(adapters.len(), 2);
    assert_eq!(adapters[0].shard(), ShardId::new(0));
    assert_eq!(adapters[1].shard(), ShardId::new(1));
    let owner = control.preferred_owner(&udp(b"hint")).unwrap();
    assert!(owner == ShardId::new(0) || owner == ShardId::new(1));
    assert_eq!(control.stats().unwrap().directory_entries, 0);
}

#[test]
fn each_flow_has_one_owner_and_opened_flows_are_routed_back_to_it() {
    let queues = (0..4).map(|_| QueueIo::new(4).0).collect();
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (adapters, control) = ShardedPacketIo::group(
        queues,
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let remote = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53));
    for port in 40_000..40_064 {
        let local = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), port));
        let endpoint = IpEndpoint {
            source: remote,
            destination: local,
            protocol: TransportProtocol::Udp,
        };
        let owners = adapters
            .iter()
            .filter(|adapter| adapter.owns_flow(endpoint))
            .map(ShardedPacketIo::shard)
            .collect::<Vec<_>>();
        assert_eq!(owners, [control.owner(endpoint).unwrap()]);
        let reply = emit_udp_packet(remote, local, b"reply", 64, 1).unwrap();
        assert_eq!(control.preferred_owner(&reply).unwrap(), owners[0]);
    }

    let mut runners = adapters
        .into_iter()
        .enumerate()
        .map(|(index, adapter)| {
            SingleShardRunner::new(
                adapter,
                Arc::clone(&ledger),
                RunnerConfig {
                    generation: NetworkGeneration::new(1),
                    shard: ShardId::new(u16::try_from(index).unwrap()),
                    ..RunnerConfig::default()
                },
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let any_port = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 0));
    for (index, runner) in runners.iter_mut().enumerate() {
        let shard = ShardId::new(u16::try_from(index).unwrap());
        for _ in 0..4 {
            let (_, local) = runner.originate_udp(any_port, remote, b"q", 0).unwrap();
            let reply = emit_udp_packet(remote, local, b"reply", 64, 1).unwrap();
            assert_eq!(control.preferred_owner(&reply).unwrap(), shard);
        }
    }

    // An explicit port is opened only by the shard its replies reach.
    let local = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 41_000));
    let owner = control
        .owner(IpEndpoint {
            source: remote,
            destination: local,
            protocol: TransportProtocol::Tcp,
        })
        .unwrap();
    for (index, runner) in runners.iter_mut().enumerate() {
        let opened = runner.connect_tcp(local, remote);
        if ShardId::new(u16::try_from(index).unwrap()) == owner {
            assert!(opened.is_ok());
        } else {
            assert!(matches!(opened, Err(RunnerError::ForeignFlow)));
        }
    }
}

#[test]
fn repeated_flow_uses_the_input_shards_bounded_route_cache() {
    let (first, first_input) = QueueIo::new(2);
    let (second, second_input) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        ledger,
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let wire = udp(b"cached");
    let owner = usize::from(control.preferred_owner(&wire).unwrap().get());
    let inputs = [first_input, second_input];
    for _ in 0..3 {
        inputs[owner].inject(wire.clone());
    }
    assert_eq!(receive(&mut adapters[owner]).unwrap().len(), 3);

    let stats = control.stats().unwrap();
    assert_eq!(stats.directory_entries, 1);
    assert_eq!(stats.local_cache_entries, 1);
    assert_eq!(stats.local_cache_misses, 1);
    assert_eq!(stats.local_cache_hits, 2);
}

#[test]
fn reset_immediately_releases_directory_and_local_cache_leases() {
    let (first, first_input) = QueueIo::new(2);
    let (second, second_input) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let wire = udp(b"reset-cache");
    let owner = usize::from(control.preferred_owner(&wire).unwrap().get());
    [first_input, second_input][owner].inject(wire);
    assert_eq!(receive(&mut adapters[owner]).unwrap().len(), 1);
    assert_eq!(control.stats().unwrap().local_cache_entries, 1);
    assert!(ledger.snapshot().used[ResourceKind::MetadataBytes as usize] > 0);

    control.reset_network(NetworkGeneration::new(2)).unwrap();
    let stats = control.stats().unwrap();
    assert_eq!(stats.directory_entries, 0);
    assert_eq!(stats.local_cache_entries, 0);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        0
    );
}

#[test]
fn critical_pressure_reclaims_and_suppresses_optional_routing_caches() {
    let (first, first_input) = QueueIo::new(2);
    let (second, second_input) = QueueIo::new(2);
    let budget = ResourceBudget {
        metadata_bytes: 1_024,
        ..BudgetProfile::Mobile.budget()
    };
    let ledger = ResourceLedger::new(budget).unwrap();
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let wire = udp(b"pressure-cache");
    let owner = usize::from(control.preferred_owner(&wire).unwrap().get());
    let inputs = [first_input, second_input];

    inputs[owner].inject(wire.clone());
    assert_eq!(receive(&mut adapters[owner]).unwrap().len(), 1);
    assert_eq!(control.stats().unwrap().directory_entries, 1);
    assert_eq!(control.stats().unwrap().local_cache_entries, 1);

    let pressure = ledger
        .try_acquire(ResourceKind::MetadataBytes, 750)
        .unwrap();
    inputs[owner].inject(wire.clone());
    assert_eq!(receive(&mut adapters[owner]).unwrap().len(), 1);
    let stats = control.stats().unwrap();
    assert_eq!(stats.directory_entries, 0);
    assert_eq!(stats.local_cache_entries, 0);
    assert_eq!(stats.pressure_cache_reclaims, 1);
    assert_eq!(stats.pressure_reclaimed_directory_entries, 1);
    assert_eq!(stats.pressure_reclaimed_local_cache_entries, 1);
    assert_eq!(stats.local_cache_admission_failures, 0);

    inputs[owner].inject(wire.clone());
    assert_eq!(receive(&mut adapters[owner]).unwrap().len(), 1);
    assert_eq!(control.stats().unwrap().directory_entries, 0);
    assert_eq!(control.stats().unwrap().local_cache_entries, 0);

    drop(pressure);
    inputs[owner].inject(wire);
    assert_eq!(receive(&mut adapters[owner]).unwrap().len(), 1);
    let stats = control.stats().unwrap();
    assert_eq!(stats.directory_entries, 1);
    assert_eq!(stats.local_cache_entries, 1);
    assert_eq!(stats.pressure_cache_reclaims, 1);
}

#[test]
fn route_cache_budget_exhaustion_falls_back_without_dropping_local_input() {
    let (first, first_input) = QueueIo::new(2);
    let (second, second_input) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let wire = udp(b"stateless-fallback");
    let owner = usize::from(control.preferred_owner(&wire).unwrap().get());
    let reservation = ledger
        .try_acquire(ResourceKind::MetadataBytes, ledger.budget().metadata_bytes)
        .unwrap();
    [first_input, second_input][owner].inject(wire);
    assert_eq!(receive(&mut adapters[owner]).unwrap().len(), 1);
    let stats = control.stats().unwrap();
    assert_eq!(stats.directory_entries, 0);
    assert_eq!(stats.local_cache_entries, 0);
    assert_eq!(stats.pressure_cache_reclaims, 1);
    assert_eq!(stats.directory_admission_failures, 0);
    assert_eq!(stats.local_cache_admission_failures, 0);
    assert_eq!(stats.dropped_packets, 0);
    drop(reservation);
}

#[test]
fn route_cache_capacity_replaces_oldest_without_dropping_local_input() {
    let (first, first_input) = QueueIo::new(2);
    let (second, second_input) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let config = SchedulerConfig {
        max_active_flows: 1,
        ..SchedulerConfig::default()
    };
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        ledger,
        NetworkGeneration::new(1),
        config,
    )
    .unwrap();
    let destination = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53));
    let mut by_owner: [Vec<Vec<u8>>; 2] = std::array::from_fn(|_| Vec::new());
    for port in 40_000..40_100 {
        let wire = emit_udp_packet(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), port)),
            destination,
            b"capacity-fallback",
            64,
            port,
        )
        .unwrap();
        let owner = usize::from(control.preferred_owner(&wire).unwrap().get());
        by_owner[owner].push(wire);
        if by_owner[owner].len() == 2 {
            break;
        }
    }
    let owner = by_owner
        .iter()
        .position(|packets| packets.len() == 2)
        .unwrap();
    let inputs = [first_input, second_input];
    let first_wire = by_owner[owner][0].clone();
    for wire in by_owner[owner].drain(..) {
        inputs[owner].inject(wire);
    }
    assert_eq!(receive(&mut adapters[owner]).unwrap().len(), 2);
    inputs[owner].inject(first_wire);
    assert_eq!(receive(&mut adapters[owner]).unwrap().len(), 1);
    let stats = control.stats().unwrap();
    // With one flow allowed, each directory stripe keeps one entry. The two
    // flows share an owner, so their hashes share a parity, and one time in
    // 32 they share a stripe too; the second then replaces the first.
    assert!(
        (1..=2).contains(&stats.directory_entries),
        "{} directory entries",
        stats.directory_entries
    );
    assert_eq!(stats.local_cache_entries, 1);
    assert_eq!(stats.local_cache_misses, 3);
    assert_eq!(stats.local_cache_admission_failures, 0);
    assert_eq!(stats.dropped_packets, 0);
}

#[test]
fn reset_discards_forwarded_packets_and_changes_directory_generation() {
    let (first, first_input) = QueueIo::new(2);
    let (second, _) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        ledger,
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    for port in 1..=64 {
        first_input.inject(
            emit_udp_packet(
                SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), port)),
                SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)),
                b"x",
                64,
                port,
            )
            .unwrap(),
        );
    }
    let _ = receive(&mut adapters[0]);
    assert!(control.stats().unwrap().directory_entries > 0);
    control.reset_network(NetworkGeneration::new(2)).unwrap();
    let stats = control.stats().unwrap();
    assert_eq!(stats.directory_entries, 0);
    assert_eq!(stats.queued_packets, 0);
}

#[test]
fn forwarding_drops_without_leaking_when_packet_budget_is_exhausted() {
    let (first, first_input) = QueueIo::new(2);
    let (second, second_input) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let wire = udp(b"budgeted-forward");
    let owner = usize::from(control.preferred_owner(&wire).unwrap().get());
    let non_owner = 1 - owner;
    let reservation = ledger
        .try_acquire(
            sail_netstack::ResourceKind::PacketBytes,
            ledger.budget().packet_bytes,
        )
        .unwrap();
    [first_input, second_input][non_owner].inject(wire);
    assert_eq!(
        receive(&mut adapters[non_owner]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let stats = control.stats().unwrap();
    assert_eq!(stats.forwarded_routes, 1);
    assert_eq!(stats.enqueued_packets, 0);
    assert_eq!(stats.dropped_packets, 1);
    assert_eq!(stats.queued_packets, 0);
    drop(reservation);
    assert_eq!(
        ledger.snapshot().used[sail_netstack::ResourceKind::PacketBytes as usize],
        0
    );
}

#[test]
fn forwarded_tcp_control_uses_reserve_when_data_packets_are_exhausted() {
    let (first, first_input) = QueueIo::new(2);
    let (second, second_input) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let wire = tcp_ack();
    let owner = usize::from(control.preferred_owner(&wire).unwrap().get());
    let non_owner = 1 - owner;
    let reservation = ledger
        .try_acquire(ResourceKind::PacketBytes, ledger.budget().packet_bytes)
        .unwrap();

    [first_input, second_input][non_owner].inject(wire.clone());
    assert_eq!(
        receive(&mut adapters[non_owner]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        ledger.snapshot().used(ResourceKind::ControlPacketBytes),
        wire.len()
    );
    let stats = control.stats().unwrap();
    assert_eq!(stats.enqueued_packets, 1);
    assert_eq!(stats.forwarded_control_packets, 1);
    assert_eq!(stats.dropped_packets, 0);

    let mut delivered = receive(&mut adapters[owner]).unwrap();
    assert_eq!(delivered.pop_front().unwrap().payload(), wire);
    assert_eq!(ledger.snapshot().used(ResourceKind::ControlPacketBytes), 0);
    drop(reservation);
}

#[test]
fn two_single_shard_runners_process_a_flow_only_on_its_owner() {
    let (first, first_input) = QueueIo::new(2);
    let (second, second_input) = QueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (adapters, _) = ShardedPacketIo::group(
        vec![first, second],
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let mut runners = adapters
        .into_iter()
        .enumerate()
        .map(|(index, adapter)| {
            SingleShardRunner::new(
                adapter,
                Arc::clone(&ledger),
                RunnerConfig {
                    generation: NetworkGeneration::new(1),
                    shard: ShardId::new(u16::try_from(index).unwrap()),
                    ..RunnerConfig::default()
                },
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let inputs = [first_input, second_input];

    inputs[0].inject(udp(b"first"));
    let first_outcome = block_on(runners[0].step(1)).unwrap();
    let owner = if first_outcome.datagrams.is_empty() {
        let owner_outcome = block_on(runners[1].step(1)).unwrap();
        assert_eq!(owner_outcome.datagrams.len(), 1);
        assert_eq!(owner_outcome.datagrams[0].token.shard(), ShardId::new(1));
        1
    } else {
        assert_eq!(first_outcome.datagrams.len(), 1);
        assert_eq!(first_outcome.datagrams[0].token.shard(), ShardId::new(0));
        0
    };

    let non_owner = 1 - owner;
    inputs[non_owner].inject(udp(b"second"));
    let wrong_outcome = block_on(runners[non_owner].step(2)).unwrap();
    assert!(wrong_outcome.datagrams.is_empty());
    let owner_outcome = block_on(runners[owner].step(2)).unwrap();
    assert_eq!(owner_outcome.datagrams.len(), 1);
    assert_eq!(owner_outcome.datagrams[0].payload.to_vec(), b"second");
    assert_eq!(
        owner_outcome.datagrams[0].token.shard(),
        ShardId::new(u16::try_from(owner).unwrap())
    );
}

#[test]
fn cross_shard_arrival_wakes_an_owner_blocked_on_platform_read() {
    let (first, first_input) = PendingQueueIo::new(2);
    let (second, second_input) = PendingQueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (mut adapters, control) = ShardedPacketIo::group(
        vec![first, second],
        ledger,
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let inputs = [first_input, second_input];

    inputs[0].inject(udp(b"first"));
    let first_result = receive(&mut adapters[0]);
    let owner = usize::from(first_result.is_err());
    if owner == 1 {
        assert_eq!(first_result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(receive(&mut adapters[1]).unwrap().len(), 1);
    }
    let non_owner = 1 - owner;
    let (owner_adapter, non_owner_adapter) = if owner == 0 {
        let (owner_side, other_side) = adapters.split_at_mut(1);
        (&mut owner_side[0], &mut other_side[0])
    } else {
        let (other_side, owner_side) = adapters.split_at_mut(1);
        (&mut owner_side[0], &mut other_side[0])
    };
    let before_block = control.stats().unwrap();
    let mut owner_batch = PacketBatch::with_limit(8);
    let mut blocked_recv = Box::pin(owner_adapter.recv(&mut owner_batch));
    let counter = Arc::new(WakeCounter::default());
    let task_waker = waker(Arc::clone(&counter));
    let mut context = Context::from_waker(&task_waker);
    assert!(matches!(
        blocked_recv.as_mut().poll(&mut context),
        Poll::Pending
    ));
    let after_block = control.stats().unwrap();
    assert_eq!(
        after_block.forwarded_waker_registrations,
        before_block.forwarded_waker_registrations + 1
    );
    assert_eq!(
        after_block.forwarded_wakeups,
        before_block.forwarded_wakeups
    );

    inputs[non_owner].inject(udp(b"second"));
    assert_eq!(
        receive(non_owner_adapter).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(counter.0.load(Ordering::Relaxed) > 0);
    assert!(matches!(
        blocked_recv.as_mut().poll(&mut context),
        Poll::Ready(Ok(1))
    ));
    drop(blocked_recv);
    assert_eq!(owner_batch.pop_front().unwrap().payload(), udp(b"second"));
    let stats = control.stats().unwrap();
    assert!(stats.forwarded_waker_registrations >= after_block.forwarded_waker_registrations);
    assert_eq!(stats.forwarded_wakeups, before_block.forwarded_wakeups + 1);
}

#[test]
fn cancelling_blocked_receive_removes_its_cross_shard_waker() {
    let (first, first_input) = PendingQueueIo::new(2);
    let (second, second_input) = PendingQueueIo::new(2);
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (mut adapters, _) = ShardedPacketIo::group(
        vec![first, second],
        ledger,
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let inputs = [first_input, second_input];
    inputs[0].inject(udp(b"first"));
    let first_result = receive(&mut adapters[0]);
    let owner = usize::from(first_result.is_err());
    if owner == 1 {
        assert_eq!(receive(&mut adapters[1]).unwrap().len(), 1);
    }
    let non_owner = 1 - owner;
    let (owner_adapter, non_owner_adapter) = if owner == 0 {
        let (owner_side, other_side) = adapters.split_at_mut(1);
        (&mut owner_side[0], &mut other_side[0])
    } else {
        let (other_side, owner_side) = adapters.split_at_mut(1);
        (&mut owner_side[0], &mut other_side[0])
    };
    let mut owner_batch = PacketBatch::with_limit(8);
    let mut blocked_recv = Box::pin(owner_adapter.recv(&mut owner_batch));
    let counter = Arc::new(WakeCounter::default());
    let task_waker = waker(Arc::clone(&counter));
    let mut context = Context::from_waker(&task_waker);
    assert!(matches!(
        blocked_recv.as_mut().poll(&mut context),
        Poll::Pending
    ));
    drop(blocked_recv);

    inputs[non_owner].inject(udp(b"second"));
    assert_eq!(
        receive(non_owner_adapter).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);
    assert_eq!(receive(owner_adapter).unwrap().len(), 1);
}

#[test]
fn concurrent_routing_reset_and_stats_release_all_shared_leases() {
    const SHARDS: usize = 4;
    const PACKETS_PER_SHARD: usize = 512;
    const RESETS: usize = 128;

    let mut queues = Vec::with_capacity(SHARDS);
    let mut inputs = Vec::with_capacity(SHARDS);
    for _ in 0..SHARDS {
        let (queue, input) = QueueIo::new(SHARDS);
        queues.push(queue);
        inputs.push(input);
    }
    let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
    let (adapters, control) = ShardedPacketIo::group(
        queues,
        Arc::clone(&ledger),
        NetworkGeneration::new(1),
        SchedulerConfig::default(),
    )
    .unwrap();
    let start = Arc::new(Barrier::new(SHARDS + 1));

    let workers = adapters
        .into_iter()
        .zip(inputs)
        .enumerate()
        .map(|(shard, (mut adapter, input))| {
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                for packet_index in 0..PACKETS_PER_SHARD {
                    let port = 10_000_u16
                        .saturating_add(u16::try_from(shard * PACKETS_PER_SHARD).unwrap())
                        .saturating_add(u16::try_from(packet_index).unwrap());
                    let wire = emit_udp_packet(
                        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), port)),
                        SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)),
                        b"concurrent-reset",
                        64,
                        port,
                    )
                    .unwrap();
                    input.inject(wire);
                    match receive(&mut adapter) {
                        Ok(_) => {}
                        Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    let reset_control = control.clone();
    let reset_start = Arc::clone(&start);
    let resetter = thread::spawn(move || {
        reset_start.wait();
        for generation in 2..=RESETS + 1 {
            reset_control
                .reset_network(NetworkGeneration::new(
                    u64::try_from(generation).expect("generation fits u64"),
                ))
                .unwrap();
            let stats = reset_control.stats().unwrap();
            assert!(
                stats.queued_packets
                    <= usize::try_from(stats.enqueued_packets).unwrap_or(usize::MAX)
            );
        }
    });

    for worker in workers {
        worker.join().unwrap();
    }
    resetter.join().unwrap();
    control
        .reset_network(NetworkGeneration::new(
            u64::try_from(RESETS + 2).expect("generation fits u64"),
        ))
        .unwrap();

    let stats = control.stats().unwrap();
    assert_eq!(stats.directory_entries, 0);
    assert_eq!(stats.local_cache_entries, 0);
    assert_eq!(stats.queued_packets, 0);
    assert_eq!(stats.queued_bytes, 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::PacketBytes), 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::ControlPacketBytes), 0);
    assert_eq!(ledger.snapshot().used(ResourceKind::MetadataBytes), 0);
}
