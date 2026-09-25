use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sail_netstack::{
    BudgetProfile, FlowKey, IpEndpoint, NetworkGeneration, ResourceKind, ResourceLedger, Route,
    SchedulerConfig, ShardId, ShardQueueError, ShardRouter, TransportProtocol,
};

fn key(port: u16, generation: u64) -> FlowKey {
    FlowKey {
        endpoint: IpEndpoint {
            source: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), port)),
            destination: SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)),
            protocol: TransportProtocol::Tcp,
        },
        generation: NetworkGeneration::new(generation),
    }
}

fn target(route: Route) -> ShardId {
    match route {
        Route::Local(shard) | Route::Forward(shard) => shard,
    }
}

#[test]
fn first_packet_assignment_is_stable_across_input_queues() {
    let ledger = ResourceLedger::new(BudgetProfile::Desktop.budget()).unwrap();
    let mut router = ShardRouter::<u8>::new(ledger, 4, SchedulerConfig::default()).unwrap();
    let flow = key(10, 1);
    let owner = target(router.route(ShardId::new(0), flow).unwrap());
    for input in 0..4 {
        let route = router.route(ShardId::new(input), flow).unwrap();
        assert_eq!(target(route), owner);
        assert_eq!(matches!(route, Route::Local(_)), input == owner.get());
    }
    assert_eq!(router.directory_len(), 1);
    let stats = router.stats();
    assert_eq!(stats.directory_entries, 1);
    let expected_local = if owner == ShardId::new(0) { 2 } else { 1 };
    assert_eq!(stats.local_routes, expected_local);
    assert_eq!(stats.local_routes + stats.forwarded_routes, 5);
}

#[test]
fn directory_entries_are_charged_and_released() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut router =
        ShardRouter::<()>::new(Arc::clone(&ledger), 1, SchedulerConfig::default()).unwrap();
    let flow = key(20, 1);
    assert_eq!(
        router.route(ShardId::new(0), flow).unwrap(),
        Route::Local(ShardId::new(0))
    );
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        64
    );
    assert!(router.remove(&flow));
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        0
    );
}

#[test]
fn directory_capacity_replaces_oldest_entry_and_releases_its_budget() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let config = SchedulerConfig {
        max_active_flows: 1,
        ..SchedulerConfig::default()
    };
    let mut router = ShardRouter::<()>::new(Arc::clone(&ledger), 1, config).unwrap();
    let first = key(20, 1);
    let second = key(21, 1);

    router.route(ShardId::new(0), first).unwrap();
    router.route(ShardId::new(0), second).unwrap();
    router.route(ShardId::new(0), first).unwrap();

    assert_eq!(router.directory_len(), 1);
    assert_eq!(router.stats().directory_admission_failures, 0);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        64
    );
    assert!(router.remove(&first));
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        0
    );
}

#[test]
fn cross_shard_queue_admission_is_bounded_and_returns_value() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let config = SchedulerConfig {
        max_queued_packets: 2,
        max_packets_per_flow: 2,
        max_time_per_round: Duration::from_secs(30),
        ..SchedulerConfig::default()
    };
    let mut router = ShardRouter::new(ledger, 2, config).unwrap();
    let target = ShardId::new(1);
    router.enqueue(target, key(1, 0), 10, "one").unwrap();
    router.enqueue(target, key(2, 0), 10, "two").unwrap();
    let rejected = router.enqueue(target, key(3, 0), 10, "three");
    assert!(matches!(rejected, Err(ShardQueueError::Admission(_))));
    assert_eq!(rejected.unwrap_err().into_inner(), "three");
    let queued = router.stats();
    assert_eq!(queued.queued_packets, 2);
    assert_eq!(queued.queued_bytes, 20);
    assert_eq!(queued.enqueued_packets, 2);
    assert_eq!(queued.enqueued_bytes, 20);
    assert_eq!(queued.dropped_packets, 1);

    let mut values = Vec::new();
    let stats = router.drain(target, |_, value| values.push(value));
    values.sort_unstable();
    assert_eq!(values, ["one", "two"]);
    assert_eq!(stats.packets, 2);
    let drained = router.stats();
    assert_eq!(drained.queued_packets, 0);
    assert_eq!(drained.queued_bytes, 0);
    assert_eq!(drained.drained_packets, 2);
    assert_eq!(drained.drained_bytes, 20);
}

#[test]
fn network_reset_drops_directory_and_every_cross_shard_queue() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut router = ShardRouter::new(Arc::clone(&ledger), 2, SchedulerConfig::default()).unwrap();
    let flow = key(1, 0);
    router.route(ShardId::new(0), flow).unwrap();
    router
        .enqueue(ShardId::new(1), flow, 100, vec![0_u8; 100])
        .unwrap();
    router.reset_network();
    assert_eq!(router.directory_len(), 0);
    assert_eq!(
        router
            .queue_snapshot(ShardId::new(1))
            .unwrap()
            .queued_packets,
        0
    );
    assert_eq!(
        ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
        0
    );
}

#[test]
fn configured_shard_counts_route_only_to_valid_owners() {
    for shard_count in [1_usize, 2, 4, 8] {
        let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
        let mut router =
            ShardRouter::<()>::new(ledger, shard_count, SchedulerConfig::default()).unwrap();
        for port in 1..=1_024 {
            let owner = target(router.route(ShardId::new(0), key(port, 0)).unwrap());
            assert!(usize::from(owner.get()) < shard_count);
        }
    }
}

#[test]
fn directory_budget_exhaustion_keeps_deterministic_routing_without_growth() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let reservation = ledger
        .try_acquire(ResourceKind::MetadataBytes, ledger.budget().metadata_bytes)
        .unwrap();
    let mut router = ShardRouter::<()>::new(ledger, 4, SchedulerConfig::default()).unwrap();
    let flow = key(44_000, 3);
    let first = target(router.route(ShardId::new(0), flow).unwrap());
    for input in 0..4 {
        assert_eq!(
            target(router.route(ShardId::new(input), flow).unwrap()),
            first
        );
    }
    assert_eq!(router.directory_len(), 0);
    assert_eq!(router.stats().directory_admission_failures, 5);
    drop(reservation);
    assert_eq!(target(router.route(ShardId::new(0), flow).unwrap()), first);
    assert_eq!(router.directory_len(), 1);
}
