use std::sync::Arc;
use std::thread;

use sail_netstack::{
    BudgetError, BudgetProfile, ChecksumCapabilities, FlowId, NetworkGeneration, Packet,
    PacketBatch, PacketCapabilities, PacketToken, PressureLevel, ResourceKind, ResourceLedger,
    ShardId, TcpFlowToken, TcpTable, TcpTableConfig, TcpTableError, UdpFlowToken,
};

#[test]
fn every_shipping_profile_is_internally_valid() {
    for profile in [
        BudgetProfile::Mobile,
        BudgetProfile::Router,
        BudgetProfile::Desktop,
        BudgetProfile::Server,
    ] {
        profile.budget().validate().unwrap();
    }
}

#[test]
fn byte_pool_and_global_ceiling_are_both_hard_limits() {
    let mut budget = BudgetProfile::Router.budget();
    budget.total_bytes = 10;
    budget.metadata_bytes = 4;
    budget.tcp_payload_bytes = 4;
    budget.packet_bytes = 1;
    budget.control_packet_bytes = 0;
    budget.fragment_bytes = 1;
    let ledger = ResourceLedger::new(budget).unwrap();

    let metadata = ledger.try_acquire(ResourceKind::MetadataBytes, 4).unwrap();
    assert!(matches!(
        ledger.try_acquire(ResourceKind::MetadataBytes, 1),
        Err(BudgetError::Exhausted { .. })
    ));
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.total_bytes, 4);
    assert_eq!(snapshot.used(ResourceKind::MetadataBytes), 4);
    assert_eq!(snapshot.peak(ResourceKind::MetadataBytes), 4);
    drop(metadata);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn concurrent_leases_never_exceed_a_hard_limit() {
    let mut budget = BudgetProfile::Router.budget();
    budget.max_udp_flows = 8;
    let ledger = ResourceLedger::new(budget).unwrap();
    let mut workers = Vec::new();
    for _ in 0..32 {
        let ledger = Arc::clone(&ledger);
        workers.push(thread::spawn(move || {
            ledger.try_acquire(ResourceKind::UdpFlows, 1).ok()
        }));
    }
    let leases: Vec<_> = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(leases.len(), 8);
    assert_eq!(ledger.snapshot().pressure, PressureLevel::Exhausted);
    drop(leases);
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 0);
}

#[test]
fn pressure_includes_individual_byte_pool_saturation() {
    let budget = BudgetProfile::Mobile.budget();
    let ledger = ResourceLedger::new(budget).unwrap();
    let amount = budget.metadata_bytes.saturating_mul(850).div_ceil(1_000);
    let lease = ledger
        .try_acquire(ResourceKind::MetadataBytes, amount)
        .unwrap();
    assert_eq!(ledger.snapshot().pressure, PressureLevel::Critical);
    drop(lease);
    assert_eq!(ledger.snapshot().pressure, PressureLevel::Normal);
}

#[test]
fn randomized_acquire_release_preserves_accounting() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut seed = 0x8d26_5f71_4a39_c0bdu64;
    let mut leases = Vec::new();
    for _ in 0..20_000 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        if seed.trailing_zeros() >= 2 && !leases.is_empty() {
            let index = usize::try_from(seed % leases.len() as u64).unwrap();
            leases.swap_remove(index);
        } else {
            let amount = ((seed >> 32) as usize % 4096) + 1;
            if let Ok(lease) = ledger.try_acquire(ResourceKind::PacketBytes, amount) {
                leases.push(lease);
            }
        }
        let snapshot = ledger.snapshot();
        assert!(snapshot.total_bytes <= ledger.budget().total_bytes);
        assert!(snapshot.used[ResourceKind::PacketBytes as usize] <= ledger.budget().packet_bytes);
    }
    drop(leases);
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.total_bytes, 0);
    assert_eq!(snapshot.used[ResourceKind::PacketBytes as usize], 0);
}

#[test]
fn packet_batch_retains_unsent_suffix() {
    let mut batch = PacketBatch::with_limit(3);
    for token in 0..3 {
        batch
            .push(Packet::from_payload(
                PacketToken::new(token),
                4,
                &[u8::try_from(token).unwrap()],
            ))
            .unwrap();
    }
    batch.acknowledge_sent(2).unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.iter().next().unwrap().token(), PacketToken::new(2));
    assert!(batch.acknowledge_sent(2).is_err());
}

#[test]
fn stale_udp_token_is_rejected_by_generation() {
    let old = NetworkGeneration::new(9);
    let token = UdpFlowToken::new(FlowId::new(7), old);
    assert!(token.is_current(old));
    assert!(token.is_owned_by(old, ShardId::new(0)));
    assert!(!token.is_owned_by(old, ShardId::new(1)));
    assert!(!token.is_current(old.next()));
}

#[test]
fn tcp_table_rejects_a_capability_owned_by_another_shard() {
    let generation = NetworkGeneration::new(3);
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = TcpTable::new_on_shard(
        ledger,
        generation,
        ShardId::new(2),
        TcpTableConfig::default(),
    );
    let foreign = TcpFlowToken::new_on_shard(FlowId::new(0), generation, ShardId::new(1));
    assert!(matches!(
        table.accept(foreign),
        Err(TcpTableError::StaleToken)
    ));
    assert_eq!(table.stats().stale_operations, 1);
}

#[test]
fn single_packet_mobile_capability_is_valid() {
    let capabilities = PacketCapabilities {
        max_batch: 1,
        queue_count: 1,
        headroom: 4,
        vectored: false,
        rx_checksum: ChecksumCapabilities::default(),
        tx_checksum: ChecksumCapabilities::default(),
        gso: None,
    };
    assert!(capabilities.validate().is_ok());
}
