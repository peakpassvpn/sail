use sail_netstack::{
    BudgetProfile, PacketArena, ResourceKind, ResourceLedger, SlabChain, SlabClass,
};

#[test]
fn chain_split_merge_and_consume_preserve_bytes_and_budget() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let baseline = ledger.snapshot().total_bytes;
    let bytes: Vec<u8> = (0..=255).cycle().take(10_000).collect();
    let mut chain = SlabChain::new(ledger.clone(), SlabClass::TcpPayload, 1024);
    chain.append(&bytes).unwrap();
    assert_eq!(chain.to_vec(), bytes);
    let charged = ledger.snapshot().total_bytes;
    assert!(charged > bytes.len());

    let mut suffix = chain.split_off(3_333);
    assert_eq!(chain.to_vec(), bytes[..3_333]);
    assert_eq!(suffix.to_vec(), bytes[3_333..]);
    // A segment split shares its one allocation and never double-charges.
    assert_eq!(ledger.snapshot().total_bytes, charged);

    assert_eq!(chain.consume(333), 333);
    assert_eq!(chain.to_vec(), bytes[333..3_333]);
    suffix.consume(suffix.len());
    assert!(suffix.is_empty());
    assert!(ledger.snapshot().total_bytes >= chain.len());
    drop(suffix);

    let tail = chain.split_off(1_500);
    chain.append_chain(tail);
    assert_eq!(chain.to_vec(), bytes[333..3_333]);
    drop(chain);
    assert_eq!(ledger.snapshot().total_bytes, baseline);
}

#[test]
fn failed_transactional_append_does_not_change_chain() {
    let mut budget = BudgetProfile::Router.budget();
    budget.total_bytes = 144;
    budget.metadata_bytes = 128;
    budget.tcp_payload_bytes = 16;
    budget.packet_bytes = 0;
    budget.control_packet_bytes = 0;
    budget.fragment_bytes = 0;
    let ledger = ResourceLedger::new(budget).unwrap();
    let mut chain = SlabChain::new(ledger.clone(), SlabClass::TcpPayload, 8);
    chain.append(b"12345678").unwrap();
    assert!(chain.append(b"abcdefghijkl").is_err());
    assert_eq!(chain.to_vec(), b"12345678");
    assert_eq!(ledger.snapshot().total_bytes, 72);
}

#[test]
fn packet_arena_charges_full_writable_allocation() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let arena = PacketArena::new(ledger.clone(), 65_535 + 128);
    let mut packet = arena.allocate(64, 1500).unwrap();
    assert_eq!(
        ledger.snapshot().used[ResourceKind::PacketBytes as usize],
        1564
    );
    packet.payload_capacity_mut()[..4].copy_from_slice(b"sail");
    packet.set_len(4).unwrap();
    assert_eq!(packet.payload(), b"sail");
    drop(packet);
    assert_eq!(
        ledger.snapshot().used[ResourceKind::PacketBytes as usize],
        0
    );
}

#[test]
fn control_packet_reserve_is_independent_from_data_packet_exhaustion() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let arena = PacketArena::new(ledger.clone(), 65_535 + 128);
    let data = ledger
        .try_acquire(ResourceKind::PacketBytes, ledger.budget().packet_bytes)
        .unwrap();
    assert!(arena.allocate(0, 1).is_err());

    let control = arena.allocate_control(4, 84).unwrap();
    assert_eq!(ledger.snapshot().used(ResourceKind::ControlPacketBytes), 88);
    drop(control);
    drop(data);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}

#[test]
fn randomized_chain_operations_match_a_vec_model() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut chain = SlabChain::new(ledger.clone(), SlabClass::TcpPayload, 127);
    let mut model = Vec::new();
    let mut seed = 0xa529_b61d_7cc3_81efu64;
    for _ in 0..10_000 {
        seed = seed
            .wrapping_mul(2_862_933_555_777_941_757)
            .wrapping_add(3_037_000_493);
        if seed.trailing_zeros() >= 2 && !model.is_empty() {
            let amount = usize::try_from(seed % (model.len() as u64 + 1)).unwrap();
            assert_eq!(chain.consume(amount), amount);
            model.drain(..amount);
        } else {
            let amount = usize::try_from((seed >> 32) % 257).unwrap();
            let value = seed.to_le_bytes()[0];
            let addition = vec![value; amount];
            chain.append(&addition).unwrap();
            model.extend_from_slice(&addition);
        }
        assert_eq!(chain.len(), model.len());
        assert_eq!(chain.to_vec(), model);
        assert!(ledger.snapshot().total_bytes >= chain.len());
    }
    drop(chain);
    assert_eq!(ledger.snapshot().total_bytes, 0);
}
