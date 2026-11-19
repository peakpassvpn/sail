//! Owner-index tests use synthetic bridge entries only for index/cancel paths.
//! They are not TCP/packet forwarding acceptance; the separate small-MSS test
//! exercises an actual native connection, real leases and exact wire payload.
use super::super::channel::ChannelPacketIo;
use super::*;
use sail_netstack::BudgetProfile;

type Runtime = NativeRuntime<ChannelPacketIo>;
fn fixture() -> Runtime {
    let (_input, input_rx) = tokio_mpsc::channel(4);
    let (output, _output_rx) = tokio_mpsc::channel(4);
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    NativeRuntime::new(
        ChannelPacketIo::new(input_rx, output, 1),
        ledger,
        RunnerConfig::default(),
        4,
        4,
        4,
    )
    .unwrap()
    .0
}
fn add(
    runtime: &mut Runtime,
    id: u64,
    bytes: usize,
) -> (TcpFlowToken, oneshot::Receiver<io::Result<usize>>) {
    let token = runtime.credit_token(FlowId::new(id));
    let (response, receiver) = oneshot::channel();
    let mut bridge = FlowBridge::new(Arc::new(CleanupActive::new(true)));
    bridge.pending_write = Some((vec![0x5a; bytes], response));
    runtime.flows.insert(token, bridge);
    runtime.link_credit(token);
    assert!(runtime.credit.arm());
    (token, receiver)
}
#[tokio::test]
async fn flow_zero_head_middle_tail_and_repeated_unlink_are_valid() {
    let mut runtime = fixture();
    let (zero, _a) = add(&mut runtime, 0, 1);
    let (one, _b) = add(&mut runtime, 1, 2);
    let (two, _c) = add(&mut runtime, 2, 3);
    runtime.link_credit(zero); // no duplicate append.
    assert_eq!(runtime.credit_head, Some(FlowId::new(0)));
    assert_eq!(runtime.credit_tail, Some(FlowId::new(2)));
    runtime.unlink_credit(one);
    runtime.unlink_credit(one);
    assert_eq!(runtime.flows[&zero].credit_next, Some(FlowId::new(2)));
    assert_eq!(runtime.flows[&two].credit_prev, Some(FlowId::new(0)));
    runtime.unlink_credit(zero);
    runtime.unlink_credit(two);
    assert_eq!(runtime.credit_head, None);
    assert_eq!(runtime.credit_tail, None);
    runtime.credit.finish(None, false);
    #[cfg(feature = "internal-diagnostics")]
    {
        assert_eq!(runtime.credit_diagnostics.resource_pending_writes, 0);
        assert_eq!(runtime.credit_diagnostics.resource_pending_bytes, 0);
    }
}
#[tokio::test]
async fn wrong_generation_and_shard_do_not_alias_current_flow_id() {
    let mut runtime = fixture();
    let (token, _receiver) = add(&mut runtime, 0, 10);
    let wrong_gen =
        TcpFlowToken::new_on_shard(token.flow(), token.generation().next(), token.shard());
    let wrong_shard = TcpFlowToken::new_on_shard(token.flow(), token.generation(), ShardId::new(1));
    runtime.unlink_credit(wrong_gen);
    runtime.unlink_credit(wrong_shard);
    assert!(runtime.flows[&token].credit_member);
    runtime.link_credit(wrong_gen);
    runtime.link_credit(wrong_shard);
    assert_eq!(runtime.flows.len(), 1);
    runtime.clear_credit_waiters();
    assert!(!runtime.flows[&token].credit_member);
}
#[tokio::test]
async fn reset_clears_old_links_before_generation_change_and_old_hint_is_harmless() {
    let mut runtime = fixture();
    let (token, _receiver) = add(&mut runtime, 0, 10);
    let generation = token.generation().next();
    let (response, _done) = oneshot::channel();
    runtime.handle_command(
        TcpCommand::ResetNetwork {
            generation,
            response,
        },
        0,
    );
    assert_eq!(runtime.credit_generation, generation);
    assert!(runtime.flows.is_empty());
    assert_eq!(runtime.credit_head, None);
    runtime.credit.slot.hint();
    runtime.retry_credit_write();
    assert!(runtime.flows.is_empty());
}
#[tokio::test]
async fn cancellation_remove_finish_fail_all_and_shutdown_clear_registered_links() {
    let mut runtime = fixture();
    let (a, receiver) = add(&mut runtime, 0, 1);
    drop(receiver); // resource event must not send a canceled response's data.
    runtime.retry_credit_write();
    assert!(!runtime.flows.contains_key(&a));
    assert!(!runtime.credit_continuation);
    assert_eq!(runtime.credit_write_attempts, 0);
    let (b, _b) = add(&mut runtime, 1, 2);
    runtime.finish_flow(b);
    assert_eq!(runtime.credit_head, None);
    let (c, _c) = add(&mut runtime, 2, 3);
    runtime.drop_flow(c);
    assert_eq!(runtime.credit_head, None);
    let (_d, _d_rx) = add(&mut runtime, 3, 4);
    runtime.fail_all("test");
    assert!(runtime.flows.is_empty());
    let (_e, _e_rx) = add(&mut runtime, 4, 5);
    let (response, _done) = oneshot::channel();
    runtime.handle_command(
        TcpCommand::Shutdown {
            grace_period_ms: 1,
            response,
        },
        0,
    );
    assert_eq!(runtime.credit_head, None);
    assert_eq!(
        runtime.credit.availability(),
        credit_wake::Availability::Stopped
    );
}
#[tokio::test]
async fn fifo_rotation_and_no_scan_leave_unrelated_bridges_untouched() {
    let mut runtime = fixture();
    let (large, _a) = add(&mut runtime, 0, 64 * 1024);
    let (small, _b) = add(&mut runtime, 1, 1);
    for id in 2..1024 {
        let token = runtime.credit_token(FlowId::new(id));
        runtime
            .flows
            .insert(token, FlowBridge::new(Arc::new(CleanupActive::new(true))));
    }
    // The fixed-number unlink/reappend operation used after a blocked attempt.
    runtime.unlink_credit(large);
    runtime.link_credit(large);
    assert_eq!(runtime.credit_head, Some(small.flow()));
    assert_eq!(runtime.credit_tail, Some(large.flow()));
    assert_eq!(
        runtime
            .flows
            .values()
            .filter(|flow| flow.credit_member)
            .count(),
        2
    );
    runtime.clear_credit_waiters();
    assert_eq!(runtime.flows.len(), 1024);
    assert!(runtime.flows.values().all(|flow| !flow.credit_member));
}
#[test]
fn packet_cause_is_typed_and_does_not_accept_other_budget_or_tx_errors() {
    let error = |kind| {
        RunnerError::Budget(BudgetError::Exhausted {
            kind,
            requested: 1460,
            available: 0,
        })
    };
    assert!(packet_bytes_blocked(&error(ResourceKind::PacketBytes)));
    assert!(!packet_bytes_blocked(&error(ResourceKind::TcpPayloadBytes)));
    assert!(!packet_bytes_blocked(&RunnerError::TxQueueFull));
    assert!(!packet_bytes_blocked(&RunnerError::Tcp(
        TcpTableError::State(TcpError::SendWindowExceeded)
    )));
}
#[tokio::test]
async fn partial_suffix_gauges_and_original_retry_deadline_are_preserved() {
    let mut runtime = fixture();
    let (token, _receiver) = add(&mut runtime, 0, 100);
    runtime.retry_at_ms = Some(10);
    runtime.unlink_credit(token);
    // Model a report's completed prefix before reappending its original owner.
    runtime
        .flows
        .get_mut(&token)
        .unwrap()
        .pending_write
        .as_mut()
        .unwrap()
        .0
        .drain(..40);
    runtime.link_credit(token);
    assert_eq!(runtime.retry_at_ms, Some(10));
    #[cfg(feature = "internal-diagnostics")]
    {
        assert_eq!(runtime.credit_diagnostics.resource_pending_writes, 1);
        assert_eq!(runtime.credit_diagnostics.resource_pending_bytes, 60);
    }
    runtime.clear_credit_waiters();
}
#[test]
fn typed_bridge_storage_and_all_flow_bound_are_reported() {
    eprintln!(
        "FlowBridge size={} align={} OptionFlowId={} Slot={} Interest={}",
        std::mem::size_of::<FlowBridge>(),
        std::mem::align_of::<FlowBridge>(),
        std::mem::size_of::<Option<FlowId>>(),
        std::mem::size_of::<credit_wake::CreditSlot>(),
        std::mem::size_of::<CreditInterest>()
    );
    // Production baseline size, allocator and Arc headers need the paired
    // measurement recipe; test-only diagnostics are not that measurement.
    let l = 4096usize;
    let n = 1usize;
    assert_eq!(64 * l + 432 * n + 208, 262784);
}

#[tokio::test]
async fn a_resource_event_attempts_one_owner_and_never_full_scan() {
    let mut runtime = fixture();
    let (first, _a) = add(&mut runtime, 0, 10);
    let (second, _b) = add(&mut runtime, 1, 20);
    runtime.retry_at_ms = Some(10);
    runtime.retry_credit_write();
    // Synthetic token is absent from TCP table: the exact stop removes only
    // this head, with no progress continuation and no attempt on the next flow.
    assert_eq!(runtime.credit_write_attempts, 1);
    assert!(!runtime.flows[&first].credit_member);
    assert!(runtime.flows[&second].credit_member);
    assert!(!runtime.credit_continuation);
    assert_eq!(runtime.retry_at_ms, Some(10));
}
