use sail_netstack::{
    AppEvent, NewReno, RtoEstimator, SendControl, SeqNumber, TcpAction, TcpError, TcpFlags,
    TcpSegmentMeta, TcpState, TcpTcb, TimerEvent,
};

fn segment(
    sequence: u32,
    acknowledgment: Option<u32>,
    flags: TcpFlags,
    payload_len: usize,
) -> TcpSegmentMeta {
    TcpSegmentMeta {
        sequence: SeqNumber::new(sequence),
        acknowledgment: acknowledgment.map(SeqNumber::new),
        flags,
        window: 65_535,
        payload_len,
    }
}

fn segment_with_window(
    sequence: u32,
    acknowledgment: Option<u32>,
    flags: TcpFlags,
    window: u32,
    payload_len: usize,
) -> TcpSegmentMeta {
    TcpSegmentMeta {
        sequence: SeqNumber::new(sequence),
        acknowledgment: acknowledgment.map(SeqNumber::new),
        flags,
        window,
        payload_len,
    }
}

fn established(capacity: usize) -> TcpTcb {
    let syn = segment(100, None, TcpFlags::SYN, 0);
    let (mut tcb, _) = TcpTcb::from_syn(syn, SeqNumber::new(1_000), capacity).unwrap();
    let actions = tcb
        .on_segment(segment(101, Some(1_001), TcpFlags::ACK, 0))
        .unwrap();
    assert!(actions.contains(&TcpAction::Accepted));
    tcb
}

#[test]
fn handshake_only_accepts_the_exact_final_ack() {
    let syn = segment(100, None, TcpFlags::SYN, 0);
    let (mut tcb, actions) = TcpTcb::from_syn(syn, SeqNumber::new(1_000), 4_096).unwrap();
    assert_eq!(tcb.state(), TcpState::SynReceived);
    assert!(matches!(actions[0], TcpAction::Send(_)));
    let invalid_ack = tcb
        .on_segment(segment(101, Some(999), TcpFlags::ACK, 0))
        .unwrap();
    assert!(matches!(
        invalid_ack.as_slice(),
        [TcpAction::Send(control)]
            if control.flags == TcpFlags::RST && control.sequence == SeqNumber::new(999)
    ));
    assert_eq!(tcb.state(), TcpState::SynReceived);
    assert!(tcb
        .on_segment(segment(101, Some(1_001), TcpFlags::ACK, 0))
        .unwrap()
        .contains(&TcpAction::Accepted));
    assert_eq!(tcb.state(), TcpState::Established);
}

#[test]
fn data_and_fin_combined_with_initial_syn_are_applied_after_handshake() {
    let syn_fin = segment(100, None, TcpFlags::SYN.union(TcpFlags::FIN), 3);
    assert_eq!(
        TcpTcb::from_syn(syn_fin, SeqNumber::new(1_000), 2),
        Err(TcpError::ReceiveCreditExceeded)
    );
    let (mut tcb, syn_ack) = TcpTcb::from_syn(syn_fin, SeqNumber::new(1_000), 4_096).unwrap();
    let syn_ack = match syn_ack[0] {
        TcpAction::Send(control) => control,
        action => panic!("unexpected initial action: {action:?}"),
    };
    assert_eq!(syn_ack.acknowledgment, SeqNumber::new(101));

    assert!(!tcb
        .on_segment(segment(101, Some(1_001), TcpFlags::ACK, 0))
        .unwrap()
        .contains(&TcpAction::Accepted));
    let completed = tcb
        .on_segment(segment(105, Some(1_001), TcpFlags::ACK, 0))
        .unwrap();
    assert_eq!(tcb.state(), TcpState::CloseWait);
    assert!(completed.contains(&TcpAction::Accepted));
    assert!(completed.contains(&TcpAction::DeliverPayload { len: 3 }));
    assert!(completed.contains(&TcpAction::PeerHalfClosed));
    assert!(completed.iter().any(|action| matches!(
        action,
        TcpAction::Send(control)
            if control.flags == TcpFlags::ACK
                && control.acknowledgment == SeqNumber::new(105)
    )));

    let syn_data = segment(200, None, TcpFlags::SYN, 3);
    let (mut data_only, _) = TcpTcb::from_syn(syn_data, SeqNumber::new(2_000), 4_096).unwrap();
    let completed = data_only
        .on_segment(segment(204, Some(2_001), TcpFlags::ACK, 0))
        .unwrap();
    assert_eq!(data_only.state(), TcpState::Established);
    assert!(completed.contains(&TcpAction::DeliverPayload { len: 3 }));
    assert!(completed.contains(&TcpAction::ArmDelayedAck));
    assert!(!completed.contains(&TcpAction::PeerHalfClosed));
}

#[test]
fn send_window_only_accepts_fresh_acceptable_updates() {
    let syn = segment_with_window(100, None, TcpFlags::SYN, 500, 0);
    let (mut tcb, _) = TcpTcb::from_syn(syn, SeqNumber::new(1_000), 4_096).unwrap();
    tcb.on_segment(segment_with_window(101, Some(999), TcpFlags::ACK, 0, 0))
        .unwrap();
    assert_eq!(tcb.peer_window(), 500);

    tcb.on_segment(segment_with_window(
        101,
        Some(1_001),
        TcpFlags::ACK,
        1_000,
        0,
    ))
    .unwrap();
    assert_eq!(tcb.peer_window(), 1_000);
    tcb.on_segment(segment_with_window(
        101,
        Some(1_001),
        TcpFlags::ACK,
        2_000,
        0,
    ))
    .unwrap();
    assert_eq!(tcb.peer_window(), 2_000);

    tcb.on_segment(segment_with_window(100, Some(1_001), TcpFlags::ACK, 0, 0))
        .unwrap();
    assert_eq!(tcb.peer_window(), 2_000);
    tcb.on_segment(segment_with_window(
        10_000,
        Some(1_001),
        TcpFlags::ACK,
        0,
        0,
    ))
    .unwrap();
    assert_eq!(tcb.peer_window(), 2_000);
}

#[test]
fn scaled_receive_remainder_does_not_block_zero_window_sender_feedback() {
    let syn = segment_with_window(100, None, TcpFlags::SYN, 500, 0);
    let (mut tcb, _) =
        TcpTcb::from_syn_with_options(syn, SeqNumber::new(1_000), 65_537, 1_460, 1).unwrap();
    tcb.on_segment(segment_with_window(
        101,
        Some(1_001),
        TcpFlags::ACK,
        1_000,
        0,
    ))
    .unwrap();

    tcb.on_segment(segment_with_window(
        101,
        Some(1_001),
        TcpFlags::ACK,
        1_000,
        32_768,
    ))
    .unwrap();
    tcb.on_segment(segment_with_window(
        32_869,
        Some(1_001),
        TcpFlags::ACK,
        1_000,
        32_768,
    ))
    .unwrap();
    assert_eq!(tcb.receive_available(), 1);
    assert_eq!(tcb.advertised_window(), 0);

    tcb.on_segment(segment_with_window(
        65_637,
        Some(1_001),
        TcpFlags::ACK,
        2_000,
        0,
    ))
    .unwrap();
    assert_eq!(tcb.peer_window(), 2_000);
}

#[test]
fn out_of_window_ack_cannot_advance_send_state() {
    let mut tcb = established(1_000);
    tcb.on_app_event(AppEvent::Send(100)).unwrap();
    let before = tcb.send_unacked();
    let actions = tcb
        .on_segment(segment(50_000, Some(1_101), TcpFlags::ACK, 0))
        .unwrap();
    assert_eq!(tcb.send_unacked(), before);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], TcpAction::DefensiveAck(_)));
}

#[test]
fn synchronized_state_rejects_future_ack_missing_ack_and_unexpected_syn() {
    let mut tcb = established(1_000);
    let recv_next = tcb.recv_next();
    let future_ack = tcb
        .on_segment(segment(101, Some(9_999), TcpFlags::ACK, 10))
        .unwrap();
    assert_eq!(tcb.recv_next(), recv_next);
    assert_eq!(tcb.recv_buffered(), 0);
    assert!(matches!(
        future_ack.as_slice(),
        [TcpAction::DefensiveAck(_)]
    ));

    assert!(tcb
        .on_segment(segment(101, None, TcpFlags::default(), 10))
        .unwrap()
        .is_empty());
    assert_eq!(tcb.recv_next(), recv_next);
    assert_eq!(
        tcb.on_segment(segment(
            101,
            Some(1_001),
            TcpFlags::SYN.union(TcpFlags::ACK),
            0,
        ))
        .unwrap(),
        [TcpAction::ChallengeAck]
    );
}

#[test]
fn advertised_right_edge_never_retreats_and_requires_credit() {
    let mut tcb = established(1_000);
    let initial_edge = tcb.advertised_right_edge();
    let actions = tcb
        .on_segment(segment(101, Some(1_001), TcpFlags::ACK, 600))
        .unwrap();
    assert!(actions.contains(&TcpAction::DeliverPayload { len: 600 }));
    assert_eq!(tcb.recv_buffered(), 600);
    assert_eq!(tcb.advertised_right_edge(), initial_edge);
    assert_eq!(tcb.advertised_window(), 400);
    let mut overrun = tcb.clone();
    let trimmed = overrun
        .on_segment(segment(701, Some(1_001), TcpFlags::ACK, 401))
        .unwrap();
    assert!(trimmed.contains(&TcpAction::DeliverPayload { len: 400 }));
    assert_eq!(overrun.recv_buffered(), 1_000);
    assert_eq!(overrun.advertised_right_edge(), initial_edge);
    assert_eq!(overrun.advertised_window(), 0);
    assert!(tcb
        .on_app_event(AppEvent::Consumed(300))
        .unwrap()
        .is_empty());
    assert_eq!(tcb.advertised_window(), 400);
    let update = tcb.on_app_event(AppEvent::Consumed(300)).unwrap();
    assert!(update
        .iter()
        .any(|action| matches!(action, TcpAction::Send(_))));
    assert_eq!(tcb.advertised_window(), 1_000);
    assert!(tcb.advertised_right_edge().after(initial_edge));
}

#[test]
fn fin_at_receive_window_right_edge_is_trimmed() {
    let mut tcb = established(1);
    let actions = tcb
        .on_segment(segment(
            101,
            Some(1_001),
            TcpFlags::ACK.union(TcpFlags::FIN),
            1,
        ))
        .unwrap();

    assert_eq!(tcb.recv_next(), SeqNumber::new(102));
    assert_eq!(tcb.recv_buffered(), 1);
    assert_eq!(tcb.advertised_right_edge(), SeqNumber::new(102));
    assert_eq!(tcb.state(), TcpState::Established);
    assert!(actions.contains(&TcpAction::DeliverPayload { len: 1 }));
    assert!(!actions.contains(&TcpAction::PeerHalfClosed));
}

#[test]
fn initial_payload_beyond_quantized_window_keeps_right_edge_at_recv_next() {
    // Minimized from fuzz artifact tcp_state/minimized-from-62a8ac15: a
    // 15_104-byte capacity rounds to a zero window at scale 14, the SYN
    // carries one byte, and every sequence number wraps past u32::MAX.
    let syn = segment(u32::MAX, None, TcpFlags::SYN, 1);
    let (mut tcb, _) =
        TcpTcb::from_syn_with_options(syn, SeqNumber::new(u32::MAX), 15_104, 74, 14).unwrap();
    assert_eq!(tcb.recv_next(), SeqNumber::new(0));
    assert_eq!(tcb.advertised_right_edge(), SeqNumber::new(1));
    tcb.record_rtt_sample(0xcdcd_cdcd);

    let actions = tcb
        .on_segment(segment(1, Some(0), TcpFlags::ACK, 0))
        .unwrap();
    assert!(actions.contains(&TcpAction::Accepted));
    assert!(actions.contains(&TcpAction::DeliverPayload { len: 1 }));
    assert_eq!(tcb.recv_next(), SeqNumber::new(1));
    assert_eq!(tcb.recv_buffered(), 1);
    assert_eq!(tcb.advertised_right_edge(), tcb.recv_next());
    assert_eq!(tcb.advertised_window(), 0);
}

#[test]
fn initial_fin_at_receive_window_right_edge_is_not_admitted() {
    let syn_fin = segment(u32::MAX, None, TcpFlags::SYN.union(TcpFlags::FIN), 4);
    let (mut tcb, _) = TcpTcb::from_syn(syn_fin, SeqNumber::new(1_000), 4).unwrap();
    assert_eq!(tcb.advertised_right_edge(), SeqNumber::new(4));

    let with_fin = tcb
        .on_segment(segment(5, Some(1_001), TcpFlags::ACK, 0))
        .unwrap();
    assert!(!with_fin.contains(&TcpAction::Accepted));
    let completed = tcb
        .on_segment(segment(4, Some(1_001), TcpFlags::ACK, 0))
        .unwrap();
    assert!(completed.contains(&TcpAction::Accepted));
    assert!(completed.contains(&TcpAction::DeliverPayload { len: 4 }));
    assert!(!completed.contains(&TcpAction::PeerHalfClosed));
    assert_eq!(tcb.state(), TcpState::Established);
    assert_eq!(tcb.recv_next(), SeqNumber::new(4));
    assert_eq!(tcb.advertised_right_edge(), tcb.recv_next());
}

#[test]
fn receive_window_update_avoids_silly_window_growth() {
    let mut tcb = established(8);
    tcb.on_segment(segment(101, Some(1_001), TcpFlags::ACK, 8))
        .unwrap();
    assert_eq!(tcb.advertised_window(), 0);

    for _ in 0..3 {
        assert!(tcb.on_app_event(AppEvent::Consumed(1)).unwrap().is_empty());
        assert_eq!(tcb.advertised_window(), 0);
    }
    let update = tcb.on_app_event(AppEvent::Consumed(1)).unwrap();
    assert!(update
        .iter()
        .any(|action| matches!(action, TcpAction::Send(_))));
    assert_eq!(tcb.advertised_window(), 4);
}

#[test]
fn out_of_order_payload_is_acknowledged_but_not_delivered() {
    let mut tcb = established(1_000);
    let actions = tcb
        .on_segment(segment(102, Some(1_001), TcpFlags::ACK, 10))
        .unwrap();
    assert_eq!(tcb.recv_next(), SeqNumber::new(101));
    assert_eq!(tcb.recv_buffered(), 0);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], TcpAction::DefensiveAck(_)));
}

#[test]
fn sends_pipeline_up_to_the_current_peer_window() {
    let mut tcb = established(1_000);
    assert_eq!(tcb.send_available(), 4_380);
    tcb.on_app_event(AppEvent::Send(3_000)).unwrap();
    tcb.on_app_event(AppEvent::Send(1_380)).unwrap();
    assert_eq!(tcb.send_available(), 0);
    assert_eq!(
        tcb.on_app_event(AppEvent::Send(1)),
        Err(TcpError::SendWindowExceeded)
    );

    tcb.on_segment(segment(101, Some(2_001), TcpFlags::ACK, 0))
        .unwrap();
    assert_eq!(tcb.send_available(), 2_000);
}

#[test]
fn newreno_fast_retransmits_after_three_duplicate_acks() {
    let mut tcb = established(1_000);
    tcb.on_app_event(AppEvent::Send(1_000)).unwrap();
    for _ in 0..2 {
        assert!(!tcb
            .on_segment(segment(101, Some(1_001), TcpFlags::ACK, 0))
            .unwrap()
            .iter()
            .any(|action| matches!(action, TcpAction::RetransmitPayload(_))));
    }
    assert!(tcb
        .on_segment(segment(101, Some(1_001), TcpFlags::ACK, 0))
        .unwrap()
        .iter()
        .any(|action| matches!(action, TcpAction::RetransmitPayload(_))));
    assert_eq!(tcb.congestion_window(), 7_300);
}

#[test]
fn newreno_partial_ack_deflates_current_recovery_window_by_net_acked_bytes() {
    let mut congestion = NewReno::new(1_000);
    let recover = SeqNumber::new(20_000);
    for duplicate in 0..3 {
        assert_eq!(congestion.on_duplicate_ack(10_000, recover), duplicate == 2);
    }
    assert_eq!(congestion.window(), 8_000);

    assert!(!congestion.on_duplicate_ack(10_000, recover));
    assert_eq!(congestion.window(), 9_000);
    assert!(congestion.on_new_ack(1_000, SeqNumber::new(15_000)));
    assert_eq!(congestion.window(), 9_000);

    assert!(!congestion.on_new_ack(5_000, recover));
    assert_eq!(congestion.window(), 5_000);
}

#[test]
fn newreno_extreme_mss_arithmetic_saturates() {
    let mut congestion = NewReno::new(usize::MAX);
    assert_eq!(congestion.window(), usize::MAX);
    assert!(!congestion.on_duplicate_ack(usize::MAX, SeqNumber::new(1)));
    assert!(!congestion.on_duplicate_ack(usize::MAX, SeqNumber::new(1)));
    assert!(congestion.on_duplicate_ack(usize::MAX, SeqNumber::new(1)));
    assert_eq!(congestion.slow_start_threshold(), usize::MAX);
    assert_eq!(congestion.window(), usize::MAX);
}

#[test]
fn limited_transmit_opens_one_mss_for_each_of_the_first_two_duplicate_acks() {
    let syn = segment(100, None, TcpFlags::SYN, 0);
    let (mut tcb, _) = TcpTcb::from_syn_with_mss(syn, SeqNumber::new(1_000), 8_000, 1_000).unwrap();
    tcb.on_segment(segment(101, Some(1_001), TcpFlags::ACK, 0))
        .unwrap();
    for _ in 0..4 {
        tcb.on_app_event(AppEvent::Send(1_000)).unwrap();
    }
    assert_eq!(tcb.send_available(), 0);

    let duplicate = segment(101, Some(1_001), TcpFlags::ACK, 0);
    let first = tcb.on_segment(duplicate).unwrap();
    assert!(!first
        .iter()
        .any(|action| matches!(action, TcpAction::RetransmitPayload(_))));
    assert_eq!(tcb.send_available(), 1_000);
    tcb.on_app_event(AppEvent::Send(1_000)).unwrap();

    let second = tcb.on_segment(duplicate).unwrap();
    assert!(!second
        .iter()
        .any(|action| matches!(action, TcpAction::RetransmitPayload(_))));
    assert_eq!(tcb.send_available(), 1_000);
    tcb.on_app_event(AppEvent::Send(1_000)).unwrap();

    let third = tcb.on_segment(duplicate).unwrap();
    assert!(third
        .iter()
        .any(|action| matches!(action, TcpAction::RetransmitPayload(_))));
    assert_eq!(tcb.send_available(), 0);
}

#[test]
fn sack_recovery_sets_cwnd_to_half_flight_instead_of_duplicate_ack_inflation() {
    let mut congestion = NewReno::new(1_000);
    assert!(congestion.on_sack_loss(10_000, SeqNumber::new(20_000)));
    assert_eq!(congestion.slow_start_threshold(), 5_000);
    assert_eq!(congestion.window(), 5_000);
    assert!(!congestion.on_sack_loss(10_000, SeqNumber::new(20_000)));
}

#[test]
fn passive_half_close_then_application_close_reaches_closed() {
    let mut tcb = established(1_000);
    let actions = tcb
        .on_segment(segment(
            101,
            Some(1_001),
            TcpFlags::ACK.union(TcpFlags::FIN),
            0,
        ))
        .unwrap();
    assert_eq!(tcb.state(), TcpState::CloseWait);
    assert!(actions.contains(&TcpAction::PeerHalfClosed));
    let after_fin = tcb
        .on_segment(segment(102, Some(1_001), TcpFlags::ACK, 3))
        .unwrap();
    assert_eq!(tcb.recv_next(), SeqNumber::new(102));
    assert_eq!(tcb.recv_buffered(), 0);
    assert!(after_fin
        .iter()
        .any(|action| matches!(action, TcpAction::DefensiveAck(_))));
    assert!(!after_fin
        .iter()
        .any(|action| matches!(action, TcpAction::DeliverPayload { .. })));
    tcb.on_app_event(AppEvent::Close).unwrap();
    assert_eq!(tcb.state(), TcpState::LastAck);
    assert!(tcb
        .on_segment(segment(102, Some(1_002), TcpFlags::ACK, 0))
        .unwrap()
        .contains(&TcpAction::Closed));
    assert_eq!(tcb.state(), TcpState::Closed);
}

#[test]
fn active_close_and_peer_fin_enter_and_expire_time_wait() {
    let mut tcb = established(1_000);
    tcb.on_app_event(AppEvent::Close).unwrap();
    assert_eq!(tcb.state(), TcpState::FinWait1);
    tcb.on_segment(segment(101, Some(1_002), TcpFlags::ACK, 0))
        .unwrap();
    assert_eq!(tcb.state(), TcpState::FinWait2);
    let actions = tcb
        .on_segment(segment(
            101,
            Some(1_002),
            TcpFlags::ACK.union(TcpFlags::FIN),
            0,
        ))
        .unwrap();
    assert_eq!(tcb.state(), TcpState::TimeWait);
    assert!(actions.contains(&TcpAction::ArmTimeWait));
    assert!(tcb
        .on_timer(TimerEvent::TimeWaitExpired)
        .unwrap()
        .contains(&TcpAction::Closed));
}

#[test]
fn closing_rto_retransmits_data_before_the_fin_sequence() {
    let mut tcb = established(4_096);
    tcb.on_app_event(AppEvent::Send(100)).unwrap();
    let close = tcb.on_app_event(AppEvent::Close).unwrap();
    assert_eq!(tcb.state(), TcpState::FinWait1);
    assert!(close.iter().any(|action| matches!(
        action,
        TcpAction::Send(control)
            if control.flags.contains(TcpFlags::FIN)
                && control.sequence == SeqNumber::new(1_101)
    )));
    assert!(tcb.on_sack_loss().iter().any(|action| matches!(
        action,
        TcpAction::RetransmitPayload(control)
            if control.sequence == SeqNumber::new(1_001)
                && !control.flags.contains(TcpFlags::FIN)
    )));

    let data_timeout = tcb.on_timer(TimerEvent::Retransmission).unwrap();
    assert!(data_timeout.iter().any(|action| matches!(
        action,
        TcpAction::RetransmitPayload(control)
            if control.sequence == SeqNumber::new(1_001)
                && !control.flags.contains(TcpFlags::FIN)
    )));

    tcb.on_segment(segment(101, Some(1_101), TcpFlags::ACK, 0))
        .unwrap();
    assert_eq!(tcb.state(), TcpState::FinWait1);
    let fin_timeout = tcb.on_timer(TimerEvent::Retransmission).unwrap();
    assert!(fin_timeout.iter().any(|action| matches!(
        action,
        TcpAction::Send(control)
            if control.flags.contains(TcpFlags::FIN)
                && control.sequence == SeqNumber::new(1_101)
    )));
    assert!(!fin_timeout
        .iter()
        .any(|action| matches!(action, TcpAction::RetransmitPayload(_))));
}

#[test]
fn simultaneous_close_waits_for_our_fin_ack_before_time_wait() {
    let mut tcb = established(1_000);
    tcb.on_app_event(AppEvent::Close).unwrap();
    assert_eq!(tcb.state(), TcpState::FinWait1);

    // The peer FIN acknowledges only pre-FIN sequence space, so both sides
    // have closed but our FIN is still outstanding.
    let actions = tcb
        .on_segment(segment(
            101,
            Some(1_001),
            TcpFlags::ACK.union(TcpFlags::FIN),
            0,
        ))
        .unwrap();
    assert_eq!(tcb.state(), TcpState::Closing);
    assert!(actions.contains(&TcpAction::PeerHalfClosed));
    assert!(!actions.contains(&TcpAction::ArmTimeWait));

    let actions = tcb
        .on_segment(segment(102, Some(1_002), TcpFlags::ACK, 0))
        .unwrap();
    assert_eq!(tcb.state(), TcpState::TimeWait);
    assert!(actions.contains(&TcpAction::ArmTimeWait));
}

#[test]
fn rst_is_accepted_exactly_challenged_in_window_and_dropped_outside() {
    let mut tcb = established(1_000);
    assert!(tcb
        .on_segment(segment(50_000, None, TcpFlags::RST, 0))
        .unwrap()
        .is_empty());
    assert_eq!(
        tcb.on_segment(segment(102, None, TcpFlags::RST, 0))
            .unwrap(),
        [TcpAction::ChallengeAck]
    );
    assert!(tcb
        .on_segment(segment(101, None, TcpFlags::RST, 0))
        .unwrap()
        .contains(&TcpAction::Closed));
}

#[test]
fn sequence_comparisons_work_across_wrap() {
    let before_wrap = SeqNumber::new(u32::MAX - 2);
    let after_wrap = before_wrap.wrapping_add(5);
    assert!(before_wrap.before(after_wrap));
    assert!(after_wrap.after(before_wrap));
    assert_eq!(after_wrap.distance_from(before_wrap), 5);
}

#[test]
fn rto_estimator_clamps_and_backs_off() {
    let mut rto = RtoEstimator::default();
    assert_eq!(rto.rto_ms(), 1_000);
    rto.record_sample(100);
    assert_eq!(rto.smoothed_rtt_ms(), Some(100));
    assert_eq!(rto.rto_ms(), 1_000);
    rto.backoff();
    assert_eq!(rto.rto_ms(), 2_000);
    for _ in 0..10 {
        rto.backoff();
    }
    assert_eq!(rto.rto_ms(), 60_000);
}

fn sent_control(actions: &[TcpAction]) -> SendControl {
    actions
        .iter()
        .find_map(|action| match action {
            TcpAction::Send(control) => Some(*control),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no control segment in {actions:?}"))
}

/// An active open whose SYN (ISS 1000) was answered by the peer's SYN-ACK
/// (IRS 5000, window 8192), so both directions are open.
fn connected(capacity: usize) -> TcpTcb {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), capacity, 1_000, 0);
    let actions = tcb
        .on_segment(segment_with_window(
            5_000,
            Some(1_001),
            TcpFlags::SYN.union(TcpFlags::ACK),
            8_192,
            0,
        ))
        .unwrap();
    assert!(actions.contains(&TcpAction::Connected));
    tcb
}

#[test]
fn connect_sends_an_unscaled_syn_and_waits_in_syn_sent() {
    let (tcb, actions) = TcpTcb::connect(SeqNumber::new(1_000), 256 * 1024, 1_000, 3);
    assert_eq!(tcb.state(), TcpState::SynSent);
    assert!(tcb.is_active_open());
    let syn = sent_control(&actions);
    assert_eq!(syn.flags, TcpFlags::SYN);
    assert_eq!(syn.sequence, SeqNumber::new(1_000));
    // RFC 7323 2.2: the window of a SYN is never scaled.
    assert_eq!(syn.window, u16::MAX);
    assert!(actions.contains(&TcpAction::ArmRetransmission { after_ms: 1_000 }));
    assert_eq!(tcb.send_unacked(), SeqNumber::new(1_000));
    assert_eq!(tcb.send_next(), SeqNumber::new(1_001));
}

#[test]
fn syn_ack_completes_an_active_open_and_opens_both_directions() {
    let mut tcb = connected(4_096);
    assert_eq!(tcb.state(), TcpState::Established);
    assert_eq!(tcb.recv_next(), SeqNumber::new(5_001));
    assert_eq!(tcb.send_unacked(), SeqNumber::new(1_001));
    assert_eq!(tcb.peer_window(), 8_192);

    let sent = tcb.on_app_event(AppEvent::Send(100)).unwrap();
    assert!(sent.iter().any(|action| matches!(
        action,
        TcpAction::SendPayload(control) if control.sequence == SeqNumber::new(1_001)
    )));
    let received = tcb
        .on_segment(segment(5_001, Some(1_101), TcpFlags::ACK, 10))
        .unwrap();
    assert!(received.contains(&TcpAction::DeliverPayload { len: 10 }));
    assert_eq!(tcb.send_unacked(), SeqNumber::new(1_101));
    assert_eq!(tcb.recv_next(), SeqNumber::new(5_011));
}

#[test]
fn syn_ack_confirmation_acknowledges_the_peer_syn() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    let actions = tcb
        .on_segment(segment(
            5_000,
            Some(1_001),
            TcpFlags::SYN.union(TcpFlags::ACK),
            0,
        ))
        .unwrap();
    let ack = sent_control(&actions);
    assert_eq!(ack.flags, TcpFlags::ACK);
    assert_eq!(ack.sequence, SeqNumber::new(1_001));
    assert_eq!(ack.acknowledgment, SeqNumber::new(5_001));
    assert!(actions.contains(&TcpAction::DisarmRetransmission));
}

#[test]
fn syn_sent_resets_an_unacceptable_ack_without_changing_state() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    for bad_ack in [1_000, 1_002, 999] {
        let actions = tcb
            .on_segment(segment(
                5_000,
                Some(bad_ack),
                TcpFlags::SYN.union(TcpFlags::ACK),
                0,
            ))
            .unwrap();
        let reset = sent_control(&actions);
        assert_eq!(reset.flags, TcpFlags::RST);
        assert_eq!(reset.sequence, SeqNumber::new(bad_ack));
        assert_eq!(tcb.state(), TcpState::SynSent);
    }
    // A reset is never answered with a reset.
    assert!(tcb
        .on_segment(segment(
            5_000,
            Some(1_002),
            TcpFlags::RST.union(TcpFlags::ACK),
            0
        ))
        .unwrap()
        .is_empty());
    assert_eq!(tcb.state(), TcpState::SynSent);
}

#[test]
fn syn_sent_takes_only_a_reset_that_acknowledges_the_syn() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    // Without an ACK a reset cannot be told from a forgery.
    assert!(tcb
        .on_segment(segment(5_000, None, TcpFlags::RST, 0))
        .unwrap()
        .is_empty());
    assert_eq!(tcb.state(), TcpState::SynSent);

    let refused = tcb
        .on_segment(segment(
            0,
            Some(1_001),
            TcpFlags::RST.union(TcpFlags::ACK),
            0,
        ))
        .unwrap();
    assert!(refused.contains(&TcpAction::Closed));
    assert_eq!(tcb.state(), TcpState::Closed);
}

#[test]
fn syn_sent_ignores_segments_without_syn_or_reset() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    for flags in [TcpFlags::ACK, TcpFlags::ACK.union(TcpFlags::FIN)] {
        assert!(tcb
            .on_segment(segment(5_000, Some(1_001), flags, 10))
            .unwrap()
            .is_empty());
    }
    assert!(tcb
        .on_segment(segment(5_000, None, TcpFlags::default(), 10))
        .unwrap()
        .is_empty());
    assert_eq!(tcb.state(), TcpState::SynSent);
}

#[test]
fn syn_sent_retransmits_the_syn_with_backoff() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    let first = tcb.on_timer(TimerEvent::Retransmission).unwrap();
    let syn = sent_control(&first);
    assert_eq!(syn.flags, TcpFlags::SYN);
    assert_eq!(syn.sequence, SeqNumber::new(1_000));
    assert!(first.contains(&TcpAction::ArmRetransmission { after_ms: 2_000 }));
    let second = tcb.on_timer(TimerEvent::Retransmission).unwrap();
    assert!(second.contains(&TcpAction::ArmRetransmission { after_ms: 4_000 }));
    assert_eq!(tcb.state(), TcpState::SynSent);
}

#[test]
fn closing_or_aborting_in_syn_sent_sends_nothing() {
    for event in [AppEvent::Close, AppEvent::Abort] {
        let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
        let actions = tcb.on_app_event(event).unwrap();
        assert!(actions.contains(&TcpAction::Closed));
        assert!(!actions
            .iter()
            .any(|action| matches!(action, TcpAction::Send(_))));
        assert_eq!(tcb.state(), TcpState::Closed);
    }
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    assert_eq!(
        tcb.on_app_event(AppEvent::Send(1)),
        Err(TcpError::InvalidSendState)
    );
}

#[test]
fn simultaneous_open_completes_on_the_peer_syn_ack() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    // The peer's own SYN crosses ours.
    let crossed = tcb
        .on_segment(segment(5_000, None, TcpFlags::SYN, 0))
        .unwrap();
    assert_eq!(tcb.state(), TcpState::SynReceived);
    let syn_ack = sent_control(&crossed);
    assert_eq!(syn_ack.flags, TcpFlags::SYN.union(TcpFlags::ACK));
    assert_eq!(syn_ack.sequence, SeqNumber::new(1_000));
    assert_eq!(syn_ack.acknowledgment, SeqNumber::new(5_001));

    // The peer answered our SYN from its SYN-RECEIVED (RFC 9293 figure 8).
    let completed = tcb
        .on_segment(segment(
            5_000,
            Some(1_001),
            TcpFlags::SYN.union(TcpFlags::ACK),
            0,
        ))
        .unwrap();
    assert!(completed.contains(&TcpAction::Connected));
    assert!(!completed.contains(&TcpAction::Accepted));
    assert_eq!(tcb.state(), TcpState::Established);
    assert_eq!(tcb.recv_next(), SeqNumber::new(5_001));
    assert_eq!(tcb.send_unacked(), SeqNumber::new(1_001));
}

#[test]
fn simultaneous_open_also_completes_on_a_plain_ack() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    tcb.on_segment(segment(5_000, None, TcpFlags::SYN, 0))
        .unwrap();
    let completed = tcb
        .on_segment(segment(5_001, Some(1_001), TcpFlags::ACK, 0))
        .unwrap();
    assert!(completed.contains(&TcpAction::Connected));
    assert_eq!(tcb.state(), TcpState::Established);
}

#[test]
fn simultaneous_open_retransmits_its_syn_ack() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    tcb.on_segment(segment(5_000, None, TcpFlags::SYN, 0))
        .unwrap();
    let retransmitted = tcb.on_timer(TimerEvent::Retransmission).unwrap();
    let syn_ack = sent_control(&retransmitted);
    assert_eq!(syn_ack.flags, TcpFlags::SYN.union(TcpFlags::ACK));
    assert_eq!(syn_ack.sequence, SeqNumber::new(1_000));
}

#[test]
fn active_open_sequence_numbers_wrap() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(u32::MAX), 4_096, 1_000, 0);
    assert_eq!(tcb.send_next(), SeqNumber::new(0));
    let actions = tcb
        .on_segment(segment(
            u32::MAX,
            Some(0),
            TcpFlags::SYN.union(TcpFlags::ACK),
            0,
        ))
        .unwrap();
    assert!(actions.contains(&TcpAction::Connected));
    assert_eq!(tcb.recv_next(), SeqNumber::new(0));
    assert_eq!(sent_control(&actions).acknowledgment, SeqNumber::new(0));
}

#[test]
fn syn_ack_data_and_fin_wait_for_the_peer_to_resend_them() {
    let (mut tcb, _) = TcpTcb::connect(SeqNumber::new(1_000), 4_096, 1_000, 0);
    let actions = tcb
        .on_segment(segment(
            5_000,
            Some(1_001),
            TcpFlags::SYN.union(TcpFlags::ACK).union(TcpFlags::FIN),
            20,
        ))
        .unwrap();
    assert!(actions.contains(&TcpAction::Connected));
    assert!(!actions
        .iter()
        .any(|action| matches!(action, TcpAction::DeliverPayload { .. })));
    assert!(!actions.contains(&TcpAction::PeerHalfClosed));
    // Only the SYN is acknowledged, so the peer sends the rest again.
    assert_eq!(sent_control(&actions).acknowledgment, SeqNumber::new(5_001));
    assert_eq!(tcb.state(), TcpState::Established);
    let resent = tcb
        .on_segment(segment(5_001, Some(1_001), TcpFlags::ACK, 20))
        .unwrap();
    assert!(resent.contains(&TcpAction::DeliverPayload { len: 20 }));
}
