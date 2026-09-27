#![no_main]

use libfuzzer_sys::fuzz_target;
use sail_netstack::{AppEvent, SeqNumber, TcpFlags, TcpSegmentMeta, TcpState, TcpTcb, TimerEvent};

const MAX_INPUT_LEN: usize = 4_096;
const OPERATION_BYTES: usize = 16;

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn assert_invariants(tcb: &TcpTcb, receive_capacity: usize, previous_right_edge: SeqNumber) {
    assert!(tcb.recv_buffered() <= receive_capacity);
    assert!(
        usize::try_from(tcb.advertised_right_edge().distance_from(tcb.recv_next()))
            .unwrap_or(usize::MAX)
            <= receive_capacity.saturating_sub(tcb.recv_buffered())
    );
    assert!(!tcb.advertised_right_edge().before(previous_right_edge));
    assert!(!tcb.send_next().before(tcb.send_unacked()));
    if tcb.state() == TcpState::SynSent {
        // Only the SYN is outstanding.
        assert_eq!(tcb.send_next(), tcb.send_unacked().wrapping_add(1));
    }
}

fuzz_target!(|input: &[u8]| {
    let data = &input[..input.len().min(MAX_INPUT_LEN)];
    if data.len() < OPERATION_BYTES {
        return;
    }

    let receive_capacity = usize::from(u16_at(data, 0)).max(1);
    let initial_payload = usize::from(u16_at(data, 2)) % (receive_capacity + 1);
    let initial_sequence = SeqNumber::new(u32_at(data, 4));
    let server_sequence = SeqNumber::new(u32_at(data, 8));
    let initial = TcpSegmentMeta {
        sequence: initial_sequence,
        acknowledgment: None,
        flags: if data[15] & 0x80 == 0 {
            TcpFlags::SYN
        } else {
            TcpFlags::SYN.union(TcpFlags::FIN)
        },
        window: u32::from(u16_at(data, 12)),
        payload_len: initial_payload,
    };
    // The low window bit selects an active open, whose initial window is
    // never used.
    let (mut tcb, _) = if data[12] & 1 == 0 {
        let Ok(passive) = TcpTcb::from_syn_with_options(
            initial,
            server_sequence,
            receive_capacity,
            usize::from(data[14]).max(1),
            data[15] % 15,
        ) else {
            return;
        };
        passive
    } else {
        TcpTcb::connect(
            server_sequence,
            receive_capacity,
            usize::from(data[14]).max(1),
            data[15] % 15,
        )
    };

    let mut previous_right_edge = tcb.advertised_right_edge();
    assert_invariants(&tcb, receive_capacity, previous_right_edge);
    for operation in data[OPERATION_BYTES..].as_chunks::<OPERATION_BYTES>().0 {
        let was_syn_sent = tcb.state() == TcpState::SynSent;
        let selector = operation[0] % 13;
        match selector {
            0..=4 => {
                let flags = TcpFlags::from_bits(operation[1]);
                // Bits 1 and 2 aim the ACK and sequence at the current edges,
                // so the handshakes and data paths are reached.
                let acknowledgment = (operation[2] & 1 != 0).then(|| {
                    if operation[2] & 2 == 0 {
                        SeqNumber::new(u32_at(operation, 7))
                    } else {
                        tcb.send_next()
                    }
                });
                let sequence = if operation[2] & 4 == 0 {
                    SeqNumber::new(u32_at(operation, 3))
                } else {
                    tcb.recv_next()
                };
                let segment = TcpSegmentMeta {
                    sequence,
                    acknowledgment,
                    flags,
                    window: u32_at(operation, 11),
                    payload_len: usize::from(operation[15])
                        .min(tcb.receive_available().saturating_add(1)),
                };
                let _ = tcb.on_segment(segment);
            }
            5 => {
                let amount = usize::from(u16_at(operation, 1));
                let _ = tcb.on_app_event(AppEvent::Consumed(amount));
            }
            6 => {
                let amount = usize::from(u16_at(operation, 1));
                let _ = tcb.on_app_event(AppEvent::Send(amount));
            }
            7 => {
                let _ = tcb.on_app_event(AppEvent::Close);
            }
            8 => {
                let _ = tcb.on_app_event(AppEvent::Abort);
            }
            9 => {
                let event = match operation[1] % 5 {
                    0 => TimerEvent::Retransmission,
                    1 => TimerEvent::DelayedAck,
                    2 => TimerEvent::Persist,
                    3 => TimerEvent::Keepalive,
                    _ => TimerEvent::TimeWaitExpired,
                };
                let _ = tcb.on_timer(event);
            }
            10 => tcb.record_rtt_sample(u64::from(u32_at(operation, 1))),
            11 => {
                let _ = tcb.on_sack_loss();
            }
            _ => {
                let _ = tcb.force_ack();
            }
        }
        // The receive sequence space starts at the peer's SYN, so the right
        // edge is only monotonic from the moment SYN-SENT is left.
        if was_syn_sent {
            previous_right_edge = tcb.advertised_right_edge();
        }
        assert_invariants(&tcb, receive_capacity, previous_right_edge);
        previous_right_edge = tcb.advertised_right_edge();
        if tcb.state() == TcpState::Closed {
            break;
        }
    }
});
