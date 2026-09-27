//! Packet builders shared by the tests of the stack's users.

use std::net::SocketAddr;

use sail_netstack::{emit_tcp_segment, SendControl, SeqNumber, TcpFlags};

pub(crate) fn tcp_packet(
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

pub(crate) fn tcp_packet_with_window(
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
