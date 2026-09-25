use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use sail_netstack::{
    emit_tcp_control, parse_ip_packet, parse_tcp_segment, SendControl, SeqNumber, TcpFlags,
    WireError,
};

#[test]
fn ipv4_and_ipv6_control_segments_round_trip() {
    let pairs = [
        (
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 443)),
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 50_000)),
        ),
        (
            SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 50_000)),
        ),
    ];
    let control = SendControl {
        sequence: SeqNumber::new(100),
        acknowledgment: SeqNumber::new(200),
        flags: TcpFlags::SYN.union(TcpFlags::ACK),
        window: 32_000,
    };
    for (source, destination) in pairs {
        let packet = emit_tcp_control(source, destination, control, 64, 7).unwrap();
        let parsed = parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true).unwrap();
        assert_eq!(parsed.source, source);
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.meta.sequence, control.sequence);
        assert_eq!(parsed.meta.acknowledgment, Some(control.acknowledgment));
        assert_eq!(parsed.meta.flags, control.flags);
        assert_eq!(parsed.meta.window, u32::from(control.window));
        assert!(parsed.payload.is_empty());
    }
}

#[test]
fn parses_bounded_syn_options() {
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv4Addr::BROADCAST, 20));
    let control = SendControl {
        sequence: SeqNumber::new(1),
        acknowledgment: SeqNumber::new(0),
        flags: TcpFlags::SYN,
        window: 1_000,
    };
    let base = emit_tcp_control(source, destination, control, 64, 1).unwrap();
    let mut packet = vec![0_u8; base.len() + 20];
    packet[..20].copy_from_slice(&base[..20]);
    packet[2..4].copy_from_slice(&60_u16.to_be_bytes());
    packet[20..40].copy_from_slice(&base[20..40]);
    packet[32] = 10 << 4;
    packet[40..60].copy_from_slice(&[
        2, 4, 0x05, 0xb4, 3, 3, 7, 4, 2, 1, 8, 10, 0, 0, 0, 9, 0, 0, 0, 0,
    ]);
    // Recompute by using parser without checksum; checksum behavior is covered by round-trip.
    let parsed = parse_tcp_segment(parse_ip_packet(&packet, false).unwrap(), false).unwrap();
    assert_eq!(parsed.options.maximum_segment_size, Some(1_460));
    assert_eq!(parsed.options.window_scale, Some(7));
    assert!(parsed.options.sack_permitted);
    assert_eq!(parsed.options.timestamps, Some((9, 0)));
}

#[test]
fn oversized_window_scale_is_clamped_to_protocol_maximum() {
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv4Addr::BROADCAST, 20));
    let packet = sail_netstack::emit_tcp_segment_with_options(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(1),
            acknowledgment: SeqNumber::new(0),
            flags: TcpFlags::SYN,
            window: 1,
        },
        &[3, 3, u8::MAX, 1],
        &[],
        64,
        1,
    )
    .unwrap();
    let parsed = parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true).unwrap();
    assert_eq!(parsed.options.window_scale, Some(14));
    assert!(parsed.options.window_scale_clamped);
}

#[test]
fn malformed_options_and_checksum_corruption_fail_closed() {
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv4Addr::BROADCAST, 20));
    let control = SendControl {
        sequence: SeqNumber::new(1),
        acknowledgment: SeqNumber::new(2),
        flags: TcpFlags::ACK,
        window: 1_000,
    };
    let mut packet = emit_tcp_control(source, destination, control, 64, 1).unwrap();
    packet[39] ^= 1;
    assert_eq!(
        parse_tcp_segment(parse_ip_packet(&packet, true).unwrap(), true),
        Err(WireError::Checksum)
    );

    let mut malformed = emit_tcp_control(source, destination, control, 64, 1).unwrap();
    malformed.extend_from_slice(&[2, 1, 0, 0]);
    malformed[2..4].copy_from_slice(&44_u16.to_be_bytes());
    malformed[32] = 6 << 4;
    assert!(matches!(
        parse_tcp_segment(parse_ip_packet(&malformed, false).unwrap(), false),
        Err(WireError::Malformed(_))
    ));

    let mut nonzero_padding = emit_tcp_control(source, destination, control, 64, 1).unwrap();
    nonzero_padding.extend_from_slice(&[0, 1, 0, 0]);
    nonzero_padding[2..4].copy_from_slice(&44_u16.to_be_bytes());
    nonzero_padding[32] = 6 << 4;
    assert_eq!(
        parse_tcp_segment(parse_ip_packet(&nonzero_padding, false).unwrap(), false),
        Err(WireError::Malformed("nonzero TCP option padding"))
    );
}

#[test]
fn receiver_ignores_reserved_bits_while_emitter_keeps_them_zero() {
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv4Addr::BROADCAST, 20));
    let control = SendControl {
        sequence: SeqNumber::new(1),
        acknowledgment: SeqNumber::new(2),
        flags: TcpFlags::ACK,
        window: 1_000,
    };
    let mut packet = emit_tcp_control(source, destination, control, 64, 1).unwrap();
    assert_eq!(packet[32] & 0x0f, 0);

    packet[32] |= 0x0f;
    let parsed = parse_tcp_segment(parse_ip_packet(&packet, false).unwrap(), false).unwrap();
    assert_eq!(parsed.meta.sequence, control.sequence);
    assert_eq!(parsed.meta.acknowledgment, Some(control.acknowledgment));
    assert_eq!(parsed.meta.flags, control.flags);
}

#[test]
fn every_truncation_is_rejected_without_panicking() {
    let packet = emit_tcp_control(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 1)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 2)),
        SendControl {
            sequence: SeqNumber::new(1),
            acknowledgment: SeqNumber::new(2),
            flags: TcpFlags::ACK,
            window: 3,
        },
        64,
        0,
    )
    .unwrap();
    for end in 0..packet.len() {
        if let Ok(ip) = parse_ip_packet(&packet[..end], false) {
            assert!(parse_tcp_segment(ip, false).is_err());
        }
    }
}
