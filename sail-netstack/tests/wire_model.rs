use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use sail_netstack::{
    emit_udp_packet, parse_icmp_packet, parse_ip_packet, parse_tcp_segment, parse_udp_datagram,
    IpVersion, WireError,
};

#[test]
fn ipv4_udp_round_trip_and_checksum_failure() {
    let source = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 52_000));
    let destination = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
    let mut packet = emit_udp_packet(source, destination, b"query", 64, 7).unwrap();
    let ip = parse_ip_packet(&packet, true).unwrap();
    assert_eq!(ip.version, IpVersion::V4);
    let udp = parse_udp_datagram(ip, true).unwrap();
    assert_eq!(udp.source, source);
    assert_eq!(udp.destination, destination);
    assert_eq!(udp.payload, b"query");

    *packet.last_mut().unwrap() ^= 1;
    let ip = parse_ip_packet(&packet, true).unwrap();
    assert_eq!(parse_udp_datagram(ip, true), Err(WireError::Checksum));
}

#[test]
fn ipv6_udp_round_trip_requires_checksum() {
    let source = SocketAddr::from((Ipv6Addr::LOCALHOST, 1_000));
    let destination = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 2_000));
    let mut packet = emit_udp_packet(source, destination, b"hello-v6", 32, 0).unwrap();
    let ip = parse_ip_packet(&packet, false).unwrap();
    assert_eq!(parse_udp_datagram(ip, true).unwrap().payload, b"hello-v6");
    packet[46] = 0;
    packet[47] = 0;
    let ip = parse_ip_packet(&packet, false).unwrap();
    assert_eq!(parse_udp_datagram(ip, true), Err(WireError::Checksum));
}

#[test]
fn fragmented_udp_is_not_delivered_before_reassembly() {
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv4Addr::BROADCAST, 20));
    let mut packet = emit_udp_packet(source, destination, b"fragment", 64, 42).unwrap();
    packet[6] = 0x20;
    packet[10] = 0;
    packet[11] = 0;
    // Parsing without header verification lets this test focus on reassembly gating.
    let ip = parse_ip_packet(&packet, false).unwrap();
    assert!(ip.fragment.is_some());
    assert!(matches!(
        parse_udp_datagram(ip, false),
        Err(WireError::Unsupported(_))
    ));
}

#[test]
fn ipv4_rejects_reserved_and_df_fragment_flag_combinations() {
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv4Addr::BROADCAST, 20));
    let packet = emit_udp_packet(source, destination, b"fragment", 64, 42).unwrap();

    let mut reserved = packet.clone();
    reserved[6] |= 0x80;
    assert_eq!(
        parse_ip_packet(&reserved, false),
        Err(WireError::Malformed("IPv4 reserved fragment flag"))
    );

    let mut fragmented_with_df = packet;
    fragmented_with_df[6] |= 0x20;
    assert_eq!(
        parse_ip_packet(&fragmented_with_df, false),
        Err(WireError::Malformed("IPv4 DF set on a fragment"))
    );
}

#[test]
fn ipv4_options_require_bounded_tlvs_and_zero_padding() {
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv4Addr::BROADCAST, 20));
    let packet = emit_udp_packet(source, destination, b"options", 64, 42).unwrap();
    let with_options = |options: [u8; 4]| {
        let mut extended = Vec::with_capacity(packet.len() + options.len());
        extended.extend_from_slice(&packet[..20]);
        extended.extend_from_slice(&options);
        extended.extend_from_slice(&packet[20..]);
        extended[0] = 0x46;
        let total_len = u16::try_from(extended.len()).unwrap();
        extended[2..4].copy_from_slice(&total_len.to_be_bytes());
        extended
    };

    assert!(parse_ip_packet(&with_options([1, 0, 0, 0]), false).is_ok());
    assert_eq!(
        parse_ip_packet(&with_options([0x83, 5, 0, 0]), false),
        Err(WireError::Malformed("truncated IPv4 option"))
    );
    assert_eq!(
        parse_ip_packet(&with_options([0x83, 1, 0, 0]), false),
        Err(WireError::Malformed("invalid IPv4 option length"))
    );
    assert_eq!(
        parse_ip_packet(&with_options([0, 1, 0, 0]), false),
        Err(WireError::Malformed("nonzero IPv4 option padding"))
    );
}

#[test]
fn ipv6_ignores_fragment_header_reserved_fields() {
    let source = SocketAddr::from((Ipv6Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 20));
    let packet = emit_udp_packet(source, destination, b"fragment", 64, 0).unwrap();
    let mut fragment = packet[..40].to_vec();
    fragment[6] = 44;
    fragment.extend_from_slice(&[17, 0xff, 0, 0x06, 0, 0, 0, 7]);
    fragment.extend_from_slice(&packet[40..]);
    let payload_len = u16::try_from(fragment.len() - 40).unwrap();
    fragment[4..6].copy_from_slice(&payload_len.to_be_bytes());
    let ip = parse_ip_packet(&fragment, true).unwrap();
    assert!(ip.fragment.unwrap().is_atomic());
    assert_eq!(parse_udp_datagram(ip, true).unwrap().payload, b"fragment");
}

#[test]
fn ipv6_rejects_multiple_fragment_headers() {
    let source = SocketAddr::from((Ipv6Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 20));
    let packet = emit_udp_packet(source, destination, b"fragment", 64, 0).unwrap();
    let mut nested = packet[..40].to_vec();
    nested[6] = 44;
    nested.extend_from_slice(&[44, 0, 0, 0, 0, 0, 0, 7]);
    nested.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 8]);
    nested.extend_from_slice(&packet[40..]);
    let payload_len = u16::try_from(nested.len() - 40).unwrap();
    nested[4..6].copy_from_slice(&payload_len.to_be_bytes());
    assert_eq!(
        parse_ip_packet(&nested, false),
        Err(WireError::Malformed("multiple IPv6 fragment headers"))
    );
}

#[test]
fn ipv6_reports_hop_by_hop_header_after_an_extension() {
    let mut packet = vec![0_u8; 64];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&24_u16.to_be_bytes());
    packet[6] = 60;
    packet[7] = 64;
    packet[40] = 0;
    packet[48] = 17;
    packet[56..58].copy_from_slice(&1_u16.to_be_bytes());
    packet[58..60].copy_from_slice(&2_u16.to_be_bytes());
    packet[60..62].copy_from_slice(&8_u16.to_be_bytes());
    assert_eq!(
        parse_ip_packet(&packet, false),
        Err(WireError::Ipv6NextHeaderDiscard { pointer: 40 })
    );
}

#[test]
fn ipv6_unrecognized_routing_type_depends_on_segments_left() {
    let source = SocketAddr::from((Ipv6Addr::LOCALHOST, 10));
    let destination = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 20));
    let packet = emit_udp_packet(source, destination, b"routing", 64, 0).unwrap();
    let with_routing_header = |segments_left| {
        let mut routed = packet[..40].to_vec();
        routed[6] = 43;
        routed.extend_from_slice(&[17, 0, 255, segments_left, 0, 0, 0, 0]);
        routed.extend_from_slice(&packet[40..]);
        let payload_len = u16::try_from(routed.len() - 40).unwrap();
        routed[4..6].copy_from_slice(&payload_len.to_be_bytes());
        routed
    };

    let exhausted = with_routing_header(0);
    let ip = parse_ip_packet(&exhausted, true).unwrap();
    assert_eq!(parse_udp_datagram(ip, true).unwrap().payload, b"routing");
    assert_eq!(
        parse_ip_packet(&with_routing_header(1), true),
        Err(WireError::Ipv6RoutingDiscard { pointer: 42 })
    );
}

#[test]
fn ipv6_options_require_bounded_tlvs_zero_padn_and_supported_actions() {
    let packet_with_options = |options: [u8; 6]| {
        let mut packet = vec![0_u8; 56];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16_u16.to_be_bytes());
        packet[6] = 60;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = 17;
        packet[41] = 0;
        packet[42..48].copy_from_slice(&options);
        packet[48..50].copy_from_slice(&1_u16.to_be_bytes());
        packet[50..52].copy_from_slice(&2_u16.to_be_bytes());
        packet[52..54].copy_from_slice(&8_u16.to_be_bytes());
        packet
    };

    let valid = packet_with_options([0, 1, 2, 0, 0, 0]);
    let ip = parse_ip_packet(&valid, false).unwrap();
    assert!(parse_udp_datagram(ip, false).is_ok());
    assert_eq!(
        parse_ip_packet(&packet_with_options([5, 5, 0, 0, 0, 0]), false),
        Err(WireError::Malformed("truncated IPv6 option"))
    );
    assert_eq!(
        parse_ip_packet(&packet_with_options([1, 2, 0, 1, 0, 0]), false),
        Err(WireError::Malformed("nonzero IPv6 PadN data"))
    );
    assert_eq!(
        parse_ip_packet(&packet_with_options([0x40, 0, 0, 0, 0, 0]), false),
        Err(WireError::Ipv6OptionDiscard {
            pointer: 42,
            send_icmp: false
        })
    );
    assert_eq!(
        parse_ip_packet(&packet_with_options([0x80, 0, 0, 0, 0, 0]), false),
        Err(WireError::Ipv6OptionDiscard {
            pointer: 42,
            send_icmp: true
        })
    );
    assert_eq!(
        parse_ip_packet(&packet_with_options([0xc0, 0, 0, 0, 0, 0]), false),
        Err(WireError::Ipv6OptionDiscard {
            pointer: 42,
            send_icmp: true
        })
    );

    let mut multicast = packet_with_options([0xc0, 0, 0, 0, 0, 0]);
    multicast[24..40].copy_from_slice(&"ff02::1".parse::<Ipv6Addr>().unwrap().octets());
    assert_eq!(
        parse_ip_packet(&multicast, false),
        Err(WireError::Ipv6OptionDiscard {
            pointer: 42,
            send_icmp: false
        })
    );
    multicast[42] = 0x80;
    assert_eq!(
        parse_ip_packet(&multicast, false),
        Err(WireError::Ipv6OptionDiscard {
            pointer: 42,
            send_icmp: true
        })
    );
}

#[test]
fn all_truncations_and_random_bytes_fail_without_panicking() {
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 10)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 20)),
        b"payload",
        64,
        0,
    )
    .unwrap();
    for end in 0..packet.len() {
        assert!(parse_ip_packet(&packet[..end], true).is_err());
    }

    let mut seed = 0x23a9_e155_17c4_b29du64;
    for length in 0..512 {
        let mut bytes = vec![0_u8; length];
        for byte in &mut bytes {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *byte = seed.to_le_bytes()[3];
        }
        if let Ok(ip) = parse_ip_packet(&bytes, true) {
            let _ = parse_udp_datagram(ip, true);
        }
    }
}

#[test]
fn deterministic_arbitrary_packet_corpus_exercises_every_transport_parser() {
    let mut random = 0x9e37_79b9_7f4a_7c15_u64;
    let mut parsed_ip = 0_usize;
    let mut parsed_tcp = 0_usize;
    let mut parsed_udp = 0_usize;
    let mut parsed_icmp = 0_usize;
    for case in 0..4_096 {
        random = xorshift64(random);
        let length = usize::try_from(random % 2_049).unwrap();
        let mut bytes = vec![0_u8; length];
        for byte in &mut bytes {
            random = xorshift64(random);
            *byte = random.to_le_bytes()[3];
        }

        match case % 4 {
            0 if length >= 20 => {
                bytes[0] = 0x45;
                bytes[2..4].copy_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
                bytes[9] = [1, 6, 17][case % 3];
            }
            1 if length >= 40 => {
                bytes[0] = 0x60;
                bytes[4..6].copy_from_slice(&u16::try_from(length - 40).unwrap().to_be_bytes());
                bytes[6] = [6, 17, 58][case % 3];
            }
            2 if length >= 4 => {
                bytes[0] = 0x4f;
                let declared = u16::try_from((length + 63).min(usize::from(u16::MAX))).unwrap();
                bytes[2..4].copy_from_slice(&declared.to_be_bytes());
            }
            3 if length >= 6 => {
                bytes[0] = 0x60;
                bytes[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
            }
            _ => {}
        }

        if let Ok(ip) = parse_ip_packet(&bytes, false) {
            parsed_ip += 1;
            parsed_tcp += usize::from(parse_tcp_segment(ip, false).is_ok());
            parsed_udp += usize::from(parse_udp_datagram(ip, false).is_ok());
            parsed_icmp += usize::from(parse_icmp_packet(ip, false).is_ok());
        }
    }
    assert!(
        parsed_ip > 1_000,
        "corpus did not reach the IP payload boundary"
    );
    assert!(
        parsed_tcp > 0 && parsed_udp > 0 && parsed_icmp > 0,
        "corpus did not reach every transport payload boundary"
    );
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value << 13;
    value ^= value >> 7;
    value ^ (value << 17)
}

#[test]
fn ipv6_extension_chain_honors_its_exact_traversal_bound() {
    let accepted = ipv6_extension_packet(7);
    let ip = parse_ip_packet(&accepted, false).unwrap();
    assert_eq!(ip.next_header, 17);
    assert!(parse_udp_datagram(ip, false).is_ok());

    let rejected = ipv6_extension_packet(8);
    assert_eq!(
        parse_ip_packet(&rejected, false),
        Err(WireError::Unsupported("IPv6 extension chain exceeds limit"))
    );
}

fn ipv6_extension_packet(extension_count: usize) -> Vec<u8> {
    let payload_len = extension_count * 8 + 8;
    let mut packet = vec![0_u8; 40 + payload_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&u16::try_from(payload_len).unwrap().to_be_bytes());
    packet[6] = if extension_count == 0 { 17 } else { 60 };
    packet[7] = 64;
    for index in 0..extension_count {
        let offset = 40 + index * 8;
        packet[offset] = if index + 1 == extension_count { 17 } else { 60 };
    }
    let udp = 40 + extension_count * 8;
    packet[udp..udp + 2].copy_from_slice(&1_u16.to_be_bytes());
    packet[udp + 2..udp + 4].copy_from_slice(&2_u16.to_be_bytes());
    packet[udp + 4..udp + 6].copy_from_slice(&8_u16.to_be_bytes());
    packet
}

#[test]
fn mixed_address_families_are_rejected() {
    let result = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 2)),
        &[],
        64,
        0,
    );
    assert!(matches!(result, Err(WireError::Malformed(_))));
}
