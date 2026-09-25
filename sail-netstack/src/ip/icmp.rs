use std::net::IpAddr;

use crate::wire::{
    checksum_sum, finalize_checksum, parse_ip_packet, parse_ip_packet_for_icmp_error,
    transport_checksum_sum, IpVersion, ParsedIpPacket, WireError,
};

const ICMPV4_PROTOCOL: u8 = 1;
const ICMPV6_PROTOCOL: u8 = 58;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpMessage {
    EchoRequest { identifier: u16, sequence: u16 },
    EchoReply { identifier: u16, sequence: u16 },
    DestinationUnreachable { code: u8 },
    PacketTooBig { mtu: u32 },
    TimeExceeded { code: u8 },
    ParameterProblem { code: u8, pointer: u32 },
    Other { kind: u8, code: u8 },
}

impl IcmpMessage {
    #[must_use]
    pub const fn is_error(self) -> bool {
        matches!(
            self,
            Self::DestinationUnreachable { .. }
                | Self::PacketTooBig { .. }
                | Self::TimeExceeded { .. }
                | Self::ParameterProblem { .. }
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedIcmpPacket<'a> {
    pub message: IcmpMessage,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpErrorKind {
    DestinationUnreachable { code: u8 },
    PacketTooBig { mtu: u32 },
    TimeExceeded { code: u8 },
    ParameterProblem { code: u8, pointer: u32 },
    UnsupportedProtocol,
}

/// Parses an ICMP message after IP reassembly.
///
/// # Errors
///
/// Returns [`WireError`] for the wrong IP protocol, short input, or an invalid
/// ICMP/ICMPv6 checksum.
pub fn parse_icmp_packet(
    ip: ParsedIpPacket<'_>,
    verify_checksum: bool,
) -> Result<ParsedIcmpPacket<'_>, WireError> {
    let expected = match ip.version {
        IpVersion::V4 => ICMPV4_PROTOCOL,
        IpVersion::V6 => ICMPV6_PROTOCOL,
    };
    if ip.next_header != expected {
        return Err(WireError::Unsupported("not ICMP"));
    }
    if ip.fragment.is_some_and(|fragment| !fragment.is_atomic()) {
        return Err(WireError::Unsupported("ICMP requires IP reassembly"));
    }
    if ip.payload.len() < 8 {
        return Err(WireError::Truncated);
    }
    if verify_checksum {
        let sum = match ip.version {
            IpVersion::V4 => checksum_sum(ip.payload, 0),
            IpVersion::V6 => {
                transport_checksum_sum(ip.source, ip.destination, ICMPV6_PROTOCOL, ip.payload)
            }
        };
        if sum != 0xffff {
            return Err(WireError::Checksum);
        }
    }
    let kind = ip.payload[0];
    let code = ip.payload[1];
    let message = match (ip.version, kind, code) {
        (IpVersion::V4, 8, 0) | (IpVersion::V6, 128, 0) => IcmpMessage::EchoRequest {
            identifier: u16::from_be_bytes([ip.payload[4], ip.payload[5]]),
            sequence: u16::from_be_bytes([ip.payload[6], ip.payload[7]]),
        },
        (IpVersion::V4, 0, 0) | (IpVersion::V6, 129, 0) => IcmpMessage::EchoReply {
            identifier: u16::from_be_bytes([ip.payload[4], ip.payload[5]]),
            sequence: u16::from_be_bytes([ip.payload[6], ip.payload[7]]),
        },
        (IpVersion::V4, 3, 4) => IcmpMessage::PacketTooBig {
            mtu: u32::from(u16::from_be_bytes([ip.payload[6], ip.payload[7]])),
        },
        (IpVersion::V4, 3, _) | (IpVersion::V6, 1, _) => {
            IcmpMessage::DestinationUnreachable { code }
        }
        (IpVersion::V6, 2, 0) => IcmpMessage::PacketTooBig {
            mtu: u32::from_be_bytes([ip.payload[4], ip.payload[5], ip.payload[6], ip.payload[7]]),
        },
        (IpVersion::V4, 11, _) | (IpVersion::V6, 3, _) => IcmpMessage::TimeExceeded { code },
        (IpVersion::V4, 12, _) => IcmpMessage::ParameterProblem {
            code,
            pointer: u32::from(ip.payload[4]),
        },
        (IpVersion::V6, 4, _) => IcmpMessage::ParameterProblem {
            code,
            pointer: u32::from_be_bytes([
                ip.payload[4],
                ip.payload[5],
                ip.payload[6],
                ip.payload[7],
            ]),
        },
        _ => IcmpMessage::Other { kind, code },
    };
    Ok(ParsedIcmpPacket {
        message,
        payload: &ip.payload[8..],
    })
}

/// Emits an echo reply with the request payload and reversed IP addresses.
///
/// # Errors
///
/// Returns [`WireError`] if `ip` is not a valid echo request or the output
/// cannot be represented by its IP version.
pub fn emit_icmp_echo_reply(ip: ParsedIpPacket<'_>, hop_limit: u8) -> Result<Vec<u8>, WireError> {
    let parsed = parse_icmp_packet(ip, true)?;
    if !matches!(parsed.message, IcmpMessage::EchoRequest { .. }) {
        return Err(WireError::Unsupported("not ICMP echo request"));
    }
    if invalid_error_address(ip.source) || invalid_error_address(ip.destination) {
        return Err(WireError::Unsupported(
            "ICMP echo reply requires unicast addresses",
        ));
    }
    let mut icmp = ip.payload.to_vec();
    icmp[0] = match ip.version {
        IpVersion::V4 => 0,
        IpVersion::V6 => 129,
    };
    icmp[2..4].fill(0);
    emit(ip.destination, ip.source, &mut icmp, hop_limit, 0)
}

/// Emits an ICMP error quoting as much of the invoking packet as is safe for
/// the minimum reassembly size. Errors are never generated in response to
/// multicast/broadcast destinations, non-initial fragments, or ICMP errors.
///
/// # Errors
///
/// Returns [`WireError`] when the invoking packet is malformed or is not
/// eligible for an ICMP error response.
pub fn emit_icmp_error(
    invoking_packet: &[u8],
    error: IcmpErrorKind,
    hop_limit: u8,
) -> Result<Vec<u8>, WireError> {
    let ip = if matches!(error, IcmpErrorKind::ParameterProblem { .. }) {
        parse_ip_packet_for_icmp_error(invoking_packet, true)?
    } else {
        parse_ip_packet(invoking_packet, true)?
    };
    if ip
        .fragment
        .is_some_and(|fragment| fragment.offset_bytes != 0)
        || invalid_error_address(ip.destination)
        || invalid_icmp_error_source(ip.source)
        || is_icmp_error(ip)
    {
        return Err(WireError::Unsupported("ICMP error response suppressed"));
    }
    let (kind, code) = match ip.version {
        IpVersion::V4 => match error {
            IcmpErrorKind::DestinationUnreachable { code } => (3, code),
            IcmpErrorKind::PacketTooBig { .. } => (3, 4),
            IcmpErrorKind::TimeExceeded { code } => (11, code),
            IcmpErrorKind::ParameterProblem { code, .. } => (12, code),
            IcmpErrorKind::UnsupportedProtocol => (3, 2),
        },
        IpVersion::V6 => match error {
            IcmpErrorKind::DestinationUnreachable { code } => (1, code),
            IcmpErrorKind::PacketTooBig { .. } => (2, 0),
            IcmpErrorKind::TimeExceeded { code } => (3, code),
            IcmpErrorKind::ParameterProblem { code, .. } => (4, code),
            IcmpErrorKind::UnsupportedProtocol => (4, 1),
        },
    };
    let max_quote = match ip.version {
        IpVersion::V4 => 576 - 20 - 8,
        IpVersion::V6 => 1_280 - 40 - 8,
    };
    let invoking_len = match ip.version {
        IpVersion::V4 => usize::from(u16::from_be_bytes([invoking_packet[2], invoking_packet[3]])),
        IpVersion::V6 => {
            40 + usize::from(u16::from_be_bytes([invoking_packet[4], invoking_packet[5]]))
        }
    };
    let mut icmp = vec![0; 8 + invoking_len.min(max_quote)];
    icmp[0] = kind;
    icmp[1] = code;
    match (ip.version, error) {
        (IpVersion::V4, IcmpErrorKind::PacketTooBig { mtu }) => {
            let mtu = u16::try_from(mtu).unwrap_or(u16::MAX);
            icmp[6..8].copy_from_slice(&mtu.to_be_bytes());
        }
        (IpVersion::V6, IcmpErrorKind::PacketTooBig { mtu }) => {
            icmp[4..8].copy_from_slice(&mtu.to_be_bytes());
        }
        (IpVersion::V4, IcmpErrorKind::ParameterProblem { pointer, .. }) => {
            icmp[4] = u8::try_from(pointer).unwrap_or(u8::MAX);
        }
        (IpVersion::V6, IcmpErrorKind::ParameterProblem { pointer, .. }) => {
            icmp[4..8].copy_from_slice(&pointer.to_be_bytes());
        }
        (IpVersion::V6, IcmpErrorKind::UnsupportedProtocol) => {
            let pointer = ipv6_next_header_pointer(invoking_packet)?;
            icmp[4..8].copy_from_slice(&pointer.to_be_bytes());
        }
        _ => {}
    }
    let quote_len = icmp.len() - 8;
    icmp[8..].copy_from_slice(&invoking_packet[..quote_len]);
    emit(ip.destination, ip.source, &mut icmp, hop_limit, 0)
}

fn is_icmp_error(ip: ParsedIpPacket<'_>) -> bool {
    let protocol = match ip.version {
        IpVersion::V4 => ICMPV4_PROTOCOL,
        IpVersion::V6 => ICMPV6_PROTOCOL,
    };
    if ip.next_header != protocol || ip.payload.len() < 8 {
        return false;
    }
    match ip.version {
        IpVersion::V4 => matches!(ip.payload[0], 3 | 4 | 5 | 11 | 12),
        IpVersion::V6 => matches!(ip.payload[0], 1..=4),
    }
}

fn invalid_error_address(address: IpAddr) -> bool {
    address.is_unspecified()
        || address.is_multicast()
        || matches!(address, IpAddr::V4(address) if address.is_broadcast())
}

fn invalid_icmp_error_source(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let first_octet = address.octets()[0];
            first_octet == 0 || first_octet == 127 || first_octet >= 224
        }
        IpAddr::V6(address) => address.is_unspecified() || address.is_multicast(),
    }
}

fn ipv6_next_header_pointer(packet: &[u8]) -> Result<u32, WireError> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Err(WireError::Malformed("not IPv6"));
    }
    let total_len = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let mut next = packet[6];
    let mut pointer = 6_usize;
    let mut offset = 40_usize;
    for _ in 0..8 {
        let length = match next {
            0 | 43 | 60 => {
                if offset + 2 > total_len || offset + 2 > packet.len() {
                    return Err(WireError::Truncated);
                }
                (usize::from(packet[offset + 1]) + 1) * 8
            }
            44 => 8,
            51 => {
                if offset + 2 > total_len || offset + 2 > packet.len() {
                    return Err(WireError::Truncated);
                }
                (usize::from(packet[offset + 1]) + 2) * 4
            }
            _ => return u32::try_from(pointer).map_err(|_| WireError::Malformed("IPv6 header")),
        };
        if offset + length > total_len || offset + length > packet.len() {
            return Err(WireError::Truncated);
        }
        pointer = offset;
        next = packet[offset];
        offset += length;
    }
    Err(WireError::Unsupported("IPv6 extension chain exceeds limit"))
}

fn emit(
    source: IpAddr,
    destination: IpAddr,
    icmp: &mut [u8],
    hop_limit: u8,
    ipv4_identification: u16,
) -> Result<Vec<u8>, WireError> {
    let (header_len, protocol) = match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => (20_usize, ICMPV4_PROTOCOL),
        (IpAddr::V6(_), IpAddr::V6(_)) => (40_usize, ICMPV6_PROTOCOL),
        _ => return Err(WireError::Malformed("mixed address families")),
    };
    let total_len = header_len
        .checked_add(icmp.len())
        .ok_or(WireError::Malformed("ICMP length overflow"))?;
    if matches!(source, IpAddr::V6(_)) && icmp.len() > usize::from(u16::MAX) {
        return Err(WireError::Malformed("ICMPv6 packet too large"));
    }
    icmp[2..4].fill(0);
    let checksum = match source {
        IpAddr::V4(_) => finalize_checksum(checksum_sum(icmp, 0)),
        IpAddr::V6(_) => {
            finalize_checksum(transport_checksum_sum(source, destination, protocol, icmp))
        }
    };
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut packet = vec![0; total_len];
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(
                &u16::try_from(total_len)
                    .map_err(|_| WireError::Malformed("IPv4 packet too large"))?
                    .to_be_bytes(),
            );
            packet[4..6].copy_from_slice(&ipv4_identification.to_be_bytes());
            packet[6] = 0x40;
            packet[8] = hop_limit;
            packet[9] = protocol;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            let checksum = finalize_checksum(checksum_sum(&packet[..20], 0));
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(
                &u16::try_from(icmp.len())
                    .map_err(|_| WireError::Malformed("ICMPv6 packet too large"))?
                    .to_be_bytes(),
            );
            packet[6] = protocol;
            packet[7] = hop_limit;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&destination.octets());
        }
        _ => unreachable!("address families checked above"),
    }
    packet[header_len..].copy_from_slice(icmp);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn request(source: IpAddr, destination: IpAddr, payload: &[u8]) -> Vec<u8> {
        let kind = if source.is_ipv4() { 8 } else { 128 };
        let mut icmp = vec![kind, 0, 0, 0, 0x12, 0x34, 0, 7];
        icmp.extend_from_slice(payload);
        emit(source, destination, &mut icmp, 64, 9).unwrap()
    }

    #[test]
    fn echoes_ipv4_and_preserves_payload() {
        let wire = request(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            b"ping",
        );
        let ip = parse_ip_packet(&wire, true).unwrap();
        let reply = emit_icmp_echo_reply(ip, 55).unwrap();
        let reply_ip = parse_ip_packet(&reply, true).unwrap();
        let parsed = parse_icmp_packet(reply_ip, true).unwrap();
        assert_eq!(reply_ip.source, ip.destination);
        assert_eq!(reply_ip.destination, ip.source);
        assert_eq!(reply_ip.hop_limit, 55);
        assert_eq!(parsed.payload, b"ping");
        assert_eq!(
            parsed.message,
            IcmpMessage::EchoReply {
                identifier: 0x1234,
                sequence: 7
            }
        );
    }

    #[test]
    fn echoes_ipv6_with_pseudo_header_checksum() {
        let wire = request(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            b"six",
        );
        let reply = emit_icmp_echo_reply(parse_ip_packet(&wire, true).unwrap(), 64).unwrap();
        let reply_ip = parse_ip_packet(&reply, true).unwrap();
        assert!(matches!(
            parse_icmp_packet(reply_ip, true).unwrap().message,
            IcmpMessage::EchoReply { .. }
        ));
    }

    #[test]
    fn echo_reply_never_uses_a_multicast_or_unspecified_source() {
        let multicast = request(
            IpAddr::V6("2001:db8::2".parse().unwrap()),
            IpAddr::V6("ff02::1".parse().unwrap()),
            b"multicast",
        );
        assert_eq!(
            emit_icmp_echo_reply(parse_ip_packet(&multicast, true).unwrap(), 64),
            Err(WireError::Unsupported(
                "ICMP echo reply requires unicast addresses"
            ))
        );

        let unspecified = request(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            b"unspecified",
        );
        assert_eq!(
            emit_icmp_echo_reply(parse_ip_packet(&unspecified, true).unwrap(), 64),
            Err(WireError::Unsupported(
                "ICMP echo reply requires unicast addresses"
            ))
        );
    }

    #[test]
    fn emits_packet_too_big_and_suppresses_error_loops() {
        let wire = request(
            IpAddr::V6("2001:db8::2".parse().unwrap()),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            b"oversized",
        );
        let error = emit_icmp_error(&wire, IcmpErrorKind::PacketTooBig { mtu: 1280 }, 64).unwrap();
        let error_ip = parse_ip_packet(&error, true).unwrap();
        assert_eq!(
            parse_icmp_packet(error_ip, true).unwrap().message,
            IcmpMessage::PacketTooBig { mtu: 1280 }
        );
        assert!(matches!(
            emit_icmp_error(
                &error,
                IcmpErrorKind::DestinationUnreachable { code: 1 },
                64
            ),
            Err(WireError::Unsupported(_))
        ));
    }

    #[test]
    fn suppresses_ipv4_errors_for_sources_that_do_not_name_one_host() {
        for source in [
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            let wire = request(
                IpAddr::V4(source),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                b"invalid-source",
            );
            assert_eq!(
                emit_icmp_error(&wire, IcmpErrorKind::DestinationUnreachable { code: 3 }, 64),
                Err(WireError::Unsupported("ICMP error response suppressed"))
            );
        }

        let ipv6_loopback = request(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            b"local-source",
        );
        assert!(emit_icmp_error(
            &ipv6_loopback,
            IcmpErrorKind::DestinationUnreachable { code: 4 },
            64
        )
        .is_ok());
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut wire = request(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            b"ping",
        );
        *wire.last_mut().unwrap() ^= 1;
        let ip = parse_ip_packet(&wire, true).unwrap();
        assert_eq!(parse_icmp_packet(ip, true), Err(WireError::Checksum));
    }
}
