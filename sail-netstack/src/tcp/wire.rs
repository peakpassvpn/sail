use std::net::{IpAddr, SocketAddr};

use crate::wire::{finalize_checksum, transport_checksum_sum};
use crate::{ParsedIpPacket, SendControl, SeqNumber, TcpFlags, TcpSegmentMeta, WireError};

const TCP_PROTOCOL: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SackBlock {
    pub left: SeqNumber,
    pub right: SeqNumber,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpOptions {
    pub maximum_segment_size: Option<u16>,
    pub window_scale: Option<u8>,
    pub window_scale_clamped: bool,
    pub sack_permitted: bool,
    pub sack_blocks: [Option<SackBlock>; 4],
    pub timestamps: Option<(u32, u32)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedTcpSegment<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub meta: TcpSegmentMeta,
    pub options: TcpOptions,
    pub payload: &'a [u8],
}

/// Parses a complete TCP segment after IP reassembly.
///
/// # Errors
///
/// Returns [`WireError`] for non-TCP, fragmented, malformed-option, truncated,
/// or checksum-invalid input.
pub fn parse_tcp_segment(
    ip: ParsedIpPacket<'_>,
    verify_checksum: bool,
) -> Result<ParsedTcpSegment<'_>, WireError> {
    if ip.next_header != TCP_PROTOCOL {
        return Err(WireError::Unsupported("not TCP"));
    }
    if ip.fragment.is_some_and(|fragment| !fragment.is_atomic()) {
        return Err(WireError::Unsupported("TCP requires IP reassembly"));
    }
    if ip.payload.len() < 20 {
        return Err(WireError::Truncated);
    }
    let header_len = usize::from(ip.payload[12] >> 4) * 4;
    if !(20..=60).contains(&header_len) || header_len > ip.payload.len() {
        return Err(WireError::Malformed("TCP data offset"));
    }
    if verify_checksum
        && transport_checksum_sum(ip.source, ip.destination, TCP_PROTOCOL, ip.payload) != 0xffff
    {
        return Err(WireError::Checksum);
    }
    let flags = TcpFlags::from_bits(ip.payload[13]);
    let acknowledgment = flags.contains(TcpFlags::ACK).then(|| {
        SeqNumber::new(u32::from_be_bytes([
            ip.payload[8],
            ip.payload[9],
            ip.payload[10],
            ip.payload[11],
        ]))
    });
    let options = parse_options(&ip.payload[20..header_len])?;
    let payload = &ip.payload[header_len..];
    Ok(ParsedTcpSegment {
        source: SocketAddr::new(
            ip.source,
            u16::from_be_bytes([ip.payload[0], ip.payload[1]]),
        ),
        destination: SocketAddr::new(
            ip.destination,
            u16::from_be_bytes([ip.payload[2], ip.payload[3]]),
        ),
        meta: TcpSegmentMeta {
            sequence: SeqNumber::new(u32::from_be_bytes([
                ip.payload[4],
                ip.payload[5],
                ip.payload[6],
                ip.payload[7],
            ])),
            acknowledgment,
            flags,
            window: u32::from(u16::from_be_bytes([ip.payload[14], ip.payload[15]])),
            payload_len: payload.len(),
        },
        options,
        payload,
    })
}

fn parse_options(mut bytes: &[u8]) -> Result<TcpOptions, WireError> {
    let mut options = TcpOptions::default();
    let mut sack_index = 0;
    while let Some((&kind, remainder)) = bytes.split_first() {
        bytes = remainder;
        match kind {
            0 => {
                if bytes.iter().any(|&byte| byte != 0) {
                    return Err(WireError::Malformed("nonzero TCP option padding"));
                }
                break;
            }
            1 => {}
            _ => {
                let Some((&length, remainder)) = bytes.split_first() else {
                    return Err(WireError::Truncated);
                };
                let length = usize::from(length);
                if length < 2 || length - 1 > bytes.len() {
                    return Err(WireError::Malformed("TCP option length"));
                }
                let data = &remainder[..length - 2];
                match (kind, length) {
                    (2, 4) => {
                        if options.maximum_segment_size.is_some() {
                            return Err(WireError::Malformed("duplicate TCP MSS option"));
                        }
                        options.maximum_segment_size = Some(u16::from_be_bytes([data[0], data[1]]));
                    }
                    (3, 3) => {
                        if options.window_scale.is_some() {
                            return Err(WireError::Malformed("duplicate TCP window scale"));
                        }
                        options.window_scale_clamped = data[0] > 14;
                        options.window_scale = Some(data[0].min(14));
                    }
                    (4, 2) => options.sack_permitted = true,
                    (5, _) if length >= 10 && (length - 2) % 8 == 0 => {
                        for block in data.as_chunks::<8>().0 {
                            if sack_index == options.sack_blocks.len() {
                                return Err(WireError::Malformed("too many TCP SACK blocks"));
                            }
                            let left = SeqNumber::new(u32::from_be_bytes([
                                block[0], block[1], block[2], block[3],
                            ]));
                            let right = SeqNumber::new(u32::from_be_bytes([
                                block[4], block[5], block[6], block[7],
                            ]));
                            if !right.after(left) {
                                return Err(WireError::Malformed("invalid TCP SACK block"));
                            }
                            options.sack_blocks[sack_index] = Some(SackBlock { left, right });
                            sack_index += 1;
                        }
                    }
                    (8, 10) => {
                        if options.timestamps.is_some() {
                            return Err(WireError::Malformed("duplicate TCP timestamp option"));
                        }
                        options.timestamps = Some((
                            u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                            u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                        ));
                    }
                    (2 | 3 | 4 | 5 | 8, _) => {
                        return Err(WireError::Malformed("invalid known TCP option length"));
                    }
                    _ => {}
                }
                bytes = &bytes[length - 1..];
            }
        }
    }
    Ok(options)
}

/// Emits a checksum-valid TCP control segment without options or payload.
///
/// # Errors
///
/// Returns [`WireError`] for mixed address families.
pub fn emit_tcp_control(
    source: SocketAddr,
    destination: SocketAddr,
    control: SendControl,
    hop_limit: u8,
    ipv4_identification: u16,
) -> Result<Vec<u8>, WireError> {
    emit_tcp_segment(
        source,
        destination,
        control,
        &[],
        hop_limit,
        ipv4_identification,
    )
}

/// Emits a checksum-valid TCP segment without TCP options.
///
/// # Errors
///
/// Returns [`WireError`] for mixed address families or a segment too large for
/// the IP representation.
pub fn emit_tcp_segment(
    source: SocketAddr,
    destination: SocketAddr,
    control: SendControl,
    payload: &[u8],
    hop_limit: u8,
    ipv4_identification: u16,
) -> Result<Vec<u8>, WireError> {
    emit_tcp_segment_with_options(
        source,
        destination,
        control,
        &[],
        payload,
        hop_limit,
        ipv4_identification,
    )
}

/// Emits a checksum-valid TCP segment with already encoded, padded options.
///
/// # Errors
///
/// Returns [`WireError`] for malformed options, mixed address families, or an
/// oversized segment.
pub fn emit_tcp_segment_with_options(
    source: SocketAddr,
    destination: SocketAddr,
    control: SendControl,
    options: &[u8],
    payload: &[u8],
    hop_limit: u8,
    ipv4_identification: u16,
) -> Result<Vec<u8>, WireError> {
    if options.len() > 40 || !options.len().is_multiple_of(4) {
        return Err(WireError::Malformed(
            "TCP options must be padded to 32 bits",
        ));
    }
    parse_options(options)?;
    let ip_header_len: usize = match (source.ip(), destination.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 20,
        (IpAddr::V6(_), IpAddr::V6(_)) => 40,
        _ => return Err(WireError::Malformed("mixed address families")),
    };
    let tcp_header_len = 20_usize + options.len();
    let tcp_len = tcp_header_len
        .checked_add(payload.len())
        .ok_or(WireError::Malformed("TCP segment too large"))?;
    let ip_len = ip_header_len
        .checked_add(tcp_len)
        .ok_or(WireError::Malformed("TCP segment too large"))?;
    let tcp_len_u16 =
        u16::try_from(tcp_len).map_err(|_| WireError::Malformed("TCP segment too large"))?;
    let ip_len_u16 =
        u16::try_from(ip_len).map_err(|_| WireError::Malformed("TCP segment too large"))?;
    let mut packet = vec![0_u8; ip_len];
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&ip_len_u16.to_be_bytes());
            packet[4..6].copy_from_slice(&ipv4_identification.to_be_bytes());
            packet[6] = 0x40;
            packet[8] = hop_limit;
            packet[9] = TCP_PROTOCOL;
            packet[12..16].copy_from_slice(&source_ip.octets());
            packet[16..20].copy_from_slice(&destination_ip.octets());
            let checksum = ipv4_header_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&tcp_len_u16.to_be_bytes());
            packet[6] = TCP_PROTOCOL;
            packet[7] = hop_limit;
            packet[8..24].copy_from_slice(&source_ip.octets());
            packet[24..40].copy_from_slice(&destination_ip.octets());
        }
        _ => unreachable!("address families checked above"),
    }
    let tcp = &mut packet[ip_header_len..];
    tcp[0..2].copy_from_slice(&source.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&control.sequence.get().to_be_bytes());
    tcp[8..12].copy_from_slice(&control.acknowledgment.get().to_be_bytes());
    tcp[12] = u8::try_from(tcp_header_len / 4).unwrap_or(15) << 4;
    tcp[13] = control.flags.bits();
    tcp[14..16].copy_from_slice(&control.window.to_be_bytes());
    tcp[20..tcp_header_len].copy_from_slice(options);
    tcp[tcp_header_len..].copy_from_slice(payload);
    let checksum = finalize_checksum(transport_checksum_sum(
        source.ip(),
        destination.ip(),
        TCP_PROTOCOL,
        tcp,
    ));
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    finalize_checksum(u16::try_from(sum).unwrap_or(u16::MAX))
}
