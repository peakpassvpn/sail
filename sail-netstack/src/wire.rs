//! Fail-closed IPv4, IPv6, and UDP wire boundary.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const UDP_PROTOCOL: u8 = 17;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentInfo {
    pub identification: u32,
    pub offset_bytes: u32,
    pub more_fragments: bool,
}

impl FragmentInfo {
    #[must_use]
    pub const fn is_atomic(self) -> bool {
        self.offset_bytes == 0 && !self.more_fragments
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedIpPacket<'a> {
    pub version: IpVersion,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub next_header: u8,
    pub hop_limit: u8,
    pub fragment: Option<FragmentInfo>,
    /// Raw bytes covered by fragment offsets, including any extension headers
    /// after the IPv6 Fragment header. `payload` remains the upper-layer view.
    pub fragment_payload: Option<&'a [u8]>,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedUdpDatagram<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Truncated,
    Malformed(&'static str),
    Unsupported(&'static str),
    Ipv6OptionDiscard { pointer: u32, send_icmp: bool },
    Ipv6RoutingDiscard { pointer: u32 },
    Ipv6NextHeaderDiscard { pointer: u32 },
    Checksum,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated packet"),
            Self::Malformed(message) => write!(formatter, "malformed packet: {message}"),
            Self::Unsupported(message) => write!(formatter, "unsupported packet: {message}"),
            Self::Ipv6OptionDiscard { pointer, send_icmp } => write!(
                formatter,
                "unrecognized IPv6 option at byte {pointer} requires discard (ICMP: {send_icmp})"
            ),
            Self::Ipv6RoutingDiscard { pointer } => write!(
                formatter,
                "unrecognized IPv6 routing type at byte {pointer} requires discard"
            ),
            Self::Ipv6NextHeaderDiscard { pointer } => write!(
                formatter,
                "unrecognized IPv6 next-header value at byte {pointer} requires discard"
            ),
            Self::Checksum => formatter.write_str("invalid checksum"),
        }
    }
}

impl std::error::Error for WireError {}

/// Returns whether `address` may originate an intercepted unicast flow
/// (RFC 1122 section 3.2.1.3 for IPv4; unspecified and multicast for IPv6).
#[must_use]
pub(crate) fn valid_flow_source(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let first_octet = address.octets()[0];
            first_octet != 0 && first_octet != 127 && first_octet < 224
        }
        IpAddr::V6(address) => !address.is_unspecified() && !address.is_multicast(),
    }
}

/// Returns whether `address` may terminate an intercepted unicast flow.
#[must_use]
pub(crate) fn valid_flow_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let first_octet = address.octets()[0];
            first_octet != 0 && first_octet < 224 && !address.is_broadcast()
        }
        IpAddr::V6(address) => !address.is_unspecified() && !address.is_multicast(),
    }
}

/// Parses one complete IP packet. Trailing platform padding is ignored.
///
/// # Errors
///
/// Returns [`WireError`] for truncated, malformed, or checksum-invalid input.
pub fn parse_ip_packet(
    packet: &[u8],
    verify_ipv4_checksum: bool,
) -> Result<ParsedIpPacket<'_>, WireError> {
    let version = packet.first().ok_or(WireError::Truncated)? >> 4;
    match version {
        4 => parse_ipv4(packet, verify_ipv4_checksum),
        6 => parse_ipv6(packet, true),
        _ => Err(WireError::Unsupported("IP version")),
    }
}

pub(crate) fn parse_ip_packet_for_icmp_error(
    packet: &[u8],
    verify_ipv4_checksum: bool,
) -> Result<ParsedIpPacket<'_>, WireError> {
    let version = packet.first().ok_or(WireError::Truncated)? >> 4;
    match version {
        4 => parse_ipv4(packet, verify_ipv4_checksum),
        6 => parse_ipv6(packet, false),
        _ => Err(WireError::Unsupported("IP version")),
    }
}

fn parse_ipv4(packet: &[u8], verify_checksum: bool) -> Result<ParsedIpPacket<'_>, WireError> {
    if packet.len() < 20 {
        return Err(WireError::Truncated);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return Err(WireError::Malformed("IPv4 header length"));
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || total_len > packet.len() {
        return Err(WireError::Truncated);
    }
    validate_ipv4_options(&packet[20..header_len])?;
    if verify_checksum && checksum_sum(&packet[..header_len], 0) != 0xffff {
        return Err(WireError::Checksum);
    }
    let fragment_bits = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment_bits & 0x8000 != 0 {
        return Err(WireError::Malformed("IPv4 reserved fragment flag"));
    }
    let fragment_offset = u32::from(fragment_bits & 0x1fff) * 8;
    let more_fragments = fragment_bits & 0x2000 != 0;
    if fragment_bits & 0x4000 != 0 && (fragment_offset != 0 || more_fragments) {
        return Err(WireError::Malformed("IPv4 DF set on a fragment"));
    }
    let fragment = (fragment_offset != 0 || more_fragments).then_some(FragmentInfo {
        identification: u32::from(u16::from_be_bytes([packet[4], packet[5]])),
        offset_bytes: fragment_offset,
        more_fragments,
    });
    let payload = &packet[header_len..total_len];
    Ok(ParsedIpPacket {
        version: IpVersion::V4,
        source: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        destination: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        next_header: packet[9],
        hop_limit: packet[8],
        fragment,
        fragment_payload: fragment.map(|_| payload),
        payload,
    })
}

fn validate_ipv4_options(options: &[u8]) -> Result<(), WireError> {
    let mut offset = 0_usize;
    while offset < options.len() {
        match options[offset] {
            0 => {
                if options[offset + 1..].iter().any(|&byte| byte != 0) {
                    return Err(WireError::Malformed("nonzero IPv4 option padding"));
                }
                return Ok(());
            }
            1 => offset += 1,
            _ => {
                let length = usize::from(
                    *options
                        .get(offset + 1)
                        .ok_or(WireError::Malformed("truncated IPv4 option"))?,
                );
                if length < 2 {
                    return Err(WireError::Malformed("invalid IPv4 option length"));
                }
                offset = offset
                    .checked_add(length)
                    .filter(|&end| end <= options.len())
                    .ok_or(WireError::Malformed("truncated IPv4 option"))?;
            }
        }
    }
    Ok(())
}

fn parse_ipv6(
    packet: &[u8],
    enforce_extension_actions: bool,
) -> Result<ParsedIpPacket<'_>, WireError> {
    if packet.len() < 40 {
        return Err(WireError::Truncated);
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = 40_usize
        .checked_add(payload_len)
        .ok_or(WireError::Truncated)?;
    if total_len > packet.len() {
        return Err(WireError::Truncated);
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("fixed IPv6 address"));
    let destination =
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("fixed IPv6 address"));
    let mut next_header = packet[6];
    let mut next_header_pointer = 6_usize;
    let mut offset = 40_usize;
    let mut fragment = None;
    let mut fragment_payload = None;
    for _ in 0..8 {
        let extension_len = match next_header {
            0 if offset != 40 && enforce_extension_actions => {
                return Err(WireError::Ipv6NextHeaderDiscard {
                    pointer: ipv6_wire_pointer(next_header_pointer)?,
                });
            }
            0 | 43 | 60 => {
                require(packet, offset, 2, total_len)?;
                let len = (usize::from(packet[offset + 1]) + 1) * 8;
                require(packet, offset, len, total_len)?;
                if next_header == 43 && enforce_extension_actions && packet[offset + 3] != 0 {
                    return Err(WireError::Ipv6RoutingDiscard {
                        pointer: ipv6_wire_pointer(offset + 2)?,
                    });
                }
                if matches!(next_header, 0 | 60) {
                    validate_ipv6_options(
                        &packet[offset + 2..offset + len],
                        offset + 2,
                        destination.is_multicast(),
                        enforce_extension_actions,
                    )?;
                }
                len
            }
            51 => {
                require(packet, offset, 2, total_len)?;
                let len = (usize::from(packet[offset + 1]) + 2) * 4;
                require(packet, offset, len, total_len)?;
                len
            }
            44 => {
                require(packet, offset, 8, total_len)?;
                if fragment.is_some() || packet[offset] == 44 {
                    return Err(WireError::Malformed("multiple IPv6 fragment headers"));
                }
                let bits = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                let info = FragmentInfo {
                    identification: u32::from_be_bytes([
                        packet[offset + 4],
                        packet[offset + 5],
                        packet[offset + 6],
                        packet[offset + 7],
                    ]),
                    offset_bytes: u32::from((bits >> 3) & 0x1fff) * 8,
                    more_fragments: bits & 1 != 0,
                };
                fragment = Some(info);
                fragment_payload = Some(&packet[offset + 8..total_len]);
                if info.offset_bytes != 0 {
                    return Ok(ParsedIpPacket {
                        version: IpVersion::V6,
                        source: IpAddr::V6(source),
                        destination: IpAddr::V6(destination),
                        next_header: packet[offset],
                        hop_limit: packet[7],
                        fragment,
                        fragment_payload,
                        payload: &packet[offset + 8..total_len],
                    });
                }
                8
            }
            _ => {
                return Ok(ParsedIpPacket {
                    version: IpVersion::V6,
                    source: IpAddr::V6(source),
                    destination: IpAddr::V6(destination),
                    next_header,
                    hop_limit: packet[7],
                    fragment,
                    fragment_payload,
                    payload: &packet[offset..total_len],
                });
            }
        };
        next_header_pointer = offset;
        next_header = packet[offset];
        offset += extension_len;
    }
    Err(WireError::Unsupported("IPv6 extension chain exceeds limit"))
}

fn ipv6_wire_pointer(offset: usize) -> Result<u32, WireError> {
    u32::try_from(offset).map_err(|_| WireError::Malformed("IPv6 wire pointer"))
}

fn validate_ipv6_options(
    options: &[u8],
    absolute_offset: usize,
    destination_is_multicast: bool,
    enforce_actions: bool,
) -> Result<(), WireError> {
    let mut offset = 0_usize;
    while offset < options.len() {
        let kind = options[offset];
        if kind == 0 {
            offset += 1;
            continue;
        }
        let data_len = usize::from(
            *options
                .get(offset + 1)
                .ok_or(WireError::Malformed("truncated IPv6 option"))?,
        );
        let end = offset
            .checked_add(2)
            .and_then(|start| start.checked_add(data_len))
            .filter(|&end| end <= options.len())
            .ok_or(WireError::Malformed("truncated IPv6 option"))?;
        if kind == 1 {
            if options[offset + 2..end].iter().any(|&byte| byte != 0) {
                return Err(WireError::Malformed("nonzero IPv6 PadN data"));
            }
        } else if enforce_actions && kind >> 6 != 0 {
            let pointer = u32::try_from(absolute_offset.saturating_add(offset))
                .map_err(|_| WireError::Malformed("IPv6 option pointer overflow"))?;
            let send_icmp = match kind >> 6 {
                1 => false,
                2 => true,
                3 => !destination_is_multicast,
                _ => unreachable!("two-bit IPv6 option action"),
            };
            return Err(WireError::Ipv6OptionDiscard { pointer, send_icmp });
        }
        offset = end;
    }
    Ok(())
}

fn require(packet: &[u8], offset: usize, len: usize, total_len: usize) -> Result<(), WireError> {
    let end = offset.checked_add(len).ok_or(WireError::Truncated)?;
    if end > total_len || end > packet.len() {
        return Err(WireError::Truncated);
    }
    Ok(())
}

/// Parses UDP only after IP reassembly. IPv6 atomic fragments are accepted.
///
/// # Errors
///
/// Returns [`WireError`] for non-UDP, fragmented, malformed, or
/// checksum-invalid packets.
pub fn parse_udp_datagram(
    ip: ParsedIpPacket<'_>,
    verify_checksum: bool,
) -> Result<ParsedUdpDatagram<'_>, WireError> {
    if ip.next_header != UDP_PROTOCOL {
        return Err(WireError::Unsupported("not UDP"));
    }
    if ip.fragment.is_some_and(|fragment| !fragment.is_atomic()) {
        return Err(WireError::Unsupported("UDP requires IP reassembly"));
    }
    if ip.payload.len() < 8 {
        return Err(WireError::Truncated);
    }
    let udp_len = usize::from(u16::from_be_bytes([ip.payload[4], ip.payload[5]]));
    if udp_len < 8 || udp_len > ip.payload.len() {
        return Err(WireError::Truncated);
    }
    let udp = &ip.payload[..udp_len];
    let wire_checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if verify_checksum {
        if matches!(ip.version, IpVersion::V6) && wire_checksum == 0 {
            return Err(WireError::Checksum);
        }
        if wire_checksum != 0
            && transport_checksum_sum(ip.source, ip.destination, UDP_PROTOCOL, udp) != 0xffff
        {
            return Err(WireError::Checksum);
        }
    }
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    Ok(ParsedUdpDatagram {
        source: SocketAddr::new(ip.source, source_port),
        destination: SocketAddr::new(ip.destination, destination_port),
        payload: &udp[8..],
    })
}

/// Emits a checksummed IPv4 or IPv6 UDP packet without fragmentation.
///
/// # Errors
///
/// Returns [`WireError`] for mixed address families or packets too large for
/// the IP and UDP length fields.
pub fn emit_udp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    hop_limit: u8,
    ipv4_identification: u16,
) -> Result<Vec<u8>, WireError> {
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or(WireError::Malformed("UDP length overflow"))?;
    let udp_len_u16 = u16::try_from(udp_len).map_err(|_| WireError::Malformed("UDP too large"))?;
    let header_len = match (source.ip(), destination.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 20,
        (IpAddr::V6(_), IpAddr::V6(_)) => 40,
        _ => return Err(WireError::Malformed("mixed address families")),
    };
    let total_len = header_len + udp_len;
    let mut packet = vec![0; total_len];
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(
                &u16::try_from(total_len)
                    .map_err(|_| WireError::Malformed("IPv4 packet too large"))?
                    .to_be_bytes(),
            );
            packet[4..6].copy_from_slice(&ipv4_identification.to_be_bytes());
            packet[6] = 0x40;
            packet[8] = hop_limit;
            packet[9] = UDP_PROTOCOL;
            packet[12..16].copy_from_slice(&source_ip.octets());
            packet[16..20].copy_from_slice(&destination_ip.octets());
            let checksum = finalize_checksum(checksum_sum(&packet[..20], 0));
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
            packet[6] = UDP_PROTOCOL;
            packet[7] = hop_limit;
            packet[8..24].copy_from_slice(&source_ip.octets());
            packet[24..40].copy_from_slice(&destination_ip.octets());
        }
        _ => unreachable!("address families checked above"),
    }
    let udp = &mut packet[header_len..];
    udp[0..2].copy_from_slice(&source.port().to_be_bytes());
    udp[2..4].copy_from_slice(&destination.port().to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let mut checksum = finalize_checksum(transport_checksum_sum(
        source.ip(),
        destination.ip(),
        UDP_PROTOCOL,
        udp,
    ));
    if checksum == 0 {
        checksum = 0xffff;
    }
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

pub(crate) fn transport_checksum_sum(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload: &[u8],
) -> u16 {
    let mut sum = 0_u32;
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            sum = checksum_accumulate(&source.octets(), sum);
            sum = checksum_accumulate(&destination.octets(), sum);
            sum += u32::from(protocol);
            sum += u32::try_from(payload.len()).unwrap_or(u32::MAX);
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            sum = checksum_accumulate(&source.octets(), sum);
            sum = checksum_accumulate(&destination.octets(), sum);
            sum += u32::try_from(payload.len()).unwrap_or(u32::MAX);
            sum += u32::from(protocol);
        }
        _ => return 0,
    }
    checksum_sum(payload, sum)
}

pub(crate) fn checksum_sum(bytes: &[u8], initial: u32) -> u16 {
    fold_checksum(checksum_accumulate(bytes, initial))
}

fn checksum_accumulate(bytes: &[u8], mut sum: u32) -> u32 {
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*chunk)));
    }
    if let Some(byte) = remainder.first() {
        sum = sum.wrapping_add(u32::from(*byte) << 8);
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(sum).expect("checksum fold fits u16")
}

pub(crate) fn finalize_checksum(sum: u16) -> u16 {
    !sum
}
