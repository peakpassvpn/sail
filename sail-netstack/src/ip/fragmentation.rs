use crate::wire::{checksum_sum, finalize_checksum, parse_ip_packet, IpVersion, WireError};

/// Fragments a locally generated IPv4 or IPv6 packet to `mtu`.
///
/// IPv4 option copy bits are honored: the first fragment retains every option
/// and later fragments retain only copied options. The DF bit is cleared
/// because this API is specifically the source-fragmentation path.
/// For IPv6, the Fragment header is inserted after the Hop-by-Hop header and,
/// when present, the Routing header plus preceding Destination Options. The
/// remaining extension chain is part of the fragmentable payload.
///
/// # Errors
///
/// Returns [`WireError`] for malformed input, unsupported header layouts, or
/// an MTU too small to carry an aligned non-final fragment.
pub fn fragment_outbound_ip_packet(
    packet: &[u8],
    mtu: usize,
    identification: u32,
) -> Result<Vec<Vec<u8>>, WireError> {
    let ip = parse_ip_packet(packet, true)?;
    let packet_len = match ip.version {
        IpVersion::V4 => usize::from(u16::from_be_bytes([packet[2], packet[3]])),
        IpVersion::V6 => 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])),
    };
    if packet_len <= mtu {
        return Ok(vec![packet[..packet_len].to_vec()]);
    }
    if ip.fragment.is_some_and(|fragment| !fragment.is_atomic()) {
        return Err(WireError::Unsupported(
            "source fragmentation cannot refragment an IP fragment",
        ));
    }
    match ip.version {
        IpVersion::V4 => fragment_ipv4(&packet[..packet_len], mtu, identification),
        IpVersion::V6 => fragment_ipv6(&packet[..packet_len], mtu, identification),
    }
}

fn fragment_ipv4(
    packet: &[u8],
    mtu: usize,
    identification: u32,
) -> Result<Vec<Vec<u8>>, WireError> {
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let copied_options = copied_ipv4_options(&packet[20..header_len])?;
    let later_header_len = 20 + copied_options.len();
    let first_chunk_len = aligned_chunk(mtu, header_len)?;
    let later_chunk_len = aligned_chunk(mtu, later_header_len)?;
    let payload = &packet[header_len..];
    let mut fragments = Vec::new();
    let mut offset = 0_usize;
    while offset < payload.len() {
        let first = offset == 0;
        let capacity = if first {
            first_chunk_len
        } else {
            later_chunk_len
        };
        let remaining = payload.len() - offset;
        let amount = remaining.min(capacity);
        let chunk = &payload[offset..offset + amount];
        let current_header_len = if first { header_len } else { later_header_len };
        let mut fragment = if first {
            packet[..header_len].to_vec()
        } else {
            let mut header = packet[..20].to_vec();
            header.extend_from_slice(&copied_options);
            header[0] = 0x40 | u8::try_from(later_header_len / 4).expect("IPv4 IHL fits u8");
            header
        };
        fragment.extend_from_slice(chunk);
        fragment[4..6].copy_from_slice(&identification.to_be_bytes()[2..]);
        let fragment_len = u16::try_from(fragment.len())
            .map_err(|_| WireError::Malformed("IPv4 fragment too large"))?;
        fragment[2..4].copy_from_slice(&fragment_len.to_be_bytes());
        let mut bits = u16::try_from(offset / 8)
            .map_err(|_| WireError::Malformed("IPv4 fragment offset overflow"))?;
        if offset + amount < payload.len() {
            bits |= 0x2000;
        }
        fragment[6..8].copy_from_slice(&bits.to_be_bytes());
        fragment[10..12].fill(0);
        let checksum = finalize_checksum(checksum_sum(&fragment[..current_header_len], 0));
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        fragments.push(fragment);
        offset = offset
            .checked_add(amount)
            .ok_or(WireError::Malformed("IPv4 fragment offset overflow"))?;
    }
    Ok(fragments)
}

fn copied_ipv4_options(options: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut copied = Vec::new();
    let mut offset = 0_usize;
    while offset < options.len() {
        let kind = options[offset];
        match kind {
            0 => break,
            1 => offset += 1,
            _ => {
                let length = usize::from(
                    *options
                        .get(offset + 1)
                        .ok_or(WireError::Malformed("truncated IPv4 option"))?,
                );
                if length < 2 || offset + length > options.len() {
                    return Err(WireError::Malformed("invalid IPv4 option length"));
                }
                if kind & 0x80 != 0 {
                    copied.extend_from_slice(&options[offset..offset + length]);
                }
                offset += length;
            }
        }
    }
    copied.resize(copied.len().next_multiple_of(4), 0);
    if copied.len() > 40 {
        return Err(WireError::Malformed("copied IPv4 options exceed header"));
    }
    Ok(copied)
}

fn fragment_ipv6(
    packet: &[u8],
    mtu: usize,
    identification: u32,
) -> Result<Vec<Vec<u8>>, WireError> {
    let (insertion, previous_next_header, original_next_header) = ipv6_fragment_insertion(packet)?;
    let chunk_len = aligned_chunk(mtu, insertion + 8)?;
    let payload = &packet[insertion..];
    let mut fragments = Vec::with_capacity(payload.len().div_ceil(chunk_len));
    for (index, chunk) in payload.chunks(chunk_len).enumerate() {
        let offset = index
            .checked_mul(chunk_len)
            .ok_or(WireError::Malformed("IPv6 fragment offset overflow"))?;
        let mut fragment = Vec::with_capacity(insertion + 8 + chunk.len());
        fragment.extend_from_slice(&packet[..insertion]);
        fragment[previous_next_header] = 44;
        let payload_len = u16::try_from(insertion - 40 + 8 + chunk.len())
            .map_err(|_| WireError::Malformed("IPv6 fragment too large"))?;
        fragment[4..6].copy_from_slice(&payload_len.to_be_bytes());
        fragment.push(original_next_header);
        fragment.push(0);
        let mut bits = u16::try_from(offset)
            .map_err(|_| WireError::Malformed("IPv6 fragment offset overflow"))?;
        if offset + chunk.len() < payload.len() {
            bits |= 1;
        }
        fragment.extend_from_slice(&bits.to_be_bytes());
        fragment.extend_from_slice(&identification.to_be_bytes());
        fragment.extend_from_slice(chunk);
        fragments.push(fragment);
    }
    Ok(fragments)
}

fn ipv6_fragment_insertion(packet: &[u8]) -> Result<(usize, usize, u8), WireError> {
    let total_len = 40_usize
        .checked_add(usize::from(u16::from_be_bytes([packet[4], packet[5]])))
        .ok_or(WireError::Truncated)?;
    let mut next_header = packet[6];
    let mut offset = 40_usize;
    let mut records = Vec::new();
    for _ in 0..8 {
        let length = match next_header {
            0 | 43 | 60 => {
                if offset + 2 > total_len {
                    return Err(WireError::Truncated);
                }
                (usize::from(packet[offset + 1]) + 1) * 8
            }
            51 => {
                if offset + 2 > total_len {
                    return Err(WireError::Truncated);
                }
                (usize::from(packet[offset + 1]) + 2) * 4
            }
            44 => return Err(WireError::Unsupported("already-fragmented IPv6 packet")),
            _ => break,
        };
        if offset + length > total_len {
            return Err(WireError::Truncated);
        }
        records.push((next_header, offset, length));
        next_header = packet[offset];
        offset += length;
    }
    if matches!(next_header, 0 | 43 | 44 | 51 | 60) {
        return Err(WireError::Unsupported("IPv6 extension chain exceeds limit"));
    }

    let included = if let Some(routing) = records.iter().rposition(|record| record.0 == 43) {
        routing + 1
    } else {
        records.iter().take_while(|record| record.0 == 0).count()
    };
    let (insertion, previous_next_header) = if included == 0 {
        (40, 6)
    } else {
        let (_, start, length) = records[included - 1];
        (start + length, start)
    };
    Ok((
        insertion,
        previous_next_header,
        packet[previous_next_header],
    ))
}

fn aligned_chunk(mtu: usize, header_len: usize) -> Result<usize, WireError> {
    let available = mtu
        .checked_sub(header_len)
        .ok_or(WireError::Malformed("MTU smaller than IP header"))?;
    let chunk = available / 8 * 8;
    if chunk == 0 {
        return Err(WireError::Malformed("MTU cannot carry an IP fragment"));
    }
    Ok(chunk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emit_udp_packet, parse_udp_datagram, BudgetProfile, FragmentReassembler, ResourceLedger,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    #[test]
    fn fragments_ipv4_on_eight_byte_boundaries() {
        let wire = emit_udp_packet(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 1000)),
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 2000)),
            &[7; 100],
            64,
            42,
        )
        .unwrap();
        let fragments = fragment_outbound_ip_packet(&wire, 68, 0x1234_5678).unwrap();
        assert_eq!(fragments.len(), 3);
        for (index, fragment) in fragments.iter().enumerate() {
            let ip = parse_ip_packet(fragment, true).unwrap();
            let info = ip.fragment.unwrap();
            assert_eq!(info.identification, 0x5678);
            assert_eq!(info.offset_bytes, u32::try_from(index * 48).unwrap());
            assert_eq!(info.more_fragments, index != 2);
            assert!(fragment.len() <= 68);
        }
    }

    #[test]
    fn source_fragmentation_rejects_refragmenting_ipv4_input() {
        let wire = emit_udp_packet(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 1000)),
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 2000)),
            &[7; 100],
            64,
            42,
        )
        .unwrap();
        let fragments = fragment_outbound_ip_packet(&wire, 68, 0x1234_5678).unwrap();
        assert_eq!(
            fragment_outbound_ip_packet(&fragments[0], 60, 0x8765_4321),
            Err(WireError::Unsupported(
                "source fragmentation cannot refragment an IP fragment"
            ))
        );
    }

    #[test]
    fn ipv4_fragmentation_honors_option_copy_bits() {
        let wire = emit_udp_packet(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 1000)),
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 2000)),
            &[6; 80],
            64,
            42,
        )
        .unwrap();
        let mut extended = Vec::with_capacity(wire.len() + 8);
        extended.extend_from_slice(&wire[..20]);
        extended.extend_from_slice(&[0x83, 4, 0xaa, 0xbb, 0x03, 4, 0xcc, 0xdd]);
        extended.extend_from_slice(&wire[20..]);
        extended[0] = 0x47;
        let extended_len = u16::try_from(extended.len()).unwrap();
        extended[2..4].copy_from_slice(&extended_len.to_be_bytes());
        extended[10..12].fill(0);
        let checksum = finalize_checksum(checksum_sum(&extended[..28], 0));
        extended[10..12].copy_from_slice(&checksum.to_be_bytes());

        let fragments = fragment_outbound_ip_packet(&extended, 72, 0x5566_7788).unwrap();
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0][0] & 0x0f, 7);
        assert_eq!(fragments[0][20..28], extended[20..28]);
        assert_eq!(fragments[1][0] & 0x0f, 6);
        assert_eq!(fragments[1][20..24], [0x83, 4, 0xaa, 0xbb]);
        assert_eq!(
            parse_ip_packet(&fragments[1], true)
                .unwrap()
                .fragment
                .unwrap()
                .offset_bytes,
            40
        );

        let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
        let mut reassembler = FragmentReassembler::new(ledger, 1_000);
        assert!(reassembler.ingest(&fragments[1], 1).unwrap().is_none());
        let rebuilt = reassembler
            .ingest(&fragments[0], 2)
            .unwrap()
            .expect("IPv4 options fragments should reassemble");
        let ip = parse_ip_packet(&rebuilt, true).unwrap();
        assert_eq!(parse_udp_datagram(ip, true).unwrap().payload, &[6; 80]);
    }

    #[test]
    fn fragments_ipv6_with_fragment_header() {
        let wire = emit_udp_packet(
            SocketAddr::from((Ipv6Addr::LOCALHOST, 1000)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 2000)),
            &[9; 80],
            64,
            0,
        )
        .unwrap();
        let fragments = fragment_outbound_ip_packet(&wire, 80, 0x1234_5678).unwrap();
        assert_eq!(fragments.len(), 3);
        assert!(fragments.iter().all(|fragment| fragment.len() <= 80));
        assert!(fragments
            .iter()
            .all(|fragment| fragment[41] == 0 && fragment[43] & 0x06 == 0));
        let first = parse_ip_packet(&fragments[0], true).unwrap();
        assert_eq!(first.fragment.unwrap().identification, 0x1234_5678);
        assert!(parse_udp_datagram(first, true).is_err());
    }

    #[test]
    fn fragments_and_reassembles_ipv6_after_hop_by_hop_options() {
        let wire = emit_udp_packet(
            SocketAddr::from((Ipv6Addr::LOCALHOST, 1000)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 2000)),
            &[3; 80],
            64,
            0,
        )
        .unwrap();
        let mut extended = Vec::with_capacity(wire.len() + 8);
        extended.extend_from_slice(&wire[..40]);
        extended[4..6].copy_from_slice(&u16::try_from(wire.len() - 40 + 8).unwrap().to_be_bytes());
        extended[6] = 0;
        extended.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
        extended.extend_from_slice(&wire[40..]);

        let fragments = fragment_outbound_ip_packet(&extended, 80, 0x1122_3344).unwrap();
        assert!(fragments.len() > 1);
        assert!(fragments
            .iter()
            .all(|fragment| { fragment[6] == 0 && fragment[40] == 44 && fragment.len() <= 80 }));

        let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
        let mut reassembler = FragmentReassembler::new(Arc::clone(&ledger), 1_000);
        let mut rebuilt = None;
        for (now, fragment) in fragments.iter().rev().enumerate() {
            if let Some(packet) = reassembler
                .ingest(fragment, u64::try_from(now).unwrap())
                .unwrap()
            {
                rebuilt = Some(packet);
            }
        }
        let rebuilt = rebuilt.expect("all IPv6 fragments should reassemble");
        assert_eq!(rebuilt, extended);
        let ip = parse_ip_packet(&rebuilt, true).unwrap();
        assert_eq!(parse_udp_datagram(ip, true).unwrap().payload, &[3; 80]);
        assert_eq!(ledger.snapshot().total_bytes, 0);
    }

    #[test]
    fn ipv6_fragmentable_destination_options_survive_reassembly() {
        let wire = emit_udp_packet(
            SocketAddr::from((Ipv6Addr::LOCALHOST, 1000)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 2000)),
            &[5; 80],
            64,
            0,
        )
        .unwrap();
        let mut extended = Vec::with_capacity(wire.len() + 24);
        extended.extend_from_slice(&wire[..40]);
        extended[4..6].copy_from_slice(&u16::try_from(wire.len() - 40 + 24).unwrap().to_be_bytes());
        extended[6] = 60;
        extended.extend_from_slice(&[43, 0, 0, 0, 0, 0, 0, 0]);
        extended.extend_from_slice(&[60, 0, 0, 0, 0, 0, 0, 0]);
        extended.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
        extended.extend_from_slice(&wire[40..]);

        let fragments = fragment_outbound_ip_packet(&extended, 88, 0xaabb_ccdd).unwrap();
        assert!(fragments.len() > 1);
        assert!(fragments
            .iter()
            .all(|fragment| fragment[6] == 60 && fragment[48] == 44));

        let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
        let mut reassembler = FragmentReassembler::new(ledger, 1_000);
        let mut rebuilt = None;
        for (now, fragment) in fragments.iter().rev().enumerate() {
            rebuilt = reassembler
                .ingest(fragment, u64::try_from(now).unwrap())
                .unwrap()
                .or(rebuilt);
        }
        let rebuilt = rebuilt.expect("all IPv6 fragments should reassemble");
        assert_eq!(rebuilt, extended);
        let ip = parse_ip_packet(&rebuilt, true).unwrap();
        assert_eq!(parse_udp_datagram(ip, true).unwrap().payload, &[5; 80]);
    }
}
