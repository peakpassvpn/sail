//! Fitting packets from peers to the stack's MTU: a peer's MTU may be
//! larger than the endpoint's, and a network interface in its place would
//! have taken them. Whole packets are fragmented as a source would; a
//! fragment is split into smaller fragments of the same datagram, as an
//! IPv4 router does (and, for IPv6, as the source could have).

use tracing::debug;

/// `packet`, as packets of at most `mtu` bytes; none if it cannot be.
pub(super) fn fit(packet: Vec<u8>, mtu: usize, identification: &mut u32) -> Vec<Vec<u8>> {
    if packet.len() <= mtu {
        return vec![packet];
    }
    let fragmented = match refragment(&packet, mtu) {
        Some(fragments) => Ok(fragments),
        None => {
            *identification = identification.wrapping_add(1);
            sail_netstack::fragment_outbound_ip_packet(&packet, mtu, *identification)
        }
    };
    fragmented.unwrap_or_else(|e| {
        debug!(
            "wireguard: a packet of {} bytes does not fit the MTU {}: {}",
            packet.len(),
            mtu,
            e
        );
        Vec::new()
    })
}

/// Splits `packet`, if it is a fragment, into fragments of at most `mtu`
/// bytes. None if it is not a fragment, or not one this can split.
fn refragment(packet: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    match packet.first()? >> 4 {
        4 => refragment_v4(packet, mtu),
        6 => refragment_v6(packet, mtu),
        _ => None,
    }
}

fn refragment_v4(packet: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
    if header_len < 20 || total > packet.len() || total <= header_len {
        return None;
    }
    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    let more = flags & 0x2000 != 0;
    let offset = usize::from(flags & 0x1fff) * 8;
    if !more && offset == 0 {
        // A whole packet.
        return None;
    }
    // Options are rare in fragments; copying them all is harmless.
    let chunk = mtu.checked_sub(header_len)? / 8 * 8;
    if chunk == 0 {
        return None;
    }
    let data = &packet[header_len..total];
    let mut out = Vec::new();
    for (i, piece) in data.chunks(chunk).enumerate() {
        let last = (i + 1) * chunk >= data.len();
        let mut p = Vec::with_capacity(header_len + piece.len());
        p.extend_from_slice(&packet[..header_len]);
        p.extend_from_slice(piece);
        let len = u16::try_from(p.len()).ok()?;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        let off = u16::try_from((offset + i * chunk) / 8).ok()?;
        let mf = if !last || more { 0x2000 } else { 0 };
        p[6..8].copy_from_slice(&(off | mf).to_be_bytes());
        p[10..12].copy_from_slice(&[0, 0]);
        let sum = checksum(&p[..header_len]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        out.push(p);
    }
    Some(out)
}

/// An IPv6 fragment whose Fragment header follows the fixed header.
fn refragment_v6(packet: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    const HEADERS: usize = 40 + 8;
    if *packet.get(6)? != 44 || packet.len() < HEADERS {
        return None;
    }
    let total = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if total > packet.len() || total <= HEADERS {
        return None;
    }
    let field = u16::from_be_bytes([packet[42], packet[43]]);
    let more = field & 1 != 0;
    let offset = usize::from(field >> 3) * 8;
    let chunk = mtu.checked_sub(HEADERS)? / 8 * 8;
    if chunk == 0 {
        return None;
    }
    let data = &packet[HEADERS..total];
    let mut out = Vec::new();
    for (i, piece) in data.chunks(chunk).enumerate() {
        let last = (i + 1) * chunk >= data.len();
        let mut p = Vec::with_capacity(HEADERS + piece.len());
        p.extend_from_slice(&packet[..HEADERS]);
        p.extend_from_slice(piece);
        let payload = u16::try_from(p.len() - 40).ok()?;
        p[4..6].copy_from_slice(&payload.to_be_bytes());
        let off = u16::try_from((offset + i * chunk) / 8).ok()?;
        let m = u16::from(!last || more);
        p[42..44].copy_from_slice(&((off << 3) | m).to_be_bytes());
        out.push(p);
    }
    Some(out)
}

fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_v4(payload: usize) -> Vec<u8> {
        let total = 28 + payload;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[6] = 0x40; // DF
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[24..26].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
        for (i, b) in p[28..].iter_mut().enumerate() {
            *b = i as u8;
        }
        let sum = checksum(&p[..20]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p
    }

    /// Puts IPv4 fragments back together, checking each header.
    fn reassemble_v4(fragments: &[Vec<u8>]) -> Vec<u8> {
        let mut data = Vec::new();
        for (i, f) in fragments.iter().enumerate() {
            assert_eq!(checksum(&f[..20]), 0, "header checksum of {}", i);
            let field = u16::from_be_bytes([f[6], f[7]]);
            assert_eq!(usize::from(field & 0x1fff) * 8, data.len());
            assert_eq!(field & 0x2000 != 0, i + 1 < fragments.len());
            data.extend_from_slice(&f[20..]);
        }
        data
    }

    #[test]
    fn packets_that_fit_pass_and_others_are_fragmented() {
        let mut id = 0;
        let small = udp_v4(100);
        assert_eq!(fit(small.clone(), 1408, &mut id), vec![small]);

        // A whole packet, as a source fragments it.
        let big = udp_v4(1392);
        let fragments = fit(big.clone(), 1408, &mut id);
        assert_eq!(fragments.len(), 2);
        assert!(fragments.iter().all(|f| f.len() <= 1408));
        assert_eq!(reassemble_v4(&fragments), big[20..]);

        // A fragment of 1420, as a kernel peer sends, split again: the
        // pieces of both fragments make up the datagram.
        let whole = udp_v4(2972);
        let kernel = sail_netstack::fragment_outbound_ip_packet(&whole, 1420, 7).unwrap();
        let mut pieces = Vec::new();
        for f in kernel {
            pieces.extend(fit(f, 1408, &mut id));
        }
        assert!(pieces.iter().all(|f| f.len() <= 1408));
        // Three fragments of the kernel's, the two full ones split in two.
        assert_eq!(pieces.len(), 5);
        assert_eq!(reassemble_v4(&pieces), whole[20..]);
    }

    #[test]
    fn ipv6_fragments_are_split_again() {
        let payload = 2800;
        let mut whole = vec![0u8; 48 + payload];
        whole[0] = 0x60;
        whole[4..6].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
        whole[6] = 17;
        whole[7] = 64;
        whole[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        whole[24..40].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        whole[44..46].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
        let kernel = sail_netstack::fragment_outbound_ip_packet(&whole, 1420, 9).unwrap();
        let mut id = 0;
        let mut data = Vec::new();
        let mut pieces = Vec::new();
        for f in kernel {
            pieces.extend(fit(f, 1280, &mut id));
        }
        for (i, p) in pieces.iter().enumerate() {
            assert!(p.len() <= 1280);
            assert_eq!(p[6], 44);
            let field = u16::from_be_bytes([p[42], p[43]]);
            assert_eq!(usize::from(field >> 3) * 8, data.len());
            assert_eq!(field & 1 != 0, i + 1 < pieces.len());
            data.extend_from_slice(&p[48..]);
        }
        assert_eq!(data, whole[40..]);
    }
}
