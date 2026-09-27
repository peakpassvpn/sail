//! Protocols that are only recognized, by their first bytes, as sing-box
//! recognizes them: STUN, DTLS and BitTorrent.

use super::{be_u16, Sniff};

/// A STUN message (RFC 8489), by its magic cookie.
pub fn stun(packet: &[u8]) -> Sniff {
    if packet.len() < 20 || packet[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return Sniff::NotMatch;
    }
    match be_u16(&packet[2..]) {
        Some(len) if packet.len() >= 20 + len as usize => Sniff::Found(None),
        _ => Sniff::NotMatch,
    }
}

/// A DTLS record: a known content type, of DTLS 1.0 or 1.2.
pub fn dtls(packet: &[u8]) -> Sniff {
    if packet.len() < 13 {
        return Sniff::NotMatch;
    }
    match packet[..3] {
        [20 | 21 | 22 | 23 | 25, 0xfe, 0xff | 0xfd] => Sniff::Found(None),
        _ => Sniff::NotMatch,
    }
}

/// The handshake a BitTorrent peer opens a stream with (BEP 3).
pub fn bittorrent_stream(buf: &[u8]) -> Sniff {
    const HEADER: &[u8] = b"\x13BitTorrent protocol";
    let n = buf.len().min(HEADER.len());
    if buf[..n] != HEADER[..n] {
        Sniff::NotMatch
    } else if n < HEADER.len() {
        Sniff::NeedMore
    } else {
        Sniff::Found(None)
    }
}

/// A BitTorrent datagram: a uTP packet (BEP 29), or a UDP tracker's connect
/// request (BEP 15).
pub fn bittorrent_datagram(packet: &[u8]) -> Sniff {
    if utp(packet) || udp_tracker(packet) {
        Sniff::Found(None)
    } else {
        Sniff::NotMatch
    }
}

fn utp(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let (version, kind) = (packet[0] & 0x0f, packet[0] >> 4);
    if version != 1 || kind > 4 {
        return false;
    }
    // The extensions, chained each by the type of the next.
    let mut next = packet[1];
    let mut rest = &packet[20..];
    while next != 0 {
        if next > 4 {
            return false;
        }
        let [kind, len, tail @ ..] = rest else {
            return false;
        };
        let len = *len as usize;
        if tail.len() < len {
            return false;
        }
        next = *kind;
        rest = &tail[len..];
    }
    true
}

fn udp_tracker(packet: &[u8]) -> bool {
    const PROTOCOL_ID: u64 = 0x41727101980;
    packet.len() >= 16 && packet[..8] == PROTOCOL_ID.to_be_bytes() && packet[8..12] == [0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_by_its_cookie() {
        let mut binding = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        binding.extend_from_slice(&[5; 12]);
        assert_eq!(stun(&binding), Sniff::Found(None));
        binding[3] = 4;
        assert_eq!(stun(&binding), Sniff::NotMatch);
        binding.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(stun(&binding), Sniff::Found(None));
        binding[4] = 0;
        assert_eq!(stun(&binding), Sniff::NotMatch);
    }

    #[test]
    fn dtls_by_its_record() {
        let mut hello = vec![22, 0xfe, 0xfd];
        hello.extend_from_slice(&[0; 10]);
        assert_eq!(dtls(&hello), Sniff::Found(None));
        hello[1] = 3;
        assert_eq!(dtls(&hello), Sniff::NotMatch);
        assert_eq!(dtls(&[22, 0xfe, 0xfd]), Sniff::NotMatch);
    }

    #[test]
    fn bittorrent_by_its_handshake() {
        let handshake = b"\x13BitTorrent protocol\0\0\0\0\0\0\0\0";
        assert_eq!(bittorrent_stream(handshake), Sniff::Found(None));
        assert_eq!(bittorrent_stream(&handshake[..5]), Sniff::NeedMore);
        assert_eq!(
            bittorrent_stream(b"\x13BitTorrent protocoL"),
            Sniff::NotMatch
        );
        assert_eq!(bittorrent_stream(b"GET"), Sniff::NotMatch);

        let mut syn = vec![0x41, 2];
        syn.extend_from_slice(&[0; 18]);
        syn.extend_from_slice(&[0, 3, 1, 2, 3]);
        assert_eq!(bittorrent_datagram(&syn), Sniff::Found(None));
        syn.pop();
        assert_eq!(bittorrent_datagram(&syn), Sniff::NotMatch);

        let mut connect = 0x41727101980u64.to_be_bytes().to_vec();
        connect.extend_from_slice(&[0, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(bittorrent_datagram(&connect), Sniff::Found(None));
    }
}
