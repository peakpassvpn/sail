//! Splitting a UDP packet into QUIC datagrams and putting it back together.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use super::proto::{encode_packet, PacketHeader};
use crate::session::SocksAddr;

/// `Packet` commands for `payload`, each small enough for a datagram of
/// `max_size` bytes. Only the first fragment carries the address.
pub fn fragment(
    assoc_id: u16,
    pkt_id: u16,
    addr: &SocksAddr,
    payload: &[u8],
    max_size: usize,
) -> io::Result<Vec<Bytes>> {
    let mut header = PacketHeader {
        assoc_id,
        pkt_id,
        frag_total: 1,
        frag_id: 0,
        addr: Some(addr.clone()),
    };
    // Sized by the first fragment's header, which is the largest.
    let room = max_size
        .checked_sub(header.len())
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            io::Error::other(format!(
                "tuic: datagrams of {} bytes cannot carry a packet header",
                max_size
            ))
        })?;
    if payload.len() <= room {
        return Ok(vec![encode_packet(&header, payload)?]);
    }
    let total = payload.len().div_ceil(room);
    header.frag_total = u8::try_from(total).map_err(|_| {
        io::Error::other(format!(
            "tuic: a packet of {} bytes needs more than 255 fragments",
            payload.len()
        ))
    })?;
    payload
        .chunks(room)
        .enumerate()
        .map(|(i, chunk)| {
            header.frag_id = i as u8;
            if i == 1 {
                header.addr = None;
            }
            encode_packet(&header, chunk)
        })
        .collect()
}

/// A packet some of whose fragments have come.
struct Partial {
    fragments: Vec<Option<Bytes>>,
    received: usize,
    size: usize,
    addr: Option<SocksAddr>,
    started: Instant,
}

/// Fragments of one association's packets waiting for the rest.
///
/// Bounded: at most `max_pending` packets wait at once, the oldest giving
/// way to a new one, and each waits at most `timeout`. UDP loses packets
/// anyway, so dropping one is always allowed.
pub struct Reassembler {
    pending: HashMap<u16, Partial>,
    max_pending: usize,
    timeout: Duration,
}

impl Reassembler {
    pub fn new(max_pending: usize, timeout: Duration) -> Self {
        Self {
            pending: HashMap::new(),
            max_pending: max_pending.max(1),
            timeout,
        }
    }

    /// Takes one fragment, returning the packet it completes, if any.
    pub fn feed(
        &mut self,
        header: PacketHeader,
        data: Bytes,
        now: Instant,
    ) -> Option<(SocksAddr, Bytes)> {
        if header.frag_total <= 1 {
            return header.addr.map(|addr| (addr, data));
        }
        let total = header.frag_total as usize;
        let id = header.frag_id as usize;
        if id >= total {
            return None;
        }
        self.pending
            .retain(|_, p| now.saturating_duration_since(p.started) < self.timeout);
        if let Some(p) = self.pending.get(&header.pkt_id) {
            // A packet id reused for another packet: the old one is lost.
            if p.fragments.len() != total {
                self.pending.remove(&header.pkt_id);
            }
        }
        if !self.pending.contains_key(&header.pkt_id) {
            if self.pending.len() >= self.max_pending {
                let oldest = self
                    .pending
                    .iter()
                    .min_by_key(|(_, p)| p.started)
                    .map(|(k, _)| *k);
                if let Some(oldest) = oldest {
                    self.pending.remove(&oldest);
                }
            }
            self.pending.insert(
                header.pkt_id,
                Partial {
                    fragments: vec![None; total],
                    received: 0,
                    size: 0,
                    addr: None,
                    started: now,
                },
            );
        }
        let p = self.pending.get_mut(&header.pkt_id)?;
        if p.fragments[id].is_some() {
            return None;
        }
        // A reassembled packet is still one UDP packet.
        if p.size + data.len() > u16::MAX as usize {
            self.pending.remove(&header.pkt_id);
            return None;
        }
        if id == 0 {
            p.addr = header.addr;
        }
        p.size += data.len();
        p.fragments[id] = Some(data);
        p.received += 1;
        if p.received < total {
            return None;
        }
        let p = self.pending.remove(&header.pkt_id)?;
        let addr = p.addr?;
        let mut packet = BytesMut::with_capacity(p.size);
        for fragment in p.fragments.into_iter().flatten() {
            packet.extend_from_slice(&fragment);
        }
        Some((addr, packet.freeze()))
    }

    #[cfg(test)]
    fn pending(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::proto::{decode_datagram, Datagram};
    use super::*;

    fn decode(wire: Bytes) -> (PacketHeader, Bytes) {
        match decode_datagram(wire).unwrap() {
            Datagram::Packet(h, p) => (h, p),
            Datagram::Heartbeat => panic!("heartbeat"),
        }
    }

    fn addr() -> SocksAddr {
        SocksAddr::Domain("example.com".into(), 443)
    }

    #[test]
    fn a_small_packet_is_one_fragment() {
        let wire = fragment(1, 2, &addr(), b"hello", 1200).unwrap();
        assert_eq!(wire.len(), 1);
        let (h, p) = decode(wire[0].clone());
        assert_eq!((h.frag_total, h.frag_id), (1, 0));
        let mut r = Reassembler::new(4, Duration::from_secs(10));
        assert_eq!(
            r.feed(h, p, Instant::now()),
            Some((addr(), Bytes::from("hello")))
        );
    }

    #[test]
    fn fragments_fit_and_reassemble_in_any_order() {
        let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let wire = fragment(3, 9, &addr(), &payload, 1200).unwrap();
        assert!(wire.len() > 4);
        assert!(wire.iter().all(|w| w.len() <= 1200));
        let mut frags: Vec<_> = wire.into_iter().map(decode).collect();
        assert!(frags[0].0.addr.is_some());
        assert!(frags[1..].iter().all(|(h, _)| h.addr.is_none()));
        frags.reverse();
        let last = frags.pop().unwrap();
        let mut r = Reassembler::new(4, Duration::from_secs(10));
        let now = Instant::now();
        for (h, p) in frags {
            assert_eq!(r.feed(h, p, now), None);
        }
        let (a, p) = r.feed(last.0, last.1, now).unwrap();
        assert_eq!(a, addr());
        assert_eq!(&p[..], &payload[..]);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn duplicates_are_ignored() {
        let payload = vec![1u8; 3000];
        let frags: Vec<_> = fragment(1, 1, &addr(), &payload, 1200)
            .unwrap()
            .into_iter()
            .map(decode)
            .collect();
        let mut r = Reassembler::new(4, Duration::from_secs(10));
        let now = Instant::now();
        assert_eq!(r.feed(frags[0].0.clone(), frags[0].1.clone(), now), None);
        assert_eq!(r.feed(frags[0].0.clone(), frags[0].1.clone(), now), None);
        let mut done = None;
        for (h, p) in frags.into_iter().skip(1) {
            done = r.feed(h, p, now);
        }
        assert_eq!(done.unwrap().1.len(), 3000);
    }

    #[test]
    fn pending_packets_are_bounded_and_expire() {
        let mut r = Reassembler::new(2, Duration::from_secs(10));
        let now = Instant::now();
        let first = |pkt_id| {
            decode(
                fragment(1, pkt_id, &addr(), &[0u8; 3000], 1200)
                    .unwrap()
                    .remove(0),
            )
        };
        for pkt_id in 0..5 {
            let (h, p) = first(pkt_id);
            r.feed(h, p, now);
        }
        assert_eq!(r.pending(), 2);
        let (h, p) = first(9);
        r.feed(h, p, now + Duration::from_secs(11));
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn a_lost_first_fragment_loses_the_packet() {
        let frags: Vec<_> = fragment(1, 1, &addr(), &[0u8; 3000], 1200)
            .unwrap()
            .into_iter()
            .map(decode)
            .collect();
        let mut r = Reassembler::new(4, Duration::from_secs(10));
        let now = Instant::now();
        // Another sender's fragment 0 without address never reaches here
        // (decoding rejects it), so feed only the rest: nothing completes.
        for (h, p) in frags.into_iter().skip(1) {
            assert_eq!(r.feed(h, p, now), None);
        }
    }

    #[test]
    fn too_many_fragments_is_an_error() {
        assert!(fragment(1, 1, &addr(), &[0u8; 65000], 100).is_err());
        assert!(fragment(1, 1, &addr(), b"x", 10).is_err());
    }
}
