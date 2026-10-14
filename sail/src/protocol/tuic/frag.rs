//! Splitting a UDP packet into QUIC datagrams and putting it back together.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use super::proto::{encode_packet, PacketHeader};
use crate::session::SocksAddr;
use crate::transport::quic::FragmentBudget;

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

/// The largest packet put back together: a UDP packet's length is 16 bits.
const MAX_PACKET: usize = u16::MAX as usize;

/// Fragments of one association's packets waiting for the rest.
///
/// Bounded: at most `max_pending` packets wait at once, the oldest giving
/// way to a new one, each of at most `MAX_PACKET` bytes, and each waits at
/// most `timeout`. What they hold counts against the connection's
/// `budget`, shared by all of its associations. UDP loses packets anyway,
/// so dropping one is always allowed.
pub struct Reassembler {
    pending: HashMap<u16, Partial>,
    max_pending: usize,
    timeout: Duration,
    budget: Arc<FragmentBudget>,
}

impl Reassembler {
    pub fn new(max_pending: usize, timeout: Duration, budget: Arc<FragmentBudget>) -> Self {
        Self {
            pending: HashMap::new(),
            max_pending: max_pending.max(1),
            timeout,
            budget,
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
        self.expire(now);
        // A packet id reused for another packet: the old one is lost.
        if self
            .pending
            .get(&header.pkt_id)
            .is_some_and(|p| p.fragments.len() != total)
        {
            self.remove(header.pkt_id);
        }
        if !self.pending.contains_key(&header.pkt_id) {
            if self.pending.len() >= self.max_pending {
                let oldest = self
                    .pending
                    .iter()
                    .min_by_key(|(_, p)| p.started)
                    .map(|(k, _)| *k);
                if let Some(oldest) = oldest {
                    self.remove(oldest);
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
        // A reassembled packet is still one UDP packet, and the connection
        // holds only so much.
        if p.size + data.len() > MAX_PACKET || !self.budget.take(data.len()) {
            self.remove(header.pkt_id);
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
        self.budget.give(p.size);
        let addr = p.addr?;
        let mut packet = BytesMut::with_capacity(p.size);
        for fragment in p.fragments.into_iter().flatten() {
            packet.extend_from_slice(&fragment);
        }
        Some((addr, packet.freeze()))
    }

    /// Drops the packets that have waited `timeout` for the rest.
    pub fn expire(&mut self, now: Instant) {
        let (timeout, budget) = (self.timeout, &self.budget);
        self.pending.retain(|_, p| {
            let keep = now.saturating_duration_since(p.started) < timeout;
            if !keep {
                budget.give(p.size);
            }
            keep
        });
    }

    fn remove(&mut self, pkt_id: u16) {
        if let Some(p) = self.pending.remove(&pkt_id) {
            self.budget.give(p.size);
        }
    }

    #[cfg(test)]
    fn pending(&self) -> usize {
        self.pending.len()
    }
}

impl Drop for Reassembler {
    fn drop(&mut self) {
        for p in self.pending.values() {
            self.budget.give(p.size);
        }
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

    fn reassembler(max_pending: usize, timeout: u64) -> Reassembler {
        Reassembler::new(
            max_pending,
            Duration::from_secs(timeout),
            FragmentBudget::new(crate::transport::quic::MAX_FRAGMENT_BYTES),
        )
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
        let mut r = reassembler(4, 10);
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
        let mut r = reassembler(4, 10);
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
        let mut r = reassembler(4, 10);
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
        let mut r = reassembler(2, 10);
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
        let mut r = reassembler(4, 10);
        let now = Instant::now();
        // Another sender's fragment 0 without address never reaches here
        // (decoding rejects it), so feed only the rest: nothing completes.
        for (h, p) in frags.into_iter().skip(1) {
            assert_eq!(r.feed(h, p, now), None);
        }
    }

    /// A packet whose fragments come to more than a UDP packet holds is
    /// dropped, and what it held given back.
    #[test]
    fn a_packet_past_the_largest_is_dropped() {
        let budget = FragmentBudget::new(crate::transport::quic::MAX_FRAGMENT_BYTES);
        let mut r = Reassembler::new(4, Duration::from_secs(10), budget.clone());
        let now = Instant::now();
        let header = |frag_id| PacketHeader {
            assoc_id: 1,
            pkt_id: 1,
            frag_total: 3,
            frag_id,
            addr: (frag_id == 0).then(addr),
        };
        let big = Bytes::from(vec![0u8; 30_000]);
        assert_eq!(r.feed(header(0), big.clone(), now), None);
        assert_eq!(r.feed(header(1), big.clone(), now), None);
        assert_eq!(budget.held(), 60_000);
        assert_eq!(r.feed(header(2), big, now), None);
        assert_eq!((r.pending(), budget.held()), (0, 0));
    }

    /// The associations of one connection share its budget: a fragment
    /// past it is dropped with its packet, and what expires, completes or
    /// goes with its association is given back.
    #[test]
    fn associations_share_their_connections_budget() {
        let budget = FragmentBudget::new(4000);
        let now = Instant::now();
        let first = |pkt_id| {
            decode(
                fragment(1, pkt_id, &addr(), &[0u8; 3000], 1200)
                    .unwrap()
                    .remove(0),
            )
        };
        let mut one = Reassembler::new(4, Duration::from_secs(10), budget.clone());
        let mut two = Reassembler::new(4, Duration::from_secs(10), budget.clone());
        let (h, p) = first(1);
        let held = p.len();
        // Three first fragments fit the budget, four do not.
        assert!(3 * held <= 4000 && 4 * held > 4000, "{}", held);
        one.feed(h, p, now);
        let (h, p) = first(2);
        one.feed(h, p, now);
        assert_eq!(budget.held(), 2 * held);
        let (h, p) = first(1);
        two.feed(h, p, now);
        assert_eq!(budget.held(), 3 * held);
        // Past the budget: dropped.
        let (h, p) = first(2);
        two.feed(h, p, now);
        assert_eq!((two.pending(), budget.held()), (1, 3 * held));
        one.expire(now + Duration::from_secs(10));
        assert_eq!((one.pending(), budget.held()), (0, held));
        drop(two);
        assert_eq!(budget.held(), 0);
    }

    #[test]
    fn too_many_fragments_is_an_error() {
        assert!(fragment(1, 1, &addr(), &[0u8; 65000], 100).is_err());
        assert!(fragment(1, 1, &addr(), b"x", 10).is_err());
    }
}
