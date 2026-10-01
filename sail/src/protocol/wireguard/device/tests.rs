//! In-process tests of the device: peers wired together by a fake network,
//! lossless or deliberately lossy, on a fake clock.

use super::*;
use crate::protocol::wireguard::messages::DATA_MIN_LEN;

const A_ADDR: &str = "192.0.2.1:51820";
const B_ADDR: &str = "192.0.2.2:51820";

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A minimal IPv4 UDP packet from `src` to `dst` carrying `payload`.
fn ipv4(src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
    let src: Ipv4Addr = src.parse().unwrap();
    let dst: Ipv4Addr = dst.parse().unwrap();
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&1000u16.to_be_bytes());
    p[22..24].copy_from_slice(&2000u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

struct Node {
    dev: Device,
    addr: SocketAddr,
    delivered: Vec<(PeerId, Vec<u8>)>,
}

type Datagram = (SocketAddr, SocketAddr, Vec<u8>);

/// Devices and the datagrams in flight between them.
struct Net {
    nodes: Vec<Node>,
    now: Instant,
    wire: VecDeque<Datagram>,
    /// Message types the network drops.
    drop_types: Vec<u8>,
    /// Every datagram sent, dropped or not.
    log: Vec<Datagram>,
}

impl Net {
    fn new(now: Instant) -> Self {
        Net {
            nodes: Vec::new(),
            now,
            wire: VecDeque::new(),
            drop_types: Vec::new(),
            log: Vec::new(),
        }
    }

    fn add(&mut self, addr: &str, config: DeviceConfig) -> usize {
        self.nodes.push(Node {
            dev: Device::new(config, self.now),
            addr: sa(addr),
            delivered: Vec::new(),
        });
        self.nodes.len() - 1
    }

    fn send(&mut self, from: usize, out: Vec<Transmit>) {
        let src = self.nodes[from].addr;
        for t in out {
            self.wire.push_back((src, t.dst, t.payload));
        }
    }

    fn encap(&mut self, from: usize, packet: &[u8]) {
        let now = self.now;
        let out = self.nodes[from].dev.encapsulate(now, packet).unwrap();
        self.send(from, out);
    }

    /// Delivers until nothing is in flight.
    fn pump(&mut self) {
        let mut guard = 0;
        while let Some((src, dst, payload)) = self.wire.pop_front() {
            guard += 1;
            assert!(guard < 10_000, "datagram storm");
            self.log.push((src, dst, payload.clone()));
            if self.drop_types.contains(&payload[0]) {
                continue;
            }
            let Some(i) = self.nodes.iter().position(|n| n.addr == dst) else {
                continue;
            };
            let now = self.now;
            let node = &mut self.nodes[i];
            let mut out = Vec::new();
            match node.dev.handle_incoming(now, src, &payload) {
                Incoming::WriteBack(t) => out.push(t),
                Incoming::Deliver { peer, packet } => node.delivered.push((peer, packet)),
                Incoming::Nothing => {}
            }
            while let Some(t) = node.dev.poll_transmit() {
                out.push(t);
            }
            self.send(i, out);
        }
    }

    /// Moves the clock to `to`, firing timers at each deadline on the way.
    fn advance_to(&mut self, to: Instant) {
        loop {
            let next = self
                .nodes
                .iter_mut()
                .filter_map(|n| n.dev.next_deadline())
                .min();
            match next {
                Some(d) if d <= to => {
                    self.now = self.now.max(d);
                    for i in 0..self.nodes.len() {
                        let now = self.now;
                        let out = self.nodes[i].dev.tick(now);
                        self.send(i, out);
                    }
                    self.pump();
                }
                _ => break,
            }
        }
        self.now = to;
    }

    fn advance(&mut self, by: Duration) {
        let to = self.now + by;
        self.advance_to(to);
    }

    fn take_delivered(&mut self, i: usize) -> Vec<(PeerId, Vec<u8>)> {
        std::mem::take(&mut self.nodes[i].delivered)
    }

    fn count(&self, ty: u8) -> usize {
        self.log.iter().filter(|(_, _, p)| p[0] == ty).count()
    }

    fn keepalives_from(&self, addr: &str) -> usize {
        let addr = sa(addr);
        self.log
            .iter()
            .filter(|(s, _, p)| *s == addr && p[0] == TYPE_DATA && p.len() == DATA_MIN_LEN)
            .count()
    }
}

struct Pair {
    net: Net,
    a: usize,
    b: usize,
    /// B as A's peer.
    pa: PeerId,
    /// A as B's peer.
    pb: PeerId,
}

/// A at 10.0.0.1 and B at 10.0.0.2, each routing the other's /32.
fn pair(tweak_a: impl FnOnce(&mut PeerConfig), tweak_b: impl FnOnce(&mut PeerConfig)) -> Pair {
    let mut net = Net::new(Instant::now());
    let ka = crypto::generate_private_key();
    let kb = crypto::generate_private_key();
    let psk = [9u8; 32];
    let a = net.add(A_ADDR, DeviceConfig::new(ka));
    let b = net.add(B_ADDR, DeviceConfig::new(kb));

    let mut to_b = PeerConfig::new(crypto::public_key(&kb));
    to_b.endpoint = Some(sa(B_ADDR));
    to_b.allowed_ips = vec![(ip("10.0.0.2"), 32)];
    to_b.preshared_key = Some(psk.into());
    tweak_a(&mut to_b);
    let pa = net.nodes[a].dev.add_peer(to_b).unwrap();

    let mut to_a = PeerConfig::new(crypto::public_key(&ka));
    to_a.endpoint = Some(sa(A_ADDR));
    to_a.allowed_ips = vec![(ip("10.0.0.1"), 32)];
    to_a.preshared_key = Some(psk.into());
    tweak_b(&mut to_a);
    let pb = net.nodes[b].dev.add_peer(to_a).unwrap();
    Pair { net, a, b, pa, pb }
}

fn default_pair() -> Pair {
    pair(|_| {}, |_| {})
}

#[test]
fn handshake_and_data_both_ways() {
    let Pair {
        mut net,
        a,
        b,
        pa,
        pb,
    } = default_pair();
    let p1 = ipv4("10.0.0.1", "10.0.0.2", b"hello");
    net.encap(a, &p1);
    net.pump();
    // Initiation, response, then the staged packet.
    assert_eq!(net.count(TYPE_INITIATION), 1);
    assert_eq!(net.count(TYPE_RESPONSE), 1);
    assert_eq!(net.take_delivered(b), vec![(pb, p1)]);

    let p2 = ipv4("10.0.0.2", "10.0.0.1", b"world, a longer payload to pad");
    net.encap(b, &p2);
    net.pump();
    assert_eq!(net.take_delivered(a), vec![(pa, p2)]);

    for i in 0..50u8 {
        net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", &[i; 100]));
    }
    net.pump();
    assert_eq!(net.take_delivered(b).len(), 50);
    assert_eq!(net.count(TYPE_INITIATION), 1);

    let st = net.nodes[a].dev.peer_stats(pa).unwrap();
    assert!(st.has_session && st.last_handshake.is_some());
    assert!(st.tx_bytes > 0 && st.rx_bytes > 0);
    // Transport plaintexts are padded to 16 bytes.
    for (_, _, p) in net.log.iter().filter(|(_, _, p)| p[0] == TYPE_DATA) {
        assert_eq!((p.len() - DATA_HEADER_LEN - crypto::TAG_LEN) % 16, 0);
    }
}

#[test]
fn responder_waits_for_confirmation() {
    let Pair { mut net, a, b, .. } = default_pair();
    // Only the initiation and response cross; A's first data is lost.
    net.drop_types = vec![TYPE_DATA];
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"x"));
    net.pump();
    net.drop_types.clear();
    // B holds a next keypair, not a current one: its packet waits, and it
    // may not initiate within REKEY_TIMEOUT of its response.
    net.encap(b, &ipv4("10.0.0.2", "10.0.0.1", b"y"));
    net.pump();
    assert!(net.take_delivered(a).is_empty());
    assert_eq!(net.count(TYPE_INITIATION), 1);
    // A's next packet confirms the session and releases B's.
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"z"));
    net.pump();
    assert_eq!(net.take_delivered(b).len(), 1);
    assert_eq!(net.take_delivered(a).len(), 1);
}

#[test]
fn allowed_ips_route_and_filter() {
    let mut net = Net::new(Instant::now());
    let keys: Vec<[u8; 32]> = (0..3).map(|_| crypto::generate_private_key()).collect();
    let hub = net.add("192.0.2.10:1", DeviceConfig::new(keys[0]));
    let x = net.add("192.0.2.11:1", DeviceConfig::new(keys[1]));
    let y = net.add("192.0.2.12:1", DeviceConfig::new(keys[2]));

    let peer = |k: &[u8; 32], ep: &str, ips: &[(&str, u8)]| {
        let mut c = PeerConfig::new(crypto::public_key(k));
        c.endpoint = Some(sa(ep));
        c.allowed_ips = ips.iter().map(|(i, l)| (ip(i), *l)).collect();
        c
    };
    // The hub routes 10.1/16 to X, but 10.1.2/24 to Y.
    let hx = net.nodes[hub]
        .dev
        .add_peer(peer(&keys[1], "192.0.2.11:1", &[("10.1.0.0", 16)]))
        .unwrap();
    let hy = net.nodes[hub]
        .dev
        .add_peer(peer(
            &keys[2],
            "192.0.2.12:1",
            &[("10.1.2.0", 24), ("fd00::", 64)],
        ))
        .unwrap();
    for n in [x, y] {
        net.nodes[n]
            .dev
            .add_peer(peer(&keys[0], "192.0.2.10:1", &[("0.0.0.0", 0)]))
            .unwrap();
    }
    assert_eq!(
        net.nodes[hub].dev.allowed_ips(hy),
        vec![(ip("10.1.2.0"), 24), (ip("fd00::"), 64)]
    );

    net.encap(hub, &ipv4("10.9.9.9", "10.1.7.7", b"to x"));
    net.encap(hub, &ipv4("10.9.9.9", "10.1.2.7", b"to y"));
    net.pump();
    assert_eq!(net.take_delivered(x).len(), 1);
    assert_eq!(net.take_delivered(y).len(), 1);

    let now = net.now;
    assert_eq!(
        net.nodes[hub]
            .dev
            .encapsulate(now, &ipv4("10.9.9.9", "10.2.0.1", b"")),
        Err(Error::NoRoute(ip("10.2.0.1")))
    );
    assert_eq!(
        net.nodes[hub].dev.encapsulate(now, &[0x10; 30]),
        Err(Error::NotIp)
    );

    // X may send from 10.1/16, but not from Y's 10.1.2/24.
    net.encap(x, &ipv4("10.1.7.7", "10.9.9.9", b"legit"));
    net.encap(x, &ipv4("10.1.2.7", "10.9.9.9", b"spoofed"));
    net.encap(x, &ipv4("10.5.0.1", "10.9.9.9", b"outside"));
    net.pump();
    let got = net.take_delivered(hub);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, hx);
    assert!(got[0].1.ends_with(b"legit"));
}

#[test]
fn replayed_or_tampered_data_is_dropped() {
    let Pair { mut net, a, b, .. } = default_pair();
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"once"));
    net.pump();
    assert_eq!(net.take_delivered(b).len(), 1);
    let (src, dst, p) = net
        .log
        .iter()
        .find(|(_, _, p)| p[0] == TYPE_DATA)
        .cloned()
        .unwrap();
    net.wire.push_back((src, dst, p.clone()));
    net.pump();
    assert!(net.take_delivered(b).is_empty());
    let mut bad = p;
    *bad.last_mut().unwrap() ^= 1;
    net.wire.push_back((src, dst, bad));
    net.pump();
    assert!(net.take_delivered(b).is_empty());
}

#[test]
fn reserved_bytes_are_sent_and_ignored() {
    let Pair { mut net, a, b, .. } = pair(|c| c.reserved = [0xaa, 0xbb, 0xcc], |_| {});
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"warp"));
    net.pump();
    assert_eq!(net.take_delivered(b).len(), 1);
    net.encap(b, &ipv4("10.0.0.2", "10.0.0.1", b"back"));
    net.pump();
    assert_eq!(net.take_delivered(a).len(), 1);
    for (src, _, p) in &net.log {
        let want: &[u8] = if *src == sa(A_ADDR) {
            &[0xaa, 0xbb, 0xcc]
        } else {
            &[0, 0, 0]
        };
        assert_eq!(&p[1..4], want, "type {}", p[0]);
    }
}

#[test]
fn endpoint_roams() {
    let Pair {
        mut net, a, b, pb, ..
    } = default_pair();
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"1"));
    net.pump();
    net.take_delivered(b);
    // A moves.
    net.nodes[a].addr = sa("198.51.100.7:4242");
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"2"));
    net.pump();
    assert_eq!(net.take_delivered(b).len(), 1);
    let roamed = Some(sa("198.51.100.7:4242"));
    assert_eq!(net.nodes[b].dev.peer_stats(pb).unwrap().endpoint, roamed);
    net.encap(b, &ipv4("10.0.0.2", "10.0.0.1", b"3"));
    net.pump();
    assert_eq!(net.take_delivered(a).len(), 1);
    // Unauthenticated datagrams do not move it.
    let mut junk = vec![TYPE_DATA; 64];
    junk[4..8].copy_from_slice(&[1, 2, 3, 4]);
    net.wire.push_back((sa("203.0.113.1:1"), sa(B_ADDR), junk));
    net.pump();
    assert_eq!(net.nodes[b].dev.peer_stats(pb).unwrap().endpoint, roamed);
}

#[test]
fn learns_endpoint_from_initiator() {
    let Pair { mut net, a, b, .. } = pair(|_| {}, |c| c.endpoint = None);
    // B cannot reach A until A speaks: its packet waits.
    net.encap(b, &ipv4("10.0.0.2", "10.0.0.1", b"early"));
    net.pump();
    assert_eq!(net.count(TYPE_INITIATION), 0);
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"hi"));
    net.pump();
    assert_eq!(net.take_delivered(b).len(), 1);
    // The confirmed session flushes B's staged packet.
    assert_eq!(net.take_delivered(a).len(), 1);
}

#[test]
fn retransmits_then_gives_up() {
    let Pair { mut net, a, pa, .. } = default_pair();
    net.drop_types = vec![TYPE_INITIATION];
    let t0 = net.now;
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"lost"));
    net.pump();
    assert_eq!(net.count(TYPE_INITIATION), 1);
    net.advance_to(t0 + REKEY_TIMEOUT - Duration::from_millis(1));
    assert_eq!(net.count(TYPE_INITIATION), 1);
    // One retry per REKEY_TIMEOUT + jitter.
    net.advance_to(t0 + REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX);
    assert_eq!(net.count(TYPE_INITIATION), 2);
    // The first attempt and MAX_TIMER_HANDSHAKES + 1 retries, as Linux.
    net.advance_to(t0 + Duration::from_secs(120));
    let all = MAX_TIMER_HANDSHAKES as usize + 2;
    assert_eq!(net.count(TYPE_INITIATION), all);
    let peer = net.nodes[a].dev.peer(pa).unwrap();
    assert!(peer.staged.is_empty());
    assert!(peer.timers.zero_key_material.is_pending());
    net.advance(Duration::from_secs(600));
    assert_eq!(net.count(TYPE_INITIATION), all);
}

#[test]
fn initiations_are_rate_limited() {
    let Pair { mut net, a, .. } = default_pair();
    net.drop_types = vec![TYPE_INITIATION];
    for _ in 0..20 {
        net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"x"));
    }
    net.pump();
    assert_eq!(net.count(TYPE_INITIATION), 1);
}

#[test]
fn staged_queue_is_bounded() {
    let Pair {
        mut net, a, b, pa, ..
    } = default_pair();
    net.drop_types = vec![TYPE_INITIATION];
    for i in 0..(MAX_STAGED_PACKETS + 10) as u32 {
        net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", &i.to_be_bytes()));
    }
    net.pump();
    let staged = net.nodes[a].dev.peer(pa).unwrap().staged.len();
    assert_eq!(staged, MAX_STAGED_PACKETS);
    net.drop_types.clear();
    net.advance(REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX);
    let got = net.take_delivered(b);
    assert_eq!(got.len(), MAX_STAGED_PACKETS);
    // The oldest went.
    assert!(got[0].1.ends_with(&10u32.to_be_bytes()));
}

#[test]
fn passive_keepalive_and_new_handshake_timers() {
    let Pair { mut net, a, b, .. } = default_pair();
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"ping"));
    net.pump();
    assert_eq!(net.keepalives_from(B_ADDR), 0);
    // B got data and sent nothing back: a keepalive after KEEPALIVE_TIMEOUT.
    net.advance(KEEPALIVE_TIMEOUT - Duration::from_millis(1));
    assert_eq!(net.keepalives_from(B_ADDR), 0);
    net.advance(Duration::from_millis(2));
    assert_eq!(net.keepalives_from(B_ADDR), 1);
    assert!(net.take_delivered(a).is_empty());
    // The keepalive stopped A's new-handshake timer.
    net.advance(Duration::from_secs(30));
    assert_eq!(net.count(TYPE_INITIATION), 1);

    // B goes silent: A's data gets no answer, and after KEEPALIVE_TIMEOUT
    // + REKEY_TIMEOUT (+ jitter) A starts a new handshake.
    net.nodes[b].addr = sa("192.0.2.99:1");
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"hello?"));
    net.pump();
    net.advance(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT - Duration::from_millis(1));
    assert_eq!(net.count(TYPE_INITIATION), 1);
    net.advance(REKEY_TIMEOUT_JITTER_MAX + Duration::from_millis(2));
    assert_eq!(net.count(TYPE_INITIATION), 2);
}

#[test]
fn persistent_keepalive() {
    let Pair { mut net, .. } = pair(
        |c| c.persistent_keepalive = Some(Duration::from_secs(25)),
        |_| {},
    );
    // Configuring it handshakes and sends a keepalive right away.
    net.advance(Duration::from_millis(1));
    assert_eq!(net.count(TYPE_INITIATION), 1);
    let k0 = net.keepalives_from(A_ADDR);
    assert!(k0 >= 1);
    net.advance(Duration::from_secs(24));
    assert_eq!(net.keepalives_from(A_ADDR), k0);
    net.advance(Duration::from_secs(2));
    assert_eq!(net.keepalives_from(A_ADDR), k0 + 1);
    net.advance(Duration::from_secs(25));
    assert_eq!(net.keepalives_from(A_ADDR), k0 + 2);
}

#[test]
fn rekey_after_time_keeps_previous_keypair() {
    let Pair {
        mut net, a, b, pa, ..
    } = default_pair();
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"1"));
    net.pump();
    net.take_delivered(b);
    let current = |net: &Net| {
        let k = &net.nodes[a].dev.peer(pa).unwrap().keypairs;
        (
            k.previous.as_ref().map(|k| k.local_index),
            k.current.as_ref().unwrap().local_index,
        )
    };
    let (_, first) = current(&net);

    // Traffic both ways, so no timer rekeys first.
    let step = Duration::from_secs(5);
    let mut t = Duration::ZERO;
    while t + step < REKEY_AFTER_TIME {
        net.advance(step);
        t += step;
        net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"tick"));
        net.encap(b, &ipv4("10.0.0.2", "10.0.0.1", b"tock"));
        net.pump();
    }
    assert_eq!(net.count(TYPE_INITIATION), 1);

    // Past REKEY_AFTER_TIME, the initiator's next send starts a handshake.
    // Hold back that packet, sent under the old keypair.
    net.advance(step + Duration::from_secs(1));
    net.drop_types = vec![TYPE_DATA];
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"old key"));
    net.pump();
    net.drop_types.clear();
    assert_eq!(net.count(TYPE_INITIATION), 2);
    let old = net
        .log
        .iter()
        .rev()
        .find(|(s, _, p)| *s == sa(A_ADDR) && p[0] == TYPE_DATA && p.len() > DATA_MIN_LEN)
        .cloned()
        .unwrap();
    let (prev, now_current) = current(&net);
    assert_eq!(prev, Some(first));
    assert_ne!(now_current, first);

    // It still arrives after the rekey.
    net.take_delivered(b);
    net.wire.push_back(old);
    net.pump();
    let got = net.take_delivered(b);
    assert_eq!(got.len(), 1);
    assert!(got[0].1.ends_with(b"old key"));
    // And new traffic flows on the new keypair both ways.
    net.take_delivered(a);
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"new"));
    net.encap(b, &ipv4("10.0.0.2", "10.0.0.1", b"new"));
    net.pump();
    assert_eq!(net.take_delivered(b).len(), 1);
    assert_eq!(net.take_delivered(a).len(), 1);
}

#[test]
fn session_expiry_and_zeroing() {
    let Pair {
        mut net, a, b, pa, ..
    } = default_pair();
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"1"));
    net.pump();
    net.take_delivered(b);
    // Silence: past REJECT_AFTER_TIME the session cannot send.
    net.drop_types = vec![1, 2, 3, 4];
    net.advance(REJECT_AFTER_TIME + Duration::from_secs(1));
    let now = net.now;
    let kp = net.nodes[a]
        .dev
        .peer_mut(pa)
        .unwrap()
        .keypairs
        .current
        .as_mut();
    assert!(!kp.unwrap().can_send(now));
    net.drop_types.clear();
    let inits = net.count(TYPE_INITIATION);
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"2"));
    net.pump();
    assert_eq!(net.count(TYPE_INITIATION), inits + 1);
    assert_eq!(net.take_delivered(b).len(), 1);

    // REJECT_AFTER_TIME * 3 after the last session, all keys go.
    net.drop_types = vec![1, 2, 3, 4];
    net.advance(REJECT_AFTER_TIME * 3 + Duration::from_secs(1));
    let p = net.nodes[a].dev.peer(pa).unwrap();
    assert!(p.keypairs.current.is_none() && p.keypairs.previous.is_none());
    assert!(net.nodes[a].dev.s.indices.is_empty());
}

#[test]
fn rekey_after_messages() {
    let Pair {
        mut net, a, b, pa, ..
    } = default_pair();
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"1"));
    net.pump();
    net.take_delivered(b);
    let kp = net.nodes[a]
        .dev
        .peer_mut(pa)
        .unwrap()
        .keypairs
        .current
        .as_mut();
    kp.unwrap().set_send_counter(REKEY_AFTER_MESSAGES + 1);
    // Past the initiation rate limit.
    net.advance(REKEY_TIMEOUT);
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"2"));
    net.pump();
    assert_eq!(net.count(TYPE_INITIATION), 2);
    assert_eq!(net.take_delivered(b).len(), 1);
}

#[test]
fn cookie_under_load() {
    let mut net = Net::new(Instant::now());
    let ka = crypto::generate_private_key();
    let kb = crypto::generate_private_key();
    let a = net.add(A_ADDR, DeviceConfig::new(ka));
    let mut cb = DeviceConfig::new(kb);
    cb.under_load_threshold = 0;
    let b = net.add(B_ADDR, cb);
    let mut to_b = PeerConfig::new(crypto::public_key(&kb));
    to_b.endpoint = Some(sa(B_ADDR));
    to_b.allowed_ips = vec![(ip("10.0.0.2"), 32)];
    let pa = net.nodes[a].dev.add_peer(to_b).unwrap();
    let mut to_a = PeerConfig::new(crypto::public_key(&ka));
    to_a.allowed_ips = vec![(ip("10.0.0.1"), 32)];
    net.nodes[b].dev.add_peer(to_a).unwrap();

    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"hi"));
    net.pump();
    // B, under load, answers the cookie-less initiation with a cookie.
    assert_eq!(net.count(TYPE_COOKIE_REPLY), 1);
    assert_eq!(net.count(TYPE_RESPONSE), 0);
    assert!(net.nodes[a].dev.peer(pa).unwrap().cookie.has_cookie());
    // The retry carries mac2, and B answers it.
    net.advance(REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX);
    assert_eq!(net.count(TYPE_INITIATION), 2);
    assert_eq!(net.count(TYPE_RESPONSE), 1);
    assert_eq!(net.take_delivered(b).len(), 1);
    let retry = net
        .log
        .iter()
        .filter(|(_, _, p)| p[0] == TYPE_INITIATION)
        .nth(1)
        .unwrap();
    assert_ne!(&retry.2[132..], &[0u8; 16]);
}

#[test]
fn cookie_reply_under_the_wrong_key_is_ignored() {
    let Pair { mut net, a, pa, .. } = default_pair();
    net.drop_types = vec![TYPE_INITIATION];
    net.encap(a, &ipv4("10.0.0.1", "10.0.0.2", b"hi"));
    net.pump();
    let idx = net.nodes[a]
        .dev
        .peer(pa)
        .unwrap()
        .handshake
        .local_index
        .unwrap();
    let mut other = CookieChecker::new(&[5u8; 32]);
    let init = net.log[0].2.clone();
    let reply = other.create_reply(&init, idx, sa(A_ADDR), net.now);
    net.wire
        .push_back((sa(B_ADDR), sa(A_ADDR), reply.to_bytes().to_vec()));
    net.pump();
    assert!(!net.nodes[a].dev.peer(pa).unwrap().cookie.has_cookie());
}

#[test]
fn add_and_remove_peers() {
    let now = Instant::now();
    let k = crypto::generate_private_key();
    let mut d = Device::new(DeviceConfig::new(k), now);
    assert_eq!(
        d.add_peer(PeerConfig::new(crypto::public_key(&k))),
        Err(Error::OwnKey)
    );
    let other = crypto::public_key(&crypto::generate_private_key());
    let mut c = PeerConfig::new(other);
    c.allowed_ips = vec![(ip("10.0.0.0"), 8)];
    let id = d.add_peer(c.clone()).unwrap();
    assert_eq!(d.add_peer(c), Err(Error::DuplicatePeer));
    assert_eq!(d.peer_by_key(&other), Some(id));
    d.remove_peer(id).unwrap();
    assert_eq!(
        d.encapsulate(now, &ipv4("10.0.0.1", "10.0.0.2", b"")),
        Err(Error::NoRoute(ip("10.0.0.2")))
    );
    let mut bad = PeerConfig::new(other);
    bad.allowed_ips = vec![(ip("10.0.0.0"), 33)];
    assert_eq!(
        d.add_peer(bad),
        Err(Error::InvalidPrefix(ip("10.0.0.0"), 33))
    );
}
