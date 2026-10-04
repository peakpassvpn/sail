//! Interop with the Linux kernel's WireGuard, in network namespaces.
//!
//! Ignored by default: it needs root, `wireguard-tools`, `socat`, and the
//! namespaces below. The kernel peer lives in `sailwg-a`; this test runs in
//! `sailwg-b` and crafts IP packets straight into the sans-IO core's shell.
//!
//! ```sh
//! ip netns add sailwg-a && ip netns add sailwg-b
//! ip link add sailwg-va netns sailwg-a type veth peer name sailwg-vb netns sailwg-b
//! ip -n sailwg-a addr add 172.31.99.1/24 dev sailwg-va
//! ip -n sailwg-b addr add 172.31.99.2/24 dev sailwg-vb
//! for n in a b; do ip -n sailwg-$n link set lo up; ip -n sailwg-$n link set sailwg-v$n up; done
//! wg genkey > kernel.key && wg genkey > sail.key
//! ip -n sailwg-a link add wg0 type wireguard
//! ip netns exec sailwg-a wg set wg0 private-key kernel.key listen-port 51820 \
//!     peer "$(wg pubkey < sail.key)" allowed-ips 10.99.0.2/32,fd99::2/128 \
//!     endpoint 172.31.99.2:51821
//! ip -n sailwg-a addr add 10.99.0.1/24 dev wg0
//! ip -n sailwg-a addr add fd99::1/64 dev wg0
//! ip -n sailwg-a link set wg0 mtu 1420 up
//! ip netns exec sailwg-a socat UDP4-RECVFROM:7,fork EXEC:cat &
//! ip netns exec sailwg-a socat UDP6-RECVFROM:7,ipv6only=1,fork EXEC:cat &
//!
//! WG_KERNEL_PUBLIC="$(wg pubkey < kernel.key)" WG_SAIL_PRIVATE="$(cat sail.key)" \
//!     ip netns exec sailwg-b cargo test -p sail --features wireguard \
//!     --test test_wireguard_interop -- --ignored --nocapture --test-threads=1
//!
//! ip netns del sailwg-a; ip netns del sailwg-b
//! ```
//!
//! `WG_PSK` sets a preshared key, to match `wg set wg0 peer ...
//! preshared-key <file>`. `WG_INTEROP_REKEY=1` adds a run of a little over three minutes that
//! crosses REKEY_AFTER_TIME.
//!
//! The test covers both roles: first the kernel initiates (a `ping` it
//! runs in `sailwg-a`, which the test answers), then this side does (after
//! the peer is removed and added again), with ICMP echo over IPv4 and
//! IPv6, packets up to the MTU, and UDP to the socat echo servers.
//!
//! A second test floods the kernel with initiations (valid mac1, garbage
//! otherwise) until it is under load, and checks that our handshake gets a
//! cookie reply, and completes on the retry that carries mac2.

#![cfg(feature = "wireguard")]
// Tests drive tasks of their own.
#![allow(clippy::disallowed_methods)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sail::protocol::wireguard::shell::InboundPacket;
use sail::protocol::wireguard::{Device, DeviceConfig, PeerConfig, PeerId, WireGuard};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

const SAIL_V4: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
const KERNEL_V4: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
const SAIL_V6: &str = "fd99::2";
const KERNEL_V6: &str = "fd99::1";
const KERNEL_ENDPOINT: &str = "172.31.99.1:51820";
const LISTEN: &str = "0.0.0.0:51821";

fn base64_key(s: &str) -> [u8; 32] {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.trim().bytes().take_while(|&c| c != b'=') {
        let v = ALPHABET.iter().position(|&a| a == c).expect("base64") as u32;
        bits = bits << 6 | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out.try_into().expect("a 32-byte key")
}

fn base64(key: &[u8; 32]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in key.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

fn env_key(name: &str) -> [u8; 32] {
    base64_key(&std::env::var(name).unwrap_or_else(|_| panic!("{} is not set", name)))
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for part in parts {
        for chunk in part.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += word as u32;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, body: &[u8]) -> Vec<u8> {
    let total = 20 + body.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6] = 0x40; // don't fragment
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let c = checksum(&[&p]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(body);
    p
}

fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
    p[6] = next;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p.extend_from_slice(body);
    p
}

fn v6_pseudo(src: &[u8], dst: &[u8], len: usize, next: u8) -> Vec<u8> {
    let mut ph = Vec::with_capacity(40);
    ph.extend_from_slice(src);
    ph.extend_from_slice(dst);
    ph.extend_from_slice(&(len as u32).to_be_bytes());
    ph.extend_from_slice(&[0, 0, 0, next]);
    ph
}

fn icmp4_echo(ty: u8, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut b = vec![ty, 0, 0, 0];
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(data);
    let c = checksum(&[&b]);
    b[2..4].copy_from_slice(&c.to_be_bytes());
    b
}

fn icmp6_echo(src: Ipv6Addr, dst: Ipv6Addr, ty: u8, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut b = vec![ty, 0, 0, 0];
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(data);
    let ph = v6_pseudo(&src.octets(), &dst.octets(), b.len(), 58);
    let c = checksum(&[&ph, &b]);
    b[2..4].copy_from_slice(&c.to_be_bytes());
    b
}

fn udp(src_port: u16, dst_port: u16, data: &[u8], pseudo: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + data.len());
    b.extend_from_slice(&src_port.to_be_bytes());
    b.extend_from_slice(&dst_port.to_be_bytes());
    b.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(data);
    let c = checksum(&[pseudo, &b]);
    b[6..8].copy_from_slice(&(if c == 0 { 0xffff } else { c }).to_be_bytes());
    b
}

fn udp4(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, data: &[u8]) -> Vec<u8> {
    let mut ph = Vec::new();
    ph.extend_from_slice(&src.octets());
    ph.extend_from_slice(&dst.octets());
    ph.extend_from_slice(&[0, 17]);
    ph.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    ipv4(src, dst, 17, &udp(sp, dp, data, &ph))
}

fn udp6(src: Ipv6Addr, dst: Ipv6Addr, sp: u16, dp: u16, data: &[u8]) -> Vec<u8> {
    let ph = v6_pseudo(&src.octets(), &dst.octets(), 8 + data.len(), 17);
    ipv6(src, dst, 17, &udp(sp, dp, data, &ph))
}

/// The transport payload of an IP packet, checking the header checksum on
/// IPv4: (source, destination, protocol, payload).
fn parse(p: &[u8]) -> (IpAddr, IpAddr, u8, &[u8]) {
    match p[0] >> 4 {
        4 => {
            let ihl = (p[0] & 0x0f) as usize * 4;
            assert_eq!(checksum(&[&p[..ihl]]), 0, "IPv4 header checksum");
            let total = u16::from_be_bytes([p[2], p[3]]) as usize;
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(&p[12..16]).unwrap());
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&p[16..20]).unwrap());
            (src.into(), dst.into(), p[9], &p[ihl..total])
        }
        6 => {
            let len = u16::from_be_bytes([p[4], p[5]]) as usize;
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap());
            (src.into(), dst.into(), p[6], &p[40..40 + len])
        }
        v => panic!("IP version {}", v),
    }
}

async fn recv(rx: &mut Receiver<InboundPacket>) -> InboundPacket {
    // Long enough for a handshake retry: the kernel may still be under
    // load from the other test.
    timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("a packet within 15 s")
        .expect("the shell is running")
}

struct Sail {
    wg: WireGuard,
    rx: Receiver<InboundPacket>,
    peer: PeerId,
    kernel_public: [u8; 32],
}

impl Sail {
    async fn ping4(&mut self, seq: u16, size: usize) {
        let data: Vec<u8> = (0..size).map(|i| (i as u16 ^ seq) as u8).collect();
        let req = ipv4(SAIL_V4, KERNEL_V4, 1, &icmp4_echo(8, 0x5a11, seq, &data));
        self.wg.send(&req).await.unwrap();
        loop {
            let got = recv(&mut self.rx).await;
            assert_eq!(got.peer, self.peer);
            let (src, dst, proto, body) = parse(&got.packet);
            if proto != 1 || body[0] != 0 {
                continue;
            }
            assert_eq!((src, dst), (IpAddr::V4(KERNEL_V4), IpAddr::V4(SAIL_V4)));
            assert_eq!(checksum(&[body]), 0, "ICMP checksum");
            assert_eq!(&body[4..8], &[0x5a, 0x11, (seq >> 8) as u8, seq as u8]);
            assert_eq!(&body[8..], &data[..]);
            return;
        }
    }

    async fn ping6(&mut self, seq: u16, size: usize) {
        let (s, d): (Ipv6Addr, Ipv6Addr) = (SAIL_V6.parse().unwrap(), KERNEL_V6.parse().unwrap());
        let data: Vec<u8> = (0..size).map(|i| (i as u16 ^ seq) as u8).collect();
        let req = ipv6(s, d, 58, &icmp6_echo(s, d, 128, 0x5a11, seq, &data));
        self.wg.send(&req).await.unwrap();
        loop {
            let got = recv(&mut self.rx).await;
            let (src, dst, proto, body) = parse(&got.packet);
            // Skip neighbour discovery and the like.
            if proto != 58 || body[0] != 129 {
                continue;
            }
            assert_eq!((src, dst), (IpAddr::V6(d), IpAddr::V6(s)));
            let ph = v6_pseudo(&d.octets(), &s.octets(), body.len(), 58);
            assert_eq!(checksum(&[&ph, body]), 0, "ICMPv6 checksum");
            assert_eq!(&body[4..8], &[0x5a, 0x11, (seq >> 8) as u8, seq as u8]);
            assert_eq!(&body[8..], &data[..]);
            return;
        }
    }

    async fn udp_echo(&mut self, v6: bool, data: &[u8]) {
        let req = if v6 {
            udp6(
                SAIL_V6.parse().unwrap(),
                KERNEL_V6.parse().unwrap(),
                40000,
                7,
                data,
            )
        } else {
            udp4(SAIL_V4, KERNEL_V4, 40000, 7, data)
        };
        self.wg.send(&req).await.unwrap();
        loop {
            let got = recv(&mut self.rx).await;
            let (_, _, proto, body) = parse(&got.packet);
            if proto != 17 {
                continue;
            }
            assert_eq!(&body[..4], &[0, 7, 0x9c, 0x40]);
            assert_eq!(&body[8..], data);
            return;
        }
    }

    async fn stats(&self) -> sail::protocol::wireguard::PeerStats {
        let peer = self.peer;
        self.wg
            .with_device(|d, _| (d.peer_stats(peer).unwrap(), Vec::new()))
            .await
    }

    /// Forgets the kernel peer and adds it again: new keys, no session.
    async fn reset_peer(&mut self) {
        let (old, public) = (self.peer, self.kernel_public);
        self.peer = self
            .wg
            .with_device(|d, _| {
                d.remove_peer(old).unwrap();
                (d.add_peer(kernel_peer(public)).unwrap(), Vec::new())
            })
            .await;
    }
}

fn kernel_peer(public: [u8; 32]) -> PeerConfig {
    let mut pc = PeerConfig::new(public);
    pc.preshared_key = std::env::var("WG_PSK").ok().map(|k| base64_key(&k).into());
    pc.endpoint = Some(KERNEL_ENDPOINT.parse::<SocketAddr>().unwrap());
    pc.allowed_ips = vec![
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    ];
    pc
}

/// The two tests speak to the one kernel peer, as the one peer it knows:
/// run at once, each would take the other's session from it. Each holds
/// this for as long as it runs, so that they follow one another however
/// the binary is run.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `fut` in a task scope, as an instance's: what sail's parts spawn goes
/// into one.
fn scoped<F: std::future::Future>(fut: F) -> impl std::future::Future<Output = F::Output> {
    static SCOPE: std::sync::OnceLock<sail::runtime::scope::TaskScope> = std::sync::OnceLock::new();
    SCOPE.get_or_init(Default::default).clone().enter(fut)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root and the sailwg-* namespaces; see the module docs"]
async fn kernel_wireguard() {
    scoped(kernel_wireguard_scoped()).await
}

async fn kernel_wireguard_scoped() {
    let _one = ONE_AT_A_TIME.lock().await;
    let kernel_public = env_key("WG_KERNEL_PUBLIC");
    let private = env_key("WG_SAIL_PRIVATE");
    let netns = std::env::var("WG_KERNEL_NETNS").unwrap_or_else(|_| "sailwg-a".into());

    let sock = UdpSocket::bind(LISTEN).await.unwrap();
    let mut dev = Device::new(
        DeviceConfig::new(private),
        tokio::time::Instant::now().into_std(),
    );
    let peer = dev.add_peer(kernel_peer(kernel_public)).unwrap();
    let (wg, rx) = WireGuard::spawn(dev, Arc::new(sock));
    let mut sail = Sail {
        wg,
        rx,
        peer,
        kernel_public,
    };

    // 1. The kernel initiates: it pings us, we answer. Remove and re-add
    // its peer first, so that it holds no session from an earlier run, and
    // point it at us: another test may have moved its endpoint.
    let sail_public = base64(&sail::protocol::wireguard::crypto::public_key(&private));
    let script = format!(
        "set -e; c=$(mktemp); wg showconf wg0 > $c; wg set wg0 peer {p} remove; \
         wg addconf wg0 $c; rm $c; wg set wg0 peer {p} endpoint 172.31.99.2:51821",
        p = sail_public
    );
    let reset = std::process::Command::new("ip")
        .args(["netns", "exec", &netns, "sh", "-c", &script])
        .status()
        .unwrap();
    assert!(reset.success());
    let ping = std::thread::spawn(move || {
        std::process::Command::new("ip")
            .args([
                "netns", "exec", &netns, "ping", "-c", "5", "-i", "0.2", "-w", "30",
            ])
            .arg(SAIL_V4.to_string())
            .output()
            .unwrap()
    });
    // Answer until ping is done: with -w it waits for five replies, even
    // if the handshake needs a retry (the kernel may still be under load
    // from the other test, and want a cookie).
    let mut answered = 0;
    while !ping.is_finished() {
        let Ok(Some(got)) = timeout(Duration::from_millis(200), sail.rx.recv()).await else {
            continue;
        };
        let (src, dst, proto, body) = parse(&got.packet);
        if proto != 1 || body[0] != 8 {
            continue;
        }
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (src, dst) else {
            panic!("an IPv4 echo");
        };
        assert_eq!(checksum(&[body]), 0);
        let id = u16::from_be_bytes([body[4], body[5]]);
        let seq = u16::from_be_bytes([body[6], body[7]]);
        let reply = ipv4(dst, src, 1, &icmp4_echo(0, id, seq, &body[8..]));
        sail.wg.send(&reply).await.unwrap();
        answered += 1;
    }
    assert!(answered >= 5);
    let out = ping.join().unwrap();
    println!("{}", String::from_utf8_lossy(&out.stdout));
    assert!(out.status.success(), "the kernel's ping failed");
    let st = sail.stats().await;
    assert!(st.has_session && st.last_handshake.is_some());
    println!("responder role: ok, {:?}", st);

    // 2. We initiate, on a fresh peer.
    sail.reset_peer().await;
    let t = Instant::now();
    sail.ping4(1, 56).await;
    println!("initiator role: first echo after {:?}", t.elapsed());
    for (seq, size) in (2u16..).zip([0, 1, 15, 16, 17, 100, 500, 1000, 1371, 1392]) {
        sail.ping4(seq, size).await;
    }
    for seq in 100..300 {
        sail.ping4(seq, 64).await;
    }
    for (seq, size) in (1u16..).zip([0, 56, 1000, 1372]) {
        sail.ping6(seq, size).await;
    }
    sail.udp_echo(false, b"hello over udp4").await;
    sail.udp_echo(true, b"hello over udp6").await;
    sail.udp_echo(false, &[0xab; 1392 - 28]).await;
    let st = sail.stats().await;
    println!("initiator role: ok, {:?}", st);

    // 3. Optionally, across REKEY_AFTER_TIME.
    if std::env::var("WG_INTEROP_REKEY").is_ok() {
        let first = st.last_handshake.unwrap();
        let start = Instant::now();
        let mut seq = 1000u16;
        while start.elapsed() < Duration::from_secs(190) {
            sail.ping4(seq, 32).await;
            seq = seq.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let st = sail.stats().await;
        assert!(st.last_handshake.unwrap() > first, "no rekey happened");
        println!(
            "rekey: ok, last handshake {:?} after the first",
            st.last_handshake.unwrap() - first
        );
    }
}

/// A transport that counts the cookie replies it receives.
struct Counting {
    sock: UdpSocket,
    cookie_replies: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl sail::protocol::wireguard::Transport for Counting {
    async fn send_to(&self, datagram: &[u8], dst: SocketAddr) -> std::io::Result<()> {
        self.sock.send_to(datagram, dst).await.map(|_| ())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let r = self.sock.recv_from(buf).await?;
        if r.0 > 0 && buf[0] == 3 {
            self.cookie_replies
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(r)
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root and the sailwg-* namespaces; see the module docs"]
async fn kernel_cookie_under_load() {
    scoped(kernel_cookie_under_load_scoped()).await
}

async fn kernel_cookie_under_load_scoped() {
    let _one = ONE_AT_A_TIME.lock().await;
    use sail::protocol::wireguard::cookie::LABEL_MAC1;
    use sail::protocol::wireguard::crypto;

    let kernel_public = env_key("WG_KERNEL_PUBLIC");
    let private = env_key("WG_SAIL_PRIVATE");

    // The flood: initiations whose mac1 is right, so the kernel queues
    // them for the expensive checks, and nothing else is.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mac1_key = crypto::hash(&[LABEL_MAC1, &kernel_public]);
    let msgs: Arc<Vec<[u8; 148]>> = Arc::new(
        (0..256)
            .map(|_| {
                let mut msg = [0u8; 148];
                msg[0] = 1;
                crypto::random_bytes(&mut msg[4..116]);
                let mac1 = crypto::mac(&mac1_key, &[&msg[..116]]);
                msg[116..132].copy_from_slice(&mac1);
                msg
            })
            .collect(),
    );
    let floods: Vec<_> = (0..4)
        .map(|_| {
            let (stop, msgs) = (stop.clone(), msgs.clone());
            std::thread::spawn(move || {
                let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
                sock.connect(KERNEL_ENDPOINT).unwrap();
                let mut sent = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    for m in msgs.iter() {
                        let _ = sock.send(m);
                    }
                    sent += msgs.len() as u64;
                }
                sent
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let transport = Arc::new(Counting {
        sock: UdpSocket::bind("0.0.0.0:51822").await.unwrap(),
        cookie_replies: Default::default(),
    });
    let mut dev = Device::new(
        DeviceConfig::new(private),
        tokio::time::Instant::now().into_std(),
    );
    let peer = dev.add_peer(kernel_peer(kernel_public)).unwrap();
    let (wg, rx) = WireGuard::spawn(dev, transport.clone());
    let mut sail = Sail {
        wg,
        rx,
        peer,
        kernel_public,
    };
    let req = ipv4(SAIL_V4, KERNEL_V4, 1, &icmp4_echo(8, 1, 1, b"under load"));
    sail.wg.send(&req).await.unwrap();
    // The first initiation gets a cookie; the retry, REKEY_TIMEOUT later,
    // carries mac2 and gets a response.
    let got = timeout(Duration::from_secs(15), sail.rx.recv()).await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let sent: u64 = floods.into_iter().map(|f| f.join().unwrap()).sum();
    let cookies = transport
        .cookie_replies
        .load(std::sync::atomic::Ordering::Relaxed);
    println!(
        "flood: {} initiations; cookie replies to us: {}",
        sent, cookies
    );
    assert!(cookies >= 1, "the kernel never demanded a cookie");
    let got = got.expect("an echo reply within 15 s").unwrap();
    let (_, _, proto, body) = parse(&got.packet);
    assert_eq!((proto, body[0]), (1, 0));
    sail.ping4(2, 100).await;
}
