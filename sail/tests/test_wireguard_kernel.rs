//! The WireGuard endpoint against the Linux kernel's WireGuard, in network
//! namespaces this test creates and deletes (`sailwgX-<id>-{k,s,e}`); the
//! root namespace's network is not touched.
//!
//! Needs Linux, root, `ip` and `wg` (wireguard-tools). Ignored unless asked
//! for, one test at a time:
//!
//! ```sh
//! cargo test -p sail --release --features wireguard --test test_wireguard_kernel \
//!     -- --ignored --nocapture --test-threads=1
//! ```
//!
//! ```text
//!   k: kernel wg0 10.98.0.1 fd98::1 :51820      s: sail                e: echo
//!      echo servers on wg0's addresses             socks inbounds         172.31.97.1:7
//!      kernel wg1 10.97.0.2, client of sail's      endpoints wg-out,
//!      wg-srv, routes 172.31.97.0/24 into it       wg-det, wg-srv
//!   k 172.31.98.1 ----veth---- 172.31.98.2 s 172.31.97.2 ----veth---- 172.31.97.1 e
//! ```
//!
//! - (a) sail's endpoint `wg-out` dials the kernel's wg0, which has echo
//!   servers behind it: TCP and UDP over IPv4 and IPv6, 64 connections at
//!   once, a transfer long enough to cross a rekey, and throughput.
//! - (b) the kernel's wg1 dials sail's endpoint `wg-srv`, whose traffic sail
//!   routes out directly to the echo server in `e`.
//! - (c) sail's endpoint `wg-det` sends its datagrams through a SOCKS
//!   outbound to sail's own SOCKS inbound, and from there to wg0.

#![cfg(all(
    target_os = "linux",
    feature = "wireguard",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
))]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use sail::protocol::wireguard::crypto;
use sail::session::{Session, SocksAddr};

fn base64(key: &[u8]) -> String {
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

struct Keys {
    private: String,
    public: String,
}

impl Keys {
    fn new() -> Self {
        let private = crypto::generate_private_key();
        Keys {
            private: base64(&private),
            public: base64(&crypto::public_key(&private)),
        }
    }
}

fn sh(args: &[&str]) {
    let status = Command::new(args[0])
        .args(&args[1..])
        .status()
        .unwrap_or_else(|e| panic!("{:?}: {}", args, e));
    assert!(status.success(), "{:?}: {}", args, status);
}

fn output(args: &[&str]) -> String {
    let out = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(out.status.success(), "{:?}", args);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Moves the calling thread into the namespace `name`.
fn enter(name: &str) {
    let file = std::fs::File::open(format!("/var/run/netns/{}", name)).unwrap();
    // SAFETY: setns on a namespace file this thread opened.
    let r = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(r, 0, "setns {}: {}", name, std::io::Error::last_os_error());
}

/// Runs `f` on a thread in the namespace `name`: sockets it opens stay
/// there.
fn in_netns<T: Send + 'static>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let name = name.to_string();
    std::thread::spawn(move || {
        enter(&name);
        f()
    })
    .join()
    .unwrap()
}

const WG0_PORT: u16 = 51820;
const SRV_PORT: u16 = 51830;

/// The namespaces, the kernel's interfaces and the keys; deleted when
/// dropped.
struct Lab {
    k: String,
    s: String,
    e: String,
    wg0: Keys,
    wg1: Keys,
    out: Keys,
    det: Keys,
    srv: Keys,
    _dir: common::TempDir,
}

impl Lab {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let id = format!(
            "{}{}",
            std::process::id() % 10_000,
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let [k, s, e] = ["k", "s", "e"].map(|n| format!("sailwgX-{}-{}", id, n));
        let lab = Lab {
            k,
            s,
            e,
            wg0: Keys::new(),
            wg1: Keys::new(),
            out: Keys::new(),
            det: Keys::new(),
            srv: Keys::new(),
            _dir: common::TempDir::new("wg-kernel").unwrap(),
        };
        lab.setup(&id);
        lab
    }

    fn setup(&self, id: &str) {
        let (k, s, e) = (self.k.as_str(), self.s.as_str(), self.e.as_str());
        for ns in [k, s, e] {
            sh(&["ip", "netns", "add", ns]);
            sh(&["ip", "-n", ns, "link", "set", "lo", "up"]);
        }
        let (vk, vs, vt, ve) = (
            format!("wk{}", id),
            format!("ws{}", id),
            format!("wt{}", id),
            format!("we{}", id),
        );
        sh(&[
            "ip", "link", "add", &vk, "netns", k, "type", "veth", "peer", "name", &vs, "netns", s,
        ]);
        sh(&[
            "ip", "link", "add", &ve, "netns", e, "type", "veth", "peer", "name", &vt, "netns", s,
        ]);
        for (ns, dev, addr) in [
            (k, &vk, "172.31.98.1/24"),
            (s, &vs, "172.31.98.2/24"),
            (s, &vt, "172.31.97.2/24"),
            (e, &ve, "172.31.97.1/24"),
        ] {
            sh(&["ip", "-n", ns, "addr", "add", addr, "dev", dev]);
            sh(&["ip", "-n", ns, "link", "set", dev, "up"]);
        }
        let key = |name: &str, keys: &Keys| {
            let path = self._dir.join(name);
            std::fs::write(&path, &keys.private).unwrap();
            path.to_string_lossy().into_owned()
        };
        let (wg0_key, wg1_key) = (key("wg0.key", &self.wg0), key("wg1.key", &self.wg1));
        // wg0: the peer of sail's wg-out and wg-det.
        sh(&["ip", "-n", k, "link", "add", "wg0", "type", "wireguard"]);
        sh(&[
            "ip",
            "netns",
            "exec",
            k,
            "wg",
            "set",
            "wg0",
            "private-key",
            &wg0_key,
            "listen-port",
            &WG0_PORT.to_string(),
            "peer",
            &self.out.public,
            "allowed-ips",
            "10.98.0.2/32,fd98::2/128",
            "peer",
            &self.det.public,
            "allowed-ips",
            "10.98.0.3/32",
        ]);
        sh(&["ip", "-n", k, "addr", "add", "10.98.0.1/24", "dev", "wg0"]);
        sh(&[
            "ip",
            "-n",
            k,
            "addr",
            "add",
            "fd98::1/64",
            "dev",
            "wg0",
            "nodad",
        ]);
        sh(&["ip", "-n", k, "link", "set", "wg0", "mtu", "1420", "up"]);
        // wg1: a client of sail's wg-srv, through which the echo server in
        // e is reached.
        sh(&["ip", "-n", k, "link", "add", "wg1", "type", "wireguard"]);
        sh(&[
            "ip",
            "netns",
            "exec",
            k,
            "wg",
            "set",
            "wg1",
            "private-key",
            &wg1_key,
            "peer",
            &self.srv.public,
            "allowed-ips",
            "10.97.0.0/24,172.31.97.0/24",
            "endpoint",
            &format!("172.31.98.2:{}", SRV_PORT),
            "persistent-keepalive",
            "25",
        ]);
        sh(&["ip", "-n", k, "addr", "add", "10.97.0.2/32", "dev", "wg1"]);
        sh(&["ip", "-n", k, "link", "set", "wg1", "mtu", "1420", "up"]);
        sh(&[
            "ip",
            "-n",
            k,
            "route",
            "add",
            "172.31.97.0/24",
            "dev",
            "wg1",
            "src",
            "10.97.0.2",
        ]);
    }

    fn sail_config(&self, socks_a: u16, socks_c: u16, relay: u16) -> String {
        json!({
            "inbounds": [
                { "type": "socks", "tag": "socks-a", "listen": "127.0.0.1", "listen_port": socks_a },
                { "type": "socks", "tag": "socks-c", "listen": "127.0.0.1", "listen_port": socks_c },
                { "type": "socks", "tag": "relay", "listen": "127.0.0.1", "listen_port": relay },
            ],
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "wg-out",
                    "address": ["10.98.0.2/32", "fd98::2/128"],
                    "private_key": self.out.private,
                    "mtu": 1420,
                    "peers": [{
                        "address": "172.31.98.1",
                        "port": WG0_PORT,
                        "public_key": self.wg0.public,
                        "allowed_ips": ["10.98.0.0/24", "fd98::/64"],
                    }],
                },
                {
                    "type": "wireguard",
                    "tag": "wg-det",
                    "address": ["10.98.0.3/32"],
                    "private_key": self.det.private,
                    "detour": "relay-out",
                    "peers": [{
                        "address": "172.31.98.1",
                        "port": WG0_PORT,
                        "public_key": self.wg0.public,
                        "allowed_ips": ["10.98.0.0/24"],
                    }],
                },
                {
                    "type": "wireguard",
                    "tag": "wg-srv",
                    "address": ["10.97.0.1/24"],
                    "private_key": self.srv.private,
                    "listen_port": SRV_PORT,
                    "mtu": 1420,
                    "peers": [{
                        "public_key": self.wg1.public,
                        "allowed_ips": ["10.97.0.2/32"],
                    }],
                },
            ],
            "outbounds": [
                { "type": "direct" },
                { "type": "socks", "tag": "relay-out", "server": "127.0.0.1", "server_port": relay },
            ],
            // SAIL_WG_LOG=debug, for more.
            "log": { "level": std::env::var("SAIL_WG_LOG").unwrap_or_else(|_| "info".into()) },
            "route": {
                "rules": [
                    { "inbound": ["relay", "wg-srv"], "outbound": "direct" },
                    { "inbound": ["socks-c"], "outbound": "wg-det" },
                ],
                "final": "wg-out",
            },
        })
        .to_string()
    }

    /// Runs `f` with sail running in s, echo servers in k and e.
    fn run(
        &self,
        f: impl FnOnce(&Ports) -> anyhow::Result<()> + Send + 'static,
    ) -> anyhow::Result<()> {
        // Echo servers, bound in their namespaces.
        let k_tcp = in_netns(&self.k, || {
            ["10.98.0.1:7", "[fd98::1]:7"].map(|a| TcpListener::bind(a).unwrap())
        });
        let k_udp = in_netns(&self.k, || {
            ["10.98.0.1:7", "[fd98::1]:7"].map(|a| UdpSocket::bind(a).unwrap())
        });
        let e_tcp = in_netns(&self.e, || TcpListener::bind("172.31.97.1:7").unwrap());
        let e_udp = in_netns(&self.e, || UdpSocket::bind("172.31.97.1:7").unwrap());
        let config = {
            let ports = in_netns(&self.s, || {
                // Free in s, which has nothing else.
                [0; 3].map(|_| {
                    TcpListener::bind("127.0.0.1:0")
                        .unwrap()
                        .local_addr()
                        .unwrap()
                        .port()
                })
            });
            (ports, self.sail_config(ports[0], ports[1], ports[2]))
        };
        let k = self.k.clone();
        let s = self.s.clone();
        std::thread::spawn(move || {
            enter(&s);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let _g = rt.enter();
            for l in k_tcp.into_iter().chain([e_tcp]) {
                l.set_nonblocking(true)?;
                rt.spawn(tcp_echo_server(tokio::net::TcpListener::from_std(l)?));
            }
            for u in k_udp.into_iter().chain([e_udp]) {
                u.set_nonblocking(true)?;
                rt.spawn(udp_echo_server(tokio::net::UdpSocket::from_std(u)?));
            }
            let ((socks_a, socks_c, _), config) =
                ((config.0[0], config.0[1], config.0[2]), config.1);
            let ids = common::run_sail_instances(&rt, vec![config])?;
            let ports = Ports {
                rt,
                socks_a,
                socks_c,
                k,
            };
            let result = f(&ports);
            common::shutdown_instances(&ports.rt, ids);
            result
        })
        .join()
        .unwrap()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        for ns in [&self.k, &self.s, &self.e] {
            let _ = Command::new("ip").args(["netns", "del", ns]).status();
        }
    }
}

struct Ports {
    rt: tokio::runtime::Runtime,
    socks_a: u16,
    socks_c: u16,
    /// The kernel's namespace, for clients of sail's wg-srv.
    k: String,
}

async fn tcp_echo_server(listener: tokio::net::TcpListener) {
    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let (mut r, mut w) = stream.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
    }
}

async fn udp_echo_server(socket: tokio::net::UdpSocket) {
    let mut buf = vec![0u8; 65536];
    while let Ok((n, from)) = socket.recv_from(&mut buf).await {
        let _ = socket.send_to(&buf[..n], from).await;
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Sends `data` over `stream` and reads the echo back at once.
async fn echo_over<S: tokio::io::AsyncRead + tokio::io::AsyncWrite>(
    stream: S,
    data: &[u8],
) -> anyhow::Result<()> {
    let (mut r, mut w) = tokio::io::split(stream);
    let expected = data.to_vec();
    tokio::try_join!(
        async {
            w.write_all(data).await?;
            anyhow::Ok(())
        },
        async {
            let mut got = vec![0u8; expected.len()];
            r.read_exact(&mut got).await?;
            anyhow::ensure!(got == expected, "the echo differs");
            anyhow::Ok(())
        }
    )?;
    Ok(())
}

async fn socks_stream(socks: u16, target: &str) -> anyhow::Result<sail::adapter::AnyStream> {
    let sess = Session {
        destination: SocksAddr::Ip(target.parse()?),
        ..Default::default()
    };
    common::new_socks_stream("127.0.0.1", socks, &sess, None, None).await
}

async fn tcp_echo(socks: u16, target: &str, data: &[u8]) -> anyhow::Result<()> {
    let stream = socks_stream(socks, target).await?;
    timeout(Duration::from_secs(120), echo_over(stream, data)).await?
}

async fn udp_echo(socks: u16, target: &str) -> anyhow::Result<()> {
    let target: SocketAddr = target.parse()?;
    let sess = Session {
        destination: SocksAddr::Ip(target),
        ..Default::default()
    };
    let datagram = common::new_socks_datagram("127.0.0.1", socks, &sess, None, None).await?;
    let (mut r, mut s) = datagram.split();
    for i in 0..20u8 {
        // Past the tunnel's MTU, fragmented, but within the 2 KiB the SOCKS
        // inbound relays.
        let msg = pattern(1 + i as usize * 100, i);
        let mut buf = vec![0u8; 8192];
        let mut answered = false;
        for _ in 0..5 {
            s.send_to(&msg, &SocksAddr::Ip(target)).await?;
            if let Ok(r) = timeout(Duration::from_secs(2), r.recv_from(&mut buf)).await {
                let (n, from) = r?;
                anyhow::ensure!(buf[..n] == msg[..], "the UDP echo differs");
                anyhow::ensure!(from == SocksAddr::Ip(target), "from {}", from);
                answered = true;
                break;
            }
        }
        anyhow::ensure!(
            answered,
            "no UDP echo of {} bytes from {}",
            msg.len(),
            target
        );
    }
    Ok(())
}

/// (a) sail's endpoint to the kernel's, and what is behind it.
#[test]
#[ignore]
fn test_wireguard_kernel_outbound() -> anyhow::Result<()> {
    let lab = Lab::new();
    lab.run(|p| {
        p.rt.block_on(async {
            for target in ["10.98.0.1:7", "[fd98::1]:7"] {
                tcp_echo(p.socks_a, target, b"to the kernel").await?;
                tcp_echo(p.socks_a, target, &pattern(8 << 20, 9)).await?;
                udp_echo(p.socks_a, target).await?;
            }
            let many = (0..64u8).map(|i| async move {
                let target = if i % 2 == 0 {
                    "10.98.0.1:7"
                } else {
                    "[fd98::1]:7"
                };
                tcp_echo(p.socks_a, target, &pattern(512 << 10, i)).await
            });
            futures::future::try_join_all(many).await?;
            anyhow::Ok(())
        })
    })
}

/// (b) the kernel's endpoint to sail's, which sends it on directly.
#[test]
#[ignore]
fn test_wireguard_kernel_inbound() -> anyhow::Result<()> {
    let lab = Lab::new();
    lab.run(|p| {
        let k = p.k.clone();
        // Sockets of a client in k, whose route to e is wg1.
        let (tcp, udp) = in_netns(&k, || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let tcp = loop {
                match TcpStream::connect_timeout(
                    &"172.31.97.1:7".parse().unwrap(),
                    Duration::from_secs(5),
                ) {
                    Ok(s) => break s,
                    Err(e) if Instant::now() < deadline => {
                        eprintln!("connect through wg1: {}", e);
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(e) => panic!("connect through wg1: {}", e),
                }
            };
            let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
            (tcp, udp)
        });
        // A blocking exchange first.
        let mut tcp = tcp;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
        tcp.write_all(b"from the kernel")?;
        let mut got = [0u8; 15];
        tcp.read_exact(&mut got)?;
        anyhow::ensure!(&got == b"from the kernel");
        p.rt.block_on(async {
            tcp.set_nonblocking(true)?;
            let tcp = tokio::net::TcpStream::from_std(tcp)?;
            anyhow::ensure!(tcp.local_addr()?.ip().to_string() == "10.97.0.2");
            timeout(
                Duration::from_secs(60),
                echo_over(tcp, &pattern(8 << 20, 3)),
            )
            .await??;
            udp.set_nonblocking(true)?;
            let udp = tokio::net::UdpSocket::from_std(udp)?;
            let mut buf = vec![0u8; 8192];
            for i in 0..20u8 {
                // Past the tunnel's MTU, fragmented, but within the 2 KiB
                // sail's UDP relays.
                let msg = pattern(1 + i as usize * 100, i);
                let mut answered = false;
                'send: for _ in 0..5 {
                    udp.send_to(&msg, "172.31.97.1:7").await?;
                    // An echo of an earlier try may come first.
                    while let Ok(r) = timeout(Duration::from_secs(2), udp.recv_from(&mut buf)).await
                    {
                        let (n, from) = r?;
                        anyhow::ensure!(from.to_string() == "172.31.97.1:7", "from {}", from);
                        if buf[..n] == msg[..] {
                            answered = true;
                            break 'send;
                        }
                    }
                }
                anyhow::ensure!(answered, "no UDP echo of {} bytes", msg.len());
            }
            anyhow::Ok(())
        })
    })
}

/// (c) WireGuard's own UDP through a SOCKS outbound.
#[test]
#[ignore]
fn test_wireguard_kernel_detour() -> anyhow::Result<()> {
    let lab = Lab::new();
    lab.run(|p| {
        p.rt.block_on(async {
            tcp_echo(p.socks_c, "10.98.0.1:7", &pattern(4 << 20, 1)).await?;
            udp_echo(p.socks_c, "10.98.0.1:7").await?;
            anyhow::Ok(())
        })
    })
}

/// A transfer across REKEY_AFTER_TIME (120s): data keeps flowing, intact,
/// while the session is replaced.
#[test]
#[ignore]
fn test_wireguard_kernel_rekey() -> anyhow::Result<()> {
    let lab = Lab::new();
    let out = lab.out.public.clone();
    let k = lab.k.clone();
    lab.run(move |p| {
        p.rt.block_on(async {
            tcp_echo(p.socks_a, "10.98.0.1:7", b"first handshake").await?;
            let first = latest_handshake(&k, &out);
            let stream = socks_stream(p.socks_a, "10.98.0.1:7").await?;
            let (mut r, mut w) = tokio::io::split(stream);
            let started = Instant::now();
            let mut sent = 0usize;
            let chunk = pattern(64 << 10, 5);
            let mut got = vec![0u8; chunk.len()];
            while started.elapsed() < Duration::from_secs(135) {
                w.write_all(&chunk).await?;
                timeout(Duration::from_secs(10), r.read_exact(&mut got)).await??;
                anyhow::ensure!(got == chunk, "the echo differs after {} bytes", sent);
                sent += chunk.len();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let last = latest_handshake(&k, &out);
            println!(
                "rekey: {} MiB echoed over {:?}; handshakes at {} then {}",
                sent >> 20,
                started.elapsed(),
                first,
                last
            );
            anyhow::ensure!(last > first, "no new handshake during the transfer");
            anyhow::Ok(())
        })
    })
}

fn latest_handshake(k: &str, peer: &str) -> u64 {
    output(&[
        "ip",
        "netns",
        "exec",
        k,
        "wg",
        "show",
        "wg0",
        "latest-handshakes",
    ])
    .lines()
    .find_map(|l| {
        let (key, time) = l.split_once('\t')?;
        (key == peer).then(|| time.trim().parse().ok())?
    })
    .unwrap_or(0)
}

/// 256 MiB each way through sail's endpoint and the kernel's.
#[test]
#[ignore]
fn test_wireguard_kernel_throughput() -> anyhow::Result<()> {
    let lab = Lab::new();
    lab.run(|p| {
        p.rt.block_on(async {
            tcp_echo(p.socks_a, "10.98.0.1:7", b"warm up").await?;
            let size = 256usize << 20;
            let data = pattern(size, 3);
            let cpu = cpu_seconds();
            let started = Instant::now();
            tcp_echo(p.socks_a, "10.98.0.1:7", &data).await?;
            let elapsed = started.elapsed().as_secs_f64();
            let cpu = cpu_seconds() - cpu;
            println!(
                "sail<->kernel: 256 MiB each way in {:.2}s: {:.1} Mbit/s each way, \
                 sail process CPU {:.2}s ({:.0}% of one core)",
                elapsed,
                size as f64 * 8.0 / elapsed / 1e6,
                cpu,
                cpu / elapsed * 100.0
            );
            anyhow::Ok(())
        })
    })
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage fills the struct it is given.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let t = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6;
    t(usage.ru_utime) + t(usage.ru_stime)
}
