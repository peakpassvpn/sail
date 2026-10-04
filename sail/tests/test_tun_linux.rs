//! The TUN inbound end to end on Linux, as root: sockets of this host reach
//! servers in another network namespace through the TUN, the netstack, the
//! dispatcher and a direct outbound, over IPv4 and IPv6; DNS queries to
//! port 53 through it, over UDP and TCP, are hijacked and answered by sail.
//!
//! The servers' addresses are routed into the TUN for every socket but
//! those the direct outbound marks, which take the veth to the namespace, so
//! nothing loops back into the TUN.
#![cfg(target_os = "linux")]
// Tests drive tasks of their own.
#![allow(clippy::disallowed_methods)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const NAMESPACE: &str = "sailns-peer";
const TUN: &str = "sailns-e2e2";
/// The routing table and the mark that keep the outbound out of the TUN.
const TABLE: &str = "2120";
const SERVER_V4: Ipv4Addr = Ipv4Addr::new(10, 212, 1, 2);
const SERVER_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x212, 1, 0, 0, 0, 0, 2);
const TCP_PORT: u16 = 7001;
const UDP_PORT: u16 = 7002;

/// Echoes TCP until the client's FIN, then closes. Echoes UDP, except
/// `whoami`, answered with the sender's port, and `delay:N`, answered after
/// N seconds.
const SERVER: &str = r#"
import socket, threading, time

def echo(conn):
    while True:
        data = conn.recv(65536)
        if not data:
            break
        conn.sendall(data)
    conn.shutdown(socket.SHUT_WR)
    conn.close()

def tcp():
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("::", 7001))
    server.listen(256)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=echo, args=(conn,), daemon=True).start()

udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
udp.bind(("::", 7002))

def later(seconds, peer):
    time.sleep(seconds)
    udp.sendto(b"late", peer)

threading.Thread(target=tcp, daemon=True).start()
while True:
    data, peer = udp.recvfrom(65535)
    if data == b"whoami":
        udp.sendto(str(peer[1]).encode(), peer)
    elif data.startswith(b"delay:"):
        threading.Thread(target=later, args=(int(data[6:]), peer), daemon=True).start()
    else:
        udp.sendto(data, peer)
"#;

fn run(command: &str) -> Result<()> {
    let mut words = command.split_whitespace();
    let program = words.next().context("empty command")?;
    let output = Command::new(program).args(words).output()?;
    ensure!(
        output.status.success(),
        "{command}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Undoes what the test sets up, whatever of it exists.
fn tear_down() {
    for command in [
        format!("ip rule del pref {TABLE}"),
        format!("ip -6 rule del pref {TABLE}"),
        format!("ip route flush table {TABLE}"),
        format!("ip -6 route flush table {TABLE}"),
        "ip link del sailv0".to_string(),
        format!("ip netns del {NAMESPACE}"),
    ] {
        let _ = run(&command);
    }
}

/// The servers' namespace, its veth, and the rules that send the servers'
/// addresses into the TUN.
struct Peer {
    server: Child,
}

impl Peer {
    fn up() -> Result<Self> {
        tear_down();
        for command in [
            format!("ip netns add {NAMESPACE}"),
            "ip link add sailv0 type veth peer name sailv1".to_string(),
            format!("ip link set sailv1 netns {NAMESPACE}"),
            "ip addr add 10.212.1.1/24 dev sailv0".to_string(),
            "ip -6 addr add fd00:212:1::1/64 dev sailv0 nodad".to_string(),
            "ip link set sailv0 up".to_string(),
            format!("ip netns exec {NAMESPACE} ip link set lo up"),
            format!("ip netns exec {NAMESPACE} ip addr add 10.212.1.2/24 dev sailv1"),
            format!("ip netns exec {NAMESPACE} ip -6 addr add fd00:212:1::2/64 dev sailv1 nodad"),
            format!("ip netns exec {NAMESPACE} ip link set sailv1 up"),
            format!("ip rule add not fwmark {TABLE} lookup {TABLE} pref {TABLE}"),
            format!("ip -6 rule add not fwmark {TABLE} lookup {TABLE} pref {TABLE}"),
        ] {
            run(&command)?;
        }
        let server = Command::new("ip")
            .args(["netns", "exec", NAMESPACE, "python3", "-c", SERVER])
            .stdin(Stdio::null())
            .spawn()?;
        // Wait until both of its sockets are there.
        let started = Instant::now();
        loop {
            let listening = Command::new("ip")
                .args(["netns", "exec", NAMESPACE, "ss", "-Hlntu"])
                .output()?;
            let listening = String::from_utf8_lossy(&listening.stdout);
            if listening.contains(":7001") && listening.contains(":7002") {
                break;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(10),
                "the servers did not start"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(Self { server })
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
        tear_down();
    }
}

/// A sail runtime with a TUN inbound and a direct outbound that marks its
/// sockets, with the servers routed into the TUN.
struct Sail {
    id: u16,
    thread: Option<std::thread::JoinHandle<Result<(), sail::Error>>>,
}

impl Sail {
    async fn start(id: u16, udp_timeout: &str, session_check: Duration) -> Result<Self> {
        let config = format!(
            r#"{{
                "inbounds": [{{
                    "type": "tun",
                    "tag": "tun",
                    "interface_name": "{TUN}",
                    "address": "10.213.0.1/24",
                    "mtu": 1500,
                    "udp_timeout": "{udp_timeout}"
                }}],
                "outbounds": [{{ "type": "direct", "tag": "direct", "routing_mark": {TABLE} }}],
                "dns": {{ "servers": [{{ "type": "hosts", "predefined": {{
                    "one.sail": ["192.0.2.1", "2001:db8::1"],
                    "many.sail": [{many}]
                }} }}] }},
                "route": {{ "rules": [{{ "port": 53, "action": "hijack-dns" }}] }}
            }}"#,
            many = (1..=60)
                .map(|i| format!("\"2001:db8::{i:x}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let mut runtime = sail::runtime::RuntimeOptions::default();
        runtime.udp.session_check_interval = session_check;
        let thread = std::thread::spawn(move || {
            sail::start(
                id,
                sail::StartOptions {
                    signals: false,
                    config: sail::Config::Str(config),
                    #[cfg(feature = "auto-reload")]
                    auto_reload: false,
                    runtime_opt: sail::RuntimeOption::MultiThread(2, 2 * 1024 * 1024),
                    runtime,
                    host: Default::default(),
                },
            )
        });
        let sail = Self {
            id,
            thread: Some(thread),
        };
        let started = Instant::now();
        while !sail::is_running(id) || run(&format!("ip link show {TUN}")).is_err() {
            ensure!(
                started.elapsed() < Duration::from_secs(10),
                "sail did not start"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for command in [
            format!("ip route add {SERVER_V4}/32 dev {TUN} table {TABLE}"),
            format!("ip -6 addr add fd00:212:9::1/64 dev {TUN} nodad"),
            format!("ip -6 route add {SERVER_V6}/128 dev {TUN} table {TABLE}"),
        ] {
            run(&command)?;
        }
        Ok(sail)
    }
}

impl Drop for Sail {
    fn drop(&mut self) {
        // Shutting down blocks, which a runtime's own thread may not.
        let id = self.id;
        let thread = self.thread.take();
        let _ = std::thread::spawn(move || {
            sail::shutdown(id);
            if let Some(thread) = thread {
                let _ = thread.join();
            }
        })
        .join();
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).unwrap() ^ seed)
        .collect()
}

fn dns_query(name: &str, ty: hickory_proto::rr::RecordType) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    let mut m = Message::new(0x5a1, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        hickory_proto::rr::Name::from_ascii(name).unwrap(),
        ty,
    ));
    m.to_vec().unwrap()
}

/// The answer's TC bit and addresses.
fn dns_answer(reply: &[u8]) -> Result<(bool, Vec<IpAddr>)> {
    use hickory_proto::rr::RData;
    let m = hickory_proto::op::Message::from_vec(reply)?;
    ensure!(m.metadata.id == 0x5a1, "the answer has another ID");
    let ips = m
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect();
    Ok((m.metadata.truncation, ips))
}

/// Queries to port 53 of `server`, which serves no DNS, are answered by
/// sail's hosts server: over UDP, cut to 512 bytes with TC when too big;
/// over TCP, in full.
async fn dns_hijacked(server: IpAddr) -> Result<()> {
    use hickory_proto::rr::RecordType;
    let target = SocketAddr::new(server, 53);
    let socket = udp_socket(server).await?;
    let ask = async |name: &str, ty| -> Result<(usize, bool, Vec<IpAddr>)> {
        socket.send_to(&dns_query(name, ty), target).await?;
        let mut buf = vec![0_u8; 65_536];
        let (n, from) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
            .await
            .map_err(|_| anyhow!("no DNS answer over UDP from {target}"))??;
        ensure!(from == target, "the DNS answer came from {from}");
        let (truncated, ips) = dns_answer(&buf[..n])?;
        Ok((n, truncated, ips))
    };
    let (_, truncated, ips) = ask("one.sail.", RecordType::A).await?;
    ensure!(
        !truncated && ips == ["192.0.2.1".parse::<IpAddr>()?],
        "A: {ips:?}"
    );
    let (_, truncated, ips) = ask("one.sail.", RecordType::AAAA).await?;
    ensure!(
        !truncated && ips == ["2001:db8::1".parse::<IpAddr>()?],
        "AAAA: {ips:?}"
    );
    let (n, truncated, ips) = ask("many.sail.", RecordType::AAAA).await?;
    ensure!(
        n <= 512 && truncated && !ips.is_empty() && ips.len() < 60,
        "{n} bytes, TC {truncated}, {} addresses",
        ips.len()
    );
    let mut tcp = timeout(Duration::from_secs(5), TcpStream::connect(target))
        .await
        .map_err(|_| anyhow!("connecting to {target} timed out"))??;
    let query = dns_query("many.sail.", RecordType::AAAA);
    tcp.write_u16(u16::try_from(query.len())?).await?;
    tcp.write_all(&query).await?;
    let len = timeout(Duration::from_secs(3), tcp.read_u16()).await??;
    let mut reply = vec![0_u8; len.into()];
    tcp.read_exact(&mut reply).await?;
    let (truncated, ips) = dns_answer(&reply)?;
    ensure!(
        !truncated && ips.len() == 60,
        "TCP: {} addresses",
        ips.len()
    );
    Ok(())
}

/// Sends `size` bytes while reading the echo, closes the sending half, and
/// checks that the echo, ended by the server's FIN, is what was sent.
async fn tcp_round_trip(server: IpAddr, size: usize) -> Result<()> {
    let stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(SocketAddr::new(server, TCP_PORT)),
    )
    .await
    .map_err(|_| anyhow!("connecting to {server} timed out"))??;
    let sent = pattern(size, 0x5a);
    let (mut read, mut write) = stream.into_split();
    let (written, received) = timeout(Duration::from_secs(60), async {
        tokio::join!(
            async {
                write.write_all(&sent).await?;
                write.shutdown().await
            },
            async {
                let mut received = Vec::new();
                read.read_to_end(&mut received).await.map(|_| received)
            }
        )
    })
    .await
    .map_err(|_| anyhow!("the transfer with {server} stalled"))?;
    written?;
    ensure!(received? == sent, "the echo from {server} differs");
    Ok(())
}

async fn udp_socket(server: IpAddr) -> Result<UdpSocket> {
    let local: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    Ok(UdpSocket::bind(local).await?)
}

async fn udp_ask(
    socket: &UdpSocket,
    server: IpAddr,
    question: &[u8],
    wait: Duration,
) -> Result<Vec<u8>> {
    let target = SocketAddr::new(server, UDP_PORT);
    socket.send_to(question, target).await?;
    let mut answer = vec![0_u8; 65_536];
    let (count, source) = timeout(wait, socket.recv_from(&mut answer))
        .await
        .map_err(|_| anyhow!("no UDP answer from {server}"))??;
    ensure!(
        source == target,
        "the answer came from {source}, not {target}"
    );
    answer.truncate(count);
    Ok(answer)
}

fn ping(server: IpAddr) -> Result<()> {
    let family = if server.is_ipv4() { "-4" } else { "-6" };
    run(&format!("ping {family} -c 1 -W 2 {server}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires root: network namespaces, veth, a TUN and policy routing"]
async fn tun_inbound_carries_tcp_udp_and_icmp_over_ipv4_and_ipv6() -> Result<()> {
    let _peer = Peer::up()?;
    let servers = [IpAddr::V4(SERVER_V4), IpAddr::V6(SERVER_V6)];

    {
        let _sail = Sail::start(61_001, "2s", Duration::from_secs(1)).await?;

        for server in servers {
            // The netstack answers echo requests for any destination.
            ping(server).with_context(|| format!("ping {server}"))?;
            tcp_round_trip(server, 1 << 20)
                .await
                .with_context(|| format!("TCP to {server}"))?;
            let socket = udp_socket(server).await?;
            for size in [64, 4_000] {
                let question = pattern(size, 0x33);
                let answer = udp_ask(&socket, server, &question, Duration::from_secs(3))
                    .await
                    .with_context(|| format!("{size}-byte UDP to {server}"))?;
                ensure!(
                    answer == question,
                    "the {size}-byte UDP echo from {server} differs: {} bytes back, first difference at {:?}",
                    answer.len(),
                    answer.iter().zip(&question).position(|(a, b)| a != b)
                );
            }
        }

        for server in servers {
            dns_hijacked(server)
                .await
                .with_context(|| format!("DNS to {server}"))?;
        }

        // Several connections at once, over both families.
        let transfers = (0..16).map(|index| tcp_round_trip(servers[index % 2], 64 << 10));
        for result in futures::future::join_all(transfers).await {
            result?;
        }

        // A NAT session ends after `udp_timeout` of silence: the next
        // datagram leaves from a new outbound socket.
        for server in servers {
            let socket = udp_socket(server).await?;
            let first = udp_ask(&socket, server, b"whoami", Duration::from_secs(3)).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            let again = udp_ask(&socket, server, b"whoami", Duration::from_secs(3)).await?;
            ensure!(
                first == again,
                "the session to {server} ended within its timeout"
            );
            tokio::time::sleep(Duration::from_secs(4)).await;
            let later = udp_ask(&socket, server, b"whoami", Duration::from_secs(3)).await?;
            ensure!(
                first != later,
                "the session to {server} outlived its timeout"
            );
        }
    }

    // A reply after a minute of silence still reaches the client while the
    // session lasts: the netstack's flow must not expire before it.
    let _sail = Sail::start(61_002, "90s", Duration::from_secs(10)).await?;
    let late = futures::future::join_all(servers.map(|server| async move {
        let socket = udp_socket(server).await?;
        udp_ask(&socket, server, b"delay:65", Duration::from_secs(75))
            .await
            .with_context(|| format!("the late UDP answer from {server}"))
    }))
    .await;
    for answer in late {
        ensure!(answer? == b"late", "the late answer changed");
    }
    Ok(())
}
