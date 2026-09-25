//! The redirect and tproxy inbounds, end to end, through real nftables
//! REDIRECT and TPROXY rules.
//!
//! Needs root and the network namespaces `tests/scripts/tproxy_netns.sh`
//! builds: it runs these tests inside the router namespace, where sail
//! runs, while the client and the echo server run on threads moved into
//! namespaces of their own. Ignored otherwise.
//!
//! client (10.33.1.2, fd33:1::2) -- router, sail -- server (10.33.2.2, fd33:2::2)
//!
//! The router diverts, from the client side only:
//! - TCP to port 33220 with REDIRECT to sail's redirect inbound on 33201;
//! - TCP to 33230 and UDP to 33231 with TPROXY to its tproxy inbound on
//!   33202.
//!
//! sail's direct outbound then reaches the echo server, which listens on
//! every one of those ports.

#![cfg(all(
    target_os = "linux",
    feature = "inbound-redirect",
    feature = "inbound-tproxy",
    feature = "outbound-direct"
))]

mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

const SERVER_V4: &str = "10.33.2.2";
const SERVER_V6: &str = "fd33:2::2";

const REDIRECTED_TCP_PORT: u16 = 33220;
const TPROXY_TCP_PORT: u16 = 33230;
const TPROXY_UDP_PORT: u16 = 33231;

const CONFIG: &str = r#"
{
    "log": { "level": "debug" },
    "inbounds": [
        { "type": "redirect", "tag": "redirect-in", "listen": "::", "listen_port": 33201 },
        { "type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 33202 }
    ],
    "outbounds": [ { "type": "direct" } ]
}
"#;

const TIMEOUT: Duration = Duration::from_secs(5);

fn namespace(var: &str) -> File {
    let path = std::env::var(var)
        .unwrap_or_else(|_| panic!("{} is not set: run tests/scripts/tproxy_netns.sh", var));
    File::open(&path).unwrap_or_else(|e| panic!("open {}: {}", path, e))
}

/// Moves the calling thread into the network namespace `ns`.
fn enter(ns: &File) {
    // SAFETY: a plain syscall on a file descriptor that stays open.
    let ret = unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(ret, 0, "setns: {}", std::io::Error::last_os_error());
}

/// Runs `f` on a thread of its own inside the network namespace `ns`.
fn run_in<T: Send + 'static>(ns: &'static File, f: impl FnOnce() -> T + Send + 'static) -> T {
    thread::spawn(move || {
        enter(ns);
        f()
    })
    .join()
    .expect("thread in namespace panicked")
}

/// Starts, once for every test, the echo servers in the server namespace
/// and sail here, in the router's.
fn setup() -> &'static File {
    static CLIENT: OnceLock<File> = OnceLock::new();
    static SAIL: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let server: &'static File = Box::leak(Box::new(namespace("SAILTP_SERVER_NS")));
        run_in(server, || {
            for ip in [SERVER_V4, SERVER_V6] {
                for port in [REDIRECTED_TCP_PORT, TPROXY_TCP_PORT] {
                    let listener = TcpListener::bind(SocketAddr::new(ip.parse().unwrap(), port))
                        .expect("bind tcp echo");
                    thread::spawn(move || tcp_echo(listener));
                }
                let socket = UdpSocket::bind(SocketAddr::new(ip.parse().unwrap(), TPROXY_UDP_PORT))
                    .expect("bind udp echo");
                thread::spawn(move || udp_echo(socket));
            }
        });

        let rt = SAIL.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
        });
        common::run_sail_instances(rt, vec![CONFIG.to_string()]).expect("start sail");
        namespace("SAILTP_CLIENT_NS")
    })
}

fn tcp_echo(listener: TcpListener) {
    for stream in listener.incoming().flatten() {
        thread::spawn(move || {
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        });
    }
}

fn udp_echo(socket: UdpSocket) {
    let mut buf = [0u8; 4096];
    while let Ok((n, from)) = socket.recv_from(&mut buf) {
        let _ = socket.send_to(&buf[..n], from);
    }
}

/// Connects from the client to `ip`:`port`, which the router diverts, and
/// checks that what it sends comes back.
fn tcp_round_trip(ip: &'static str, port: u16) {
    let client = setup();
    run_in(client, move || {
        let target = SocketAddr::new(ip.parse().unwrap(), port);
        let mut stream = TcpStream::connect_timeout(&target, TIMEOUT)
            .unwrap_or_else(|e| panic!("connect {}: {}", target, e));
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        let payload: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let mut writer = stream.try_clone().unwrap();
        let sent = payload.clone();
        let writing = thread::spawn(move || writer.write_all(&sent));
        let mut echoed = vec![0u8; payload.len()];
        stream
            .read_exact(&mut echoed)
            .unwrap_or_else(|e| panic!("read echo from {}: {}", target, e));
        writing.join().unwrap().unwrap();
        assert!(echoed == payload, "echo from {} differs", target);
    });
}

/// Sends datagrams from the client to `ip`:`port`, which the router
/// diverts, and checks that each reply comes back, from that very address.
fn udp_round_trip(ip: &'static str, port: u16) {
    let client = setup();
    run_in(client, move || {
        let target = SocketAddr::new(ip.parse().unwrap(), port);
        let bind: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind).unwrap();
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut buf = [0u8; 2048];
        for i in 0..5u8 {
            let payload = [i; 1000];
            socket.send_to(&payload, target).unwrap();
            let (n, from) = socket
                .recv_from(&mut buf)
                .unwrap_or_else(|e| panic!("no reply from {}: {}", target, e));
            assert_eq!(
                from, target,
                "reply came from {} rather than {}",
                from, target
            );
            assert_eq!(&buf[..n], &payload[..]);
        }
    });
}

#[test]
#[ignore = "needs root and the namespaces of tests/scripts/tproxy_netns.sh"]
fn redirect_tcp_v4() {
    tcp_round_trip(SERVER_V4, REDIRECTED_TCP_PORT);
}

#[test]
#[ignore = "needs root and the namespaces of tests/scripts/tproxy_netns.sh"]
fn redirect_tcp_v6() {
    tcp_round_trip(SERVER_V6, REDIRECTED_TCP_PORT);
}

#[test]
#[ignore = "needs root and the namespaces of tests/scripts/tproxy_netns.sh"]
fn tproxy_tcp_v4() {
    tcp_round_trip(SERVER_V4, TPROXY_TCP_PORT);
}

#[test]
#[ignore = "needs root and the namespaces of tests/scripts/tproxy_netns.sh"]
fn tproxy_tcp_v6() {
    tcp_round_trip(SERVER_V6, TPROXY_TCP_PORT);
}

#[test]
#[ignore = "needs root and the namespaces of tests/scripts/tproxy_netns.sh"]
fn tproxy_udp_v4() {
    udp_round_trip(SERVER_V4, TPROXY_UDP_PORT);
}

#[test]
#[ignore = "needs root and the namespaces of tests/scripts/tproxy_netns.sh"]
fn tproxy_udp_v6() {
    udp_round_trip(SERVER_V6, TPROXY_UDP_PORT);
}
