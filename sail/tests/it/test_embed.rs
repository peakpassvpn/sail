//! sail embedded (`sail::embed`): an instance driven from the host's own
//! runtime, as an in-process engine drives it.
#![cfg(all(feature = "outbound-direct", feature = "inbound-socks"))]

use std::time::Duration;

use sail::embed::{Address, Config, ErrorKind, Instance, Options, State, Threads};
use sail::session::Session;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

fn config(socks_port: u16, dns_port: u16) -> String {
    serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "upstream", "type": "udp", "server": "127.0.0.1", "server_port": dns_port }],
        },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks_port,
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "final": "direct" },
    })
    .to_string()
}

fn options() -> Options {
    Options::new().threads(Threads::One).log_lines(100)
}

async fn round_trip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    s: &mut S,
    what: &[u8],
) {
    s.write_all(what).await.unwrap();
    let mut back = vec![0u8; what.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back))
        .await
        .expect("an echo in time")
        .unwrap();
    assert_eq!(back, what);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_instance_runs_from_the_hosts_runtime_and_stops_clean() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let (udp_echo, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let socks_port = common::free_port();

    let instance = Instance::new(options()).unwrap();
    assert_eq!(instance.state(), State::Idle);
    // Taken before the start: it sees the start.
    let mut states = instance.states();
    instance
        .start(Config::Json(config(socks_port, 53)))
        .await
        .unwrap();
    assert!(matches!(*states.borrow_and_update(), State::Running { .. }));
    assert!(matches!(instance.state(), State::Running { .. }));

    // A start while it runs is refused, and changes nothing.
    let again = instance.start(Config::Json(config(socks_port, 53))).await;
    assert_eq!(again.unwrap_err().kind(), ErrorKind::State);

    // Queries.
    let tags: Vec<String> = instance
        .outbounds()
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.tag)
        .collect();
    assert_eq!(tags, ["direct"]);
    assert_eq!(
        instance
            .dial_tcp("nowhere", Address::from(echo), Duration::from_secs(5))
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::NotFound)
    );

    // A stream and datagrams through the outbound named, used from this
    // runtime.
    let mut stream = instance
        .dial_tcp("direct", Address::from(echo), Duration::from_secs(5))
        .await
        .unwrap();
    round_trip(&mut stream, b"through direct").await;
    let connections = instance.connections().await.unwrap();
    assert!(
        connections.iter().any(|c| c.inbound_type == "control"),
        "the dialled connection is listed: {:?}",
        connections
    );
    let datagram = instance
        .dial_udp("direct", Address::from(udp_echo), Duration::from_secs(5))
        .await
        .unwrap();
    datagram.send(b"a datagram").await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), datagram.recv_from(&mut buf))
        .await
        .expect("a datagram back in time")
        .unwrap();
    assert_eq!(&buf[..n], b"a datagram");
    assert_eq!(from, Address::from(udp_echo));

    // Stopped: the stream fails rather than hangs, the port is free, and
    // calls say it does not run.
    let mut stopping = instance.states();
    instance.stop().await.unwrap();
    assert_eq!(*stopping.borrow_and_update(), State::Stopped);
    assert_eq!(instance.state(), State::Stopped);
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("the stream ends with the instance");
    assert!(matches!(read, Ok(0) | Err(_)));
    std::net::TcpListener::bind(("127.0.0.1", socks_port)).expect("the inbound's port is free");
    assert_eq!(
        instance.traffic().await.unwrap_err().kind(),
        ErrorKind::NotRunning
    );

    // And it starts again.
    instance
        .start(Config::Json(config(socks_port, 53)))
        .await
        .unwrap();
    instance.stop().await.unwrap();
}

/// What a reload that only changes `dns.servers` keeps: the inbound's
/// listener, and a connection held through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_of_the_dns_servers_keeps_a_connection_held() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let socks_port = common::free_port();

    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(socks_port, 53)))
        .await
        .unwrap();

    let sess = Session {
        destination: echo.into(),
        ..Default::default()
    };
    let mut held = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut held, b"before the reload").await;
    let before: Vec<u64> = instance
        .connections()
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(before.len(), 1);

    instance
        .reload(Some(Config::Json(config(socks_port, 5353))))
        .await
        .unwrap();

    round_trip(&mut held, b"after the reload").await;
    let after: Vec<u64> = instance
        .connections()
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(after, before, "the same connection, not a new one");
    // The listener too: a new connection comes in.
    let mut new = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut new, b"a new one").await;

    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configuration_that_fails_says_why_and_the_log_says_it_too() {
    let instance = Instance::new(options()).unwrap();
    let err = instance
        .start(Config::Json(
            r#"{"outbounds": [{"type": "nonesuch"}]}"#.into(),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Config, "{}", err);
    assert!(matches!(instance.state(), State::Failed(ref e) if e.kind() == ErrorKind::Config));
    assert_eq!(
        instance.reload(None).await.unwrap_err().kind(),
        ErrorKind::NotRunning
    );
}

/// A configuration checked as a start would build it: its warnings, or why
/// it does not build; from the host's runtime, nothing started.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configuration_is_checked_without_an_instance() {
    let port = common::free_port();
    let warned = serde_json::json!({
        "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct", "tcp_multi_path": true }],
    })
    .to_string();
    let warnings = sail::embed::check(&Config::Json(warned), &options()).unwrap();
    assert_eq!(
        warnings,
        ["outbounds[0].tcp_multi_path: sail does not implement this field; ignored"]
    );
    // Nothing listens: the port is free.
    std::net::TcpListener::bind(("127.0.0.1", port)).expect("check binds nothing");

    let wrong = r#"{"outbounds": [{"type": "nonesuch"}]}"#.to_string();
    assert_eq!(
        sail::embed::check(&Config::Json(wrong), &options())
            .unwrap_err()
            .kind(),
        ErrorKind::Config
    );
}

/// The build names its release and its commit: in a git checkout of sail,
/// HEAD's short hash, unless the release build said which.
#[test]
fn the_build_names_its_release_and_commit() {
    let build = sail::embed::BUILD;
    assert_eq!(build.version, env!("CARGO_PKG_VERSION"));
    assert!(!build.commit.is_empty());
    if option_env!("SAIL_COMMIT").is_some() || option_env!("CFG_COMMIT_HASH").is_some() {
        return;
    }
    let head = std::process::Command::new("git")
        .args(["-C", concat!(env!("CARGO_MANIFEST_DIR"), "/..")])
        .args(["rev-parse", "--short", "HEAD"])
        .output();
    if let Some(head) = head.ok().filter(|o| o.status.success()) {
        assert_eq!(build.commit, String::from_utf8_lossy(&head.stdout).trim());
    }
}

/// Network changes, as a host pushes them, come as events in order, each
/// named, and pair with the snapshot by generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_changes_come_as_events_that_pair_with_the_snapshot() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds, NetworkChangeKind};

    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    let wifi = r#"{"interface": "en0", "type": "wifi", "gateway": "192.168.1.1",
                   "addresses": ["192.168.1.2/24"]}"#;
    instance.set_network_state(wifi).unwrap();

    // Subscribe, then read: the events after the snapshot's generation.
    let mut events = Box::pin(instance.events(Kinds::NETWORK));
    let snapshot = instance.network().unwrap();
    assert_eq!(
        snapshot.interface.as_ref().map(|i| i.name.as_str()),
        Some("en0")
    );
    assert!(!snapshot.offline());

    let moved = r#"{"interface": "en0", "type": "wifi", "gateway": "10.0.0.1",
                    "addresses": ["10.0.0.2/24"]}"#;
    let ethernet = r#"{"interface": "en1", "type": "ethernet", "gateway": "10.0.0.1",
                       "addresses": ["10.0.0.3/24"]}"#;
    for state in [moved, "{}", wifi, ethernet] {
        instance.set_network_state(state).unwrap();
    }
    let mut seen = Vec::new();
    while seen.len() < 4 {
        let event = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("an event in time")
            .expect("the stream goes on");
        match event {
            Event::Network(e) if e.generation <= snapshot.generation => {}
            Event::Network(e) => seen.push((e.generation, e.change)),
            other => panic!("unexpected {:?}", other),
        }
    }
    let g = snapshot.generation;
    assert_eq!(
        seen,
        [
            (g + 1, NetworkChangeKind::Moved),
            (g + 2, NetworkChangeKind::Offline),
            (g + 3, NetworkChangeKind::Restored),
            (g + 4, NetworkChangeKind::InterfaceChanged),
        ]
    );
    let now = instance.network().unwrap();
    assert_eq!(now.generation, g + 4);
    assert_eq!(now.interface.map(|i| i.name), Some("en1".to_string()));

    // A subscriber that falls behind is told how far.
    let mut slow = Box::pin(instance.events(Kinds::NETWORK));
    for i in 0..70 {
        instance
            .set_network_state(if i % 2 == 0 { wifi } else { ethernet })
            .unwrap();
    }
    let first = tokio::time::timeout(Duration::from_secs(5), slow.next())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(first, Event::Lagged { kind, missed } if kind == Kinds::NETWORK && missed > 0),
        "{:?}",
        first
    );
    instance.stop().await.unwrap();
}

/// An instance that changes nothing in the system writes no ledger: its
/// run directory is not even made. A sweep of an empty one undoes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_instance_that_changes_nothing_leaves_its_run_dir_unmade() {
    let dir = std::env::temp_dir().join(format!("sail-run-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let instance = Instance::new(options().run_dir(sail::embed::RunDir::Dir(dir.clone()))).unwrap();
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    instance.stop().await.unwrap();
    assert!(!dir.exists(), "no ledger, no directory");
    assert!(sail::embed::sweep(&sail::embed::RunDir::Dir(dir.clone())).is_empty());
    assert!(sail::embed::sweep(&sail::embed::RunDir::Off).is_empty());
}

/// An IPv6 link-local address of this machine, with its interface as the
/// scope: lo0's fe80::1 on macOS, the runner's Ethernet's on Linux. None
/// where there is none.
#[cfg(unix)]
fn link_local() -> Option<std::net::SocketAddrV6> {
    let mut found = None;
    // SAFETY: getifaddrs's list is read, then freed once.
    unsafe {
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut addrs) != 0 {
            return None;
        }
        let mut cur = addrs;
        while !cur.is_null() {
            let a = &*cur;
            if !a.ifa_addr.is_null()
                && i32::from((*a.ifa_addr).sa_family) == libc::AF_INET6
                && a.ifa_flags & libc::IFF_UP as u32 != 0
            {
                let sin6 = &*(a.ifa_addr as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let index = libc::if_nametoindex(a.ifa_name);
                if ip.segments()[0] & 0xffc0 == 0xfe80 && index != 0 {
                    found = Some(std::net::SocketAddrV6::new(ip, 0, 0, index));
                    break;
                }
            }
            cur = a.ifa_next;
        }
        libc::freeifaddrs(addrs);
    }
    found
}

/// A datagram to a link-local address goes out with its zone: the scope id
/// a host gives reaches the kernel unchanged, through the direct outbound.
/// Runs wherever an interface has an IPv6 link-local address, which needs
/// no root: lo0 on macOS, the runner's Ethernet on Linux CI.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_datagram_to_a_link_local_address_keeps_its_zone() {
    let Some(local) = link_local() else {
        eprintln!("no IPv6 link-local address here: nothing to test");
        return;
    };
    let echo = tokio::net::UdpSocket::bind(std::net::SocketAddr::V6(local))
        .await
        .unwrap();
    let to = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], from).await;
        }
    });

    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    let datagram = instance
        .dial_udp("direct", Address::from(to), Duration::from_secs(5))
        .await
        .unwrap();
    datagram.send(b"scoped").await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), datagram.recv_from(&mut buf))
        .await
        .expect("an answer over the link-local address")
        .unwrap();
    assert_eq!(&buf[..n], b"scoped");
    match from {
        Address::Ip(std::net::SocketAddr::V6(v6)) => assert_eq!(*v6.ip(), *local.ip()),
        other => panic!("from {:?}", other),
    }
    instance.stop().await.unwrap();
}

/// The state's changes come as events, and the status as a stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_state_comes_as_events_and_the_status_as_a_stream() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds};

    let instance = Instance::new(options()).unwrap();
    let mut events = Box::pin(instance.events(Kinds::STATE));
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    let mut status = Box::pin(instance.status(Duration::from_millis(100)));
    let first = tokio::time::timeout(Duration::from_secs(5), status.next())
        .await
        .expect("a status in time")
        .unwrap();
    assert_eq!(first.up, 0, "no rate before a second item");
    instance.stop().await.unwrap();
    let mut seen = Vec::new();
    while !matches!(seen.last(), Some(State::Stopped)) {
        match tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("a state in time")
            .unwrap()
        {
            Event::State(state) => seen.push(state),
            other => panic!("unexpected {:?}", other),
        }
    }
    assert!(
        seen.iter().any(|s| matches!(s, State::Running { .. })),
        "{:?}",
        seen
    );
}

/// An inbound added and removed while the instance runs: removing it closes
/// its own connections at once, frees its port, and leaves the other
/// inbounds' connections as they are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_an_inbound_closes_its_connections_only() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [kept_port, removed_port] = common::free_ports::<2>();
    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(kept_port, 53)))
        .await
        .unwrap();
    let proxy = serde_json::json!({
        "type": "socks", "tag": "system-proxy", "listen": "127.0.0.1", "listen_port": removed_port,
    });
    instance.add_inbound(proxy.clone()).await.unwrap();

    let sess = Session {
        destination: echo.into(),
        ..Default::default()
    };
    let mut kept = common::new_socks_stream("127.0.0.1", kept_port, &sess, None, None)
        .await
        .unwrap();
    let mut removed = common::new_socks_stream("127.0.0.1", removed_port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut kept, b"kept").await;
    round_trip(&mut removed, b"removed").await;

    assert_eq!(instance.remove_inbound("system-proxy").await.unwrap(), 1);
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), removed.read(&mut buf))
        .await
        .expect("the removed inbound's connection ends at once");
    assert!(matches!(read, Ok(0) | Err(_)));
    round_trip(&mut kept, b"still here").await;
    std::net::TcpListener::bind(("127.0.0.1", removed_port)).expect("its port is free");
    assert_eq!(
        instance
            .remove_inbound("system-proxy")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::Config
    );

    // And back again.
    instance.add_inbound(proxy).await.unwrap();
    let mut again = common::new_socks_stream("127.0.0.1", removed_port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut again, b"again").await;
    instance.stop().await.unwrap();
}

/// The network is settled when start returns: the interface (or an
/// explicit offline) at generation 1, before any change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_network_is_settled_when_start_returns() {
    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    let network = instance.network().unwrap();
    assert!(network.generation >= 1, "{:?}", network);
    // CI's runners and a developer's machine have a default route.
    assert!(network.interface.is_some(), "{:?}", network);
    instance.stop().await.unwrap();
}

/// A stop ends the instance's tasks within its bound and says so; a run
/// with no panic has no faults; test builds catch panics.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_reports_its_tasks_ended() {
    const { assert!(sail::embed::PANICS_ARE_CAUGHT) };
    let instance = Instance::new(options().stop_within(Duration::from_secs(2))).unwrap();
    assert!(instance.stop_report().is_none(), "no stop yet");
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    assert_eq!(instance.faults().unwrap(), 0);
    instance.stop().await.unwrap();
    let report = instance.stop_report().expect("a report after a stop");
    assert!(report.clean(), "{:?}", report);
    assert!(report.waited <= Duration::from_secs(2));
}
