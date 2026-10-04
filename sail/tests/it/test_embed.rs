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
        loop {
            let (n, from) = crate::common::recv_past_errors(&echo, &mut buf).await;
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
    // Closed on return, not a moment later: a connection is refused now.
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", removed_port)).is_err(),
        "the removed inbound still listens once the removal returned"
    );
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
        ErrorKind::NotFound
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

/// A SOCKS5 connection through `proxy` asking for 127.0.0.1:`port`, its
/// greeting answered and its request sent, the reply not read.
async fn socks_asked(proxy: u16, port: u16) -> tokio::net::TcpStream {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", proxy))
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeted = [0u8; 2];
    s.read_exact(&mut greeted).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend(port.to_be_bytes());
    s.write_all(&request).await.unwrap();
    s
}

/// The reply's code: 0 when connected.
async fn socks_reply(s: &mut tokio::net::TcpStream) -> u8 {
    let mut reply = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut reply))
        .await
        .expect("a SOCKS reply in time")
        .unwrap();
    reply[1]
}

/// `Kinds::ROUTE` tells every connection once: one that is over before
/// any poll of the connections open, a dial that fails, a reject and a
/// hijacked DNS query, none of which such a poll shows. While no one
/// subscribes, none is built.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_connection_is_told_once_and_none_is_built_unheard() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds, RouteAction, RoutedConnection};
    use sail::session::{Network, SocksAddr};
    use std::sync::Arc;

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [socks, rejected, hijacked, dead] = common::free_ports();
    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "upstream", "type": "udp", "server": "127.0.0.1", "server_port": 53 }],
        },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks,
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": {
            "rules": [
                { "port": [rejected], "action": "reject" },
                // One entry of the list, whatever it holds.
                { "type": "logical", "mode": "or",
                  "rules": [{ "port": [1] }, { "port": [2] }], "outbound": "direct" },
                { "port": [hijacked], "action": "hijack-dns" },
                { "port": [echo.port()], "outbound": "direct" },
            ],
            "final": "direct",
        },
    })
    .to_string();
    let instance = Instance::new(options()).unwrap();
    instance.start(Config::Json(config)).await.unwrap();

    // A connection over at once: asked for, a byte each way, closed.
    async fn short(socks: u16, port: u16) {
        let mut s = socks_asked(socks, port).await;
        assert_eq!(socks_reply(&mut s).await, 0);
        round_trip(&mut s, b"x").await;
    }

    // No one listens: nothing is built.
    for _ in 0..3 {
        short(socks, echo.port()).await;
    }
    assert_eq!(instance.routes_built().unwrap(), 0);

    let mut events = Box::pin(instance.events(Kinds::ROUTE));
    async fn next(
        events: &mut (impl futures::Stream<Item = Event> + Unpin),
    ) -> Arc<RoutedConnection> {
        match tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("a routed connection in time")
            .unwrap()
        {
            Event::Routed(routed) => routed,
            other => panic!("unexpected {:?}", other),
        }
    }
    let to = |port: u16| SocksAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], port)));

    // One that is over before any poll would see it.
    short(socks, echo.port()).await;
    let told = next(&mut events).await;
    assert_eq!(told.action, RouteAction::Outbound, "{:?}", told);
    assert_eq!(told.network, Network::Tcp);
    assert_eq!(told.inbound, "socks-in");
    assert_eq!(told.destination, to(echo.port()));
    assert_eq!(told.request_destination, Some(to(echo.port())));
    assert_eq!(told.rule, Some(3), "its index in route.rules as written");
    assert!(told.rule_text.is_some());
    assert_eq!(told.chain, ["direct"]);
    assert_eq!(told.target, Some(echo));
    assert!(matches!(told.connect, Some(Ok(_))), "{:?}", told);
    assert!(told.id.is_some());
    assert_eq!(told.domain, None);

    // A dial that fails: nothing listens there. `final` decided.
    let mut s = socks_asked(socks, dead).await;
    assert_ne!(socks_reply(&mut s).await, 0);
    let told = next(&mut events).await;
    assert_eq!(told.action, RouteAction::Outbound, "{:?}", told);
    assert_eq!(told.rule, None);
    assert_eq!(told.chain, ["direct"]);
    assert_eq!(
        told.connect,
        Some(Err(std::io::ErrorKind::ConnectionRefused)),
        "{:?}",
        told
    );
    assert_eq!(told.id, None, "it never opened");

    // A reject.
    let mut s = socks_asked(socks, rejected).await;
    assert_ne!(socks_reply(&mut s).await, 0);
    let told = next(&mut events).await;
    assert_eq!(told.action, RouteAction::Reject, "{:?}", told);
    assert_eq!(told.rule, Some(0));
    assert_eq!(told.connect, None);
    assert!(told.chain.is_empty());

    // A hijacked DNS query: told when the rules decide, whatever it asks.
    let s = socks_asked(socks, hijacked).await;
    let told = next(&mut events).await;
    assert_eq!(told.action, RouteAction::HijackDns, "{:?}", told);
    assert_eq!(told.rule, Some(2));
    assert_eq!(told.destination, to(hijacked));
    drop(s);

    // Each exactly once: four built, and no fifth event.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), events.next())
            .await
            .is_err(),
        "a connection was told twice"
    );
    assert_eq!(instance.routes_built().unwrap(), 4);

    // The subscription dropped, nothing is built again.
    drop(events);
    short(socks, echo.port()).await;
    assert_eq!(instance.routes_built().unwrap(), 4);
    instance.stop().await.unwrap();
}

/// `Kinds::DNS` tells the queries the instance makes to dial a domain,
/// and a rule's answer; none is built while no one subscribes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_queries_are_told_and_none_is_built_unheard() {
    use futures::StreamExt;
    use sail::embed::{DnsExchange, DnsOutcome, DnsSource, Event, Kinds};
    use sail::session::SocksAddr;
    use std::sync::Arc;

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "home", "type": "hosts",
                          "predefined": { "echo.test": "127.0.0.1" } }],
            "rules": [{ "domain": "blocked.test", "action": "reject" }],
        },
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    })
    .to_string();
    let instance = Instance::new(options()).unwrap();
    instance.start(Config::Json(config)).await.unwrap();
    let dial = |name: &str| {
        let instance = &instance;
        let to = SocksAddr::Domain(name.into(), echo.port());
        async move {
            instance
                .dial_tcp("direct", to, Duration::from_secs(5))
                .await
        }
    };

    dial("echo.test").await.unwrap();
    assert_eq!(instance.dns_built().unwrap(), 0);

    let mut events = Box::pin(instance.events(Kinds::DNS));
    // Every event until `name`'s A query is told.
    async fn until_a(
        events: &mut (impl futures::Stream<Item = Event> + Unpin),
        name: &str,
    ) -> Arc<DnsExchange> {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), events.next())
                .await
                .expect("a DNS event in time")
                .unwrap()
            {
                Event::DnsExchange(e) if e.name == name && e.qtype == "A" => return e,
                // The other family, or the query before's.
                Event::DnsExchange(_) => {}
                other => panic!("unexpected {:?}", other),
            }
        }
    }

    let mut s = dial("echo.test").await.unwrap();
    let told = until_a(&mut events, "echo.test").await;
    assert_eq!(told.server.as_deref(), Some("home"), "{:?}", told);
    assert_eq!(told.answers, ["127.0.0.1"]);
    assert!(told.for_instance);
    assert!(
        matches!(told.outcome, DnsOutcome::Answered { .. }),
        "{:?}",
        told
    );
    round_trip(&mut s, b"x").await;

    assert!(dial("blocked.test").await.is_err());
    let told = until_a(&mut events, "blocked.test").await;
    assert_eq!(told.source, DnsSource::Rule, "{:?}", told);
    assert_eq!(told.server, None);
    assert!(told.for_instance);

    let built = instance.dns_built().unwrap();
    assert!(built >= 2, "{}", built);
    drop(events);
    dial("echo.test").await.unwrap();
    assert_eq!(instance.dns_built().unwrap(), built);
    instance.stop().await.unwrap();
}

/// The outbounds a connection went through are told outermost first, the
/// one that carried it last, by `Event::Routed` and `Event::DialFailed`
/// alike, for a rule that names a group whose member is a group; the
/// connections list has them the other way round, as the Clash API does.
#[cfg(feature = "outbound-select")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chain_is_told_outermost_first_by_routed_and_dial_failed_alike() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds};

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [socks, dead] = common::free_ports();
    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "upstream", "type": "udp", "server": "127.0.0.1", "server_port": 53 }],
        },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks,
        }],
        "outbounds": [
            { "type": "direct", "tag": "m" },
            { "type": "selector", "tag": "G", "outbounds": ["m"] },
            { "type": "selector", "tag": "F", "outbounds": ["G"] },
        ],
        "route": {
            "rules": [{ "port": [echo.port(), dead], "outbound": "F" }],
            "final": "m",
        },
    })
    .to_string();
    let instance = Instance::new(options()).unwrap();
    instance.start(Config::Json(config)).await.unwrap();
    let mut events = Box::pin(instance.events(Kinds::ROUTE | Kinds::DIAL));
    async fn next(events: &mut (impl futures::Stream<Item = Event> + Unpin)) -> Event {
        tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("an event in time")
            .unwrap()
    }

    // One that connects, held open: listed, and told.
    let mut held = socks_asked(socks, echo.port()).await;
    assert_eq!(socks_reply(&mut held).await, 0);
    round_trip(&mut held, b"x").await;
    match next(&mut events).await {
        Event::Routed(routed) => {
            assert_eq!(routed.chain, ["F", "G", "m"], "{:?}", routed);
            assert!(matches!(routed.connect, Some(Ok(_))), "{:?}", routed);
        }
        other => panic!("unexpected {:?}", other),
    }
    let listed = instance.connections().await.unwrap();
    let listed = listed
        .iter()
        .find(|c| c.inbound_tag == "socks-in")
        .expect("the connection held is listed");
    assert_eq!(listed.chains, ["m", "G", "F"], "the Clash API's order");

    // One whose dial fails: both events, in whichever order they come.
    let mut refused = socks_asked(socks, dead).await;
    assert_ne!(socks_reply(&mut refused).await, 0);
    let (mut routed, mut failed) = (None, None);
    while routed.is_none() || failed.is_none() {
        match next(&mut events).await {
            Event::Routed(event) => routed = Some(event),
            Event::DialFailed { failure, .. } => failed = Some(failure),
            other => panic!("unexpected {:?}", other),
        }
    }
    let (routed, failed) = (routed.unwrap(), failed.unwrap());
    assert_eq!(routed.chain, ["F", "G", "m"], "{:?}", routed);
    assert!(matches!(routed.connect, Some(Err(_))), "{:?}", routed);
    assert_eq!(failed.chain, "F>G>m", "{:?}", failed);
    assert_eq!(failed.chain, routed.chain.join(">"));
    drop(held);
    instance.stop().await.unwrap();
}

/// A DNS answer to `query`: 127.0.0.1 for an A question, none for any
/// other.
#[cfg(feature = "rule-set")]
fn dns_answer(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    // The question's end: its name, its type and class.
    let mut at = 12;
    while answer[at] != 0 {
        at += 1 + answer[at] as usize;
    }
    let a = answer[at + 1..at + 3] == [0, 1];
    answer.truncate(at + 5);
    // A response, recursion available; one answer or none, nothing else.
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[6..12].copy_from_slice(&[0, u8::from(a), 0, 0, 0, 0]);
    if a {
        answer.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
    }
    answer
}

/// A host's own DNS service, which the configuration names, is asked
/// while the instance starts, for the name of a remote rule-set the start
/// waits for. It answers by dialling back through the instance, and reads
/// the network first: both work in `Starting`, so the start succeeds.
/// A dial made as the start begins waits rather than being refused; once
/// the run has ended, both say it does not run.
#[cfg(feature = "rule-set")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_service_asked_during_the_start_dials_back_and_reads_the_network() {
    use std::sync::{Arc, Mutex};

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);

    // What the host's service asks in its turn: answers every name.
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = common::recv_past_errors(&upstream, &mut buf).await;
            let _ = upstream.send_to(&dns_answer(&buf[..n]), from).await;
        }
    });

    // The rule-set, at a name only that DNS knows.
    let rules = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rules_port = rules.local_addr().unwrap().port();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Write};
        for stream in rules.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                line.clear();
            }
            let body = r#"{ "version": 3, "rules": [{ "ip_cidr": "192.0.2.0/24" }] }"#;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });

    let instance = Arc::new(Instance::new(options()).unwrap());

    // The host's DNS service: for each query, the network and the state
    // as it sees them, then the answer fetched through the instance.
    struct Asked {
        starting: bool,
        interface: Result<bool, ErrorKind>,
        dialled: Result<(), ErrorKind>,
    }
    let asked: Arc<Mutex<Vec<Asked>>> = Arc::default();
    let service = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let service_port = service.local_addr().unwrap().port();
    tokio::spawn({
        let (instance, asked, service) = (instance.clone(), asked.clone(), service.clone());
        async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, from) = common::recv_past_errors(&service, &mut buf).await;
                let query = buf[..n].to_vec();
                let (instance, asked, service) = (instance.clone(), asked.clone(), service.clone());
                tokio::spawn(async move {
                    let starting = instance.state() == State::Starting;
                    let interface = instance
                        .network()
                        .map(|network| network.interface.is_some())
                        .map_err(|e| e.kind());
                    let answered = async {
                        let upstream = instance
                            .dial_udp(
                                "direct",
                                Address::from(upstream_addr),
                                Duration::from_secs(2),
                            )
                            .await
                            .map_err(|e| e.kind())?;
                        upstream.send(&query).await.map_err(|_| ErrorKind::Io)?;
                        let mut answer = [0u8; 1500];
                        let (n, _) = tokio::time::timeout(
                            Duration::from_secs(2),
                            upstream.recv_from(&mut answer),
                        )
                        .await
                        .map_err(|_| ErrorKind::Timeout)?
                        .map_err(|_| ErrorKind::Io)?;
                        let _ = service.send_to(&answer[..n], from).await;
                        Ok(())
                    };
                    let dialled = answered.await;
                    asked.lock().unwrap().push(Asked {
                        starting,
                        interface,
                        dialled,
                    });
                });
            }
        }
    });

    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "host", "type": "udp", "server": "127.0.0.1", "server_port": service_port }],
        },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": common::free_port(),
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": {
            "rule_set": [{
                "type": "remote", "tag": "s", "format": "source",
                "url": format!("http://rules.test:{}/s.json", rules_port),
            }],
            "rules": [{ "rule_set": "s", "action": "reject" }],
            "final": "direct",
        },
    })
    .to_string();

    // Not started: a dial is refused, and so is the network.
    let idle = instance
        .dial_tcp("direct", Address::from(echo), Duration::from_secs(5))
        .await;
    assert_eq!(idle.err().map(|e| e.kind()), Some(ErrorKind::NotRunning));
    assert_eq!(
        instance.network().unwrap_err().kind(),
        ErrorKind::NotRunning
    );

    // A dial made as the start begins waits for the outbounds, and dials.
    let (started, early) = tokio::join!(
        instance.start(Config::Json(config)),
        instance.dial_tcp("direct", Address::from(echo), Duration::from_secs(5)),
    );
    // The start waited for the rule-set, whose name the host's service
    // resolved by dialling back: a refusal there fails the start.
    started.expect("the start, which needs the rule-set's name resolved");
    let mut early = early.expect("a dial made while it starts");
    round_trip(&mut early, b"dialled while it started").await;

    {
        let asked = asked.lock().unwrap();
        assert!(
            !asked.is_empty(),
            "the host's DNS was asked during the start"
        );
        for asked in asked.iter() {
            assert_eq!(asked.dialled, Ok(()), "a dial back was refused");
            assert_eq!(asked.interface, Ok(true), "the network was not settled");
        }
        assert!(
            asked.iter().any(|asked| asked.starting),
            "none was asked while it started"
        );
    }

    // The run ended: what dialled through it dials no more.
    instance.stop().await.unwrap();
    let after = instance
        .dial_udp(
            "direct",
            Address::from(upstream_addr),
            Duration::from_secs(2),
        )
        .await;
    assert_eq!(after.err().map(|e| e.kind()), Some(ErrorKind::NotRunning));
    assert_eq!(
        instance.network().unwrap_err().kind(),
        ErrorKind::NotRunning
    );
}

/// A group's health check, spawned while the instance is built, on no
/// task, is the instance's: in its scope while it runs, ended by its stop.
#[cfg(feature = "outbound-urltest")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_groups_checks_built_at_start_are_the_instances() {
    let mut config: serde_json::Value =
        serde_json::from_str(&config(common::free_port(), 53)).unwrap();
    config["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "type": "urltest", "tag": "auto", "outbounds": ["direct"],
            "url": "http://127.0.0.1:9/", "interval": "1m",
        }));
    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config.to_string()))
        .await
        .unwrap();
    let tasks = instance.tasks().unwrap();
    assert!(
        tasks.iter().any(|(name, _)| *name == "group health check"),
        "{:?}",
        tasks
    );
    instance.stop().await.unwrap();
    let report = instance.stop_report().expect("a report after a stop");
    assert!(report.clean(), "{:?}", report);
}

/// Two instances on the host's runtime at once, as a desktop app's UI and
/// service in one process: each carries its connections; stopped in the
/// order other than started, they leave nothing on the runtime. (Their
/// logs: test_embed_host_subscriber.rs.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instances_on_the_hosts_runtime_carry_and_leave_nothing() {
    let host = tokio::runtime::Handle::current();
    let (echo_a, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let (echo_b, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let alive_before = host.metrics().num_alive_tasks();

    let on_host = || {
        // `threads` is ignored under the host's runtime.
        options().runtime(sail::embed::Runtime::Host(host.clone()))
    };
    let (a, b) = (
        Instance::new(on_host()).unwrap(),
        Instance::new(on_host()).unwrap(),
    );
    let (a_port, b_port) = (common::free_port(), common::free_port());
    a.start(Config::Json(config(a_port, 53))).await.unwrap();
    b.start(Config::Json(config(b_port, 53))).await.unwrap();
    assert!(
        host.metrics().num_alive_tasks() > alive_before,
        "the instances' tasks run on the host's runtime"
    );

    for (port, echo) in [(a_port, echo_a), (b_port, echo_b)] {
        let mut s = socks_asked(port, echo.port()).await;
        assert_eq!(socks_reply(&mut s).await, 0);
        round_trip(&mut s, b"on the host's runtime").await;
    }
    b.stop().await.unwrap();
    assert!(matches!(a.state(), State::Running { .. }), "a goes on");
    let mut s = socks_asked(a_port, echo_a.port()).await;
    assert_eq!(socks_reply(&mut s).await, 0);
    round_trip(&mut s, b"after b stopped").await;
    drop(s);
    a.stop().await.unwrap();
    for instance in [&a, &b] {
        let report = instance.stop_report().expect("a report after a stop");
        assert!(report.clean(), "{:?}", report);
    }
    std::net::TcpListener::bind(("127.0.0.1", a_port)).expect("a's port is free");
    std::net::TcpListener::bind(("127.0.0.1", b_port)).expect("b's port is free");

    // Not one task of theirs left on the host's runtime: a task's last
    // drop may finish just after the stop.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while host.metrics().num_alive_tasks() > alive_before && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(host.metrics().num_alive_tasks(), alive_before);

    // And one starts again on it.
    a.start(Config::Json(config(a_port, 53))).await.unwrap();
    a.stop().await.unwrap();
}

/// A current-thread runtime is refused at start, saying so: the instance's
/// own thread blocks on it, which such a runtime does not serve.
#[tokio::test(flavor = "current_thread")]
async fn a_current_thread_host_runtime_is_refused() {
    let instance = Instance::new(
        options().runtime(sail::embed::Runtime::Host(tokio::runtime::Handle::current())),
    )
    .unwrap();
    let err = instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument, "{}", err);
    assert!(err.to_string().contains("current-thread"), "{}", err);
    assert!(
        matches!(instance.state(), State::Failed(ref e) if e.kind() == ErrorKind::InvalidArgument)
    );
}

/// A runtime without timers is refused at start, saying what to build it
/// with, rather than the first timer panicking in a task.
#[test]
fn a_host_runtime_without_timers_is_refused() {
    let host = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_io()
        .build()
        .unwrap();
    let instance =
        Instance::new(options().runtime(sail::embed::Runtime::Host(host.handle().clone())))
            .unwrap();
    let err =
        futures::executor::block_on(instance.start(Config::Json(config(common::free_port(), 53))))
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument, "{}", err);
    assert!(err.to_string().contains("enable_all()"), "{}", err);
}
