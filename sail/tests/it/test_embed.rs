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
