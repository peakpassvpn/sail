//! Dynamic packet TUN on the SAME running proxy core. No OS route/device changes.
#![cfg(all(
    feature = "inbound-tun",
    feature = "inbound-mixed",
    feature = "outbound-direct"
))]
#![allow(clippy::disallowed_methods)]
use sail::embed::{Config, ErrorKind, Instance, Options, Runtime, TunState};
use sail_netstack::{emit_udp_packet, parse_ip_packet, parse_udp_datagram};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TUN: &str = r#"{"type":"tun","tag":"capture","address":["10.19.0.1/24"],"mtu":1500}"#;
fn config(port: u16) -> String {
    serde_json::json!({"log":{"level":"warn"}, "inbounds":[{"type":"mixed","tag":"mixed","listen":"127.0.0.1","listen_port":port,"users":[{"username":"u","password":"p"}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}).to_string()
}
async fn start_config(i: &Instance) -> u16 {
    for _ in 0..10 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        match i.start(Config::Json(config(port))).await {
            Ok(()) => return port,
            Err(e) if e.message().contains("Address already in use") => continue,
            Err(e) => panic!("start: {e}"),
        }
    }
    panic!("could not reserve a proxy listener port");
}
async fn start(enabled: bool) -> (Instance, u16) {
    let i = Instance::new(
        Options::new()
            .dynamic_tun(enabled)
            .runtime(Runtime::Host(tokio::runtime::Handle::current())),
    )
    .unwrap();
    let port = start_config(&i).await;
    (i, port)
}
async fn socks(port: u16, command: u8, target: SocketAddr) -> (tokio::net::TcpStream, SocketAddr) {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut r = [0; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 2]);
    s.write_all(&[1, 1, b'u', 1, b'p']).await.unwrap();
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [1, 0]);
    let SocketAddr::V4(v4) = target else {
        unreachable!()
    };
    let mut req = vec![5, command, 0, 1];
    req.extend(v4.ip().octets());
    req.extend(v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut r = [0; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0);
    (
        s,
        SocketAddr::from(([r[4], r[5], r[6], r[7]], u16::from_be_bytes([r[8], r[9]]))),
    )
}
async fn roundtrip(s: &mut tokio::net::TcpStream, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    let mut r = vec![0; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut r))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r, msg);
}
async fn tcp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let t = tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (a, t)
}
async fn udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    (
        a,
        tokio::spawn(async move {
            let mut b = [0; 2048];
            loop {
                let (n, a) = s.recv_from(&mut b).await.unwrap();
                s.send_to(&b[..n], a).await.unwrap();
            }
        }),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_authenticated_tcp_http_and_udp_survive_three_tun_generations() {
    let (i, port) = start(true).await;
    let original = i.manager().unwrap();
    let (tcp, task) = tcp_echo().await;
    let (udp, utask) = udp_echo().await;
    let (mut s, _) = socks(port, 1, tcp).await;
    let mut http = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    http.write_all(
        format!("CONNECT {tcp} HTTP/1.1\r\nHost: {tcp}\r\nProxy-Authorization: Basic dTpw\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    loop {
        let b = http.read_u8().await.unwrap();
        head.push(b);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let (_association, relay) = socks(port, 3, "0.0.0.0:0".parse().unwrap()).await;
    let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(v4) = udp else {
        unreachable!()
    };
    let mut udp_req = vec![0, 0, 0, 1];
    udp_req.extend(v4.ip().octets());
    udp_req.extend(v4.port().to_be_bytes());
    udp_req.extend(b"mixed-udp");
    for n in 0..3 {
        roundtrip(&mut s, b"before").await;
        roundtrip(&mut http, b"before-http").await;
        let (p, mut flow) = i.prepare_tun_packets(TUN, 2).await.unwrap();
        assert!(matches!(i.tun_state().unwrap(), TunState::Prepared { .. }));
        p.commit().await.unwrap();
        assert!(original.has_tun());
        let source = "10.19.0.2:41000".parse().unwrap();
        flow.uplink
            .send(emit_udp_packet(source, udp, b"captured-udp", 64, n).unwrap())
            .await
            .unwrap();
        let wire = tokio::time::timeout(Duration::from_secs(5), flow.downlink.recv())
            .await
            .unwrap()
            .unwrap();
        let ip = parse_ip_packet(&wire, true).unwrap();
        let parsed = parse_udp_datagram(ip, true).unwrap();
        assert_eq!(parsed.destination, source);
        assert_eq!(parsed.payload, b"captured-udp");
        roundtrip(&mut s, b"attached").await;
        roundtrip(&mut http, b"attached-http").await;
        u.send_to(&udp_req, relay).await.unwrap();
        let mut b = [0; 256];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), u.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[10..len], b"mixed-udp");
        assert!(i.detach_tun().await.unwrap().clean());
        assert!(!original.has_tun());
        assert!(flow.uplink.send(vec![0x45]).await.is_err());
        assert!(flow.downlink.recv().await.is_none());
        assert!(i.detach_tun().await.unwrap().clean());
        roundtrip(&mut s, b"after").await;
        roundtrip(&mut http, b"after-http").await;
        u.send_to(&udp_req, relay).await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), u.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[10..len], b"mixed-udp");
        assert!(Arc::ptr_eq(&original, &i.manager().unwrap()));
        let mut denied = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        denied.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0; 2];
        denied.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 255]);
    }
    i.stop().await.unwrap();
    task.abort();
    utask.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepare_drop_backpressure_stale_handle_and_opt_in() {
    let (i, _) = start(false).await;
    assert_eq!(
        i.prepare_tun_packets(TUN, 1).await.unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    i.stop().await.unwrap();
    let (i, _) = start(true).await;
    let (p, mut f) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    f.uplink.send(vec![0x45]).await.unwrap();
    assert!(futures::poll!(std::pin::pin!(f.uplink.send(vec![0x45]))).is_pending());
    assert_eq!(
        i.prepare_tun_packets(TUN, 1).await.unwrap_err().kind(),
        ErrorKind::State
    );
    drop(p);
    assert!(f.uplink.send(vec![0x45]).await.is_err());
    assert!(f.downlink.recv().await.is_none());
    let old_manager = i.manager().unwrap();
    let (old, mut flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    i.stop().await.unwrap();
    assert!(flow.downlink.recv().await.is_none());
    start_config(&i).await;
    assert!(!Arc::ptr_eq(&old_manager, &i.manager().unwrap()));
    assert!(old.commit().await.is_err());
    assert_eq!(i.tun_state().unwrap(), TunState::Detached);
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    assert!(i.detach_tun().await.unwrap().clean());
    i.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_default_compatibility_and_dynamic_conflicts() {
    let (i, port) = start(true).await;
    let mut static_config: serde_json::Value = serde_json::from_str(&config(port)).unwrap();
    static_config["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::from_str(TUN).unwrap());
    assert_eq!(
        i.reload(Some(Config::Json(static_config.to_string())))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NeedsRestart
    );
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    assert!(i
        .reload(Some(Config::Json(static_config.to_string())))
        .await
        .is_err());
    p.commit().await.unwrap();
    i.reload(Some(Config::Json(config(port)))).await.unwrap();
    assert!(i.manager().unwrap().has_tun());
    assert!(i.detach_tun().await.unwrap().clean());
    i.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_prepares_and_cancelled_host_awaits_reconcile_by_detach() {
    let (i, _) = start(true).await;
    let (a, b) = tokio::join!(i.prepare_tun_packets(TUN, 1), i.prepare_tun_packets(TUN, 1));
    let (p, mut flow) = match (a, b) {
        (Ok(p), Err(e)) | (Err(e), Ok(p)) => {
            assert_eq!(e.kind(), ErrorKind::State);
            p
        }
        _ => panic!("exactly one reservation"),
    };
    // First poll transfers execution to Sail. Cancelling the host await
    // cannot lose an attachment: idempotent detach reconciles either outcome.
    let mut commit = Box::pin(p.commit());
    let _ = futures::poll!(&mut commit);
    drop(commit);
    let mut detach = Box::pin(i.detach_tun());
    let _ = futures::poll!(&mut detach);
    drop(detach);
    assert!(i.detach_tun().await.unwrap().clean());
    assert_eq!(i.tun_state().unwrap(), TunState::Detached);
    assert!(flow.downlink.recv().await.is_none());
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    i.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_joins_a_captured_tcp_stream_without_ending_the_proxy_stream() {
    use sail_netstack::{emit_tcp_segment, parse_tcp_segment, SendControl, SeqNumber, TcpFlags};
    let (i, port) = start(true).await;
    let (echo, task) = tcp_echo().await;
    let (mut proxy, _) = socks(port, 1, echo).await;
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = target.local_addr().unwrap();
    let source = "10.19.0.2:42000".parse().unwrap();
    let (received_tx, received) = tokio::sync::oneshot::channel();
    let closed = tokio::spawn(async move {
        let (mut s, _) = target.accept().await.unwrap();
        let mut payload = [0; 7];
        s.read_exact(&mut payload).await.unwrap();
        received_tx.send(payload).unwrap();
        let mut byte = [0];
        s.read(&mut byte).await.unwrap()
    });
    let (p, mut flow) = i.prepare_tun_packets(TUN, 4).await.unwrap();
    p.commit().await.unwrap();
    let packet = |sequence, acknowledgment, flags, payload: &[u8]| {
        emit_tcp_segment(
            source,
            destination,
            SendControl {
                sequence: SeqNumber::new(sequence),
                acknowledgment: SeqNumber::new(acknowledgment),
                flags,
                window: 32000,
            },
            payload,
            64,
            1,
        )
        .unwrap()
    };
    flow.uplink
        .send(packet(100, 0, TcpFlags::SYN, &[]))
        .await
        .unwrap();
    let wire = tokio::time::timeout(Duration::from_secs(5), flow.downlink.recv())
        .await
        .unwrap()
        .unwrap();
    let syn = parse_tcp_segment(parse_ip_packet(&wire, true).unwrap(), true).unwrap();
    let next = syn.meta.sequence.wrapping_add(1).get();
    flow.uplink
        .send(packet(101, next, TcpFlags::ACK, b"tun-tcp"))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), received)
            .await
            .unwrap()
            .unwrap(),
        *b"tun-tcp"
    );
    roundtrip(&mut proxy, b"proxy during capture").await;
    assert!(i.detach_tun().await.unwrap().clean());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), closed)
            .await
            .unwrap()
            .unwrap(),
        0
    );
    roundtrip(&mut proxy, b"proxy after captured EOF").await;
    i.stop().await.unwrap();
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_transport_failure_is_local_and_requires_explicit_detach() {
    let (i, port) = start(true).await;
    let (echo, task) = tcp_echo().await;
    let (mut proxy, _) = socks(port, 1, echo).await;
    let (p, flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    drop(flow);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(i.tun_state().unwrap(), TunState::Failed { .. }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    roundtrip(&mut proxy, b"proxy after packet transport failure").await;
    assert!(i.prepare_tun_packets(TUN, 1).await.is_err());
    assert!(i.detach_tun().await.unwrap().clean());
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    i.stop().await.unwrap();
    task.abort();
}
