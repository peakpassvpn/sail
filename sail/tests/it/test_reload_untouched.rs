//! What did not change is left alone: a reload whose configuration differs
//! from what runs in its inbounds alone builds nothing else again. The
//! outbound is the one that ran, so the multiplexed session it holds
//! carries the next stream; the group's checks are not started over; the
//! DNS cache keeps its answers. A reload that changes anything else, a
//! rule, or follows a file the configuration names being written, builds
//! it all again, and tells so.
#![cfg(all(
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks",
    feature = "outbound-urltest",
    feature = "mux"
))]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sail::embed::{Config, InboundChange, Instance, Options, ReloadPath, Threads};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::common;

const SS_METHOD: &str = "2022-blake3-aes-128-gcm";
const SS_KEY: &str = "a8C5QncIl9HvTmenrEb7aw==";

/// Relays what it accepts to `to`, and counts the connections: one a
/// multiplexed session the client opens.
async fn counting_relay(to: u16) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let accepted = accepted.clone();
        async move {
            while let Ok((mut from, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    if let Ok(mut to) = TcpStream::connect(("127.0.0.1", to)).await {
                        let _ = tokio::io::copy_bidirectional(&mut from, &mut to).await;
                    }
                });
            }
        }
    });
    (port, accepted)
}

/// A DNS server that answers every A question with 127.0.0.1 for a
/// minute, any other with nothing, and counts the A questions.
async fn counting_dns() -> (u16, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let asked = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let asked = asked.clone();
        async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let mut answer = buf[..n].to_vec();
                let mut at = 12;
                while answer[at] != 0 {
                    at += 1 + answer[at] as usize;
                }
                let a = answer[at + 1..at + 3] == [0, 1];
                // The answers that can be kept: an empty one, to another
                // question, carries no time to keep it for, and is asked
                // for again each time.
                if a {
                    asked.fetch_add(1, Ordering::SeqCst);
                }
                answer.truncate(at + 5);
                answer[2] = 0x81;
                answer[3] = 0x80;
                answer[6..12].copy_from_slice(&[0, u8::from(a), 0, 0, 0, 0]);
                if a {
                    answer.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
                }
                let _ = socket.send_to(&answer, from).await;
            }
        }
    });
    (port, asked)
}

/// An HTTP server that answers 204 to anything, and counts the requests:
/// one a check a group makes of a member.
async fn counting_checks() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let checked = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let checked = checked.clone();
        async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let checked = checked.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    if matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {
                        checked.fetch_add(1, Ordering::SeqCst);
                        let _ = stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                            .await;
                    }
                });
            }
        }
    });
    (port, checked)
}

/// A SOCKS5 connection through the inbound on `port`, to an address or a
/// name, relayed.
async fn through(port: u16, host: Result<SocketAddr, (&str, u16)>) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut greeted = [0u8; 2];
    s.read_exact(&mut greeted).await?;
    let mut request = vec![5, 1, 0];
    match host {
        Ok(SocketAddr::V4(to)) => {
            request.push(1);
            request.extend(to.ip().octets());
            request.extend(to.port().to_be_bytes());
        }
        Ok(SocketAddr::V6(_)) => return Err(std::io::Error::other("an IPv4 destination")),
        Err((name, to)) => {
            request.push(3);
            request.push(name.len() as u8);
            request.extend(name.as_bytes());
            request.extend(to.to_be_bytes());
        }
    }
    s.write_all(&request).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS REP {}", reply[1])));
    }
    Ok(s)
}

/// Sends through `s` and has it back from the echo server.
async fn relays(s: &mut TcpStream) -> bool {
    let relayed = async {
        s.write_all(b"still here").await?;
        let mut back = [0u8; 10];
        s.read_exact(&mut back).await?;
        std::io::Result::Ok(back == *b"still here")
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(5), relayed).await,
        Ok(Ok(true))
    )
}

/// Waits until `counter` has moved past `past`, at most 10 s.
async fn moved_past(counter: &AtomicUsize, past: usize, what: &str) -> usize {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let now = counter.load(Ordering::SeqCst);
        if now > past {
            return now;
        }
        assert!(tokio::time::Instant::now() < deadline, "{}", what);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_of_the_inbounds_alone_builds_nothing_else_again() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [server_port, keep, extra] = common::free_ports();
    let (relay_port, sessions) = counting_relay(server_port).await;
    let (dns_port, questions) = counting_dns().await;
    let (check_port, checks) = counting_checks().await;
    // Root certificates in a file: one the configuration names and sail
    // does not watch.
    let dir = common::TempDir::new("reload-untouched").unwrap();
    let roots = dir.join("roots.pem");
    let pem = |name: &str| {
        rcgen::generate_simple_self_signed(vec![name.to_string()])
            .unwrap()
            .cert
            .pem()
    };
    std::fs::write(&roots, pem("one.test")).unwrap();

    // The server the multiplexed outbound goes to.
    let server = Instance::new(Options::new().threads(Threads::One).log_lines(100)).unwrap();
    server
        .start(Config::Json(
            serde_json::json!({
                "inbounds": [{
                    "type": "shadowsocks", "tag": "ss-in",
                    "listen": "127.0.0.1", "listen_port": server_port,
                    "method": SS_METHOD, "password": SS_KEY,
                    "multiplex": { "enabled": true },
                }],
                "outbounds": [{ "type": "direct", "tag": "direct" }],
            })
            .to_string(),
        ))
        .await
        .unwrap();

    let socks = |tag: &str, port: u16| serde_json::json!({ "type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": port });
    let config = |inbounds: serde_json::Value, rules: serde_json::Value| {
        Config::Json(
            serde_json::json!({
                "log": { "level": "info" },
                "dns": { "servers": [{ "tag": "counted", "type": "udp",
                                       "server": "127.0.0.1", "server_port": dns_port }] },
                "inbounds": inbounds,
                "outbounds": [
                    { "type": "direct", "tag": "direct" },
                    { "type": "shadowsocks", "tag": "mux",
                      "server": "127.0.0.1", "server_port": relay_port,
                      "method": SS_METHOD, "password": SS_KEY,
                      "multiplex": { "enabled": true, "protocol": "smux" } },
                    { "type": "urltest", "tag": "auto", "outbounds": ["direct"],
                      "url": format!("http://127.0.0.1:{}/", check_port), "interval": "1h" },
                ],
                "route": { "rules": rules, "final": "direct" },
                "certificate": { "certificate_path": [roots] },
            })
            .to_string(),
        )
    };
    let to_mux = serde_json::json!([{ "port": [echo.port()], "ip_cidr": ["127.0.0.1/32"],
                                      "outbound": "mux" }]);
    let one = || serde_json::json!([socks("keep", keep)]);
    let two = || serde_json::json!([socks("keep", keep), socks("extra", extra)]);

    let instance = Instance::new(Options::new().threads(Threads::One).log_lines(100)).unwrap();
    instance.start(config(one(), to_mux.clone())).await.unwrap();

    // What runs: a stream over a session to the server, a name resolved,
    // the group's first check done.
    let mut first = through(keep, Ok(echo)).await.unwrap();
    assert!(relays(&mut first).await);
    assert_eq!(
        sessions.load(Ordering::SeqCst),
        1,
        "one session to the server"
    );
    drop(
        through(keep, Err(("cached.test", echo.port())))
            .await
            .unwrap(),
    );
    let asked = questions.load(Ordering::SeqCst);
    assert!(asked > 0, "the name was asked for");
    moved_past(&checks, 0, "the group did not check its member").await;
    // Its first round over: the count stands still from here, the next
    // being an hour away.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let checked = checks.load(Ordering::SeqCst);

    // The same configuration again, then one inbound more, then that one
    // gone: each time only the inbounds are looked at.
    let report = instance
        .reload(Some(config(one(), to_mux.clone())))
        .await
        .unwrap();
    assert_eq!(report.path, ReloadPath::InboundsOnly);
    assert_eq!(
        report.inbounds,
        [("keep".to_string(), InboundChange::Untouched)]
    );
    let report = instance
        .reload(Some(config(two(), to_mux.clone())))
        .await
        .unwrap();
    assert_eq!(report.path, ReloadPath::InboundsOnly);
    assert_eq!(
        report.inbounds,
        [
            ("keep".to_string(), InboundChange::Untouched),
            ("extra".to_string(), InboundChange::Added),
        ]
    );
    // The inbound added is served by the outbound that ran: its stream
    // goes over the session there is.
    let mut second = through(extra, Ok(echo)).await.unwrap();
    assert!(relays(&mut second).await);
    assert!(relays(&mut first).await, "the stream open before goes on");
    assert_eq!(
        sessions.load(Ordering::SeqCst),
        1,
        "the outbound opened another session: it was built again"
    );
    // The answer is still cached, and the group has not checked again.
    drop(
        through(keep, Err(("cached.test", echo.port())))
            .await
            .unwrap(),
    );
    assert_eq!(
        questions.load(Ordering::SeqCst),
        asked,
        "the DNS cache was emptied"
    );
    let report = instance
        .reload(Some(config(one(), to_mux.clone())))
        .await
        .unwrap();
    assert_eq!(report.path, ReloadPath::InboundsOnly);
    assert_eq!(
        report.inbounds,
        [
            ("keep".to_string(), InboundChange::Untouched),
            ("extra".to_string(), InboundChange::Removed),
        ]
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        checks.load(Ordering::SeqCst),
        checked,
        "the group's checks were started over"
    );

    // A file the configuration names is written: what was read of it is
    // stale, and the same configuration is built again, all of it.
    std::fs::write(&roots, pem("another.test")).unwrap();
    let report = instance
        .reload(Some(config(one(), to_mux.clone())))
        .await
        .unwrap();
    assert_eq!(report.path, ReloadPath::Full, "a file it names was written");
    moved_past(&checks, checked, "the group built again did not check").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let checked = checks.load(Ordering::SeqCst);
    // Read again, it is what runs: the same once more is the inbounds'.
    let report = instance
        .reload(Some(config(one(), to_mux.clone())))
        .await
        .unwrap();
    assert_eq!(report.path, ReloadPath::InboundsOnly);

    // A rule more: not the inbounds alone. The outbound is built again,
    // and opens a session of its own; the cache starts empty.
    let mut more = to_mux.clone();
    more.as_array_mut()
        .unwrap()
        .push(serde_json::json!({ "port": [1], "outbound": "direct" }));
    let report = instance.reload(Some(config(one(), more))).await.unwrap();
    assert_eq!(report.path, ReloadPath::Full);
    assert_eq!(
        report.inbounds,
        [("keep".to_string(), InboundChange::Untouched)]
    );
    let before = sessions.load(Ordering::SeqCst);
    let mut third = through(keep, Ok(echo)).await.unwrap();
    assert!(relays(&mut third).await);
    assert_eq!(
        sessions.load(Ordering::SeqCst),
        before + 1,
        "the outbound built again opens a session of its own"
    );
    drop(
        through(keep, Err(("cached.test", echo.port())))
            .await
            .unwrap(),
    );
    assert!(
        questions.load(Ordering::SeqCst) > asked,
        "a new client asks again"
    );
    moved_past(&checks, checked, "the group built again did not check").await;
    assert!(
        relays(&mut first).await,
        "a stream open goes on through it all"
    );

    instance.stop().await.unwrap();
    server.stop().await.unwrap();
}

/// A fallback pinned to a member by hand stays pinned through a reload
/// that builds the group again, and through one of the inbounds alone.
#[cfg(feature = "outbound-fallback")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fallback_s_pin_is_kept_by_a_reload() {
    let (check_port, _checks) = counting_checks().await;
    let [keep] = common::free_ports();
    let config = |rules: serde_json::Value| {
        Config::Json(
            serde_json::json!({
                "log": { "level": "info" },
                "inbounds": [{ "type": "socks", "tag": "keep",
                               "listen": "127.0.0.1", "listen_port": keep }],
                "outbounds": [
                    { "type": "direct", "tag": "a" },
                    { "type": "direct", "tag": "b" },
                    { "type": "fallback", "tag": "fb", "outbounds": ["a", "b"],
                      "url": format!("http://127.0.0.1:{}/", check_port), "interval": "1h" },
                ],
                "route": { "rules": rules, "final": "fb" },
            })
            .to_string(),
        )
    };
    let instance = Instance::new(Options::new().threads(Threads::One).log_lines(100)).unwrap();
    instance.start(config(serde_json::json!([]))).await.unwrap();
    /// The member the fallback is pinned to, and the one it sends to.
    async fn pinned(instance: &Instance) -> (Option<String>, String) {
        let group = instance
            .groups()
            .await
            .unwrap()
            .into_iter()
            .find(|g| g.tag == "fb")
            .and_then(|g| g.group)
            .expect("the fallback is a group");
        (group.fixed, group.selected)
    }
    instance.select("fb", "b").await.unwrap();
    assert_eq!(
        pinned(&instance).await,
        (Some("b".to_string()), "b".to_string())
    );

    // The group is built again: its pin is taken over.
    let rule = serde_json::json!([{ "port": [1], "outbound": "a" }]);
    let report = instance.reload(Some(config(rule.clone()))).await.unwrap();
    assert_eq!(report.path, ReloadPath::Full);
    assert_eq!(
        pinned(&instance).await,
        (Some("b".to_string()), "b".to_string()),
        "a reload that built the group again lost its pin"
    );
    // The inbounds alone: the group is the one that ran.
    let report = instance.reload(Some(config(rule))).await.unwrap();
    assert_eq!(report.path, ReloadPath::InboundsOnly);
    assert_eq!(
        pinned(&instance).await,
        (Some("b".to_string()), "b".to_string())
    );
    instance.stop().await.unwrap();
}

/// A UDP session open through an inbound that stays goes on through a
/// reload of the inbounds alone, and through one that builds the
/// outbounds again: datagrams still go and come back on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_udp_session_goes_on_through_a_reload() {
    use sail::session::{Session, SocksAddr};

    let (udp_echo, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [keep, extra] = common::free_ports();
    let socks = |tag: &str, port: u16| serde_json::json!({ "type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": port });
    let config = |inbounds: serde_json::Value, rules: serde_json::Value| {
        Config::Json(
            serde_json::json!({
                "log": { "level": "info" },
                "inbounds": inbounds,
                "outbounds": [{ "type": "direct", "tag": "direct" }],
                "route": { "rules": rules, "final": "direct" },
            })
            .to_string(),
        )
    };
    let none = serde_json::json!([]);
    let instance = Instance::new(Options::new().threads(Threads::One).log_lines(100)).unwrap();
    instance
        .start(config(
            serde_json::json!([socks("keep", keep)]),
            none.clone(),
        ))
        .await
        .unwrap();

    let sess = Session {
        destination: SocksAddr::from(udp_echo),
        ..Default::default()
    };
    let datagram = common::new_socks_datagram("127.0.0.1", keep, &sess, None, None)
        .await
        .unwrap();
    let (mut recv, mut send) = datagram.split();
    let to = SocksAddr::from(udp_echo);
    macro_rules! echoed {
        ($what:expr) => {{
            send.send_to($what, &to).await.unwrap();
            let mut buf = [0u8; 64];
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), recv.recv_from(&mut buf))
                .await
                .expect("a datagram back on the session")
                .unwrap();
            assert_eq!(&buf[..n], $what);
        }};
    }
    echoed!(b"before");

    let report = instance
        .reload(Some(config(
            serde_json::json!([socks("keep", keep), socks("extra", extra)]),
            none.clone(),
        )))
        .await
        .unwrap();
    assert_eq!(report.path, ReloadPath::InboundsOnly);
    echoed!(b"after the inbounds alone");

    let rule = serde_json::json!([{ "port": [1], "outbound": "direct" }]);
    let report = instance
        .reload(Some(config(
            serde_json::json!([socks("keep", keep), socks("extra", extra)]),
            rule,
        )))
        .await
        .unwrap();
    assert_eq!(report.path, ReloadPath::Full);
    echoed!(b"after all was built again");
    instance.stop().await.unwrap();
}
