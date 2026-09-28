//! SOCKS5 UDP ASSOCIATE through the socks and mixed inbounds: each
//! association has a relay socket of its own (RFC 1928), which takes the
//! client's datagrams only, carries the user who asked for it, and closes
//! with the control connection. And sail's socks outbound, against sail and
//! sing-box.

#![cfg(all(
    feature = "inbound-mixed",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-drop",
    feature = "outbound-socks",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// An inbound of `protocol` that knows alice and bob and lets only bob
/// through, so that the user's name has to reach routing.
fn server(protocol: &str, port: u16) -> String {
    json!({
        "inbounds": [{
            "type": protocol,
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [
                { "username": "alice", "password": "alice-pass" },
                { "username": "bob", "password": "bob-pass" }
            ]
        }],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" }
        ],
        "route": {
            "rules": [{ "auth_user": ["bob"], "outbound": "direct" }],
            "final": "block"
        }
    })
    .to_string()
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

/// Runs `configs`, then `check` with a UDP echo server's address, and
/// shuts the instances down.
fn with_instances<F, Fut>(configs: Vec<String>, check: F) -> anyhow::Result<()>
where
    F: FnOnce(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let rt = runtime()?;
    let ids = common::run_sail_instances(&rt, configs)?;
    let result = rt.block_on(async {
        let (echo, echo_fut) = common::run_udp_echo_server("127.0.0.1:0").await?;
        let echo_task = tokio::spawn(echo_fut);
        let result = check(echo).await;
        echo_task.abort();
        result
    });
    common::shutdown_instances(&rt, ids);
    result
}

/// How the client declares the address it will send from.
#[derive(Clone, Copy)]
enum Declare {
    /// 0.0.0.0:0, as RFC 1928 has a client that does not know it do.
    Nothing,
    /// Its socket's address.
    Own,
}

/// A UDP association: the control connection, the client's socket, and
/// the relay the server named.
struct Association {
    control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

/// A SOCKS5 UDP request to `to` carrying `data`.
fn request(to: SocketAddr, data: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(to) = to else {
        panic!("not ipv4: {}", to);
    };
    let mut packet = vec![0, 0, 0, 0x01];
    packet.extend_from_slice(&to.ip().octets());
    packet.extend_from_slice(&to.port().to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

impl Association {
    /// Associates on `port`, as `user` when given.
    async fn open(port: u16, user: Option<(&str, &str)>, declare: Declare) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let mut control = TcpStream::connect(("127.0.0.1", port)).await?;
        let method = if user.is_some() { 0x02 } else { 0x00 };
        control.write_all(&[0x05, 0x01, method]).await?;
        let mut reply = [0u8; 2];
        control.read_exact(&mut reply).await?;
        anyhow::ensure!(reply == [0x05, method], "method refused: {:?}", reply);
        if let Some((user, password)) = user {
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            control.write_all(&auth).await?;
            control.read_exact(&mut reply).await?;
            anyhow::ensure!(reply == [0x01, 0x00], "authentication refused");
        }
        let mut request = vec![0x05, 0x03, 0x00, 0x01];
        match (declare, socket.local_addr()?) {
            (Declare::Own, SocketAddr::V4(addr)) => {
                request.extend_from_slice(&addr.ip().octets());
                request.extend_from_slice(&addr.port().to_be_bytes());
            }
            _ => request.extend_from_slice(&[0, 0, 0, 0, 0, 0]),
        }
        control.write_all(&request).await?;
        let mut answer = [0u8; 10];
        timeout(Duration::from_secs(5), control.read_exact(&mut answer)).await??;
        anyhow::ensure!(answer[..4] == [0x05, 0x00, 0x00, 0x01], "{:?}", answer);
        let relay = SocketAddr::from((
            [answer[4], answer[5], answer[6], answer[7]],
            u16::from_be_bytes([answer[8], answer[9]]),
        ));
        socket.connect(relay).await?;
        Ok(Association {
            control,
            socket,
            relay,
        })
    }

    async fn send(&self, to: SocketAddr, data: &[u8]) -> anyhow::Result<()> {
        self.socket.send(&request(to, data)).await?;
        Ok(())
    }

    /// The payload of the next datagram within `wait`, and whom it is from.
    async fn recv(&self, wait: Duration) -> anyhow::Result<Option<(Vec<u8>, SocketAddr)>> {
        recv_on(&self.socket, wait).await
    }

    /// Whether `data` sent to the echo server `echo` comes back.
    async fn echoes(&self, echo: SocketAddr, data: &[u8]) -> anyhow::Result<bool> {
        self.send(echo, data).await?;
        let wait = Duration::from_secs(2);
        Ok(self.recv(wait).await? == Some((data.to_vec(), echo)))
    }
}

/// The next SOCKS5 UDP reply on `socket` within `wait`: its payload, and
/// whom it is from.
async fn recv_on(
    socket: &UdpSocket,
    wait: Duration,
) -> anyhow::Result<Option<(Vec<u8>, SocketAddr)>> {
    let mut buf = [0u8; 2048];
    let Ok(n) = timeout(wait, socket.recv(&mut buf)).await else {
        return Ok(None);
    };
    let n = n?;
    anyhow::ensure!(
        n >= 10 && buf[3] == 0x01,
        "unexpected answer {:?}",
        &buf[..n]
    );
    let from = SocketAddr::from((
        [buf[4], buf[5], buf[6], buf[7]],
        u16::from_be_bytes([buf[8], buf[9]]),
    ));
    Ok(Some((buf[10..n].to_vec(), from)))
}

/// Runs `check` against a fresh `protocol` inbound; see `server`.
fn on_inbound<F, Fut>(protocol: &'static str, check: F) -> anyhow::Result<()>
where
    F: Fn(u16, SocketAddr) -> Fut + Clone,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    common::retry_port_clash(|| {
        let port = common::free_port();
        let check = check.clone();
        with_instances(vec![server(protocol, port)], move |echo| check(port, echo))
    })
}

// bob's datagrams are routed by his name, alice's are blocked by hers.
fn udp_is_routed_by_user(protocol: &'static str) -> anyhow::Result<()> {
    on_inbound(protocol, |port, echo| async move {
        let bob = Association::open(port, Some(("bob", "bob-pass")), Declare::Nothing).await?;
        let alice = Association::open(port, Some(("alice", "alice-pass")), Declare::Own).await?;
        anyhow::ensure!(
            bob.echoes(echo, b"from bob").await?,
            "bob was not let through"
        );
        anyhow::ensure!(
            !alice.echoes(echo, b"from alice").await?,
            "alice was routed through"
        );
        anyhow::ensure!(bob.echoes(echo, b"again").await?, "bob lost his name");
        Ok(())
    })
}

#[test]
fn test_socks_udp_is_routed_by_user() -> anyhow::Result<()> {
    udp_is_routed_by_user("socks")
}

#[test]
fn test_mixed_udp_is_routed_by_user() -> anyhow::Result<()> {
    udp_is_routed_by_user("mixed")
}

// Each association is relayed on a port of its own, on the address the
// client reached the inbound at, and the listen port serves no UDP.
fn each_association_has_its_own_relay(protocol: &'static str) -> anyhow::Result<()> {
    on_inbound(protocol, |port, echo| async move {
        let a = Association::open(port, Some(("bob", "bob-pass")), Declare::Nothing).await?;
        let b = Association::open(port, Some(("bob", "bob-pass")), Declare::Own).await?;
        for relay in [a.relay, b.relay] {
            anyhow::ensure!(
                relay.ip() == std::net::Ipv4Addr::LOCALHOST && relay.port() != port,
                "relay {} is not a port of its own",
                relay
            );
        }
        anyhow::ensure!(a.relay != b.relay, "two associations share {}", a.relay);
        anyhow::ensure!(a.echoes(echo, b"a").await? && b.echoes(echo, b"b").await?);

        // Nothing listens on the listen port's UDP: sail does not bind it.
        let listen = SocketAddr::from(([127, 0, 0, 1], port));
        anyhow::ensure!(
            std::net::UdpSocket::bind(listen).is_ok(),
            "udp {} is bound",
            listen
        );
        Ok(())
    })
}

#[test]
fn test_socks_udp_each_association_has_its_own_relay() -> anyhow::Result<()> {
    each_association_has_its_own_relay("socks")
}

#[test]
fn test_mixed_udp_each_association_has_its_own_relay() -> anyhow::Result<()> {
    each_association_has_its_own_relay("mixed")
}

/// Whether `stranger`'s datagram to `relay`, bound for `echo`, comes back.
async fn stranger_gets_through(
    stranger: &UdpSocket,
    relay: SocketAddr,
    echo: SocketAddr,
) -> anyhow::Result<bool> {
    stranger.send_to(&request(echo, b"stranger"), relay).await?;
    let mut buf = [0u8; 2048];
    Ok(timeout(Duration::from_secs(1), stranger.recv(&mut buf))
        .await
        .is_ok())
}

// A client that declared its address is held to it: a datagram from
// another port of the same IP is dropped.
#[test]
fn test_socks_udp_other_port_is_dropped_when_declared() -> anyhow::Result<()> {
    on_inbound("socks", |port, echo| async move {
        let bob = Association::open(port, Some(("bob", "bob-pass")), Declare::Own).await?;
        let stranger = UdpSocket::bind("127.0.0.1:0").await?;
        // Even first: the declaration, not the first datagram, names bob.
        anyhow::ensure!(
            !stranger_gets_through(&stranger, bob.relay, echo).await?,
            "a datagram from another port got through"
        );
        anyhow::ensure!(bob.echoes(echo, b"bob").await?, "bob was not let through");
        Ok(())
    })
}

// A client that declared nothing is known by its first datagram's address:
// one from another port, or another IP, is dropped after it.
#[test]
fn test_socks_udp_other_source_is_dropped_when_undeclared() -> anyhow::Result<()> {
    on_inbound("socks", |port, echo| async move {
        let bob = Association::open(port, Some(("bob", "bob-pass")), Declare::Nothing).await?;
        anyhow::ensure!(bob.echoes(echo, b"bob").await?, "bob was not let through");
        let stranger = UdpSocket::bind("127.0.0.1:0").await?;
        anyhow::ensure!(
            !stranger_gets_through(&stranger, bob.relay, echo).await?,
            "a datagram from another port got through"
        );
        // Not every host routes 127.0.0.2; skip that part when it cannot.
        if let Ok(stranger) = UdpSocket::bind("127.0.0.2:0").await {
            anyhow::ensure!(
                !stranger_gets_through(&stranger, bob.relay, echo).await?,
                "a datagram from another IP got through"
            );
        }
        anyhow::ensure!(bob.echoes(echo, b"still bob").await?, "bob lost his relay");
        Ok(())
    })
}

// A datagram from another IP is dropped before the client has sent any:
// it neither gets through nor takes the client's place.
#[test]
fn test_socks_udp_other_ip_cannot_pin_the_relay() -> anyhow::Result<()> {
    on_inbound("socks", |port, echo| async move {
        let Ok(stranger) = UdpSocket::bind("127.0.0.2:0").await else {
            return Ok(());
        };
        let bob = Association::open(port, Some(("bob", "bob-pass")), Declare::Nothing).await?;
        anyhow::ensure!(
            !stranger_gets_through(&stranger, bob.relay, echo).await?,
            "a datagram from another IP got through"
        );
        anyhow::ensure!(bob.echoes(echo, b"bob").await?, "bob was not let through");
        Ok(())
    })
}

// Two clients on one IP, neither declaring its address: what a shared
// socket could only guess, a relay each tells apart. Each keeps its own
// user, whichever sends first.
fn two_clients_on_one_ip(protocol: &'static str) -> anyhow::Result<()> {
    on_inbound(protocol, |port, echo| async move {
        let alice =
            Association::open(port, Some(("alice", "alice-pass")), Declare::Nothing).await?;
        let bob = Association::open(port, Some(("bob", "bob-pass")), Declare::Nothing).await?;
        anyhow::ensure!(alice.relay != bob.relay, "one relay for both");
        anyhow::ensure!(
            !alice.echoes(echo, b"alice").await?,
            "alice was routed as bob"
        );
        anyhow::ensure!(bob.echoes(echo, b"bob").await?, "bob was routed as alice");
        anyhow::ensure!(
            !alice.echoes(echo, b"alice again").await?,
            "alice was routed as bob"
        );
        Ok(())
    })
}

#[test]
fn test_socks_udp_two_clients_on_one_ip() -> anyhow::Result<()> {
    two_clients_on_one_ip("socks")
}

#[test]
fn test_mixed_udp_two_clients_on_one_ip() -> anyhow::Result<()> {
    two_clients_on_one_ip("mixed")
}

// Closing the control connection closes the relay socket: its port is
// free again.
fn relay_closes_with_control(protocol: &'static str) -> anyhow::Result<()> {
    on_inbound(protocol, |port, echo| async move {
        let bob = Association::open(port, Some(("bob", "bob-pass")), Declare::Nothing).await?;
        anyhow::ensure!(bob.echoes(echo, b"bob").await?, "bob was not let through");
        let relay = bob.relay;
        anyhow::ensure!(
            std::net::UdpSocket::bind(relay).is_err(),
            "the relay {} is not bound",
            relay
        );
        drop(bob.control);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while std::net::UdpSocket::bind(relay).is_err() {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "the relay {} outlived its control connection",
                relay
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    })
}

#[test]
fn test_socks_udp_relay_closes_with_control() -> anyhow::Result<()> {
    relay_closes_with_control("socks")
}

#[test]
fn test_mixed_udp_relay_closes_with_control() -> anyhow::Result<()> {
    relay_closes_with_control("mixed")
}

// Closing the control connection ends the association's NAT sessions (RFC
// 1928): the outbound socket the session sent from takes nothing more back
// to the client, well before the session would have idled out.
#[test]
fn test_socks_udp_association_end_ends_its_sessions() -> anyhow::Result<()> {
    on_inbound("socks", |port, _echo| async move {
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let target_addr = target.local_addr()?;
        let bob = Association::open(port, Some(("bob", "bob-pass")), Declare::Nothing).await?;
        bob.send(target_addr, b"hello").await?;
        let mut buf = [0u8; 2048];
        let (n, outbound) = timeout(Duration::from_secs(5), target.recv_from(&mut buf)).await??;
        anyhow::ensure!(&buf[..n] == b"hello", "target got {:?}", &buf[..n]);

        // While the association lasts, its session takes datagrams back.
        target.send_to(b"ping", outbound).await?;
        let answer = bob.recv(Duration::from_secs(5)).await?;
        anyhow::ensure!(
            answer == Some((b"ping".to_vec(), target_addr)),
            "bob got {:?}",
            answer
        );

        let Association {
            control, socket, ..
        } = bob;
        drop(control);
        tokio::time::sleep(Duration::from_millis(500)).await;
        target.send_to(b"late", outbound).await?;
        let answer = recv_on(&socket, Duration::from_secs(1)).await;
        anyhow::ensure!(
            !matches!(answer, Ok(Some(_))),
            "the session outlived its association"
        );
        Ok(())
    })
}

/// A UDP round trip to `echo` through sail's socks outbound, to the SOCKS5
/// server on `port`, as `user`.
async fn outbound_round_trip(
    port: u16,
    user: Option<(&str, &str)>,
    echo: SocketAddr,
) -> anyhow::Result<()> {
    let sess = sail::session::Session {
        destination: sail::session::SocksAddr::from(echo),
        ..Default::default()
    };
    let datagram = common::new_socks_datagram(
        "127.0.0.1",
        port,
        &sess,
        user.map(|u| u.0.to_string()),
        user.map(|u| u.1.to_string()),
    )
    .await?;
    let (mut recv, mut send) = datagram.split();
    let target = sail::session::SocksAddr::from(echo);
    let mut buf = [0u8; 2048];
    for payload in [&b"one"[..], b"two"] {
        send.send_to(payload, &target).await?;
        let (n, from) = timeout(Duration::from_secs(5), recv.recv_from(&mut buf)).await??;
        anyhow::ensure!(&buf[..n] == payload, "echoed {:?}", &buf[..n]);
        anyhow::ensure!(from == target, "echoed from {}", from);
    }
    Ok(())
}

// sail's socks outbound to sail's socks and mixed inbounds.
#[test]
fn test_socks_udp_sail_outbound_to_sail_inbound() -> anyhow::Result<()> {
    for protocol in ["socks", "mixed"] {
        on_inbound(protocol, |port, echo| async move {
            outbound_round_trip(port, Some(("bob", "bob-pass")), echo).await
        })?;
    }
    Ok(())
}

// sail's socks outbound to sing-box's socks and mixed inbounds.
#[test]
#[ignore = "needs sing-box"]
fn test_socks_udp_sail_outbound_to_sing_box() -> anyhow::Result<()> {
    for protocol in ["socks", "mixed"] {
        common::retry_port_clash(|| {
            let port = common::free_port();
            let dir = common::TempDir::new("socks-udp")?;
            let _sing_box = common::Daemon::sing_box(
                dir.path(),
                protocol,
                json!({
                    "inbounds": [{
                        "type": protocol,
                        "listen": "127.0.0.1",
                        "listen_port": port,
                        "users": [{ "username": "bob", "password": "bob-pass" }]
                    }],
                    "outbounds": [{ "type": "direct" }]
                }),
            )?;
            runtime()?.block_on(async {
                let (echo, echo_fut) = common::run_udp_echo_server("127.0.0.1:0").await?;
                let echo_task = tokio::spawn(echo_fut);
                let result = outbound_round_trip(port, Some(("bob", "bob-pass")), echo).await;
                echo_task.abort();
                result
            })
        })?;
    }
    Ok(())
}

// sing-box's socks outbound to sail's socks and mixed inbounds: a client
// associates with sing-box's mixed inbound, and sing-box associates with
// sail as bob, whom sail routes by name.
#[test]
#[ignore = "needs sing-box"]
fn test_socks_udp_sing_box_outbound_to_sail() -> anyhow::Result<()> {
    for protocol in ["socks", "mixed"] {
        common::retry_port_clash(|| {
            let [sail_port, sing_box_port] = common::free_ports();
            let dir = common::TempDir::new("socks-udp")?;
            let rt = runtime()?;
            let ids = common::run_sail_instances(&rt, vec![server(protocol, sail_port)])?;
            let result = (|| {
                let client = |user: &str, password: &str| {
                    json!({
                        "type": "socks",
                        "tag": user,
                        "server": "127.0.0.1",
                        "server_port": sail_port,
                        "version": "5",
                        "username": user,
                        "password": password
                    })
                };
                let _sing_box = common::Daemon::sing_box(
                    dir.path(),
                    "client",
                    json!({
                        "inbounds": [{
                            "type": "mixed",
                            "listen": "127.0.0.1",
                            "listen_port": sing_box_port,
                            "users": [
                                { "username": "bob", "password": "bob-pass" },
                                { "username": "alice", "password": "alice-pass" }
                            ]
                        }],
                        "outbounds": [
                            client("bob", "bob-pass"),
                            client("alice", "alice-pass")
                        ],
                        "route": {
                            "rules": [{ "auth_user": ["alice"], "outbound": "alice" }],
                            "final": "bob"
                        }
                    }),
                )?;
                rt.block_on(async {
                    let (echo, echo_fut) = common::run_udp_echo_server("127.0.0.1:0").await?;
                    let echo_task = tokio::spawn(echo_fut);
                    let result = async {
                        let bob = Association::open(
                            sing_box_port,
                            Some(("bob", "bob-pass")),
                            Declare::Nothing,
                        )
                        .await?;
                        anyhow::ensure!(
                            bob.echoes(echo, b"bob").await?,
                            "bob did not get through sing-box and sail"
                        );
                        let alice = Association::open(
                            sing_box_port,
                            Some(("alice", "alice-pass")),
                            Declare::Nothing,
                        )
                        .await?;
                        anyhow::ensure!(
                            !alice.echoes(echo, b"alice").await?,
                            "sail routed alice through"
                        );
                        anyhow::ensure!(bob.echoes(echo, b"bob again").await?);
                        Ok(())
                    }
                    .await;
                    echo_task.abort();
                    result
                })
            })();
            common::shutdown_instances(&rt, ids);
            result
        })?;
    }
    Ok(())
}
