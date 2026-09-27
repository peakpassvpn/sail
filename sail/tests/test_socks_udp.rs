//! SOCKS5 UDP ASSOCIATE through the socks and mixed inbounds: datagrams
//! carry the user who asked for the association.

#![cfg(all(
    feature = "inbound-mixed",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-drop",
))]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// An inbound of `protocol` that knows alice and bob and lets only bob
/// through, so that the user's name has to reach routing.
fn server(protocol: &str, port: u16) -> String {
    serde_json::json!({
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

/// Runs `configs`, then `check`, and shuts the instances down.
fn with_instances<F, Fut>(configs: Vec<String>, check: F) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ids = common::run_sail_instances(&rt, configs)?;
    let result = rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        check().await
    });
    for id in ids {
        sail::shutdown(id);
    }
    result
}

/// A UDP association asked for as `user`: the control connection, and the
/// client's socket, sending to the relay.
struct Association {
    control: TcpStream,
    socket: UdpSocket,
}

impl Association {
    /// Authenticates as `user` with `password` on `port`, and associates,
    /// declaring the client socket's address when `declare`, else 0.0.0.0:0
    /// as RFC 1928 has a client that does not know its address do.
    async fn open(port: u16, user: &str, password: &str, declare: bool) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let mut control = TcpStream::connect(("127.0.0.1", port)).await?;
        control.write_all(&[0x05, 0x01, 0x02]).await?;
        let mut reply = [0u8; 2];
        control.read_exact(&mut reply).await?;
        anyhow::ensure!(reply == [0x05, 0x02], "method refused: {:?}", reply);
        let mut auth = vec![0x01, user.len() as u8];
        auth.extend_from_slice(user.as_bytes());
        auth.push(password.len() as u8);
        auth.extend_from_slice(password.as_bytes());
        control.write_all(&auth).await?;
        control.read_exact(&mut reply).await?;
        anyhow::ensure!(reply == [0x01, 0x00], "authentication refused");
        let mut request = vec![0x05, 0x03, 0x00, 0x01];
        match socket.local_addr()? {
            SocketAddr::V4(addr) if declare => {
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
        Ok(Association { control, socket })
    }

    async fn send(&self, to: SocketAddr, data: &[u8]) -> anyhow::Result<()> {
        let SocketAddr::V4(to) = to else {
            anyhow::bail!("not ipv4: {}", to);
        };
        let mut packet = vec![0, 0, 0, 0x01];
        packet.extend_from_slice(&to.ip().octets());
        packet.extend_from_slice(&to.port().to_be_bytes());
        packet.extend_from_slice(data);
        self.socket.send(&packet).await?;
        Ok(())
    }

    /// The payload of the next datagram within `wait`, and whom it is from.
    async fn recv(&self, wait: Duration) -> anyhow::Result<Option<(Vec<u8>, SocketAddr)>> {
        let mut buf = [0u8; 2048];
        let Ok(n) = timeout(wait, self.socket.recv(&mut buf)).await else {
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
}

/// bob's datagrams are routed by his name, alice's are blocked by hers,
/// on the inbound `protocol`.
fn udp_is_routed_by_user(protocol: &'static str) -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        with_instances(vec![server(protocol, port)], move || async move {
            let (echo, echo_fut) = common::run_udp_echo_server("127.0.0.1:0").await?;
            let echo_task = tokio::spawn(echo_fut);
            let result = async {
                // bob is known by his IP, alice by the address she declares.
                let bob = Association::open(port, "bob", "bob-pass", false).await?;
                let alice = Association::open(port, "alice", "alice-pass", true).await?;
                bob.send(echo, b"from bob").await?;
                let answer = bob.recv(Duration::from_secs(5)).await?;
                anyhow::ensure!(
                    answer == Some((b"from bob".to_vec(), echo)),
                    "bob got {:?}",
                    answer
                );
                alice.send(echo, b"from alice").await?;
                let answer = alice.recv(Duration::from_secs(1)).await?;
                anyhow::ensure!(answer.is_none(), "alice was routed through: {:?}", answer);
                // bob's association still carries his name.
                bob.send(echo, b"again").await?;
                let answer = bob.recv(Duration::from_secs(5)).await?;
                anyhow::ensure!(
                    answer == Some((b"again".to_vec(), echo)),
                    "bob got {:?}",
                    answer
                );
                drop(alice.control);
                drop(bob.control);
                Ok(())
            }
            .await;
            echo_task.abort();
            result
        })
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

// Datagrams outside any association are nobody's, and dropped when the
// inbound authenticates: here, from a host no control connection came from.
#[test]
fn test_socks_udp_without_association_is_dropped() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        with_instances(vec![server("socks", port)], move || async move {
            let (echo, echo_fut) = common::run_udp_echo_server("127.0.0.1:0").await?;
            let echo_task = tokio::spawn(echo_fut);
            let result = async {
                let bob = Association::open(port, "bob", "bob-pass", false).await?;
                // bob's association is known by 127.0.0.1; 127.0.0.2 is
                // nobody's. Not every host routes it, so skip when it cannot.
                let Ok(stranger) = UdpSocket::bind("127.0.0.2:0").await else {
                    return Ok(());
                };
                let relay = bob.socket.peer_addr()?;
                let mut packet = vec![0, 0, 0, 0x01, 127, 0, 0, 1];
                packet.extend_from_slice(&echo.port().to_be_bytes());
                packet.extend_from_slice(b"stranger");
                stranger.send_to(&packet, relay).await?;
                let mut buf = [0u8; 2048];
                let answer = timeout(Duration::from_secs(1), stranger.recv(&mut buf)).await;
                anyhow::ensure!(answer.is_err(), "a stranger's datagram got through");
                Ok(())
            }
            .await;
            echo_task.abort();
            result
        })
    })
}

// Closing the control connection ends the association's NAT sessions (RFC
// 1928): the outbound socket the session sent from takes nothing more back
// to the client, well before the session would have idled out.
#[test]
fn test_socks_udp_association_end_ends_its_sessions() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        with_instances(vec![server("socks", port)], move || async move {
            let target = UdpSocket::bind("127.0.0.1:0").await?;
            let target_addr = target.local_addr()?;
            let bob = Association::open(port, "bob", "bob-pass", false).await?;
            bob.send(target_addr, b"hello").await?;
            let mut buf = [0u8; 2048];
            let (n, outbound) =
                timeout(Duration::from_secs(5), target.recv_from(&mut buf)).await??;
            anyhow::ensure!(&buf[..n] == b"hello", "target got {:?}", &buf[..n]);

            // While the association lasts, its session takes datagrams back.
            target.send_to(b"ping", outbound).await?;
            let answer = bob.recv(Duration::from_secs(5)).await?;
            anyhow::ensure!(
                answer == Some((b"ping".to_vec(), target_addr)),
                "bob got {:?}",
                answer
            );

            let Association { control, socket } = bob;
            drop(control);
            let bob = Association {
                control: TcpStream::connect(("127.0.0.1", port)).await?,
                socket,
            };
            tokio::time::sleep(Duration::from_millis(500)).await;
            target.send_to(b"late", outbound).await?;
            let answer = bob.recv(Duration::from_secs(1)).await?;
            anyhow::ensure!(answer.is_none(), "the session outlived its association");
            Ok(())
        })
    })
}
