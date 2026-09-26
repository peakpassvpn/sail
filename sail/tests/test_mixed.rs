//! The mixed inbound serving HTTP, SOCKS4a and SOCKS5 (TCP and UDP) on one
//! port, and the socks inbound with more than one user.

#![cfg(all(
    feature = "inbound-mixed",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-drop",
))]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use base64::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

/// An inbound of `protocol` that knows alice and bob and, with `bob_only`,
/// lets only bob through, so that the user's name has to reach routing.
fn server(protocol: &str, port: u16, users: bool, bob_only: bool) -> String {
    let users = if users {
        r#", "users": [
            { "username": "alice", "password": "alice-pass" },
            { "username": "bob", "password": "bob-pass" }
        ]"#
    } else {
        ""
    };
    let route = if bob_only {
        r#", "route": {
            "rules": [{ "auth_user": ["bob"], "outbound": "direct" }],
            "final": "block"
        }"#
    } else {
        ""
    };
    format!(
        r#"{{
            "inbounds": [{{
                "type": "{protocol}",
                "listen": "127.0.0.1",
                "listen_port": {port}
                {users}
            }}],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "block" }}
            ]
            {route}
        }}"#
    )
}

/// Runs `configs`, then `check` against a TCP echo server, and shuts the
/// instances down.
fn with_instances<F, Fut>(configs: Vec<String>, check: F) -> anyhow::Result<()>
where
    F: FnOnce(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (echo, echo_fut) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    let echo_task = rt.spawn(echo_fut);
    let ids = common::run_sail_instances(&rt, configs)?;
    let result = rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        check(echo).await
    });
    echo_task.abort();
    for id in ids {
        sail::shutdown(id);
    }
    result
}

/// Writes `data` to `stream` and expects it back.
async fn expect_echo(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
) -> anyhow::Result<()> {
    let data = b"mixed echo";
    stream.write_all(data).await?;
    let mut back = [0u8; 10];
    timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await??;
    anyhow::ensure!(&back == data, "echo mismatch");
    Ok(())
}

/// Reads an HTTP response head off `stream`.
async fn read_head(stream: &mut TcpStream) -> anyhow::Result<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let b = timeout(Duration::from_secs(5), stream.read_u8()).await??;
        head.push(b);
        anyhow::ensure!(head.len() < 8192, "response head too long");
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// `CONNECT`s through the HTTP proxy at `port` to `echo` as `credentials`,
/// returning the answer's head and the stream.
async fn http_connect(
    port: u16,
    echo: SocketAddr,
    credentials: Option<&str>,
) -> anyhow::Result<(String, TcpStream)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let authorization = credentials
        .map(|c| {
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                BASE64_STANDARD.encode(c)
            )
        })
        .unwrap_or_default();
    stream
        .write_all(
            format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n{authorization}\r\n").as_bytes(),
        )
        .await?;
    let head = read_head(&mut stream).await?;
    Ok((head, stream))
}

async fn socks_stream(
    port: u16,
    echo: SocketAddr,
    user: Option<(&str, &str)>,
) -> anyhow::Result<sail::adapter::AnyStream> {
    let sess = Session {
        destination: SocksAddr::from(echo),
        ..Default::default()
    };
    timeout(
        Duration::from_secs(5),
        common::new_socks_stream(
            "127.0.0.1",
            port,
            &sess,
            user.map(|u| u.0.to_string()),
            user.map(|u| u.1.to_string()),
        ),
    )
    .await?
}

// HTTP CONNECT, SOCKS5 and a proxied plain HTTP request on one port, with
// bob, the second user, the only one routing lets through.
#[test]
fn test_mixed_http_and_socks5_tcp() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        with_instances(
            vec![server("mixed", port, true, true)],
            move |echo| async move {
                // HTTP as bob.
                let (head, mut stream) = http_connect(port, echo, Some("bob:bob-pass")).await?;
                anyhow::ensure!(head.starts_with("HTTP/1.1 200"), "answered {:?}", head);
                expect_echo(&mut stream).await?;

                // HTTP without credentials, or wrong ones.
                for credentials in [None, Some("bob:alice-pass")] {
                    let (head, _) = http_connect(port, echo, credentials).await?;
                    anyhow::ensure!(
                        head.starts_with("HTTP/1.1 407 ")
                            && head.contains("Proxy-Authenticate: Basic realm="),
                        "answered {:?}",
                        head
                    );
                }

                // SOCKS5 as bob.
                let mut stream = socks_stream(port, echo, Some(("bob", "bob-pass"))).await?;
                expect_echo(&mut stream).await?;

                // SOCKS5 with a wrong password, and without credentials.
                anyhow::ensure!(
                    socks_stream(port, echo, Some(("bob", "alice-pass")))
                        .await
                        .is_err(),
                    "socks5 with a wrong password got in"
                );
                anyhow::ensure!(
                    socks_stream(port, echo, None).await.is_err(),
                    "socks5 without credentials got in"
                );

                // alice authenticates, and routing, which sees her name, blocks her.
                let (head, mut stream) = http_connect(port, echo, Some("alice:alice-pass")).await?;
                anyhow::ensure!(head.starts_with("HTTP/1.1 200"), "answered {:?}", head);
                anyhow::ensure!(
                    expect_echo(&mut stream).await.is_err(),
                    "alice was routed through"
                );
                Ok(())
            },
        )
    })
}

// A plain HTTP request in absolute form reaches the origin in origin form,
// without the headers meant for the proxy.
#[test]
fn test_mixed_http_forward() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        with_instances(
            vec![server("mixed", port, true, false)],
            move |_| async move {
                let origin = TcpListener::bind("127.0.0.1:0").await?;
                let origin_addr = origin.local_addr()?;
                let serve = tokio::spawn(async move {
                    let (mut stream, _) = origin.accept().await?;
                    let head = read_head(&mut stream).await?;
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await?;
                    anyhow::Ok(head)
                });

                let mut client = TcpStream::connect(("127.0.0.1", port)).await?;
                client
                    .write_all(
                        format!(
                            "GET http://{origin_addr}/path?q=1 HTTP/1.1\r\nHost: {origin_addr}\r\n\
                     Proxy-Authorization: Basic {}\r\nProxy-Connection: keep-alive\r\n\r\n",
                            BASE64_STANDARD.encode("alice:alice-pass")
                        )
                        .as_bytes(),
                    )
                    .await?;
                let answer = read_head(&mut client).await?;
                anyhow::ensure!(
                    answer.starts_with("HTTP/1.1 200 OK"),
                    "answered {:?}",
                    answer
                );

                let request = timeout(Duration::from_secs(5), serve).await???;
                anyhow::ensure!(
                    request.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
                    "origin got {:?}",
                    request
                );
                anyhow::ensure!(
                    !request.to_ascii_lowercase().contains("proxy-"),
                    "origin got the proxy's headers: {:?}",
                    request
                );
                Ok(())
            },
        )
    })
}

// SOCKS5 TCP and UDP ASSOCIATE through the mixed port, as bob.
#[test]
fn test_mixed_socks5_tcp_and_udp() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        common::test_configs_with_auth(
            vec![server("mixed", port, true, false)],
            "127.0.0.1",
            port,
            Some("bob".into()),
            Some("bob-pass".into()),
        )
    })
}

// SOCKS4a through the mixed port, which takes it only without users.
#[test]
fn test_mixed_socks4a() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [port, port2] = common::free_ports();
        let configs = vec![
            server("mixed", port, false, false),
            server("mixed", port2, true, false),
        ];
        with_instances(configs, move |echo| async move {
            let socks4a = |port: u16| async move {
                let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
                let mut request = vec![0x04, 0x01];
                request.extend_from_slice(&echo.port().to_be_bytes());
                request.extend_from_slice(&[0, 0, 0, 1]);
                request.extend_from_slice(b"user\0127.0.0.1\0");
                stream.write_all(&request).await?;
                let mut reply = [0u8; 8];
                timeout(Duration::from_secs(5), stream.read_exact(&mut reply)).await??;
                anyhow::Ok((reply[1], stream))
            };
            let (status, mut stream) = socks4a(port).await?;
            anyhow::ensure!(status == 90, "socks4a refused: {}", status);
            expect_echo(&mut stream).await?;

            let (status, _) = socks4a(port2).await?;
            anyhow::ensure!(status == 91, "socks4a let in with users set: {}", status);
            Ok(())
        })
    })
}

// The socks inbound with two users: the second authenticates, and its name
// reaches routing.
#[test]
fn test_socks_second_user() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        with_instances(
            vec![server("socks", port, true, true)],
            move |echo| async move {
                let mut stream = socks_stream(port, echo, Some(("bob", "bob-pass"))).await?;
                expect_echo(&mut stream).await?;

                anyhow::ensure!(
                    socks_stream(port, echo, Some(("bob", "alice-pass")))
                        .await
                        .is_err(),
                    "a wrong password got in"
                );

                // alice authenticates, and routing blocks her by name.
                let mut stream = socks_stream(port, echo, Some(("alice", "alice-pass"))).await?;
                anyhow::ensure!(
                    expect_echo(&mut stream).await.is_err(),
                    "alice was routed through"
                );
                Ok(())
            },
        )
    })
}
