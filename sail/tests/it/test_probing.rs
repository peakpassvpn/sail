//! What an active prober learns of an inbound, and what a flood of
//! connections that never authenticate costs it (5.6). A Shadowsocks
//! server that fails a request reads on rather than closing, so how long
//! it takes to close tells no header's length; an inbound has so many
//! connections in their handshake at once, and closes one more.
#![cfg(all(feature = "inbound-shadowsocks", feature = "outbound-direct"))]

use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

/// The handshake deadline the instance runs with: short, so that a test
/// waits it out quickly.
const DEADLINE: Duration = Duration::from_secs(2);

fn start(config: serde_json::Value) -> Result<sail::RuntimeId> {
    start_with(config, &[("inbound.handshake_timeout", "2s")])
}

/// Starts `config` with the runtime options `set`.
fn start_with(config: serde_json::Value, set: &[(&str, &str)]) -> Result<sail::RuntimeId> {
    let id = common::next_rt_id();
    let mut runtime = common::runtime_options();
    for (key, value) in set {
        runtime.set(key, value)?;
    }
    let config = sail::config::from_string(&config.to_string())?;
    let opts = sail::StartOptions {
        config: sail::Config::Internal(Box::new(config)),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime,
        host: Default::default(),
    };
    common::start_instance(id, opts)?;
    Ok(id)
}

/// How long the server takes to close a connection that sends `garbage`,
/// from before it connects: the server's deadline runs from its accept,
/// which is no earlier.
async fn closed_after(port: u16, garbage: &[u8]) -> Result<Duration> {
    let sent = Instant::now();
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    // The server may close before it has taken it all.
    let _ = s.write_all(garbage).await;
    let mut buf = [0u8; 64];
    loop {
        match tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await? {
            Ok(0) | Err(_) => return Ok(sent.elapsed()),
            Ok(_) => {}
        }
    }
}

fn random(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

#[test]
fn a_shadowsocks_server_closes_a_bad_request_at_no_telling_length() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, ports) = common::retry_port_clash(|| {
        let [ss2022, legacy] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [
                { "type": "shadowsocks", "tag": "ss2022", "listen": "127.0.0.1",
                  "listen_port": ss2022, "method": "2022-blake3-aes-128-gcm",
                  "password": "AAECAwQFBgcICQoLDA0ODw==" },
                { "type": "shadowsocks", "tag": "legacy", "listen": "127.0.0.1",
                  "listen_port": legacy, "method": "aes-128-gcm", "password": "p" },
            ],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((vec![start(config)?], [ss2022, legacy]))
    })?;
    let result = rt.block_on(async {
        // Shorter than, as long as, and longer than each header, all at
        // once: the close comes at the deadline whatever the length.
        let lengths = [1usize, 16, 32, 48, 60, 100, 200];
        let short = ports.iter().flat_map(|port| {
            lengths.iter().map(move |n| async move {
                let took = closed_after(*port, &random(*n)).await?;
                ensure!(
                    took >= DEADLINE - Duration::from_millis(50),
                    "port {port}: {n} bytes closed after {took:?}, before the deadline"
                );
                anyhow::Ok(())
            })
        });
        // What is read of it is bounded: well past the limit (and what
        // the server had read ahead before it failed), it is closed.
        let long = ports.iter().map(|port| async move {
            let took = closed_after(*port, &random(256 * 1024)).await?;
            ensure!(
                took < DEADLINE - Duration::from_millis(500),
                "port {port}: more than the read limit was read on for {took:?}"
            );
            anyhow::Ok(())
        });
        let (short, long) = tokio::join!(
            futures::future::try_join_all(short),
            futures::future::try_join_all(long)
        );
        short?;
        long?;
        anyhow::Ok(())
    });
    for id in ids {
        sail::shutdown(id);
    }
    result
}

/// Whether the server closes `stream` within `within`.
#[cfg(feature = "inbound-socks")]
async fn closed_within(stream: &mut tokio::net::TcpStream, within: Duration) -> bool {
    let closed = async {
        let mut buf = [0u8; 16];
        // What it says before it closes, a refusal, is read past.
        while !matches!(stream.read(&mut buf).await, Ok(0) | Err(_)) {}
    };
    tokio::time::timeout(within, closed).await.is_ok()
}

/// A SOCKS5 client past its greeting, with no authentication.
#[cfg(feature = "inbound-socks")]
async fn socks_greeted(port: u16) -> Result<tokio::net::TcpStream> {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut reply)).await??;
    ensure!(reply == [5, 0], "greeting answered {:?}", reply);
    Ok(s)
}

/// Asks the SOCKS5 server to connect to `target`.
#[cfg(feature = "inbound-socks")]
async fn socks_connect(s: &mut tokio::net::TcpStream, target: std::net::SocketAddr) -> Result<()> {
    let std::net::SocketAddr::V4(target) = target else {
        anyhow::bail!("an IPv4 target");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&request).await?;
    Ok(())
}

/// A connection holds its inbound's handshake place until it has a place
/// among the sessions, and no longer: one waiting for a session's place
/// still counts against the handshakes, and one that has it does not.
#[cfg(feature = "inbound-socks")]
#[test]
fn a_connection_is_counted_among_the_handshakes_until_it_is_a_session() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (id, port) = common::retry_port_clash(|| {
        let port = common::free_port();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
        });
        let id = start_with(
            config,
            &[
                ("inbound.max_handshakes", "1"),
                ("inbound.max_connections", "1"),
            ],
        )?;
        Ok((id, port))
    })?;
    let result = rt.block_on(async {
        let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        let serve = tokio::spawn(serve);
        // B has the one place among the sessions, and has given back the
        // one among the handshakes: A gets in.
        let mut b = socks_greeted(port).await?;
        socks_connect(&mut b, echo).await?;
        let mut reply = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(3), b.read_exact(&mut reply)).await??;
        ensure!(reply[1] == 0, "B was refused: {:?}", reply);
        let mut a = socks_greeted(port).await?;
        // A waits for a session's place (`MAX_CONNECTIONS_WAIT`, 1 s),
        // which B holds: it holds the handshake place meanwhile, so C is
        // closed at once.
        socks_connect(&mut a, echo).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let refused = Instant::now();
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        ensure!(
            closed_within(&mut c, Duration::from_millis(400)).await,
            "one more than the handshakes allowed was let in while another waited for a session"
        );
        // How long a refusal at the cap takes here: what the check that D
        // is not refused waits by.
        let refusal = refused.elapsed();
        // A is refused a session's place; the handshake place is free
        // again, and D is let in.
        ensure!(
            closed_within(&mut a, Duration::from_secs(3)).await,
            "A was given a second session's place"
        );
        let mut d = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        ensure!(
            !closed_within(&mut d, Duration::from_millis(500).max(refusal * 10)).await,
            "the handshake place was not given back"
        );
        drop(b);
        serve.abort();
        anyhow::Ok(())
    });
    sail::shutdown(id);
    result
}
