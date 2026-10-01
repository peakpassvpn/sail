//! A switch of network on Linux, as root, inside the namespaces
//! tests/scripts/network_switch_netns.sh builds: the default route moves
//! from one link to the other and the old link goes down, as when a laptop
//! leaves its Wi-Fi.
//!
//! Locks 2.12's behaviour on a real switch, which the host-pushed tests
//! cannot show: sail sees the change by itself, closes the connection open
//! on the old link, and a new connection goes out of the new link (sail's
//! sockets follow the default interface) within 2 s. The 5.5 harness
//! measures how fast; this test says whether it is right.
#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// The server, behind both links.
const SERVER: &str = "10.94.255.1:7101";
/// The sail side's address on each link.
const OLD_SOURCE: &str = "10.94.0.2";
const NEW_SOURCE: &str = "10.93.0.2";
/// The longest a new connection may take to work after the switch: sail
/// looks 100 ms after the notices stop, 1 s at the latest, and the 5.5
/// harness measured 1.05 s with the 1 s it waited before (2026-10-01).
const RECOVERY: Duration = Duration::from_secs(2);

fn ip(args: &str) -> Result<()> {
    let status = Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .with_context(|| format!("ip {}", args))?;
    ensure!(status.success(), "ip {}: {}", args, status);
    Ok(())
}

/// A connection to the server through sail's SOCKS port.
async fn through_sail(socks: u16) -> Result<BufReader<TcpStream>> {
    let mut s = TcpStream::connect(("127.0.0.1", socks)).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    let addr: std::net::SocketAddrV4 = SERVER.parse()?;
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&addr.ip().octets());
    request.extend_from_slice(&addr.port().to_be_bytes());
    s.write_all(&request).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    ensure!(reply[1] == 0, "socks reply {}", reply[1]);
    Ok(BufReader::new(s))
}

/// The source address the server sees the connection from.
async fn source(conn: &mut BufReader<TcpStream>) -> Result<String> {
    conn.get_mut().write_all(b"whoami\n").await?;
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(2), conn.read_line(&mut line)).await??;
    Ok(line.trim().to_string())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root, in the namespace tests/scripts/network_switch_netns.sh builds"]
async fn a_switch_closes_the_old_link_s_connections_and_new_ones_take_the_new_link() -> Result<()> {
    ensure!(
        std::env::var_os("SAIL_SWITCH_NETNS").is_some(),
        "run through tests/scripts/network_switch_netns.sh"
    );
    let socks = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let config = format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {socks} }}],
            "outbounds": [{{ "type": "direct" }}],
            "route": {{ "auto_detect_interface": true }}
        }}"#
    );
    let id = 1200;
    let thread = std::thread::spawn(move || {
        sail::start(
            id,
            sail::StartOptions {
                config: sail::Config::Str(config),
                #[cfg(feature = "auto-reload")]
                auto_reload: false,
                runtime_opt: sail::RuntimeOption::MultiThread(2, 2 * 1024 * 1024),
                runtime: Default::default(),
                host: Default::default(),
            },
        )
    });
    let started = Instant::now();
    while TcpStream::connect(("127.0.0.1", socks)).await.is_err() {
        ensure!(
            started.elapsed() < Duration::from_secs(10),
            "sail did not start"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let checked = async {
        let mut old = through_sail(socks).await?;
        ensure!(
            source(&mut old).await? == OLD_SOURCE,
            "out of the first link"
        );

        // The switch: the default route moves, then the old link goes.
        ip("route replace default via 10.93.0.1 dev b0")?;
        ip("link set a0 down")?;
        let switched = Instant::now();

        // The connection made on the old link is closed.
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), old.read(&mut buf)).await;
        ensure!(
            matches!(read, Ok(Ok(0)) | Ok(Err(_))),
            "the old connection is closed: {:?}",
            read
        );

        // A new one goes out of the new link, soon.
        loop {
            let attempt = async {
                let mut conn = through_sail(socks).await?;
                source(&mut conn).await
            };
            match tokio::time::timeout(Duration::from_millis(500), attempt).await {
                Ok(Ok(source)) if source == NEW_SOURCE => break,
                other => ensure!(
                    switched.elapsed() < RECOVERY,
                    "no new connection out of the new link {:?} after the switch: {:?}",
                    switched.elapsed(),
                    other
                ),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        println!("recovered in {:?}", switched.elapsed());
        anyhow::Ok(())
    }
    .await;

    sail::shutdown(id);
    let _ = thread.join();
    checked
}
