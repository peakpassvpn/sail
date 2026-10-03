//! What an active prober learns of an inbound. A Shadowsocks server that
//! fails a request reads on rather than closing, so how long it takes to
//! close tells no header's length (5.6 A1).
#![cfg(all(feature = "inbound-shadowsocks", feature = "outbound-direct"))]

use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

/// The handshake deadline the instance runs with: short, so that a test
/// waits it out quickly.
const DEADLINE: Duration = Duration::from_secs(2);

fn start(config: serde_json::Value) -> Result<sail::RuntimeId> {
    let id = common::next_rt_id();
    let mut runtime = common::runtime_options();
    runtime.set("inbound.handshake_timeout", "2s")?;
    let config = sail::config::from_string(&config.to_string())?;
    let opts = sail::StartOptions {
        config: sail::Config::Internal(Box::new(config)),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime,
        host: Default::default(),
    };
    let start = std::thread::spawn(move || sail::start(id, opts));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sail::is_running(id) {
        ensure!(!start.is_finished(), "sail did not start");
        ensure!(Instant::now() < deadline, "sail did not start within 10s");
        std::thread::sleep(Duration::from_millis(10));
    }
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
