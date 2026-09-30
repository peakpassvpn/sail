#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-drop",
    feature = "outbound-network-group"
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Whether `stream` relays a message to the echo server and back.
async fn echoes(stream: &mut sail::adapter::AnyStream) -> bool {
    let message = b"network";
    if stream.write_all(message).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 7];
    matches!(
        timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await,
        Ok(Ok(_))
    ) && &buf == message
}

/// A connection through sail's SOCKS inbound on `port` to `echo`; none
/// when sail refuses it.
async fn connect(port: u16, echo: SocketAddr) -> Option<sail::adapter::AnyStream> {
    let sess = sail::session::Session {
        destination: sail::session::SocksAddr::from(echo),
        ..Default::default()
    };
    common::new_socks_stream("127.0.0.1", port, &sess, None, None)
        .await
        .ok()
}

/// Whether a new connection through sail reaches the echo server.
async fn reaches(port: u16, echo: SocketAddr) -> bool {
    match connect(port, echo).await {
        Some(mut stream) => echoes(&mut stream).await,
        None => false,
    }
}

// app(socks) -> sail(route by the network the host is on: a rule, then a
// network group) -> direct or block -> echo
#[test]
fn connections_go_the_way_the_network_calls_for() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [
                { "type": "network", "tag": "Scene",
                  "branches": [{ "wifi_ssid": "Cafe", "outbound": "BLOCK" }],
                  "default": "DIRECT" },
                { "type": "direct", "tag": "DIRECT" },
                { "type": "block", "tag": "BLOCK" }
            ],
            "route": {
                "rules": [{ "network_type": "cellular", "action": "reject" }],
                "final": "Scene"
            }
        });

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let id = ids[0];
        let result = rt.block_on(async {
            let (echo, server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            tokio::spawn(server);
            tokio::time::sleep(Duration::from_millis(200)).await;

            let manager = sail::runtime_managers()
                .get(&id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no runtime manager"))?;
            anyhow::ensure!(
                manager.needs_network(),
                "the configuration needs the network"
            );

            // Nothing known of the network: the group's default.
            anyhow::ensure!(reaches(port, echo).await, "unknown network: direct");

            sail::set_network_state(id, r#"{ "type": "wifi", "ssid": "Cafe" }"#)?;
            anyhow::ensure!(!reaches(port, echo).await, "at the cafe: blocked");

            sail::set_network_state(id, r#"{ "type": "wifi", "ssid": "Home" }"#)?;
            let mut open = connect(port, echo)
                .await
                .ok_or_else(|| anyhow::anyhow!("at home: refused"))?;
            anyhow::ensure!(echoes(&mut open).await, "at home: direct");

            // Another access point of the same network: a roam, which the
            // connection open survives.
            sail::set_network_state(id, r#"{ "type": "wifi", "ssid": "Home 5G" }"#)?;
            anyhow::ensure!(
                echoes(&mut open).await,
                "the connection open survives a roam"
            );

            // On cellular the rule rejects new connections, and the one
            // open, made on the network before, is closed (2.12).
            sail::set_network_state(id, r#"{ "type": "cellular", "mcc_mnc": "46001" }"#)?;
            anyhow::ensure!(!reaches(port, echo).await, "on cellular: rejected");
            anyhow::ensure!(
                !echoes(&mut open).await,
                "the connection open before the change is closed"
            );
            anyhow::Ok(())
        });
        for id in ids {
            assert!(sail::shutdown(id));
        }
        result
    })
}
