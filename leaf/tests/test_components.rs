mod common;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

fn outbound(json: serde_json::Value) -> leaf::config::Outbound {
    serde_json::from_value(json).unwrap()
}

fn inbound(json: serde_json::Value) -> leaf::config::Inbound {
    serde_json::from_value(json).unwrap()
}

/// Whether a connection through the socks inbound on `port` reaches the
/// echo server.
async fn relayed(port: u16, sess: &leaf::session::Session) -> bool {
    let Ok(mut stream) = common::new_socks_stream("127.0.0.1", port, sess, None, None).await else {
        return false;
    };
    if stream.write_all(b"ping").await.is_err() {
        return false;
    }
    let mut buf = [0u8; 4];
    matches!(
        timeout(Duration::from_secs(2), stream.read(&mut buf)).await,
        Ok(Ok(4))
    ) && &buf == b"ping"
}

// Outbounds and inbounds added to and removed from a running instance.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-failover"
))]
#[test]
fn components_are_added_and_removed_while_running() -> anyhow::Result<()> {
    let config = r#"
    {
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": 1089 }],
        "outbounds": [{ "type": "direct" }, { "type": "direct", "tag": "routed" }],
        "route": { "rules": [{ "domain": ["example.com"], "outbound": "routed" }] }
    }
    "#;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ids = common::run_leaf_instances(&rt, vec![config.to_string()])?;
    let id = ids[0];

    // Fails with an error rather than a panic, so that the instance is shut
    // down either way.
    let result = rt.block_on(async {
        let (echo_addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(echo);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let manager = leaf::RUNTIME_MANAGER
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("the instance is not running"))?;
        let sess = leaf::session::Session {
            destination: leaf::session::SocksAddr::from(echo_addr),
            ..Default::default()
        };

        // Inbounds.
        anyhow::ensure!(!relayed(1090, &sess).await, "nothing listens on 1090 yet");
        manager
            .add_inbound(inbound(serde_json::json!({
                "type": "socks", "tag": "extra", "listen": "127.0.0.1", "listen_port": 1090
            })))
            .await?;
        anyhow::ensure!(relayed(1090, &sess).await, "the added inbound serves");
        let taken = manager
            .add_inbound(inbound(serde_json::json!({
                "type": "socks", "tag": "again", "listen": "127.0.0.1", "listen_port": 1090
            })))
            .await;
        anyhow::ensure!(taken.is_err(), "a port in use fails the add");
        manager.remove_inbound("extra").await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        anyhow::ensure!(!relayed(1090, &sess).await, "the removed inbound stops");
        anyhow::ensure!(relayed(1089, &sess).await, "the others go on");

        // Outbounds.
        manager
            .add_outbound(outbound(serde_json::json!({
                "type": "failover", "tag": "group", "outbounds": ["direct"]
            })))
            .await?;
        let err = manager.remove_outbound("direct").await.unwrap_err();
        anyhow::ensure!(
            err.to_string().contains("[group] is built on it"),
            "an outbound another is built on stays: {}",
            err
        );
        let err = manager.remove_outbound("routed").await.unwrap_err();
        anyhow::ensure!(
            err.to_string().contains("the routing uses it"),
            "an outbound the routing uses stays: {}",
            err
        );
        manager.remove_outbound("group").await?;
        let err = manager.remove_outbound("group").await.unwrap_err();
        anyhow::ensure!(err.to_string().contains("does not exist"), "{}", err);
        anyhow::Ok(())
    });
    for id in ids {
        assert!(leaf::shutdown(id));
    }
    result
}
