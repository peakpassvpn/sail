//! The users of a running instance, as a host manages them: their traffic,
//! their limits, disconnecting them, and adding them to or taking them out
//! of an inbound.
#![cfg(all(feature = "inbound-trojan", feature = "outbound-direct"))]
use crate::common;

use std::time::Duration;

use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A Trojan connection to `echo` through the inbound on `port`, with
/// `password`, that has echoed "ping"; `None` if it was refused.
async fn connect(port: u16, password: &str, echo: std::net::SocketAddr) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    let mut request = hex::encode(Sha224::digest(password.as_bytes())).into_bytes();
    request.extend_from_slice(b"\r\n\x01");
    sail::session::SocksAddr::from(echo)
        .write_buf(&mut request, sail::session::SocksAddrWireType::PortLast);
    request.extend_from_slice(b"\r\nping");
    stream.write_all(&request).await.ok()?;
    let mut buf = [0u8; 4];
    match tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) if &buf == b"ping" => Some(stream),
        _ => None,
    }
}

/// Whether `stream` was closed by the instance.
async fn closed(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

#[test]
fn users_are_managed_while_running() -> anyhow::Result<()> {
    common::retry_port_clash(|| users_are_managed(common::free_port()))
}

fn users_are_managed(port: u16) -> anyhow::Result<()> {
    let config = serde_json::json!({
        "inbounds": [{ "type": "trojan", "tag": "t", "listen": "127.0.0.1", "listen_port": port,
                       "users": [{ "name": "alice", "password": "a" }] }],
        "outbounds": [{ "type": "direct" }]
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
    let result = rt.block_on(async {
        let (echo, server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(server);
        let manager = sail::RUNTIME_MANAGER
            .lock()
            .unwrap()
            .get(&ids[0])
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("the instance is not running"))?;
        let mut events = manager.user_events();

        let alice = manager.user("alice")?.expect("alice");
        assert_eq!(alice.inbounds, ["t"]);
        let mut first = connect(port, "a", echo).await.expect("alice connects");

        // Traffic, read and cleared as ssm-api reads it.
        let traffic = manager.read_traffic(true);
        let (_, counts) = traffic.users.iter().find(|(n, _)| n == "alice").unwrap();
        assert_eq!((counts.up, counts.down, counts.tcp), (4, 4, 1));
        let traffic = manager.read_traffic(false);
        let (_, counts) = traffic.users.iter().find(|(n, _)| n == "alice").unwrap();
        assert_eq!((counts.up, counts.down), (0, 0));
        assert_eq!(manager.user("alice")?.unwrap().traffic.up, 4);

        // Limits changed while running.
        manager.set_user_limits(
            "alice",
            sail::user::Limits {
                max_connections: Some(1),
                ..Default::default()
            },
        )?;
        assert!(connect(port, "a", echo).await.is_none(), "one at most");

        // Disconnected, and let in again.
        assert_eq!(manager.disconnect_user("alice")?, 1);
        assert!(closed(&mut first).await);
        let mut again = connect(port, "a", echo).await.expect("alice again");

        // Taken out of the inbound: disconnected and refused; another
        // added.
        manager
            .add_user("t", serde_json::json!({ "name": "bob", "password": "b" }))
            .await?;
        assert!(manager.remove_user("t", "alice").await?);
        assert!(!manager.remove_user("t", "alice").await?);
        assert!(closed(&mut again).await);
        assert!(connect(port, "a", echo).await.is_none());
        assert!(connect(port, "b", echo).await.is_some());
        assert_eq!(manager.user("bob")?.unwrap().inbounds, ["t"]);
        assert_eq!(
            events.recv().await?,
            sail::user::UserEvent::Removed {
                user: "alice".into(),
                inbound: "t".into()
            }
        );
        assert!(manager.disconnect_user("carol").is_err());
        Ok::<_, anyhow::Error>(())
    });
    common::shutdown_instances(&rt, ids);
    result
}
