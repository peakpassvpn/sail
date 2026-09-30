//! A change of network drops the connections made on the one before; a
//! roam within one network does not.

#![cfg(all(feature = "inbound-socks", feature = "outbound-direct"))]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

// socks client -> (socks)sail(direct) -> a server that holds the
// connection; the host tells sail of the network.
#[test]
fn a_move_closes_the_connections_and_a_roam_does_not() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let hold = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        anyhow::Ok(port)
    })?;
    let (ids, socks) = common::retry_port_clash(|| {
        let [socks] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [
                { "type": "socks", "listen": "127.0.0.1", "listen_port": socks }
            ],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            socks,
        ))
    })?;
    let id = ids[0];
    let network = |interface: &str, ssid: &str| {
        serde_json::json!({
            "interface": interface, "type": "wifi", "ssid": ssid,
            "gateway": "192.168.1.1", "addresses": ["192.168.1.2/24"],
        })
        .to_string()
    };
    let checked = rt.block_on(async {
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                hold,
            ))),
            ..Default::default()
        };
        sail::set_network_state(id, &network("en0", "Home"))?;
        let mut conn = common::new_socks_stream("127.0.0.1", socks, &sess, None, None).await?;
        conn.write_all(b"x").await?;
        let mut buf = [0u8; 1];
        // A roam: another access point, the same interface and addresses.
        sail::set_network_state(id, &network("en0", "Home 5G"))?;
        let read = tokio::time::timeout(Duration::from_millis(500), conn.read(&mut buf)).await;
        assert!(read.is_err(), "the connection survives a roam: {:?}", read);
        // A move: another interface.
        sail::set_network_state(id, &network("en1", "Home"))?;
        let read = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf))
            .await
            .expect("the connection is closed");
        assert!(matches!(read, Ok(0) | Err(_)), "{:?}", read);
        // A new one works on the network there is now.
        let mut conn = common::new_socks_stream("127.0.0.1", socks, &sess, None, None).await?;
        conn.write_all(b"x").await?;
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}

/// With `outbounds` and `final`, which let no connection through, a
/// connection is let through behind a captive portal, as the host says,
/// and not before or after.
fn a_portal_lets_through(outbounds: serde_json::Value, last: &str) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let server = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        anyhow::Ok(port)
    })?;
    let (ids, socks) = common::retry_port_clash(|| {
        let [socks] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [
                { "type": "socks", "listen": "127.0.0.1", "listen_port": socks }
            ],
            "outbounds": outbounds,
            "route": { "final": last },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            socks,
        ))
    })?;
    let id = ids[0];
    let checked = rt.block_on(async {
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                server,
            ))),
            ..Default::default()
        };
        let connect = || common::new_socks_stream("127.0.0.1", socks, &sess, None, None);
        let reaches = |stream: anyhow::Result<sail::adapter::AnyStream>| async move {
            let Ok(mut stream) = stream else {
                return false;
            };
            let mut buf = [0u8; 1];
            stream.write_all(b"x").await.is_ok()
                && tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf))
                    .await
                    .is_err()
        };
        // Errors, not panics: the instance is shut down whatever happens.
        anyhow::ensure!(
            !reaches(connect().await).await,
            "the rules let nothing through"
        );
        sail::set_network_state(id, r#"{ "interface": "en0", "captive": true }"#)?;
        anyhow::ensure!(reaches(connect().await).await, "direct behind the portal");
        sail::set_network_state(id, r#"{ "interface": "en0" }"#)?;
        anyhow::ensure!(!reaches(connect().await).await, "the rules again");
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}

// socks client -> (socks)sail(rules: block) -> server; behind a captive
// portal, as the host says, it goes direct whatever the rules say.
#[cfg(feature = "outbound-drop")]
#[test]
fn behind_a_captive_portal_every_connection_goes_direct() -> anyhow::Result<()> {
    a_portal_lets_through(
        serde_json::json!([{ "type": "block", "tag": "block" }]),
        "block",
    )
}

// socks client -> (socks)sail(final: the configuration's DIRECT, which
// reaches nothing) -> server: the rules take the configuration's DIRECT by
// its tag, the portal sail's own direct, which no tag names.
#[cfg(feature = "outbound-drop")]
#[test]
fn the_portal_s_direct_is_not_an_outbound_tagged_direct() -> anyhow::Result<()> {
    a_portal_lets_through(
        serde_json::json!([
            // Dialled through the block outbound: it reaches nothing.
            { "type": "direct", "tag": "DIRECT", "detour": "block" },
            { "type": "block", "tag": "block" }
        ]),
        "DIRECT",
    )
}
