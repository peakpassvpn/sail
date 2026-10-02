#![cfg(all(feature = "inbound-socks", feature = "outbound-socks"))]

use crate::common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A SOCKS5 server that records the address each CONNECT asks for, says
/// it connected, and carries nothing.
pub(crate) async fn recording_socks_server() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let record = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let record = record.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                stream.read_exact(&mut head).await?;
                let mut methods = vec![0u8; head[1] as usize];
                stream.read_exact(&mut methods).await?;
                stream.write_all(&[5, 0]).await?;
                let mut request = [0u8; 4];
                stream.read_exact(&mut request).await?;
                let host = match request[3] {
                    1 => {
                        let mut ip = [0u8; 4];
                        stream.read_exact(&mut ip).await?;
                        std::net::Ipv4Addr::from(ip).to_string()
                    }
                    4 => {
                        let mut ip = [0u8; 16];
                        stream.read_exact(&mut ip).await?;
                        std::net::Ipv6Addr::from(ip).to_string()
                    }
                    _ => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).await?;
                        let mut name = vec![0u8; len[0] as usize];
                        stream.read_exact(&mut name).await?;
                        String::from_utf8_lossy(&name).into_owned()
                    }
                };
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                record.lock().unwrap().push(host);
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                let _ = tokio::io::copy(&mut stream, &mut tokio::io::sink()).await;
                std::io::Result::Ok(())
            });
        }
    });
    (port, asked)
}

/// What the proxy at `asked` is asked for when a client connects through
/// sail, listening for SOCKS on `port`, to `resolve.test`.
async fn asked_for(port: u16, asked: &Mutex<Vec<String>>) -> anyhow::Result<String> {
    tokio::time::sleep(Duration::from_millis(200)).await;
    let sess = sail::session::Session {
        destination: sail::session::SocksAddr::Domain("resolve.test".into(), 80),
        ..Default::default()
    };
    let _stream = common::new_socks_stream("127.0.0.1", port, &sess, None, None).await?;
    for _ in 0..50 {
        if let Some(host) = asked.lock().unwrap().first() {
            return Ok(host.clone());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("the proxy was asked for nothing")
}

// app(socks) -> sail(resolve) -> (socks)proxy
//
// As sing-box hands the addresses a `resolve` action resolved to every
// outbound (route/conn.go:101-104), a proxy's server is asked for the
// address, which the local DNS chose, not for the domain.
#[test]
fn a_resolve_action_hands_a_proxy_the_address() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (proxy_port, asked) = rt.block_on(recording_socks_server());
        let port = common::free_port();
        let config = serde_json::json!({
            "dns": { "servers": [
                { "type": "hosts", "predefined": { "resolve.test": "127.0.0.7" } }
            ] },
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "socks", "tag": "proxy",
                            "server": "127.0.0.1", "server_port": proxy_port }],
            "route": {
                "rules": [{ "action": "resolve" }],
                "final": "proxy",
            },
        });
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let result = rt.block_on(asked_for(port, &asked));
        for id in ids {
            assert!(sail::shutdown(id));
        }
        anyhow::ensure!(result? == "127.0.0.7", "{:?}", asked.lock().unwrap());
        Ok(())
    })
}

// app(socks) -> (mixed)sail, read from a Clash configuration -> (socks)proxy
//
// As in Mihomo, a rule on addresses resolves the domain to match it, and
// only a direct dial would take the address: the proxy's server is asked
// for the domain.
#[cfg(all(feature = "config-clash", feature = "inbound-mixed"))]
#[test]
fn a_clash_rule_on_addresses_leaves_a_proxy_the_domain() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (proxy_port, asked) = rt.block_on(recording_socks_server());
        let port = common::free_port();
        let yaml = format!(
            "mixed-port: {}\n\
             log-level: silent\n\
             hosts:\n  resolve.test: 127.0.0.7\n\
             proxies:\n  - {{ name: proxy, type: socks5, server: 127.0.0.1, port: {} }}\n\
             rules:\n  - IP-CIDR,127.0.0.7/32,proxy\n  - MATCH,REJECT\n",
            port, proxy_port
        );
        let ids = common::run_sail_instances(&rt, vec![yaml])?;
        let result = rt.block_on(asked_for(port, &asked));
        for id in ids {
            assert!(sail::shutdown(id));
        }
        anyhow::ensure!(result? == "resolve.test", "{:?}", asked.lock().unwrap());
        Ok(())
    })
}

// app(socks) -> sail(resolve) -> (socks)sail -> udp echo
//
// Datagrams to the domain go to the address the resolve action handed the
// proxy. Its answers come back as from the domain, or, with
// `udp_disable_domain_unmapping`, from the address, as sing-box's
// unidirectional NAT has it (route/conn.go:237-241).
#[cfg(feature = "outbound-direct")]
#[test]
fn answers_to_an_address_handed_on_come_back_as_the_option_says() -> anyhow::Result<()> {
    for disabled in [false, true] {
        let from = common::retry_port_clash(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let [port, proxy_port] = common::free_ports();
            let proxy = serde_json::json!({
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1",
                               "listen_port": proxy_port }],
                "outbounds": [{ "type": "direct" }],
            });
            let config = serde_json::json!({
                "dns": { "servers": [
                    { "type": "hosts", "predefined": { "resolve.test": "127.0.0.1" } }
                ] },
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
                "outbounds": [{ "type": "socks", "tag": "proxy",
                                "server": "127.0.0.1", "server_port": proxy_port }],
                "route": {
                    "rules": [
                        { "action": "resolve" },
                        { "action": "route-options", "udp_timeout": "30s",
                          "udp_disable_domain_unmapping": disabled },
                    ],
                    "final": "proxy",
                },
            });
            let ids = common::run_sail_instances(&rt, vec![proxy.to_string(), config.to_string()])?;
            let result = rt.block_on(async {
                let (echo_addr, echo) = common::run_udp_echo_server("127.0.0.1:0").await?;
                tokio::spawn(echo);
                tokio::time::sleep(Duration::from_millis(200)).await;
                let to = sail::session::SocksAddr::Domain("resolve.test".into(), echo_addr.port());
                let sess = sail::session::Session {
                    network: sail::session::Network::Udp,
                    destination: to.clone(),
                    ..Default::default()
                };
                let datagram =
                    common::new_socks_datagram("127.0.0.1", port, &sess, None, None).await?;
                let (mut recv, mut send) = datagram.split();
                send.send_to(b"x", &to).await?;
                let mut buf = [0u8; 16];
                let (_, from) =
                    tokio::time::timeout(Duration::from_secs(10), recv.recv_from(&mut buf))
                        .await??;
                anyhow::Ok((from, echo_addr))
            });
            for id in ids {
                assert!(sail::shutdown(id));
            }
            result
        })?;
        let (from, echo_addr) = from;
        let expected = if disabled {
            sail::session::SocksAddr::Ip(echo_addr)
        } else {
            sail::session::SocksAddr::Domain("resolve.test".into(), echo_addr.port())
        };
        anyhow::ensure!(from == expected, "disabled {}: from {}", disabled, from);
    }
    Ok(())
}
