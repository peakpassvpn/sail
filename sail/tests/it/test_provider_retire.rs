#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// A member a provider's refresh removes leaves nothing running once its
// connections close: the members that keep state of their own in the
// background, a Hysteria2 one and a TUIC one (their QUIC endpoints and
// connections) and a sing-mux one (its mux connections and their
// drivers).
//
// The client runs on a current-thread runtime of its own, so that the
// tasks alive on it are its own: the provider starts with a member that
// spawns nothing, the refresh adds the one under test, and once that is
// removed again and its connections are closed, no more tasks are alive
// than before it came. What it held outside the runtime goes too: the
// server sees its connections close, or its socket can be bound again.

#[cfg(all(
    feature = "outbound-provider",
    feature = "outbound-select",
    feature = "outbound-direct",
    any(
        all(feature = "inbound-hysteria2", feature = "outbound-hysteria2"),
        all(feature = "inbound-tuic", feature = "outbound-tuic"),
        all(
            feature = "mux",
            feature = "inbound-shadowsocks",
            feature = "outbound-shadowsocks"
        )
    )
))]
mod harness {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{anyhow, ensure, Result};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Instant};

    use sail::session::{Session, SocksAddr};

    use super::common;

    /// What shows, from outside the client, that the member was used and
    /// that what it held is gone.
    pub trait Evidence {
        fn used(&self) -> bool;
        /// Why not, while it is not.
        fn freed(&self) -> Result<(), String>;
        /// Whether a stream open through the member goes on after it is
        /// retired, until it is closed.
        fn in_flight_survives(&self) -> bool {
            false
        }
    }

    /// The echo servers the member's connections go to: TCP and UDP.
    pub struct Echo {
        pub tcp: SocketAddr,
        pub udp: SocketAddr,
    }

    impl Echo {
        pub fn start(rt: &tokio::runtime::Runtime) -> Result<Self> {
            let (tcp, tcp_echo) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
            let (udp, udp_echo) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
            rt.spawn(tcp_echo);
            rt.spawn(udp_echo);
            Ok(Echo { tcp, udp })
        }
    }

    fn alive() -> usize {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    }

    /// Runs the client with a local provider that holds `keep`, a direct
    /// member, then `member` too (named `X`, and selected), then `keep`
    /// alone again; through `X`, a TCP stream and a UDP session to `echo`
    /// open across the refresh that removes it.
    pub fn member_retired(member: &str, echo: &Echo, evidence: &dyn Evidence) -> Result<()> {
        let dir = common::TempDir::new("provider-retire")?;
        let proxies = dir.join("proxies.yaml");
        let keep = "  - { name: keep, type: direct }\n";
        let write =
            |members: &[&str]| std::fs::write(&proxies, format!("proxies:\n{}", members.concat()));
        write(&[keep])?;
        let config = format!(
            r#"{{
                "outbounds": [
                    {{ "type": "selector", "tag": "pick", "providers": "sub", "default": "X" }},
                    {{ "type": "direct" }}
                ],
                "outbound_providers": [{{
                    "type": "local", "tag": "sub", "path": "{}", "update_interval": "1s"
                }}]
            }}"#,
            crate::common::json_path(&proxies)
        );
        let config = sail::config::from_string(&config)?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(common::scoped(async {
            let dial = Arc::new(sail::net::DialDefaults::new(&config.route)?);
            let env = Arc::new(sail::runtime::RuntimeEnv {
                options: common::runtime_options(),
                ..Default::default()
            });
            let instance = sail::app::instance::Instance::build(&config, env, dial)?;
            // What refreshes the provider, every second, and stops the
            // tasks of the members it retires.
            let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
            let (shutdown_tx, _shutdown_rx) = tokio::sync::mpsc::channel(1);
            #[cfg(feature = "inbound-tun")]
            let (network_change_tx, _network_change_rx) = tokio::sync::mpsc::channel(1);
            let manager = sail::RuntimeManager::new(
                #[cfg(feature = "auto-reload")]
                0,
                None,
                #[cfg(feature = "auto-reload")]
                false,
                reload_tx,
                shutdown_tx,
                #[cfg(feature = "inbound-tun")]
                network_change_tx,
                &instance,
            );
            let members_become = |expected: &'static [&'static str]| {
                let manager = manager.clone();
                async move {
                    let deadline = Instant::now() + Duration::from_secs(10);
                    loop {
                        let now = manager
                            .get_outbound_selects("pick")
                            .await
                            .map_err(|e| anyhow!("{}", e))?;
                        if now == expected {
                            return anyhow::Ok(());
                        }
                        ensure!(
                            Instant::now() < deadline,
                            "members {:?}, not {:?}",
                            now,
                            expected
                        );
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            };

            members_become(&["keep"]).await?;
            let before = alive();

            write(&[keep, member])?;
            members_become(&["keep", "X"]).await?;
            let selected = manager
                .get_outbound_selected("pick")
                .await
                .map_err(|e| anyhow!("{}", e))?;
            ensure!(selected == "X", "{} selected", selected);

            let to = |destination: SocketAddr| Session {
                destination: SocksAddr::from(destination),
                ..Default::default()
            };
            let mut stream = timeout(
                Duration::from_secs(10),
                instance.dispatcher.stream_via("pick", to(echo.tcp)),
            )
            .await??;
            timeout(Duration::from_secs(10), async {
                stream.write_all(b"ping").await?;
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
                ensure!(&buf == b"ping", "echoed {:?}", buf);
                anyhow::Ok(())
            })
            .await??;
            let datagram = timeout(
                Duration::from_secs(10),
                instance.dispatcher.datagram_via("pick", to(echo.udp)),
            )
            .await??;
            let (mut recv, mut send) = datagram.split();
            timeout(Duration::from_secs(10), async {
                send.send_to(b"pong", &SocksAddr::from(echo.udp)).await?;
                let mut buf = [0u8; 16];
                let (n, _) = recv.recv_from(&mut buf).await?;
                ensure!(&buf[..n] == b"pong", "echoed {:?}", &buf[..n]);
                anyhow::Ok(())
            })
            .await??;
            ensure!(evidence.used(), "the connections went another way");
            let using = alive();
            ensure!(
                using > before,
                "{} tasks alive while X is used, {} before it came",
                using,
                before
            );

            write(&[keep])?;
            members_become(&["keep"]).await?;
            if evidence.in_flight_survives() {
                // Past the check that stops what the retired held.
                tokio::time::sleep(Duration::from_millis(1500)).await;
                timeout(Duration::from_secs(10), async {
                    stream.write_all(b"still").await?;
                    let mut buf = [0u8; 5];
                    stream.read_exact(&mut buf).await?;
                    ensure!(&buf == b"still", "echoed {:?}", buf);
                    anyhow::Ok(())
                })
                .await
                .map_err(|_| anyhow!("the stream in flight stalled once X was retired"))?
                .map_err(|e| anyhow!("the stream in flight failed once X was retired: {}", e))?;
                ensure!(
                    evidence.freed().is_err(),
                    "X's connection closed under a stream still in flight"
                );
            }
            drop((stream, recv, send));

            // The retired are checked on every second.
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let now = alive();
                let freed = evidence.freed();
                if now <= before && freed.is_ok() {
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "X gone and its connections closed: {} tasks alive, {} before it came \
                     ({} while it was used); {}",
                    now,
                    before,
                    using,
                    freed.err().unwrap_or_else(|| "its state freed".into())
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            anyhow::Ok(())
        }))
    }
}

/// A UDP relay in front of a QUIC server, which learns the address the
/// client's endpoint sends from: the socket that, once closed, can be
/// bound again.
#[cfg(all(
    feature = "outbound-provider",
    feature = "outbound-select",
    feature = "outbound-direct",
    any(
        all(feature = "inbound-hysteria2", feature = "outbound-hysteria2"),
        all(feature = "inbound-tuic", feature = "outbound-tuic")
    )
))]
mod quic_relay {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use super::harness;

    /// Relays between the client and the server, and learns the address
    /// the client's endpoint sends from.
    pub struct UdpRelay {
        client: Arc<Mutex<Option<SocketAddr>>>,
    }

    impl harness::Evidence for UdpRelay {
        fn used(&self) -> bool {
            self.client.lock().unwrap().is_some()
        }

        fn freed(&self) -> Result<(), String> {
            let Some(client) = *self.client.lock().unwrap() else {
                return Err("no client".into());
            };
            // Bound only once the endpoint's socket is closed.
            std::net::UdpSocket::bind(client)
                .map(drop)
                .map_err(|_| format!("its endpoint's socket {} still bound", client))
        }
    }

    pub async fn relay(server: SocketAddr) -> anyhow::Result<(u16, UdpRelay)> {
        let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
        let back = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
        back.connect(server).await?;
        let port = front.local_addr()?.port();
        let client = Arc::new(Mutex::new(None));
        let seen = client.clone();
        let (f, b) = (front.clone(), back.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, from) = crate::common::recv_past_errors(&f, &mut buf).await;
                *seen.lock().unwrap() = Some(from);
                let _ = b.send(&buf[..n]).await;
            }
        });
        let learnt = client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                // A client gone refuses what is sent it; the next may be new.
                let Ok(n) = back.recv(&mut buf).await else {
                    continue;
                };
                let to = *learnt.lock().unwrap();
                if let Some(to) = to {
                    let _ = front.send_to(&buf[..n], to).await;
                }
            }
        });
        Ok((port, UdpRelay { client }))
    }
}

/// The Hysteria2 member's QUIC connection and endpoint: its tasks stop,
/// and its socket is closed.
#[cfg(all(
    feature = "outbound-provider",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2"
))]
#[test]
fn a_hysteria2_member_retired_leaves_nothing_running() -> anyhow::Result<()> {
    use std::net::SocketAddr;

    use serde_json::json;

    use quic_relay::relay;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let servers = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let echo = harness::Echo::start(&servers)?;
    common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let server = json!({
            "inbounds": [{
                "type": "hysteria2",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{ "name": "alice", "password": "hy2" }],
                "tls": {
                    "enabled": true,
                    "certificate": cert.cert.pem(),
                    "key": cert.key_pair.serialize_pem(),
                },
            }],
            "outbounds": [{ "type": "direct" }],
        });
        let ids = common::run_sail_instances(&servers, vec![server.to_string()])?;
        let result = (|| {
            let (relay_port, relay) =
                servers.block_on(relay(SocketAddr::from(([127, 0, 0, 1], port))))?;
            let member = format!(
                "  - {{ name: X, type: hysteria2, server: 127.0.0.1, port: {}, password: hy2, \
                 sni: localhost, skip-cert-verify: true }}\n",
                relay_port
            );
            harness::member_retired(&member, &echo, &relay)
        })();
        common::shutdown_instances(&servers, ids);
        result
    })
}

/// The TUIC member's QUIC connection and endpoint, in either UDP relay
/// mode: its tasks (heartbeats, datagrams, the server's streams) stop, and
/// its socket is closed.
#[cfg(all(
    feature = "outbound-provider",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-tuic",
    feature = "outbound-tuic"
))]
#[test]
fn a_tuic_member_retired_leaves_nothing_running() -> anyhow::Result<()> {
    use std::net::SocketAddr;

    use serde_json::json;

    use quic_relay::relay;

    const UUID: &str = "2dd61d93-75d8-4da4-ac0e-6aece7eac365";

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let servers = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let echo = harness::Echo::start(&servers)?;
    for mode in ["native", "quic"] {
        common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let server = json!({
                "inbounds": [{
                    "type": "tuic",
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "users": [{ "name": "alice", "uuid": UUID, "password": "tuic" }],
                    "tls": {
                        "enabled": true,
                        "certificate": cert.cert.pem(),
                        "key": cert.key_pair.serialize_pem(),
                    },
                }],
                "outbounds": [{ "type": "direct" }],
            });
            let ids = common::run_sail_instances(&servers, vec![server.to_string()])?;
            let result = (|| {
                let (relay_port, relay) =
                    servers.block_on(relay(SocketAddr::from(([127, 0, 0, 1], port))))?;
                let member = format!(
                    "  - {{ name: X, type: tuic, server: 127.0.0.1, port: {}, uuid: {}, \
                     password: tuic, sni: localhost, skip-cert-verify: true, \
                     udp-relay-mode: {} }}\n",
                    relay_port, UUID, mode
                );
                harness::member_retired(&member, &echo, &relay)
            })()
            .map_err(|e| anyhow::anyhow!("{}: {:#}", mode, e));
            common::shutdown_instances(&servers, ids);
            result
        })?;
    }
    Ok(())
}

/// A sing-mux member, framed (smux, yamux) and over HTTP/2 (h2mux): a
/// stream open through it goes on after it is retired, and once that is
/// closed its connections' drivers and its idle check stop, and the server
/// sees its connections close.
#[cfg(all(
    feature = "outbound-provider",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "mux",
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks"
))]
#[test]
fn a_mux_member_retired_leaves_nothing_running() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use serde_json::json;

    const METHOD: &str = "2022-blake3-aes-128-gcm";
    const KEY: &str = "a8C5QncIl9HvTmenrEb7aw==";

    /// Forwards to the server, counting the connections made and those
    /// still open.
    struct TcpRelay {
        made: Arc<AtomicUsize>,
        open: Arc<AtomicUsize>,
    }

    impl harness::Evidence for TcpRelay {
        fn used(&self) -> bool {
            self.made.load(Ordering::SeqCst) > 0
        }

        fn freed(&self) -> Result<(), String> {
            match self.open.load(Ordering::SeqCst) {
                0 => Ok(()),
                n => Err(format!("{} of its connections open", n)),
            }
        }

        fn in_flight_survives(&self) -> bool {
            true
        }
    }

    async fn relay(server: u16) -> anyhow::Result<(u16, TcpRelay)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let made = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicUsize::new(0));
        let (m, o) = (made.clone(), open.clone());
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                m.fetch_add(1, Ordering::SeqCst);
                o.fetch_add(1, Ordering::SeqCst);
                let o = o.clone();
                tokio::spawn(async move {
                    if let Ok(mut outbound) =
                        tokio::net::TcpStream::connect(("127.0.0.1", server)).await
                    {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                    o.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Ok((port, TcpRelay { made, open }))
    }

    let servers = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let echo = harness::Echo::start(&servers)?;
    for protocol in ["smux", "yamux", "h2mux"] {
        common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let server = json!({
                "inbounds": [{
                    "type": "shadowsocks",
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "method": METHOD,
                    "password": KEY,
                    "multiplex": { "enabled": true },
                }],
                "outbounds": [{ "type": "direct" }],
            });
            let ids = common::run_sail_instances(&servers, vec![server.to_string()])?;
            let result = (|| {
                let (relay_port, relay) = servers.block_on(relay(port))?;
                let member = format!(
                    "  - {{ name: X, type: ss, server: 127.0.0.1, port: {}, cipher: {}, \
                     password: \"{}\", smux: {{ enabled: true, protocol: {} }} }}\n",
                    relay_port, METHOD, KEY, protocol
                );
                harness::member_retired(&member, &echo, &relay)
            })()
            .map_err(|e| anyhow::anyhow!("{}: {:#}", protocol, e));
            common::shutdown_instances(&servers, ids);
            result
        })?;
    }
    Ok(())
}
