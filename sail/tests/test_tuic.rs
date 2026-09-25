mod common;

// TUIC between two sail instances, and against sing-box in both directions:
//
//   app(socks) -> sail(socks -> tuic) -> sail|sing-box(tuic -> direct) -> echo
//   app(socks) -> sing-box(socks -> tuic) -> sail(tuic -> direct) -> echo
//
// The sing-box tests need `sing-box` on PATH (or SING_BOX set to it) and
// are ignored by default: run them with `--ignored`.
//
// Ports: 32300-32399 only.

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-tuic",
    feature = "inbound-tuic",
    feature = "outbound-direct",
))]
mod tuic {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    use super::common;

    const UUID: &str = "2dd61d93-75d8-4da4-ac0e-6aece7eac365";
    const PASSWORD: &str = "tuic-password";

    struct Cert {
        pem: String,
        key_pem: String,
        dir: PathBuf,
    }

    impl Cert {
        fn new(name: &str) -> anyhow::Result<Self> {
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let dir = std::env::temp_dir().join(format!(
                "sail-test-tuic-{}-{}",
                name,
                std::process::id()
            ));
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("cert.pem"), cert.pem())?;
            std::fs::write(dir.join("key.pem"), key_pair.serialize_pem())?;
            Ok(Self {
                pem: cert.pem(),
                key_pem: key_pair.serialize_pem(),
                dir,
            })
        }

        fn cert_path(&self) -> String {
            self.dir.join("cert.pem").to_string_lossy().into_owned()
        }

        fn key_path(&self) -> String {
            self.dir.join("key.pem").to_string_lossy().into_owned()
        }
    }

    impl Drop for Cert {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn sail_client(socks_port: u16, server_port: u16, cert: &Cert, extra: &str) -> String {
        serde_json::json!({
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
            "outbounds": [serde_json::from_str::<serde_json::Value>(&format!(
                r#"{{
                    "type": "tuic",
                    "tag": "proxy",
                    "server": "127.0.0.1",
                    "server_port": {server_port},
                    "uuid": "{UUID}",
                    "password": "{PASSWORD}",
                    {extra}
                    "tls": {{"enabled": true, "server_name": "localhost", "alpn": ["h3"], "certificate": {pem}}}
                }}"#,
                pem = serde_json::to_string(&cert.pem).unwrap(),
            ))
            .unwrap()]
        })
        .to_string()
    }

    fn sail_server(server_port: u16, cert: &Cert, extra: &str) -> String {
        serde_json::json!({
            "inbounds": [serde_json::from_str::<serde_json::Value>(&format!(
                r#"{{
                    "type": "tuic",
                    "tag": "tuic-in",
                    "listen": "127.0.0.1",
                    "listen_port": {server_port},
                    "users": [{{"name": "alice", "uuid": "{UUID}", "password": "{PASSWORD}"}}],
                    {extra}
                    "tls": {{"enabled": true, "alpn": ["h3"], "certificate": {pem}, "key": {key}}}
                }}"#,
                pem = serde_json::to_string(&cert.pem).unwrap(),
                key = serde_json::to_string(&cert.key_pem).unwrap(),
            ))
            .unwrap()],
            "outbounds": [{"type": "direct"}]
        })
        .to_string()
    }

    /// A UDP echo server taking packets of any size.
    async fn run_big_udp_echo_server(
    ) -> anyhow::Result<(SocketAddr, impl std::future::Future<Output = ()>)> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        Ok((addr, async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], from).await;
            }
        }))
    }

    /// UDP packets up to the 2 KiB sail relays by default, larger than a
    /// QUIC datagram, which `native` mode must fragment, and a TCP transfer of some size, through the socks inbound
    /// at `socks_port`. The instances in `configs` run meanwhile.
    fn check_large_transfers(configs: Vec<String>, socks_port: u16) -> anyhow::Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (udp_addr, udp_echo) = rt.block_on(run_big_udp_echo_server())?;
        let (tcp_addr, tcp_echo) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
        let udp_echo = rt.spawn(udp_echo);
        let tcp_echo = rt.spawn(tcp_echo);
        let ids = common::run_sail_instances(&rt, configs)?;
        let result = rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let mut sess = sail::session::Session {
                destination: sail::session::SocksAddr::Ip(udp_addr),
                ..Default::default()
            };
            let dgram =
                common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None).await?;
            let (mut r, mut s) = dgram.split();
            for size in [1, 1000, 1400, 2000] {
                let msg: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
                // Fragments may be lost even on loopback; try a few times.
                let mut echoed = false;
                for _ in 0..3 {
                    s.send_to(&msg, &sess.destination).await?;
                    let mut buf = vec![0u8; 65536];
                    if let Ok(got) = timeout(Duration::from_secs(2), r.recv_from(&mut buf)).await {
                        let (n, from) = got?;
                        anyhow::ensure!(buf[..n] == msg[..], "{}-byte packet corrupted", size);
                        anyhow::ensure!(from == sess.destination, "reply from {}", from);
                        echoed = true;
                        break;
                    }
                }
                anyhow::ensure!(echoed, "{}-byte packet never echoed", size);
            }

            sess.destination = sail::session::SocksAddr::Ip(tcp_addr);
            let mut stream =
                common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None).await?;
            let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 253) as u8).collect();
            let (mut rd, mut wr) = tokio::io::split(stream.as_mut());
            let write = async {
                wr.write_all(&data).await?;
                wr.flush().await?;
                anyhow::Ok(())
            };
            let read = async {
                let mut got = vec![0u8; data.len()];
                rd.read_exact(&mut got).await?;
                anyhow::ensure!(got == data, "stream corrupted");
                anyhow::Ok(())
            };
            timeout(Duration::from_secs(20), async {
                tokio::try_join!(write, read)
            })
            .await??;
            anyhow::Ok(())
        });
        for id in ids {
            sail::shutdown(id);
        }
        udp_echo.abort();
        tcp_echo.abort();
        result
    }

    #[test]
    fn test_tuic_sail_to_sail() -> anyhow::Result<()> {
        let cert = Cert::new("sail")?;
        let native = vec![
            sail_client(32301, 32300, &cert, r#""congestion_control": "bbr","#),
            sail_server(32300, &cert, r#""congestion_control": "bbr","#),
        ];
        common::test_configs(native.clone(), "127.0.0.1", 32301)?;
        check_large_transfers(native, 32301)?;

        let quic = vec![
            sail_client(
                32303,
                32302,
                &cert,
                r#""udp_relay_mode": "quic", "zero_rtt_handshake": true, "heartbeat": "1s","#,
            ),
            sail_server(
                32302,
                &cert,
                r#""zero_rtt_handshake": true, "congestion_control": "new_reno","#,
            ),
        ];
        common::test_configs(quic.clone(), "127.0.0.1", 32303)?;
        check_large_transfers(quic, 32303)?;
        Ok(())
    }

    #[test]
    fn test_tuic_wrong_password_is_refused() -> anyhow::Result<()> {
        let cert = Cert::new("refused")?;
        let client = sail_client(32305, 32304, &cert, "").replace(PASSWORD, "wrong");
        let configs = vec![client, sail_server(32304, &cert, "")];
        anyhow::ensure!(
            common::test_configs(configs, "127.0.0.1", 32305).is_err(),
            "a wrong password got through"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // sing-box
    // -----------------------------------------------------------------------

    struct SingBox {
        child: Child,
        _dir: tempdir::Dir,
    }

    mod tempdir {
        pub struct Dir(pub std::path::PathBuf);
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    impl SingBox {
        /// Runs sing-box with `config`, waiting for `ready_tcp_port` to
        /// listen when there is one.
        fn start(
            name: &str,
            config: serde_json::Value,
            ready_tcp_port: Option<u16>,
        ) -> anyhow::Result<Self> {
            let dir = std::env::temp_dir().join(format!(
                "sail-test-tuic-singbox-{}-{}",
                name,
                std::process::id()
            ));
            std::fs::create_dir_all(&dir)?;
            let path = dir.join("config.json");
            std::fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
            let bin = std::env::var("SING_BOX").unwrap_or_else(|_| {
                if std::path::Path::new("/opt/homebrew/bin/sing-box").exists() {
                    "/opt/homebrew/bin/sing-box".to_string()
                } else {
                    "sing-box".to_string()
                }
            });
            let child = Command::new(bin)
                .arg("run")
                .arg("-c")
                .arg(&path)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| anyhow::anyhow!("run sing-box failed: {}", e))?;
            let mut sing_box = SingBox {
                child,
                _dir: tempdir::Dir(dir),
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = sing_box.child.try_wait()? {
                    anyhow::bail!("sing-box exited: {}", status);
                }
                let ready = match ready_tcp_port {
                    Some(port) => std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(),
                    // A UDP listener cannot be probed; give it a moment.
                    None => {
                        std::thread::sleep(Duration::from_millis(500));
                        true
                    }
                };
                if ready {
                    return Ok(sing_box);
                }
                anyhow::ensure!(
                    std::time::Instant::now() < deadline,
                    "sing-box did not start"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    impl Drop for SingBox {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn sing_box_server(port: u16, cert: &Cert, congestion: &str) -> serde_json::Value {
        serde_json::json!({
            "log": {"level": "warn"},
            "inbounds": [{
                "type": "tuic",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"name": "alice", "uuid": UUID, "password": PASSWORD}],
                "congestion_control": congestion,
                "tls": {
                    "enabled": true,
                    "alpn": ["h3"],
                    "certificate_path": cert.cert_path(),
                    "key_path": cert.key_path()
                }
            }],
            "outbounds": [{"type": "direct"}]
        })
    }

    fn sing_box_client(
        socks_port: u16,
        server_port: u16,
        cert: &Cert,
        mode: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
            "outbounds": [{
                "type": "tuic",
                "server": "127.0.0.1",
                "server_port": server_port,
                "uuid": UUID,
                "password": PASSWORD,
                "udp_relay_mode": mode,
                "tls": {
                    "enabled": true,
                    "server_name": "localhost",
                    "alpn": ["h3"],
                    "certificate_path": cert.cert_path()
                }
            }]
        })
    }

    #[test]
    #[ignore = "needs sing-box"]
    fn test_tuic_sail_outbound_to_sing_box_inbound() -> anyhow::Result<()> {
        let cert = Cert::new("to-sing-box")?;
        let _server = SingBox::start("server", sing_box_server(32310, &cert, "cubic"), None)?;

        let native = vec![sail_client(32311, 32310, &cert, "")];
        common::test_configs(native.clone(), "127.0.0.1", 32311)?;
        check_large_transfers(native, 32311)?;

        let quic = vec![sail_client(
            32312,
            32310,
            &cert,
            r#""udp_relay_mode": "quic", "congestion_control": "bbr","#,
        )];
        common::test_configs(quic.clone(), "127.0.0.1", 32312)?;
        check_large_transfers(quic, 32312)?;
        Ok(())
    }

    #[test]
    #[ignore = "needs sing-box"]
    fn test_tuic_sing_box_outbound_to_sail_inbound() -> anyhow::Result<()> {
        let cert = Cert::new("from-sing-box")?;
        let server = vec![sail_server(32320, &cert, "")];
        for (mode, socks_port) in [("native", 32321), ("quic", 32322)] {
            // Each check starts the sail server anew, and sing-box would keep
            // using its connection to the one before until that times out:
            // a fresh sing-box for each.
            let client = |name: &str| {
                SingBox::start(
                    &format!("client-{}-{}", mode, name),
                    sing_box_client(socks_port, 32320, &cert, mode),
                    Some(socks_port),
                )
            };
            {
                let _client = client("basic")?;
                common::test_configs(server.clone(), "127.0.0.1", socks_port)
                    .map_err(|e| anyhow::anyhow!("{}: {}", mode, e))?;
            }
            {
                let _client = client("large")?;
                check_large_transfers(server.clone(), socks_port)
                    .map_err(|e| anyhow::anyhow!("{}: {}", mode, e))?;
            }
        }
        Ok(())
    }
}
