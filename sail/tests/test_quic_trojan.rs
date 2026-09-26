mod common;

// app(socks) -> (socks)client(chain(quic+trojan)) -> (chain(quic+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-quic",
    feature = "outbound-trojan",
    feature = "inbound-quic",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_quic_trojan() -> anyhow::Result<()> {
    // The certificate and key, as files of this test's own.
    let dir = common::TempDir::new("quic-trojan")?;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| anyhow::anyhow!("generate cert failed: {}", e))?;
    std::fs::write(dir.join("key.der"), &key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("write key.der failed: {}", e))?;
    std::fs::write(dir.join("cert.der"), &cert.der().to_vec())
        .map_err(|e| anyhow::anyhow!("write cert.der failed: {}", e))?;
    std::fs::write(dir.join("key.pem"), &key_pair.serialize_pem())
        .map_err(|e| anyhow::anyhow!("write key.pem failed: {}", e))?;
    std::fs::write(dir.join("cert.pem"), &cert.pem())
        .map_err(|e| anyhow::anyhow!("write cert.pem failed: {}", e))?;
    let cert_pem = cert.pem();

    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let config1 = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": socks_port
                }
            ],
            "outbounds": [
                {
                    "type": "trojan",
                    "tag": "proxy",
                    "server": "127.0.0.1",
                    "server_port": server_port,
                    "password": "password",
                    "transport": {
                        "type": "quic"
                    },
                    "tls": {
                        "enabled": true,
                        "server_name": "localhost",
                        "alpn": [
                            "http/1.1",
                            "trojan"
                        ],
                        "certificate_path": dir.join("cert.der")
                    }
                }
            ]
        });

        let config2 = serde_json::json!({
            "inbounds": [
                {
                    "type": "trojan",
                    "tag": "quic-in",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
                    "users": [
                        {
                            "password": "password"
                        }
                    ],
                    "transport": {
                        "type": "quic"
                    },
                    "tls": {
                        "enabled": true,
                        "certificate_path": dir.join("cert.der"),
                        "key_path": dir.join("key.der"),
                        "alpn": [
                            "http/1.1",
                            "trojan"
                        ]
                    }
                }
            ],
            "outbounds": [
                {
                    "type": "direct"
                }
            ]
        });

        let configs = vec![config1.to_string(), config2.to_string()];
        common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
        common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", socks_port)?;
        common::test_data_transfering_reliability_on_configs(configs, "127.0.0.1", socks_port)
    })?;

    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let config3 = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": socks_port
                }
            ],
            "outbounds": [
                {
                    "type": "trojan",
                    "tag": "proxy",
                    "server": "127.0.0.1",
                    "server_port": server_port,
                    "password": "password",
                    "transport": {
                        "type": "quic"
                    },
                    "tls": {
                        "enabled": true,
                        "server_name": "localhost",
                        "certificate_path": dir.join("cert.pem")
                    }
                }
            ]
        });

        let config4 = serde_json::json!({
            "inbounds": [
                {
                    "type": "trojan",
                    "tag": "quic-in",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
                    "users": [
                        {
                            "password": "password"
                        }
                    ],
                    "transport": {
                        "type": "quic"
                    },
                    "tls": {
                        "enabled": true,
                        "certificate_path": dir.join("cert.pem"),
                        "key_path": dir.join("key.pem")
                    }
                }
            ],
            "outbounds": [
                {
                    "type": "direct"
                }
            ]
        });

        let configs = vec![config3.to_string(), config4.to_string()];
        common::test_configs(configs, "127.0.0.1", socks_port)
    })?;

    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let config5 = format!(
            r#"
[Certificate.mycert]
{cert_pem}
[General]
socks-interface = 127.0.0.1
socks-port = {socks_port}
[Proxy]
Proxy = trojan, 127.0.0.1, {server_port}, password=password, sni=localhost, quic=true, tls-cert=mycert
[Rule]
FINAL,Proxy
"#,
            cert_pem = cert_pem
        );
        let config6 = serde_json::json!({
            "inbounds": [
                {
                    "type": "trojan",
                    "tag": "quic-in",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
                    "users": [
                        {
                            "password": "password"
                        }
                    ],
                    "transport": {
                        "type": "quic"
                    },
                    "tls": {
                        "enabled": true,
                        "certificate_path": dir.join("cert.pem"),
                        "key_path": dir.join("key.pem"),
                        "alpn": [
                            "http/1.1"
                        ]
                    }
                }
            ],
            "outbounds": [
                {
                    "type": "direct"
                }
            ]
        });
        let configs = vec![config5, config6.to_string()];
        common::test_configs(configs, "127.0.0.1", socks_port)
    })
}
