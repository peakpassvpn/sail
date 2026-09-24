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
    let config1 = r#"
    {
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1086
            }
        ],
        "outbounds": [
            {
                "type": "chain",
                "outbounds": [
                    "quic",
                    "trojan"
                ]
            },
            {
                "type": "quic",
                "tag": "quic",
                "server": "127.0.0.1",
                "server_port": 3001,
                "server_name": "localhost",
                "certificate": "cert.der",
                "alpn": [
                    "http/1.1",
                    "trojan"
                ]
            },
            {
                "type": "trojan",
                "tag": "trojan",
                "password": "password"
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "type": "chain",
                "tag": "quic-in",
                "listen": "127.0.0.1",
                "listen_port": 3001,
                "inbounds": [
                    "quic",
                    "trojan"
                ]
            },
            {
                "type": "quic",
                "tag": "quic",
                "certificate": "cert.der",
                "certificate_key": "key.der",
                "alpn": [
                    "http/1.1",
                    "trojan"
                ]
            },
            {
                "type": "trojan",
                "tag": "trojan",
                "users": [
                    {
                        "password": "password"
                    }
                ]
            }
        ],
        "outbounds": [
            {
                "type": "direct"
            }
        ]
    }
    "#;

    let config3 = r#"
    {
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1087
            }
        ],
        "outbounds": [
            {
                "type": "chain",
                "outbounds": [
                    "quic",
                    "trojan"
                ]
            },
            {
                "type": "quic",
                "tag": "quic",
                "server": "127.0.0.1",
                "server_port": 3002,
                "server_name": "localhost",
                "certificate": "cert.pem"
            },
            {
                "type": "trojan",
                "tag": "trojan",
                "password": "password"
            }
        ]
    }
    "#;

    let config4 = r#"
    {
        "inbounds": [
            {
                "type": "chain",
                "tag": "quic-in",
                "listen": "127.0.0.1",
                "listen_port": 3002,
                "inbounds": [
                    "quic",
                    "trojan"
                ]
            },
            {
                "type": "quic",
                "tag": "quic",
                "certificate": "cert.pem",
                "certificate_key": "key.pem"
            },
            {
                "type": "trojan",
                "tag": "trojan",
                "users": [
                    {
                        "password": "password"
                    }
                ]
            }
        ],
        "outbounds": [
            {
                "type": "direct"
            }
        ]
    }
    "#;

    std::env::set_var("TCP_DOWNLINK_TIMEOUT", "3");
    std::env::set_var("TCP_UPLINK_TIMEOUT", "3");

    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| anyhow::anyhow!("generate cert failed: {}", e))?;
    std::fs::write(&path.join("key.der"), &key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("write key.der failed: {}", e))?;
    std::fs::write(&path.join("cert.der"), &cert.der().to_vec())
        .map_err(|e| anyhow::anyhow!("write cert.der failed: {}", e))?;
    std::fs::write(&path.join("key.pem"), &key_pair.serialize_pem())
        .map_err(|e| anyhow::anyhow!("write key.pem failed: {}", e))?;
    std::fs::write(&path.join("cert.pem"), &cert.pem())
        .map_err(|e| anyhow::anyhow!("write cert.pem failed: {}", e))?;
    let cert_pem = cert.pem();

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1086)?;
    common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", 1086)?;
    common::test_data_transfering_reliability_on_configs(configs.clone(), "127.0.0.1", 1086)?;

    let configs = vec![config3.to_string(), config4.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1087)?;

    let config5 = format!(
        r#"
[Certificate.mycert]
{cert_pem}
[General]
socks-interface = 127.0.0.1
socks-port = 1089
[Proxy]
Proxy = trojan, 127.0.0.1, 3004, password=password, sni=localhost, quic=true, tls-cert=mycert
[Rule]
FINAL,Proxy
"#,
        cert_pem = cert_pem
    );
    let config6 = r#"
    {
        "inbounds": [
            {
                "type": "chain",
                "tag": "quic-in",
                "listen": "127.0.0.1",
                "listen_port": 3004,
                "inbounds": [
                    "quic",
                    "trojan"
                ]
            },
            {
                "type": "quic",
                "tag": "quic",
                "certificate": "cert.pem",
                "certificate_key": "key.pem",
                "alpn": [
                    "http/1.1"
                ]
            },
            {
                "type": "trojan",
                "tag": "trojan",
                "users": [
                    {
                        "password": "password"
                    }
                ]
            }
        ],
        "outbounds": [
            {
                "type": "direct"
            }
        ]
    }
    "#;
    let configs = vec![config5, config6.to_string()];
    common::test_configs(configs, "127.0.0.1", 1089)
}
