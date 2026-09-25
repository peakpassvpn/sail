mod common;

// app(socks) -> (socks)client(chain(tls+trojan)) -> (chain(tls+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-tls",
    feature = "outbound-trojan",
    feature = "inbound-tls",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_tls_trojan() -> anyhow::Result<()> {
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
                "type": "trojan",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": 23001,
                "password": "password",
                "tls": {
                    "enabled": true,
                    "server_name": "localhost",
                    "certificate_path": "cert.pem"
                }
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "type": "trojan",
                "listen": "127.0.0.1",
                "listen_port": 23001,
                "users": [
                    {
                        "password": "password"
                    }
                ],
                "tls": {
                    "enabled": true,
                    "certificate_path": "cert.pem",
                    "key_path": "key.pem"
                }
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
                "type": "trojan",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": 23002,
                "password": "password",
                "tls": {
                    "enabled": true,
                    "server_name": "localhost",
                    "certificate_path": "cert.pem"
                }
            }
        ]
    }
    "#;

    let config4 = r#"
    {
        "inbounds": [
            {
                "type": "trojan",
                "listen": "127.0.0.1",
                "listen_port": 23002,
                "users": [
                    {
                        "password": "password"
                    }
                ],
                "tls": {
                    "enabled": true,
                    "certificate_path": "cert.pem",
                    "key_path": "key.pem"
                }
            }
        ],
        "outbounds": [
            {
                "type": "direct"
            }
        ]
    }
    "#;

    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| anyhow::anyhow!("generate cert failed: {}", e))?;
    std::fs::write(path.join("key.der"), key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("write key.der failed: {}", e))?;
    std::fs::write(path.join("cert.der"), cert.der())
        .map_err(|e| anyhow::anyhow!("write cert.der failed: {}", e))?;
    std::fs::write(path.join("key.pem"), key_pair.serialize_pem())
        .map_err(|e| anyhow::anyhow!("write key.pem failed: {}", e))?;
    std::fs::write(path.join("cert.pem"), cert.pem())
        .map_err(|e| anyhow::anyhow!("write cert.pem failed: {}", e))?;
    let cert_pem = cert.pem();
    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)?;

    let configs = vec![config3.to_string(), config4.to_string()];
    common::test_configs(configs, "127.0.0.1", 1087)?;

    let config5 = format!(
        r#"
[Certificate.mycert]
{cert_pem}
[General]
socks-interface = 127.0.0.1
socks-port = 1088
[Proxy]
Proxy = trojan, 127.0.0.1, 23003, password=password, sni=localhost, tls=true, tls-cert=mycert
[Rule]
FINAL,Proxy
"#,
        cert_pem = cert_pem
    );
    let config6 = r#"
    {
        "inbounds": [
            {
                "type": "trojan",
                "listen": "127.0.0.1",
                "listen_port": 23003,
                "users": [
                    {
                        "password": "password"
                    }
                ],
                "tls": {
                    "enabled": true,
                    "certificate_path": "cert.pem",
                    "key_path": "key.pem"
                }
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
    common::test_configs(configs, "127.0.0.1", 1088)
}
