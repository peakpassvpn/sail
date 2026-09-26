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
    // The certificate and key, as files of this test's own.
    let dir = common::TempDir::new("tls-trojan")?;
    // A client with a socks inbound on `socks_port` and a trojan outbound
    // to `trojan_port`.
    let client = |socks_port: u16, trojan_port: u16| {
        serde_json::json!({
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
                    "server_port": trojan_port,
                    "password": "password",
                    "tls": {
                        "enabled": true,
                        "server_name": "localhost",
                        "certificate_path": dir.join("cert.pem")
                    }
                }
            ]
        })
        .to_string()
    };

    // A trojan server on `trojan_port`.
    let server = |trojan_port: u16| {
        serde_json::json!({
            "inbounds": [
                {
                    "type": "trojan",
                    "listen": "127.0.0.1",
                    "listen_port": trojan_port,
                    "users": [
                        {
                            "password": "password"
                        }
                    ],
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
        })
        .to_string()
    };

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| anyhow::anyhow!("generate cert failed: {}", e))?;
    std::fs::write(dir.join("key.der"), key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("write key.der failed: {}", e))?;
    std::fs::write(dir.join("cert.der"), cert.der())
        .map_err(|e| anyhow::anyhow!("write cert.der failed: {}", e))?;
    std::fs::write(dir.join("key.pem"), key_pair.serialize_pem())
        .map_err(|e| anyhow::anyhow!("write key.pem failed: {}", e))?;
    std::fs::write(dir.join("cert.pem"), cert.pem())
        .map_err(|e| anyhow::anyhow!("write cert.pem failed: {}", e))?;
    let cert_pem = cert.pem();
    common::retry_port_clash(|| {
        let [socks_port, trojan_port] = common::free_ports();
        let configs = vec![client(socks_port, trojan_port), server(trojan_port)];
        common::test_configs(configs, "127.0.0.1", socks_port)
    })?;

    common::retry_port_clash(|| {
        let [socks_port, trojan_port] = common::free_ports();
        let configs = vec![client(socks_port, trojan_port), server(trojan_port)];
        common::test_configs(configs, "127.0.0.1", socks_port)
    })?;

    common::retry_port_clash(|| {
        let [socks_port, trojan_port] = common::free_ports();
        let config5 = format!(
            r#"
[Certificate.mycert]
{cert_pem}
[General]
socks-interface = 127.0.0.1
socks-port = {socks_port}
[Proxy]
Proxy = trojan, 127.0.0.1, {trojan_port}, password=password, sni=localhost, tls=true, tls-cert=mycert
[Rule]
FINAL,Proxy
"#
        );
        let configs = vec![config5, server(trojan_port)];
        common::test_configs(configs, "127.0.0.1", socks_port)
    })
}
