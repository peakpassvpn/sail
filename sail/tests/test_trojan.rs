mod common;

// app(socks) -> (socks)client(trojan) -> (trojan)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-trojan",
    feature = "inbound-trojan",
    feature = "outbound-direct",
))]
#[test]
fn test_trojan() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port, trojan_port] = common::free_ports();
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
                    "server": "127.0.0.1",
                    "server_port": trojan_port,
                    "password": "password2"
                }
            ]
        });

        let config2 = serde_json::json!({
            "inbounds": [
                {
                    "type": "trojan",
                    "listen": "127.0.0.1",
                    "listen_port": trojan_port,
                    "users": [
                        {
                            "password": "password"
                        },
                        {
                            "password": "password2"
                        }
                    ]
                }
            ],
            "outbounds": [
                {
                    "type": "direct"
                }
            ]
        });

        let configs = vec![config1.to_string(), config2.to_string()];
        common::test_configs(configs, "127.0.0.1", socks_port)
    })
}
