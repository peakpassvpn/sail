mod common;

// app(socks) -> (socks)client(chain(ws+trojan)) -> (chain(ws+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "outbound-trojan",
    feature = "inbound-ws",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_ws_trojan() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let config1 = serde_json::json!({
            "log": {
                "level": "trace"
            },
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
                        "type": "ws",
                        "path": "/sail"
                    }
                }
            ]
        });

        let config2 = serde_json::json!({
            "log": {
                "level": "trace"
            },
            "inbounds": [
                {
                    "type": "trojan",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
                    "users": [
                        {
                            "password": "password"
                        }
                    ],
                    "transport": {
                        "type": "ws",
                        "path": "/sail"
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
        common::test_configs(configs, "127.0.0.1", socks_port)
    })
}
