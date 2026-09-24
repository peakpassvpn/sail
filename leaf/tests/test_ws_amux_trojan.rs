mod common;

// app(socks) -> (socks)client(chain(amux(ws)+trojan)) -> (chain(amux(ws)+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "outbound-amux",
    feature = "outbound-trojan",
    feature = "inbound-ws",
    feature = "inbound-amux",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_ws_amux_trojan() -> anyhow::Result<()> {
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
                    "amux",
                    "trojan"
                ]
            },
            {
                "type": "amux",
                "tag": "amux",
                "outbounds": [
                    "ws"
                ],
                "server": "127.0.0.1",
                "server_port": 3001,
                "max_accepts": 16,
                "concurrency": 1
            },
            {
                "type": "ws",
                "tag": "ws",
                "path": "/leaf"
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
                "listen": "127.0.0.1",
                "listen_port": 3001,
                "inbounds": [
                    "amux",
                    "trojan"
                ]
            },
            {
                "type": "amux",
                "tag": "amux",
                "inbounds": [
                    "ws"
                ]
            },
            {
                "type": "ws",
                "tag": "ws",
                "path": "/leaf"
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)
}
