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
    let config1 = r#"
    {
        "log": {
            "level": "trace"
        },
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
                "server_port": 3001,
                "password": "password",
                "transport": {
                    "type": "ws",
                    "path": "/leaf"
                }
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "log": {
            "level": "trace"
        },
        "inbounds": [
            {
                "type": "trojan",
                "listen": "127.0.0.1",
                "listen_port": 3001,
                "users": [
                    {
                        "password": "password"
                    }
                ],
                "transport": {
                    "type": "ws",
                    "path": "/leaf"
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)
}
