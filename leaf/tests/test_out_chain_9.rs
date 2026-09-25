mod common;

// app(socks) -> (socks)client(chain(chain(amux(ws)+trojan)+trojan)) -> (chain(amux(ws)+trojan))server1(direct) -> (trojan)server2(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-amux",
    feature = "outbound-ws",
    feature = "outbound-trojan",
    feature = "inbound-amux",
    feature = "inbound-ws",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_out_chain_9() -> anyhow::Result<()> {
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
                "tag": "out",
                "server": "127.0.0.1",
                "server_port": 23002,
                "password": "password",
                "detour": "out/1"
            },
            {
                "type": "trojan",
                "tag": "out/1",
                "server": "127.0.0.1",
                "server_port": 23001,
                "password": "password",
                "transport": {
                    "type": "ws",
                    "path": "/leaf"
                },
                "multiplex": {
                    "enabled": true,
                    "protocol": "amux",
                    "max_accepts": 16,
                    "concurrency": 1
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
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": 23001,
                "users": [
                    {
                        "password": "password"
                    }
                ],
                "transport": {
                    "type": "ws",
                    "path": "/leaf"
                },
                "multiplex": {
                    "enabled": true,
                    "protocol": "amux"
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
                "type": "trojan",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": 23002,
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

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 1086)
}
