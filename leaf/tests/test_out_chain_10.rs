mod common;

// app(socks) -> (socks)client(chain(chain(amux(ws)+trojan)+shadowsocks)) -> (chain(amux(ws)+trojan))server1(direct) -> (shadowsocks)server2(direct) -> echo
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
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks",
))]
#[test]
fn test_out_chain_10() -> anyhow::Result<()> {
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
                "tag": "out",
                "outbounds": [
                    "chain-amux-ws-trojan",
                    "shadowsocks"
                ]
            },
            {
                "type": "chain",
                "tag": "chain-amux-ws-trojan",
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
            },
            {
                "type": "shadowsocks",
                "tag": "shadowsocks",
                "server": "127.0.0.1",
                "server_port": 3002,
                "method": "chacha20-ietf-poly1305",
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
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": 3001,
                "inbounds": [
                    "amux",
                    "trojan"
                ]
            },
            {
                "type": "ws",
                "tag": "ws",
                "path": "/leaf"
            },
            {
                "type": "amux",
                "tag": "amux",
                "inbounds": [
                    "ws"
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
                "type": "shadowsocks",
                "listen": "127.0.0.1",
                "listen_port": 3002,
                "method": "chacha20-ietf-poly1305",
                "password": "password"
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
