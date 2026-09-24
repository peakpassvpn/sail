mod common;

// app(socks) -> (socks)client(chain(ws+trojan)->chain(ws+trojan)) -> (chain(ws+trojan))server1(direct) -> (chain(ws+trojan))server2(direct) -> echo
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
fn test_out_chain_1() -> anyhow::Result<()> {
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
                "tag": "chain-server1-server2",
                "outbounds": [
                    "server1",
                    "server2"
                ]
            },
            {
                "type": "chain",
                "tag": "server1",
                "outbounds": [
                    "server1-ws",
                    "server1-trojan"
                ]
            },
            {
                "type": "ws",
                "tag": "server1-ws",
                "path": "/leaf"
            },
            {
                "type": "trojan",
                "tag": "server1-trojan",
                "server": "127.0.0.1",
                "server_port": 3001,
                "password": "password"
            },
            {
                "type": "chain",
                "tag": "server2",
                "outbounds": [
                    "server2-ws",
                    "server2-trojan"
                ]
            },
            {
                "type": "ws",
                "tag": "server2-ws",
                "path": "/leaf2"
            },
            {
                "type": "trojan",
                "tag": "server2-trojan",
                "server": "127.0.0.1",
                "server_port": 3002,
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
                "tag": "server1",
                "listen": "127.0.0.1",
                "listen_port": 3001,
                "inbounds": [
                    "ws",
                    "trojan"
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

    let config3 = r#"
    {
        "inbounds": [
            {
                "type": "chain",
                "tag": "server2",
                "listen": "127.0.0.1",
                "listen_port": 3002,
                "inbounds": [
                    "ws",
                    "trojan"
                ]
            },
            {
                "type": "ws",
                "tag": "ws",
                "path": "/leaf2"
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

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 1086)
}
