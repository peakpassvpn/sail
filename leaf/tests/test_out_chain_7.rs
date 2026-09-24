mod common;

// app(socks) -> (socks)client(chain(chain(ws+trojan)+shadowsocks+chain(ws+trojan))) -> (chain(ws+trojan))server1(direct) -> (shadowsocks)server2(direct) -> (chain(ws+trojan))server3(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "outbound-trojan",
    feature = "inbound-ws",
    feature = "inbound-trojan",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_out_chain_7() -> anyhow::Result<()> {
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
                    "server2",
                    "server3"
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
                "type": "shadowsocks",
                "tag": "server2",
                "server": "127.0.0.1",
                "server_port": 3002,
                "method": "aes-128-gcm",
                "password": "password"
            },
            {
                "type": "chain",
                "tag": "server3",
                "outbounds": [
                    "server3-ws",
                    "server3-trojan"
                ]
            },
            {
                "type": "ws",
                "tag": "server3-ws",
                "path": "/leaf"
            },
            {
                "type": "trojan",
                "tag": "server3-trojan",
                "server": "127.0.0.1",
                "server_port": 3003,
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
                "type": "shadowsocks",
                "listen": "127.0.0.1",
                "listen_port": 3002,
                "method": "aes-128-gcm",
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

    let config4 = r#"
    {
        "inbounds": [
            {
                "type": "chain",
                "tag": "server1",
                "listen": "127.0.0.1",
                "listen_port": 3003,
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

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
        config4.to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 1086)
}
