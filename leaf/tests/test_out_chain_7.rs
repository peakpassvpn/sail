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
                "type": "trojan",
                "tag": "chain-server1-server2",
                "server": "127.0.0.1",
                "server_port": 3003,
                "password": "password",
                "transport": {
                    "type": "ws",
                    "path": "/leaf"
                },
                "detour": "chain-server1-server2/2"
            },
            {
                "type": "trojan",
                "tag": "chain-server1-server2/1",
                "server": "127.0.0.1",
                "server_port": 3001,
                "password": "password",
                "transport": {
                    "type": "ws",
                    "path": "/leaf"
                }
            },
            {
                "type": "shadowsocks",
                "tag": "chain-server1-server2/2",
                "server": "127.0.0.1",
                "server_port": 3002,
                "method": "aes-128-gcm",
                "password": "password",
                "detour": "chain-server1-server2/1"
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "type": "trojan",
                "tag": "server1",
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
                "type": "trojan",
                "tag": "server1",
                "listen": "127.0.0.1",
                "listen_port": 3003,
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

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
        config4.to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 1086)
}
