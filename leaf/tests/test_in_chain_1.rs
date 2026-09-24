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
fn test_in_chain_1() -> anyhow::Result<()> {
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
                "type": "chain",
                "outbounds": [
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
                "server": "127.0.0.1",
                "server_port": 3001,
                "password": "password"
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
                "type": "chain",
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)
}
