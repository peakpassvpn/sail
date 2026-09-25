mod common;

// app(socks) -> (socks)client(static(shadowsocks)) -> (shadowsocks)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
    feature = "outbound-static",
))]
#[test]
fn test_static() -> anyhow::Result<()> {
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
                "type": "static",
                "outbounds": [
                    "ss_out"
                ],
                "method": "rr"
            },
            {
                "type": "shadowsocks",
                "tag": "ss_out",
                "server": "127.0.0.1",
                "server_port": 23001,
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
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1086
            }
        ],
        "outbounds": [
            {
                "type": "static",
                "outbounds": [
                    "ss_out"
                ],
                "method": "random"
            },
            {
                "type": "shadowsocks",
                "tag": "ss_out",
                "server": "127.0.0.1",
                "server_port": 23001,
                "method": "chacha20-ietf-poly1305",
                "password": "password"
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
                "listen_port": 23001,
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

    let configs = vec![config1.to_string(), config3.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)?;
    let configs = vec![config2.to_string(), config3.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086)
}
