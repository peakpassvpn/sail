mod common;

// app(socks) -> (socks)client(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
))]
#[test]
fn test_socks() -> anyhow::Result<()> {
    let config_server = r#"
    {
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1116
            }
        ],
        "outbounds": [
            {
                "type": "direct"
            }
        ]
    }
    "#;

    let config_client = r#"
    {
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1119
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "server": "127.0.0.1",
                "server_port": 1116
            }
        ]
    }
    "#;

    let configs = vec![config_server.to_string(), config_client.to_string()];
    common::test_configs(configs, "127.0.0.1", 1119)
}

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
))]
#[test]
fn test_socks_auth() -> anyhow::Result<()> {
    let config_server = r#"
    {
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1127,
                "users": [
                    {
                        "username": "user",
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

    let config_client = r#"
    {
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1128
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "server": "127.0.0.1",
                "server_port": 1127,
                "username": "user",
                "password": "password"
            }
        ]
    }
    "#;

    let configs = vec![config_server.to_string(), config_client.to_string()];
    common::test_configs(configs, "127.0.0.1", 1128)
}
