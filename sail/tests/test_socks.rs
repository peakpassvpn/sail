mod common;

// app(socks) -> (socks)client(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
))]
#[test]
fn test_socks() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [server_port, client_port] = common::free_ports();
        let config_server = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": server_port
                }
            ],
            "outbounds": [
                {
                    "type": "direct"
                }
            ]
        });

        let config_client = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": client_port
                }
            ],
            "outbounds": [
                {
                    "type": "socks",
                    "server": "127.0.0.1",
                    "server_port": server_port
                }
            ]
        });

        let configs = vec![config_server.to_string(), config_client.to_string()];
        common::test_configs(configs, "127.0.0.1", client_port)
    })
}

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
))]
#[test]
fn test_socks_auth() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [server_port, client_port] = common::free_ports();
        let config_server = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
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
        });

        let config_client = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": client_port
                }
            ],
            "outbounds": [
                {
                    "type": "socks",
                    "server": "127.0.0.1",
                    "server_port": server_port,
                    "username": "user",
                    "password": "password"
                }
            ]
        });

        let configs = vec![config_server.to_string(), config_client.to_string()];
        common::test_configs(configs, "127.0.0.1", client_port)
    })
}
