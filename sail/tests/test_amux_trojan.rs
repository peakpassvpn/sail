mod common;

// app(socks) -> (socks)client(chain(amux(tcp)+trojan)) -> (chain(amux(tcp)+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-amux",
    feature = "outbound-trojan",
    feature = "inbound-amux",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_amux_trojan() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let config1 = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": socks_port
                }
            ],
            "outbounds": [
                {
                    "type": "trojan",
                    "tag": "proxy",
                    "server": "127.0.0.1",
                    "server_port": server_port,
                    "password": "password",
                    "multiplex": {
                        "enabled": true,
                        "protocol": "amux"
                    }
                }
            ]
        });

        let config2 = serde_json::json!({
            "inbounds": [
                {
                    "type": "trojan",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
                    "users": [
                        {
                            "password": "password"
                        }
                    ],
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
        });

        let configs = vec![config1.to_string(), config2.to_string()];
        common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
        common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", socks_port)?;
        common::test_data_transfering_reliability_on_configs(
            configs.clone(),
            "127.0.0.1",
            socks_port,
        )
    })
}
