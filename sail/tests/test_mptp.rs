mod common;

// app(socks) -> (socks)client(mptp(direct1, direct2)) -> (mptp)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-mptp",
    feature = "inbound-mptp",
    feature = "outbound-direct",
))]
#[test]
fn test_mptp() -> anyhow::Result<()> {
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
                    "type": "mptp",
                    "outbounds": [
                        "direct1",
                        "direct2"
                    ],
                    "server": "127.0.0.1",
                    "server_port": server_port
                },
                {
                    "type": "direct",
                    "tag": "direct1"
                },
                {
                    "type": "direct",
                    "tag": "direct2"
                }
            ]
        });

        let config2 = serde_json::json!({
            "inbounds": [
                {
                    "type": "mptp",
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
