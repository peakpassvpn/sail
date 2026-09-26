mod common;

// app(socks) -> (socks)client(shadowsocks) -> (shadowsocks)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
))]
#[test]
fn test_shadowsocks() -> anyhow::Result<()> {
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
                    "type": "shadowsocks",
                    "server": "127.0.0.1",
                    "server_port": server_port,
                    "method": "chacha20-ietf-poly1305",
                    "password": "password"
                }
            ]
        });

        let config2 = serde_json::json!({
            "inbounds": [
                {
                    "type": "shadowsocks",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
                    "method": "chacha20-ietf-poly1305",
                    "password": "password"
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
