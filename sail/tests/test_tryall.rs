mod common;

// app(socks) -> (socks)client(tryall(shadowsocks)) -> (shadowsocks)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
    feature = "outbound-tryall",
))]
#[test]
fn test_tryall() -> anyhow::Result<()> {
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
                    "type": "tryall",
                    "outbounds": [
                        "ss_out"
                    ]
                },
                {
                    "type": "shadowsocks",
                    "tag": "ss_out",
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
        common::test_configs(configs, "127.0.0.1", socks_port)
    })
}
