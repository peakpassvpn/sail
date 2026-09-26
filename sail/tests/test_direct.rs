mod common;

// app(socks) -> (socks)client(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
))]
#[test]
fn test_direct() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port] = common::free_ports();
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
                    "type": "direct"
                }
            ]
        });

        let configs = vec![config1.to_string()];
        common::test_configs(configs, "127.0.0.1", socks_port)
    })
}
