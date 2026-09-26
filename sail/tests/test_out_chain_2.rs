mod common;

// app(socks) -> (socks)client(chain(shadowsocks+shadowsocks)) -> (shadowsocks)server1(direct) -> (shadowsocks)server2(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
    feature = "outbound-chain",
))]
#[test]
fn test_out_chain_2() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port, port1, port2] = common::free_ports();
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
                    "tag": "proxy",
                    "server": "127.0.0.1",
                    "server_port": port2,
                    "method": "aes-128-gcm",
                    "password": "password",
                    "detour": "proxy/1"
                },
                {
                    "type": "shadowsocks",
                    "tag": "proxy/1",
                    "server": "127.0.0.1",
                    "server_port": port1,
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
                    "listen_port": port1,
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

        let config3 = serde_json::json!({
            "inbounds": [
                {
                    "type": "shadowsocks",
                    "listen": "127.0.0.1",
                    "listen_port": port2,
                    "method": "aes-128-gcm",
                    "password": "password"
                }
            ],
            "outbounds": [
                {
                    "type": "direct"
                }
            ]
        });

        let configs = vec![
            config1.to_string(),
            config2.to_string(),
            config3.to_string(),
        ];
        common::test_configs(configs, "127.0.0.1", socks_port)
    })
}
