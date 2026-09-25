mod common;

// app(socks) -> (socks)client(chain(ws+trojan+shadowsocks)) -> (chain(ws+trojan))server1(direct) -> (shadowsocks)server2(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "outbound-trojan",
    feature = "inbound-ws",
    feature = "inbound-trojan",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_out_chain_6() -> anyhow::Result<()> {
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
                "type": "shadowsocks",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": 23002,
                "method": "aes-128-gcm",
                "password": "password",
                "detour": "proxy/1"
            },
            {
                "type": "trojan",
                "tag": "proxy/1",
                "server": "127.0.0.1",
                "server_port": 23001,
                "password": "password",
                "transport": {
                    "type": "ws",
                    "path": "/sail"
                }
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "type": "trojan",
                "tag": "server1",
                "listen": "127.0.0.1",
                "listen_port": 23001,
                "users": [
                    {
                        "password": "password"
                    }
                ],
                "transport": {
                    "type": "ws",
                    "path": "/sail"
                }
            }
        ],
        "outbounds": [
            {
                "type": "direct"
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
                "listen_port": 23002,
                "method": "aes-128-gcm",
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

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 1086)
}
