#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// app(socks) -> (socks)client(socks to proxy.sail.test) -> (socks)server(direct) -> echo
//
// The client's outbound dials a name only a hosts server knows, found as
// its `domain_resolver`, `route.default_domain_resolver` or a DNS rule for
// the outbound says.
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
))]
#[test]
fn an_outbound_s_server_resolves_as_its_resolver_says() -> anyhow::Result<()> {
    let ways = [
        (
            serde_json::json!({ "domain_resolver": "hosts" }),
            serde_json::json!({}),
            serde_json::json!({}),
        ),
        (
            serde_json::json!({}),
            serde_json::json!({ "default_domain_resolver": { "server": "hosts" } }),
            serde_json::json!({}),
        ),
        (
            serde_json::json!({}),
            serde_json::json!({}),
            serde_json::json!({ "rules": [{ "outbound": "proxy", "server": "hosts" }] }),
        ),
    ];
    // None of them: `final` is asked, and the name does not resolve.
    let none = (
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    );
    for (i, (outbound, route, dns)) in ways.into_iter().chain([none]).enumerate() {
        let result = common::retry_port_clash(|| {
            let [server_port, client_port] = common::free_ports();
            let config_server = serde_json::json!({
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": server_port }],
                "outbounds": [{ "type": "direct" }]
            });
            let mut proxy = serde_json::json!({
                "type": "socks",
                "tag": "proxy",
                "server": "proxy.sail.test",
                "server_port": server_port
            });
            for (k, v) in outbound.as_object().unwrap() {
                proxy[k] = v.clone();
            }
            let mut dns_config = serde_json::json!({
                "servers": [
                    // `final`, which cannot resolve the name.
                    { "type": "hosts", "tag": "nothing", "predefined": { "other.test": "192.0.2.1" } },
                    { "type": "hosts", "tag": "hosts",
                      "predefined": { "proxy.sail.test": "127.0.0.1" } }
                ]
            });
            for (k, v) in dns.as_object().unwrap() {
                dns_config[k] = v.clone();
            }
            let config_client = serde_json::json!({
                "dns": dns_config,
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": client_port }],
                "outbounds": [proxy],
                "route": route
            });
            let configs = vec![config_server.to_string(), config_client.to_string()];
            common::test_configs(configs, "127.0.0.1", client_port)
        });
        if i < 3 {
            result?;
        } else {
            assert!(result.is_err(), "resolved with no resolver");
        }
    }
    Ok(())
}
