mod common;

// app(socks) -> (socks)sail(route by rule-set) -> echo
//
// A rule-set holding the echo server's address makes the rule reject the
// connection; one that does not lets it through.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "rule-set"
))]
#[test]
fn a_rule_set_decides_the_route() -> anyhow::Result<()> {
    let dir = common::TempDir::new("rule-set")?;
    let file = |name: &str, cidr: &str| {
        let path = dir.join(name);
        std::fs::write(
            &path,
            serde_json::json!({ "version": 3, "rules": [{ "ip_cidr": cidr }] }).to_string(),
        )
        .unwrap();
        path
    };
    let loopback = file("loopback.json", "127.0.0.0/8");
    let elsewhere = file("elsewhere.json", "192.0.2.0/24");
    for (rule_set, rejected) in [
        (
            serde_json::json!({ "type": "local", "tag": "s", "path": loopback }),
            true,
        ),
        (
            serde_json::json!({ "type": "local", "tag": "s", "path": elsewhere }),
            false,
        ),
        (
            serde_json::json!({ "tag": "s", "rules": [{ "ip_cidr": "127.0.0.1/32" }] }),
            true,
        ),
    ] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let config = serde_json::json!({
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
                "outbounds": [{ "type": "direct" }],
                "route": {
                    "rule_set": [rule_set],
                    "rules": [{ "rule_set": "s", "action": "reject" }]
                }
            });
            common::test_configs(vec![config.to_string()], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), rejected, "{}: {:?}", rule_set, result);
    }
    Ok(())
}
