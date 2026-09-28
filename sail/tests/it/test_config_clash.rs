#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// app(socks) -> (mixed)sail, read from a Clash configuration -> echo
//
// Its rules decide: through a group to DIRECT, or REJECT for the echo
// server's address.
#[cfg(all(
    feature = "config-clash",
    feature = "inbound-mixed",
    feature = "outbound-direct",
    feature = "outbound-drop",
    feature = "outbound-select"
))]
#[test]
fn a_clash_configuration_routes() -> anyhow::Result<()> {
    for (rules, rejected) in [
        ("  - MATCH,Proxy\n", false),
        (
            "  - IP-CIDR,127.0.0.0/8,REJECT,no-resolve\n  - MATCH,Proxy\n",
            true,
        ),
        ("  - DST-PORT,1-65535,REJECT-DROP\n  - MATCH,Proxy\n", true),
        ("  - NETWORK,tcp,PASS\n  - MATCH,Proxy\n", false),
    ] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let yaml = format!(
                "mixed-port: {}\n\
                 log-level: silent\n\
                 proxy-groups:\n  - {{ name: Proxy, type: select, proxies: [DIRECT] }}\n\
                 rules:\n{}",
                port, rules
            );
            common::test_configs(vec![yaml], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), rejected, "{}: {:?}", rules, result);
    }
    Ok(())
}

// The same, by rule-providers read from files: Mihomo's binary (MRS) and
// text forms of a set holding the loopback range.
#[cfg(all(
    feature = "config-clash",
    feature = "rule-set",
    feature = "inbound-mixed",
    feature = "outbound-direct",
    feature = "outbound-drop",
    feature = "outbound-select"
))]
#[test]
fn rule_providers_route() -> anyhow::Result<()> {
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rule_set");
    for (provider, rejected) in [
        (
            format!(
                "{{ type: file, behavior: ipcidr, format: mrs, path: '{}/loopback.mrs' }}",
                fixtures
            ),
            true,
        ),
        (
            format!(
                "{{ type: file, behavior: ipcidr, format: text, path: '{}/loopback.list' }}",
                fixtures
            ),
            true,
        ),
        (
            format!(
                "{{ type: file, behavior: ipcidr, format: mrs, path: '{}/geoip-telegram.mrs' }}",
                fixtures
            ),
            false,
        ),
        (
            "{ type: inline, behavior: classical, payload: ['IP-CIDR,127.0.0.1/32'] }".to_string(),
            true,
        ),
    ] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let yaml = format!(
                "mixed-port: {}\n\
                 log-level: silent\n\
                 rule-providers:\n  lo: {}\n\
                 rules:\n  - RULE-SET,lo,REJECT,no-resolve\n  - MATCH,DIRECT\n",
                port, provider
            );
            common::test_configs(vec![yaml], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), rejected, "{}: {:?}", provider, result);
    }
    Ok(())
}
