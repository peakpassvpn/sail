mod common;

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
