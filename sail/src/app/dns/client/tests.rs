#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use super::{DnsClient, Kind, ServerSelectorState};

    fn dns(servers: serde_json::Value) -> crate::config::Dns {
        let mut config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": { "servers": servers } }).to_string(),
        )
        .unwrap();
        std::mem::take(&mut config.dns)
    }

    fn client(servers: serde_json::Value) -> anyhow::Result<DnsClient> {
        DnsClient::new(&dns(servers), Default::default(), &Default::default())
    }

    fn error(servers: serde_json::Value) -> String {
        client(servers).err().unwrap().to_string()
    }

    #[test]
    fn every_type_builds() {
        #[allow(unused_mut)]
        let mut servers = vec![
            serde_json::json!({ "type": "udp", "tag": "udp", "server": "1.1.1.1" }),
            serde_json::json!({ "type": "tcp", "tag": "tcp", "server": "::1", "server_port": 5353 }),
            serde_json::json!({ "type": "local", "tag": "local" }),
            serde_json::json!({ "type": "hosts", "tag": "hosts",
                                "predefined": { "a.example": ["10.0.0.1", "::1"] } }),
            serde_json::json!({ "type": "smart_select", "tag": "best", "servers": ["udp", "tcp"] }),
        ];
        #[cfg(feature = "tls")]
        servers.push(serde_json::json!({
            "type": "tls", "tag": "dot", "server": "1.1.1.1",
            "tls": { "server_name": "one.one.one.one" }
        }));
        #[cfg(feature = "dns-doh")]
        servers.push(serde_json::json!({
            "type": "https", "tag": "doh", "server": "dns.google",
            "domain_resolver": "udp", "path": "/resolve"
        }));
        #[cfg(feature = "quic")]
        servers.push(serde_json::json!({ "type": "quic", "tag": "doq", "server": "94.140.14.14" }));
        #[cfg(feature = "dns-h3")]
        servers.push(serde_json::json!({ "type": "h3", "tag": "doh3", "server": "223.5.5.5" }));
        let client = client(serde_json::Value::Array(servers)).unwrap();
        assert_eq!(client.final_server, "udp");
        assert!(matches!(
            client.servers["best"].kind,
            Kind::SmartSelect { .. }
        ));
        #[cfg(feature = "dns-doh")]
        match &client.servers["doh"].kind {
            Kind::Upstream(u) => {
                assert_eq!(u.to_string(), "https://dns.google:443/resolve");
                assert_eq!(u.address.resolver.as_ref().unwrap().server, "udp");
            }
            _ => panic!("not an upstream"),
        }
        #[cfg(feature = "tls")]
        match &client.servers["dot"].kind {
            Kind::Upstream(u) => assert_eq!(u.server_name, "one.one.one.one"),
            _ => panic!("not an upstream"),
        }
    }

    #[test]
    fn no_servers_is_the_system_resolver() {
        let client = client(serde_json::json!([])).unwrap();
        assert_eq!(client.final_server, "local");
        assert!(matches!(client.servers["local"].kind, Kind::Local));
    }

    #[test]
    fn mistakes_name_the_server() {
        for (servers, message) in [
            (
                serde_json::json!([{ "type": "dohh", "tag": "d" }]),
                "dns.servers[d]: unknown server type \"dohh\"",
            ),
            (
                serde_json::json!([{ "type": "udp", "tag": "u" }]),
                "dns.servers[u]: server: missing",
            ),
            (
                serde_json::json!([{ "type": "udp", "tag": "u", "server": "dns.google" }]),
                "is a domain; set domain_resolver",
            ),
            (
                serde_json::json!([{ "type": "udp", "tag": "u", "server": "1.1.1.1",
                                     "domain_resolver": "u" }]),
                "the server is an address",
            ),
            (
                serde_json::json!([{ "type": "udp", "tag": "u", "server": "a.example",
                                     "domain_resolver": "nowhere" }]),
                "server [nowhere] does not exist",
            ),
            (
                serde_json::json!([{ "type": "udp", "tag": "u", "server": "1.1.1.1",
                                     "path": "/x" }]),
                "path: a udp server takes none",
            ),
            (
                serde_json::json!([{ "type": "udp", "tag": "u", "server": "1.1.1.1",
                                     "detour": "proxy", "bind_interface": "en0" }]),
                "no effect with a detour",
            ),
            (
                serde_json::json!([{ "type": "udp", "tag": "u", "server": "1.1.1.1",
                                     "sever_port": 53 }]),
                "sever_port",
            ),
            (
                serde_json::json!([
                    { "type": "udp", "tag": "a", "server": "a.example", "domain_resolver": "b" },
                    { "type": "udp", "tag": "b", "server": "b.example", "domain_resolver": "a" }
                ]),
                "[a] -> [b] -> [a] need each other",
            ),
            (
                serde_json::json!([
                    { "type": "local", "tag": "l" },
                    { "type": "smart_select", "tag": "s1", "servers": ["l", "s2"] },
                    { "type": "smart_select", "tag": "s2", "servers": ["l", "l"] }
                ]),
                "[s2] is a smart_select too",
            ),
            (
                serde_json::json!([{ "type": "smart_select", "tag": "s", "servers": ["x"] }]),
                "a smart_select takes two or more",
            ),
        ] {
            let err = error(servers.clone());
            assert!(err.contains(message), "{}: {}", servers, err);
        }
    }

    #[test]
    fn tags_are_unique_and_final_names_one() {
        for (dns, message) in [
            (
                serde_json::json!({ "servers": [{ "type": "local" }, { "type": "local" }] }),
                "another server is tagged [local]",
            ),
            (
                serde_json::json!({ "servers": [{ "type": "local" }], "final": "x" }),
                "dns.final: server [x] does not exist",
            ),
        ] {
            let err =
                crate::config::Config::from_json(&serde_json::json!({ "dns": dns }).to_string())
                    .unwrap_err()
                    .to_string();
            assert!(err.contains(message), "{}: {}", dns, err);
        }
    }

    #[tokio::test]
    async fn a_hosts_server_answers_for_its_names_alone() {
        let client = client(serde_json::json!([{
            "type": "hosts",
            "predefined": { "A.example": ["10.0.0.1", "::1"], "b.example": "10.0.0.2" }
        }]))
        .unwrap();
        let ips = client.lookup("a.example").await.unwrap();
        assert_eq!(
            ips,
            [
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "::1".parse().unwrap()
            ]
        );
        assert_eq!(
            client.lookup("b.example").await.unwrap(),
            ["10.0.0.2".parse::<IpAddr>().unwrap()]
        );
        assert!(client.lookup("c.example").await.is_err());
    }

    #[tokio::test]
    async fn a_smart_select_falls_back_to_a_member_that_answers() {
        let client = client(serde_json::json!([
            { "type": "smart_select", "tag": "best", "servers": ["empty", "hosts"] },
            { "type": "hosts", "tag": "empty", "predefined": { "other.example": "10.0.0.9" } },
            { "type": "hosts", "tag": "hosts", "predefined": { "a.example": "10.0.0.1" } }
        ]))
        .unwrap();
        assert_eq!(client.final_server, "best");
        assert_eq!(
            client.lookup("a.example").await.unwrap(),
            ["10.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    fn with_rules(rules: serde_json::Value) -> anyhow::Result<DnsClient> {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "hosts", "tag": "home",
                      "predefined": { "nas.home.arpa": ["192.168.1.2", "fd00::2"] } },
                    { "type": "hosts", "tag": "world",
                      "predefined": { "a.example": ["10.0.0.1", "2001:db8::1"],
                                      "nas.home.arpa": "203.0.113.9" } }
                ],
                "rules": rules,
                "final": "world"
            } })
            .to_string(),
        )?;
        DnsClient::new(&config.dns, Default::default(), &Default::default())
    }

    fn ips(ips: &[&str]) -> Vec<IpAddr> {
        ips.iter().map(|ip| ip.parse().unwrap()).collect()
    }

    #[tokio::test]
    async fn rules_pick_the_server() {
        let client = with_rules(serde_json::json!([
            { "domain_suffix": "home.arpa", "server": "home" }
        ]))
        .unwrap();
        assert_eq!(
            client.lookup("nas.home.arpa").await.unwrap(),
            ips(&["192.168.1.2", "fd00::2"])
        );
        assert_eq!(
            client.lookup("a.example").await.unwrap(),
            ips(&["10.0.0.1", "2001:db8::1"])
        );
    }

    #[tokio::test]
    async fn a_rule_by_query_type_rejects_one_family() {
        let client = with_rules(serde_json::json!([
            { "query_type": ["AAAA"], "action": "reject" }
        ]))
        .unwrap();
        assert_eq!(client.lookup("a.example").await.unwrap(), ips(&["10.0.0.1"]));

        let client = with_rules(serde_json::json!([
            { "domain": "a.example", "action": "reject" }
        ]))
        .unwrap();
        let err = client.lookup("a.example").await.unwrap_err().to_string();
        assert!(err.contains("rejected by a dns rule"), "{}", err);
    }

    #[tokio::test]
    async fn a_rule_sets_the_families() {
        let client = with_rules(serde_json::json!([
            { "domain": "a.example", "server": "world", "strategy": "prefer_ipv6" },
            { "query_type": 28, "domain": "nas.home.arpa", "server": "home",
              "strategy": "ipv6_only" }
        ]))
        .unwrap();
        assert_eq!(
            client.lookup("a.example").await.unwrap(),
            ips(&["2001:db8::1", "10.0.0.1"])
        );
        // The A query goes to `final`, the AAAA one to `home`, which alone
        // is asked for by the strategy of the A query's rule, `final`'s.
        assert_eq!(
            client.lookup("nas.home.arpa").await.unwrap(),
            ips(&["203.0.113.9", "fd00::2"])
        );
    }

    #[tokio::test]
    async fn rules_match_the_inbound_and_user() {
        let client = with_rules(serde_json::json!([
            { "inbound": "lan", "auth_user": "alice", "server": "home" }
        ]))
        .unwrap();
        let mut ctx = super::LookupContext {
            inbound: Some("lan".into()),
            user: Some("bob".into()),
        };
        assert_eq!(
            client.lookup_in("nas.home.arpa", &ctx).await.unwrap(),
            ips(&["203.0.113.9"])
        );
        // A new client: answers are cached by name alone, as in sing-box.
        let client = with_rules(serde_json::json!([
            { "inbound": "lan", "auth_user": "alice", "server": "home" }
        ]))
        .unwrap();
        ctx.user = Some("alice".into());
        assert_eq!(
            client.lookup_in("nas.home.arpa", &ctx).await.unwrap(),
            ips(&["192.168.1.2", "fd00::2"])
        );
    }

    #[test]
    fn rule_mistakes_name_the_rule() {
        for (rules, message) in [
            (
                serde_json::json!([{ "domain": "a.example" }]),
                "dns.rules[0]: server: a route rule needs one",
            ),
            (
                serde_json::json!([{ "domain": "a.example", "server": "nowhere" }]),
                "dns.rules[0]: server [nowhere] does not exist",
            ),
            (
                serde_json::json!([{ "server": "home" }]),
                "dns.rules[0]: the rule has no conditions",
            ),
            (
                serde_json::json!([{ "domain": "a", "action": "reject", "server": "home" }]),
                "server and strategy are for route rules",
            ),
            (
                serde_json::json!([{ "query_type": "NOPE", "server": "home" }]),
                "dns.rules[0]: query_type: unknown record type \"NOPE\"",
            ),
            (
                serde_json::json!([{ "outbound": "proxy", "server": "home" }]),
                "dns.rules[0].outbound: sail does not implement this field yet",
            ),
            (
                serde_json::json!([{ "domain": "a", "action": "predefined" }]),
                "dns.rules[0].action: sail does not implement \"predefined\" yet",
            ),
        ] {
            let err = with_rules(rules.clone()).err().unwrap().to_string();
            assert!(err.contains(message), "{}: {}", rules, err);
        }
    }

    fn tags(tags: &[&str]) -> Vec<String> {
        tags.iter().map(|t| t.to_string()).collect()
    }

    #[test]
    fn selector_primary_switches_after_consecutive_failures() {
        let servers = tags(&["a", "b"]);
        let mut selector = ServerSelectorState::default();
        assert_eq!(selector.select_primary_index(&servers), 0);
        let threshold = crate::runtime::options::Dns::default()
            .switch_threshold
            .max(1);
        for _ in 0..threshold {
            selector.mark_failure("a", true);
        }
        assert_eq!(selector.select_primary_index(&servers), 1);
    }

    #[test]
    fn selector_prefers_lower_latency_in_fallback_order() {
        let servers = tags(&["a", "b", "c"]);
        let mut selector = ServerSelectorState::default();
        selector.mark_success("b", Duration::from_millis(30));
        selector.mark_success("c", Duration::from_millis(450));
        assert_eq!(selector.fallback_indices(&servers, 0), vec![1, 2]);
    }

    #[test]
    fn selector_marks_slow_server_as_degraded() {
        let mut selector = ServerSelectorState::default();
        let tuning = crate::runtime::options::Dns::default();
        let slow = tuning.slow_response + Duration::from_millis(50);
        for _ in 0..tuning.switch_threshold.max(1) {
            selector.mark_success("a", slow);
        }
        assert!(selector.is_degraded("a"));
    }
}
