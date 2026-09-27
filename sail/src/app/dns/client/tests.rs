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
        // A port nothing listens on: no answer comes.
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": { "timeout": "200ms", "servers": [
                { "type": "smart_select", "tag": "best", "servers": ["dead", "hosts"] },
                { "type": "udp", "tag": "dead", "server": "127.0.0.1", "server_port": dead_port },
                { "type": "hosts", "tag": "hosts", "predefined": { "a.example": "10.0.0.1" } }
            ] } })
            .to_string(),
        )
        .unwrap();
        let client =
            DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
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
            ..Default::default()
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
                serde_json::json!([{ "domain_regex": "^a", "server": "home" }]),
                "dns.rules[0].domain_regex: sail does not implement this field yet",
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

    #[tokio::test]
    async fn an_outbound_s_names_resolve_as_its_dial_options_say() {
        let client = with_rules(serde_json::json!([
            { "outbound": "lan-proxy", "server": "home" }
        ]))
        .unwrap();
        let mut dial = crate::net::DialOptions::default();
        // No resolver: `final`, and the rules for the outbound.
        assert_eq!(
            client.lookup_dial("nas.home.arpa", &dial).await.unwrap(),
            ips(&["203.0.113.9"])
        );
        dial.outbound = Some("lan-proxy".into());
        assert_eq!(
            client.lookup_dial("nas.home.arpa", &dial).await.unwrap(),
            ips(&["203.0.113.9"]),
            "cached by name, as in sing-box"
        );
        let client = with_rules(serde_json::json!([
            { "outbound": "lan-proxy", "server": "home" }
        ]))
        .unwrap();
        assert_eq!(
            client.lookup_dial("nas.home.arpa", &dial).await.unwrap(),
            ips(&["192.168.1.2", "fd00::2"])
        );
        // A resolver of its own, which the rules have no say in.
        let client = with_rules(serde_json::json!([
            { "outbound": "lan-proxy", "server": "world" }
        ]))
        .unwrap();
        dial.domain_resolver = Some(crate::config::model::DomainResolver {
            server: "home".into(),
            strategy: Some(crate::config::model::DnsStrategy::Ipv6Only),
        });
        assert_eq!(
            client.lookup_dial("nas.home.arpa", &dial).await.unwrap(),
            ips(&["fd00::2"])
        );
    }

    fn loops(config: serde_json::Value) -> anyhow::Result<()> {
        let config = crate::config::Config::from_json(&config.to_string())?;
        let client = DnsClient::new(&config.dns, Default::default(), &Default::default())?;
        client.check_loops(
            &config.outbounds,
            config.route.default_domain_resolver.as_ref(),
        )
    }

    /// A remote server reached through a proxy whose own name the remote
    /// server would resolve: the usual loop, and the ways out of it.
    #[test]
    fn a_server_reached_through_an_outbound_that_needs_it_is_an_error() {
        let config = |dns_extra: serde_json::Value, proxy_extra: serde_json::Value| {
            let mut dns = serde_json::json!({
                "servers": [
                    { "type": "udp", "tag": "remote", "server": "8.8.8.8", "detour": "select" },
                    { "type": "local", "tag": "local" }
                ]
            });
            for (k, v) in dns_extra.as_object().unwrap() {
                dns[k] = v.clone();
            }
            let mut proxy = serde_json::json!({
                "type": "socks", "tag": "proxy", "server": "proxy.example", "server_port": 1080
            });
            for (k, v) in proxy_extra.as_object().unwrap() {
                proxy[k] = v.clone();
            }
            serde_json::json!({
                "dns": dns,
                "outbounds": [
                    { "type": "selector", "tag": "select", "outbounds": ["proxy", "direct"] },
                    proxy,
                    { "type": "direct", "tag": "direct" }
                ]
            })
        };

        let err = loops(config(serde_json::json!({}), serde_json::json!({})))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "dns server [remote] -> outbound [select] -> outbound [proxy] -> dns server [remote]"
            ),
            "{}",
            err
        );

        // Out by a rule for the outbound, by its own resolver, or by the
        // default one.
        loops(config(
            serde_json::json!({ "rules": [{ "outbound": "proxy", "server": "local" }] }),
            serde_json::json!({}),
        ))
        .unwrap();
        loops(config(
            serde_json::json!({}),
            serde_json::json!({ "domain_resolver": "local" }),
        ))
        .unwrap();
        let mut with_default = config(serde_json::json!({}), serde_json::json!({}));
        with_default["route"] = serde_json::json!({ "default_domain_resolver": "local" });
        loops(with_default).unwrap();
        // A proxy at an address has nothing to resolve.
        loops(config(
            serde_json::json!({}),
            serde_json::json!({ "server": "192.0.2.1" }),
        ))
        .unwrap();
    }

    #[test]
    fn domain_resolvers_name_servers_that_exist() {
        for (config, message) in [
            (
                serde_json::json!({ "route": { "default_domain_resolver": "nowhere" } }),
                "route.default_domain_resolver: dns server [nowhere] does not exist",
            ),
            (
                serde_json::json!({ "outbounds": [{ "type": "direct",
                    "domain_resolver": { "server": "nowhere", "strategy": "ipv4_only" } }] }),
                "[direct] outbound: domain_resolver: dns server [nowhere] does not exist",
            ),
            (
                serde_json::json!({ "outbounds": [{ "type": "direct",
                    "domain_resolver": { "server": "local", "stratgy": "ipv4_only" } }] }),
                "stratgy",
            ),
            (
                serde_json::json!({ "outbounds": [{ "type": "direct" }], "route": { "rules": [
                    { "action": "resolve", "server": "nowhere" }] } }),
                "route.rules[0].server: dns server [nowhere] does not exist",
            ),
            (
                serde_json::json!({ "outbounds": [{ "type": "direct" }], "route": { "rules": [
                    { "domain": "a", "outbound": "direct", "server": "local" }] } }),
                "route.rules[0].server: not for a route rule",
            ),
        ] {
            let err = crate::config::Config::from_json(&config.to_string())
                .unwrap_err()
                .to_string();
            assert!(err.contains(message), "{}: {}", config, err);
        }
        // With no servers, the system's resolver is `local`.
        crate::config::Config::from_json(
            &serde_json::json!({ "route": { "default_domain_resolver": "local" } }).to_string(),
        )
        .unwrap();
    }

    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType};

    fn query(name: &str, ty: RecordType) -> Vec<u8> {
        DnsClient::new_query(Name::from_ascii(format!("{}.", name)).unwrap(), ty)
            .to_vec()
            .unwrap()
    }

    fn answer_ips(message: &Message) -> Vec<IpAddr> {
        message
            .answers()
            .iter()
            .filter_map(|r| match r.data() {
                Some(RData::A(a)) => Some(IpAddr::V4(**a)),
                Some(RData::AAAA(a)) => Some(IpAddr::V6(**a)),
                _ => None,
            })
            .collect()
    }

    async fn exchange(client: &DnsClient, name: &str, ty: RecordType) -> Message {
        let request = query(name, ty);
        let response = client
            .exchange(&request, &super::LookupContext::default())
            .await
            .unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.id(), Message::from_vec(&request).unwrap().id());
        response
    }

    fn fake_ip_client() -> DnsClient {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "hosts", "tag": "hosts",
                      "predefined": { "lan.example": "192.168.1.9" } },
                    { "type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15" }
                ],
                "rules": [
                    { "domain": "blocked.example", "action": "reject" },
                    { "domain": "v4only.example", "query_type": "AAAA",
                      "server": "fake", "strategy": "ipv4_only" },
                    { "domain_suffix": "lan.example", "server": "hosts" },
                    { "query_type": ["A", "AAAA"], "server": "fake" }
                ],
                "final": "hosts"
            } })
            .to_string(),
        )
        .unwrap();
        DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap()
    }

    #[tokio::test]
    async fn clients_queries_are_answered_as_the_rules_say() {
        let client = fake_ip_client();
        // Fake IPs, in turn, for as long as the domain has one.
        let a = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&a), ips(&["198.18.0.2"]));
        assert_eq!(a.answers()[0].ttl(), 600);
        let b = exchange(&client, "b.example", RecordType::A).await;
        assert_eq!(answer_ips(&b), ips(&["198.18.0.3"]));
        let again = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&again), ips(&["198.18.0.2"]));
        // No inet6_range: no records, and no error.
        let aaaa = exchange(&client, "a.example", RecordType::AAAA).await;
        assert_eq!(aaaa.response_code(), ResponseCode::NoError);
        assert!(aaaa.answers().is_empty());
        // What connections to them become.
        assert_eq!(
            client.fake_ip("198.18.0.2".parse().unwrap()),
            super::FakeIp::Domain("a.example".into())
        );
        assert_eq!(
            client.fake_ip("198.18.0.99".parse().unwrap()),
            super::FakeIp::Unknown
        );
        assert_eq!(
            client.fake_ip("10.0.0.1".parse().unwrap()),
            super::FakeIp::NotFake
        );
        assert_eq!(
            client.fake_ip_of("b.example", false),
            Some("198.18.0.3".parse().unwrap())
        );

        let refused = exchange(&client, "blocked.example", RecordType::A).await;
        assert_eq!(refused.response_code(), ResponseCode::Refused);
        let v4only = exchange(&client, "v4only.example", RecordType::AAAA).await;
        assert!(v4only.answers().is_empty());
        let lan = exchange(&client, "lan.example", RecordType::A).await;
        assert_eq!(answer_ips(&lan), ips(&["192.168.1.9"]));
        // A hosts server answers addresses only; NXDOMAIN to the rest, as
        // sing-box's does.
        let mx = exchange(&client, "lan.example", RecordType::MX).await;
        assert_eq!(mx.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn a_reload_keeps_the_fake_ips_handed_out() {
        let client = fake_ip_client();
        exchange(&client, "a.example", RecordType::A).await;
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": { "servers": [
                { "type": "fakeip", "inet4_range": "198.18.0.0/15" }
            ] } })
            .to_string(),
        )
        .unwrap();
        let reloaded = client
            .reloaded(&config.dns, Default::default(), &Default::default(), &Default::default())
            .unwrap();
        assert_eq!(
            reloaded.fake_ip("198.18.0.2".parse().unwrap()),
            super::FakeIp::Domain("a.example".into())
        );
        // Other ranges: a store of their own.
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": { "servers": [
                { "type": "fakeip", "inet4_range": "198.20.0.0/16" }
            ] } })
            .to_string(),
        )
        .unwrap();
        let other = client
            .reloaded(&config.dns, Default::default(), &Default::default(), &Default::default())
            .unwrap();
        assert_eq!(
            other.fake_ip("198.18.0.2".parse().unwrap()),
            super::FakeIp::NotFake
        );
    }

    /// A UDP server answering every A query with 10.0.0.7, TTL 300, and
    /// counting them.
    async fn udp_server() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = count.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let request = Message::from_vec(&buf[..n]).unwrap();
                let reply = DnsClient::reply(&request, &ips(&["10.0.0.7"]), 300);
                let _ = socket.send_to(&reply.to_vec().unwrap(), peer).await;
            }
        });
        (port, count)
    }

    #[tokio::test]
    async fn a_forwarded_query_keeps_its_id_and_its_answer_is_kept() {
        let (port, count) = udp_server().await;
        let client = client(serde_json::json!([
            { "type": "udp", "server": "127.0.0.1", "server_port": port }
        ]))
        .unwrap();
        let first = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&first), ips(&["10.0.0.7"]));
        let second = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&second), ips(&["10.0.0.7"]));
        assert!(second.answers()[0].ttl() <= 300);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
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
