#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use super::{DnsClient, Kind};
    use crate::util::DnsMessageExt;

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
            serde_json::json!({ "type": "race", "tag": "best", "servers": ["udp", "tcp"] }),
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
            Kind::Race { .. }
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
                    { "type": "race", "tag": "s1", "servers": ["l", "s2"] },
                    { "type": "race", "tag": "s2", "servers": ["l", "l"] }
                ]),
                "[s2] is a race too",
            ),
            (
                serde_json::json!([{ "type": "race", "tag": "s", "servers": ["x"] }]),
                "a race takes two or more",
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

    /// A UDP server answering every query with `code` and no records.
    async fn failing_server(code: hickory_proto::op::ResponseCode) -> u16 {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let request = Message::from_vec(&buf[..n]).unwrap();
                let mut reply = DnsClient::reply(&request, &[], 0);
                reply.set_response_code(code);
                let _ = socket.send_to(&reply.to_vec().unwrap(), peer).await;
            }
        });
        port
    }

    fn race_client(servers: serde_json::Value) -> DnsClient {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": { "timeout": "2s", "servers": servers } }).to_string(),
        )
        .unwrap();
        DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap()
    }

    #[tokio::test]
    async fn a_race_takes_the_first_member_to_answer_well() {
        use hickory_proto::op::ResponseCode;
        // A port nothing listens on: no answer comes.
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let servfail = failing_server(ResponseCode::ServFail).await;
        let refused = failing_server(ResponseCode::Refused).await;
        let (good, _) = counting_server(300, false).await;
        let client = race_client(serde_json::json!([
            { "type": "race", "tag": "all",
              "servers": ["dead", "servfail", "refused", "good"] },
            { "type": "udp", "tag": "dead", "server": "127.0.0.1", "server_port": dead_port },
            { "type": "udp", "tag": "servfail", "server": "127.0.0.1", "server_port": servfail },
            { "type": "udp", "tag": "refused", "server": "127.0.0.1", "server_port": refused },
            { "type": "udp", "tag": "good", "server": "127.0.0.1", "server_port": good },
        ]));
        assert_eq!(client.final_server, "all");
        let started = std::time::Instant::now();
        let answer = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&answer), ips(&["10.0.0.1"]));
        // Not held up by the member that never answers.
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());

        // NXDOMAIN is an answer: the first one wins.
        let nxdomain = failing_server(ResponseCode::NXDomain).await;
        let client = race_client(serde_json::json!([
            { "type": "race", "tag": "all", "servers": ["nx", "dead"] },
            { "type": "udp", "tag": "nx", "server": "127.0.0.1", "server_port": nxdomain },
            { "type": "udp", "tag": "dead", "server": "127.0.0.1", "server_port": dead_port },
        ]));
        let answer = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::NXDomain);

        // Every one failing: SERVFAIL to the client.
        let client = race_client(serde_json::json!([
            { "type": "race", "tag": "all", "servers": ["servfail", "refused"] },
            { "type": "udp", "tag": "servfail", "server": "127.0.0.1", "server_port": servfail },
            { "type": "udp", "tag": "refused", "server": "127.0.0.1", "server_port": refused },
        ]));
        let err = client.lookup("a.example").await.unwrap_err().to_string();
        assert!(err.contains("every server failed"), "{}", err);
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

    /// As one of the published templates has it: an A or AAAA query for a
    /// name not in a set goes to one server, the rest to `final`.
    #[tokio::test]
    async fn logical_and_inverted_rules() {
        let client = with_rules(serde_json::json!([
            { "type": "logical", "mode": "and", "rules": [
                { "query_type": ["A", "AAAA"] },
                { "domain_suffix": "example", "invert": true }
            ], "server": "home" }
        ]))
        .unwrap();
        // .arpa is not .example: home.
        assert_eq!(
            client.lookup("nas.home.arpa").await.unwrap(),
            ips(&["192.168.1.2", "fd00::2"])
        );
        // .example: world, the final server.
        assert_eq!(
            client.lookup("a.example").await.unwrap(),
            ips(&["10.0.0.1", "2001:db8::1"])
        );
        for (rules, message) in [
            (
                serde_json::json!([{ "type": "logical", "mode": "or", "server": "home",
                    "rules": [{ "domain": "a", "server": "world" }] }]),
                "dns.rules[0]: rules[0]: server: a rule a logical one combines has none",
            ),
            (
                serde_json::json!([{ "type": "logical", "mode": "or", "server": "home",
                    "rules": [{ "query_type": "NOPE" }] }]),
                "dns.rules[0].rules[0].query_type: unknown record type \"NOPE\"",
            ),
        ] {
            let err = with_rules(rules.clone()).err().unwrap().to_string();
            assert!(err.contains(message), "{}: {}", rules, err);
        }
    }

    #[tokio::test]
    async fn clash_mode_picks_the_server() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "experimental": { "clash_api": { "default_mode": "Direct",
                                                  "external_controller": "127.0.0.1:9090" } },
                "dns": { "servers": [
                    { "type": "hosts", "tag": "home", "predefined": { "a.example": "10.0.0.1" } },
                    { "type": "hosts", "tag": "world", "predefined": { "a.example": "10.0.0.2" } }
                ], "rules": [{ "clash_mode": "Direct", "server": "home" }], "final": "world" }
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(config.experimental.clash_api.as_ref().unwrap().default_mode.as_deref(), Some("Direct"));
        assert_eq!(config.warnings.len(), 1, "{:?}", config.warnings);
        let env = crate::runtime::RuntimeEnv::default();
        env.clash_mode
            .configure(config.experimental.clash_api.as_ref(), None);
        let client = DnsClient::new(&config.dns, Default::default(), &env).unwrap();
        assert_eq!(client.lookup("a.example").await.unwrap(), ips(&["10.0.0.1"]));
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
                "dns.rules[0]: server: not with action reject",
            ),
            (
                serde_json::json!([{ "query_type": "NOPE", "server": "home" }]),
                "dns.rules[0].query_type: unknown record type \"NOPE\"",
            ),
            (
                serde_json::json!([{ "wifi_ssid": "home", "server": "home" }]),
                "dns.rules[0].wifi_ssid: sail does not implement this field yet",
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
        // The rules' server for the outbound, not what `final` answered
        // before: answers are kept by server, as sing-box 1.14 keeps them.
        dial.outbound = Some("lan-proxy".into());
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
            ..Default::default()
        });
        assert_eq!(
            client.lookup_dial("nas.home.arpa", &dial).await.unwrap(),
            ips(&["fd00::2"])
        );
    }

    fn loops(config: serde_json::Value) -> anyhow::Result<()> {
        let config = crate::config::Config::from_json(&config.to_string())?;
        let client = DnsClient::new(&config.dns, Default::default(), &Default::default())?;
        client.check_loops(&config.outbounds, &config.route)
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
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
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

    /// A name a hosts server gives another is answered with a CNAME and
    /// the other's addresses, looked up as the rules say; a pattern's
    /// names with its own.
    #[tokio::test]
    async fn a_hosts_alias_is_answered_with_its_names_addresses() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "hosts", "tag": "clash", "predefined": {
                        "alias.example": "far.example",
                        "+.plus.example": "10.0.0.2"
                    } },
                    { "type": "hosts", "tag": "other",
                      "predefined": { "far.example": "10.9.9.9" } }
                ],
                "rules": [
                    { "domain": ["alias.example"], "domain_suffix": ["plus.example"],
                      "server": "clash" }
                ],
                "final": "other"
            } })
            .to_string(),
        )
        .unwrap();
        let client = DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
        let alias = exchange(&client, "alias.example", RecordType::A).await;
        match &alias.answers()[0].data {
            RData::CNAME(target) => assert_eq!(target.0.to_ascii(), "far.example."),
            other => panic!("not a CNAME: {:?}", other),
        }
        assert_eq!(answer_ips(&alias), ips(&["10.9.9.9"]));
        assert_eq!(
            client.lookup("alias.example").await.unwrap(),
            ips(&["10.9.9.9"])
        );
        let plus = exchange(&client, "a.plus.example", RecordType::A).await;
        assert_eq!(answer_ips(&plus), ips(&["10.0.0.2"]));
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
        assert_eq!(answer_ips(&a), ips(&["198.18.0.4"]));
        assert_eq!(a.answers()[0].ttl, 600);
        let b = exchange(&client, "b.example", RecordType::A).await;
        assert_eq!(answer_ips(&b), ips(&["198.18.0.5"]));
        let again = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&again), ips(&["198.18.0.4"]));
        // No inet6_range: no records, and no error.
        let aaaa = exchange(&client, "a.example", RecordType::AAAA).await;
        assert_eq!(aaaa.response_code(), ResponseCode::NoError);
        assert!(aaaa.answers().is_empty());
        // What connections to them become.
        assert_eq!(
            client.fake_ip("198.18.0.4".parse().unwrap()),
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
            Some("198.18.0.5".parse().unwrap())
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
            reloaded.fake_ip("198.18.0.4".parse().unwrap()),
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
            other.fake_ip("198.18.0.4".parse().unwrap()),
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
        assert!(second.answers()[0].ttl <= 300);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// As the published templates have it: a query goes first to a
    /// server abroad, and when the address it answers is at home, to the
    /// server at home; the rest get fake IPs, but the instance's own
    /// lookups, which go to `final`.
    fn evaluating(rules: serde_json::Value) -> anyhow::Result<DnsClient> {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "hosts", "tag": "abroad",
                      "predefined": { "home.example": "1.1.1.1", "away.example": "8.8.8.8" } },
                    { "type": "hosts", "tag": "home",
                      "predefined": { "home.example": "1.2.2.2", "away.example": "8.9.9.9" } },
                    { "type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15" }
                ],
                "rules": rules,
                "final": "abroad"
            } })
            .to_string(),
        )?;
        DnsClient::new(&config.dns, Default::default(), &Default::default())
    }

    #[tokio::test]
    async fn a_rule_matches_an_evaluated_response() {
        let client = evaluating(serde_json::json!([
            { "query_type": "A", "action": "evaluate", "server": "abroad" },
            { "match_response": true, "ip_cidr": "1.0.0.0/8", "server": "home" },
            { "query_type": ["A", "AAAA"], "server": "fake" }
        ]))
        .unwrap();
        let home = exchange(&client, "home.example", RecordType::A).await;
        assert_eq!(answer_ips(&home), ips(&["1.2.2.2"]));
        let away = exchange(&client, "away.example", RecordType::A).await;
        assert_eq!(answer_ips(&away), ips(&["198.18.0.4"]));
        // The instance's own lookup passes over the fakeip server.
        let client = evaluating(serde_json::json!([
            { "query_type": "A", "action": "evaluate", "server": "abroad" },
            { "match_response": true, "ip_cidr": "1.0.0.0/8", "server": "home" },
            { "query_type": ["A", "AAAA"], "server": "fake" }
        ]))
        .unwrap();
        assert_eq!(client.lookup("home.example").await.unwrap(), ips(&["1.2.2.2"]));
        assert_eq!(client.lookup("away.example").await.unwrap(), ips(&["8.8.8.8"]));
    }

    /// The published templates' own: an address in a rule-set of the
    /// country's.
    #[cfg(feature = "rule-set")]
    #[tokio::test]
    async fn a_rule_set_matches_an_evaluated_response() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "route": { "rule_set": [
                    { "tag": "geoip-cn", "rules": [{ "ip_cidr": "1.0.0.0/8" }] }
                ] },
                "dns": {
                    "servers": [
                        { "type": "hosts", "tag": "abroad",
                          "predefined": { "home.example": "1.1.1.1", "away.example": "8.8.8.8" } },
                        { "type": "hosts", "tag": "home",
                          "predefined": { "home.example": "1.2.2.2", "away.example": "8.9.9.9" } }
                    ],
                    "rules": [
                        { "type": "logical", "mode": "and", "rules": [
                            { "query_type": ["A", "AAAA"] },
                            { "domain": "never.example", "invert": true }
                        ], "action": "evaluate", "server": "abroad",
                          "client_subnet": "223.5.5.0/24", "timeout": "2s" },
                        { "match_response": true, "rule_set": "geoip-cn", "server": "home" }
                    ],
                    "final": "abroad"
                }
            })
            .to_string(),
        )
        .unwrap();
        let env = crate::runtime::RuntimeEnv::default();
        let rule_sets = crate::app::router::rule_set::RuleSets::load(
            &config.route.rule_set,
            &Default::default(),
            &env,
        )
        .unwrap();
        let client =
            DnsClient::with_rule_sets(&config.dns, Default::default(), &env, &rule_sets).unwrap();
        assert_eq!(client.lookup("home.example").await.unwrap(), ips(&["1.2.2.2"]));
        assert_eq!(client.lookup("away.example").await.unwrap(), ips(&["8.8.8.8"]));
    }

    #[tokio::test]
    async fn respond_answers_with_the_evaluated_response() {
        let client = evaluating(serde_json::json!([
            { "domain_suffix": "example", "action": "evaluate", "server": "home", "tag": "h" },
            { "domain_suffix": "example", "action": "evaluate", "server": "abroad" },
            // By tag, the one at home.
            { "match_response": "h", "ip_cidr": "8.0.0.0/8", "action": "respond" },
            // The latest one without a tag, abroad.
            { "match_response": true, "ip_is_private": true, "invert": true, "action": "respond" }
        ]))
        .unwrap();
        let away = exchange(&client, "away.example", RecordType::A).await;
        assert_eq!(answer_ips(&away), ips(&["8.9.9.9"]));
        let home = exchange(&client, "home.example", RecordType::A).await;
        assert_eq!(answer_ips(&home), ips(&["1.1.1.1"]));

        // A hosts server answers NXDOMAIN for the names it has not.
        let client = evaluating(serde_json::json!([
            { "domain_suffix": "example", "action": "evaluate", "server": "home" },
            { "match_response": true, "response_rcode": "NXDOMAIN", "action": "reject" },
            { "match_response": true, "ip_accept_any": true, "action": "respond" }
        ]))
        .unwrap();
        let missing = exchange(&client, "missing.example", RecordType::A).await;
        assert_eq!(missing.response_code(), ResponseCode::Refused);
        let away = exchange(&client, "away.example", RecordType::A).await;
        assert_eq!(answer_ips(&away), ips(&["8.9.9.9"]));
    }

    #[tokio::test]
    async fn without_its_response_a_rule_matches_only_inverted() {
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = dead.local_addr().unwrap().port();
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "hosts", "tag": "home", "predefined": { "a.example": "1.2.2.2" } },
                    { "type": "udp", "tag": "dead", "server": "127.0.0.1", "server_port": port }
                ],
                "rules": [
                    { "domain": "a.example", "action": "evaluate", "server": "dead",
                      "timeout": "100ms" },
                    { "match_response": true, "ip_accept_any": true, "action": "respond" },
                    { "match_response": true, "ip_accept_any": true, "invert": true,
                      "server": "home" }
                ],
                "final": "dead"
            } })
            .to_string(),
        )
        .unwrap();
        let client = DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
        let started = std::time::Instant::now();
        let a = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&a), ips(&["1.2.2.2"]));
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());

        // Respond with nothing evaluated fails the query.
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "udp", "tag": "dead", "server": "127.0.0.1", "server_port": port }
                ],
                "rules": [
                    { "domain": "a.example", "action": "evaluate", "server": "dead",
                      "timeout": "100ms" },
                    { "domain": "a.example", "action": "respond" }
                ]
            } })
            .to_string(),
        )
        .unwrap();
        let client = DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
        let a = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(a.response_code(), ResponseCode::ServFail);
    }

    /// A UDP server answering every A query with 10.0.0.7, TTL 300, and
    /// keeping the client subnet of each.
    async fn subnet_server() -> (
        u16,
        std::sync::Arc<std::sync::Mutex<Vec<Option<crate::config::model::Prefix>>>>,
    ) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = seen.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let request = Message::from_vec(&buf[..n]).unwrap();
                kept.lock().unwrap().push(super::rules::client_subnet(&request));
                let reply = DnsClient::reply(&request, &ips(&["10.0.0.7"]), 300);
                let _ = socket.send_to(&reply.to_vec().unwrap(), peer).await;
            }
        });
        (port, seen)
    }

    #[tokio::test]
    async fn queries_carry_the_client_subnet_and_options_rules_set() {
        let (port, seen) = subnet_server().await;
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [{ "type": "udp", "tag": "up", "server": "127.0.0.1",
                              "server_port": port }],
                "client_subnet": "192.0.2.1",
                "rules": [
                    { "domain": "own.example", "server": "up", "client_subnet": "223.5.5.9/24" },
                    { "domain": "none.example", "server": "up", "remove_client_subnet": true },
                    { "domain": "ttl.example", "action": "route-options", "rewrite_ttl": 5,
                      "disable_cache": true },
                    { "domain": "ttl.example", "server": "up" }
                ]
            } })
            .to_string(),
        )
        .unwrap();
        let client = DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
        exchange(&client, "a.example", RecordType::A).await;
        exchange(&client, "own.example", RecordType::A).await;
        exchange(&client, "none.example", RecordType::A).await;
        let ttl = exchange(&client, "ttl.example", RecordType::A).await;
        assert_eq!(ttl.answers()[0].ttl, 5);
        // Not cached: asked again.
        exchange(&client, "ttl.example", RecordType::A).await;
        let prefix = |p: &str| Some(p.parse::<crate::config::model::Prefix>().unwrap());
        assert_eq!(
            *seen.lock().unwrap(),
            [
                prefix("192.0.2.1/32"),
                prefix("223.5.5.0/24"),
                None,
                prefix("192.0.2.1/32"),
                prefix("192.0.2.1/32"),
            ]
        );
    }

    #[tokio::test]
    async fn a_domain_resolver_sends_its_queries_as_it_says() {
        let (port, seen) = subnet_server().await;
        let client = client(serde_json::json!([
            { "type": "udp", "tag": "up", "server": "127.0.0.1", "server_port": port }
        ]))
        .unwrap();
        let resolver: crate::config::model::DomainResolver = serde_json::from_value(
            serde_json::json!({ "server": "up", "strategy": "ipv4_only",
                                "client_subnet": "223.5.5.0/24", "disable_cache": true,
                                "timeout": "1s", "rewrite_ttl": 5 }),
        )
        .unwrap();
        let dial = crate::net::DialOptions {
            domain_resolver: Some(resolver),
            ..Default::default()
        };
        for _ in 0..2 {
            assert_eq!(
                client.lookup_dial("a.example", &dial).await.unwrap(),
                ips(&["10.0.0.7"])
            );
        }
        // Not cached: asked each time, with its subnet.
        let prefix = "223.5.5.0/24".parse::<crate::config::model::Prefix>().ok();
        assert_eq!(*seen.lock().unwrap(), [prefix, prefix]);
    }

    #[tokio::test]
    async fn domain_strategy_sets_the_families_of_what_is_dialled() {
        let client = with_rules(serde_json::json!([])).unwrap();
        // With no resolver, the rules', of its families.
        let dial = crate::net::DialOptions {
            strategy: Some(crate::config::model::DnsStrategy::Ipv6Only),
            ..Default::default()
        };
        assert_eq!(
            client.lookup_dial("a.example", &dial).await.unwrap(),
            ips(&["2001:db8::1"])
        );
        // Over the default resolver's strategy, as in sing-box; not over
        // a resolver of its own.
        let defaults = crate::net::DialOptions {
            domain_resolver: Some(crate::config::model::DomainResolver {
                server: "world".into(),
                strategy: Some(crate::config::model::DnsStrategy::Ipv4Only),
                ..Default::default()
            }),
            ..Default::default()
        };
        let dial = crate::net::DialOptions {
            strategy: Some(crate::config::model::DnsStrategy::Ipv6Only),
            ..Default::default()
        }
        .or(&defaults);
        assert_eq!(
            dial.domain_resolver.as_ref().unwrap().strategy,
            Some(crate::config::model::DnsStrategy::Ipv6Only)
        );
        let own = crate::net::DialOptions {
            domain_resolver: Some(crate::config::model::DomainResolver {
                server: "world".into(),
                strategy: Some(crate::config::model::DnsStrategy::Ipv4Only),
                ..Default::default()
            }),
            strategy: Some(crate::config::model::DnsStrategy::Ipv6Only),
            ..Default::default()
        }
        .or(&defaults);
        assert_eq!(
            own.domain_resolver.as_ref().unwrap().strategy,
            Some(crate::config::model::DnsStrategy::Ipv4Only)
        );
    }

    #[cfg(feature = "dns-doh")]
    #[test]
    fn a_doh_server_sends_its_headers() {
        let client = client(serde_json::json!([
            { "type": "udp", "tag": "udp", "server": "1.1.1.1" },
            { "type": "https", "tag": "doh", "server": "1.1.1.1", "path": "/q",
              "headers": { "Host": "dns.example", "X-Token": ["a", "b"],
                           "accept": "application/dns-message" } }
        ]))
        .unwrap();
        let Kind::Upstream(upstream) = &client.servers["doh"].kind else {
            panic!("not an upstream");
        };
        assert_eq!(
            upstream.http1_head(33),
            "POST /q HTTP/1.1\r\nHost: dns.example\r\nContent-Length: 33\r\n\
             Content-Type: application/dns-message\r\nX-Token: a\r\nX-Token: b\r\n\
             accept: application/dns-message\r\n\r\n"
        );
        let request = upstream.http_request(33).unwrap();
        assert_eq!(request.uri(), "https://dns.example/q");
        let tokens: Vec<_> = request.headers().get_all("x-token").iter().collect();
        assert_eq!(tokens, ["a", "b"]);
        assert_eq!(request.headers().get_all("accept").iter().count(), 1);

        for (servers, message) in [
            (
                serde_json::json!([{ "type": "udp", "server": "1.1.1.1",
                                     "headers": { "X-A": "1" } }]),
                "headers: only https and h3 servers take them",
            ),
            (
                serde_json::json!([{ "type": "https", "server": "1.1.1.1",
                                     "headers": { "Content-Length": "1" } }]),
                "headers: Content-Length is sail's to set",
            ),
        ] {
            let err = error(servers.clone());
            assert!(err.contains(message), "{}: {}", servers, err);
        }
    }

    #[test]
    fn response_rule_mistakes_name_the_rule() {
        for (rules, message) in [
            (
                serde_json::json!([{ "match_response": true, "ip_cidr": "1.0.0.0/8",
                                     "server": "home" }]),
                "dns.rules[0]: the response it matches comes from an evaluate rule before it, \
                 and there is none",
            ),
            (
                serde_json::json!([
                    { "domain": "a", "action": "evaluate", "server": "home", "tag": "x" },
                    { "match_response": true, "server": "home" }
                ]),
                "dns.rules[1]: the response it matches comes from an evaluate rule without a \
                 tag before it; match_response names a tagged one",
            ),
            (
                serde_json::json!([{ "match_response": "x", "server": "home" }]),
                "dns.rules[0]: match_response: no evaluate rule before it is tagged [x]",
            ),
            (
                serde_json::json!([
                    { "domain": "a", "action": "evaluate", "server": "home", "tag": "x" },
                    { "domain": "b", "action": "evaluate", "server": "home", "tag": "x" }
                ]),
                "dns.rules[1]: tag: another evaluate rule is tagged [x]",
            ),
            (
                serde_json::json!([{ "domain": "a", "action": "respond" }]),
                "dns.rules[0]: the response it matches comes from an evaluate rule before it, \
                 and there is none",
            ),
            (
                serde_json::json!([{ "ip_cidr": "1.0.0.0/8", "server": "home" }]),
                "dns.rules[0]: ip_cidr: matches an evaluated response, and needs \
                 match_response",
            ),
            (
                serde_json::json!([
                    { "domain": "a", "action": "evaluate", "server": "home" },
                    { "domain": "b", "server": "home", "strategy": "ipv4_only" }
                ]),
                "dns.rules[1].strategy: not with evaluated responses (dns.rules[0])",
            ),
            (
                serde_json::json!([{ "domain": "a", "action": "route-options" }]),
                "dns.rules[0]: a route-options rule sets some option",
            ),
            (
                serde_json::json!([{ "domain": "a", "server": "home",
                                     "client_subnet": "1.2.3.0/24",
                                     "remove_client_subnet": true }]),
                "dns.rules[0]: client_subnet: not with remove_client_subnet",
            ),
            (
                serde_json::json!([{ "domain": "a", "server": "home",
                                     "client_subnet": "1.2.3.0/33" }]),
                "the prefix length is 0 to 32",
            ),
            (
                serde_json::json!([{ "domain": "a", "action": "respond", "tag": "x" }]),
                "dns.rules[0]: tag: not with action respond",
            ),
            (
                serde_json::json!([{ "domain": "a", "action": "evaluate", "server": "home",
                                     "race": true }]),
                "dns.rules[0]: race: not with action evaluate",
            ),
        ] {
            let err = with_rules(rules.clone()).err().unwrap().to_string();
            assert!(err.contains(message), "{}: {}", rules, err);
        }
        let err = evaluating(serde_json::json!([
            { "domain": "a", "action": "evaluate", "server": "fake" }
        ]))
        .err()
        .unwrap()
        .to_string();
        assert!(
            err.contains("dns.rules[0]: server: [fake] is the fakeip server"),
            "{}",
            err
        );
    }

    #[tokio::test]
    async fn a_predefined_rule_answers_with_its_code() {
        let client = with_rules(serde_json::json!([
            { "domain": "ads.example", "action": "predefined", "rcode": "NXDOMAIN" },
            { "domain": "quiet.example", "action": "predefined" },
            { "query_type": "HTTPS", "action": "predefined", "rcode": 5 }
        ]))
        .unwrap();
        let ads = exchange(&client, "ads.example", RecordType::A).await;
        assert_eq!(ads.response_code(), ResponseCode::NXDomain);
        let quiet = exchange(&client, "quiet.example", RecordType::A).await;
        assert_eq!(quiet.response_code(), ResponseCode::NoError);
        assert!(quiet.answers().is_empty());
        let https = exchange(&client, "a.example", RecordType::HTTPS).await;
        assert_eq!(https.response_code(), ResponseCode::Refused);
        // The instance's own lookups get no address from it.
        let err = client.lookup("ads.example").await.unwrap_err().to_string();
        assert!(err.contains("does not exist"), "{}", err);
        assert!(client.lookup("quiet.example").await.is_err());
        assert_eq!(
            client.lookup("a.example").await.unwrap(),
            ips(&["10.0.0.1", "2001:db8::1"])
        );

        let err = with_rules(serde_json::json!([
            { "domain": "a", "server": "home", "rcode": "NXDOMAIN" }
        ]))
        .err()
        .unwrap()
        .to_string();
        assert!(
            err.contains("dns.rules[0]: rcode: not with action route"),
            "{}",
            err
        );
    }

    /// Mihomo's fallback filter: the answer is kept only when every address
    /// in it is at home.
    #[tokio::test]
    async fn ip_match_all_holds_for_every_address() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "hosts", "tag": "main", "predefined": {
                        "home.example": ["1.1.1.1", "1.2.2.2"],
                        "mixed.example": ["1.1.1.1", "8.8.8.8"],
                        "none.example": [] } },
                    { "type": "hosts", "tag": "fallback", "predefined": {
                        "home.example": "9.9.9.1", "mixed.example": "9.9.9.2",
                        "none.example": "9.9.9.3" } }
                ],
                "rules": [
                    { "query_type": ["A", "AAAA"], "action": "evaluate", "server": "main" },
                    { "match_response": true, "ip_cidr": "1.0.0.0/8", "ip_match_all": true,
                      "action": "respond" }
                ],
                "final": "fallback"
            } })
            .to_string(),
        )
        .unwrap();
        let client = DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
        let home = exchange(&client, "home.example", RecordType::A).await;
        assert_eq!(answer_ips(&home), ips(&["1.1.1.1", "1.2.2.2"]));
        let mixed = exchange(&client, "mixed.example", RecordType::A).await;
        assert_eq!(answer_ips(&mixed), ips(&["9.9.9.2"]));
        let none = exchange(&client, "none.example", RecordType::A).await;
        assert_eq!(answer_ips(&none), ips(&["9.9.9.3"]));

        for (rules, message) in [
            (
                serde_json::json!([{ "domain": "a", "ip_match_all": true, "server": "home" }]),
                "dns.rules[0]: ip_match_all: matches an evaluated response",
            ),
            (
                serde_json::json!([
                    { "domain": "a", "action": "evaluate", "server": "home" },
                    { "match_response": true, "ip_cidr": "1.0.0.0/8", "ip_match_all": true,
                      "invert": true, "server": "home" }
                ]),
                "dns.rules[1]: ip_match_all: not with invert",
            ),
        ] {
            let err = with_rules(rules.clone()).err().unwrap().to_string();
            assert!(err.contains(message), "{}: {}", rules, err);
        }
    }

    #[tokio::test]
    async fn a_fakeip_server_answers_https_with_no_records() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15" }
                ],
                "rules": [{ "query_type": ["A", "AAAA", "HTTPS", "SVCB"], "server": "fake" }]
            } })
            .to_string(),
        )
        .unwrap();
        let client = DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
        for ty in [RecordType::HTTPS, RecordType::SVCB] {
            let answer = exchange(&client, "a.example", ty).await;
            assert_eq!(answer.response_code(), ResponseCode::NoError);
            assert!(answer.answers().is_empty());
        }
        let mx = exchange(&client, "a.example", RecordType::MX).await;
        assert_eq!(mx.response_code(), ResponseCode::ServFail);
    }

    /// A server's own client subnet goes over the one the rules or
    /// `dns.client_subnet` set.
    #[tokio::test]
    async fn a_server_s_client_subnet_goes_over_the_rules() {
        let (port, seen) = subnet_server().await;
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "udp", "tag": "ecs", "server": "127.0.0.1", "server_port": port,
                      "client_subnet": "1.1.1.1/24" },
                    { "type": "udp", "tag": "plain", "server": "127.0.0.1",
                      "server_port": port }
                ],
                "client_subnet": "192.0.2.1",
                "rules": [{ "domain": "plain.example", "server": "plain" }],
                "final": "ecs"
            } })
            .to_string(),
        )
        .unwrap();
        let client = DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
        exchange(&client, "a.example", RecordType::A).await;
        exchange(&client, "plain.example", RecordType::A).await;
        let prefix = |p: &str| Some(p.parse::<crate::config::model::Prefix>().unwrap());
        assert_eq!(
            *seen.lock().unwrap(),
            [prefix("1.1.1.0/24"), prefix("192.0.2.1/32")]
        );
        let err = error(serde_json::json!([
            { "type": "local", "tag": "l", "client_subnet": "1.1.1.1/24" }
        ]));
        assert!(err.contains("client_subnet"), "{}", err);
    }

    /// A server that respects the rules may go through any outbound the
    /// routing rules name, and so needs none of them to resolve through it.
    #[test]
    fn a_server_that_respects_the_rules_is_checked_against_every_route() {
        let config = |final_outbound: &str, proxy_extra: serde_json::Value| {
            let mut proxy = serde_json::json!({
                "type": "socks", "tag": "proxy", "server": "proxy.example", "server_port": 1080
            });
            for (k, v) in proxy_extra.as_object().unwrap() {
                proxy[k] = v.clone();
            }
            serde_json::json!({
                "dns": { "servers": [
                    { "type": "udp", "tag": "remote", "server": "8.8.8.8",
                      "respect_rules": true },
                    { "type": "local", "tag": "local" }
                ] },
                "outbounds": [proxy, { "type": "direct", "tag": "direct" }],
                "route": { "rules": [{ "domain": "a.example", "outbound": "direct" }],
                           "final": final_outbound }
            })
        };
        let err = loops(config("proxy", serde_json::json!({})))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("dns server [remote] -> outbound [proxy] -> dns server [remote]"),
            "{}",
            err
        );
        loops(config("direct", serde_json::json!({}))).unwrap();
        loops(config("proxy", serde_json::json!({ "domain_resolver": "local" }))).unwrap();

        // Skipping the default resolver, the rules resolve for it again.
        let mut skipped = config(
            "proxy",
            serde_json::json!({ "skip_default_domain_resolver": true }),
        );
        skipped["route"]["default_domain_resolver"] = "local".into();
        let err = loops(skipped.clone()).unwrap_err().to_string();
        assert!(err.contains("outbound [proxy] -> dns server [remote]"), "{}", err);
        skipped["outbounds"][0]
            .as_object_mut()
            .unwrap()
            .remove("skip_default_domain_resolver");
        loops(skipped).unwrap();

        let err = error(serde_json::json!([
            { "type": "udp", "server": "8.8.8.8", "respect_rules": true, "detour": "proxy" }
        ]));
        assert!(err.contains("respect_rules: not with a detour"), "{}", err);
    }

    /// A UDP server answering the `n`th A query with 10.0.0.`n`, TTL
    /// `ttl`, or with no records when `empty`; and how many it got.
    async fn counting_server(
        ttl: u32,
        empty: bool,
    ) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = count.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let nth = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                let request = Message::from_vec(&buf[..n]).unwrap();
                let ip: IpAddr = format!("10.0.0.{}", nth).parse().unwrap();
                let ips = if empty { vec![] } else { vec![ip] };
                let reply = DnsClient::reply(&request, &ips, ttl);
                let _ = socket.send_to(&reply.to_vec().unwrap(), peer).await;
            }
        });
        (port, count)
    }

    fn cache_client(port: u16, dns: serde_json::Value) -> anyhow::Result<std::sync::Arc<DnsClient>> {
        let mut dns = dns;
        dns["servers"] = serde_json::json!([
            { "type": "udp", "server": "127.0.0.1", "server_port": port }
        ]);
        let mut config =
            crate::config::Config::from_json(&serde_json::json!({ "dns": dns }).to_string())?;
        let dns = std::mem::take(&mut config.dns);
        Ok(DnsClient::new(&dns, Default::default(), &Default::default())?.into_arc())
    }

    fn asked(count: &std::sync::atomic::AtomicUsize) -> usize {
        count.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[tokio::test]
    async fn optimistic_gives_the_expired_answer_and_asks_again_behind() {
        let (port, count) = counting_server(1, false).await;
        let client = cache_client(port, serde_json::json!({ "optimistic": true })).unwrap();
        let first = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&first), ips(&["10.0.0.1"]));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        // Expired: given still, with a TTL of 1, while asked again.
        let stale = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&stale), ips(&["10.0.0.1"]));
        assert_eq!(stale.answers()[0].ttl, 1);
        for _ in 0..100 {
            if asked(&count) == 2 && client.cache_stats().entries == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let fresh = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&fresh), ips(&["10.0.0.2"]));
        assert_eq!(asked(&count), 2);
        let stats = client.cache_stats();
        assert_eq!((stats.hits, stats.stale_hits, stats.misses), (1, 1, 1));
    }

    #[tokio::test]
    async fn without_optimistic_an_expired_answer_is_asked_for_again() {
        let (port, count) = counting_server(1, false).await;
        let client = cache_client(port, serde_json::json!({})).unwrap();
        exchange(&client, "a.example", RecordType::A).await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let again = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&again), ips(&["10.0.0.2"]));
        assert_eq!(asked(&count), 2);
    }

    #[tokio::test]
    async fn a_rule_can_leave_the_optimistic_cache_out() {
        let (port, count) = counting_server(1, false).await;
        let client = cache_client(
            port,
            serde_json::json!({
                "optimistic": { "enabled": true, "timeout": "1h" },
                "rules": [{ "domain": "a.example", "action": "route-options",
                            "disable_optimistic_cache": true }],
            }),
        )
        .unwrap();
        exchange(&client, "a.example", RecordType::A).await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let again = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&again), ips(&["10.0.0.2"]));
        assert_eq!(asked(&count), 2);
    }

    #[tokio::test]
    async fn an_answer_without_records_or_soa_is_not_kept_nor_is_any_without_cache() {
        let (port, count) = counting_server(300, true).await;
        let client = cache_client(port, serde_json::json!({})).unwrap();
        exchange(&client, "a.example", RecordType::A).await;
        exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(asked(&count), 2);

        let (port, count) = counting_server(300, false).await;
        let client = cache_client(port, serde_json::json!({ "disable_cache": true })).unwrap();
        exchange(&client, "a.example", RecordType::A).await;
        exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(asked(&count), 2);

        // Kept, and cleared.
        let (port, count) = counting_server(300, false).await;
        let client = cache_client(port, serde_json::json!({})).unwrap();
        exchange(&client, "a.example", RecordType::A).await;
        exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(asked(&count), 1);
        client.clear_cache();
        exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(asked(&count), 2);
    }

    #[test]
    fn optimistic_is_not_with_disable_cache_or_disable_expire() {
        for (other, message) in [
            ("disable_cache", "not with dns.disable_cache"),
            ("disable_expire", "not with dns.disable_expire"),
        ] {
            let err = cache_client(53, serde_json::json!({ "optimistic": true, other: true }))
                .err()
                .unwrap()
                .to_string();
            assert!(err.contains(message), "{}", err);
        }
        // Off, it is no conflict.
        cache_client(
            53,
            serde_json::json!({ "optimistic": false, "disable_cache": true }),
        )
        .unwrap();
    }

    fn rules_client(rules: serde_json::Value) -> anyhow::Result<DnsClient> {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [
                    { "type": "hosts", "tag": "one", "predefined": {
                        "a.example": "10.0.0.1", "b.example": "10.0.0.2" } },
                    { "type": "hosts", "tag": "two", "predefined": {
                        "a.example": "10.0.0.9", "b.example": "10.0.0.2" } },
                    { "type": "hosts", "tag": "other", "predefined": {
                        "a.example": "192.0.2.1", "b.example": "192.0.2.2" } },
                ],
                "final": "other",
                "rules": rules,
            } })
            .to_string(),
        )?;
        DnsClient::new(&config.dns, Default::default(), &Default::default())
    }

    #[tokio::test]
    async fn a_predefined_answer_carries_its_records() {
        let client = rules_client(serde_json::json!([
            { "domain_suffix": "local.example", "action": "predefined",
              "answer": ["*.local.example. IN A 10.1.1.1", "fixed.example. 60 IN A 10.1.1.2"],
              "ns": "local.example. IN NS ns.local.example." },
            { "domain": "gone.example", "action": "predefined", "rcode": "NXDOMAIN" },
        ]))
        .unwrap();
        let m = exchange(&client, "x.local.example", RecordType::A).await;
        assert!(m.metadata.authoritative);
        assert_eq!(m.answers().len(), 2);
        // The wildcard takes the name asked for; the other keeps its own.
        assert_eq!(m.answers()[0].name.to_utf8(), "x.local.example.");
        assert_eq!(m.answers()[0].ttl, 3600);
        assert_eq!(m.answers()[1].name.to_utf8(), "fixed.example.");
        assert_eq!(m.answers()[1].ttl, 60);
        assert_eq!(m.name_servers().len(), 1);
        // Not under `local.example.`: the name stays.
        let apex = exchange(&client, "local.example", RecordType::A).await;
        assert_eq!(apex.answers()[0].name.to_utf8(), "*.local.example.");
        // The instance's own lookups get its addresses.
        assert_eq!(
            client.lookup("y.local.example").await.unwrap(),
            ips(&["10.1.1.1", "10.1.1.2"])
        );
        let gone = exchange(&client, "gone.example", RecordType::A).await;
        assert_eq!(gone.response_code(), hickory_proto::op::ResponseCode::NXDomain);
        assert!(gone.answers().is_empty());
    }

    #[tokio::test]
    async fn a_rule_matches_the_records_of_a_response() {
        let client = rules_client(serde_json::json!([
            { "domain_suffix": "example", "action": "evaluate", "server": "one" },
            { "match_response": true,
              "response_answer": ["a.example. IN A 10.0.0.1"], "action": "respond" },
        ]))
        .unwrap();
        // one answers a.example with 10.0.0.1: responded with.
        let a = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&a), ips(&["10.0.0.1"]));
        // b.example with 10.0.0.2: no match; final.
        let b = exchange(&client, "b.example", RecordType::A).await;
        assert_eq!(answer_ips(&b), ips(&["192.0.2.2"]));
    }

    #[tokio::test]
    async fn rules_a_logical_one_combines_match_responses_of_their_own() {
        let client = rules_client(serde_json::json!([
            { "domain_suffix": "example", "action": "evaluate", "server": "one", "tag": "1" },
            { "domain_suffix": "example", "action": "evaluate", "server": "two", "tag": "2" },
            // Both agree: answer with the first's.
            { "type": "logical", "mode": "and", "rules": [
                { "match_response": "1", "ip_cidr": "10.0.0.2/32" },
                { "match_response": "2", "response_answer": "b.example. IN A 10.0.0.2" },
              ], "match_response": "1", "action": "respond" },
            // A sub-rule naming a response that did not come matches only
            // inverted.
            { "type": "logical", "mode": "or", "rules": [
                { "match_response": "1", "ip_cidr": "10.0.0.1/32", "invert": true },
              ], "action": "route", "server": "two" },
        ]))
        .unwrap();
        let b = exchange(&client, "b.example", RecordType::A).await;
        assert_eq!(answer_ips(&b), ips(&["10.0.0.2"]));
        // one and two disagree on a.example; one's is 10.0.0.1, so the
        // inverted rule does not match either: final.
        let a = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&a), ips(&["192.0.2.1"]));
    }

    #[test]
    fn record_mistakes_name_the_field() {
        for (rules, message) in [
            (
                serde_json::json!([{ "domain": "x", "action": "predefined",
                                     "answer": ["x. IN A 1.2.3"] }]),
                "dns.rules[0].answer[0]: record",
            ),
            (
                serde_json::json!([{ "domain_suffix": "example", "action": "evaluate", "server": "one" },
                                   { "match_response": true, "response_ns": ["bad"],
                                     "action": "respond" }]),
                "dns.rules[1].response_ns[0]: record",
            ),
            (
                serde_json::json!([{ "domain": "x", "response_answer": "x. IN A 1.1.1.1",
                                     "server": "one" }]),
                "response_answer: matches an evaluated response, and needs match_response",
            ),
            (
                serde_json::json!([{ "domain_suffix": "example", "action": "evaluate", "server": "one" },
                                   { "type": "logical", "mode": "and", "rules": [
                                       { "match_response": true, "ip_match_all": true,
                                         "ip_cidr": "10.0.0.0/8" }],
                                     "server": "one" }]),
                "ip_match_all: sail takes it on a rule",
            ),
            (
                serde_json::json!([{ "type": "logical", "mode": "and", "rules": [
                                       { "match_response": "t", "ip_cidr": "10.0.0.0/8" }],
                                     "server": "one" }]),
                "no evaluate rule before it is tagged [t]",
            ),
            (
                serde_json::json!([{ "domain": "x", "answer": "x. IN A 1.1.1.1",
                                     "server": "one" }]),
                "answer: not with action route",
            ),
        ] {
            let err = rules_client(rules).err().unwrap().to_string();
            assert!(err.contains(message), "{}: {}", message, err);
        }
    }

    /// A UDP server answering every A query with `ip`, or with no records
    /// without one, after `delay`; and how many it got.
    async fn slow_server(
        ip: Option<&str>,
        delay: Duration,
    ) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let socket = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = socket.local_addr().unwrap().port();
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (counter, ips): (_, Vec<IpAddr>) =
            (count.clone(), ip.iter().map(|ip| ip.parse().unwrap()).collect());
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let request = Message::from_vec(&buf[..n]).unwrap();
                let reply = DnsClient::reply(&request, &ips, 60).to_vec().unwrap();
                let socket = socket.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&reply, peer).await;
                });
            }
        });
        (port, count)
    }

    /// As the published sing-box 1.14 template has it: two servers
    /// evaluated at once, the first to answer with an address responded
    /// with, else a route.
    fn racing(slow: u16, fast: u16, other: u16, speculative: bool) -> DnsClient {
        let udp = |tag: &str, port: u16| {
            serde_json::json!({ "type": "udp", "tag": tag, "server": "127.0.0.1",
                                "server_port": port })
        };
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": {
                "servers": [udp("slow", slow), udp("fast", fast), udp("other", other)],
                "rules": [
                    { "domain_suffix": "example", "action": "evaluate", "server": "slow",
                      "tag": "s" },
                    { "domain_suffix": "example", "action": "evaluate", "server": "fast",
                      "tag": "f" },
                    // A domain condition would satisfy the destination
                    // on its own, as in sing-box, where ip_accept_any is
                    // one of the destination's conditions.
                    { "match_response": "s", "ip_accept_any": true, "action": "respond",
                      "race": true },
                    { "match_response": "f", "ip_accept_any": true, "action": "respond",
                      "race": true },
                    { "domain_suffix": "example", "action": "route", "server": "other",
                      "speculative": speculative },
                ],
                "final": "other",
            } })
            .to_string(),
        )
        .unwrap();
        DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap()
    }

    #[tokio::test]
    async fn the_first_race_rule_to_match_decides() {
        let (slow, _) = slow_server(Some("10.0.0.1"), Duration::from_millis(400)).await;
        let (fast, _) = slow_server(Some("10.0.0.2"), Duration::from_millis(10)).await;
        let (other, count) = slow_server(Some("10.0.0.3"), Duration::ZERO).await;
        let client = racing(slow, fast, other, false);
        let started = std::time::Instant::now();
        let answer = exchange(&client, "a.example", RecordType::A).await;
        // The fast one's, without waiting for the slow one.
        assert_eq!(answer_ips(&answer), ips(&["10.0.0.2"]));
        assert!(started.elapsed() < Duration::from_millis(300), "{:?}", started.elapsed());
        // The route after the races was held, and never sent.
        assert_eq!(asked(&count), 0);
    }

    #[tokio::test]
    async fn a_race_rule_that_does_not_match_leaves_it_to_the_others() {
        // The fast one answers with no address: the slow one's decides.
        let (slow, _) = slow_server(Some("10.0.0.1"), Duration::from_millis(100)).await;
        let (fast, _) = slow_server(None, Duration::ZERO).await;
        let (other, count) = slow_server(Some("10.0.0.3"), Duration::ZERO).await;
        let answer = exchange(&racing(slow, fast, other, false), "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&answer), ips(&["10.0.0.1"]));
        assert_eq!(asked(&count), 0);

        // Neither answers with one: the route after them, once both came.
        let (slow, _) = slow_server(None, Duration::from_millis(100)).await;
        let (fast, _) = slow_server(None, Duration::ZERO).await;
        let (other, count) = slow_server(Some("10.0.0.3"), Duration::ZERO).await;
        let answer = exchange(&racing(slow, fast, other, false), "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&answer), ips(&["10.0.0.3"]));
        assert_eq!(asked(&count), 1);
    }

    #[tokio::test]
    async fn a_speculative_route_is_sent_while_the_races_are_pending() {
        // The races are lost after 300ms; the route's query went out
        // meanwhile, and its answer is used then.
        let (slow, _) = slow_server(None, Duration::from_millis(300)).await;
        let (fast, _) = slow_server(None, Duration::from_millis(300)).await;
        let (other, count) = slow_server(Some("10.0.0.3"), Duration::from_millis(250)).await;
        let client = racing(slow, fast, other, true);
        let started = std::time::Instant::now();
        let answer = exchange(&client, "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&answer), ips(&["10.0.0.3"]));
        assert_eq!(asked(&count), 1);
        // Not 300ms and then 250ms more.
        assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());

        // Won by a race: the speculative answer is not used.
        let (slow, _) = slow_server(Some("10.0.0.1"), Duration::from_millis(50)).await;
        let (fast, _) = slow_server(None, Duration::from_millis(50)).await;
        let (other, _) = slow_server(Some("10.0.0.3"), Duration::from_millis(200)).await;
        let answer = exchange(&racing(slow, fast, other, true), "a.example", RecordType::A).await;
        assert_eq!(answer_ips(&answer), ips(&["10.0.0.1"]));
    }

    #[test]
    fn race_mistakes_name_the_rule() {
        for (rules, message) in [
            (
                serde_json::json!([{ "domain": "x", "server": "one", "race": true }]),
                "race: a race rule matches an evaluated response, and needs match_response",
            ),
            (
                serde_json::json!([{ "domain_suffix": "example", "action": "evaluate",
                                     "server": "one" },
                                   { "match_response": true, "ip_accept_any": true,
                                     "server": "one", "race": true, "speculative": true }]),
                "race: not with speculative",
            ),
            (
                serde_json::json!([{ "domain": "x", "action": "reject", "speculative": true }]),
                "speculative: not with action reject",
            ),
        ] {
            let err = rules_client(rules).err().unwrap().to_string();
            assert!(err.contains(message), "{}: {}", message, err);
        }
    }
}
