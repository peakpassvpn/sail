//! `sail::embed::RuleSet`: sing-box's headless rule-sets, read and matched
//! for a host by the code sail routes with.
#![cfg(feature = "rule-set")]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use sail::embed::{ErrorKind, MatchInput, Network, RuleSet, RuleSetFormat};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rule_set");

/// A probe of `expected.json`, as the router's own test has it: to port
/// 443 of an address, or of a name.
fn input(probe: &str) -> MatchInput {
    match probe.parse::<IpAddr>() {
        Ok(ip) => MatchInput::new(443).ip(ip),
        Err(_) => MatchInput::new(443).domain(probe),
    }
}

fn source(json: serde_json::Value) -> Result<RuleSet, sail::embed::Error> {
    RuleSet::from_bytes(json.to_string().as_bytes(), RuleSetFormat::Source)
}

/// sing-box compiled the `.srs` fixtures from the `.json` ones, and
/// `sing-box rule-set match` gave `expected.json`: a host's rule-set, of
/// either form and by bytes or by path, matches as sing-box does.
#[test]
fn a_hosts_rule_set_matches_as_sing_box_does() {
    let expected: HashMap<String, HashMap<String, bool>> =
        serde_json::from_slice(&std::fs::read(format!("{}/expected.json", FIXTURES)).unwrap())
            .unwrap();
    assert!(!expected.is_empty());
    for (name, probes) in &expected {
        for file in [
            format!("{}/{}.json", FIXTURES, name),
            format!("{}/{}.srs", FIXTURES, name),
        ] {
            let set = RuleSet::from_path(&file).unwrap_or_else(|e| panic!("{}: {}", file, e));
            assert!(!set.is_empty(), "{}", file);
            let wrong: Vec<&String> = probes
                .iter()
                .filter(|(probe, matched)| set.matches(&input(probe)) != **matched)
                .map(|(probe, _)| probe)
                .collect();
            assert!(wrong.is_empty(), "{}: wrong: {:?}", file, wrong);
        }
    }
}

/// Ports, networks, sources, `invert` and logical rules, as a routing
/// rule's conditions.
#[test]
fn a_hosts_rule_set_matches_ports_networks_sources_and_logic() {
    let set = source(serde_json::json!({
        "version": 3,
        "rules": [
            { "domain_suffix": ["example.com"], "port": [443], "network": ["tcp"] },
            { "ip_cidr": ["10.0.0.0/8"], "port_range": ["1000:2000"] },
            { "type": "logical", "mode": "and", "rules": [
                { "source_ip_cidr": ["192.168.1.0/24"] },
                { "domain_keyword": ["video"], "invert": true },
            ]},
        ],
    }))
    .unwrap();
    let to = |port: u16| MatchInput::new(port);
    assert!(set.matches(&to(443).domain("www.example.com")));
    assert!(!set.matches(&to(80).domain("www.example.com")));
    assert!(!set.matches(&to(443).domain("www.example.com").network(Network::Udp)));
    assert!(set.matches(&to(1500).ip("10.1.2.3".parse().unwrap())));
    assert!(!set.matches(&to(2500).ip("10.1.2.3".parse().unwrap())));
    // An address the name resolved to, given beside it.
    assert!(set.matches(
        &to(1500)
            .domain("internal.test")
            .ip("10.9.9.9".parse().unwrap())
    ));
    let lan: SocketAddr = "192.168.1.7:5000".parse().unwrap();
    assert!(set.matches(&to(8080).domain("news.test").source(lan)));
    assert!(!set.matches(&to(8080).domain("video.test").source(lan)));
    assert!(!set.matches(&to(8080).domain("news.test")));
}

/// A condition a host's input cannot carry is refused as the rule-set is
/// read, naming the rule, rather than never matching; so is what does not
/// read, and a path whose format its extension does not tell.
#[test]
fn what_a_host_cannot_match_is_refused_as_it_is_read() {
    let refused = |json: serde_json::Value| source(json).unwrap_err();
    let e = refused(serde_json::json!({
        "version": 3,
        "rules": [
            { "domain": ["a.test"] },
            { "type": "logical", "mode": "or", "rules": [
                { "domain": ["b.test"] },
                { "process_name": ["curl"] },
            ]},
        ],
    }));
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    assert!(
        e.message().contains("rules[1].rules[1].process_name"),
        "{}",
        e
    );
    for field in [
        serde_json::json!({ "query_type": ["A"] }),
        serde_json::json!({ "package_name": ["com.example"] }),
        serde_json::json!({ "wifi_ssid": ["home"] }),
        serde_json::json!({ "ip_asn": [13335] }),
        serde_json::json!({ "network_is_expensive": true }),
    ] {
        let name = field.as_object().unwrap().keys().next().unwrap().clone();
        let e = refused(serde_json::json!({ "version": 3, "rules": [field] }));
        assert!(e.message().contains(&format!("rules[0].{}", name)), "{}", e);
    }

    let e = RuleSet::from_bytes(b"SRS\x01not zlib", RuleSetFormat::Binary).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    let e = source(serde_json::json!({ "version": 99, "rules": [] })).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    let e = RuleSet::from_path(format!("{}/geoip-telegram.mrs", FIXTURES)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    let e = RuleSet::from_path(format!("{}/missing.srs", FIXTURES)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Io);
    // Its extension aside, a file of a format named.
    let set = RuleSet::from_path_as(format!("{}/ips.srs", FIXTURES), RuleSetFormat::Binary);
    assert!(set.is_ok());
}
