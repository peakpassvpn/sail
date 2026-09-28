use super::*;

fn load(yaml: &str) -> Config {
    parse(yaml).unwrap()
}

fn error(yaml: &str) -> String {
    format!("{:#}", parse(yaml).unwrap_err())
}

fn outbound<'a>(config: &'a Config, tag: &str) -> &'a crate::config::Outbound {
    config
        .outbounds
        .iter()
        .find(|o| o.tag == tag)
        .unwrap_or_else(|| panic!("no outbound [{}]", tag))
}

const TEMPLATE: &str = r#"
mixed-port: 7890
allow-lan: true
mode: rule
log-level: warning
ipv6: false
external-controller: 127.0.0.1:9090
x-tls: &tls
  skip-cert-verify: false
proxies:
  - name: hk-ss
    type: ss
    server: hk.example.com
    port: "8388"
    cipher: aes-128-gcm
    password: secret
    udp: true
    plugin: obfs
    plugin-opts: { mode: tls, host: bing.com }
  - name: jp-vless
    type: vless
    server: jp.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    flow: xtls-rprx-vision
    tls: true
    servername: jp.example.com
    client-fingerprint: chrome
    reality-opts: { public-key: KEY, short-id: "0a" }
    network: tcp
  - name: us-trojan
    type: trojan
    server: us.example.com
    port: 443
    password: pw
    <<: *tls
    network: ws
    ws-opts: { path: /ws, headers: { Host: cdn.example.com }, max-early-data: 2048 }
  - name: sg-hy2
    type: hysteria2
    server: sg.example.com
    ports: 20000-30000,443
    hop-interval: 30
    password: pw
    up: "50 Mbps"
    down: 200
    obfs: salamander
    obfs-password: ob
    sni: sg.example.com
proxy-groups:
  - name: Proxy
    type: select
    proxies: [Auto, hk-ss, jp-vless, us-trojan, sg-hy2, DIRECT]
    icon: https://example.com/p.png
  - name: Auto
    type: url-test
    proxies: [hk-ss, jp-vless]
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
  - name: Balance
    type: load-balance
    proxies: [hk-ss, sg-hy2]
    strategy: round-robin
    tolerance: 50
rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - DOMAIN-KEYWORD,ads,REJECT
  - DST-PORT,6881-6889/51413,REJECT-DROP
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,8.8.8.8/32,Proxy
  - IN-TYPE,MIXED,Balance
  - MATCH,Proxy
  - DOMAIN,never.example,DIRECT
"#;

#[test]
fn a_template_loads() {
    let config = load(TEMPLATE);
    // The mixed port, on every address.
    assert_eq!(config.inbounds.len(), 1);
    let mixed = &config.inbounds[0];
    assert_eq!(
        (
            mixed.protocol.as_str(),
            mixed.tag.as_str(),
            mixed.listen.as_deref(),
            mixed.listen_port
        ),
        ("mixed", "DEFAULT-MIXED", Some("::"), Some(7890))
    );
    assert_eq!(
        config.dns.strategy,
        crate::config::model::DnsStrategy::Ipv4Only
    );

    let ss = &outbound(&config, "hk-ss").options;
    assert_eq!(outbound(&config, "hk-ss").protocol, "shadowsocks");
    assert_eq!(ss["server_port"], 8388);
    assert_eq!(ss["plugin"], "obfs-local");
    assert_eq!(ss["plugin_opts"], "obfs=tls;obfs-host=bing.com");

    let vless = &outbound(&config, "jp-vless").options;
    assert_eq!(vless["flow"], "xtls-rprx-vision");
    assert_eq!(vless["tls"]["reality"]["public_key"], "KEY");
    assert_eq!(vless["tls"]["utls"]["fingerprint"], "chrome");

    let trojan = &outbound(&config, "us-trojan").options;
    assert_eq!(trojan["tls"]["enabled"], true);
    assert_eq!(trojan["transport"]["type"], "ws");
    assert_eq!(trojan["transport"]["headers"]["Host"], "cdn.example.com");
    assert_eq!(trojan["transport"]["max_early_data"], 2048);

    let hy2 = &outbound(&config, "sg-hy2").options;
    assert_eq!(
        hy2["server_ports"],
        serde_json::json!(["20000:30000", "443:443"])
    );
    assert_eq!(hy2["hop_interval"], "30s");
    assert_eq!(
        (hy2["up_mbps"].clone(), hy2["down_mbps"].clone()),
        (50.into(), 200.into())
    );
    assert_eq!(hy2["obfs"]["type"], "salamander");

    assert_eq!(outbound(&config, "Proxy").protocol, "selector");
    assert_eq!(outbound(&config, "Auto").options["tolerance"], 50);
    assert_eq!(
        outbound(&config, "Balance").options["strategy"],
        "round-robin"
    );
    assert_eq!(outbound(&config, "GLOBAL").protocol, "selector");

    assert_eq!(config.route.final_outbound.as_deref(), Some("Proxy"));
    let actions: Vec<String> = config
        .route
        .rules
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    // The mode rules, then each rule, a resolve before the first IP rule
    // that resolves.
    assert_eq!(actions.len(), 2 + 6 + 1, "{:#?}", actions);
    assert!(actions[6].contains("resolve"), "{}", actions[6]);
    assert_eq!(
        config.warnings,
        [
            "rules[7]: after MATCH, where no connection gets; ignored",
            "external-controller: sail does not implement this field; ignored",
        ]
    );
}

#[test]
fn keys_holding_anchors_are_passed_over_and_others_warned_of() {
    let config = load("mixed-port: 1\nx-filter: &f \"(?i)hk\"\ncfw-latency-url: http://x\nrules: [\"MATCH,DIRECT\"]\n");
    assert_eq!(
        config.warnings,
        ["cfw-latency-url: not a field Mihomo takes; ignored"]
    );
}

#[test]
fn mistakes_name_the_field() {
    for (yaml, message) in [
        ("proxies: [{ name: a, type: ss, server: s, port: 1, password: p }]", "proxies[0].cipher: missing"),
        ("proxies: [{ name: a, type: ssr, server: s, port: 1 }]", "proxies[0].type: sail does not implement \"ssr\" yet"),
        ("proxies: [{ name: DIRECT, type: direct }]", "proxies[0].name: DIRECT is Mihomo's own policy"),
        (
            "proxies: [{ name: a, type: vmess, server: s, port: 1, uuid: u, network: h2 }]",
            "proxies[0].network: sail does not implement the h2 transport yet",
        ),
        (
            "proxies: [{ name: a, type: trojan, server: s, port: 1, password: p, fingerprint: ab }]",
            "proxies[0].fingerprint: sail does not implement this field yet",
        ),
        (
            "proxy-groups: [{ name: G, type: select, proxies: [nowhere] }]",
            "proxy-groups[0].proxies[0]: no proxy or group is named \"nowhere\"",
        ),
        (
            "proxy-groups: [{ name: G, type: select, use: [p], proxies: [DIRECT] }]",
            "proxy-groups[0].use: sail does not implement this field yet",
        ),
        ("rules: [\"DOMAIN,a.example,Nowhere\"]", "rules[0]: no proxy or group is named \"Nowhere\""),
        ("rules: [\"GEOIP,CN,DIRECT\"]", "rules[0]: sail does not implement GEOIP rules yet"),
        ("dns: { enable: true }", "dns: sail does not implement Mihomo's DNS module yet"),
        ("tun: { enable: true }", "tun: sail does not implement this section yet"),
        ("mode: script", "mode: \"script\" is none of rule, global and direct"),
    ] {
        let err = error(yaml);
        assert!(err.contains(message), "{}\n  => {}", yaml, err);
    }
}

#[test]
fn a_reject_proxy_is_a_block() {
    let config = load("proxies: [{ name: 拒绝, type: reject }, { name: 直连, type: direct }]\nrules: [\"MATCH,拒绝\"]\n");
    assert_eq!(outbound(&config, "拒绝").protocol, "block");
    assert_eq!(outbound(&config, "直连").protocol, "direct");
}

#[test]
fn off_sections_and_the_system_resolver() {
    let config = load("dns: { enable: false, nameserver: [1.1.1.1] }\ntun: { enable: false }\nrules: [\"MATCH,DIRECT\"]\n");
    assert_eq!(config.dns.servers[0].kind, "local");
    assert_eq!(config.route.final_outbound.as_deref(), Some("DIRECT"));
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
}

fn rules(config: &Config) -> Vec<serde_json::Value> {
    config
        .route
        .rules
        .iter()
        .skip(2)
        .map(|r| serde_json::to_value(r).unwrap())
        .collect()
}

#[test]
fn logical_rules_are_sail_s() {
    let config = load(
        "rules:\n\
         - AND,((DOMAIN-SUFFIX,example.com),(NETWORK,UDP)),REJECT\n\
         - OR,((DST-PORT,443),(AND,((DOMAIN,a.example),(NOT,((NETWORK,tcp)))))),DIRECT\n\
         - NOT,((IP-CIDR,10.0.0.0/8)),DIRECT\n\
         - DOMAIN-WILDCARD,*.a?.example,REJECT\n",
    );
    let rules = rules(&config);
    assert_eq!(rules[0]["type"], "logical");
    assert_eq!(rules[0]["mode"], "and");
    assert_eq!(rules[0]["rules"][1]["network"], serde_json::json!(["udp"]));
    assert_eq!(rules[1]["mode"], "or");
    assert_eq!(rules[1]["rules"][1]["rules"][1]["invert"], true);
    // The NOT of an IP rule resolves first.
    assert_eq!(rules[2]["action"], "resolve");
    assert_eq!(rules[3]["invert"], true);
    assert_eq!(
        rules[4]["domain_regex"],
        serde_json::json!(["^.*\\.a.\\.example$"])
    );
}

#[test]
fn sub_rules_stand_where_they_are_named() {
    let config = load(
        "sub-rules:\n\
         \x20 outer:\n\
         \x20   - DOMAIN,a.example,DIRECT\n\
         \x20   - SUB-RULE,(NETWORK,udp),inner\n\
         \x20   - DOMAIN,b.example,REJECT\n\
         \x20 inner:\n\
         \x20   - DST-PORT,53,DIRECT\n\
         rules:\n\
         - SUB-RULE,(DOMAIN-SUFFIX,example),outer\n\
         - MATCH,REJECT\n",
    );
    let rules = rules(&config);
    // example AND a.example; example AND udp AND 53; example AND NOT udp
    // AND b.example; and MATCH's reject.
    assert_eq!(rules.len(), 4, "{:#?}", rules);
    assert_eq!(
        rules[0]["rules"][1]["domain"],
        serde_json::json!(["a.example"])
    );
    assert_eq!(rules[1]["rules"][2]["port"], serde_json::json!([53]));
    assert_eq!(rules[2]["rules"][1]["invert"], true);
    assert_eq!(rules[2]["action"], "reject");

    let err = error(
        "sub-rules:\n  a:\n    - SUB-RULE,(NETWORK,tcp),a\nrules:\n  - SUB-RULE,(NETWORK,tcp),a\n",
    );
    assert!(err.contains("a leads back to itself"), "{}", err);
    let err = error("rules:\n  - AND,(DOMAIN,a),DIRECT\n");
    assert!(err.contains("rules[0]: AND:"), "{}", err);
    let err = error("rules:\n  - OR,((MATCH)),DIRECT\n");
    assert!(err.contains("a MATCH rule cannot be within"), "{}", err);
}
