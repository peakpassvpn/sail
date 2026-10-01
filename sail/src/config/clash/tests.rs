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
    reality-opts: { public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0, short-id: "0a" }
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
    assert_eq!(
        vless["tls"]["reality"]["public_key"],
        "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
    );
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
        ["rules[7]: after MATCH, where no connection gets; ignored"]
    );
}

#[test]
fn the_controller_is_the_clash_api() {
    let config = load(
        "mode: global\n\
         external-controller: 127.0.0.1:9090\n\
         external-controller-tls: 127.0.0.1:9443\n\
         secret: s3cret\n\
         external-ui: ui\n\
         external-ui-name: xd\n\
         external-ui-url: https://example.com/ui.zip\n\
         external-controller-cors: { allow-origins: [https://a.example], allow-private-network: false }\n",
    );
    let api = serde_json::to_value(config.clash_api.as_ref().unwrap()).unwrap();
    assert_eq!(
        api,
        serde_json::json!({
            "external_controller": "127.0.0.1:9090",
            "secret": "s3cret",
            "external_ui": "ui/xd",
            "external_ui_download_url": "https://example.com/ui.zip",
            "access_control_allow_origin": ["https://a.example"],
            "default_mode": "Global",
        })
    );
    assert_eq!(
        config.warnings,
        ["external-controller-tls: sail does not implement this field; ignored"]
    );

    // Mihomo's CORS defaults: any origin, and private networks.
    let config =
        load("external-controller: ':9090'\nexternal-controller-cors: { allow-origins: ['*'] }\n");
    let api = config.clash_api.unwrap();
    assert_eq!(api.external_controller.as_deref(), Some(":9090"));
    assert!(api.access_control_allow_origin.is_empty());
    assert!(api.access_control_allow_private_network);
    assert_eq!(api.default_mode.as_deref(), Some("Rule"));

    let err = error("external-ui: ui\nexternal-ui-name: ../x\n");
    assert!(err.contains("external-ui-name"), "{}", err);
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
            "proxies: [{ name: a, type: trojan, server: s, port: 1, password: p, name-cert-verify: b }]",
            "proxies[0].name-cert-verify: sail does not implement this field yet",
        ),
        (
            "proxy-groups: [{ name: G, type: select, proxies: [nowhere] }]",
            "proxy-groups[0].proxies[0]: no proxy or group is named \"nowhere\"",
        ),
        (
            "proxy-groups: [{ name: G, type: select, use: [p], proxies: [DIRECT] }]",
            "proxy-groups[0].use[0]: no proxy-provider is named \"p\"",
        ),
        ("rules: [\"DOMAIN,a.example,Nowhere\"]", "rules[0]: no proxy or group is named \"Nowhere\""),
        ("rules: [\"DSCP,4,DIRECT\"]", "rules[0]: sail does not implement DSCP rules yet"),
        (
            "dns: { enable: true, nameserver: ['dhcp://en0'] }",
            "dns.nameserver[0]: sail does not implement dhcp:// servers yet",
        ),
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
fn a_shadow_tls_plugin_is_an_outbound_the_proxy_goes_through() {
    let config = load(
        r#"
proxies:
  - name: st
    type: ss
    server: st.example.com
    port: 443
    cipher: aes-128-gcm
    password: pw
    client-fingerprint: firefox
    dialer-proxy: hop
    interface-name: en0
    smux: { enabled: true }
    plugin: shadow-tls
    plugin-opts: { host: www.example.com, password: stpw, version: 3, skip-cert-verify: true }
  - { name: hop, type: socks5, server: 127.0.0.1, port: 1080 }
proxy-groups:
  - { name: all, type: select, include-all: true }
rules: ["MATCH,all"]
"#,
    );
    let ss = &outbound(&config, "st").options;
    assert_eq!(ss["detour"], "st (shadow-tls)");
    assert!(ss.get("bind_interface").is_none());
    assert_eq!(ss["multiplex"]["enabled"], true);
    let shadow_tls = outbound(&config, "st (shadow-tls)");
    assert_eq!(shadow_tls.protocol, "shadowtls");
    assert_eq!(
        serde_json::Value::Object(shadow_tls.options.clone().into_iter().collect()),
        serde_json::json!({
            "server": "st.example.com",
            "server_port": 443,
            "version": 3,
            "password": "stpw",
            "detour": "hop",
            "bind_interface": "en0",
            "tls": {
                "enabled": true,
                "server_name": "www.example.com",
                "insecure": true,
                "alpn": ["h2", "http/1.1"],
                "utls": { "enabled": true, "fingerprint": "firefox" }
            }
        })
    );
    // Groups take the proxies Mihomo has, not what sail makes for them.
    let all = &outbound(&config, "all").options;
    assert_eq!(all["outbounds"], serde_json::json!(["hop", "st"]));
}

#[test]
fn shadow_tls_plugin_mistakes_name_the_field() {
    let proxy = |opts: &str| {
        format!(
            "proxies: [{{ name: st, type: ss, server: s, port: 443, cipher: aes-128-gcm, \
             password: pw, plugin: shadow-tls, plugin-opts: {{ {} }} }}]\nrules: [\"MATCH,st\"]\n",
            opts
        )
    };
    assert_eq!(
        error(&proxy("host: a.example, password: p")),
        "proxies[0].plugin-opts.version: ShadowTLS v1/v2 are not supported; use version 3"
    );
    assert_eq!(
        error(&proxy("password: p, version: 3")),
        "proxies[0].plugin-opts.host: missing"
    );
    // The handshake server's certificate, pinned.
    let config = load(&proxy(
        "host: a.example, password: p, version: 3, fingerprint: 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89'",
    ));
    let shadow_tls = config
        .outbounds
        .iter()
        .find(|o| o.protocol == "shadowtls")
        .expect("the shadowtls outbound");
    assert_eq!(
        shadow_tls.options["tls"]["certificate_sha256"],
        serde_json::json!(["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"])
    );
    assert!(error(&proxy(
        "host: a.example, password: p, version: 3, fingerprint: chrome"
    ))
    .contains("plugin-opts.fingerprint: `fingerprint` is used for TLS certificate pinning"));
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
fn no_resolve_reaches_the_resolve_on_demand() {
    let config = load(
        "rules:\n\
         - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n\
         - AND,((IP-CIDR,172.16.0.0/12,no-resolve),(NETWORK,TCP)),REJECT\n\
         - IP-CIDR,192.168.0.0/16,DIRECT\n",
    );
    let rules = rules(&config);
    assert_eq!(rules[0]["no_resolve"], true);
    assert_eq!(rules[1]["rules"][0]["no_resolve"], true);
    // Only a rule that would resolve arms it.
    assert_eq!(
        rules[2],
        serde_json::json!({ "action": "resolve", "on_demand": true, "ignore_failure": true })
    );
    assert!(rules[3].get("no_resolve").is_none());
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
    // The NOT of an IP rule resolves first, once it has an address to
    // match.
    assert_eq!(rules[2]["action"], "resolve");
    assert_eq!(rules[2]["on_demand"], true);
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

#[test]
fn rule_providers_are_rule_sets() {
    let config = load(
        "proxy-groups: [{ name: P, type: select, proxies: [DIRECT] }]\n\
         rule-providers:\n\
         \x20 cn: { type: http, behavior: domain, format: mrs, url: 'https://example.com/cn.mrs', interval: 86400 }\n\
         \x20 ips: { type: http, behavior: ipcidr, format: text, url: 'https://example.com/ip.txt', proxy: P,\n\
         \x20        header: { Authorization: [Bearer t] }, size-limit: 1000 }\n\
         \x20 local: { type: file, behavior: classical, path: ./rules/local.yaml }\n\
         \x20 mine: { type: inline, behavior: domain, payload: ['+.a.example', '.b.example', '*.c.example', d.example] }\n\
         rules:\n\
         - RULE-SET,cn,DIRECT\n\
         - RULE-SET,ips,P,no-resolve\n\
         - RULE-SET,local,P\n\
         - RULE-SET,mine,REJECT\n\
         - GEOSITE,geolocation-!cn,P\n\
         - GEOIP,LAN,DIRECT\n\
         - MATCH,P\n",
    );
    let sets: Vec<serde_json::Value> = config
        .route
        .rule_set
        .iter()
        .map(|s| serde_json::to_value(s).unwrap())
        .collect();
    let set = |tag: &str| {
        sets.iter()
            .find(|s| s["tag"] == serde_json::json!([tag]) || s["tag"] == tag)
            .unwrap_or_else(|| panic!("{} in {:#?}", tag, sets))
            .clone()
    };
    let cn = set("cn");
    assert_eq!(
        (
            cn["type"].as_str(),
            cn["format"].as_str(),
            cn["behavior"].as_str()
        ),
        (Some("remote"), Some("mrs"), Some("domain"))
    );
    assert_eq!(
        config.route.rule_set[0].update_interval,
        Some(std::time::Duration::from_secs(86400))
    );
    assert_eq!(cn["download_detour"], "DIRECT");
    let ips = set("ips");
    assert_eq!(ips["http_client"]["detour"], "P");
    assert_eq!(
        ips["http_client"]["headers"]["Authorization"],
        serde_json::json!(["Bearer t"])
    );
    assert_eq!(set("local")["type"], "local");
    let mine = set("mine");
    assert_eq!(
        mine["rules"][0]["domain_suffix"],
        serde_json::json!(["a.example", ".b.example"])
    );
    assert_eq!(mine["rules"][0]["domain"], serde_json::json!(["d.example"]));
    let geosite = set("geosite:geolocation-!cn");
    assert_eq!(
        geosite["url"],
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-%21cn.mrs"
    );
    assert_eq!(set("geoip:private")["behavior"], "ipcidr");

    // A set of addresses resolves first, unless no-resolve: the classical
    // one does, and the GEOIP one.
    let rules = rules(&config);
    let resolve = rules.iter().position(|r| r["action"] == "resolve").unwrap();
    assert_eq!(rules[resolve + 1]["rule_set"], serde_json::json!(["local"]));
    // A resolve armed from there still skips a no-resolve set.
    assert_eq!(rules[resolve - 1]["no_resolve"], true);
    assert!(rules[resolve + 1].get("no_resolve").is_none());
    let geoip = rules
        .iter()
        .find(|r| r["rule_set"] == serde_json::json!(["geoip:private"]));
    assert!(geoip.unwrap().get("no_resolve").is_none());
    assert_eq!(
        config.warnings,
        ["rule-providers.ips.size-limit: sail does not implement this field; ignored"]
    );
}

#[test]
fn rule_provider_mistakes_name_the_field() {
    for (yaml, message) in [
        (
            "rule-providers: { a: { type: http, behavior: classical, format: mrs, url: 'https://x/a.mrs' } }",
            "rule-providers.a.format: an mrs rule-provider is of domains or IP prefixes",
        ),
        ("rule-providers: { a: { type: http, format: text, url: 'https://x/a' } }", "rule-providers.a.behavior: missing"),
        (
            "rule-providers: { a: { type: http, behavior: domain, url: 'https://x/a', proxy: nowhere } }",
            "rule-providers.a.proxy: no proxy or group is named \"nowhere\"",
        ),
        ("rules: [\"RULE-SET,nowhere,DIRECT\"]", "rules[0]: no rule-provider is named \"nowhere\""),
        ("rules: [\"GEOSITE,../x,DIRECT\"]", "is no geosite list"),
    ] {
        let err = error(yaml);
        assert!(err.contains(message), "{}\n  => {}", yaml, err);
    }
}

const PROVIDERS: &str = r#"
proxies:
  - { name: hk-1, type: socks5, server: 127.0.0.1, port: 1080 }
  - { name: jp-1, type: socks5, server: 127.0.0.1, port: 1081 }
  - { name: dns-out, type: dns }
proxy-providers:
  sub:
    type: http
    url: https://sub.example.com/clash
    path: ./providers/sub.yaml
    interval: 3600
    proxy: G
    filter: "HK|JP`US"
    exclude-type: "vmess|ssr"
    dialer-proxy: jp-1
    override: { skip-cert-verify: true, additional-prefix: "[sub] " }
    health-check: { enable: true, url: https://cp.example.com/generate_204, interval: 300 }
  local:
    type: file
    path: ./local.yaml
  held:
    type: inline
    exclude-filter: drop
    override: { additional-suffix: " (held)" }
    payload:
      - { name: kept, type: socks5, server: 127.0.0.1, port: 1082 }
      - { name: drop-me, type: socks5, server: 127.0.0.1, port: 1083 }
proxy-groups:
  - { name: G, type: select, proxies: [DIRECT] }
  - { name: Sub, type: url-test, use: [sub], filter: HK }
  - { name: All, type: select, include-all: true, filter: "hk", exclude-type: Direct }
  - { name: Some, type: fallback, include-all-proxies: true, filter: "^jp", empty-fallback: hk-1 }
rules:
  - MATCH,G
"#;

fn provider(config: &Config, tag: &str) -> serde_json::Value {
    let p = config
        .outbound_providers
        .iter()
        .find(|p| p.tag == tag)
        .unwrap_or_else(|| panic!("no provider [{}]", tag));
    serde_json::to_value(p).unwrap()
}

#[test]
fn proxy_providers_are_outbound_providers() {
    let config = load(PROVIDERS);
    let sub = provider(&config, "sub");
    assert_eq!(sub["type"], "remote");
    assert_eq!(sub["url"], "https://sub.example.com/clash");
    assert_eq!(
        config.outbound_providers[0].update_interval,
        Some(std::time::Duration::from_secs(3600))
    );
    assert_eq!(sub["download_detour"], "G");
    assert_eq!(sub["filter"], serde_json::json!(["HK|JP", "US"]));
    assert_eq!(sub["exclude_type"], serde_json::json!(["vmess", "ssr"]));
    assert_eq!(sub["detour"], "jp-1");
    assert_eq!(sub["override"]["skip-cert-verify"], true);
    assert!(sub.get("path").is_none());
    let passed_over = load(
        "proxy-providers: { p: { type: file, path: a, override: { client-fingerprint: chrome } } }",
    );
    assert!(
        passed_over
            .warnings
            .iter()
            .any(|w| w.contains("proxy-providers.p.override.client-fingerprint")),
        "{:?}",
        passed_over.warnings
    );
    assert!(config
        .warnings
        .iter()
        .any(|w| w.contains("proxy-providers.sub.health-check")));

    let local = provider(&config, "local");
    assert_eq!(local["type"], "local");
    assert_eq!(local["path"], "./local.yaml");

    // Picked and changed here, as Mihomo does once it has read them.
    let held = provider(&config, "held");
    assert_eq!(held["type"], "inline");
    let tags: Vec<&str> = held["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(tags, ["kept (held)"]);
}

#[test]
fn groups_take_the_providers_members() {
    let config = load(PROVIDERS);
    let options = |tag: &str| serde_json::Value::Object(outbound(&config, tag).options.clone());

    let sub = options("Sub");
    assert_eq!(sub["providers"], serde_json::json!(["sub"]));
    assert_eq!(sub["filter"], serde_json::json!(["HK"]));
    assert_eq!(sub["outbounds"], serde_json::json!([]));
    assert_eq!(sub["empty_fallback"], "COMPATIBLE");
    // The provider's health check's URL, the group naming none.
    assert_eq!(sub["url"], "https://cp.example.com/generate_204");

    // Every provider, sorted, and every proxy the filter picks; the filter
    // then goes on to the providers' proxies.
    let all = options("All");
    assert_eq!(
        all["providers"],
        serde_json::json!(["held", "local", "sub"])
    );
    assert_eq!(all["outbounds"], serde_json::json!(["hk-1"]));
    assert_eq!(all["filter"], serde_json::json!(["hk"]));
    assert_eq!(all["exclude_type"], serde_json::json!(["Direct"]));

    let some = options("Some");
    assert_eq!(some["outbounds"], serde_json::json!(["jp-1"]));
    assert!(some.get("providers").is_none());
    assert!(some.get("filter").is_none());
    assert!(some.get("empty_fallback").is_none());

    // A group with nothing to take falls back as Mihomo's does.
    let config = load(
        "proxies: [{ name: a, type: socks5, server: 127.0.0.1, port: 1 }]\n\
         proxy-groups: [{ name: G, type: select, include-all-proxies: true, filter: nothing }]",
    );
    let g = serde_json::Value::Object(outbound(&config, "G").options.clone());
    assert_eq!(g["outbounds"], serde_json::json!(["COMPATIBLE"]));
    assert_eq!(outbound(&config, "COMPATIBLE").protocol, "direct");
}

#[test]
fn proxy_provider_mistakes_name_the_field() {
    for (yaml, message) in [
        ("proxy-providers: { p: { type: ftp } }", "proxy-providers.p.type: \"ftp\" is none of http, file and inline"),
        ("proxy-providers: { p: { type: http } }", "proxy-providers.p.url: missing"),
        (
            "proxy-providers: { p: { type: http, url: 'https://x/', age-secret-key: k } }",
            "proxy-providers.p.age-secret-key: sail does not implement this field yet",
        ),
        (
            "proxy-providers: { p: { type: http, url: 'https://x/', proxy: nowhere } }",
            "download_detour: outbound [nowhere] does not exist",
        ),
        (
            "proxy-providers: { p: { type: file, path: a } }\n\
             proxy-groups: [{ name: G, type: select, use: [p], empty-fallback: H }, { name: H, type: select, proxies: [DIRECT] }]",
            "proxy-groups[0].empty-fallback: no proxy, not a group, is named \"H\"",
        ),
        (
            "proxy-groups: [{ name: G, type: select }]",
            "proxy-groups[0].proxies: a group of no proxies and no providers",
        ),
    ] {
        let err = error(yaml);
        assert!(err.contains(message), "{}\n  => {}", yaml, err);
    }
}

fn dns_json(config: &Config) -> serde_json::Value {
    serde_json::to_value(&config.dns).unwrap()
}

/// A config as the published templates write them: fake IPs, a policy,
/// and a fallback abroad.
const DNS_TEMPLATE: &str = r#"
proxies:
  - { name: hk, type: socks5, server: hk.example.com, port: 1080 }
proxy-groups:
  - { name: Proxy, type: select, proxies: [hk, DIRECT] }
rule-providers:
  cn: { type: inline, behavior: domain, payload: [+.cn] }
dns:
  enable: true
  # The system's hosts, as the hosts tests have them.
  use-system-hosts: false
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: ['*.lan', '+.local', 'geosite:private', 'rule-set:cn']
  default-nameserver: [223.5.5.5, 119.29.29.29]
  nameserver: ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']
  proxy-server-nameserver: ['https://dns.alidns.com/dns-query']
  nameserver-policy:
    'geosite:cn,apple': ['223.5.5.5']
    '+.google.com': 'https://dns.google/dns-query#Proxy'
    'www.google.com': 'tls://8.8.8.8#h3=false&disable-qtype-65=true'
    'rule-set:cn': rcode://name_error
  fallback: ['tls://1.1.1.1#Proxy']
  fallback-filter: { geoip: true, geoip-code: CN, ipcidr: [240.0.0.0/4], domain: ['+.twitter.com'] }
rules:
  - MATCH,Proxy
"#;

#[test]
fn a_fake_ip_policy_and_fallback_config_lowers_to_rules() {
    let config = load(DNS_TEMPLATE);
    assert_eq!(config.warnings, Vec::<String>::new());
    let dns = dns_json(&config);
    let types = serde_json::json!({ "query_type": ["A", "AAAA", "CNAME"] });
    let fallback = "tls://1.1.1.1#Proxy";
    assert_eq!(
        dns["rules"],
        serde_json::json!([
            // 1. Fake IPs, but for what the filter keeps out.
            { "type": "logical", "mode": "and", "rules": [
                { "query_type": ["A", "AAAA", "HTTPS", "SVCB"] },
                { "type": "logical", "mode": "and", "invert": true, "rules": [
                    { "type": "logical", "mode": "or", "rules": [
                        { "domain_regex": ["^[^.]+\\.lan$"], "domain_suffix": ["local"] },
                        { "rule_set": ["geosite:private", "cn"] }
                    ] }
                ] }
              ], "server": "fake-ip", "rewrite_ttl": 1 },
            // 2. The policy, the most specific domain first.
            { "rule_set": ["geosite:cn", "geosite:apple"], "server": "223.5.5.5" },
            { "type": "logical", "mode": "and", "rules": [
                { "domain": ["www.google.com"] }, { "query_type": [65] }
              ], "action": "predefined" },
            { "domain": ["www.google.com"],
              "server": "tls://8.8.8.8#h3=false&disable-qtype-65=true" },
            { "domain_suffix": ["google.com"], "server": "https://dns.google/dns-query#Proxy" },
            { "rule_set": ["cn"], "action": "predefined", "rcode": "NXDOMAIN" },
            // 3. The fallback's domains, then the fallback filter.
            { "type": "logical", "mode": "and", "rules": [
                types, { "domain_suffix": ["twitter.com"] }
              ], "server": fallback },
            { "query_type": ["A", "AAAA", "CNAME"], "action": "evaluate",
              "server": "dns.nameserver" },
            { "match_response": true, "ip_cidr": ["240.0.0.0/4"], "server": fallback },
            { "match_response": true, "ip_match_all": true, "ip_is_private": true,
              "rule_set": ["geoip:cn"], "action": "respond" },
            { "query_type": ["A", "AAAA", "CNAME"], "server": fallback }
        ])
    );
    // 4. The rest.
    assert_eq!(dns["final"], "dns.nameserver");
    assert_eq!(dns["strategy"], "prefer_ipv4");
    assert_eq!(dns["reverse_mapping"], true);
    let server = |tag: &str| {
        dns["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["tag"] == tag)
            .cloned()
            .unwrap_or_else(|| panic!("no server [{}]", tag))
    };
    assert_eq!(
        server("dns.nameserver"),
        serde_json::json!({ "type": "race", "tag": "dns.nameserver",
            "servers": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"] })
    );
    assert_eq!(
        server("https://dns.google/dns-query#Proxy"),
        serde_json::json!({ "type": "https", "tag": "https://dns.google/dns-query#Proxy",
            "server": "dns.google", "server_port": 443, "path": "/dns-query",
            "detour": "Proxy", "domain_resolver": "dns.default-nameserver" })
    );
    assert_eq!(
        server("dns.default-nameserver")["servers"],
        serde_json::json!(["223.5.5.5", "119.29.29.29"])
    );
    assert_eq!(
        server("fake-ip"),
        serde_json::json!({ "type": "fakeip", "tag": "fake-ip", "inet4_range": "198.18.0.0/16" })
    );
    // The proxies' servers resolve through proxy-server-nameserver, and
    // DIRECT as a query goes.
    assert_eq!(
        config
            .route
            .default_domain_resolver
            .as_ref()
            .unwrap()
            .server,
        "https://dns.alidns.com/dns-query"
    );
    assert_eq!(
        outbound(&config, "DIRECT").options["skip_default_domain_resolver"],
        true
    );
}

/// What the lowered DNS is checked for when it is built.
#[cfg(all(feature = "rule-set", feature = "dns-doh"))]
#[test]
fn a_lowered_dns_builds_and_has_no_loop() {
    let config = load(DNS_TEMPLATE);
    let env = crate::runtime::RuntimeEnv::default();
    let rule_sets = crate::app::router::rule_set::RuleSets::load(
        &config.route.rule_set,
        &Default::default(),
        &env,
    )
    .unwrap();
    let client = crate::app::dns::DnsClient::with_rule_sets(
        &config.dns,
        Default::default(),
        &env,
        &rule_sets,
    )
    .unwrap();
    client.check_loops(&config).unwrap();
}

fn dns_of(fields: &str) -> Config {
    load(&format!(
        "proxies:\n  - {{ name: hk, type: socks5, server: 192.0.2.1, port: 1080 }}\n\
         rule-providers:\n  ips: {{ type: inline, behavior: ipcidr, payload: [10.0.0.0/8] }}\n\
         dns:\n  enable: true\n  use-system-hosts: false\n{}",
        fields
    ))
}

fn dns_error(fields: &str) -> String {
    error(&format!(
        "proxies:\n  - {{ name: hk, type: socks5, server: 192.0.2.1, port: 1080 }}\n\
         rule-providers:\n  ips: {{ type: inline, behavior: ipcidr, payload: [10.0.0.0/8] }}\n\
         dns:\n  enable: true\n{}",
        fields
    ))
}

#[test]
fn servers_are_read_as_mihomo_reads_them() {
    let config = dns_of(
        "  nameserver:\n\
         \x20   - 1.1.1.1\n\
         \x20   - '2001:db8::1'\n\
         \x20   - 'udp://9.9.9.9:5353'\n\
         \x20   - 'tcp://[2001:db8::2]'\n\
         \x20   - 'tls://dns.example:8853#hk'\n\
         \x20   - 'https://1.0.0.1/q?x=1#h3=true&skip-cert-verify=true'\n\
         \x20   - 'quic://94.140.14.14#en0'\n\
         \x20   - 'https://8.8.8.8/dns-query#ecs=1.2.3.4/24&ecs-override=true'\n\
         \x20   - system\n\
         \x20   - 'dhcp://system'\n\
         \x20   - '8.8.4.4#DIRECT'\n\
         \x20   - '8.8.4.4#%E4%BB%A3%E7%90%86'\n",
    );
    let dns = dns_json(&config);
    let servers: Vec<serde_json::Value> = dns["servers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["type"] != "race" && s["tag"] != "114.114.114.114")
        .cloned()
        .collect();
    assert_eq!(
        serde_json::Value::Array(servers),
        serde_json::json!([
            { "type": "udp", "tag": "1.1.1.1", "server": "1.1.1.1", "server_port": 53 },
            { "type": "udp", "tag": "2001:db8::1", "server": "2001:db8::1", "server_port": 53 },
            { "type": "udp", "tag": "udp://9.9.9.9:5353", "server": "9.9.9.9",
              "server_port": 5353 },
            { "type": "tcp", "tag": "tcp://[2001:db8::2]", "server": "2001:db8::2",
              "server_port": 53 },
            // Mihomo's default resolvers, for the domain.
            { "type": "udp", "tag": "223.5.5.5", "server": "223.5.5.5", "server_port": 53 },
            { "type": "udp", "tag": "8.8.8.8", "server": "8.8.8.8", "server_port": 53 },
            { "type": "udp", "tag": "1.0.0.1", "server": "1.0.0.1", "server_port": 53 },
            { "type": "tls", "tag": "tls://dns.example:8853#hk", "server": "dns.example",
              "server_port": 8853, "detour": "hk",
              "domain_resolver": "dns.default-nameserver" },
            { "type": "h3", "tag": "https://1.0.0.1/q?x=1#h3=true&skip-cert-verify=true",
              "server": "1.0.0.1", "server_port": 443, "path": "/q",
              "tls": { "insecure": true } },
            // A name no proxy has is an interface's.
            { "type": "quic", "tag": "quic://94.140.14.14#en0", "server": "94.140.14.14",
              "server_port": 853, "bind_interface": "en0" },
            { "type": "https", "tag": "https://8.8.8.8/dns-query#ecs=1.2.3.4/24&ecs-override=true",
              "server": "8.8.8.8", "server_port": 443, "path": "/dns-query",
              "client_subnet": "1.2.3.4/24" },
            { "type": "local", "tag": "system" },
            { "type": "udp", "tag": "8.8.4.4#DIRECT", "server": "8.8.4.4", "server_port": 53 },
            { "type": "udp", "tag": "8.8.4.4#%E4%BB%A3%E7%90%86", "server": "8.8.4.4",
              "server_port": 53, "bind_interface": "代理" }
        ])
    );
    assert_eq!(dns["final"], "dns.nameserver");
    // The instance resolves IPv6 too, with the top-level `ipv6` on by
    // default; its clients get IPv4 alone without `dns.ipv6: true`.
    assert_eq!(dns["strategy"], "prefer_ipv4");
    assert_eq!(dns["client_strategy"], "ipv4_only");
    let both = dns_json(&dns_of(
        "  ipv6: true
  nameserver: [1.1.1.1]
",
    ));
    assert!(both.get("client_strategy").is_none());
    let config = dns_of("  enhanced-mode: normal\n  nameserver: [1.1.1.1]\n");
    let dns = dns_json(&config);
    assert_eq!(dns["reverse_mapping"], serde_json::Value::Null);
    assert_eq!(dns["final"], "1.1.1.1");
}

#[test]
fn dns_mistakes_name_the_field() {
    for (fields, message) in [
        (
            "  nameserver: []\n",
            "dns.nameserver: no server, which Mihomo requires",
        ),
        (
            "  nameserver: ['rcode://nope']\n",
            "dns.nameserver[0]: rcode://nope: not a code",
        ),
        (
            "  nameserver: ['rcode://refused']\n",
            "dns.nameserver: an rcode:// server",
        ),
        (
            "  nameserver: ['http://1.1.1.1/dns-query']\n",
            "dns.nameserver[0]: sail does not implement DNS over plain HTTP",
        ),
        (
            "  nameserver: ['ts://node']\n",
            "dns.nameserver[0]: sail does not implement ts:// servers",
        ),
        (
            "  nameserver: ['doq://1.1.1.1']\n",
            "dns.nameserver[0]: \"doq\" is not a scheme",
        ),
        (
            "  nameserver: ['tls://1.1.1.1#name-cert-verify=a.example']\n",
            "dns.nameserver[0]: name-cert-verify: sail does not implement",
        ),
        (
            "  nameserver: ['1.1.1.1:0']\n",
            "dns.nameserver[0]: \"1.1.1.1:0\": \"0\" is not a port",
        ),
        (
            "  default-nameserver: ['tls://dns.example']\n  nameserver: ['tls://dns.google']\n",
            "dns.default-nameserver[0]: \"tls://dns.example\" is not an address",
        ),
        (
            "  respect-rules: true\n  nameserver: [1.1.1.1]\n",
            "dns.proxy-server-nameserver: missing, which Mihomo requires with respect-rules",
        ),
        (
            "  nameserver: [1.1.1.1]\n  proxy-server-nameserver: [1.1.1.1]\n\
             \x20 proxy-server-nameserver-policy: { '+.example': 8.8.8.8 }\n",
            "dns.proxy-server-nameserver-policy.\"+.example\": sail does not implement this field \
             yet",
        ),
        (
            "  nameserver: [1.1.1.1]\n  nameserver-policy: { 'rule-set:ips': 8.8.8.8 }\n",
            "dns.nameserver-policy.\"rule-set:ips\": \"ips\" is a rule-set of IP prefixes",
        ),
        (
            "  nameserver: [1.1.1.1]\n  nameserver-policy: { 'rule-set:nowhere': 8.8.8.8 }\n",
            "dns.nameserver-policy.\"rule-set:nowhere\": no rule-provider is named \"nowhere\"",
        ),
        (
            "  nameserver: [1.1.1.1]\n  enhanced-mode: mapping\n",
            "dns.enhanced-mode: \"mapping\" is none of normal, fake-ip and redir-host",
        ),
        (
            "  nameserver: [1.1.1.1]\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: grey\n",
            "dns.fake-ip-filter-mode: \"grey\" is none of blacklist, whitelist and rule",
        ),
        (
            "  nameserver: [1.1.1.1]\n  enhanced-mode: fake-ip\n  fake-ip-range: ''\n",
            "dns.fake-ip-range: missing, and so is fake-ip-range6",
        ),
        (
            "  nameserver: [1.1.1.1]\n  enhanced-mode: fake-ip\n  fake-ip-range: 'fc00::/18'\n",
            "dns.fake-ip-range: \"fc00::/18\" is not an IPv4 prefix",
        ),
        (
            "  nameserver: [1.1.1.1]\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: rule\n\
             \x20 fake-ip-filter: ['DOMAIN,a.example,proxy']\n",
            "dns.fake-ip-filter[0]: \"proxy\" is neither fake-ip nor real-ip",
        ),
        (
            "  nameserver: [1.1.1.1]\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: rule\n\
             \x20 fake-ip-filter: ['IP-CIDR,10.0.0.0/8,real-ip']\n",
            "dns.fake-ip-filter[0]: IP-CIDR rules match no domain",
        ),
        (
            "  nameserver: [1.1.1.1]\n  enhanced-mode: fake-ip\n\
             \x20 fake-ip-filter: ['rule-set:ips']\n",
            "dns.fake-ip-filter[0]: \"ips\" is a rule-set of IP prefixes",
        ),
    ] {
        let err = dns_error(fields);
        assert!(err.contains(message), "{}\n  => {}", fields, err);
    }
}

#[test]
fn what_sail_does_not_implement_of_dns_is_warned_of() {
    let config = dns_of(
        "  nameserver: ['tls://1.1.1.1#disable-reuse=true&x=1', 'https://1.1.1.1/q#ecs=nope']\n\
         \x20 prefer-h3: true\n  use-hosts: true\n\
         \x20 listen: 0.0.0.0:53\n  ipv6-timeout: 100\n  cache-algorithm: arc\n\
         \x20 fallback-lazy-query: false\n  cache-max-size: 1000\n  cache: true\n",
    );
    assert_eq!(
        config.warnings,
        [
            "dns.prefer-h3: sail does not implement this field; ignored",
            "dns.cache-algorithm: sail does not implement this field; ignored",
            "tls://1.1.1.1#disable-reuse=true&x=1: disable-reuse: sail does not implement this \
             parameter; ignored",
            "tls://1.1.1.1#disable-reuse=true&x=1: x: not a parameter Mihomo takes; ignored",
            "https://1.1.1.1/q#ecs=nope: ecs=\"nope\" is no address or prefix; ignored, as by \
             Mihomo",
            "dns.ipv6-timeout: sail does not implement this field; ignored",
            "dns.cache: not a field Mihomo takes; ignored",
        ]
    );
    // cache-max-size, but sail keeps 1024 answers at least.
    assert_eq!(config.dns.cache_capacity, Some(1024));
    // Unset, Mihomo's 4096.
    assert_eq!(dns_of("").dns.cache_capacity, Some(4096));
}

#[test]
fn fake_ip_filter_modes() {
    let fake = |fields: &str| {
        let config = dns_of(&format!(
            "  nameserver: [1.1.1.1]\n  enhanced-mode: fake-ip\n  fake-ip-ttl: 30\n{}",
            fields
        ));
        let dns = dns_json(&config);
        let rules: Vec<serde_json::Value> = dns["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["server"] == "fake-ip")
            .cloned()
            .collect();
        (rules, dns)
    };
    let types = serde_json::json!({ "query_type": ["A", "AAAA", "HTTPS", "SVCB"] });
    // Mihomo's default filter.
    let (rules, dns) = fake("");
    assert_eq!(
        rules[0]["rules"][1]["rules"][0]["domain"],
        serde_json::json!([
            "dns.msftnsci.com",
            "www.msftnsci.com",
            "www.msftconnecttest.com"
        ])
    );
    assert_eq!(rules[0]["rewrite_ttl"], 30);
    // No IPv6 range unless set.
    let fake_ip = dns["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["type"] == "fakeip")
        .unwrap();
    assert_eq!(fake_ip["inet6_range"], serde_json::Value::Null);
    // An empty filter keeps nothing out.
    let (rules, _) = fake("  fake-ip-filter: []\n  fake-ip-range6: 'fdfe:dcba:9876::1/64'\n");
    let mut all = types.clone();
    all["server"] = "fake-ip".into();
    all["rewrite_ttl"] = 30.into();
    assert_eq!(rules, [all.clone()]);
    // Whitelist: only the filter's.
    let (rules, _) = fake("  fake-ip-filter-mode: whitelist\n  fake-ip-filter: ['+.example']\n");
    assert_eq!(
        rules[0]["rules"],
        serde_json::json!([types, { "domain_suffix": ["example"] }])
    );
    let (rules, _) = fake("  fake-ip-filter-mode: whitelist\n  fake-ip-filter: []\n");
    assert!(rules.is_empty());
    // Rules, in order: a real-ip rule holds off the fake-ip ones after it.
    let (rules, _) = fake(
        "  fake-ip-filter-mode: rule\n  fake-ip-filter:\n\
         \x20   - DOMAIN-SUFFIX,lan,real-ip\n\
         \x20   - DOMAIN,a.lan.example,fake-ip\n\
         \x20   - GEOSITE,cn,real-ip\n",
    );
    let not_lan = serde_json::json!({ "type": "logical", "mode": "and", "invert": true,
        "rules": [{ "domain_suffix": ["lan"] }] });
    assert_eq!(
        rules,
        [
            serde_json::json!({ "type": "logical", "mode": "and", "rules": [
                types, { "domain": ["a.lan.example"] }, not_lan
            ], "server": "fake-ip", "rewrite_ttl": 30 }),
            serde_json::json!({ "type": "logical", "mode": "and", "rules": [
                types,
                { "type": "logical", "mode": "and", "invert": true, "rules": [
                    { "type": "logical", "mode": "or", "rules": [
                        { "domain_suffix": ["lan"] }, { "rule_set": ["geosite:cn"] }
                    ] }
                ] }
            ], "server": "fake-ip", "rewrite_ttl": 30 }),
        ]
    );
    let (rules, _) = fake("  fake-ip-filter-mode: rule\n  fake-ip-filter: ['MATCH,fake-ip']\n");
    assert_eq!(rules, [all]);
    let (rules, _) = fake("  fake-ip-filter-mode: rule\n  fake-ip-filter: ['MATCH,real-ip']\n");
    assert!(rules.is_empty());
}

#[test]
fn respect_rules_and_where_outbounds_resolve() {
    // The servers of queries that name no proxy go where the rules say;
    // those that resolve outbounds' names do not.
    let config = dns_of(
        "  respect-rules: true\n  nameserver: [1.1.1.1, '8.8.8.8#hk']\n\
         \x20 proxy-server-nameserver: [1.1.1.1]\n\
         \x20 direct-nameserver: [223.5.5.5]\n",
    );
    let dns = dns_json(&config);
    let tags: Vec<&str> = dns["servers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags,
        [
            "1.1.1.1#RULES",
            "8.8.8.8#hk",
            "dns.nameserver",
            "1.1.1.1",
            "223.5.5.5"
        ]
    );
    assert_eq!(dns["servers"][0]["respect_rules"], true);
    assert_eq!(dns["servers"][3]["respect_rules"], serde_json::Value::Null);
    assert_eq!(dns["rules"], serde_json::Value::Null);
    // DIRECT resolves through direct-nameserver alone.
    assert_eq!(
        outbound(&config, "DIRECT").options["domain_resolver"],
        "223.5.5.5"
    );
    assert_eq!(
        outbound(&config, "COMPATIBLE").options["domain_resolver"],
        "223.5.5.5"
    );

    // Following the policy: the policy first, then direct-nameserver.
    let config = dns_of(
        "  nameserver: [1.1.1.1]\n  proxy-server-nameserver: [1.1.1.1]\n\
         \x20 direct-nameserver: [223.5.5.5]\n  direct-nameserver-follow-policy: true\n\
         \x20 nameserver-policy: { '+.example': '9.9.9.9' }\n",
    );
    let dns = dns_json(&config);
    assert_eq!(
        dns["rules"],
        serde_json::json!([
            { "domain_suffix": ["example"], "server": "9.9.9.9" },
            { "outbound": ["DIRECT", "COMPATIBLE"], "server": "223.5.5.5" }
        ])
    );
    assert_eq!(
        outbound(&config, "DIRECT").options["skip_default_domain_resolver"],
        true
    );
    // Without proxy-server-nameserver, everything resolves as a query goes.
    let config = dns_of("  nameserver: [1.1.1.1]\n");
    assert!(config.route.default_domain_resolver.is_none());
    assert!(outbound(&config, "DIRECT").options.is_empty());
}

#[test]
fn off_and_ipv6() {
    let config = load("ipv6: false\ndns: { enable: false, nameserver: [1.1.1.1] }\n");
    assert_eq!(dns_json(&config)["strategy"], "ipv4_only");
    let config = load("dns: { enable: true, ipv6: true, nameserver: [1.1.1.1] }\n");
    assert_eq!(dns_json(&config)["strategy"], "prefer_ipv4");
    let config = load("ipv6: false\ndns: { enable: true, ipv6: true, nameserver: [1.1.1.1] }\n");
    assert_eq!(dns_json(&config)["strategy"], "ipv4_only");
}

const SNIFFER: &str = r#"
rule-providers:
  lan: { type: inline, behavior: ipcidr, payload: [192.168.0.0/16] }
sniffer:
  enable: true
  sniff:
    HTTP: { ports: [80, 8080-8880], override-destination: true }
    QUIC: { ports: [443] }
    TLS: { ports: [443, 8443] }
  override-destination: false
  force-domain: [+.v2ex.com]
  skip-domain: [Mijia Cloud, +.push.apple.com]
  skip-src-address: [rule-set:lan]
  skip-dst-address: [10.0.0.0/8]
rules:
  - MATCH,DIRECT
"#;

/// Every rule, Clash's modes' among them.
fn all_rules(config: &Config) -> Vec<serde_json::Value> {
    config
        .route
        .rules
        .iter()
        .map(|r| serde_json::to_value(r).unwrap())
        .collect()
}

#[test]
fn the_sniffer_is_sniff_rules_before_every_other() {
    let config = load(SNIFFER);
    let rules = all_rules(&config);
    // TLS, HTTP and QUIC, as Mihomo tries them, before Clash's modes.
    let sniffers: Vec<&serde_json::Value> = rules.iter().take(3).map(|r| &r["sniffer"]).collect();
    assert_eq!(
        sniffers,
        [
            &serde_json::json!(["tls"]),
            &serde_json::json!(["http"]),
            &serde_json::json!(["quic"])
        ]
    );
    let http = &rules[1];
    assert_eq!(http["action"], "sniff");
    assert_eq!(http["override_destination"], true);
    assert!(rules[0].get("override_destination").is_none());
    assert_eq!(
        http["skip_rule_set"],
        serde_json::json!(["sniffer:skip-domain"])
    );
    let conditions = http["rules"].as_array().unwrap();
    // An address, or a name force-domain matches.
    assert_eq!(conditions[0]["mode"], "or");
    assert_eq!(
        conditions[0]["rules"][0]["ip_cidr"],
        serde_json::json!(["0.0.0.0/0", "::/0"])
    );
    assert_eq!(
        conditions[0]["rules"][1]["domain_suffix"],
        serde_json::json!(["v2ex.com"])
    );
    // From and to none of the addresses skipped.
    assert_eq!(conditions[1]["rule_set"], serde_json::json!(["lan"]));
    assert_eq!(conditions[1]["rule_set_ip_cidr_match_source"], true);
    assert_eq!(conditions[1]["invert"], true);
    assert_eq!(conditions[2]["ip_cidr"], serde_json::json!(["10.0.0.0/8"]));
    assert_eq!(conditions[2]["invert"], true);
    assert_eq!(conditions[3]["network"], serde_json::json!(["tcp"]));
    assert_eq!(conditions[3]["port"], serde_json::json!([80]));
    assert_eq!(
        conditions[3]["port_range"],
        serde_json::json!(["8080:8880"])
    );
    assert_eq!(rules[2]["rules"][3]["network"], serde_json::json!(["udp"]));
    assert!(config
        .route
        .rule_set
        .iter()
        .any(|s| s.tag.contains(&"sniffer:skip-domain".to_string())));

    // A router takes them, skip_rule_set and all.
    #[cfg(feature = "rule-set")]
    router_takes(&config);
}

#[cfg(feature = "rule-set")]
fn router_takes(config: &Config) {
    let env = crate::runtime::RuntimeEnv::default();
    let sets = crate::app::router::rule_set::RuleSets::load(
        &config.route.rule_set,
        &Default::default(),
        &env,
    )
    .unwrap();
    let dns = crate::app::dns_client::DnsClient::new(&config.dns, Default::default(), &env)
        .unwrap()
        .into_shared();
    crate::app::router::Router::with_rule_sets(
        &config.route,
        dns,
        &env,
        &sets,
        &Default::default(),
    )
    .unwrap();
}

#[test]
fn a_sniffer_off_or_unset_is_no_rule() {
    for yaml in [
        "sniffer: { enable: false, sniff: { NOPE: {} } }\nrules: [\"MATCH,DIRECT\"]",
        "rules: [\"MATCH,DIRECT\"]",
    ] {
        let config = load(yaml);
        assert!(
            all_rules(&config).iter().all(|r| r["action"] != "sniff"),
            "{}",
            yaml
        );
    }
    // Deprecated, and still read.
    let config = load("sniffer: { enable: true, sniffing: [tls], port-whitelist: [443] }\nrules: [\"MATCH,DIRECT\"]");
    assert_eq!(all_rules(&config)[0]["sniffer"], serde_json::json!(["tls"]));
    // parse-pure-ip and force-dns-mapping off, and no force-domain: nothing is sniffed.
    let config = load(
        "sniffer: { enable: true, parse-pure-ip: false, force-dns-mapping: false, sniff: { TLS: {} } }\nrules: [\"MATCH,DIRECT\"]",
    );
    assert!(all_rules(&config).iter().all(|r| r["action"] != "sniff"));
}

#[test]
fn sniffer_mistakes_name_the_field() {
    for (yaml, message) in [
        (
            "sniffer: { enable: true, sniff: { SSH: {} } }",
            "sniffer.sniff.SSH: \"SSH\" is none of TLS, HTTP and QUIC",
        ),
        (
            "sniffer: { enable: true, sniff: { TLS: { ports: [x] } } }",
            "\"x\" is not a port",
        ),
        (
            "sniffer: { enable: true, sniff: { TLS: {} }, skip-dst-address: [10.0.0.1] }",
            "sniffer.skip-dst-address[0]: \"10.0.0.1\" is not an IP prefix",
        ),
        (
            "sniffer: { enable: true, sniff: { TLS: {} }, force-domain: [rule-set:nope] }",
            "sniffer.force-domain[0]: no rule-provider is named \"nope\"",
        ),
    ] {
        let err = error(yaml);
        assert!(err.contains(message), "{}\n  => {}", yaml, err);
    }
}

const TUN: &str = r#"
dns: { enable: false, fake-ip-range: 28.0.0.1/8 }
rule-providers:
  lan: { type: inline, behavior: ipcidr, payload: [192.168.0.0/16] }
sniffer: { enable: true, sniff: { TLS: {} } }
tun:
  enable: true
  stack: mixed
  device: utun9
  auto-route: true
  auto-redirect: true
  strict-route: true
  auto-detect-interface: true
  mtu: 1500
  gso: true
  inet6-address: [fdfe:dcba:9876::1/126]
  dns-hijack: [any:53, tcp://any:53, udp://8.8.8.8:5353]
  route-exclude-address: [10.0.0.0/8]
  route-exclude-address-set: [lan]
  exclude-interface: [lo]
  include-uid: [1000]
rules:
  - IN-TYPE,TUN,DIRECT
  - MATCH,DIRECT
"#;

#[test]
fn tun_is_a_tun_inbound_and_its_dns_hijack_a_rule_before_every_other() {
    let config = load(TUN);
    let tun = config
        .inbounds
        .iter()
        .find(|i| i.tag == "DEFAULT-TUN")
        .expect("the TUN inbound");
    assert_eq!(tun.protocol, "tun");
    let o = serde_json::Value::Object(tun.options.clone());
    assert_eq!(o["interface_name"], "utun9");
    // fake-ip-range's first address, as a /30.
    assert_eq!(
        o["address"],
        serde_json::json!(["28.0.0.1/30", "fdfe:dcba:9876::1/126"])
    );
    assert_eq!(o["mtu"], 1500);
    assert_eq!(o["auto_route"], true);
    assert_eq!(o.get("auto_redirect").is_some(), cfg!(target_os = "linux"));
    assert_eq!(o["strict_route"], true);
    assert_eq!(
        o["route_exclude_address"],
        serde_json::json!(["10.0.0.0/8"])
    );
    // With auto-redirect alone, as Mihomo takes it.
    assert_eq!(
        o.get("route_exclude_address_set"),
        cfg!(target_os = "linux")
            .then(|| serde_json::json!(["lan"]))
            .as_ref()
    );
    assert_eq!(o["exclude_interface"], serde_json::json!(["lo"]));
    assert_eq!(o["include_uid"], serde_json::json!([1000]));
    assert!(config.route.auto_detect_interface);
    assert!(config.warnings.iter().any(|w| w.contains("tun.stack")));
    // As sail's TUN inbound takes it: on Linux, where auto_redirect takes
    // the routes left out; elsewhere that is route management, not
    // implemented yet.
    #[cfg(all(feature = "inbound-tun", target_os = "linux"))]
    {
        let settings = crate::protocol::tun::inbound::options(tun, &Default::default()).unwrap();
        assert_eq!(settings.mtu, 1500);
        assert!(settings.auto_route);
    }

    let rules = all_rules(&config);
    let hijack = &rules[0];
    assert_eq!(hijack["action"], "hijack-dns");
    assert_eq!(
        hijack["rules"][0]["inbound"],
        serde_json::json!(["DEFAULT-TUN"])
    );
    let to = &hijack["rules"][1]["rules"];
    // Port 53 anywhere; the addresses after the device's; the one listed.
    assert_eq!(to[0], serde_json::json!({ "port": [53] }));
    assert_eq!(to[1]["ip_cidr"], serde_json::json!(["28.0.0.2/32"]));
    assert_eq!(
        to[2]["ip_cidr"],
        serde_json::json!(["fdfe:dcba:9876::2/128"])
    );
    assert_eq!(
        to[3],
        serde_json::json!({ "ip_cidr": ["8.8.8.8/32"], "port": [5353] })
    );
    // Then the sniffer's, then Clash's modes'.
    assert_eq!(rules[1]["action"], "sniff");
    assert!(rules
        .iter()
        .any(|r| r["inbound"] == serde_json::json!(["DEFAULT-TUN"]) && r["outbound"] == "DIRECT"));
}

#[test]
fn a_tun_off_is_no_inbound() {
    let config = load(
        "tun: { enable: false, stack: gvisor, exclude-src-port: [1] }\nrules: [\"MATCH,DIRECT\"]",
    );
    assert!(config.inbounds.iter().all(|i| i.protocol != "tun"));
    // Mihomo's default device address, without fake-ip-range.
    let config = load("tun: { enable: true }\nrules: [\"MATCH,DIRECT\"]");
    let tun = config
        .inbounds
        .iter()
        .find(|i| i.protocol == "tun")
        .unwrap();
    assert_eq!(tun.options["address"], serde_json::json!(["198.18.0.1/30"]));
    assert_eq!(tun.options["mtu"], 9000);
}

#[test]
fn tun_mistakes_name_the_field() {
    for (yaml, message) in [
        (
            "tun: { enable: true, exclude-src-port: [1] }",
            "tun.exclude-src-port: sail does not implement this field yet",
        ),
        (
            "tun: { enable: true, dns-hijack: [8.8.8.8] }",
            "tun.dns-hijack[0]: \"8.8.8.8\" names no port",
        ),
        (
            "tun: { enable: true, file-descriptor: 5 }",
            "tun.file-descriptor: 5: sail does not take a device opened elsewhere yet",
        ),
    ] {
        let err = error(yaml);
        assert!(err.contains(message), "{}\n  => {}", yaml, err);
    }
    // Taken, and so checked, with auto-redirect alone, on Linux.
    let yaml = "tun: { enable: true, auto-redirect: true, route-address-set: [nope] }";
    if cfg!(target_os = "linux") {
        assert!(
            error(yaml).contains("tun.route-address-set[0]: no rule-provider is named \"nope\"")
        );
    } else {
        load(yaml);
    }
}

#[test]
fn hosts_answer_before_every_server() {
    let config = load(
        "hosts:\n\
         \x20 dns.google: [8.8.8.8, 8.8.4.4]\n\
         \x20 '+.mcdn.bilivideo.com': 0.0.0.0\n\
         \x20 services.googleapis.cn: services.googleapis.com\n\
         dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [223.5.5.5]\n",
    );
    let dns = dns_json(&config);
    let rules = dns["rules"].as_array().unwrap();
    // Hosts, then the system's, then the fake IPs.
    assert_eq!(rules[0]["server"], "hosts");
    assert_eq!(rules[0]["query_type"], serde_json::json!(["A", "AAAA"]));
    assert_eq!(rules[0]["rewrite_ttl"], 10);
    assert_eq!(
        rules[0]["domain"],
        serde_json::json!(["dns.google", "services.googleapis.cn"])
    );
    assert_eq!(
        rules[0]["domain_suffix"],
        serde_json::json!(["mcdn.bilivideo.com"])
    );
    assert_eq!(rules[1]["action"], "evaluate");
    assert_eq!(rules[1]["server"], "system-hosts");
    assert_eq!(rules[2]["action"], "respond");
    assert_eq!(rules[2]["ip_accept_any"], true);
    assert_eq!(rules[3]["server"], "fake-ip");
    let hosts = dns["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["tag"] == "hosts")
        .unwrap();
    assert_eq!(
        hosts["predefined"]["services.googleapis.cn"],
        "services.googleapis.com"
    );
    assert_eq!(hosts["predefined"]["+.mcdn.bilivideo.com"], "0.0.0.0");
    // The first server stays the final one.
    assert_eq!(dns["final"], "223.5.5.5");

    // Off, the system resolver reads the system's hosts itself.
    let config = load("hosts: { a.example: 10.0.0.1 }\ndns: { enable: false }");
    let dns = dns_json(&config);
    assert_eq!(dns["rules"].as_array().unwrap().len(), 1);
    assert!(dns["servers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["tag"] != "system-hosts"));
    // And as the DNS client builds it.
    crate::app::dns::DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
}

#[test]
fn hosts_mistakes_name_the_field() {
    for (yaml, message) in [
        (
            "hosts: { a.example: { x: 1 } }",
            "hosts.a.example: an address, addresses or a name, not a map",
        ),
        (
            "hosts: { a.example: [1.2.3.4, [x]] }",
            "hosts.a.example: addresses, not a list",
        ),
    ] {
        let err = error(yaml);
        assert!(err.contains(message), "{}\n  => {}", yaml, err);
    }
    let config = load("dns: { enable: true, use-hosts: false }");
    assert!(config
        .warnings
        .iter()
        .any(|w| w.contains("dns.use-hosts: false")));
}

#[test]
fn dns_listen_is_a_direct_inbound_hijacked() {
    for (listen, address) in [
        ("0.0.0.0:1053", Some(("0.0.0.0", 1053))),
        (":53", Some(("::", 53))),
        ("'[::1]:5353'", Some(("::1", 5353))),
        ("127.0.0.1:0", None),
    ] {
        let config = load(&format!(
            "dns: {{ enable: true, listen: {}, nameserver: [223.5.5.5] }}\nrules: [\"MATCH,DIRECT\"]",
            listen
        ));
        let inbound = config.inbounds.iter().find(|i| i.tag == "DEFAULT-DNS");
        match address {
            None => assert!(inbound.is_none(), "{}", listen),
            Some((host, port)) => {
                let inbound = inbound.unwrap_or_else(|| panic!("{}", listen));
                assert_eq!(inbound.protocol, "direct");
                assert_eq!(inbound.listen.as_deref(), Some(host), "{}", listen);
                assert_eq!(inbound.listen_port, Some(port), "{}", listen);
                let rules = all_rules(&config);
                assert_eq!(rules[0]["inbound"], serde_json::json!(["DEFAULT-DNS"]));
                assert_eq!(rules[0]["action"], "hijack-dns");
            }
        }
    }
    let err = error("dns: { enable: true, listen: 'nowhere' }");
    assert!(
        err.contains("dns.listen: \"nowhere\" names no port"),
        "{}",
        err
    );
}

const LISTENERS_CONFIG: &str = r#"
authentication: ["alice:secret"]
proxies:
  - { name: hk, type: socks5, server: 127.0.0.1, port: 1080 }
proxy-groups:
  - { name: HK, type: select, proxies: [hk] }
sniffer: { enable: true, sniff: { TLS: {} } }
listeners:
  - { name: MIXED-HK, type: mixed, port: 50000, proxy: HK }
  - { name: SOCKS-OPEN, type: socks, port: "50001", listen: 127.0.0.1, users: [], udp: true }
  - { name: HTTP-IN, type: http, port: 50002 }
  - { name: SS-IN, type: shadowsocks, listen: "::", port: 10000, udp: true, password: pw, cipher: aes-256-gcm }
  - { name: BLOCKED, type: redir, port: 50003, proxy: REJECT }
rules:
  - IN-TYPE,MIXED,DIRECT
  - MATCH,HK
"#;

#[test]
fn listeners_are_inbounds_and_their_proxy_a_rule() {
    let config = load(LISTENERS_CONFIG);
    let inbound = |tag: &str| {
        config
            .inbounds
            .iter()
            .find(|i| i.tag == tag)
            .unwrap_or_else(|| panic!("no inbound [{}]", tag))
    };
    let mixed = inbound("MIXED-HK");
    assert_eq!(mixed.protocol, "mixed");
    assert_eq!(mixed.listen.as_deref(), Some("0.0.0.0"));
    assert_eq!(mixed.listen_port, Some(50000));
    // authentication's users, where it names none of its own.
    assert_eq!(
        mixed.options["users"],
        serde_json::json!([{ "username": "alice", "password": "secret" }])
    );
    // An empty list: anyone.
    let socks = inbound("SOCKS-OPEN");
    assert_eq!(socks.listen.as_deref(), Some("127.0.0.1"));
    assert!(socks.options.get("users").is_none());
    let ss = inbound("SS-IN");
    assert_eq!(ss.protocol, "shadowsocks");
    assert_eq!(ss.options["method"], "aes-256-gcm");
    assert_eq!(ss.options["password"], "pw");
    assert_eq!(inbound("BLOCKED").protocol, "redirect");

    let rules = all_rules(&config);
    // The sniffer's, then the listeners' proxies, then Clash's modes'.
    assert_eq!(rules[0]["action"], "sniff");
    assert_eq!(rules[1]["inbound"], serde_json::json!(["MIXED-HK"]));
    assert_eq!(rules[1]["outbound"], "HK");
    assert_eq!(rules[2]["inbound"], serde_json::json!(["BLOCKED"]));
    assert_eq!(rules[2]["action"], "reject");
    assert_eq!(rules[3]["clash_mode"], "Global");
    // IN-TYPE names Mihomo's own listeners and those of its type.
    assert!(rules.iter().any(
        |r| r["inbound"] == serde_json::json!(["DEFAULT-MIXED", "MIXED-HK"])
            && r["outbound"] == "DIRECT"
    ));
    // Mihomo's are TCP alone without udp: true.
    assert!(config
        .warnings
        .iter()
        .any(|w| w.contains("listeners[0].udp: not true")));
    assert!(!config
        .warnings
        .iter()
        .any(|w| w.contains("listeners[1].udp")));
}

#[test]
fn listener_mistakes_name_the_field() {
    for (yaml, message) in [
        (
            "listeners: [{ name: A, type: vmess, port: 1 }]",
            "listeners[0].type: sail does not implement \"vmess\" listeners yet",
        ),
        (
            "listeners: [{ type: mixed, port: 1 }]",
            "listeners[0].name: missing",
        ),
        (
            "listeners: [{ name: A, type: mixed, port: 1 }, { name: A, type: socks, port: 2 }]",
            "listeners[1].name: another listener is named \"A\"",
        ),
        (
            "listeners: [{ name: DEFAULT-MIXED, type: mixed, port: 1 }]",
            "another listener is named \"DEFAULT-MIXED\"",
        ),
        (
            "listeners: [{ name: A, type: mixed, port: 100-200 }]",
            "listeners[0].port: \"100-200\": sail takes one port, not ranges, yet",
        ),
        (
            "listeners: [{ name: A, type: mixed, port: 1, proxy: nowhere }]",
            "listeners[0].proxy: no proxy or group is named \"nowhere\"",
        ),
        (
            "listeners: [{ name: A, type: mixed, port: 1, rule: sub }]",
            "listeners[0].rule: sail does not implement this field yet",
        ),
        (
            "listeners: [{ name: A, type: shadowsocks, port: 1, password: p }]",
            "listeners[0].cipher: missing",
        ),
    ] {
        let err = error(yaml);
        assert!(err.contains(message), "{}\n  => {}", yaml, err);
    }
}

#[test]
fn tunnels_forward_to_their_targets() {
    let config = load(
        "proxy-groups: [{ name: G, type: select, proxies: [DIRECT] }]\n\
         tunnels:\n\
         \x20 - { network: [tcp, udp], address: 127.0.0.1:7788, target: jp1.example.com:443, proxy: G }\n\
         \x20 - tcp,127.0.0.1:6553,114.114.114.114:53\n\
         rules: [\"IN-TYPE,TUNNEL,DIRECT\", \"MATCH,REJECT\"]",
    );
    let inbound = |tag: &str| config.inbounds.iter().find(|i| i.tag == tag).unwrap();
    let first = inbound("tunnel:127.0.0.1:7788");
    assert_eq!(first.protocol, "direct");
    assert_eq!(first.listen.as_deref(), Some("127.0.0.1"));
    assert_eq!(first.listen_port, Some(7788));
    assert_eq!(first.options["override_address"], "jp1.example.com");
    assert_eq!(first.options["override_port"], 443);
    assert!(first.options.get("network").is_none());
    let second = inbound("tunnel:127.0.0.1:6553");
    assert_eq!(second.options["network"], "tcp");
    let rules = all_rules(&config);
    // Its proxy's rule before Clash's modes'; the other follows the rules.
    assert_eq!(
        rules[0]["inbound"],
        serde_json::json!(["tunnel:127.0.0.1:7788"])
    );
    assert_eq!(rules[0]["outbound"], "G");
    assert_eq!(rules[1]["clash_mode"], "Global");
    assert!(rules
        .iter()
        .any(|r| r["inbound"]
            == serde_json::json!(["tunnel:127.0.0.1:7788", "tunnel:127.0.0.1:6553"])));
    for (yaml, message) in [
        (
            "tunnels: [\"tcp,127.0.0.1:1\"]",
            "tunnels[0]: \"tcp,127.0.0.1:1\" is not network,address,target and a proxy",
        ),
        (
            "tunnels: [\"sctp,127.0.0.1:1,a:1\"]",
            "tunnels[0]: \"sctp\" is neither tcp nor udp",
        ),
        (
            "tunnels: [{ network: [tcp], address: 127.0.0.1, target: a:1 }]",
            "tunnels[0]: \"127.0.0.1\" names no port",
        ),
        (
            "tunnels: [\"tcp,127.0.0.1:1,a:1,nowhere\"]",
            "tunnels[0].proxy: no proxy or group is named \"nowhere\"",
        ),
    ] {
        let err = error(yaml);
        assert!(err.contains(message), "{}\n  => {}", yaml, err);
    }
}

#[test]
fn lan_ips_keep_the_listeners_that_authenticate_as_mihomo_s() {
    let config = load(
        "mixed-port: 7890\nport: 7891\nredir-port: 7892\n\
         lan-allowed-ips: [192.168.0.0/16, 127.0.0.1/32]\n\
         lan-disallowed-ips: [192.168.1.1/32]\n\
         listeners:\n\
         \x20 - { name: OWN, type: mixed, port: 50000, users: [] }\n\
         \x20 - { name: INHERITS, type: socks, port: 50001 }\n\
         sniffer: { enable: true, sniff: { TLS: {} } }\n\
         rules: [\"MATCH,DIRECT\"]",
    );
    let rules = all_rules(&config);
    let lan = &rules[0];
    assert_eq!(lan["action"], "reject");
    // Mihomo's own that authenticate, and listeners taking authentication's
    // users; not those with users of their own, nor redir.
    assert_eq!(
        lan["rules"][0]["inbound"],
        serde_json::json!(["DEFAULT-HTTP", "DEFAULT-MIXED", "INHERITS"])
    );
    let out_of = &lan["rules"][1]["rules"];
    assert_eq!(
        out_of[0]["source_ip_cidr"],
        serde_json::json!(["192.168.0.0/16", "127.0.0.1/32"])
    );
    assert_eq!(out_of[0]["invert"], true);
    assert_eq!(
        out_of[1]["source_ip_cidr"],
        serde_json::json!(["192.168.1.1/32"])
    );
    // Before the sniffer's.
    assert_eq!(rules[1]["action"], "sniff");

    // Everyone allowed, no one kept out: no rule.
    let config =
        load("mixed-port: 7890\nlan-allowed-ips: [0.0.0.0/0, ::/0]\nrules: [\"MATCH,DIRECT\"]");
    assert!(all_rules(&config).iter().all(|r| r["action"] != "reject"));
    let err = error("mixed-port: 7890\nlan-disallowed-ips: [nope]");
    assert!(
        err.contains("lan-disallowed-ips[0]: \"nope\" is not an IP prefix"),
        "{}",
        err
    );
}

#[test]
fn process_name_regex_and_path_in_bundle() {
    let config = load(
        "rule-providers:\n\
         \x20 cn: { type: http, behavior: domain, format: mrs, url: 'https://x/cn.mrs', path-in-bundle: geo/geosite/cn.mrs }\n\
         rules: [\"PROCESS-NAME-REGEX,.*telegram.*,DIRECT\", \"MATCH,REJECT\"]",
    );
    let rules = rules(&config);
    assert_eq!(
        rules[0]["process_name_regex"],
        serde_json::json!([".*telegram.*"])
    );
    assert!(config
        .warnings
        .iter()
        .any(|w| w.contains("rule-providers.cn.path-in-bundle")));
}

#[test]
fn the_profile_is_sing_box_s_cache_file() {
    let cache = |yaml: &str| {
        let config = load(yaml);
        serde_json::to_value(&config.experimental).unwrap()["cache_file"].clone()
    };
    // Selections kept, as Mihomo keeps them by default.
    assert_eq!(
        cache("rules: [\"MATCH,DIRECT\"]"),
        serde_json::json!({ "enabled": true })
    );
    assert_eq!(
        cache("profile: { store-fake-ip: true }\nrules: [\"MATCH,DIRECT\"]"),
        serde_json::json!({ "enabled": true, "store_fakeip": true })
    );
    assert!(cache("profile: { store-selected: false }\nrules: [\"MATCH,DIRECT\"]").is_null());
    let config =
        load("profile: { store-selected: true, tracing: true }\nrules: [\"MATCH,DIRECT\"]");
    assert!(config
        .warnings
        .iter()
        .any(|w| w.contains("profile.tracing: not a field Mihomo takes")));
}

#[test]
fn the_forks_smart_groups_are_sail_s() {
    let config = load(
        "proxies:\n\
         \x20 - { name: hk, type: socks5, server: 127.0.0.1, port: 1080 }\n\
         \x20 - { name: us, type: socks5, server: 127.0.0.1, port: 1081 }\n\
         proxy-groups:\n\
         \x20 - name: Auto\n\
         \x20   type: smart\n\
         \x20   proxies: [hk, us]\n\
         \x20   policy-priority: 'hk:2;us:0.5;bad;zero:0;(?!x)y:4;a\\:b:1'\n\
         \x20   tolerance: 60\n\
         \x20   timeout: 3000\n\
         \x20   prefer-asn: true\n\
         \x20   uselightgbm: true\n\
         rules: [\"MATCH,Auto\"]",
    );
    let auto = outbound(&config, "Auto");
    assert_eq!(auto.protocol, "smart");
    let o = serde_json::Value::Object(auto.options.clone());
    assert_eq!(o["tolerance"], 60);
    assert_eq!(o["timeout"], "3000ms");
    assert_eq!(o["prefer_asn"], true);
    // The fork's factor, how much more a member is wanted, inverted; its
    // regular expressions as they are; an escaped colon kept.
    assert_eq!(
        o["policy_priority"],
        serde_json::json!([
            { "regex": "hk", "factor": 0.5 },
            { "regex": "us", "factor": 2.0 },
            { "regex": "(?!x)y", "factor": 0.25 },
            { "regex": "a:b", "factor": 1.0 },
        ])
    );
    for field in ["policy-priority", "uselightgbm"] {
        assert!(
            config
                .warnings
                .iter()
                .any(|w| w.contains(&format!("proxy-groups[0].{}", field))),
            "{}: {:?}",
            field,
            config.warnings
        );
    }
}

#[test]
fn a_client_certificate_is_pem_or_a_path() {
    let config = load(
        "proxies:\n\
         \x20 - { name: a, type: trojan, server: s, port: 443, password: p,\n\
         \x20     certificate: certs/client.crt, private-key: /etc/client.key }\n\
         \x20 - { name: b, type: hysteria2, server: s, port: 443, password: p,\n\
         \x20     certificate: \"-----BEGIN CERTIFICATE-----\\nAA\\n-----END CERTIFICATE-----\",\n\
         \x20     private-key: \"-----BEGIN PRIVATE KEY-----\\nAA\\n-----END PRIVATE KEY-----\" }\n",
    );
    let tls = |tag: &str| serde_json::to_value(outbound(&config, tag)).unwrap()["tls"].clone();
    let a = tls("a");
    assert_eq!(a["client_certificate_path"], "certs/client.crt");
    assert_eq!(a["client_key_path"], "/etc/client.key");
    let b = tls("b");
    assert!(b["client_certificate"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(b["client_key"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN PRIVATE KEY-----"));

    let e = error(
        "proxies: [{ name: a, type: trojan, server: s, port: 443, password: p, \
         private-key: \"-----BEGIN PRIVATE KEY-----\" }]",
    );
    assert!(
        e.contains("proxies[0].certificate: needed with private-key"),
        "{}",
        e
    );
    assert!(!e.contains("BEGIN"), "{}", e);
    let e = error(
        "proxies: [{ name: a, type: http, server: s, port: 443, tls: true, certificate: c.crt }]",
    );
    assert!(
        e.contains("proxies[0].private-key: needed with certificate"),
        "{}",
        e
    );
}

#[test]
fn a_null_item_is_none_where_mihomo_drops_it() {
    // Mihomo reads these into lists of strings, and its YAML decoder
    // drops a null item.
    let config = load(
        "mixed-port: 7890\n\
         allow-lan: true\n\
         lan-allowed-ips: [192.168.0.0/16, ~]\n\
         lan-disallowed-ips:\n  -\n\
         dns: { enable: true, nameserver: [1.1.1.1, ~], fake-ip-filter: [~] }\n\
         sub-rules: { s: [~, 'MATCH,DIRECT'] }\n\
         rules:\n  -\n  - SUB-RULE,(NETWORK,tcp),s\n  - MATCH,DIRECT\n",
    );
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
    // A proxy's, a group's or a provider's are read as maps of anything,
    // and keep it, which Mihomo refuses.
    assert_eq!(
        error(
            "proxies: [{ name: a, type: socks5, server: 192.0.2.1, port: 1080 }]\n\
             proxy-groups: [{ name: g, type: select, proxies: [a, ~] }]\n\
             rules: ['MATCH,g']\n"
        ),
        "proxy-groups[0].proxies[1]: a string, not nothing"
    );
}

#[test]
fn interface_name_wins_over_auto_detection() {
    // Mihomo's dialer looks the interface up only without interface-name.
    let config = load(
        "interface-name: en0\n\
         tun: { enable: true, auto-detect-interface: true }\n",
    );
    assert_eq!(config.route.default_interface.as_deref(), Some("en0"));
    assert!(!config.route.auto_detect_interface);
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
}

#[test]
fn network_none_is_tcp() {
    let config = load(
        "proxies: [{ name: a, type: vmess, server: 192.0.2.1, port: 443, cipher: auto,\n\
         \x20 uuid: 1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b, alterId: 0, network: none }]\n",
    );
    assert!(outbound(&config, "a").options.get("transport").is_none());
    assert_eq!(
        error(
            "proxies: [{ name: a, type: vmess, server: 192.0.2.1, port: 443, cipher: auto,\n\
             \x20 uuid: 1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b, network: carrier-pigeon }]\n"
        ),
        "proxies[0].network: \"carrier-pigeon\" is not a network Mihomo takes"
    );
}

#[test]
fn the_global_client_fingerprint_is_mihomo_s_no_more() {
    // Mihomo 1.19 logs an error for it and reads on, fingerprinting no
    // proxy by it.
    let config = load(
        "global-client-fingerprint: chrome\n\
         proxies: [{ name: t, type: trojan, server: 192.0.2.1, port: 443, password: p }]\n",
    );
    assert_eq!(
        config.warnings,
        [
            "global-client-fingerprint: removed from Mihomo; set client-fingerprint directly \
          on the proxy instead; ignored"
        ]
    );
    assert!(outbound(&config, "t").options["tls"].get("utls").is_none());
}

#[test]
fn a_tun_takes_mihomo_s_defaults() {
    let tun = |yaml: &str| {
        let config = load(yaml);
        let tun = config
            .inbounds
            .iter()
            .find(|i| i.tag == "DEFAULT-TUN")
            .expect("the TUN inbound");
        let hijack = all_rules(&config)
            .into_iter()
            .find(|r| r["action"] == "hijack-dns")
            .expect("the hijack rule");
        (
            serde_json::Value::Object(tun.options.clone()),
            config.route.auto_detect_interface,
            hijack,
        )
    };
    // Unset: routes taken, the interface followed, every query to port 53
    // answered.
    let (o, detect, hijack) = tun("tun: { enable: true }\n");
    assert_eq!(o["auto_route"], true);
    assert!(detect);
    assert_eq!(
        hijack["rules"][1]["rules"][0],
        serde_json::json!({ "port": [53] })
    );
    // Set, as set.
    let (o, detect, hijack) = tun(
        "tun: { enable: true, auto-route: false, auto-detect-interface: false, dns-hijack: [] }\n",
    );
    assert_eq!(o["auto_route"], false);
    assert!(!detect);
    assert!(!hijack["rules"][1]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == &serde_json::json!({ "port": [53] })));
}

#[test]
fn a_wildcard_is_a_whole_label() {
    let err = error(
        "dns: { enable: true, enhanced-mode: fake-ip, fake-ip-filter: ['+.a.example', 'time*.b.example'] }\n",
    );
    assert!(
        err.contains("dns.fake-ip-filter[1]: \"time*.b.example\": \"*\" must be a whole label"),
        "{}",
        err
    );
    load("dns: { enable: true, enhanced-mode: fake-ip, fake-ip-filter: ['*.a.example', 'b.*.example'] }\n");
}

#[test]
fn pass_leaves_a_rule_for_the_next() {
    let config = load(
        "proxies: [{ name: A, type: socks5, server: a, port: 1 }]\n\
         proxy-groups:\n\
         - { name: G, type: select, proxies: [PASS, A] }\n\
         - { name: H, type: select, proxies: [G, DIRECT] }\n\
         rules:\n\
         - DOMAIN,a.example,H\n\
         - DOMAIN,b.example,PASS\n\
         - MATCH,PASS\n",
    );
    assert_eq!(outbound(&config, "PASS").protocol, "pass");
    // A rule to PASS itself is none; MATCH,PASS is Mihomo's DIRECT.
    assert!(rules(&config)
        .iter()
        .all(|r| r.get("domain") != Some(&serde_json::json!(["b.example"]))));
    assert_eq!(config.route.final_outbound.as_deref(), Some("DIRECT"));
    // Without a group taking it, there is none.
    let config = load("rules: [\"MATCH,PASS\"]\n");
    assert!(config.outbounds.iter().all(|o| o.tag != "PASS"));

    for (target, message) in [
        ("PASS", "PASS: PASS inside SUB-RULE"),
        ("H", "H: PASS inside SUB-RULE"),
    ] {
        let err = error(&format!(
            "proxy-groups:\n\
             - {{ name: G, type: select, proxies: [PASS, DIRECT] }}\n\
             - {{ name: H, type: select, proxies: [G] }}\n\
             sub-rules:\n\
             \x20 s: [\"DOMAIN,a.example,{}\"]\n\
             rules: [\"SUB-RULE,(NETWORK,tcp),s\", \"MATCH,DIRECT\"]\n",
            target
        ));
        assert!(
            err.contains(&format!("sub-rules.s[0]: {}", message)),
            "{}",
            err
        );
    }
}

#[test]
fn a_select_group_starts_on_its_default_selected() {
    let config = load(
        "proxies: [{ name: A, type: socks5, server: a, port: 1 }]\n\
         proxy-groups:\n\
         - { name: G, type: select, proxies: [DIRECT, A], default-selected: A }\n\
         - { name: H, type: select, proxies: [DIRECT, A], default-selected: B }\n",
    );
    assert_eq!(outbound(&config, "G").options["default"], "A");
    assert!(outbound(&config, "H").options.get("default").is_none());
    assert!(
        config
            .warnings
            .iter()
            .any(|w| w.contains("default-selected: \"B\" is no member")),
        "{:?}",
        config.warnings
    );
}

#[test]
fn a_proxy_s_fingerprint_is_certificate_sha256() {
    let config = load(
        "proxies:\n\
         - { name: T, type: trojan, server: a.example, port: 443, password: p,\n\
         \x20   fingerprint: 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89' }\n",
    );
    assert_eq!(
        outbound(&config, "T").options["tls"]["certificate_sha256"],
        serde_json::json!(["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"])
    );
    // A browser's name belongs in client-fingerprint, as Mihomo says.
    let err = error(
        "proxies: [{ name: T, type: trojan, server: a.example, port: 443, password: p, fingerprint: chrome }]\n",
    );
    assert!(
        err.contains("proxies[0].fingerprint: `fingerprint` is used for TLS certificate pinning")
            && err.contains("use `client-fingerprint`"),
        "{}",
        err
    );
}

/// SOCKS5 over TLS is refused where it is read: the socks outbound has no
/// TLS, and dropping it would send in the clear what was to be encrypted.
#[test]
fn socks5_over_tls_is_refused() {
    let err =
        error("proxies: [{ name: S, type: socks5, server: a.example, port: 1080, tls: true }]\n");
    assert!(
        err.contains("proxies[0].tls: sail does not implement SOCKS5 over TLS yet"),
        "{}",
        err
    );
    load("proxies: [{ name: S, type: socks5, server: a.example, port: 1080, tls: false }]\n");
}
