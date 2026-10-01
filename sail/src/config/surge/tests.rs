use serde_json::json;

use super::*;

fn load(text: &str) -> Config {
    parse(text).unwrap_or_else(|e| panic!("{:#}", e))
}

fn error(text: &str) -> String {
    format!("{:#}", parse(text).unwrap_err())
}

fn outbound(config: &Config, tag: &str) -> Value {
    let o = config
        .outbounds
        .iter()
        .find(|o| o.tag == tag)
        .unwrap_or_else(|| panic!("no outbound [{}]", tag));
    serde_json::to_value(o).unwrap()
}

/// The rules, but the one answering DNS queries to Surge's own
/// addresses, which every profile has.
fn rules(config: &Config) -> Vec<Value> {
    config
        .route
        .rules
        .iter()
        .map(|r| serde_json::to_value(r).unwrap())
        .filter(|r| r["ip_cidr"][0] != "198.18.0.2/31")
        .collect()
}

/// A profile of every kind of line this stage reads.
const PROFILE: &str = r#"
#!MANAGED-CONFIG https://example.com/profile.conf interval=86400 strict=true
[General]
loglevel = notify
LogLevel = warning
dns-server = 223.5.5.5, 119.29.29.29:53, system
encrypted-dns-server = https://dns.alidns.com/dns-query, quic://1.1.1.1
ipv6 = false
skip-proxy = 127.0.0.1, 192.168.0.0/16, localhost, *.local
http-listen = 0.0.0.0:6152
socks5-listen = 127.0.0.1:6153
proxy-test-url = http://cp.cloudflare.com/generate_204
test-timeout = 3
udp-policy-not-supported-behaviour = REJECT
tun-excluded-routes = 10.0.0.0/8
hijack-dns = 8.8.8.8:53, *:5353
always-real-ip = *.lan
show-error-page-for-reject = true
made-up-key = 1

[Proxy]
DIRECT = direct
On = direct, interface = en0
Ads = reject-drop
HK = ss, hk.example.com, 8388, encrypt-method=aes-128-gcm, password=pw, obfs=http, obfs-host=bing.com, udp-relay=true, tfo=true
Old = custom, old.example.com, 443, aes-256-gcm, "p,w", https://example.com/SSEncrypt.module
JP = vmess, jp.example.com, 443, username=00000000-0000-0000-0000-000000000001, tls=true, sni=cdn.example.com, ws=true, ws-path=/v, ws-headers=Host:cdn.example.com|X-A:"b"
US = trojan, us.example.com, 443, password=pw, skip-cert-verify=true, underlying-proxy=HK
Web = https, web.example.com, 443, user, pass
Sock = socks5, 10.0.0.1, 1080, udp-relay=false, test-url=http://a/
SG = hysteria2, sg.example.com, 443, password=pw, download-bandwidth=200, port-hopping=20000-30000;443, port-hopping-interval=30, salamander-password=ob
TU = tuic-v5, tu.example.com, 443, uuid=00000000-0000-0000-0000-000000000002, password=pw, alpn=h3
AT = anytls, at.example.com, 443, password=pw
WG = wireguard, section-name = Home, underlying-proxy = HK

[WireGuard Home]
private-key = +H8zw3vdhoAO+jn1DjDgYgxq8CxmhF2WrDfJsqzUzGI=
self-ip = 10.0.0.2
self-ip-v6 = fd00::2
dns-server = 10.0.0.1
mtu = 1280
peer = (public-key = ZJjDQHEGALKKy0jRPsjIFdmvQkD0gwJU8ZPbNpUTuSE=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = wg.example.com:51820, keepalive = 25, client-id = 1/2/3)

[Proxy Group]
Proxy = select, Auto, HK, JP, DIRECT, REJECT-DROP, icon-url=https://example.com/i.png, hidden=true
Auto = url-test, HK, JP, US, interval=300, tolerance=50, timeout=5
Fall = fallback, US, JP, timeout=2
Balance = load-balance, HK, JP, persistent=true
Smart = smart, HK, JP, DIRECT, Proxy, policy-priority="H.:0.5;J:1.3", interval=300, timeout=1.5, evaluate-before-use=true
All = select, include-all-proxies=true, policy-regex-filter=^(HK|JP)$
Mixed = select, Web, include-other-group="All, Fall"
NoUdp = select, Web, Sock
Nothing = select, include-all-proxies=true, policy-regex-filter=^none$

[Rule]
DOMAIN,ads.example.com,Ads
DOMAIN-SUFFIX,Example.com,Proxy // an inline comment
DOMAIN-KEYWORD,google,Proxy,extended-matching
DOMAIN-WILDCARD,*.cdn?.example.net,Proxy
PROCESS-NAME,Telegram,Proxy
DEST-PORT,>=10000,Auto
SRC-PORT,1000-2000,Auto
IN-PORT,6153,DIRECT
SRC-IP,192.168.1.2,DIRECT
PROTOCOL,QUIC,REJECT-NO-DROP
DOMAIN,web.example.com,NoUdp
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
IP-CIDR6,2001:db8::1,DIRECT
GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed
DOMAIN,after.example.com,DIRECT

[MITM]
hostname = *.example.com

[URL Rewrite]
^http://a http://b 302

[Script]
s = type=http-response, pattern=^https://a, script-path=a.js

[Replica]
hide-apple-request = true

[Port Forwarding]
0.0.0.0:6841 localhost:3306 policy=HK

[Unknown Section]
a = b
"#;

#[test]
fn a_profile_loads() {
    let config = load(PROFILE);
    let log = serde_json::to_value(&config.log).unwrap();
    assert_eq!(log["level"], "warn");

    let http = config
        .inbounds
        .iter()
        .find(|i| i.tag == "http-listen")
        .unwrap();
    assert_eq!(http.listen.as_deref(), Some("0.0.0.0"));
    assert_eq!(http.listen_port, Some(6152));

    let hk = outbound(&config, "HK");
    assert_eq!(hk["type"], "shadowsocks");
    assert_eq!(hk["plugin"], "obfs-local");
    assert_eq!(hk["plugin_opts"], "obfs=http;obfs-host=bing.com");
    assert_eq!(outbound(&config, "Old")["password"], "p,w");
    let jp = outbound(&config, "JP");
    assert_eq!(jp["security"], "aes-128-gcm");
    assert_eq!(jp["tls"]["server_name"], "cdn.example.com");
    assert_eq!(jp["transport"]["headers"]["X-A"], "b");
    assert_eq!(outbound(&config, "US")["detour"], "HK");
    assert_eq!(outbound(&config, "US")["tls"]["insecure"], true);
    let web = outbound(&config, "Web");
    assert_eq!(web["username"], "user");
    assert_eq!(web["password"], "pass");
    assert_eq!(web["tls"]["enabled"], true);
    let sg = outbound(&config, "SG");
    assert_eq!(sg["server_ports"], json!(["20000:30000", "443:443"]));
    assert!(sg.get("server_port").is_none());
    assert_eq!(sg["obfs"]["type"], "salamander");
    assert_eq!(outbound(&config, "On")["bind_interface"], "en0");
    assert_eq!(outbound(&config, "Ads")["type"], "block");

    let wg = serde_json::to_value(&config.endpoints[0]).unwrap();
    assert_eq!(wg["tag"], "WG");
    assert_eq!(wg["detour"], "HK");
    assert_eq!(wg["address"], json!(["10.0.0.2/32", "fd00::2/128"]));
    assert_eq!(wg["peers"][0]["reserved"], json!([1, 2, 3]));
    assert_eq!(wg["peers"][0]["allowed_ips"], json!(["0.0.0.0/0", "::/0"]));

    // REJECT-DROP rejects as REJECT in a group.
    assert_eq!(
        outbound(&config, "Proxy")["outbounds"],
        json!(["Auto", "HK", "JP", "DIRECT", "REJECT"])
    );
    let auto = outbound(&config, "Auto");
    assert_eq!(auto["type"], "urltest");
    assert_eq!(auto["url"], "http://cp.cloudflare.com/generate_204");
    assert_eq!(auto["tolerance"], 50);
    assert_eq!(outbound(&config, "Fall")["timeout"], "2s");
    assert_eq!(
        outbound(&config, "Balance")["strategy"],
        "consistent-hashing"
    );
    // Proxies alone.
    let smart = outbound(&config, "Smart");
    assert_eq!(smart["type"], "smart");
    assert_eq!(smart["outbounds"], json!(["HK", "JP"]));
    assert_eq!(
        smart["policy_priority"],
        json!([{ "regex": "H.", "factor": 0.5 }, { "regex": "J", "factor": 1.3 }])
    );
    assert_eq!(smart["timeout"], "1500ms");
    assert_eq!(smart["evaluate_before_use"], true);
    assert!(smart.get("interval").is_none());
    assert_eq!(outbound(&config, "All")["outbounds"], json!(["HK", "JP"]));
    assert_eq!(
        outbound(&config, "Mixed")["outbounds"],
        json!(["Web", "HK", "JP", "US"])
    );
    assert_eq!(outbound(&config, "Nothing")["outbounds"], json!(["DIRECT"]));

    let dns = serde_json::to_value(&config.dns).unwrap();
    assert_eq!(dns["final"], "encrypted-dns-server");
    assert_eq!(dns["strategy"], "ipv4_only");

    let warnings = config.warnings.join("\n");
    for expected in [
        "#!MANAGED-CONFIG",
        "tun-excluded-routes",
        "[General] line 19: made-up-key: not a key Surge takes",
        "HK: tfo",
        "test-url, test-timeout, test-udp of Sock",
        "JP: vmess-aead",
        "after FINAL",
        "[MITM]",
        "[URL Rewrite]",
        "[Script]",
        "[Unknown Section]",
        "[WireGuard Home] line 40: dns-server",
        // Dropped, as every warned field says.
        "not through these servers; ignored",
    ] {
        assert!(
            warnings.contains(expected),
            "{}\n---\n{}",
            expected,
            warnings
        );
    }
    for unexpected in ["skip-proxy", "always-real-ip", "Replica", "Proxy] line 21"] {
        assert!(
            !warnings.contains(unexpected),
            "{}\n---\n{}",
            unexpected,
            warnings
        );
    }
}

#[test]
fn rules_lower_in_order() {
    let config = load(PROFILE);
    let rules = rules(&config);
    let text: Vec<String> = rules.iter().map(|r| r.to_string()).collect();
    let position = |needle: &str| {
        text.iter()
            .position(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("no rule with {}:\n{}", needle, text.join("\n")))
    };
    // First, who may use the listeners, and DNS queries answered here.
    assert!(text[0].contains("source_ip_is_private"), "{}", text[0]);
    // The loopback listener is anyone's.
    assert_eq!(rules[0]["rules"][0]["inbound"], json!(["http-listen"]));
    assert!(text[1].contains("hijack-dns") && text[1].contains("8.8.8.8/32"));
    assert!(text[3].contains("port-forwarding:0.0.0.0:6841") && text[3].contains("\"HK\""));
    assert_eq!(
        rules[position("ads.example.com")],
        json!({ "domain": ["ads.example.com"], "action": "reject", "method": "drop" })
    );
    assert_eq!(
        rules[position("\"example.com\"")]["domain_suffix"],
        json!(["example.com"])
    );
    assert_eq!(
        rules[position("domain_regex")]["domain_regex"],
        json!(["^.*\\.cdn.\\.example\\.net$"])
    );
    assert_eq!(
        rules[position("port_range")]["port_range"],
        json!(["10000:"])
    );
    assert_eq!(
        rules[position("\"inbound\":[\"socks5-listen\"]")]["outbound"],
        "DIRECT"
    );
    // Sniffed first.
    let sniff = position("\"sniff\"");
    let quic = position("\"protocol\":[\"quic\"]");
    assert!(sniff < quic);
    assert_eq!(rules[quic]["no_drop"], true);
    // UDP to a group of proxies without it is rejected.
    let web = position("web.example.com");
    assert_eq!(
        rules[web],
        json!({ "domain": ["web.example.com"], "network": ["udp"], "action": "reject" })
    );
    assert_eq!(rules[web + 1]["outbound"], "NoUdp");
    // Resolved when a rule needs addresses, going on when it fails, as
    // FINAL has dns-failed; not for one with no-resolve.
    let resolve = position("resolve");
    assert_eq!(
        rules[resolve],
        json!({ "action": "resolve", "on_demand": true, "ignore_failure": true })
    );
    assert_eq!(rules[position("10.0.0.0/8")]["no_resolve"], true);
    assert!(rules[position("2001:db8::1/128")]
        .get("no_resolve")
        .is_none());
    assert_eq!(config.route.final_outbound.as_deref(), Some("Proxy"));
    assert!(!text.iter().any(|r| r.contains("after.example.com")));
}

#[test]
fn logical_http_and_early_rules() {
    let config = load(
        "[Rule]\n\
         DOMAIN,a.example,DIRECT\n\
         AND,((DOMAIN-SUFFIX,b.example),(NOT,((DEST-PORT,443)))),REJECT\n\
         USER-AGENT,Instagram*,DIRECT\n\
         URL-REGEX,\"^http://c\\.example/(x|y)\",REJECT\n\
         HOSTNAME-TYPE,IPv6,REJECT\n\
         DOMAIN-SUFFIX,d.example,DIRECT,extended-matching\n\
         IP-ASN,AS13335,DIRECT\n\
         DOMAIN,ad.example,REJECT-DROP,pre-matching\n\
         OR,((PROTOCOL,UDP),(IP-CIDR,10.0.0.0/8,no-resolve)),REJECT,pre-matching\n\
         FINAL,DIRECT\n",
    );
    let rules = rules(&config);
    let expected = [
        // The pre-matching rules first, for TCP.
        json!({ "domain": ["ad.example"], "network": ["tcp"], "action": "reject",
                "method": "drop" }),
        json!({ "type": "logical", "mode": "and", "rules": [
            { "type": "logical", "mode": "or", "rules": [
                { "network": ["udp"] }, { "ip_cidr": ["10.0.0.0/8"], "no_resolve": true },
            ] },
            { "network": ["tcp"] },
        ], "action": "reject" }),
        json!({ "domain": ["a.example"], "outbound": "DIRECT" }),
        json!({ "type": "logical", "mode": "and", "rules": [
            { "domain_suffix": ["b.example"] },
            { "type": "logical", "mode": "and", "invert": true, "rules": [{ "port": [443] }] },
        ], "action": "reject" }),
        // Sniffed where a rule needs it, from here on.
        json!({ "action": "sniff", "on_demand": true,
                "sniffer": ["http", "tls", "quic", "stun"] }),
        json!({ "http_user_agent": ["Instagram*"], "outbound": "DIRECT" }),
        json!({ "url_regex": ["^http://c\\.example/(x|y)"], "action": "reject" }),
        json!({ "ip_version": 6, "action": "reject" }),
        // The SNI and the Host.
        json!({ "action": "sniff", "sniffer": ["http", "tls", "quic"] }),
        json!({ "domain_suffix": ["d.example"], "outbound": "DIRECT" }),
        // Resolved where a rule needs addresses, from the first that may;
        // failing where it does not resolve, as FINAL has no dns-failed.
        json!({ "action": "resolve", "on_demand": true }),
        json!({ "ip_asn": [13335], "outbound": "DIRECT" }),
        json!({ "domain": ["ad.example"], "action": "reject", "method": "drop" }),
        json!({ "type": "logical", "mode": "or", "rules": [
            { "network": ["udp"] }, { "ip_cidr": ["10.0.0.0/8"], "no_resolve": true },
        ], "action": "reject" }),
    ];
    assert_eq!(rules, expected, "{:#?}", rules);
}

#[test]
fn rule_sets_of_files_built_in_and_inline() {
    let config = load(
        "[Ruleset Media]\n\
         RULE-SET,Streaming\n\
         RULE-SET,https://example.com/music.list,no-resolve\n\
         DOMAIN-SUFFIX,video.example // a comment\n\
         [Ruleset Streaming]\n\
         DOMAIN-SUFFIX,stream.example\n\
         IP-CIDR,203.0.113.0/24\n\
         [Rule]\n\
         DOMAIN-SET,https://example.com/ads.txt,REJECT,update-interval=-1\n\
         RULE-SET,SYSTEM,DIRECT\n\
         RULE-SET,https://example.com/cn.list,DIRECT,\"update-interval=43200\"\n\
         RULE-SET,Media,DIRECT\n\
         RULE-SET,LAN,DIRECT,no-resolve\n\
         FINAL,DIRECT\n",
    );
    let rules = rules(&config);
    let text: Vec<String> = rules.iter().map(|r| r.to_string()).collect();
    assert_eq!(rules[0], json!({ "action": "resolve", "on_demand": true }));
    assert_eq!(
        rules[1],
        json!({ "rule_set": ["https://example.com/ads.txt"], "action": "reject" })
    );
    // SYSTEM's names, in place.
    assert!(text[2].contains("\"push.apple.com\"") && text[2].contains("\"DIRECT\""));
    assert!(!text[2].contains("trustd"));
    // A file's rules may be of HTTP: sniffed where one needs it. What they
    // need resolved the router knows once it is read.
    assert_eq!(
        rules[3],
        json!({ "action": "sniff", "on_demand": true,
                "sniffer": ["http", "tls", "quic", "stun"] })
    );
    assert_eq!(rules[4]["rule_set"], json!(["https://example.com/cn.list"]));
    // An inline set of an inline set, and of a file: any of them.
    assert_eq!(
        rules[5],
        json!({ "type": "logical", "mode": "or", "rules": [
            { "domain_suffix": ["video.example"] },
            { "domain_suffix": ["stream.example"], "ip_cidr": ["203.0.113.0/24"] },
            { "rule_set": ["https://example.com/music.list"], "no_resolve": true },
        ], "outbound": "DIRECT" })
    );
    // LAN, without resolving.
    let lan = rules.last().unwrap();
    assert_eq!(lan["rules"][0]["domain_suffix"], json!(["local"]));
    assert_eq!(lan["rules"][1]["ip_cidr"][1], "10.0.0.0/8");
    assert_eq!(lan["rules"][1]["no_resolve"], true);
    let sets: Vec<Value> = config
        .route
        .rule_set
        .iter()
        .map(|s| serde_json::to_value(s).unwrap())
        .collect();
    assert_eq!(
        sets,
        [
            json!({ "type": "remote", "tag": ["https://example.com/ads.txt"],
                    "format": "surge-text", "behavior": "domain",
                    "url": "https://example.com/ads.txt", "download_detour": "DIRECT",
                    "update_interval": "315360000000ms" }),
            json!({ "type": "remote", "tag": ["https://example.com/cn.list"],
                    "format": "surge-text", "behavior": "classical",
                    "url": "https://example.com/cn.list", "download_detour": "DIRECT",
                    "update_interval": "43200000ms" }),
            json!({ "type": "remote", "tag": ["https://example.com/music.list"],
                    "format": "surge-text", "behavior": "classical",
                    "url": "https://example.com/music.list", "download_detour": "DIRECT" }),
        ]
    );
}

#[test]
fn dns_answers_as_surge_s_responder_and_host() {
    let config = load(
        "[General]\n\
         dns-server = 223.5.5.5\n\
         ipv6 = true\n\
         always-real-ip = -*.skip.lan, *.lan, stun.l.google.com:3478, <ip-address>\n\
         use-local-host-item-for-proxy = true\n\
         [Proxy]\n\
         HK = trojan, hk.example.com, 443, password=pw\n\
         [Host]\n\
         abc.com = 1.2.3.4, ::1\n\
         *.dev = 6.7.8.9\n\
         *google.com = 10.0.0.1\n\
         foo.com = bar.com\n\
         bar.com = server:8.8.8.8\n\
         *.cn = server:119.29.29.29, https://doh.pub/dns-query\n\
         nas = server:syslib\n\
         DOMAIN-SET:https://example.com/d.txt = server:223.5.5.5\n\
         abc.com = 5.5.5.5\n\
         RULE-SET:https://example.com/r.list = 0.0.0.0\n\
         not a line\n\
         [Rule]\n\
         FINAL,DIRECT\n",
    );
    let dns = serde_json::to_value(&config.dns).unwrap();
    let rules = dns["rules"].as_array().unwrap();
    let servers: Vec<&str> = dns["servers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        servers,
        [
            "223.5.5.5",
            "8.8.8.8",
            "119.29.29.29",
            "https://doh.pub/dns-query",
            "system",
            "fakeip",
            "hosts:*.dev",
            "hosts:*google.com",
            "server:119.29.29.29,https://doh.pub/dns-query",
            "hosts:RULE-SET:https://example.com/r.list",
            "hosts",
            "system-hosts",
        ]
    );
    let server = |tag: &str| {
        dns["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["tag"] == tag)
            .unwrap()
            .clone()
    };
    assert_eq!(server("fakeip")["inet4_range"], "198.18.0.0/15");
    assert_eq!(server("fakeip")["inet6_range"], "fd00:6152::/96");
    // The first line of a name decides; a wildcard's server holds a
    // pattern of every name it does.
    assert_eq!(
        server("hosts")["predefined"],
        json!({ "abc.com": ["1.2.3.4", "::1"], "foo.com": "bar.com" })
    );
    let any = server("hosts:*google.com")["predefined"].clone();
    assert_eq!(any["*"], json!(["10.0.0.1"]));
    assert_eq!(any[vec!["*"; 32].join(".")], json!(["10.0.0.1"]));
    // The DoH server's name resolves through the plain one.
    assert_eq!(
        server("https://doh.pub/dns-query")["domain_resolver"],
        "223.5.5.5"
    );
    let at = |i: usize| rules[i].clone();
    assert_eq!(at(0)["domain"], json!(["use-application-dns.net"]));
    assert_eq!(
        at(1),
        json!({ "query_type": ["HTTPS", "SVCB"], "server": "fakeip" })
    );
    // Fake addresses, but for always-real-ip's names, the first deciding.
    assert_eq!(
        at(2),
        json!({ "type": "logical", "mode": "and", "rules": [
            { "query_type": ["A", "AAAA"] },
            { "type": "logical", "mode": "and", "invert": true, "rules": [
                { "type": "logical", "mode": "or", "rules": [
                    { "type": "logical", "mode": "and", "rules": [
                        { "domain_regex": ["^.*\\.lan$"] },
                        { "type": "logical", "mode": "and", "invert": true, "rules": [
                            { "type": "logical", "mode": "or", "rules": [
                                { "domain_regex": ["^.*\\.skip\\.lan$"] },
                            ] },
                        ] },
                    ] },
                    { "type": "logical", "mode": "and", "rules": [
                        { "domain": ["stun.l.google.com"] },
                        { "type": "logical", "mode": "and", "invert": true, "rules": [
                            { "type": "logical", "mode": "or", "rules": [
                                { "domain_regex": ["^.*\\.skip\\.lan$"] },
                            ] },
                        ] },
                    ] },
                ] },
            ] },
        ], "server": "fakeip" })
    );
    // The proxies' servers skip [Host].
    assert_eq!(at(3), json!({ "outbound": ["HK"], "server": "223.5.5.5" }));
    let a_aaaa = |condition: Value, server: &str| {
        json!({ "type": "logical", "mode": "and", "rules": [
            condition, { "query_type": ["A", "AAAA"] },
        ], "server": server })
    };
    assert_eq!(at(4), a_aaaa(json!({ "domain": ["abc.com"] }), "hosts"));
    assert_eq!(
        at(5),
        a_aaaa(json!({ "domain_regex": ["^.*\\.dev$"] }), "hosts:*.dev")
    );
    assert_eq!(at(7), a_aaaa(json!({ "domain": ["foo.com"] }), "hosts"));
    assert_eq!(at(8), json!({ "domain": ["bar.com"], "server": "8.8.8.8" }));
    assert_eq!(
        at(9)["server"],
        "server:119.29.29.29,https://doh.pub/dns-query"
    );
    assert_eq!(at(10), json!({ "domain": ["nas"], "server": "system" }));
    assert_eq!(
        at(11),
        json!({ "rule_set": ["https://example.com/d.txt"], "server": "223.5.5.5" })
    );
    // The system's hosts, then local and simple names.
    // A set's names, any of them given the address.
    assert_eq!(
        at(13),
        a_aaaa(
            json!({ "rule_set": ["https://example.com/r.list"] }),
            "hosts:RULE-SET:https://example.com/r.list"
        )
    );
    assert_eq!(at(14)["server"], "system-hosts");
    assert_eq!(at(16)["server"], "system");
    assert_eq!(rules.len(), 17);
    assert!(config
        .route
        .rule_set
        .iter()
        .any(|s| s.tag == ["https://example.com/d.txt"]));
    let cache = serde_json::to_value(&config.experimental).unwrap();
    assert_eq!(cache["cache_file"]["store_fakeip"], true);
    // Surge's own DNS addresses are answered here.
    assert!(config.route.rules[0]
        .ip_cidr
        .contains(&"198.18.0.2/31".to_string()));
    let warnings = config.warnings.join("\n");
    assert!(
        warnings.contains("use-local-host-item-for-proxy: sail sends a proxy the name")
            && warnings.contains("\"not a line\" is not name = value"),
        "{}",
        warnings
    );
    // Without read-etc-hosts, and with allow-dns-svcb, neither rule.
    let config =
        load("[General]\nread-etc-hosts = false\nallow-dns-svcb = true\n[Rule]\nFINAL,DIRECT\n");
    let dns = serde_json::to_value(&config.dns).unwrap();
    let text = dns["rules"].to_string();
    assert!(
        !text.contains("system-hosts") && !text.contains("SVCB"),
        "{}",
        text
    );
}

#[test]
fn mistakes_name_where_they_are() {
    for (text, expected) in [
        (
            "[Proxy]\nA = ss, a, 1, password=p\n[Rule]\nFINAL,DIRECT\n",
            "[Proxy] line 2: A: encrypt-method: missing",
        ),
        (
            "[Proxy]\nA = snell, a, 1, psk=p\n[Rule]\nFINAL,DIRECT\n",
            "[Proxy] line 2: A: sail does not implement Snell: versions 4 and 5",
        ),
        (
            "[Proxy]\nREJECT = direct\n",
            "[Proxy] line 2: REJECT is Surge's own policy",
        ),
        (
            "[Proxy]\nA = hysteria2, a, 443, password=p, sni=off\n[Rule]\nFINAL,DIRECT\n",
            "[Proxy] line 2: A: sni: off: sail does not implement a QUIC handshake without SNI",
        ),
        (
            "[Proxy]\nA = trojan, a, 443, password=p, server-cert-verify-name=b.example\n\
             [Rule]\nFINAL,DIRECT\n",
            "[Proxy] line 2: A: server-cert-verify-name: sail does not implement",
        ),
        (
            "[Proxy Group]\nG = select, Nowhere\n[Rule]\nFINAL,DIRECT\n",
            "[Proxy Group] line 2: G: no policy or group is named \"Nowhere\"",
        ),
        (
            "[Proxy Group]\nG = select, policy-path=ftp://a\n[Rule]\nFINAL,G\n",
            "[Proxy Group] line 2: G: policy-path: \"ftp://a\" is neither an http(s) URL nor a file",
        ),
        (
            "[Proxy]\nA = direct\n[Proxy Group]\nG = smart, A, policy-priority=\"A:0\"\n\
             [Rule]\nFINAL,G\n",
            "[Proxy Group] line 4: G: policy-priority: \"A:0\": a factor is above 0",
        ),
        (
            "[Proxy Group]\nG = subnet, SSID:a = DIRECT\n[Rule]\nFINAL,G\n",
            "[Proxy Group] line 2: G: default: missing",
        ),
        (
            "[Proxy Group]\nG = subnet, default=DIRECT, include-all-proxies=true\n[Rule]\nFINAL,G\n",
            "subnet groups take no include-all-proxies",
        ),
        (
            "[Proxy Group]\nG = ssid, default=DIRECT, TYPE:LTE = DIRECT\n[Rule]\nFINAL,G\n",
            "none of WIFI, WIRED and CELLULAR",
        ),
        (
            "[Rule]\nCELLULAR-RADIO,LTE,DIRECT\nFINAL,DIRECT\n",
            "no host tells sail the radio technology",
        ),
        (
            "[Proxy Group]\nA = select, B\nB = select, A\n[Rule]\nFINAL,A\n",
            "holds itself",
        ),
        (
            "[Rule]\nRULE-SET,https://a/b.list,DIRECT\nDOMAIN-SET,https://a/b.list,DIRECT\n\
             FINAL,DIRECT\n",
            "[Rule] line 3: DOMAIN-SET: https://a/b.list is a RULE-SET too, which Surge refuses",
        ),
        (
            "[Ruleset A]\nRULE-SET,B\n[Ruleset B]\nDOMAIN,b\nRULE-SET,A\n\
             [Rule]\nRULE-SET,A,DIRECT\nFINAL,DIRECT\n",
            "[Rule] line 7: [Ruleset A] line 2: [Ruleset B] line 5: RULE-SET: A leads back to \
             itself: A -> B -> A",
        ),
        (
            "[Ruleset A]\nFINAL,DIRECT\n[Rule]\nRULE-SET,A,DIRECT\nFINAL,DIRECT\n",
            "[Rule] line 4: [Ruleset A] line 2: FINAL and pre-matching are not for a rule-set",
        ),
        (
            "[Rule]\nURL-REGEX,(,DIRECT\nFINAL,DIRECT\n",
            "[Rule] line 2: URL-REGEX: \"(\"",
        ),
        (
            "[Rule]\nHOSTNAME-TYPE,ipv4,DIRECT\nFINAL,DIRECT\n",
            "[Rule] line 2: HOSTNAME-TYPE: \"ipv4\" is none of IPv4",
        ),
        (
            "[Rule]\nAND,((DOMAIN,a),(DEVICE-NAME,tv)),DIRECT\nFINAL,DIRECT\n",
            "[Rule] line 2: sail does not implement DEVICE-NAME rules: they match the devices",
        ),
        (
            "[Rule]\nDOMAIN,a,Nowhere\nFINAL,DIRECT\n",
            "[Rule] line 2: no policy or group is named \"Nowhere\"",
        ),
        ("[Rule]\nDOMAIN,a,DIRECT\n", "no FINAL rule"),
        (
            "[Rule]\nDOMAIN,a,CELLULAR\nFINAL,DIRECT\n",
            "cellular policies",
        ),
        (
            "[Rule]\nSCRIPT,s,DIRECT\nFINAL,DIRECT\n",
            "sail does not implement SCRIPT rules",
        ),
        (
            "[General]\nudp-policy-not-supported-behaviour = maybe\n[Rule]\nFINAL,DIRECT\n",
            "[General] line 2: udp-policy-not-supported-behaviour: \"maybe\"",
        ),
        (
            "[Host]\na.com = script:dnspod\n[Rule]\nFINAL,DIRECT\n",
            "[Host] line 2: a.com: sail does not run DNS scripts",
        ),
        (
            "[Host]\na.com = server:dns.example\n[Rule]\nFINAL,DIRECT\n",
            "[Host] line 2: a.com: \"dns.example\" is not an IP address",
        ),
        (
            "[Script]\nr = type=rule, script-path=a.js\n[Rule]\nFINAL,DIRECT\n",
            "sail does not run rule scripts",
        ),
        (
            "[Proxy]\nA = ss, a, 1, encrypt-method=aes-128-gcm, password=p, \
             underlying-proxy=Nowhere\n[Rule]\nFINAL,DIRECT\n",
            "[Proxy] line 2: A: underlying-proxy: no policy or group is named \"Nowhere\"",
        ),
        (
            "[Rule]\nDOMAIN,a,DIRECT\n#!include more.conf\nFINAL,DIRECT\n",
            "a profile read from text, or a file included from a URL, includes no files",
        ),
    ] {
        let err = error(text);
        assert!(err.contains(expected), "{}\n---\n{}", expected, err);
    }
}

#[test]
fn udp_goes_directly_when_told() {
    let config = load(
        "[General]\nudp-policy-not-supported-behaviour = DIRECT\n\
         [Proxy]\nH = http, h, 80\n[Rule]\nDOMAIN,a,H\nFINAL,H\n",
    );
    let rules = rules(&config);
    assert_eq!(
        rules[0],
        json!({ "domain": ["a"], "network": ["udp"], "outbound": "DIRECT" })
    );
    assert_eq!(rules[1]["outbound"], "H");
    // FINAL's UDP too.
    assert_eq!(
        rules[2],
        json!({ "network": ["udp"], "outbound": "DIRECT" })
    );
    assert_eq!(config.route.final_outbound.as_deref(), Some("H"));
}

#[test]
fn surge_ios_listens_on_the_loopback_address() {
    let config = load(
        "[General]\nallow-wifi-access = false\nwifi-access-http-port = 7000\n\
         wifi-access-socks5-port = 7001\n[Rule]\nFINAL,DIRECT\n",
    );
    let ports: Vec<_> = config
        .inbounds
        .iter()
        .map(|i| (i.listen.clone().unwrap(), i.listen_port.unwrap()))
        .collect();
    assert_eq!(
        ports,
        [
            ("127.0.0.1".to_string(), 7000),
            ("127.0.0.1".to_string(), 7001)
        ]
    );
    // No one else to keep out.
    assert!(rules(&config).is_empty());
    let config = load(
        "[General]\nallow-wifi-access = true\nwifi-access-http-auth = u:p\n\
         proxy-restricted-to-lan = false\n[Rule]\nFINAL,DIRECT\n",
    );
    assert_eq!(config.inbounds[0].listen.as_deref(), Some("::"));
    assert_eq!(config.inbounds[0].listen_port, Some(6152));
    assert!(rules(&config).is_empty());
}

#[test]
fn a_final_reject_is_a_rule() {
    let config = load("[Rule]\nFINAL,REJECT\n");
    assert_eq!(
        rules(&config),
        [json!({ "network": ["tcp", "udp"], "action": "reject" })]
    );
    // Without dns-failed, a name that does not resolve fails.
    let config = load("[Rule]\nGEOIP,CN,DIRECT\nFINAL,DIRECT\n");
    assert_eq!(
        rules(&config)[0],
        json!({ "action": "resolve", "on_demand": true })
    );
}

#[test]
fn a_profile_includes_its_sections_from_files() {
    let dir = std::env::temp_dir().join(format!("sail-surge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("proxies.dconf"),
        "[Proxy]\nHK = trojan, hk.example.com, 443, password=pw\n",
    )
    .unwrap();
    let path = dir.join("main.conf");
    std::fs::write(
        &path,
        "[Proxy]\n#!include proxies.dconf\n[Rule]\nDOMAIN,a,HK\nFINAL,DIRECT\n",
    )
    .unwrap();
    let config = crate::config::from_file(path.to_str().unwrap()).unwrap();
    assert_eq!(outbound(&config, "HK")["type"], "trojan");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The outbound providers, as JSON.
#[cfg(feature = "outbound-provider")]
fn providers(config: &Config) -> Vec<Value> {
    config
        .outbound_providers
        .iter()
        .map(|p| serde_json::to_value(p).unwrap())
        .collect()
}

#[cfg(feature = "outbound-provider")]
#[test]
fn policy_paths_are_providers_groups_share() {
    let config = load(
        "[Proxy]\nRelay = trojan, relay.example.com, 443, password=pw\n\
         [Proxy Group]\n\
         Pool = select, policy-path=https://sub.example.com/s?target=surge, update-interval=3600, hidden=true\n\
         HK = smart, include-other-group=Pool, policy-regex-filter=港|HK\n\
         US = url-test, policy-path=https://sub.example.com/s?target=surge, update-interval=3600, policy-regex-filter=US\n\
         HK01 = select, Relay, include-other-group=HK, policy-regex-filter=01\n\
         Plain = fallback, policy-path=https://sub.example.com/s?target=surge\n\
         [Rule]\nFINAL,HK01\n",
    );
    assert_eq!(
        providers(&config),
        [
            json!({
                "type": "remote", "tag": "Pool", "url": "https://sub.example.com/s?target=surge",
                "update_interval": "3600000ms", "download_detour": "DIRECT"
            }),
            json!({
                "type": "remote", "tag": "Plain", "url": "https://sub.example.com/s?target=surge",
                "update_interval": "86400000ms", "download_detour": "DIRECT"
            }),
        ]
    );
    let pool = outbound(&config, "Pool");
    assert_eq!(pool["outbounds"], json!([]));
    assert_eq!(pool["providers"], json!(["Pool"]));
    assert_eq!(pool["empty_fallback"], "DIRECT");
    assert!(pool.get("filter").is_none());
    assert_eq!(outbound(&config, "HK")["filter"], json!(["港|HK"]));
    assert_eq!(outbound(&config, "US")["providers"], json!(["Pool"]));
    assert_eq!(outbound(&config, "US")["filter"], json!(["US"]));
    // Every filter on the way.
    let hk01 = outbound(&config, "HK01");
    assert_eq!(hk01["outbounds"], json!(["Relay"]));
    assert_eq!(hk01["providers"], json!(["Pool"]));
    let filter = hk01["filter"][0].as_str().unwrap().to_string();
    assert_eq!(filter, r"^(?=[\s\S]*?(?:港|HK))(?=[\s\S]*?(?:01))");
    let filter = crate::common::name_filter::NameFilter::new(&filter).unwrap();
    let mut w = Vec::new();
    assert!(filter.matches("🇭🇰 HK 01", &mut w));
    assert!(!filter.matches("🇭🇰 HK 02", &mut w));
    assert!(!filter.matches("🇺🇸 US 01", &mut w));
}

#[cfg(feature = "outbound-provider")]
#[test]
fn prefix_modifier_and_underlying_proxy() {
    let text = "[Proxy]\nRelay = trojan, relay.example.com, 443, password=pw\n\
         NodeA = socks5, a.example.com, 1080\n\
         [Proxy Group]\n\
         A = select, policy-path=a.list, external-policy-name-prefix=A-, policy-regex-filter=JP, \
         external-policy-modifier=\"underlying-proxy=Relay,skip-cert-verify=true,ip-version=v4-only,test-url=http://x/,udp-relay=true\"\n\
         Chain = select, NodeA, Relay, A, policy-path=https://b.example.com/s, underlying-proxy=Relay\n\
         [Rule]\nFINAL,Chain\n";
    let config = load(text);
    let p = providers(&config);
    assert_eq!(
        p[0],
        json!({
            "type": "local", "tag": "A", "path": "a.list", "filter": ["JP"],
            "override": {
                "skip-cert-verify": true, "ip-version": "ipv4", "additional-prefix": "A-"
            },
            "detour": "Relay"
        })
    );
    assert_eq!(
        p[1]["override"],
        json!({ "additional-suffix": " (via Relay)" })
    );
    assert_eq!(p[1]["detour"], "Relay");
    // A, a group, and Relay, not a proxy but dialled through itself, are
    // as they are.
    let chain = outbound(&config, "Chain");
    assert_eq!(
        chain["outbounds"],
        json!(["NodeA (via Relay)", "Relay (via Relay)", "A"])
    );
    assert_eq!(chain["providers"], json!(["Chain"]));
    let derived = outbound(&config, "NodeA (via Relay)");
    assert_eq!(derived["type"], "socks");
    assert_eq!(derived["detour"], "Relay");
    assert_eq!(derived["server"], "a.example.com");
    assert!(
        config.warnings.iter().any(|w| w.contains("test-url")),
        "{:?}",
        config.warnings
    );
}

#[cfg(feature = "outbound-provider")]
#[test]
fn policy_path_mistakes() {
    let group = |line: &str| {
        error(&format!(
            "[Proxy]\nRelay = trojan, r.example.com, 443, password=pw\n\
             [Proxy Group]\nG = select, Relay, {}\n[Rule]\nFINAL,G\n",
            line
        ))
    };
    let e = group("underlying-proxy=G");
    assert!(e.contains("underlying-proxy: G holds the group"), "{}", e);
    let e = group("underlying-proxy=Nowhere");
    assert!(e.contains("underlying-proxy: no policy or group"), "{}", e);
    let e = group("policy-path=x.list, external-policy-modifier=\"sni=a.example.com\"");
    assert!(
        e.contains("external-policy-modifier: sni: sail does not implement this parameter yet"),
        "{}",
        e
    );
    let e = group("policy-path=ftp://a/b");
    assert!(e.contains("policy-path: \"ftp://a/b\" is neither"), "{}", e);
    let e = group("policy-path=x.list, external-policy-name-prefix=a=b");
    assert!(e.contains("holds ="), "{}", e);
    let e = group("policy-path=x.list, external-policy-modifier=\"underlying-proxy=G\"");
    assert!(e.contains("G takes the policies of x.list"), "{}", e);
}

/// Groups whose filters differ by provider filter in their providers.
#[cfg(feature = "outbound-provider")]
#[test]
fn filters_differing_by_provider_are_the_providers() {
    let config = load(
        "[Proxy Group]\n\
         A = select, policy-path=https://a.example.com/s, policy-regex-filter=HK\n\
         B = select, policy-path=https://b.example.com/s, policy-regex-filter=JP\n\
         All = select, include-other-group=\"A,B\"\n\
         [Rule]\nFINAL,All\n",
    );
    let all = outbound(&config, "All");
    assert_eq!(all["providers"], json!(["All", "All #2"]));
    assert!(all.get("filter").is_none());
    let p = providers(&config);
    assert_eq!(p.len(), 4);
    assert_eq!(p[2]["filter"], json!(["HK"]));
    assert_eq!(p[3]["filter"], json!(["JP"]));
    assert_eq!(p[3]["url"], "https://b.example.com/s");
}

#[test]
fn shadow_tls_is_an_outbound_the_proxy_goes_through() {
    let config = load(
        "[Proxy]\n\
         ST = ss, st.example.com, 443, encrypt-method=aes-128-gcm, password=pw, interface=en0, \
         underlying-proxy=Hop, shadow-tls-password=stpw, shadow-tls-sni=www.example.com, \
         shadow-tls-version=3\n\
         Hop = socks5, 127.0.0.1, 1080\n\
         [Proxy Group]\nAll = select, include-all-proxies=true\n\
         [Rule]\nFINAL,All\n",
    );
    let ss = outbound(&config, "ST");
    assert_eq!(ss["detour"], "ST (shadow-tls)");
    assert!(ss.get("bind_interface").is_none());
    let shadow_tls = outbound(&config, "ST (shadow-tls)");
    assert_eq!(
        shadow_tls,
        json!({
            "type": "shadowtls",
            "tag": "ST (shadow-tls)",
            "server": "st.example.com",
            "server_port": 443,
            "version": 3,
            "password": "stpw",
            "detour": "Hop",
            "bind_interface": "en0",
            "tls": { "enabled": true, "server_name": "www.example.com" }
        })
    );
    assert_eq!(outbound(&config, "All")["outbounds"], json!(["ST", "Hop"]));
}

#[test]
fn shadow_tls_mistakes_name_the_parameter() {
    let line = |params: &str| {
        format!(
            "[Proxy]\nST = trojan, st.example.com, 443, password=pw, {}\n[Rule]\nFINAL,ST\n",
            params
        )
    };
    assert!(
        error(&line("shadow-tls-password=p, shadow-tls-sni=a.example"))
            .ends_with("shadow-tls-version: ShadowTLS v1/v2 are not supported; use version 3"),
        "{}",
        error(&line("shadow-tls-password=p, shadow-tls-sni=a.example"))
    );
    assert!(error(&line("shadow-tls-password=p, shadow-tls-version=3"))
        .ends_with("shadow-tls-sni: needed by version 3"));
    assert!(error(&line("shadow-tls-sni=a.example"))
        .ends_with("shadow-tls-sni: needs shadow-tls-password, which turns Shadow TLS on"));
    let quic = "[Proxy]\nQ = hysteria2, q.example.com, 443, password=pw, shadow-tls-password=p\n";
    assert!(error(quic).contains("Shadow TLS wraps TCP proxies, not hysteria2 ones"));
}

#[test]
fn subnet_groups_and_rules_follow_the_network() {
    let config = load(
        "[Proxy]\nP = socks5, a, 1\n\
         [Proxy Group]\n\
         Scene = ssid, default = P, cellular = DIRECT, \"Home Wi-Fi\" = DIRECT, \"BSSID:58:C6:7E:DF:2D:51\"=REJECT\n\
         Out = subnet, default=P, TYPE:WIRED = DIRECT, ROUTER:192.168.1.1 = Scene, hidden=true\n\
         [Rule]\n\
         SUBNET,SSID:Office-*,DIRECT\n\
         CELLULAR-CARRIER,46001,Out\n\
         FINAL,Scene\n",
    );
    assert_eq!(
        outbound(&config, "Scene"),
        serde_json::json!({
            "type": "network", "tag": "Scene",
            "branches": [
                { "network_type": ["cellular"], "outbound": "DIRECT" },
                { "wifi_ssid": ["Home Wi-Fi"], "outbound": "DIRECT" },
                { "wifi_bssid": ["58:c6:7e:df:2d:51"], "outbound": "REJECT" },
            ],
            "default": "P",
        })
    );
    let out = outbound(&config, "Out");
    assert_eq!(
        out["branches"][1]["network_gateway"],
        serde_json::json!(["192.168.1.1"])
    );
    assert_eq!(out["branches"][1]["outbound"], "Scene");
    let rules = rules(&config);
    let subnet = rules
        .iter()
        .find(|r| r.get("wifi_ssid_regex").is_some())
        .unwrap();
    assert_eq!(
        subnet["wifi_ssid_regex"],
        serde_json::json!(["^Office\\-.*$"])
    );
    assert!(rules
        .iter()
        .any(|r| r["network_mcc_mnc"] == serde_json::json!(["46001"]) && r["outbound"] == "Out"));
}

#[test]
fn sni_off_sends_none() {
    let config = load(
        "[Proxy]\nA = https, a.example.com, 443, sni=off\n\
         B = trojan, b.example.com, 443, password=p, sni=off, skip-cert-verify=true\n\
         [Rule]\nFINAL,A\n",
    );
    assert_eq!(
        outbound(&config, "A")["tls"],
        json!({ "enabled": true, "disable_sni": true })
    );
    assert_eq!(
        outbound(&config, "B")["tls"],
        json!({ "enabled": true, "disable_sni": true, "insecure": true })
    );
}

/// A PKCS#12 file of a client certificate, its CA and its key, opened
/// with `password`: base64.
#[cfg(feature = "tls")]
fn p12(password: &str) -> String {
    use base64::Engine;
    use btls::pkcs12::Pkcs12;
    use btls::pkey::PKey;
    use btls::stack::Stack;
    use btls::x509::X509;
    let pki = crate::transport::tls::tests::client_pki();
    let mut ca = Stack::new().unwrap();
    ca.push(X509::from_pem(pki.ca.as_bytes()).unwrap()).unwrap();
    let mut builder = Pkcs12::builder();
    builder.ca(ca);
    let p12 = builder
        .build(
            password,
            "client",
            &PKey::private_key_from_pem(pki.key.as_bytes()).unwrap(),
            &X509::from_pem(pki.cert.as_bytes()).unwrap(),
        )
        .unwrap();
    base64::engine::general_purpose::STANDARD.encode(p12.to_der().unwrap())
}

/// The client certificate the TLS block `tls` makes: its chain's length.
#[cfg(feature = "tls")]
fn chain_len(tls: &Value) -> usize {
    let tls: crate::transport::layers::OutboundTls = serde_json::from_value(tls.clone()).unwrap();
    let identity = tls
        .client_identity(&crate::runtime::RuntimeEnv::default())
        .unwrap()
        .unwrap();
    identity.chain().len()
}

#[cfg(feature = "tls")]
#[test]
fn client_cert_of_the_keystore() {
    let profile = format!(
        "[Proxy]\nA = https, a.example.com, 443, client-cert=cert1\n\
         B = trojan, b.example.com, 443, password=p, client-cert=\"open\"\n\
         C = hysteria2, c.example.com, 443, password=p, client-cert=cert1\n\
         [Rule]\nFINAL,A\n\
         [Keystore]\n\
         cert1 = base64={}, password=\"1,2\"\n\
         open = type=p12, base64={}\n\
         ssh = type=openssh-private-key, base64=AAAA\n\
         bare = base64=AAAA\n",
        p12("1,2"),
        p12("")
    );
    let mut warnings = Vec::new();
    let config = parse(&profile).unwrap_or_else(|e| panic!("{:#}", e));
    warnings.extend(config.warnings.iter().cloned());
    // Items no policy names are not read.
    assert!(
        warnings.iter().all(|w| !w.contains("Keystore")),
        "{:?}",
        warnings
    );
    for tag in ["A", "B", "C"] {
        let tls = &outbound(&config, tag)["tls"];
        assert!(tls["client_certificate"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(tls["client_key"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----"));
        // The certificate, then its CA.
        assert_eq!(chain_len(tls), 2, "{}", tag);
    }

    let line = |param: &str, keystore: &str| {
        error(&format!(
            "[Proxy]\nA = https, a, 443, {}\n[Rule]\nFINAL,A\n[Keystore]\n{}\n",
            param, keystore
        ))
    };
    assert_eq!(
        line("client-cert=nope", ""),
        "[Proxy] line 2: A: client-cert: no [Keystore] item is named \"nope\""
    );
    let e = line(
        "client-cert=c",
        &format!("c = base64={}, password=hunter2", p12("right")),
    );
    assert_eq!(
        e,
        "[Proxy] line 2: A: client-cert: [Keystore] line 6: c: password: does not open the \
         PKCS#12 file"
    );
    assert!(!e.contains("hunter2"));
    assert!(
        line("client-cert=c", "c = type=openssh-private-key, base64=AAAA")
            .ends_with("c: a client certificate is a p12 item, not openssh-private-key")
    );
    // Untyped, an item without a password is an SSH key.
    assert!(line("client-cert=c", "c = base64=AAAA")
        .ends_with("c: a client certificate is a p12 item, not openssh-private-key"));
    assert!(line("client-cert=c", "c = type=p12, password=x").ends_with("c: base64: missing"));
    assert!(line("client-cert=c", "c = type=p12, base64=%%%").ends_with("c: base64: not base64"));
    assert!(line("client-cert=c", "c = type=p12, base64=AAAA")
        .ends_with("c: base64: not a PKCS#12 file"));
}

#[cfg(all(feature = "outbound-provider", feature = "tls"))]
#[test]
fn a_policy_path_has_a_keystore_of_its_own() {
    let body = format!(
        "[Proxy]\nA = https, a.example.com, 443, client-cert=c\n\
         B = https, b.example.com, 443, client-cert=elsewhere\n\
         [Keystore]\nc = base64={}, password=p\n",
        p12("p")
    );
    let policies = crate::config::surge::external(&body, &mut Vec::new())
        .unwrap()
        .unwrap();
    let a = policies[0].outbound.as_ref().unwrap();
    assert_eq!(chain_len(&a["tls"]), 2);
    let b = policies[1].outbound.as_ref().unwrap_err().to_string();
    assert!(
        b.ends_with("client-cert: no [Keystore] item is named \"elsewhere\""),
        "{}",
        b
    );
}

/// An alias of a built-in policy takes the common parameters, as Surge's
/// manual has it; a REJECT alias dials nothing, and its dial parameters
/// are passed over without a word.
#[test]
fn a_reject_alias_passes_its_dial_parameters_over() {
    for kind in ["reject", "reject-drop", "reject-no-drop", "reject-tinygif"] {
        let config = load(&format!(
            "[Proxy]\nOff = {}, interface = en0, ip-version = v4-only\n[Rule]\nFINAL,Off\n",
            kind
        ));
        assert!(
            config.warnings.is_empty(),
            "{}: {:?}",
            kind,
            config.warnings
        );
    }
}

#[test]
fn a_pinned_server_certificate_is_certificate_sha256() {
    let pin = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
    for line in [
        format!(
            "A = trojan, a.example, 443, password=p, server-cert-fingerprint-sha256={}",
            pin
        ),
        format!(
            "A = hysteria2, a.example, 443, password=p, server-cert-fingerprint-sha256={}",
            pin
        ),
    ] {
        let config = load(&format!("[Proxy]\n{}\n[Rule]\nFINAL,A\n", line));
        assert_eq!(
            outbound(&config, "A")["tls"]["certificate_sha256"],
            serde_json::json!(["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"]),
            "{}",
            line
        );
    }
}

/// WireGuard sections no policy names are told of in the profile's order,
/// whatever order sail keeps them in: a profile reads the same each time.
#[test]
fn unused_wireguard_sections_are_told_of_in_order() {
    let names = ["e", "d", "c", "b", "a"];
    let mut text = String::from("[Proxy]\n[Rule]\nFINAL,DIRECT\n");
    for name in names {
        text.push_str(&format!(
            "[WireGuard {}]\nprivate-key = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n",
            name
        ));
    }
    let told: Vec<String> = load(&text)
        .warnings
        .into_iter()
        .filter(|w| w.ends_with("no policy names it; ignored"))
        .collect();
    let expected: Vec<String> = names
        .iter()
        .map(|n| format!("[WireGuard {}]: no policy names it; ignored", n))
        .collect();
    assert_eq!(told, expected);
}

/// `hybrid` is sing-box's network strategy: `on` Wi-Fi and cellular at
/// once, `off` the default interface alone, `auto` as `all-hybrid` says,
/// which is the route's default.
#[test]
fn hybrid_is_a_network_strategy() {
    let config = load(
        "[General]\nall-hybrid = true\n\
         [Proxy]\n\
         On = trojan, a.example, 443, password=p, hybrid=on\n\
         Off = direct, hybrid=false\n\
         Auto = trojan, a.example, 443, password=p, hybrid=auto\n\
         [Rule]\nFINAL,On\n",
    );
    assert_eq!(outbound(&config, "On")["network_strategy"], "hybrid");
    assert_eq!(outbound(&config, "Off")["network_strategy"], "default");
    assert!(outbound(&config, "Auto").get("network_strategy").is_none());
    let route = serde_json::to_value(&config.route).unwrap();
    assert_eq!(route["default_network_strategy"], "hybrid");
    // Which sail's network strategy, as sing-box's, needs.
    assert_eq!(route["auto_detect_interface"], true);
    let one = load("[Proxy]\nA = direct, hybrid=on\n[Rule]\nFINAL,A\n");
    assert!(one.route.auto_detect_interface);
    assert!(
        !load("[Proxy]\nA = direct, hybrid=off\n[Rule]\nFINAL,A\n")
            .route
            .auto_detect_interface
    );
    assert!(
        serde_json::to_value(&load("[Rule]\nFINAL,DIRECT\n").route).unwrap()
            ["default_network_strategy"]
            .is_null()
    );
    assert!(
        error("[Proxy]\nA = direct, hybrid=maybe\n[Rule]\nFINAL,A\n")
            .contains("hybrid: \"maybe\" is none of auto, on and off"),
    );
}

/// SOCKS5 over TLS is refused where it is read: the socks outbound has no
/// TLS, and dropping it would send in the clear what was to be encrypted.
#[test]
fn socks5_tls_is_refused() {
    let err = error("[Proxy]\nS = socks5-tls, a.example, 1443\n[Rule]\nFINAL,S\n");
    assert!(
        err.contains("socks5-tls: sail does not implement SOCKS5 over TLS yet"),
        "{}",
        err
    );
    load("[Proxy]\nS = socks5, a.example, 1080\n[Rule]\nFINAL,S\n");
}
