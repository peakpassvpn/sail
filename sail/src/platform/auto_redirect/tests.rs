// A uid range is one element of a list of them.
#![allow(clippy::single_range_in_vec_init)]

use std::net::IpAddr;

use super::*;

fn prefix(s: &str) -> (IpAddr, u8) {
    let (addr, len) = s.split_once('/').unwrap();
    (addr.parse().unwrap(), len.parse().unwrap())
}

fn prefixes(list: &[&str]) -> Vec<(IpAddr, u8)> {
    list.iter().map(|s| prefix(s)).collect()
}

/// sing-box's defaults on a Linux host: dual stack, NFQUEUE there.
pub(super) fn default_options() -> RulesetOptions {
    RulesetOptions {
        table: "sail".into(),
        tun_name: "tun0".into(),
        ipv4: Some(("172.18.0.1".parse().unwrap(), 30)),
        ipv6: Some(("fdfe:dcba:9876::1".parse().unwrap(), 126)),
        input_mark: 0x2023,
        output_mark: 0x2024,
        reset_mark: 0x2025,
        nfqueue: Some(100),
        redirect_port: 7890,
        dns_hijack: true,
        exclude_mptcp: false,
        strict_route: false,
        loopback_address: vec![],
        route_address: vec![],
        route_exclude_address: vec![],
        route_address_set: None,
        route_exclude_address_set: None,
        include_interface: vec![],
        exclude_interface: vec![],
        include_uid: vec![],
        exclude_uid: vec![],
        local_prefixes: prefixes(&[
            "127.0.0.1/8",
            "192.168.1.10/24",
            "172.18.0.1/30",
            "::1/128",
            "fdfe:dcba:9876::1/126",
            "2001:db8:1::10/64",
        ]),
    }
}

/// Every option that changes the ruleset, on both families.
pub(super) fn maximal_options() -> RulesetOptions {
    RulesetOptions {
        exclude_mptcp: true,
        strict_route: true,
        loopback_address: vec!["10.7.0.1".parse().unwrap(), "fd00:7::1".parse().unwrap()],
        route_address: prefixes(&["0.0.0.0/1", "128.0.0.0/1", "2000::/3"]),
        route_exclude_address: prefixes(&["192.168.0.0/16", "10.0.0.0/8", "fc00::/7"]),
        route_address_set: Some(AddressSet {
            prefixes: prefixes(&["1.0.0.0/24", "1.0.1.0/24", "8.8.8.8/32", "2001:4860::/32"]),
        }),
        route_exclude_address_set: Some(AddressSet {
            prefixes: prefixes(&["114.114.114.114/32"]),
        }),
        include_interface: vec!["lo".into(), "eth0".into()],
        exclude_interface: vec!["eth2".into(), "docker0".into()],
        include_uid: vec![1000..=1999, 0..=0, 3000..=3000],
        exclude_uid: vec![1500..=1500],
        ..default_options()
    }
}

/// One family, strict, without NFQUEUE, the host's own traffic left out.
pub(super) fn single_stack_options() -> RulesetOptions {
    RulesetOptions {
        ipv6: None,
        nfqueue: None,
        strict_route: true,
        dns_hijack: true,
        include_interface: vec!["eth0".into()],
        exclude_uid: vec![0..=0],
        route_exclude_address_set: Some(AddressSet::default()),
        ..default_options()
    }
}

/// The text's lines, trimmed, without the blank ones.
fn lines(s: &str) -> Vec<&str> {
    s.lines().map(str::trim).filter(|l| !l.is_empty()).collect()
}

fn rendered(o: &RulesetOptions) -> String {
    render(o).unwrap().replace('\t', "    ")
}

#[test]
fn renders_default() {
    assert_eq!(rendered(&default_options()), DEFAULT.trim_start());
}

#[test]
fn renders_maximal() {
    assert_eq!(rendered(&maximal_options()), MAXIMAL.trim_start());
}

#[test]
fn renders_single_stack() {
    assert_eq!(rendered(&single_stack_options()), SINGLE_STACK.trim_start());
}

/// The batch holds what the text shows: the table made afresh, a rule per
/// line of each chain, an anonymous set per set written out in a rule --
/// one rule each, which is all the kernel allows -- and it encodes.
#[test]
fn batch_matches_the_text() {
    for o in [default_options(), maximal_options(), single_stack_options()] {
        let batch = setup(&o).unwrap();
        batch.check_wire();
        let whats: Vec<&str> = batch.descriptions().collect();
        assert_eq!(
            whats[..3],
            [
                "deleting table inet sail",
                "deleting table inet sail",
                "creating table inet sail"
            ]
        );
        let text = render(&o).unwrap();
        let mut chain = "";
        let mut want_rules = Vec::new();
        let mut inline_sets = 0;
        for line in lines(&text) {
            if let Some(name) = line.strip_prefix("chain ") {
                chain = name.trim_end_matches(" {");
            } else if !chain.is_empty() && !line.starts_with("type ") && line != "}" {
                want_rules.push(chain.to_string());
                inline_sets += line.matches('{').count();
            } else if line == "}" {
                chain = "";
            }
        }
        let got_rules: Vec<String> = whats
            .iter()
            .filter_map(|w| w.strip_prefix("creating rule "))
            .map(|w| w.split(" in chain ").nth(1).unwrap().to_string())
            .collect();
        assert_eq!(got_rules, want_rules);
        let anonymous = whats
            .iter()
            .filter(|w| w.starts_with("creating anonymous set"))
            .count();
        assert_eq!(anonymous, inline_sets);
    }
}

#[test]
fn updates_and_cleanup() {
    let o = maximal_options();
    let batch = update_local_prefixes(&o, &prefixes(&["127.0.0.1/8", "10.1.2.3/16"]));
    batch.check_wire();
    assert_eq!(
        batch.descriptions().collect::<Vec<_>>(),
        [
            "flushing set inet4_local_address_set",
            "adding elements to set inet4_local_address_set",
            // No IPv6 prefix left: emptied.
            "flushing set inet6_local_address_set",
        ]
    );

    let include = AddressSet {
        prefixes: prefixes(&["9.9.9.9/32", "2620:fe::/48"]),
    };
    let batch = update_route_address_sets(&o, Some(&include), None);
    batch.check_wire();
    assert_eq!(
        batch.descriptions().collect::<Vec<_>>(),
        [
            "flushing set inet4_route_address_set",
            "adding elements to set inet4_route_address_set",
            "flushing set inet6_route_address_set",
            "adding elements to set inet6_route_address_set",
        ]
    );
    let batch = update_route_address_sets(&o, None, Some(&AddressSet::default()));
    assert_eq!(
        batch.descriptions().collect::<Vec<_>>(),
        [
            "flushing set inet4_route_exclude_address_set",
            "flushing set inet6_route_exclude_address_set",
        ]
    );
    // Sets the ruleset was not made with are not there to fill.
    let batch = update_route_address_sets(&default_options(), Some(&include), Some(&include));
    assert!(batch.is_empty());

    let batch = cleanup("sail");
    batch.check_wire();
    assert_eq!(
        batch.descriptions().collect::<Vec<_>>(),
        ["deleting table inet sail", "deleting table inet sail"]
    );
}

#[test]
fn skips_output_as_sing_tun_does() {
    let chains = |o: &RulesetOptions| -> Vec<String> {
        lines(&render(o).unwrap())
            .into_iter()
            .filter_map(|l| l.strip_prefix("chain "))
            .map(|l| l.trim_end_matches(" {").to_string())
            .collect()
    };
    let all = chains(&default_options());
    assert!(all.contains(&"output".to_string()));
    assert!(all.contains(&"output_prematch".to_string()));
    for (include, exclude) in [(vec!["eth0"], vec![]), (vec![], vec!["lo"])] {
        let o = RulesetOptions {
            include_interface: include.into_iter().map(String::from).collect(),
            exclude_interface: exclude.into_iter().map(String::from).collect(),
            ..default_options()
        };
        assert_eq!(
            chains(&o),
            [
                "prerouting_prematch",
                "input",
                "prerouting",
                "prerouting_udp_icmp"
            ]
        );
    }
}

#[test]
fn no_dns_target_no_hijack() {
    // A /32 has no address after the TUN's own.
    let o = RulesetOptions {
        ipv4: Some(("172.18.0.1".parse().unwrap(), 32)),
        ipv6: None,
        ..default_options()
    };
    let text = render(&o).unwrap();
    assert!(!text.contains("dport 53"), "{}", text);
    let o = RulesetOptions {
        dns_hijack: false,
        ..default_options()
    };
    assert!(!render(&o).unwrap().contains("dport 53"));
}

#[test]
fn invalid_options() {
    let bad = |f: &dyn Fn(&mut RulesetOptions)| {
        let mut o = default_options();
        f(&mut o);
        let err = setup(&o).unwrap_err();
        assert_eq!(render(&o).unwrap_err(), err);
        err.to_string()
    };
    assert_eq!(
        bad(&|o| {
            o.ipv4 = None;
            o.ipv6 = None
        }),
        "auto_redirect: the TUN has no address"
    );
    assert_eq!(
        bad(&|o| o.exclude_interface = vec!["a-name-too-long-x".into()]),
        "auto_redirect: \"a-name-too-long-x\" is not an interface name"
    );
    assert_eq!(
        bad(&|o| o.reset_mark = o.input_mark),
        "auto_redirect: the input and reset marks are the same, 0x2023"
    );
    assert_eq!(
        bad(&|o| o.output_mark = 0),
        "auto_redirect: the output mark is 0"
    );
    assert_eq!(
        bad(&|o| o.redirect_port = 0),
        "auto_redirect: the redirect port is 0"
    );
    assert_eq!(
        bad(&|o| o.route_address = vec![prefix("10.0.0.0/33")]),
        "auto_redirect: 10.0.0.0/33 is not a prefix"
    );
    assert_eq!(
        bad(&|o| {
            o.route_exclude_address_set = Some(AddressSet {
                prefixes: vec![prefix("::/129")],
            })
        }),
        "auto_redirect: ::/129 is not a prefix"
    );
    #[allow(clippy::reversed_empty_ranges)]
    let empty = 2000..=1000;
    assert_eq!(
        bad(&|o| o.include_uid = vec![empty.clone()]),
        "auto_redirect: uid range 2000-1000 is empty"
    );
    assert_eq!(
        bad(&|o| o.tun_name = "lo".into()),
        "auto_redirect: the TUN cannot be lo"
    );
}

/// What `default_options` renders to -- tabs as four spaces -- and what nft(8)
/// 1.1.3 lists for it (counters without their counts).
const DEFAULT: &str = r#"
table inet sail {
    set inet4_local_address_set {
        type ipv4_addr
        flags interval
        elements = { 127.0.0.0/8, 172.18.0.0/30, 192.168.1.0/24 }
    }
    set inet6_local_address_set {
        type ipv6_addr
        flags interval
        elements = { ::1, 2001:db8:1::/64, fdfe:dcba:9876::/126 }
    }
    chain prerouting_prematch {
        type filter hook prerouting priority dstnat - 1; policy accept;
        iifname "tun0" return
        ct direction reply return
        meta mark 0x00002024 ct mark set meta mark counter return
        ct mark 0x00002024 meta mark set ct mark counter return
        meta mark 0x00002023 ct mark set meta mark counter return
        ct mark 0x00002023 meta mark set ct mark counter return
        meta l4proto != { icmp, tcp, udp, ipv6-icmp } return
        tcp flags & (syn | ack) != syn return
        meta l4proto tcp meta mark 0x00002025 counter reject with tcp reset
        iifname "tun0" counter return
        ip saddr @inet4_local_address_set meta l4proto { tcp, udp } th dport 53 counter return
        ip6 saddr @inet6_local_address_set meta l4proto { tcp, udp } th dport 53 counter return
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        meta l4proto tcp counter queue flags bypass to 100
        meta l4proto udp counter queue flags bypass to 100
        icmp type echo-request icmp code 0 counter queue flags bypass to 100
        icmpv6 type echo-request icmpv6 code 0 counter queue flags bypass to 100
    }
    chain output_prematch {
        type route hook output priority mangle + 1; policy accept;
        ct direction reply return
        meta mark 0x00002024 ct mark set meta mark counter return
        ct mark 0x00002024 meta mark set ct mark counter return
        meta mark 0x00002023 ct mark set meta mark counter return
        ct mark 0x00002023 meta mark set ct mark counter return
        meta l4proto != { icmp, tcp, udp, ipv6-icmp } return
        tcp flags & (syn | ack) != syn return
        meta l4proto tcp meta mark 0x00002025 counter reject with tcp reset
        meta nfproto ipv4 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter return
        meta nfproto ipv6 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter return
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        meta l4proto tcp counter queue flags bypass to 100
        meta l4proto udp counter queue flags bypass to 100
        icmp type echo-request icmp code 0 counter queue flags bypass to 100
        icmpv6 type echo-request icmpv6 code 0 counter queue flags bypass to 100
    }
    chain output {
        type nat hook output priority mangle + 2; policy accept;
        meta mark 0x00002024 counter return
        ct mark 0x00002024 counter return
        ct mark 0x00002023 counter return
        meta nfproto ipv4 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter dnat ip to 172.18.0.2
        meta nfproto ipv6 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter dnat ip6 to fdfe:dcba:9876::2
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        tcp option mptcp exists counter drop
        meta l4proto tcp counter redirect to :7890 return
    }
    chain output_udp_icmp {
        type route hook output priority mangle + 2; policy accept;
        meta l4proto != { icmp, udp, ipv6-icmp } return
        meta mark 0x00002024 counter return
        ct mark 0x00002024 counter return
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        meta mark set 0x00002023 ct mark set meta mark counter return
    }
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport 7890 ct status ! dnat counter reject with tcp reset
    }
    chain prerouting {
        type nat hook prerouting priority dstnat + 2; policy accept;
        ct mark 0x00002024 counter return
        ct mark 0x00002023 counter return
        iifname "tun0" counter return
        ip saddr @inet4_local_address_set meta l4proto { tcp, udp } th dport 53 counter dnat ip to 172.18.0.2
        ip6 saddr @inet6_local_address_set meta l4proto { tcp, udp } th dport 53 counter dnat ip6 to fdfe:dcba:9876::2
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        tcp option mptcp exists counter drop
        meta l4proto tcp counter redirect to :7890 return
        meta mark set 0x00002023 ct mark set meta mark counter return
    }
    chain prerouting_udp_icmp {
        type filter hook prerouting priority dstnat + 3; policy accept;
        meta l4proto != { icmp, udp, ipv6-icmp } return
        iifname "tun0" counter return
        iifname != "tun0" ct mark 0x00002023 meta mark set ct mark counter
        ct mark != 0x00002023 meta mark set 0x00002024 ct mark set meta mark counter
    }
}
"#;

/// What `maximal_options` renders to -- tabs as four spaces -- and what nft(8)
/// 1.1.3 lists for it (counters without their counts).
const MAXIMAL: &str = r#"
table inet sail {
    set inet4_route_address_set {
        type ipv4_addr
        flags interval
        elements = { 1.0.0.0/23, 8.8.8.8 }
    }
    set inet6_route_address_set {
        type ipv6_addr
        flags interval
        elements = { 2001:4860::/32 }
    }
    set inet4_route_exclude_address_set {
        type ipv4_addr
        flags interval
        elements = { 114.114.114.114 }
    }
    set inet6_route_exclude_address_set {
        type ipv6_addr
        flags interval
    }
    set inet4_local_address_set {
        type ipv4_addr
        flags interval
        elements = { 127.0.0.0/8, 172.18.0.0/30, 192.168.1.0/24 }
    }
    set inet6_local_address_set {
        type ipv6_addr
        flags interval
        elements = { ::1, 2001:db8:1::/64, fdfe:dcba:9876::/126 }
    }
    set inet4_local_redirect_address_set {
        type ipv4_addr
        flags constant
        elements = { 10.7.0.1 }
    }
    set inet6_local_redirect_address_set {
        type ipv6_addr
        flags constant
        elements = { fd00:7::1 }
    }
    chain prerouting_prematch {
        type filter hook prerouting priority dstnat - 1; policy accept;
        iifname "tun0" return
        ct direction reply return
        meta mark 0x00002024 ct mark set meta mark counter return
        ct mark 0x00002024 meta mark set ct mark counter return
        meta mark 0x00002023 ct mark set meta mark counter return
        ct mark 0x00002023 meta mark set ct mark counter return
        meta l4proto != { icmp, tcp, udp, ipv6-icmp } return
        tcp flags & (syn | ack) != syn return
        meta l4proto tcp meta mark 0x00002025 counter reject with tcp reset
        iifname "tun0" counter return
        iifname != { "lo", "eth0" } counter return
        iifname { "eth2", "docker0" } counter return
        ip daddr != { 0.0.0.0/0 } counter return
        ip6 daddr != { 2000::/3 } counter return
        ip daddr { 10.0.0.0/8, 192.168.0.0/16 } counter return
        ip6 daddr { fc00::/7 } counter return
        ip saddr @inet4_local_address_set meta l4proto { tcp, udp } th dport 53 counter return
        ip6 saddr @inet6_local_address_set meta l4proto { tcp, udp } th dport 53 counter return
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        ip daddr != @inet4_route_address_set counter return
        ip6 daddr != @inet6_route_address_set counter return
        ip daddr @inet4_route_exclude_address_set counter return
        ip6 daddr @inet6_route_exclude_address_set counter return
        tcp option mptcp exists counter return
        meta l4proto tcp counter queue flags bypass to 100
        meta l4proto udp counter queue flags bypass to 100
        icmp type echo-request icmp code 0 counter queue flags bypass to 100
        icmpv6 type echo-request icmpv6 code 0 counter queue flags bypass to 100
    }
    chain output_prematch {
        type route hook output priority mangle + 1; policy accept;
        ct direction reply return
        meta mark 0x00002024 ct mark set meta mark counter return
        ct mark 0x00002024 meta mark set ct mark counter return
        meta mark 0x00002023 ct mark set meta mark counter return
        ct mark 0x00002023 meta mark set ct mark counter return
        meta l4proto != { icmp, tcp, udp, ipv6-icmp } return
        tcp flags & (syn | ack) != syn return
        meta l4proto tcp meta mark 0x00002025 counter reject with tcp reset
        meta skuid != { 0, 1000-1999, 3000 } counter return
        meta skuid 1500 counter return
        ip daddr != { 0.0.0.0/0 } counter return
        ip6 daddr != { 2000::/3 } counter return
        ip daddr { 10.0.0.0/8, 192.168.0.0/16 } counter return
        ip6 daddr { fc00::/7 } counter return
        meta nfproto ipv4 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter return
        meta nfproto ipv6 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter return
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        ip daddr != @inet4_route_address_set counter return
        ip6 daddr != @inet6_route_address_set counter return
        ip daddr @inet4_route_exclude_address_set counter return
        ip6 daddr @inet6_route_exclude_address_set counter return
        tcp option mptcp exists counter return
        meta l4proto tcp counter queue flags bypass to 100
        meta l4proto udp counter queue flags bypass to 100
        icmp type echo-request icmp code 0 counter queue flags bypass to 100
        icmpv6 type echo-request icmpv6 code 0 counter queue flags bypass to 100
    }
    chain output {
        type nat hook output priority mangle + 2; policy accept;
        meta mark 0x00002024 counter return
        ct mark 0x00002024 counter return
        ct mark 0x00002023 counter return
        meta skuid != { 0, 1000-1999, 3000 } counter return
        meta skuid 1500 counter return
        ip daddr != { 0.0.0.0/0 } counter return
        ip6 daddr != { 2000::/3 } counter return
        ip daddr { 10.0.0.0/8, 192.168.0.0/16 } counter return
        ip6 daddr { fc00::/7 } counter return
        meta nfproto ipv4 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter dnat ip to 172.18.0.2
        meta nfproto ipv6 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter dnat ip6 to fdfe:dcba:9876::2
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        ip daddr != @inet4_route_address_set counter return
        ip6 daddr != @inet6_route_address_set counter return
        ip daddr @inet4_route_exclude_address_set counter return
        ip6 daddr @inet6_route_exclude_address_set counter return
        tcp option mptcp exists counter return
        ip daddr != @inet4_local_redirect_address_set meta l4proto tcp counter redirect to :7890 return
        ip6 daddr != @inet6_local_redirect_address_set meta l4proto tcp counter redirect to :7890 return
    }
    chain output_route {
        type route hook output priority mangle + 2; policy accept;
        meta l4proto tcp meta mark != 0x00002023 ip daddr @inet4_local_redirect_address_set meta mark set 0x00002023 ct mark set meta mark counter
        meta l4proto tcp meta mark != 0x00002023 ip6 daddr @inet6_local_redirect_address_set meta mark set 0x00002023 ct mark set meta mark counter
    }
    chain output_udp_icmp {
        type route hook output priority mangle + 2; policy accept;
        meta l4proto != { icmp, udp, ipv6-icmp } return
        meta mark 0x00002024 counter return
        ct mark 0x00002024 counter return
        meta skuid != { 0, 1000-1999, 3000 } counter return
        meta skuid 1500 counter return
        ip daddr != { 0.0.0.0/0 } counter return
        ip6 daddr != { 2000::/3 } counter return
        ip daddr { 10.0.0.0/8, 192.168.0.0/16 } counter return
        ip6 daddr { fc00::/7 } counter return
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        ip daddr != @inet4_route_address_set counter return
        ip6 daddr != @inet6_route_address_set counter return
        ip daddr @inet4_route_exclude_address_set counter return
        ip6 daddr @inet6_route_exclude_address_set counter return
        tcp option mptcp exists counter return
        meta mark set 0x00002023 ct mark set meta mark counter return
    }
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport 7890 ct status ! dnat counter reject with tcp reset
    }
    chain prerouting {
        type nat hook prerouting priority dstnat + 2; policy accept;
        ct mark 0x00002024 counter return
        ct mark 0x00002023 counter return
        iifname "tun0" counter return
        iifname != { "lo", "eth0" } counter return
        iifname { "eth2", "docker0" } counter return
        ip daddr != { 0.0.0.0/0 } counter return
        ip6 daddr != { 2000::/3 } counter return
        ip daddr { 10.0.0.0/8, 192.168.0.0/16 } counter return
        ip6 daddr { fc00::/7 } counter return
        ip saddr @inet4_local_address_set meta l4proto { tcp, udp } th dport 53 counter dnat ip to 172.18.0.2
        ip6 saddr @inet6_local_address_set meta l4proto { tcp, udp } th dport 53 counter dnat ip6 to fdfe:dcba:9876::2
        ip daddr @inet4_local_address_set counter return
        ip6 daddr @inet6_local_address_set counter return
        ip daddr != @inet4_route_address_set counter return
        ip6 daddr != @inet6_route_address_set counter return
        ip daddr @inet4_route_exclude_address_set counter return
        ip6 daddr @inet6_route_exclude_address_set counter return
        tcp option mptcp exists counter return
        ip daddr != @inet4_local_redirect_address_set meta l4proto tcp counter redirect to :7890 return
        ip6 daddr != @inet6_local_redirect_address_set meta l4proto tcp counter redirect to :7890 return
        meta mark set 0x00002023 ct mark set meta mark counter return
    }
    chain prerouting_filter {
        type filter hook prerouting priority dstnat + 2; policy accept;
        meta l4proto tcp meta mark != 0x00002023 ip daddr @inet4_local_redirect_address_set meta mark set 0x00002023 counter
        meta l4proto tcp meta mark != 0x00002023 ip6 daddr @inet6_local_redirect_address_set meta mark set 0x00002023 counter
    }
    chain prerouting_udp_icmp {
        type filter hook prerouting priority dstnat + 3; policy accept;
        meta l4proto != { icmp, udp, ipv6-icmp } return
        iifname "tun0" counter return
        iifname != "tun0" ct mark 0x00002023 meta mark set ct mark counter
        ct mark != 0x00002023 meta mark set 0x00002024 ct mark set meta mark counter
    }
}
"#;

/// What `single_stack_options` renders to -- tabs as four spaces -- and what nft(8)
/// 1.1.3 lists for it (counters without their counts).
const SINGLE_STACK: &str = r#"
table inet sail {
    set inet4_route_exclude_address_set {
        type ipv4_addr
        flags interval
    }
    set inet4_local_address_set {
        type ipv4_addr
        flags interval
        elements = { 127.0.0.0/8, 172.18.0.0/30, 192.168.1.0/24 }
    }
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport 7890 ct status ! dnat counter reject with tcp reset
    }
    chain prerouting {
        type nat hook prerouting priority dstnat + 1; policy accept;
        iifname "tun0" counter return
        iifname != "eth0" counter return
        ip saddr @inet4_local_address_set meta l4proto { tcp, udp } th dport 53 counter dnat ip to 172.18.0.2
        ip daddr @inet4_local_address_set counter return
        ip daddr @inet4_route_exclude_address_set counter return
        tcp option mptcp exists counter drop
        meta nfproto ipv6 counter reject with icmpv6 no-route
        meta nfproto ipv4 meta l4proto tcp counter redirect to :7890 return
        meta mark set 0x00002023 ct mark set meta mark counter return
    }
    chain prerouting_udp_icmp {
        type filter hook prerouting priority dstnat + 2; policy accept;
        meta l4proto != { icmp, udp, ipv6-icmp } return
        iifname "tun0" counter return
        iifname != "tun0" ct mark 0x00002023 meta mark set ct mark counter
        ct mark != 0x00002023 meta mark set 0x00002024 ct mark set meta mark counter
    }
}
"#;

/// The ruleset in the kernel, read back with nft(8). Run as root in a
/// network namespace of its own, since nftables state is per namespace:
///
/// ```text
/// ip netns add sail-ar-test
/// ip netns exec sail-ar-test env SAIL_NFT=<nft> <test binary> --ignored \
///     platform::auto_redirect::tests::kernel
/// ip netns del sail-ar-test
/// ```
#[cfg(target_os = "linux")]
mod kernel {
    use std::process::Command;

    use super::*;

    /// nft(8): `$SAIL_NFT`, or `nft`.
    fn nft(args: &[&str]) -> String {
        let bin = std::env::var("SAIL_NFT").unwrap_or_else(|_| "nft".into());
        let out = Command::new(&bin)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("cannot run {}: {}", bin, e));
        assert!(
            out.status.success(),
            "nft {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// The table as nft(8) lists it, a line per rule: indentation dropped,
    /// counters without their counts, set elements wrapped over lines
    /// joined.
    fn listing(table: &str) -> String {
        let raw = nft(&["list", "table", "inet", table]);
        let mut out = String::new();
        for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let mut words: Vec<&str> = Vec::new();
            let mut it = line.split(' ').peekable();
            while let Some(w) = it.next() {
                words.push(w);
                if w == "counter" && it.peek() == Some(&"packets") {
                    // packets N bytes N
                    it.nth(3);
                }
            }
            out += &crate::platform::nft::older_notation(&words.join(" "));
            out.push(if line.ends_with(',') { ' ' } else { '\n' });
        }
        out
    }

    /// Sets the ruleset up, twice -- the second time over the first,
    /// which it replaces -- and checks the kernel has what `render` says.
    fn set_up(o: &RulesetOptions) -> String {
        setup(o)
            .unwrap()
            .commit()
            .unwrap_or_else(|e| panic!("setup: {}", e));
        let got = listing(&o.table);
        println!("{}", got);
        assert_eq!(lines(&got), lines(&render(o).unwrap()));
        setup(o)
            .unwrap()
            .commit()
            .unwrap_or_else(|e| panic!("setup again: {}", e));
        assert_eq!(listing(&o.table), got);
        got
    }

    /// The elements of a set in a listing, as nft(8) writes them: `{ a, b }`,
    /// or nothing for none.
    fn elements<'a>(listing: &'a str, set: &str) -> &'a str {
        let head = format!("set {} {{", set);
        listing
            .lines()
            .skip_while(|l| *l != head)
            .take_while(|l| *l != "}")
            .find_map(|l| l.strip_prefix("elements = "))
            .unwrap_or("")
    }

    fn gone(table: &str) -> bool {
        !crate::platform::nft::list_tables(None)
            .unwrap()
            .iter()
            .any(|t| t.name == table)
    }

    fn tear_down(table: &str) {
        cleanup(table).commit().unwrap();
        assert!(gone(table));
        // Gone, it is fine to clean up again.
        cleanup(table).commit().unwrap();
    }

    #[test]
    #[ignore = "requires root and nf_tables"]
    fn kernel_default() {
        let o = default_options();
        let got = set_up(&o);
        assert_eq!(lines(&got), lines(DEFAULT));
        tear_down(&o.table);
    }

    #[test]
    #[ignore = "requires root and nf_tables"]
    fn kernel_single_stack() {
        let o = single_stack_options();
        let got = set_up(&o);
        assert_eq!(lines(&got), lines(SINGLE_STACK));
        tear_down(&o.table);
    }

    #[test]
    #[ignore = "requires root and nf_tables"]
    fn kernel_maximal_and_updates() {
        let o = maximal_options();
        let got = set_up(&o);
        assert_eq!(lines(&got), lines(MAXIMAL));

        // The interfaces change.
        update_local_prefixes(
            &o,
            &prefixes(&["127.0.0.1/8", "10.9.8.7/24", "::1/128", "2001:db8:2::5/64"]),
        )
        .commit()
        .unwrap_or_else(|e| panic!("update local: {}", e));
        let got = listing(&o.table);
        assert_eq!(
            elements(&got, "inet4_local_address_set"),
            "{ 10.9.8.0/24, 127.0.0.0/8 }"
        );
        assert_eq!(
            elements(&got, "inet6_local_address_set"),
            "{ ::1, 2001:db8:2::/64 }"
        );
        // Emptied.
        update_local_prefixes(&o, &prefixes(&["127.0.0.1/8"]))
            .commit()
            .unwrap();
        let got = listing(&o.table);
        assert_eq!(elements(&got, "inet6_local_address_set"), "");

        // The rule-sets change: thousands of prefixes, more than one
        // message holds, and one overlapping.
        let mut big: Vec<(IpAddr, u8)> = (0..3000u32)
            .map(|i| {
                let a = std::net::Ipv4Addr::from((20u32 << 24) + (i << 9));
                (IpAddr::V4(a), 24)
            })
            .collect();
        big.push(prefix("20.0.0.0/23"));
        big.push(prefix("2a00::/16"));
        let include = AddressSet { prefixes: big };
        update_route_address_sets(&o, Some(&include), Some(&AddressSet::default()))
            .commit()
            .unwrap_or_else(|e| panic!("update rule-sets: {}", e));
        let got = listing(&o.table);
        let v4 = elements(&got, "inet4_route_address_set");
        // The /23 joins the first two /24s, the second adjacent to it.
        assert_eq!(v4.matches(',').count() + 1, 2999, "{}", v4);
        assert!(
            v4.starts_with("{ 20.0.0.0-20.0.2.255, 20.0.4.0/24,"),
            "{}",
            v4
        );
        assert_eq!(elements(&got, "inet6_route_address_set"), "{ 2a00::/16 }");
        assert_eq!(elements(&got, "inet4_route_exclude_address_set"), "");
        // The chains stay as they were.
        let chains = |l: &str| -> Vec<String> {
            lines(l)
                .into_iter()
                .skip_while(|l| !l.starts_with("chain "))
                .map(String::from)
                .collect()
        };
        assert_eq!(chains(&got), chains(MAXIMAL));

        tear_down(&o.table);
    }
}
