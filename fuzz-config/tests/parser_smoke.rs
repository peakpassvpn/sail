use sail_config_fuzz::{
    parse_auto_bytes, parse_dns_message_bytes, parse_json_bytes, parse_protocol_inbound_bytes,
    parse_rule_set_binary_bytes, parse_rule_set_source_bytes, parse_sniff_bytes,
    parse_subscription_bytes, MAX_INPUT_LEN,
};

const SEEDS: &[&[u8]] = &[
    include_bytes!("../seeds/config_json/minimal.jsonc"),
    include_bytes!("../seeds/config_json/full-shape.jsonc"),
    include_bytes!("../seeds/config_json/schema-error.json"),
    include_bytes!("../seeds/config_json/deep-rules.json"),
    include_bytes!("../seeds/config_json/over-recursion-limit.json"),
    include_bytes!("../seeds/config_json/string-boundaries.json"),
    include_bytes!("../seeds/config_json/truncated.json"),
    include_bytes!("../seeds/config_auto/clash-like.yaml"),
    include_bytes!("../seeds/config_auto/surge-like.conf"),
];

const SUBSCRIPTION_SEEDS: &[&[u8]] = &[
    include_bytes!("../seeds/subscription/synthetic-links.txt"),
    include_bytes!("../seeds/subscription/status-lines.txt"),
];

#[test]
fn committed_seeds_are_bounded_and_do_not_panic() {
    for seed in SEEDS {
        assert!(seed.len() <= MAX_INPUT_LEN);
        assert!(parse_json_bytes(seed));
        assert!(parse_auto_bytes(seed));
    }
    for seed in SUBSCRIPTION_SEEDS {
        assert!(seed.len() <= MAX_INPUT_LEN);
        assert!(parse_subscription_bytes(seed));
    }
}

#[test]
fn malformed_and_deep_inputs_return_without_panicking() {
    let mut nested = String::from(r#"{"route":{"rules":["#);
    for _ in 0..192 {
        nested.push_str(r#"{"type":"logical","mode":"and","rules":["#);
    }
    nested.push_str(r#"{"port":53}"#);
    for _ in 0..192 {
        nested.push_str("]}");
    }
    nested.push_str("]}}");

    assert!(parse_json_bytes(nested.as_bytes()));
    assert!(parse_auto_bytes(nested.as_bytes()));
    assert!(parse_json_bytes(br#"{"dns":{"timeout":"1e999h"}}"#));
    assert!(!parse_json_bytes(&[0xff, 0xfe, 0xfd]));
}

#[test]
fn valid_jsonc_is_accepted_and_format_errors_are_clean() {
    let valid = include_str!("../seeds/config_json/minimal.jsonc");
    assert!(sail::config::Config::from_json(valid).is_ok());
    assert!(sail::config::from_string(valid).is_ok());

    let clash = include_str!("../seeds/config_auto/clash-like.yaml");
    let surge = include_str!("../seeds/config_auto/surge-like.conf");
    assert!(sail::config::from_string(clash).is_err());
    assert!(sail::config::from_string(surge).is_err());
}

#[test]
fn parsing_does_not_load_configured_files_or_urls() {
    let inert_locations = r#"{
        "certificate": { "certificate_path": "/does/not/exist/cert.pem" },
        "route": { "rule_set": [{
            "type": "remote",
            "tag": "not-fetched",
            "url": "http://127.0.0.1:9/not-fetched.json",
            "initial_path": "/does/not/exist/rules.json"
        }] }
    }"#;
    assert!(sail::config::Config::from_json(inert_locations).is_ok());
}

#[test]
fn oversized_inputs_are_rejected_by_the_harness() {
    let oversized = vec![b' '; MAX_INPUT_LEN + 1];
    assert!(!parse_json_bytes(&oversized));
    assert!(!parse_auto_bytes(&oversized));
    assert!(!parse_subscription_bytes(&oversized));
}

#[test]
fn subscription_harness_rejects_non_utf8_and_accepts_plain_or_base64_text() {
    assert!(!parse_subscription_bytes(&[0xff, 0xfe, 0xfd]));
    for seed in SUBSCRIPTION_SEEDS {
        assert!(parse_subscription_bytes(seed));
    }
    // "trojan://password@example.com:443" in standard base64.
    assert!(parse_subscription_bytes(
        b"dHJvamFuOi8vcGFzc3dvcmRAZXhhbXBsZS5jb206NDQz"
    ));
}

#[test]
fn extreme_structure_reaches_the_parser() {
    // This exceeds the previous harness-only 512-container cutoff. serde_json
    // must see it and apply its own recursion handling.
    let deeply_nested = format!("{}0{}", "[".repeat(600), "]".repeat(600));
    assert!(parse_json_bytes(deeply_nested.as_bytes()));
    assert!(parse_auto_bytes(deeply_nested.as_bytes()));

    // This exceeds the previous 65,536 structural-token cutoff while staying
    // below the byte limit.
    let dense = format!("[{}]", "0,".repeat(70_000));
    assert!(dense.len() < MAX_INPUT_LEN);
    assert!(parse_json_bytes(dense.as_bytes()));
    assert!(parse_auto_bytes(dense.as_bytes()));
}

#[test]
fn duration_overflow_regression_does_not_panic() {
    let input = include_str!("../regressions/config_json/duration-overflow.min.json");
    assert!(parse_json_bytes(input.as_bytes()));
    let error = sail::config::Config::from_json(input).unwrap_err();
    assert!(error.to_string().contains("invalid duration"), "{error}");
}

#[test]
fn rule_set_imports_do_not_panic() {
    assert!(parse_rule_set_source_bytes(include_bytes!(
        "../seeds/rule_set_source/minimal.json"
    )));
    assert!(parse_rule_set_binary_bytes(include_bytes!(
        "../../sail/tests/fixtures/rule_set/domains.srs"
    )));
    assert!(parse_rule_set_source_bytes(b"{\"version\":3,"));
    assert!(parse_rule_set_binary_bytes(b"SRS\x09"));
}

#[test]
fn dns_sniff_and_inbound_protocol_inputs_do_not_panic() {
    // A minimal standard DNS query for example.com A.
    let dns =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    assert!(parse_dns_message_bytes(dns));
    assert!(parse_sniff_bytes(dns));
    assert!(parse_sniff_bytes(include_bytes!(
        "../seeds/sniff/http-request"
    )));
    assert!(parse_protocol_inbound_bytes(b"\x05\x04"));
    assert!(parse_protocol_inbound_bytes(
        b"\x01\x7f\x00\x00\x01\x00\x35"
    ));
}

#[test]
fn binary_parser_harnesses_reject_oversized_inputs() {
    let oversized = vec![0; MAX_INPUT_LEN + 1];
    assert!(!parse_rule_set_source_bytes(&oversized));
    assert!(!parse_rule_set_binary_bytes(&oversized));
    assert!(!parse_dns_message_bytes(&oversized));
    assert!(!parse_sniff_bytes(&oversized));
    assert!(!parse_protocol_inbound_bytes(&oversized));
}
