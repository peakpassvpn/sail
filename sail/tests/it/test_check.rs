//! What a check of a configuration file (`sail -T`) tells: the warnings a
//! start would log, and why a configuration is refused.

#![cfg(all(feature = "outbound-direct", feature = "rule-set"))]

fn file(name: &str, contents: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sail-check-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

/// A check gives the warnings a start would log, as `sing-box check`
/// prints them.
#[test]
fn a_check_gives_the_warnings() {
    let config = file(
        "config.json",
        br#"{ "outbounds": [{ "type": "direct", "tcp_multi_path": true }] }"#,
    );
    let warnings =
        sail::test_config_with_warnings(config.to_str().unwrap(), &Default::default()).unwrap();
    assert_eq!(
        warnings,
        ["outbounds[0].tcp_multi_path: sail does not implement this field; ignored"]
    );
}

/// A rule-set that does not read is refused with the reason, as sing-box
/// gives it ("unexpected EOF"), not with its name alone.
#[test]
fn a_rule_set_that_does_not_read_says_why() {
    let whole = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rule_set/two_rules.srs"
    ))
    .unwrap();
    let srs = file("cut.srs", &whole[..30]);
    let config = srs.with_file_name("config.json");
    std::fs::write(
        &config,
        serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": {
                "rule_set": [{ "type": "local", "tag": "rs", "format": "binary", "path": srs }],
                "rules": [{ "rule_set": "rs", "outbound": "direct" }]
            }
        })
        .to_string(),
    )
    .unwrap();
    let err =
        sail::test_config_with_warnings(config.to_str().unwrap(), &Default::default()).unwrap_err();
    let told = format!("{:#}", err);
    assert!(told.starts_with("route.rule_set[0]: [rs]: "), "{}", told);
    assert!(
        told.ends_with("unexpected end of file: the compressed rules are cut short"),
        "{}",
        told
    );
}
