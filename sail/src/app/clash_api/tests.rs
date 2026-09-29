use super::*;

#[test]
fn a_controller_is_host_and_port() {
    assert_eq!(
        listen_address("127.0.0.1:9090").unwrap(),
        "127.0.0.1:9090".parse().unwrap()
    );
    assert_eq!(
        listen_address("[::1]:9090").unwrap(),
        "[::1]:9090".parse().unwrap()
    );
    // Mihomo's: an empty host is every address.
    assert_eq!(
        listen_address(":9090").unwrap(),
        "0.0.0.0:9090".parse().unwrap()
    );
    assert_eq!(
        listen_address("localhost:9090").unwrap(),
        "127.0.0.1:9090".parse().unwrap()
    );
    for bad in ["9090", "example.com:9090", "127.0.0.1:x", "127.0.0.1:70000"] {
        assert!(listen_address(bad).is_err(), "{}", bad);
    }
}

#[test]
fn query_values_are_decoded() {
    assert_eq!(
        query_value("a=1&token=x%2By%3D", "token").as_deref(),
        Some("x+y=")
    );
    assert_eq!(query_value("token=a+b", "token").as_deref(), Some("a b"));
    assert_eq!(query_value("tokens=1", "token"), None);
    assert_eq!(
        query_value("token=%zz%4", "token").as_deref(),
        Some("%zz%4")
    );
}

#[test]
fn without_a_strong_secret_it_is_not_served() {
    let api = |secret: Option<&str>| ClashApi {
        external_controller: Some("127.0.0.1:0".into()),
        secret: secret.map(str::to_owned),
        ..Default::default()
    };
    assert!(bind(Some(&api(None))).unwrap().is_none());
    assert!(bind(Some(&api(Some("123456")))).unwrap().is_none());
    assert!(bind(Some(&api(Some(&crate::generate::secret()))))
        .unwrap()
        .is_some());
    // Nowhere to listen: not served, whatever the secret.
    assert!(bind(Some(&ClashApi::default())).unwrap().is_none());
    assert!(bind(None).unwrap().is_none());
}

#[test]
fn the_view_tells_the_listeners_and_modes() {
    let config = crate::config::Config::from_json(
        &serde_json::json!({
            "log": { "level": "warn" },
            "dns": { "strategy": "ipv4_only" },
            "inbounds": [
                { "type": "mixed", "tag": "m", "listen": "0.0.0.0", "listen_port": 7890 },
                { "type": "socks", "tag": "s", "listen_port": 7891 },
            ],
            "outbounds": [{ "type": "direct" }],
            "route": { "rules": [
                { "clash_mode": "Direct", "outbound": "direct" },
                { "clash_mode": "Custom", "outbound": "direct" },
                { "type": "logical", "mode": "or", "rules": [{ "clash_mode": "Global" }],
                  "outbound": "direct" },
            ] },
            "clash_api": { "default_mode": "Rule" },
        })
        .to_string(),
    )
    .unwrap();
    let view = ConfigView::of(&config);
    assert_eq!(
        (view.mixed_port, view.socks_port, view.port),
        (7890, 7891, 0)
    );
    assert!(view.allow_lan);
    assert!(!view.ipv6);
    assert_eq!(view.log_level, "warning");
    // sing-box's order: others sorted, then Clash's; the default first.
    assert_eq!(view.modes, ["Rule", "Custom", "Global", "Direct"]);
}

#[test]
fn sing_box_s_place_is_read_and_one_place_only() {
    let config = crate::config::Config::from_json(
        r#"{ "experimental": { "clash_api": { "external_controller": "127.0.0.1:9090",
               "secret": "s" } } }"#,
    )
    .unwrap();
    assert_eq!(
        config.clash_api.unwrap().external_controller.as_deref(),
        Some("127.0.0.1:9090")
    );
    let err = crate::config::Config::from_json(
        r#"{ "clash_api": { "default_mode": "Rule" },
             "experimental": { "clash_api": { "default_mode": "Rule" } } }"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("keep one"), "{}", err);
}
