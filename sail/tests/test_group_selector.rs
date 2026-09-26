#![cfg(all(feature = "outbound-select", feature = "outbound-redirect"))]

mod test_group_common;

use std::time::Duration;

use serde_json::json;
use test_group_common::*;

fn selector(extra: serde_json::Value) -> serde_json::Value {
    let mut group = json!({ "type": "selector", "tag": "sel", "outbounds": ["a", "b", "c"] });
    group
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    json!([
        group,
        member("a", UNSERVED),
        member("b", UNSERVED),
        member("c", UNSERVED)
    ])
}

fn error(outbounds: serde_json::Value) -> String {
    manager(outbounds, &env("selector-error"))
        .err()
        .expect("the configuration must be refused")
        .to_string()
}

#[test]
fn the_first_member_is_selected_unless_a_default_is_given() {
    let m = manager(selector(json!({})), &env("selector-first")).unwrap();
    assert_eq!(selected(&m, "sel"), "a");
    let m = manager(
        selector(json!({ "default": "c" })),
        &env("selector-default"),
    )
    .unwrap();
    assert_eq!(selected(&m, "sel"), "c");
}

#[test]
fn a_selection_survives_a_restart() {
    let instance = env("selector-restart");
    let rt = rt();
    let m = manager(selector(json!({ "default": "a" })), &instance).unwrap();
    rt.block_on(async {
        let selector = m.get_selector("sel").unwrap();
        selector.write().await.set_selected("b").unwrap();
    });
    drop(m);

    // The same instance directory, as after a restart: the selection is
    // back, over the default.
    let m = manager(selector(json!({ "default": "a" })), &instance).unwrap();
    assert_eq!(selected(&m, "sel"), "b");

    // Another instance, with a directory of its own, does not see it.
    let m = manager(selector(json!({ "default": "a" })), &env("selector-other")).unwrap();
    assert_eq!(selected(&m, "sel"), "a");
}

#[test]
fn a_kept_selection_that_is_no_longer_a_member_falls_back_to_the_default() {
    let env = env("selector-stale");
    let rt = rt();
    let m = manager(selector(json!({})), &env).unwrap();
    rt.block_on(async {
        let selector = m.get_selector("sel").unwrap();
        selector.write().await.set_selected("c").unwrap();
    });
    drop(m);

    let without_c = json!([
        { "type": "selector", "tag": "sel", "outbounds": ["a", "b"], "default": "b" },
        member("a", UNSERVED),
        member("b", UNSERVED),
    ]);
    let m = manager(without_c, &env).unwrap();
    assert_eq!(selected(&m, "sel"), "b");
}

#[test]
fn a_corrupt_cache_is_ignored() {
    let env = env("selector-corrupt");
    let dir = env.host.cache_dir.clone().unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("selector.cache"), b"\xff\xff\xff not protobuf").unwrap();
    let m = manager(selector(json!({ "default": "b" })), &env).unwrap();
    assert_eq!(selected(&m, "sel"), "b");
    // And is replaced by the next selection.
    rt().block_on(async {
        let selector = m.get_selector("sel").unwrap();
        selector.write().await.set_selected("c").unwrap();
    });
    let m = manager(selector(json!({ "default": "b" })), &env).unwrap();
    assert_eq!(selected(&m, "sel"), "c");
}

#[test]
fn selecting_what_is_not_a_member_is_an_error() {
    let m = manager(selector(json!({})), &env("selector-bad-select")).unwrap();
    rt().block_on(async {
        let selector = m.get_selector("sel").unwrap();
        assert!(selector.write().await.set_selected("z").is_err());
    });
    assert_eq!(selected(&m, "sel"), "a");
}

#[test]
fn configuration_mistakes_are_errors() {
    let msg = error(json!([{ "type": "selector", "tag": "sel", "outbounds": [] }]));
    assert!(msg.contains("[sel]"), "{}", msg);

    let msg = error(json!([
        { "type": "selector", "tag": "sel", "outbounds": ["a", "nope"] },
        member("a", UNSERVED),
    ]));
    assert!(msg.contains("nope"), "{}", msg);

    let msg = error(selector(json!({ "default": "nope" })));
    assert!(msg.contains("default") && msg.contains("nope"), "{}", msg);

    let msg = error(selector(json!({ "tolerance": 50 })));
    assert!(msg.contains("tolerance"), "{}", msg);
}

#[test]
fn connections_go_to_the_selected_member_and_are_interrupted_on_a_switch() {
    let rt = rt();
    rt.block_on(async {
        let (_a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let outbounds = json!([
            {
                "type": "selector",
                "tag": "sel",
                "outbounds": ["a", "b"],
                "interrupt_exist_connections": true,
            },
            member("a", p_a),
            member("b", p_b),
        ]);
        let m = manager(outbounds, &env("selector-interrupt")).unwrap();
        let sess = session("10.0.0.1", "example.com");
        let mut old = connect(&m, "sel", &sess).await.unwrap();
        assert_eq!(which(&mut old).await.unwrap(), "a");

        m.get_selector("sel")
            .unwrap()
            .write()
            .await
            .set_selected("b")
            .unwrap();
        assert_eq!(reached(&m, "sel", &sess).await.unwrap(), "b");
        let err = which(&mut old).await.unwrap_err();
        assert!(err.to_string().contains("switched"), "{}", err);
    });
}

#[test]
fn without_interrupting_connections_stay_on_their_member() {
    let rt = rt();
    rt.block_on(async {
        let (_a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let outbounds = json!([
            { "type": "selector", "tag": "sel", "outbounds": ["a", "b"] },
            member("a", p_a),
            member("b", p_b),
        ]);
        let m = manager(outbounds, &env("selector-no-interrupt")).unwrap();
        let sess = session("10.0.0.1", "example.com");
        let mut old = connect(&m, "sel", &sess).await.unwrap();
        assert_eq!(which(&mut old).await.unwrap(), "a");
        m.get_selector("sel")
            .unwrap()
            .write()
            .await
            .set_selected("b")
            .unwrap();
        assert_eq!(which(&mut old).await.unwrap(), "a");
        assert_eq!(reached(&m, "sel", &sess).await.unwrap(), "b");
    });
}
