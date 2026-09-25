#![cfg(all(feature = "outbound-urltest", feature = "outbound-redirect"))]

mod test_group_common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::json;
use test_group_common::*;

/// Tests through a member go to its server whatever the URL says: the
/// members are redirects.
const URL: &str = "http://probe.test/generate_204";

fn urltest(members: &[(&str, u16)], extra: serde_json::Value) -> serde_json::Value {
    let tags: Vec<&str> = members.iter().map(|(tag, _)| *tag).collect();
    let mut group = json!({
        "type": "urltest",
        "tag": "auto",
        "outbounds": tags,
        "url": URL,
        "interval": "10s",
    });
    group
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let mut outbounds = vec![group];
    outbounds.extend(members.iter().map(|(tag, port)| member(tag, *port)));
    serde_json::Value::Array(outbounds)
}

fn tested(m: &sail::app::outbound::manager::OutboundManager) -> bool {
    latencies(m, "auto").iter().all(|(_, l)| l.is_some())
}

#[test]
fn the_fastest_member_is_selected_and_latencies_are_kept() {
    rt().block_on(async {
        let _a = serve(33110, "a", Duration::from_millis(300)).await;
        let _b = serve(33111, "b", Duration::ZERO).await;
        let _c = serve(33112, "c", Duration::from_millis(120)).await;
        let m = manager(
            urltest(&[("a", 33110), ("b", 33111), ("c", 33112)], json!({})),
            &env("urltest-fastest"),
        )
        .unwrap();
        // The first member until the first tests are done.
        assert_eq!(selected(&m, "auto"), "a");
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);

        assert_eq!(selected(&m, "auto"), "b");
        let l: Vec<Duration> = latencies(&m, "auto")
            .into_iter()
            .map(|(_, l)| l.unwrap())
            .collect();
        assert!(l[1] < l[2] && l[2] < l[0], "{:?}", l);
        let sess = session("10.0.0.1", "example.com");
        assert_eq!(reached(&m, "auto", &sess).await.unwrap(), "b");
    });
}

#[test]
fn a_faster_member_within_the_tolerance_does_not_make_it_switch() {
    rt().block_on(async {
        let _a = serve(33113, "a", Duration::from_millis(100)).await;
        let _b = serve(33114, "b", Duration::ZERO).await;
        let m = manager(
            urltest(&[("a", 33113), ("b", 33114)], json!({ "tolerance": 1000 })),
            &env("urltest-tolerant"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        assert_eq!(selected(&m, "auto"), "a");
    });
}

#[test]
fn a_faster_member_beyond_the_tolerance_makes_it_switch() {
    rt().block_on(async {
        let _a = serve(33115, "a", Duration::from_millis(200)).await;
        let _b = serve(33116, "b", Duration::ZERO).await;
        let m = manager(
            urltest(&[("a", 33115), ("b", 33116)], json!({ "tolerance": 20 })),
            &env("urltest-intolerant"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        assert_eq!(selected(&m, "auto"), "b");
    });
}

#[test]
fn a_member_that_dies_is_left() {
    rt().block_on(async {
        let a = serve(33117, "a", Duration::ZERO).await;
        let _b = serve(33118, "b", Duration::from_millis(100)).await;
        let m = manager(
            urltest(
                &[("a", 33117), ("b", 33118)],
                json!({ "interval": "300ms" }),
            ),
            &env("urltest-dies"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        assert_eq!(selected(&m, "auto"), "a");

        a.abort();
        assert!(
            eventually(Duration::from_secs(5), || selected(&m, "auto") == "b").await,
            "{:?}",
            latencies(&m, "auto")
        );
        assert!(latencies(&m, "auto")[0].1.is_none());
        let sess = session("10.0.0.1", "example.com");
        assert_eq!(reached(&m, "auto", &sess).await.unwrap(), "b");
    });
}

#[test]
fn a_switch_interrupts_connections_when_asked_to() {
    rt().block_on(async {
        let (_a, a_delay) = serve_adjustable(33119, "a", Duration::ZERO).await;
        let _b = serve(33120, "b", Duration::from_millis(100)).await;
        let m = manager(
            urltest(
                &[("a", 33119), ("b", 33120)],
                json!({ "interval": "300ms", "interrupt_exist_connections": true }),
            ),
            &env("urltest-interrupt"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        let sess = session("10.0.0.1", "example.com");
        let mut old = connect(&m, "auto", &sess).await.unwrap();
        assert_eq!(which(&mut old).await.unwrap(), "a");

        a_delay.store(1000, Ordering::Relaxed);
        assert!(eventually(Duration::from_secs(5), || selected(&m, "auto") == "b").await);
        let err = which(&mut old).await.unwrap_err();
        assert!(err.to_string().contains("switched"), "{}", err);
    });
}

#[test]
fn it_is_not_selected_by_hand() {
    let m = manager(
        urltest(&[("a", 33121), ("b", 33122)], json!({})),
        &env("urltest-by-hand"),
    )
    .unwrap();
    rt().block_on(async {
        let selector = m.get_selector("auto").unwrap();
        assert!(!selector.read().await.is_selectable());
        assert!(selector.write().await.set_selected("b").is_err());
    });
}

#[test]
fn configuration_mistakes_are_errors() {
    let error = |outbounds| {
        manager(outbounds, &env("urltest-error"))
            .err()
            .expect("the configuration must be refused")
            .to_string()
    };
    let msg = error(json!([{ "type": "urltest", "tag": "auto", "outbounds": [] }]));
    assert!(msg.contains("[auto]"), "{}", msg);
    let msg = error(json!([
        { "type": "urltest", "tag": "auto", "outbounds": ["a", "nope"] },
        member("a", 33121),
    ]));
    assert!(msg.contains("nope"), "{}", msg);
    let msg = error(urltest(&[("a", 33121)], json!({ "url": "ftp://x/" })));
    assert!(msg.contains("url"), "{}", msg);
    let msg = error(urltest(&[("a", 33121)], json!({ "interval": "0s" })));
    assert!(msg.contains("interval"), "{}", msg);
    let msg = error(urltest(&[("a", 33121)], json!({ "interval": "soon" })));
    assert!(msg.contains("interval"), "{}", msg);
    let msg = error(urltest(&[("a", 33121)], json!({ "default": "a" })));
    assert!(msg.contains("default"), "{}", msg);
}
