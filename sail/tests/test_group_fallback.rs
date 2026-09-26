#![cfg(all(feature = "outbound-fallback", feature = "outbound-redirect"))]

mod test_group_common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::json;
use test_group_common::*;

/// Tests through a member go to its server whatever the URL says: the
/// members are redirects.
const URL: &str = "http://probe.test/generate_204";

fn fallback(members: &[(&str, u16)], extra: serde_json::Value) -> serde_json::Value {
    let tags: Vec<&str> = members.iter().map(|(tag, _)| *tag).collect();
    let mut group = json!({
        "type": "fallback",
        "tag": "fb",
        "outbounds": tags,
        "url": URL,
        "interval": "300ms",
        "lazy": false,
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
    latencies(m, "fb").iter().all(|(_, l)| l.is_some())
}

#[test]
fn the_first_member_up_is_used_however_slow() {
    rt().block_on(async {
        let (_a, p_a) = serve("a", Duration::from_millis(200)).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let m = manager(
            fallback(&[("a", p_a), ("b", p_b)], json!({})),
            &env("fallback-order"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        let l = latencies(&m, "fb");
        assert!(l[0].1.unwrap() > l[1].1.unwrap(), "{:?}", l);

        assert_eq!(selected(&m, "fb"), "a");
        let sess = session("10.0.0.1", "example.com");
        for _ in 0..3 {
            assert_eq!(reached(&m, "fb", &sess).await.unwrap(), "a");
        }
    });
}

#[test]
fn it_moves_on_when_the_first_member_dies() {
    rt().block_on(async {
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let (_c, p_c) = serve("c", Duration::ZERO).await;
        let m = manager(
            fallback(&[("a", p_a), ("b", p_b), ("c", p_c)], json!({})),
            &env("fallback-dies"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        assert_eq!(selected(&m, "fb"), "a");

        a.abort();
        assert!(
            eventually(Duration::from_secs(5), || selected(&m, "fb") == "b").await,
            "{:?}",
            latencies(&m, "fb")
        );
        assert!(latencies(&m, "fb")[0].1.is_none());
        let sess = session("10.0.0.1", "example.com");
        assert_eq!(reached(&m, "fb", &sess).await.unwrap(), "b");
    });
}

#[test]
fn it_goes_back_to_the_first_member_once_it_passes_again() {
    rt().block_on(async {
        let (_a, a_delay, p_a) = serve_adjustable("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let m = manager(
            fallback(&[("a", p_a), ("b", p_b)], json!({ "timeout": "500ms" })),
            &env("fallback-returns"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        assert_eq!(selected(&m, "fb"), "a");

        // Too slow for its tests, then fine again.
        a_delay.store(2000, Ordering::Relaxed);
        assert!(eventually(Duration::from_secs(5), || selected(&m, "fb") == "b").await);
        a_delay.store(0, Ordering::Relaxed);
        assert!(eventually(Duration::from_secs(5), || selected(&m, "fb") == "a").await);
        let sess = session("10.0.0.1", "example.com");
        assert_eq!(reached(&m, "fb", &sess).await.unwrap(), "a");
    });
}

#[test]
fn a_connection_that_fails_is_tried_through_the_next_member() {
    rt().block_on(async {
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        // Tested once, at the start, and not again for a long while.
        let m = manager(
            fallback(&[("a", p_a), ("b", p_b)], json!({ "interval": "1h" })),
            &env("fallback-retry"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        assert_eq!(selected(&m, "fb"), "a");

        // The member dies between tests: the connection falls back.
        a.abort();
        let sess = session("10.0.0.1", "example.com");
        assert_eq!(reached(&m, "fb", &sess).await.unwrap(), "b");
        // And the failure has the members tested again, well before the
        // interval is out.
        assert!(
            eventually(Duration::from_secs(5), || selected(&m, "fb") == "b").await,
            "{:?}",
            latencies(&m, "fb")
        );
    });
}

#[test]
fn a_connection_is_tried_through_a_few_members_at_most() {
    rt().block_on(async {
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (b, p_b) = serve("b", Duration::ZERO).await;
        let (c, p_c) = serve("c", Duration::ZERO).await;
        let (_d, p_d) = serve("d", Duration::ZERO).await;
        let m = manager(
            fallback(
                &[("a", p_a), ("b", p_b), ("c", p_c), ("d", p_d)],
                json!({ "interval": "1h" }),
            ),
            &env("fallback-bounded"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);

        a.abort();
        b.abort();
        c.abort();
        // Three attempts, all failed: the fourth member is not tried.
        let sess = session("10.0.0.1", "example.com");
        assert!(connect(&m, "fb", &sess).await.is_err());
    });
}

#[test]
fn a_lazy_group_tests_only_while_it_is_used() {
    rt().block_on(async {
        let (_a, _, p_a, _) = serve_counted("a", Duration::ZERO).await;
        let (_b, _, p_b, b_requests) = serve_counted("b", Duration::ZERO).await;
        let (_c, _, p_c, _) = serve_counted("c", Duration::ZERO).await;
        let (_d, _, p_d, d_requests) = serve_counted("d", Duration::ZERO).await;
        let lazy = manager(
            fallback(&[("a", p_a), ("b", p_b)], json!({ "lazy": true })),
            &env("fallback-lazy"),
        )
        .unwrap();
        let eager = manager(
            json!([
                {
                    "type": "fallback",
                    "tag": "eager",
                    "outbounds": ["c", "d"],
                    "url": URL,
                    "interval": "300ms",
                    "lazy": false,
                },
                member("c", p_c),
                member("d", p_d),
            ]),
            &env("fallback-eager"),
        )
        .unwrap();

        // Unused for longer than the interval, the lazy group stops
        // testing; the other goes on. The second member is tested, and
        // never connected to.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (lazy_before, eager_before) = (
            b_requests.load(Ordering::Relaxed),
            d_requests.load(Ordering::Relaxed),
        );
        assert!(lazy_before >= 1, "tested at the start");
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(b_requests.load(Ordering::Relaxed), lazy_before);
        assert!(d_requests.load(Ordering::Relaxed) > eager_before);

        // Used again, it tests again.
        let sess = session("10.0.0.1", "example.com");
        assert_eq!(reached(&lazy, "fb", &sess).await.unwrap(), "a");
        assert!(
            eventually(Duration::from_secs(3), || b_requests
                .load(Ordering::Relaxed)
                > lazy_before)
            .await
        );
        drop(eager);
    });
}

#[test]
fn a_switch_interrupts_connections_when_asked_to() {
    rt().block_on(async {
        let (_a, a_delay, p_a) = serve_adjustable("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let m = manager(
            fallback(
                &[("a", p_a), ("b", p_b)],
                json!({ "interrupt_exist_connections": true, "timeout": "500ms" }),
            ),
            &env("fallback-interrupt"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        let sess = session("10.0.0.1", "example.com");
        let mut old = connect(&m, "fb", &sess).await.unwrap();
        assert_eq!(which(&mut old).await.unwrap(), "a");

        // The member answers too late for its tests, but the connection
        // open through it is still up.
        a_delay.store(2000, Ordering::Relaxed);
        assert!(eventually(Duration::from_secs(5), || selected(&m, "fb") == "b").await);
        let err = which(&mut old).await.unwrap_err();
        assert!(err.to_string().contains("switched"), "{}", err);
    });
}

#[test]
fn it_is_not_selected_by_hand() {
    rt().block_on(async {
        let m = manager(
            fallback(&[("a", UNSERVED), ("b", UNSERVED)], json!({})),
            &env("fallback-by-hand"),
        )
        .unwrap();
        let selector = m.get_selector("fb").unwrap();
        assert!(!selector.read().await.is_selectable());
        assert!(selector.write().await.set_selected("b").is_err());
    });
}

#[test]
fn configuration_mistakes_are_errors() {
    let error = |outbounds| {
        manager(outbounds, &env("fallback-error"))
            .err()
            .expect("the configuration must be refused")
            .to_string()
    };
    let msg = error(json!([{ "type": "fallback", "tag": "fb", "outbounds": [] }]));
    assert!(msg.contains("[fb]"), "{}", msg);
    let msg = error(json!([
        { "type": "fallback", "tag": "fb", "outbounds": ["a", "nope"] },
        member("a", UNSERVED),
    ]));
    assert!(msg.contains("nope"), "{}", msg);
    let a = &[("a", UNSERVED)];
    for (extra, field) in [
        (json!({ "url": "ftp://x/" }), "url"),
        (json!({ "interval": "0s" }), "interval"),
        (json!({ "interval": "soon" }), "interval"),
        (json!({ "timeout": "0ms" }), "timeout"),
        (json!({ "timeout": 5000 }), "timeout"),
        (json!({ "lazy": "yes" }), "lazy"),
        // What the failover group took, and the fallback does not.
        (json!({ "last_resort": "a" }), "last_resort"),
        (json!({ "fail_timeout": 4 }), "fail_timeout"),
        (
            json!({ "health_check_prefers": ["a"] }),
            "health_check_prefers",
        ),
        (json!({ "tolerance": 50 }), "tolerance"),
    ] {
        let msg = error(fallback(a, extra.clone()));
        assert!(msg.contains(field), "{}: {}", extra, msg);
    }
    // The old name is gone.
    let msg = error(json!([
        { "type": "failover", "tag": "fb", "outbounds": ["a"] },
        member("a", UNSERVED),
    ]));
    assert!(msg.contains("failover"), "{}", msg);
}
