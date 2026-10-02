#![cfg(all(feature = "outbound-fallback", feature = "outbound-redirect"))]

use crate::test_group_common;

use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use sail::session::{Session, SocksAddr};
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

        a.stop().await;
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
        a.stop().await;
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
fn a_member_whose_server_refuses_is_left_at_once() {
    rt().block_on(async {
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, _, p_b, b_requests) = serve_counted("b", Duration::ZERO).await;
        // Tested once, at the start, and not again for a long while.
        let m = manager(
            fallback(&[("a", p_a), ("b", p_b)], json!({ "interval": "1h" })),
            &env("fallback-at-once"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        assert_eq!(selected(&m, "fb"), "a");
        let mut changes = m.get_selector("fb").unwrap().read().await.changes();

        a.stop().await;
        let requests = b_requests.load(Ordering::Relaxed);
        let sess = session("10.0.0.1", "example.com");
        // Refused by [a]'s server, the connection goes through [b]; and
        // [a] is down at once, the group on [b], before any test: [b] was
        // asked nothing but what the connection asked.
        assert_eq!(reached(&m, "fb", &sess).await.unwrap(), "b");
        assert_eq!(selected(&m, "fb"), "b");
        assert_eq!(latencies(&m, "fb")[0].1, None);
        assert_eq!(b_requests.load(Ordering::Relaxed), requests + 1);
        // Those who watch the group heard of it.
        let heard = tokio::time::timeout(Duration::from_millis(10), changes.changed()).await;
        assert!(heard.is_ok());
        // The next connection goes to [b] first.
        assert_eq!(reached(&m, "fb", &sess).await.unwrap(), "b");
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

        a.stop().await;
        b.stop().await;
        c.stop().await;
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

/// The time of the last round of tests of the group `tag`.
fn tested_at(m: &sail::app::outbound::manager::OutboundManager, tag: &str) -> Option<SystemTime> {
    let selector = m.get_selector(tag).expect("a selector");
    let tested = selector.try_read().expect("not locked").get_tested();
    tested?.into_iter().find_map(|(_, t)| t.map(|t| t.at))
}

/// A port nothing listens on: a connection to it is refused.
async fn closed_port() -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    listener.local_addr().unwrap().port()
}

fn pinned(m: &sail::app::outbound::manager::OutboundManager) -> Option<String> {
    let selector = m.get_selector("fb").unwrap();
    let fixed = selector.try_read().unwrap().fixed();
    fixed
}

#[test]
fn it_is_pinned_by_hand_while_the_member_is_up() {
    rt().block_on(async {
        let (_a, p_a) = serve("a", Duration::ZERO).await;
        let (b, p_b) = serve("b", Duration::ZERO).await;
        let (_c, p_c) = serve("c", Duration::ZERO).await;
        let m = manager(
            fallback(&[("a", p_a), ("b", p_b), ("c", p_c)], json!({})),
            &env("fallback-pinned"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        let selector = m.get_selector("fb").unwrap();
        // It still picks by itself; it is pinned, not selected.
        assert!(!selector.read().await.is_selectable());
        assert!(selector.write().await.set_selected("nope").is_err());

        selector.write().await.set_selected("b").unwrap();
        assert_eq!(selected(&m, "fb"), "b");
        assert_eq!(pinned(&m).as_deref(), Some("b"));
        let sess = session("10.0.0.1", "example.com");
        assert_eq!(reached(&m, "fb", &sess).await.unwrap(), "b");
        // Rounds of tests leave it there, [a] up as it is.
        let at = tested_at(&m, "fb");
        assert!(eventually(Duration::from_secs(5), || tested_at(&m, "fb") > at).await);
        assert_eq!(selected(&m, "fb"), "b");

        // Down, it is unpinned, and the group goes by itself.
        b.stop().await;
        assert!(eventually(Duration::from_secs(5), || pinned(&m).is_none()).await);
        assert_eq!(selected(&m, "fb"), "a");

        // Unpinned by hand, back to its own choice.
        selector.write().await.set_selected("c").unwrap();
        assert_eq!(selected(&m, "fb"), "c");
        assert!(selector.read().await.unfix());
        assert_eq!(selected(&m, "fb"), "a");
        assert_eq!(pinned(&m), None);
    });
}

#[test]
fn a_pin_is_kept_across_a_restart() {
    rt().block_on(async {
        let (_a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let env = cached_env("fallback-pin-kept");
        let config = fallback(&[("a", p_a), ("b", p_b)], json!({}));
        let m = manager(config.clone(), &env).unwrap();
        m.get_selector("fb")
            .unwrap()
            .write()
            .await
            .set_selected("b")
            .unwrap();
        drop(m);
        restart(&env);
        let m = manager(config.clone(), &env).unwrap();
        assert_eq!(pinned(&m).as_deref(), Some("b"));
        assert_eq!(selected(&m, "fb"), "b");
        // Unpinned, it is not pinned after the next.
        assert!(m.get_selector("fb").unwrap().read().await.unfix());
        drop(m);
        restart(&env);
        let m = manager(config, &env).unwrap();
        assert_eq!(pinned(&m), None);
        assert_eq!(selected(&m, "fb"), "a");
    });
}

#[test]
fn when_every_member_is_down_the_first_takes_the_connections() {
    rt().block_on(async {
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (b, p_b) = serve("b", Duration::ZERO).await;
        let m = manager(
            fallback(&[("a", p_a), ("b", p_b)], json!({})),
            &env("fallback-all-down"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        a.stop().await;
        assert!(eventually(Duration::from_secs(5), || selected(&m, "fb") == "b").await);
        // Both down: back to the first, as Mihomo's fallback.
        b.stop().await;
        assert!(
            eventually(Duration::from_secs(5), || selected(&m, "fb") == "a").await,
            "{:?}",
            latencies(&m, "fb")
        );
        assert!(latencies(&m, "fb").iter().all(|(_, l)| l.is_none()));
    });
}

/// A member that dials the destination itself: a failure through it may
/// be the destination's.
#[cfg(feature = "outbound-direct")]
#[test]
fn failures_that_may_be_the_destinations_test_after_max_failed_times() {
    rt().block_on(async {
        let port = closed_port().await;
        let m = manager(
            json!([
                {
                    "type": "fallback",
                    "tag": "fb",
                    "outbounds": ["d"],
                    "url": format!("http://127.0.0.1:{}/", port),
                    "interval": "1h",
                    "timeout": "10s",
                    "max_failed_times": 3,
                    "lazy": false,
                },
                { "type": "direct", "tag": "d" },
            ]),
            &env("fallback-max-failed"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested_at(&m, "fb").is_some()).await);
        let first = tested_at(&m, "fb");
        let sess = Session {
            destination: SocksAddr::Ip(([127, 0, 0, 1], port).into()),
            ..Default::default()
        };
        // Two refused by the destination: not enough to test again, well
        // past the least time between two rounds.
        for _ in 0..2 {
            assert!(connect(&m, "fb", &sess).await.is_err());
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(tested_at(&m, "fb"), first);
        // The third, within the timeout of the first, is.
        assert!(connect(&m, "fb", &sess).await.is_err());
        assert!(eventually(Duration::from_secs(3), || tested_at(&m, "fb") > first).await);
    });
}

#[test]
fn only_the_statuses_expected_pass() {
    rt().block_on(async {
        let (_a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        // The members answer 204.
        let passed = manager(
            fallback(&[("a", p_a)], json!({ "expected_status": "200-299" })),
            &env("fallback-expected"),
        )
        .unwrap();
        let failed = manager(
            json!([
                {
                    "type": "fallback",
                    "tag": "other",
                    "outbounds": ["b"],
                    "url": URL,
                    "interval": "300ms",
                    "expected_status": "200/301-399",
                },
                member("b", p_b),
            ]),
            &env("fallback-unexpected"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&passed)).await);
        assert!(
            eventually(Duration::from_secs(5), || {
                latencies(&failed, "other")[0].1.is_none() && tested_at(&failed, "other").is_some()
            })
            .await
        );
        let selector = failed.get_selector("other").unwrap();
        let checks = selector.read().await.checks().unwrap();
        assert_eq!(checks.expected_status(), "200/301-399");
        assert_eq!(checks.url(), URL);
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
        (json!({ "max_failed_times": 0 }), "max_failed_times"),
        (json!({ "max_failed_times": -1 }), "max_failed_times"),
        (json!({ "expected_status": "2xx" }), "expected_status"),
        (json!({ "debounce": { "fail_after": 0 } }), "fail_after"),
        (
            json!({ "debounce": { "recover_after": 0 } }),
            "recover_after",
        ),
        (json!({ "debounce": { "min_dwell": "soon" } }), "min_dwell"),
        (
            json!({ "debounce": { "recover_rounds": 3 } }),
            "recover_rounds",
        ),
        (json!({ "dial_timeout": "500ms" }), "dial_timeout"),
        (json!({ "dial_timeout": "0s" }), "dial_timeout"),
        (json!({ "dial_timeout": "soon" }), "dial_timeout"),
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
