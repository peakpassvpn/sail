#![cfg(all(feature = "outbound-urltest", feature = "outbound-redirect"))]

use crate::test_group_common;

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
        let (_a, p_a) = serve("a", Duration::from_millis(300)).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let (_c, p_c) = serve("c", Duration::from_millis(120)).await;
        let m = manager(
            urltest(&[("a", p_a), ("b", p_b), ("c", p_c)], json!({})),
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
        let (_a, p_a) = serve("a", Duration::from_millis(100)).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let m = manager(
            urltest(&[("a", p_a), ("b", p_b)], json!({ "tolerance": 1000 })),
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
        let (_a, p_a) = serve("a", Duration::from_millis(200)).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let m = manager(
            urltest(&[("a", p_a), ("b", p_b)], json!({ "tolerance": 20 })),
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
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::from_millis(100)).await;
        let m = manager(
            urltest(&[("a", p_a), ("b", p_b)], json!({ "interval": "300ms" })),
            &env("urltest-dies"),
        )
        .unwrap();
        assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
        assert_eq!(selected(&m, "auto"), "a");

        a.stop().await;
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
        let (_a, a_delay, p_a) = serve_adjustable("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::from_millis(100)).await;
        let m = manager(
            urltest(
                &[("a", p_a), ("b", p_b)],
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

/// A connection through nested groups, a selector over a urltest, is
/// ended by a switch of either group that interrupts its connections, as
/// sing-box 1.15 attaches it to every group on its chain: the inner
/// group's switch ends it only when the inner group interrupts, the
/// outer's whatever the inner does.
#[test]
fn a_switch_of_an_inner_or_outer_group_interrupts_connections_through_both() {
    rt().block_on(async {
        for inner_interrupts in [true, false] {
            let (_a, a_delay, p_a) = serve_adjustable("a", Duration::ZERO).await;
            let (_b, p_b) = serve("b", Duration::from_millis(100)).await;
            let (_c, p_c) = serve("c", Duration::ZERO).await;
            let m = manager(
                json!([
                    {
                        "type": "selector",
                        "tag": "outer",
                        "outbounds": ["auto", "c"],
                        "interrupt_exist_connections": true,
                    },
                    {
                        "type": "urltest",
                        "tag": "auto",
                        "outbounds": ["a", "b"],
                        "url": URL,
                        "interval": "300ms",
                        "interrupt_exist_connections": inner_interrupts,
                    },
                    member("a", p_a),
                    member("b", p_b),
                    member("c", p_c),
                ]),
                &env(&format!("urltest-nested-{}", inner_interrupts)),
            )
            .unwrap();
            assert!(eventually(Duration::from_secs(5), || tested(&m)).await);
            let sess = session("10.0.0.1", "example.com");
            let mut first = connect(&m, "outer", &sess).await.unwrap();
            assert_eq!(which(&mut first).await.unwrap(), "a");

            // The inner group switches.
            a_delay.store(1000, Ordering::Relaxed);
            assert!(eventually(Duration::from_secs(5), || selected(&m, "auto") == "b").await);
            let mut second = connect(&m, "outer", &sess).await.unwrap();
            assert_eq!(which(&mut second).await.unwrap(), "b");
            if inner_interrupts {
                let err = which(&mut first).await.unwrap_err();
                assert!(err.to_string().contains("switched"), "{}", err);
            } else {
                assert_eq!(which(&mut first).await.unwrap(), "a");
            }

            // The outer one switches: every connection through it ends.
            m.get_selector("outer")
                .unwrap()
                .write()
                .await
                .set_selected("c")
                .unwrap();
            assert_eq!(reached(&m, "outer", &sess).await.unwrap(), "c");
            for stream in [&mut first, &mut second] {
                let err = which(stream).await.unwrap_err();
                assert!(
                    err.to_string().contains("switched"),
                    "{}: {}",
                    inner_interrupts,
                    err
                );
            }
        }
    });
}

#[test]
fn it_is_not_selected_by_hand() {
    let m = manager(
        urltest(&[("a", UNSERVED), ("b", UNSERVED)], json!({})),
        &env("urltest-by-hand"),
    )
    .unwrap();
    rt().block_on(async {
        let selector = m.get_selector("auto").unwrap();
        assert!(!selector.read().await.is_selectable());
        assert!(selector.write().await.set_selected("b").is_err());
    });
}

/// A member that dials the destination itself: a failure through it may
/// be the destination's, and is counted, as in Mihomo's url-test.
#[cfg(feature = "outbound-direct")]
#[test]
fn failures_that_may_be_the_destinations_test_after_max_failed_times() {
    rt().block_on(async {
        let (_refusing, port) = refusing_port();
        let m = manager(
            json!([
                {
                    "type": "urltest",
                    "tag": "auto",
                    "outbounds": ["d"],
                    "url": format!("http://127.0.0.1:{}/", port),
                    "interval": "1h",
                    "timeout": "10s",
                    "max_failed_times": 2,
                    "lazy": false,
                },
                { "type": "direct", "tag": "d" },
            ]),
            &env("urltest-max-failed"),
        )
        .unwrap();
        let at = || {
            let selector = m.get_selector("auto").unwrap();
            let tested = selector.try_read().unwrap().get_tested().unwrap();
            tested[0].1.map(|t| t.at)
        };
        assert!(eventually(Duration::from_secs(5), || at().is_some()).await);
        let first = at();
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::Ip(([127, 0, 0, 1], port).into()),
            ..Default::default()
        };
        assert!(connect(&m, "auto", &sess).await.is_err());
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(at(), first);
        assert!(connect(&m, "auto", &sess).await.is_err());
        assert!(eventually(Duration::from_secs(3), || at() > first).await);
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
        member("a", UNSERVED),
    ]));
    assert!(msg.contains("nope"), "{}", msg);
    let msg = error(urltest(&[("a", UNSERVED)], json!({ "url": "ftp://x/" })));
    assert!(msg.contains("url"), "{}", msg);
    let msg = error(urltest(&[("a", UNSERVED)], json!({ "interval": "0s" })));
    assert!(msg.contains("interval"), "{}", msg);
    let msg = error(urltest(&[("a", UNSERVED)], json!({ "interval": "soon" })));
    assert!(msg.contains("interval"), "{}", msg);
    let msg = error(urltest(&[("a", UNSERVED)], json!({ "default": "a" })));
    assert!(msg.contains("default"), "{}", msg);
    for (extra, field) in [
        (json!({ "timeout": "0s" }), "timeout"),
        (json!({ "max_failed_times": 0 }), "max_failed_times"),
        (json!({ "expected_status": "2xx" }), "expected_status"),
        (
            json!({ "lazy": false, "idle_timeout": "1m" }),
            "idle_timeout",
        ),
    ] {
        let msg = error(urltest(&[("a", UNSERVED)], extra.clone()));
        assert!(msg.contains(field), "{}: {}", extra, msg);
    }
}
