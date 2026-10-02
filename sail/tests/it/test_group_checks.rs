//! What the control facade tells of a group that checks its members: the
//! state the group goes by, at the time its checks ended, and a check run
//! on demand.
#![cfg(all(
    feature = "outbound-fallback",
    feature = "outbound-redirect",
    feature = "inbound-socks"
))]

use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::common;
use crate::test_group_common::serve_counted;

/// An instance with a fallback group `fb` of `a` and `b`, served on `p_a`
/// and `p_b`, tested once, at the start, each test given 500 ms.
fn config(p_a: u16, p_b: u16) -> String {
    serde_json::json!({
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": common::free_port(),
        }],
        "outbounds": [
            {
                "type": "fallback", "tag": "fb", "outbounds": ["a", "b"],
                "url": "http://probe.test/generate_204",
                "interval": "1h", "timeout": "500ms", "lazy": false,
            },
            { "type": "redirect", "tag": "a", "server": "127.0.0.1", "server_port": p_a },
            { "type": "redirect", "tag": "b", "server": "127.0.0.1", "server_port": p_b },
        ],
        "route": { "final": "fb" },
    })
    .to_string()
}

#[test]
fn a_group_shows_its_checks_as_it_goes_by_them() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // [a] too slow for the group's tests, until it is not.
    let (_a, a_delay, p_a, _) = rt.block_on(serve_counted("a", Duration::from_secs(2)));
    let (_b, _, p_b, b_requests) = rt.block_on(serve_counted("b", Duration::ZERO));
    let ids = common::run_sail_instances(&rt, vec![config(p_a, p_b)]).unwrap();
    let rm = sail::runtime_managers().get(&ids[0]).cloned().unwrap();

    rt.block_on(async {
        let checked = || async {
            let fb = rm.outbound("fb").await.unwrap();
            fb.group.unwrap().selected == "b"
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !checked().await && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(checked().await, "the first round moved the group to [b]");

        // The member the group found down shows so: not alive, its last
        // delay 0, as Mihomo shows it.
        let a = rm.outbound("a").await.unwrap();
        assert_eq!(a.history.len(), 1, "{:?}", a.history);
        assert_eq!(a.history[0].delay, None);
        let b = rm.outbound("b").await.unwrap();
        assert!(b.history[0].delay.is_some(), "{:?}", b.history);
        // Both at the time the round ended.
        assert_eq!(a.history[0].time, b.history[0].time);

        // Nothing checked since: the same history, the same time.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let again = rm.outbound("b").await.unwrap();
        assert_eq!(again.history, b.history);

        // The group's delay test runs the group's own check: the members
        // are tested again, and the group's checks end later.
        let before = b_requests.load(Ordering::Relaxed);
        let results = rm
            .url_test_members("fb", None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(
            results[0].1.is_err() && results[1].1.is_ok(),
            "{:?}",
            results
        );
        assert!(b_requests.load(Ordering::Relaxed) > before);
        let a2 = rm.outbound("a").await.unwrap();
        let b2 = rm.outbound("b").await.unwrap();
        let (a2, b2) = (a2.history.last().unwrap(), b2.history.last().unwrap());
        assert!(b2.time > b.history[0].time);
        // One round, which ended once for every member.
        assert_eq!(a2.time, b2.time);
        assert_eq!(a2.delay, None);

        // A member's own delay test reaches the group: [a] passes it, and
        // the group goes back to it without a round of its own.
        a_delay.store(0, Ordering::Relaxed);
        let server = format!("http://127.0.0.1:{}/", p_a);
        rm.url_test("a", Some(&server), Duration::from_secs(5))
            .await
            .unwrap();
        let fb = rm.outbound("fb").await.unwrap();
        assert_eq!(fb.group.unwrap().selected, "a");
        let a3 = rm.outbound("a").await.unwrap();
        assert!(a3.history.last().unwrap().delay.is_some());
    });

    common::shutdown_instances(&rt, ids);
}

#[test]
fn a_group_check_dropped_mid_round_records_nothing_and_leaves_the_next_whole() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // [a] slower than the request's time but within the group's.
    let (_a, a_delay, p_a, _) = rt.block_on(serve_counted("a", Duration::ZERO));
    let (_b, _, p_b, _) = rt.block_on(serve_counted("b", Duration::ZERO));
    let ids = common::run_sail_instances(&rt, vec![config(p_a, p_b)]).unwrap();
    let rm = sail::runtime_managers().get(&ids[0]).cloned().unwrap();

    rt.block_on(async {
        let history = |tag: &'static str| {
            let rm = rm.clone();
            async move { rm.outbound(tag).await.unwrap().history }
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while history("b").await.is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (a0, b0) = (history("a").await, history("b").await);
        assert_eq!(b0.len(), 1, "the first round is done");

        // The request's time runs out mid-round, [b] already measured:
        // nothing of the round is kept.
        a_delay.store(300, Ordering::Relaxed);
        let timed_out = rm
            .url_test_members("fb", None, Duration::from_millis(100))
            .await;
        assert!(timed_out.is_err(), "{:?}", timed_out);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(history("a").await, a0);
        assert_eq!(history("b").await, b0);

        // The next check is not held up by the one dropped, and is whole.
        let results = tokio::time::timeout(
            Duration::from_secs(2),
            rm.url_test_members("fb", None, Duration::from_secs(5)),
        )
        .await
        .expect("not held up")
        .unwrap();
        assert!(results.iter().all(|(_, d)| d.is_ok()), "{:?}", results);
        let (a1, b1) = (history("a").await, history("b").await);
        let (a1, b1) = (a1.last().unwrap(), b1.last().unwrap());
        assert_eq!(a1.time, b1.time);
        assert!(b1.time > b0[0].time);
        assert!(a1.delay.is_some() && b1.delay.is_some());
    });

    common::shutdown_instances(&rt, ids);
}
