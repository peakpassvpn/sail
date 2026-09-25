#![cfg(all(feature = "outbound-load-balance", feature = "outbound-redirect"))]

mod test_group_common;

use std::collections::HashMap;
use std::time::Duration;

use serde_json::json;
use test_group_common::*;

const URL: &str = "http://probe.test/generate_204";

fn load_balance(members: &[(&str, u16)], extra: serde_json::Value) -> serde_json::Value {
    let tags: Vec<&str> = members.iter().map(|(tag, _)| *tag).collect();
    let mut group = json!({
        "type": "load-balance",
        "tag": "lb",
        "outbounds": tags,
        "url": URL,
        "interval": "300ms",
    });
    group
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let mut outbounds = vec![group];
    outbounds.extend(members.iter().map(|(tag, port)| member(tag, *port)));
    serde_json::Value::Array(outbounds)
}

#[test]
fn round_robin_spreads_connections_over_every_member() {
    rt().block_on(async {
        let _a = serve(33140, "a", Duration::ZERO).await;
        let _b = serve(33141, "b", Duration::ZERO).await;
        let _c = serve(33142, "c", Duration::ZERO).await;
        let m = manager(
            load_balance(
                &[("a", 33140), ("b", 33141), ("c", 33142)],
                json!({ "strategy": "round-robin" }),
            ),
            &env("lb-round-robin"),
        )
        .unwrap();
        let sess = session("10.0.0.1", "example.com");
        let mut count: HashMap<String, usize> = HashMap::new();
        for _ in 0..9 {
            *count
                .entry(reached(&m, "lb", &sess).await.unwrap())
                .or_default() += 1;
        }
        assert_eq!(count.len(), 3, "{:?}", count);
        assert!(count.values().all(|&n| n == 3), "{:?}", count);
    });
}

#[test]
fn consistent_hashing_keeps_a_site_on_one_member() {
    rt().block_on(async {
        let _a = serve(33143, "a", Duration::ZERO).await;
        let _b = serve(33144, "b", Duration::ZERO).await;
        let _c = serve(33145, "c", Duration::ZERO).await;
        let m = manager(
            load_balance(&[("a", 33143), ("b", 33144), ("c", 33145)], json!({})),
            &env("lb-consistent"),
        )
        .unwrap();
        let first = reached(&m, "lb", &session("10.0.0.1", "www.example.com"))
            .await
            .unwrap();
        for (source, host) in [
            ("10.0.0.2", "api.example.com"),
            ("10.0.0.1", "example.com"),
            ("10.0.0.3", "www.example.com"),
        ] {
            let got = reached(&m, "lb", &session(source, host)).await.unwrap();
            assert_eq!(got, first, "{}", host);
        }
        // Different sites are spread.
        let mut members = std::collections::HashSet::new();
        for i in 0..30 {
            let host = format!("site{}.com", i);
            members.insert(
                reached(&m, "lb", &session("10.0.0.1", &host))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(members.len(), 3, "{:?}", members);
    });
}

#[test]
fn sticky_sessions_keep_a_pair_on_one_member() {
    rt().block_on(async {
        let _a = serve(33146, "a", Duration::ZERO).await;
        let _b = serve(33147, "b", Duration::ZERO).await;
        let _c = serve(33148, "c", Duration::ZERO).await;
        let m = manager(
            load_balance(
                &[("a", 33146), ("b", 33147), ("c", 33148)],
                json!({ "strategy": "sticky-sessions" }),
            ),
            &env("lb-sticky"),
        )
        .unwrap();
        let sess = session("10.0.0.1", "www.example.com");
        let first = reached(&m, "lb", &sess).await.unwrap();
        for _ in 0..10 {
            assert_eq!(reached(&m, "lb", &sess).await.unwrap(), first);
        }
    });
}

#[test]
fn a_member_that_fails_its_test_is_skipped() {
    rt().block_on(async {
        let a = serve(33149, "a", Duration::ZERO).await;
        let _b = serve(33150, "b", Duration::ZERO).await;
        let m = manager(
            load_balance(
                &[("a", 33149), ("b", 33150)],
                json!({ "strategy": "round-robin", "lazy": false }),
            ),
            &env("lb-skip"),
        )
        .unwrap();
        a.abort();
        // Once tested, every connection goes to the member left.
        tokio::time::sleep(Duration::from_millis(800)).await;
        let sess = session("10.0.0.1", "example.com");
        for _ in 0..6 {
            assert_eq!(reached(&m, "lb", &sess).await.unwrap(), "b");
        }
    });
}

#[test]
fn configuration_mistakes_are_errors() {
    let error = |outbounds| {
        manager(outbounds, &env("lb-error"))
            .err()
            .expect("the configuration must be refused")
            .to_string()
    };
    let msg = error(json!([{ "type": "load-balance", "tag": "lb", "outbounds": [] }]));
    assert!(msg.contains("[lb]"), "{}", msg);
    let msg = error(json!([
        { "type": "load-balance", "tag": "lb", "outbounds": ["a", "nope"] },
        member("a", 33151),
    ]));
    assert!(msg.contains("nope"), "{}", msg);
    let msg = error(load_balance(
        &[("a", 33151)],
        json!({ "strategy": "random" }),
    ));
    assert!(msg.contains("strategy"), "{}", msg);
    let msg = error(load_balance(
        &[("a", 33151)],
        json!({ "strategy": "round_robin" }),
    ));
    assert!(msg.contains("strategy"), "{}", msg);
    let msg = error(load_balance(
        &[("a", 33151)],
        json!({ "url": "gopher://x" }),
    ));
    assert!(msg.contains("url"), "{}", msg);
    let msg = error(load_balance(&[("a", 33151)], json!({ "interval": "0ms" })));
    assert!(msg.contains("interval"), "{}", msg);
    let msg = error(load_balance(&[("a", 33151)], json!({ "tolerance": 50 })));
    assert!(msg.contains("tolerance"), "{}", msg);
}
