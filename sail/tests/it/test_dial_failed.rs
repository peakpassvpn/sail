//! What a failed connection through groups tells (control::events): each
//! member that failed its own `DialFailure`, its chain outermost first down
//! to the member, and only the connection's last failure with nothing more
//! to try.
#![cfg(all(feature = "outbound-fallback", feature = "outbound-redirect"))]

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::broadcast::{error::TryRecvError, Receiver};

use sail::app::dispatcher::Dispatcher;
use sail::app::dns_client::DnsClient;
use sail::app::outbound::manager::OutboundManager;
use sail::app::router::Router;
use sail::app::stat_manager::StatManager;
use sail::control::events::DialFailure;

use crate::test_group_common::*;

/// Tests through a member go to its server whatever the URL says: the
/// members are redirects.
const URL: &str = "http://probe.test/generate_204";

/// A fallback `tag` of `members`, tested once at the start.
fn fallback(tag: &str, members: &[&str]) -> serde_json::Value {
    json!({
        "type": "fallback",
        "tag": tag,
        "outbounds": members,
        "url": URL,
        "interval": "1h",
        "lazy": false,
    })
}

struct Instance {
    dispatcher: Arc<Dispatcher>,
    outbounds: Arc<arc_swap::ArcSwap<OutboundManager>>,
    failures: Receiver<DialFailure>,
}

impl Instance {
    fn new(outbounds: serde_json::Value, name: &str) -> Self {
        let config =
            sail::config::Config::from_json(&json!({ "outbounds": outbounds }).to_string())
                .unwrap();
        let env = Arc::new(env(name));
        let failures = env.events.dial_failures();
        let dial = Arc::new(sail::net::DialDefaults::default());
        let dns_client = DnsClient::new(&config.dns, dial.clone(), &env)
            .unwrap()
            .into_shared();
        // What the groups start as they are built goes into env's scope,
        // as an instance's does while it is built.
        let building = env.scope.building();
        let manager = Arc::new(arc_swap::ArcSwap::from_pointee(
            OutboundManager::new(&config.outbounds, &dial, &env, dns_client.clone()).unwrap(),
        ));
        drop(building);
        let router = Arc::new(arc_swap::ArcSwap::from_pointee(
            Router::new(&config.route, dns_client.clone(), &env).unwrap(),
        ));
        let dispatcher = Arc::new(Dispatcher::new(
            manager.clone(),
            router,
            dns_client,
            Arc::new(StatManager::default()),
            env,
        ));
        Instance {
            dispatcher,
            outbounds: manager,
            failures,
        }
    }

    /// Whether every member of the group `tag` was tested.
    fn tested(&self, tag: &str) -> bool {
        latencies(&self.outbounds.load(), tag)
            .iter()
            .all(|(_, l)| l.is_some())
    }

    async fn dial(&self, tag: &str) -> bool {
        let sess = session("10.0.0.1", "example.com");
        self.dispatcher.dial_stream(tag, sess).await.is_ok()
    }

    /// The failures told so far, as `(chain, more_to_try)`; and that no
    /// other comes a while after.
    async fn told(&mut self) -> Vec<(String, bool)> {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut told = Vec::new();
        loop {
            match self.failures.try_recv() {
                Ok(f) => told.push((f.chain, f.more_to_try)),
                Err(TryRecvError::Empty) => return told,
                Err(e) => panic!("{:?}", e),
            }
        }
    }
}

fn told(chains: &[(&str, bool)]) -> Vec<(String, bool)> {
    chains.iter().map(|(c, m)| (c.to_string(), *m)).collect()
}

#[test]
fn each_member_that_fails_is_told_before_the_next_connects() {
    rt().block_on(async {
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (b, p_b) = serve("b", Duration::ZERO).await;
        let (_c, p_c) = serve("c", Duration::ZERO).await;
        let mut i = Instance::new(
            json!([
                fallback("fb", &["a", "b", "c"]),
                member("a", p_a),
                member("b", p_b),
                member("c", p_c),
            ]),
            "dial-failed-fallback",
        );
        assert!(eventually(Duration::from_secs(5), || i.tested("fb")).await);
        a.stop().await;
        b.stop().await;
        assert!(i.dial("fb").await);
        // Two, each with a member to try after it; nothing for the
        // connection, which connected.
        assert_eq!(i.told().await, told(&[("fb>a", true), ("fb>b", true)]));
    });
}

#[test]
fn only_the_last_failure_of_a_connection_has_nothing_more_to_try() {
    rt().block_on(async {
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (b, p_b) = serve("b", Duration::ZERO).await;
        let (c, p_c) = serve("c", Duration::ZERO).await;
        let mut i = Instance::new(
            json!([
                fallback("fb", &["a", "b", "c"]),
                member("a", p_a),
                member("b", p_b),
                member("c", p_c),
            ]),
            "dial-failed-all",
        );
        assert!(eventually(Duration::from_secs(5), || i.tested("fb")).await);
        a.stop().await;
        b.stop().await;
        c.stop().await;
        assert!(!i.dial("fb").await);
        // The group told the connection's failure: the dispatcher does not
        // again.
        assert_eq!(
            i.told().await,
            told(&[("fb>a", true), ("fb>b", true), ("fb>c", false)])
        );
    });
}

/// Without the dispatcher: the chain keeps the member that failed last,
/// as the connection's own failure names it.
#[test]
fn a_connection_that_failed_keeps_the_last_member_in_its_chain() {
    rt().block_on(async {
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (b, p_b) = serve("b", Duration::ZERO).await;
        let m = manager(
            json!([
                fallback("fb", &["a", "b"]),
                member("a", p_a),
                member("b", p_b)
            ]),
            &env("dial-failed-chain"),
        )
        .unwrap();
        assert!(
            eventually(Duration::from_secs(5), || latencies(&m, "fb")
                .iter()
                .all(|(_, l)| l.is_some()))
            .await
        );
        a.stop().await;
        b.stop().await;
        let sess = session("10.0.0.1", "example.com");
        assert!(connect(&m, "fb", &sess).await.is_err());
        assert_eq!(sess.chain.get(), ["b"]);
    });
}

#[test]
fn a_group_in_a_group_is_told_under_it_once() {
    rt().block_on(async {
        let (m1, p_m1) = serve("m1", Duration::ZERO).await;
        let (m2, p_m2) = serve("m2", Duration::ZERO).await;
        let (_x, p_x) = serve("x", Duration::ZERO).await;
        let mut i = Instance::new(
            json!([
                fallback("F", &["G", "x"]),
                fallback("G", &["m1", "m2"]),
                member("m1", p_m1),
                member("m2", p_m2),
                member("x", p_x),
            ]),
            "dial-failed-nested",
        );
        assert!(eventually(Duration::from_secs(5), || i.tested("F") && i.tested("G")).await);
        m1.stop().await;
        m2.stop().await;
        assert!(i.dial("F").await);
        // Each level, outermost first; G's last member with [x] still to
        // try; nothing for G itself.
        assert_eq!(i.told().await, told(&[("F>G>m1", true), ("F>G>m2", true)]));
    });
}

#[test]
fn a_selectors_member_that_fails_is_in_the_chain() {
    rt().block_on(async {
        let (a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let mut i = Instance::new(
            json!([
                { "type": "selector", "tag": "sel", "outbounds": ["a", "b"] },
                member("a", p_a),
                member("b", p_b),
            ]),
            "dial-failed-selector",
        );
        a.stop().await;
        assert!(!i.dial("sel").await);
        assert_eq!(i.told().await, told(&[("sel>a", false)]));
    });
}
