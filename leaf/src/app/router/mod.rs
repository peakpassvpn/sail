//! Routing: the rules of `route`, compiled, and matched in order against
//! what is known about a connection. A rule's action either decides where
//! the connection goes (`route`, `reject`) or learns more about it
//! (`sniff`, `resolve`) and lets the next rules decide.

mod matcher;

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tracing::debug;

use crate::app::SyncDnsClient;
use crate::config::model::{self, RuleAction};
use crate::runtime::RuntimeEnv;
use crate::session::Session;

use matcher::{Facts, Matcher, Readers};

/// Where a connection goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// To this outbound; to the default one when `None`.
    Route(Option<String>),
    /// Nowhere: it is closed.
    Reject,
}

/// What a `sniff` rule asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffAction {
    pub tls: bool,
    pub http: bool,
    /// How long to wait for the first bytes.
    pub timeout: Duration,
    /// Connects to the sniffed domain rather than to the address asked for.
    pub override_destination: bool,
}

/// Reads what a `sniff` rule asks for from a connection, into its session.
/// Only the dispatcher, which holds the connection, can.
#[async_trait]
pub trait Sniffer: Send {
    async fn sniff(&mut self, sess: &mut Session, action: &SniffAction) -> io::Result<()>;
}

/// For connections nothing can be read from, such as UDP.
pub struct NoSniffer;

#[async_trait]
impl Sniffer for NoSniffer {
    async fn sniff(&mut self, _sess: &mut Session, _action: &SniffAction) -> io::Result<()> {
        Ok(())
    }
}

enum Action {
    Route(String),
    Reject,
    Sniff(SniffAction),
    Resolve,
}

struct Rule {
    matcher: Matcher,
    action: Action,
}

impl Rule {
    fn new(rule: &model::Rule, readers: &mut Readers, env: &RuntimeEnv) -> Result<Self> {
        let action = match rule.action {
            RuleAction::Route => Action::Route(
                rule.outbound
                    .clone()
                    .ok_or_else(|| anyhow!("outbound: a route rule needs one"))?,
            ),
            RuleAction::Reject => Action::Reject,
            RuleAction::Resolve => Action::Resolve,
            RuleAction::Sniff => {
                let all = rule.sniffer.is_empty();
                Action::Sniff(SniffAction {
                    tls: all || rule.sniffer.contains(&model::Sniffer::Tls),
                    http: all || rule.sniffer.contains(&model::Sniffer::Http),
                    timeout: rule.timeout.unwrap_or(Duration::from_millis(300)),
                    override_destination: rule.override_destination,
                })
            }
        };
        Ok(Rule {
            matcher: Matcher::new(rule, readers, env)?,
            action,
        })
    }
}

pub struct Router {
    rules: Vec<Rule>,
    final_outbound: Option<String>,
    dns_client: SyncDnsClient,
}

impl Router {
    fn load_rules(route: &model::Route, env: &RuntimeEnv) -> Result<Vec<Rule>> {
        let mut readers = Readers::new();
        route
            .rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                Rule::new(rule, &mut readers, env).map_err(|e| anyhow!("route.rules[{}]: {}", i, e))
            })
            .collect()
    }

    pub fn new(route: &model::Route, dns_client: SyncDnsClient, env: &RuntimeEnv) -> Result<Self> {
        Ok(Router {
            rules: Self::load_rules(route, env)?,
            final_outbound: route.final_outbound.clone(),
            dns_client,
        })
    }

    pub fn reload(&mut self, route: &model::Route, env: &RuntimeEnv) -> Result<()> {
        self.rules = Self::load_rules(route, env)?;
        self.final_outbound = route.final_outbound.clone();
        Ok(())
    }

    /// Whether a rule, or `final`, routes to the outbound `tag`.
    pub fn uses(&self, tag: &str) -> bool {
        self.final_outbound.as_deref() == Some(tag)
            || self
                .rules
                .iter()
                .any(|rule| matches!(&rule.action, Action::Route(t) if t == tag))
    }

    /// Matches `sess` against the rules in order, sniffing through
    /// `sniffer` and resolving as they say, until one decides.
    pub async fn pick_route(
        &self,
        sess: &mut Session,
        sniffer: &mut dyn Sniffer,
    ) -> Result<Decision> {
        let mut resolved: Vec<IpAddr> = Vec::new();
        let mut facts = Facts::new(sess, &resolved);
        for (i, rule) in self.rules.iter().enumerate() {
            if !rule.matcher.matches(&facts) {
                continue;
            }
            match &rule.action {
                Action::Route(tag) => {
                    debug!("rule {} routes to {}", i, tag);
                    return Ok(Decision::Route(Some(tag.clone())));
                }
                Action::Reject => {
                    debug!("rule {} rejects", i);
                    return Ok(Decision::Reject);
                }
                Action::Sniff(action) => {
                    sniffer
                        .sniff(sess, action)
                        .await
                        .map_err(|e| anyhow!("sniff: {}", e))?;
                }
                Action::Resolve => {
                    if resolved.is_empty() && !sess.skip_resolve {
                        if let Some(domain) = facts.domain() {
                            resolved = self.resolve(domain).await;
                        }
                    }
                }
            }
            facts = Facts::new(sess, &resolved);
        }
        Ok(Decision::Route(self.final_outbound.clone()))
    }

    /// The addresses of `domain`, or none when it does not resolve: the
    /// rules after a `resolve` then match without them.
    async fn resolve(&self, domain: &str) -> Vec<IpAddr> {
        match self
            .dns_client
            .load_full()
            .lookup(&domain.to_string())
            .await
        {
            Ok(ips) => {
                debug!("resolved {} to {:?} for routing", domain, ips);
                ips
            }
            Err(e) => {
                debug!("resolving {} for routing failed: {}", domain, e);
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns_client::DnsClient;
    use crate::session::SocksAddr;

    fn router(rules: serde_json::Value) -> Router {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": { "hosts": { "test.leaf": ["127.0.0.1"] } },
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": { "rules": rules, "final": "b" },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), Default::default())
            .unwrap()
            .into_shared();
        Router::new(&config.route, dns, &RuntimeEnv::default()).unwrap()
    }

    /// Plays a connection whose first bytes carry `domain`.
    struct FakeSniffer {
        domain: &'static str,
        calls: usize,
    }

    #[async_trait]
    impl Sniffer for FakeSniffer {
        async fn sniff(&mut self, sess: &mut Session, action: &SniffAction) -> io::Result<()> {
            self.calls += 1;
            if action.tls {
                sess.tls_sniffed_domain = Some(self.domain.to_string());
            }
            Ok(())
        }
    }

    fn to_ip() -> Session {
        Session {
            destination: SocksAddr::from(("1.2.3.4".parse::<IpAddr>().unwrap(), 443)),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_sniffed_domain_is_matched_by_the_rules_after_the_sniff() {
        let router = router(serde_json::json!([
            { "domain_suffix": ["example.com"], "outbound": "a" },
            { "action": "sniff", "port_range": ["443"] },
            { "domain_suffix": ["example.com"], "outbound": "a" },
        ]));
        let mut sniffer = FakeSniffer {
            domain: "www.example.com",
            calls: 0,
        };
        let mut sess = to_ip();
        let decision = router.pick_route(&mut sess, &mut sniffer).await.unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));
        assert_eq!(sniffer.calls, 1);
        assert_eq!(sess.tls_sniffed_domain.as_deref(), Some("www.example.com"));
    }

    #[tokio::test]
    async fn without_a_sniff_rule_nothing_is_sniffed() {
        let router = router(serde_json::json!([
            { "domain_suffix": ["example.com"], "outbound": "a" },
        ]));
        let mut sniffer = FakeSniffer {
            domain: "www.example.com",
            calls: 0,
        };
        let decision = router.pick_route(&mut to_ip(), &mut sniffer).await.unwrap();
        assert_eq!(decision, Decision::Route(Some("b".into())));
        assert_eq!(sniffer.calls, 0);
    }

    #[tokio::test]
    async fn reject_ends_the_matching() {
        let router = router(serde_json::json!([
            { "ip_cidr": ["1.2.3.0/24"], "action": "reject" },
            { "ip_cidr": ["1.2.3.0/24"], "outbound": "a" },
        ]));
        let decision = router
            .pick_route(&mut to_ip(), &mut NoSniffer)
            .await
            .unwrap();
        assert_eq!(decision, Decision::Reject);
    }

    #[tokio::test]
    async fn a_resolved_domain_is_matched_by_address() {
        let router = router(serde_json::json!([
            { "action": "resolve" },
            { "ip_cidr": ["127.0.0.0/8"], "outbound": "a" },
        ]));
        let mut sess = Session {
            destination: SocksAddr::Domain("test.leaf".into(), 80),
            ..Default::default()
        };
        let decision = router.pick_route(&mut sess, &mut NoSniffer).await.unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));

        // Not for the lookups the DNS client makes for itself.
        sess.skip_resolve = true;
        let decision = router.pick_route(&mut sess, &mut NoSniffer).await.unwrap();
        assert_eq!(decision, Decision::Route(Some("b".into())));
    }
}
