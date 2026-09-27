//! Routing: the rules of `route`, compiled, and matched in order against
//! what is known about a connection. A rule's action either decides where
//! the connection goes (`route`, `reject`) or learns more about it
//! (`sniff`, `resolve`) and lets the next rules decide.

pub(crate) mod matcher;
#[cfg(feature = "rule-set")]
pub(crate) mod rule_set;

/// Without the rule-set feature: no rule-sets, and a configuration that has
/// some is refused.
#[cfg(not(feature = "rule-set"))]
pub(crate) mod rule_set {
    use anyhow::{anyhow, Result};

    #[derive(Default, Clone)]
    pub(crate) struct RuleSets;

    /// The domain matcher of binary rule-sets, of which there are none.
    pub(crate) mod succinct {
        pub(crate) enum Succinct {}

        impl Succinct {
            pub(crate) fn matches(&self, _domain: &str) -> bool {
                match *self {}
            }
        }
    }

    impl RuleSets {
        pub(crate) fn load(
            configs: &[crate::config::rule_set::RuleSet],
            _env: &crate::runtime::RuntimeEnv,
        ) -> Result<Self> {
            match configs.first() {
                Some(_) => Err(anyhow!(
                    "route.rule_set: not supported, the rule-set feature is not compiled in"
                )),
                None => Ok(RuleSets),
            }
        }

        pub(crate) fn get(&self, tag: &str) -> Result<()> {
            Err(anyhow!("rule-set [{}] does not exist", tag))
        }

        pub(crate) async fn fetch_missing(
            &self,
            _dispatcher: &crate::app::dispatcher::Dispatcher,
        ) -> Result<()> {
            Ok(())
        }

        pub(crate) fn spawn_updater(
            &self,
            _dispatcher: std::sync::Weak<crate::app::dispatcher::Dispatcher>,
        ) -> Option<tokio::task::AbortHandle> {
            None
        }
    }
}

pub(crate) mod fragment;
pub(crate) mod hijack_dns;

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tracing::debug;

use crate::app::SyncDnsClient;
use crate::config::model::{self, RejectMethod, RuleAction};
use crate::runtime::RuntimeEnv;
use crate::session::{Session, SocksAddr, TlsFragment};

use matcher::{Facts, Matcher, Readers};

/// Where a connection goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// To this outbound; to the default one when `None`.
    Route(Option<String>),
    /// Nowhere: it is closed at once, or left unanswered when `drop`.
    Reject { drop: bool },
    /// To sail's DNS client, which answers the queries it carries.
    HijackDns,
}

/// What a `sniff` rule asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffAction {
    /// The protocols to look for.
    pub protocols: crate::sniff::Protocols,
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

/// For connections nothing can be read from.
pub struct NoSniffer;

#[async_trait]
impl Sniffer for NoSniffer {
    async fn sniff(&mut self, _sess: &mut Session, _action: &SniffAction) -> io::Result<()> {
        Ok(())
    }
}

/// The route options of a `route` or `route-options` rule.
#[derive(Default)]
struct Options {
    override_address: Option<SocksAddr>,
    override_port: Option<u16>,
    udp_disable_domain_unmapping: bool,
    udp_connect: bool,
    udp_timeout: Option<Duration>,
    tls_fragment: Option<TlsFragment>,
}

/// How long apart the pieces of a fragmented ClientHello go when the rule
/// does not say, as in sing-box.
const TLS_FRAGMENT_DELAY: Duration = Duration::from_millis(500);

impl Options {
    fn new(rule: &model::Rule, path: &str) -> Result<Self> {
        let override_address = match &rule.override_address {
            None => None,
            Some(address) if address.is_empty() || address.contains(char::is_whitespace) => {
                return Err(anyhow!(
                    "{}.override_address: \"{}\" is neither an address nor a domain",
                    path,
                    address
                ))
            }
            Some(address) => Some(SocksAddr::try_from((address.as_str(), 0)).map_err(|e| {
                anyhow!(
                    "{}.override_address: \"{}\" is neither an address nor a domain: {}",
                    path,
                    address,
                    e
                )
            })?),
        };
        let tls_fragment = if rule.tls_fragment {
            Some(TlsFragment::Segments(
                rule.tls_fragment_fallback_delay
                    .unwrap_or(TLS_FRAGMENT_DELAY),
            ))
        } else if rule.tls_record_fragment {
            Some(TlsFragment::Records)
        } else {
            None
        };
        Ok(Options {
            override_address,
            override_port: rule.override_port,
            udp_disable_domain_unmapping: rule.udp_disable_domain_unmapping,
            udp_connect: rule.udp_connect,
            udp_timeout: rule.udp_timeout,
            tls_fragment,
        })
    }

    /// Sets the options in `sess`, as sing-box's `matchRule` does: an
    /// override changes the destination the next rules match, and those
    /// rules can set other options still.
    fn apply(&self, sess: &mut Session) {
        if self.override_address.is_some() || self.override_port.is_some() {
            if sess.route.original_destination.is_none() {
                sess.route.original_destination = Some(sess.destination.clone());
            }
            let port = self.override_port.unwrap_or(sess.destination.port());
            sess.destination = match self.override_address.as_ref().unwrap_or(&sess.destination) {
                SocksAddr::Ip(addr) => SocksAddr::Ip(std::net::SocketAddr::new(addr.ip(), port)),
                SocksAddr::Domain(domain, _) => SocksAddr::Domain(domain.clone(), port),
            };
        }
        let route = &mut sess.route;
        route.udp_disable_domain_unmapping |= self.udp_disable_domain_unmapping;
        route.udp_connect |= self.udp_connect;
        if self.udp_timeout.is_some() {
            route.udp_timeout = self.udp_timeout;
        }
        if self.tls_fragment.is_some() {
            route.tls_fragment = self.tls_fragment;
        }
    }
}

/// A `reject` rule's way.
struct Reject {
    method: RejectMethod,
    no_drop: bool,
    /// When the rule last rejected, for the last 30 seconds.
    recent: Mutex<VecDeque<Instant>>,
}

impl Reject {
    /// Past this many rejections in 30 seconds, a rule drops those after,
    /// as sing-box's does, unless `no_drop`.
    const FLOOD: usize = 50;
    const WINDOW: Duration = Duration::from_secs(30);

    /// Whether this rejection drops the connection.
    fn drops(&self) -> bool {
        match self.method {
            RejectMethod::Drop => true,
            _ if self.no_drop => false,
            _ => {
                let now = Instant::now();
                let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
                while recent
                    .front()
                    .is_some_and(|t| now.duration_since(*t) > Self::WINDOW)
                {
                    recent.pop_front();
                }
                recent.push_back(now);
                recent.len() > Self::FLOOD
            }
        }
    }
}

enum Action {
    Route(String, Options),
    RouteOptions(Options),
    Reject(Reject),
    HijackDns,
    Sniff(SniffAction),
    /// With the DNS server to ask, when not the one the DNS rules pick,
    /// the families, and how long to wait.
    Resolve(Option<String>, Option<model::DnsStrategy>, Option<Duration>),
}

struct Rule {
    matcher: Matcher,
    action: Action,
}

impl Rule {
    fn new(
        rule: &model::Rule,
        path: &str,
        readers: &mut Readers,
        env: &RuntimeEnv,
        rule_sets: &rule_set::RuleSets,
    ) -> Result<Self> {
        let action = match rule.action() {
            RuleAction::Route => Action::Route(
                rule.outbound
                    .clone()
                    .ok_or_else(|| anyhow!("{}: outbound: a route rule needs one", path))?,
                Options::new(rule, path)?,
            ),
            RuleAction::RouteOptions => Action::RouteOptions(Options::new(rule, path)?),
            RuleAction::Reject => {
                let method = rule.method.unwrap_or_default();
                if method == RejectMethod::Reply {
                    return Err(anyhow!(
                        "{}.method: reply answers ICMP, which sail does not route",
                        path
                    ));
                }
                Action::Reject(Reject {
                    method,
                    no_drop: rule.no_drop,
                    recent: Default::default(),
                })
            }
            RuleAction::HijackDns => Action::HijackDns,
            RuleAction::Resolve => {
                Action::Resolve(rule.server.clone(), rule.strategy, rule.timeout)
            }
            RuleAction::Sniff => {
                if !cfg!(feature = "btls") && rule.sniffer.contains(&model::Sniffer::Quic) {
                    return Err(anyhow!(
                        "{}.sniffer: quic is never sniffed, sail is built without btls",
                        path
                    ));
                }
                let protocols = crate::sniff::Protocols::of(&rule.sniffer);
                Action::Sniff(SniffAction {
                    protocols,
                    timeout: rule.timeout.unwrap_or(Duration::from_millis(300)),
                    override_destination: rule.override_destination,
                })
            }
        };
        Ok(Rule {
            matcher: Matcher::at(rule, path, readers, env, rule_sets)?,
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
    fn load_rules(
        route: &model::Route,
        env: &RuntimeEnv,
        rule_sets: &rule_set::RuleSets,
    ) -> Result<Vec<Rule>> {
        let mut readers = Readers::new();
        route
            .rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                Rule::new(
                    rule,
                    &format!("route.rules[{}]", i),
                    &mut readers,
                    env,
                    rule_sets,
                )
            })
            .collect()
    }

    pub fn new(route: &model::Route, dns_client: SyncDnsClient, env: &RuntimeEnv) -> Result<Self> {
        Self::with_rule_sets(route, dns_client, env, &Default::default())
    }

    /// A router whose rules can name the rule-sets of `rule_sets`.
    pub(crate) fn with_rule_sets(
        route: &model::Route,
        dns_client: SyncDnsClient,
        env: &RuntimeEnv,
        rule_sets: &rule_set::RuleSets,
    ) -> Result<Self> {
        Ok(Router {
            rules: Self::load_rules(route, env, rule_sets)?,
            final_outbound: route.final_outbound.clone(),
            dns_client,
        })
    }

    /// Whether a rule, or `final`, routes to the outbound `tag`.
    pub fn uses(&self, tag: &str) -> bool {
        self.final_outbound.as_deref() == Some(tag)
            || self
                .rules
                .iter()
                .any(|rule| matches!(&rule.action, Action::Route(t, _) if t == tag))
    }

    /// Matches `sess` against the rules in order, sniffing through
    /// `sniffer`, resolving and setting route options as they say, until
    /// one decides.
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
                Action::Route(tag, options) => {
                    debug!("rule {} routes to {}", i, tag);
                    options.apply(sess);
                    return Ok(Decision::Route(Some(tag.clone())));
                }
                Action::RouteOptions(options) => {
                    debug!("rule {} sets route options", i);
                    if options.override_address.is_some() {
                        resolved.clear();
                    }
                    options.apply(sess);
                }
                Action::Reject(reject) => {
                    let drop = reject.drops();
                    debug!("rule {} rejects{}", i, if drop { ", dropping" } else { "" });
                    return Ok(Decision::Reject { drop });
                }
                Action::HijackDns => {
                    debug!("rule {} hijacks dns", i);
                    return Ok(Decision::HijackDns);
                }
                Action::Sniff(action) => {
                    sniffer
                        .sniff(sess, action)
                        .await
                        .map_err(|e| anyhow!("sniff: {}", e))?;
                }
                Action::Resolve(server, strategy, timeout) => {
                    if resolved.is_empty() && !sess.skip_resolve {
                        if let Some(domain) = facts.domain().map(str::to_string) {
                            resolved = self
                                .resolve(&domain, sess, server.as_deref(), *strategy, *timeout)
                                .await;
                        }
                    }
                }
            }
            facts = Facts::new(sess, &resolved);
        }
        Ok(Decision::Route(self.final_outbound.clone()))
    }

    /// The addresses of `domain`, or none when it does not resolve in
    /// time: the rules after a `resolve` then match without them.
    async fn resolve(
        &self,
        domain: &str,
        sess: &Session,
        server: Option<&str>,
        strategy: Option<model::DnsStrategy>,
        timeout: Option<Duration>,
    ) -> Vec<IpAddr> {
        let dns = self.dns_client.load_full();
        let lookup = async {
            match server {
                Some(server) => dns.lookup_from(server, domain, strategy).await,
                None => {
                    let ctx = crate::app::dns::LookupContext {
                        inbound: Some(sess.inbound_tag.clone()),
                        user: sess.user.clone(),
                        outbound: None,
                        strategy,
                    };
                    dns.lookup_in(domain, &ctx).await
                }
            }
        };
        let result = match timeout {
            Some(timeout) => tokio::time::timeout(timeout, lookup)
                .await
                .unwrap_or_else(|_| Err(anyhow!("timed out after {:?}", timeout))),
            None => lookup.await,
        };
        match result {
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
                "dns": { "servers": [
                    { "type": "hosts", "predefined": { "test.sail": "127.0.0.1" } },
                    { "type": "hosts", "tag": "lan", "predefined": { "test.sail": "10.0.0.1" } },
                    // A server that never answers, in the documentation range.
                    { "type": "udp", "tag": "slow", "server": "192.0.2.1" }
                ] },
                "outbounds": [{ "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" }],
                "route": { "rules": rules, "final": "b" },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
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
            if action
                .protocols
                .contains(crate::session::SniffedProtocol::Tls)
            {
                sess.set_sniffed_domain(crate::session::SniffedFrom::Tls, self.domain.to_string());
                sess.sniffed_protocol = Some(crate::session::SniffedProtocol::Tls);
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
            { "action": "sniff", "port": [443] },
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
        assert_eq!(sess.sniffed_domain(), Some("www.example.com"));
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
        assert_eq!(decision, Decision::Reject { drop: false });
    }

    #[tokio::test]
    async fn a_resolved_domain_is_matched_by_address() {
        let router = router(serde_json::json!([
            { "action": "resolve" },
            { "ip_cidr": ["127.0.0.0/8"], "outbound": "a" },
        ]));
        let mut sess = Session {
            destination: SocksAddr::Domain("test.sail".into(), 80),
            ..Default::default()
        };
        let decision = router.pick_route(&mut sess, &mut NoSniffer).await.unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));

        // Not for the lookups the DNS client makes for itself.
        sess.skip_resolve = true;
        let decision = router.pick_route(&mut sess, &mut NoSniffer).await.unwrap();
        assert_eq!(decision, Decision::Route(Some("b".into())));
    }

    #[tokio::test]
    async fn a_resolve_rule_asks_the_server_it_names() {
        let router = router(serde_json::json!([
            { "action": "resolve", "server": "lan", "strategy": "ipv4_only" },
            { "ip_cidr": ["10.0.0.0/8"], "outbound": "a" },
        ]));
        let mut sess = Session {
            destination: SocksAddr::Domain("test.sail".into(), 80),
            ..Default::default()
        };
        let decision = router.pick_route(&mut sess, &mut NoSniffer).await.unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));
    }

    fn to(destination: &str) -> Session {
        Session {
            destination: match destination.parse::<std::net::SocketAddr>() {
                Ok(addr) => SocksAddr::Ip(addr),
                Err(_) => {
                    let (host, port) = destination.rsplit_once(':').unwrap();
                    SocksAddr::Domain(host.into(), port.parse().unwrap())
                }
            },
            ..Default::default()
        }
    }

    async fn pick(router: &Router, sess: &mut Session) -> Decision {
        router.pick_route(sess, &mut NoSniffer).await.unwrap()
    }

    #[tokio::test]
    async fn route_options_set_and_the_next_rules_decide() {
        let router = router(serde_json::json!([
            { "domain": "old.test", "action": "route-options",
              "override_address": "10.9.9.9", "override_port": 8443,
              "udp_timeout": "10s", "udp_connect": true },
            // The rules after match the destination put in place.
            { "ip_cidr": "10.9.9.9", "port": 8443, "outbound": "a",
              "tls_record_fragment": true, "udp_disable_domain_unmapping": true },
        ]));
        let mut sess = to("old.test:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(sess.destination, to("10.9.9.9:8443").destination);
        let route = &sess.route;
        assert_eq!(
            route.original_destination,
            Some(to("old.test:443").destination)
        );
        assert_eq!(route.udp_timeout, Some(Duration::from_secs(10)));
        assert!(route.udp_connect && route.udp_disable_domain_unmapping);
        assert_eq!(route.tls_fragment, Some(TlsFragment::Records));

        // A port alone keeps the address; the first destination is kept.
        let router = self::router(serde_json::json!([
            { "port": 53, "action": "route-options", "override_port": 5353 },
            { "port": 5353, "action": "route-options", "override_address": "dns.test",
              "tls_fragment": true },
        ]));
        let mut sess = to("1.1.1.1:53");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("b".into()))
        );
        assert_eq!(sess.destination, to("dns.test:5353").destination);
        assert_eq!(
            sess.route.original_destination,
            Some(to("1.1.1.1:53").destination)
        );
        assert_eq!(
            sess.route.tls_fragment,
            Some(TlsFragment::Segments(TLS_FRAGMENT_DELAY))
        );
    }

    #[tokio::test]
    async fn a_route_rule_sets_its_options_as_it_routes() {
        let router = router(serde_json::json!([
            { "port": 443, "outbound": "a", "override_address": "::1",
              "tls_fragment": true, "tls_fragment_fallback_delay": "10ms" },
        ]));
        let mut sess = to("x.test:443");
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(sess.destination, to("[::1]:443").destination);
        assert_eq!(
            sess.route.tls_fragment,
            Some(TlsFragment::Segments(Duration::from_millis(10)))
        );
    }

    #[tokio::test]
    async fn hijack_dns_ends_the_matching() {
        let router = router(serde_json::json!([
            { "port": 53, "action": "hijack-dns" },
            { "port": 53, "outbound": "a" },
        ]));
        assert_eq!(
            pick(&router, &mut to("8.8.8.8:53")).await,
            Decision::HijackDns
        );
        assert_eq!(
            pick(&router, &mut to("8.8.8.8:853")).await,
            Decision::Route(Some("b".into()))
        );
    }

    #[tokio::test]
    async fn reject_drops_as_its_method_says_and_past_a_flood() {
        let router = router(serde_json::json!([
            { "port": 1, "action": "reject", "method": "drop" },
            { "port": 2, "action": "reject" },
            { "port": 3, "action": "reject", "no_drop": true },
        ]));
        assert_eq!(
            pick(&router, &mut to("1.1.1.1:1")).await,
            Decision::Reject { drop: true }
        );
        for i in 0..60 {
            let expected = Decision::Reject {
                drop: i >= Reject::FLOOD,
            };
            assert_eq!(pick(&router, &mut to("1.1.1.1:2")).await, expected, "{}", i);
            assert_eq!(
                pick(&router, &mut to("1.1.1.1:3")).await,
                Decision::Reject { drop: false }
            );
        }
    }

    #[tokio::test]
    async fn logical_and_inverted_rules_route() {
        let router = router(serde_json::json!([
            { "type": "logical", "mode": "and", "outbound": "a", "rules": [
                { "domain_suffix": "example.com" },
                { "port": 80, "invert": true }
            ] },
            { "ip_is_private": true, "invert": true, "action": "reject" },
        ]));
        assert_eq!(
            pick(&router, &mut to("www.example.com:443")).await,
            Decision::Route(Some("a".into()))
        );
        assert_eq!(
            pick(&router, &mut to("www.example.com:80")).await,
            Decision::Reject { drop: false }
        );
        assert_eq!(
            pick(&router, &mut to("192.168.1.1:80")).await,
            Decision::Route(Some("b".into()))
        );
    }

    #[tokio::test]
    async fn a_resolve_rule_gives_up_at_its_timeout() {
        let router = router(serde_json::json!([
            { "action": "resolve", "timeout": "1ms", "server": "slow" },
            { "ip_cidr": ["192.0.2.0/24"], "outbound": "a" },
        ]));
        let mut sess = to("test.sail:80");
        let start = std::time::Instant::now();
        assert_eq!(
            pick(&router, &mut sess).await,
            Decision::Route(Some("b".into()))
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn mistakes_name_their_path() {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "outbounds": [{ "type": "direct", "tag": "a" }],
                "route": { "rules": [
                    { "port": 1, "outbound": "a" },
                    { "type": "logical", "mode": "or", "outbound": "a", "rules": [
                        { "port": 2 }, { "port_range": "9:1" }
                    ] },
                ] },
            })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        let err = Router::new(&config.route, dns, &RuntimeEnv::default())
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.starts_with("route.rules[1].rules[1].port_range: invalid port range"),
            "{}",
            err
        );
        for bad in ["", "a b"] {
            let rule: model::Rule = serde_json::from_value(
                serde_json::json!({ "action": "route-options", "override_address": bad }),
            )
            .unwrap();
            assert!(Options::new(&rule, "route.rules[0]").is_err(), "{:?}", bad);
        }
    }

    #[tokio::test]
    async fn the_sniffed_protocol_is_a_condition_of_the_rules_after() {
        let router = router(serde_json::json!([
            { "protocol": "tls", "outbound": "a" },
            { "action": "sniff" },
            { "protocol": ["quic", "tls"], "port": 443, "outbound": "a" },
        ]));
        let mut sniffer = FakeSniffer {
            domain: "www.example.com",
            calls: 0,
        };
        let mut sess = to_ip();
        let decision = router.pick_route(&mut sess, &mut sniffer).await.unwrap();
        assert_eq!(decision, Decision::Route(Some("a".into())));
        assert_eq!(sniffer.calls, 1);
        // Unsniffed, no protocol matches.
        let router = self::router(serde_json::json!([{ "protocol": "tls", "outbound": "a" }]));
        assert_eq!(
            pick(&router, &mut to_ip()).await,
            Decision::Route(Some("b".into()))
        );
    }

    #[test]
    fn a_protocol_never_sniffed_is_refused() {
        for (name, message) in [
            (
                "ssh",
                "route.rules[0].protocol: sail does not sniff ssh yet",
            ),
            (
                "gopher",
                "route.rules[0].protocol: unknown protocol \"gopher\"",
            ),
        ] {
            let err = matcher::sniffed_protocol("route.rules[0].protocol", name)
                .unwrap_err()
                .to_string();
            assert_eq!(err, message);
        }
        let quic = matcher::sniffed_protocol("protocol", "quic");
        assert_eq!(quic.is_ok(), cfg!(feature = "btls"), "{:?}", quic.err());
        assert_eq!(
            matcher::sniffed_protocol("protocol", "bittorrent").unwrap(),
            crate::session::SniffedProtocol::Bittorrent
        );
    }
}
