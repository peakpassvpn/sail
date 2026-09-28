//! Rule-sets: rules kept apart from the routing and DNS rules that name
//! them, inline, in a local file or downloaded, in sing-box's source
//! (JSON) or binary (`.srs`) format.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;

use crate::app::dispatcher::Dispatcher;
use crate::app::router::matcher::{Condition, Facts, Groups};
use crate::config::model::{HttpClient, HttpClientRef};
use crate::config::rule_set::{self as config, RuleSetFormat, RuleSetKind, MAX_VERSION};
use crate::net::DialOptions;
use crate::runtime::RuntimeEnv;

mod http;
mod reader;
mod remote;
pub(crate) mod rule;
mod srs;
pub(crate) mod succinct;

/// The rules of one rule-set.
pub(crate) struct RuleSet {
    rules: Vec<Condition>,
}

impl RuleSet {
    pub(crate) fn from_rules(rules: &[config::HeadlessRule]) -> Result<Self> {
        let rules = rules
            .iter()
            .enumerate()
            .map(|(i, r)| rule::from_source(r, &format!("rules[{}]", i)))
            .collect::<Result<_>>()?;
        Ok(Self { rules })
    }

    /// Reads a rule-set of `format` from `data`.
    pub(crate) fn read(data: &[u8], format: RuleSetFormat) -> Result<Self> {
        match format {
            RuleSetFormat::Binary => Ok(Self {
                rules: srs::read(data)?,
            }),
            RuleSetFormat::Source => {
                let source: config::SourceRuleSet = serde_json::from_slice(data)
                    .map_err(|e| anyhow!("invalid source rule-set: {}", e))?;
                if source.version == 0 || source.version > MAX_VERSION {
                    return Err(anyhow!(
                        "version {}: sail reads 1 to {}",
                        source.version,
                        MAX_VERSION
                    ));
                }
                Self::from_rules(&source.rules)
            }
        }
    }

    /// Whether any of its rules matches.
    pub(crate) fn matches(&self, facts: &Facts, ip_match_source: bool) -> bool {
        self.rules.iter().any(|r| r.matches(facts, ip_match_source))
    }

    /// Whether the rule naming it matches, with its own conditions in
    /// `outer`, as sing-box has it: a rule-set of one plain rule merges its
    /// conditions with the outer ones, so that a domain of either matches;
    /// any other must match itself, and the outer conditions too.
    pub(crate) fn matches_with(&self, outer: Groups, facts: &Facts, ip_match_source: bool) -> bool {
        if let [rule] = &self.rules[..] {
            if let Some(conditions) = rule.mergeable() {
                return conditions
                    .evaluate(facts, ip_match_source)
                    .is_some_and(|groups| outer.merge(groups).done());
            }
        }
        outer.done() && self.matches(facts, ip_match_source)
    }
}

/// What remote rule-sets are downloaded with: `http_clients`, and the dial
/// options of those that dial directly.
#[derive(Default)]
pub(crate) struct HttpClients {
    clients: Vec<HttpClient>,
    default: Option<String>,
    dial: Arc<DialOptions>,
}

impl HttpClients {
    pub(crate) fn new(config: &crate::config::Config, dial: Arc<DialOptions>) -> Self {
        Self {
            clients: config.http_clients.clone(),
            default: config.route.default_http_client.clone(),
            dial,
        }
    }

    fn get(&self, tag: &str) -> Result<&HttpClient> {
        self.clients
            .iter()
            .find(|c| c.tag == tag)
            .ok_or_else(|| anyhow!("http client [{}] does not exist", tag))
    }

    /// How the rule-set of `config` is downloaded, as sing-box has it: with
    /// its `http_client`, or through its `download_detour`, or with the
    /// default client; none, through the default outbound.
    fn client(&self, config: &config::RuleSet) -> Result<http::Client> {
        let client = match &config.http_client {
            Some(HttpClientRef::Tag(tag)) => self.get(tag)?,
            Some(HttpClientRef::Inline(client)) => client,
            None => {
                if let Some(detour) = &config.download_detour {
                    return Ok(http::Client {
                        via: Some(http::Via::Outbound(detour.clone())),
                        headers: Vec::new(),
                    });
                }
                match &self.default {
                    Some(tag) => self.get(tag)?,
                    None => match self.clients.first() {
                        Some(client) => client,
                        None => return Ok(http::Client::default()),
                    },
                }
            }
        };
        let via = match &client.detour {
            Some(detour) => http::Via::Outbound(detour.clone()),
            None => http::Via::Direct(Arc::new(client.dial(&self.dial))),
        };
        Ok(http::Client {
            via: Some(via),
            headers: client.header_lines(),
        })
    }
}

/// A rule-set by tag, replaced whole when a download brings a new one.
pub(crate) type SharedRuleSet = Arc<ArcSwap<RuleSet>>;

/// The rule-sets of `route.rule_set`, by tag.
#[derive(Default, Clone)]
pub(crate) struct RuleSets {
    sets: HashMap<String, SharedRuleSet>,
    remotes: Vec<Arc<remote::Remote>>,
}

impl RuleSets {
    /// Reads the inline and local rule-sets. A remote one starts from its
    /// cached copy, or its `initial_path`, or else empty until downloaded.
    pub(crate) fn load(
        configs: &[config::RuleSet],
        clients: &HttpClients,
        env: &RuntimeEnv,
    ) -> Result<Self> {
        let mut sets = HashMap::new();
        let mut remotes = Vec::new();
        for (i, config) in configs.iter().enumerate() {
            for tag in &config.tag {
                let context = || format!("route.rule_set[{}]: [{}]", i, tag);
                let set = if config.kind == RuleSetKind::Remote {
                    let client = clients.client(config).with_context(context)?;
                    let remote = Arc::new(
                        remote::Remote::load(config, tag, client, env).with_context(context)?,
                    );
                    let set = remote.set.clone();
                    remotes.push(remote);
                    set
                } else {
                    Arc::new(ArcSwap::from_pointee(
                        Self::load_one(config, tag, env).with_context(context)?,
                    ))
                };
                sets.insert(tag.clone(), set);
            }
        }
        Ok(Self { sets, remotes })
    }

    /// Downloads the remote rule-sets that have no copy yet: the rules
    /// that name them cannot match until they do.
    pub(crate) async fn fetch_missing(&self, dispatcher: &Dispatcher) -> Result<()> {
        let missing = self.remotes.iter().filter(|r| !r.is_loaded());
        let downloads = missing.map(|remote| async move {
            remote
                .update(dispatcher)
                .await
                .map_err(|e| anyhow!("rule-set [{}]: download: {:#}", remote.tag, e))
        });
        futures::future::try_join_all(downloads).await?;
        Ok(())
    }

    /// Downloads the remote rule-sets again as each falls due; stopped by
    /// aborting the task.
    pub(crate) fn spawn_updater(
        &self,
        dispatcher: std::sync::Weak<Dispatcher>,
    ) -> Option<tokio::task::AbortHandle> {
        if self.remotes.is_empty() {
            return None;
        }
        let remotes = self.remotes.clone();
        let task = tokio::spawn(async move {
            loop {
                let now = std::time::SystemTime::now();
                let next = remotes
                    .iter()
                    .map(|r| r.due_in(now))
                    .min()
                    .unwrap_or_default();
                // At least a second apart, whatever the clock does.
                tokio::time::sleep(next.max(std::time::Duration::from_secs(1))).await;
                let Some(dispatcher) = dispatcher.upgrade() else {
                    return;
                };
                let now = std::time::SystemTime::now();
                for remote in remotes.iter().filter(|r| r.due_in(now).is_zero()) {
                    if let Err(e) = remote.update(&dispatcher).await {
                        tracing::warn!(
                            "rule-set [{}]: download failed, keeping the rules in use: {:#}",
                            remote.tag,
                            e
                        );
                    }
                }
            }
        });
        Some(task.abort_handle())
    }

    fn load_one(config: &config::RuleSet, tag: &str, env: &RuntimeEnv) -> Result<RuleSet> {
        match config.kind {
            RuleSetKind::Inline => RuleSet::from_rules(&config.rules),
            RuleSetKind::Local => {
                let path = env.data_path(&config::RuleSet::for_tag(
                    config.path.as_deref().unwrap_or_default(),
                    tag,
                ));
                read_file(&path, config)
            }
            RuleSetKind::Remote => unreachable!("remote rule-sets are loaded apart"),
        }
    }

    pub(crate) fn get(&self, tag: &str) -> Result<SharedRuleSet> {
        self.sets
            .get(tag)
            .cloned()
            .ok_or_else(|| anyhow!("rule-set [{}] does not exist", tag))
    }
}

fn read_file(path: &str, config: &config::RuleSet) -> Result<RuleSet> {
    let data = std::fs::read(path).map_err(|e| anyhow!("{}: {}", path, e))?;
    // Checked with the configuration.
    let format = config.format().unwrap_or(RuleSetFormat::Source);
    RuleSet::read(&data, format).map_err(|e| anyhow!("{}: {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Session, SocksAddr};

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rule_set");

    fn facts(probe: &str) -> Facts {
        let destination = match probe.parse::<std::net::IpAddr>() {
            Ok(ip) => SocksAddr::Ip((ip, 443).into()),
            Err(_) => SocksAddr::Domain(probe.to_string(), 443),
        };
        Facts::new(
            &Session {
                destination,
                ..Default::default()
            },
            &[],
        )
    }

    /// sing-box compiled the `.srs` files from the `.json` ones, and
    /// `sing-box rule-set match` gave `expected.json`, for both forms.
    #[test]
    fn source_and_binary_match_as_sing_box_does() {
        let expected: HashMap<String, HashMap<String, bool>> =
            serde_json::from_slice(&std::fs::read(format!("{}/expected.json", FIXTURES)).unwrap())
                .unwrap();
        for (name, probes) in &expected {
            for (file, format) in [
                (format!("{}/{}.json", FIXTURES, name), RuleSetFormat::Source),
                (format!("{}/{}.srs", FIXTURES, name), RuleSetFormat::Binary),
            ] {
                let set = RuleSet::read(&std::fs::read(&file).unwrap(), format)
                    .unwrap_or_else(|e| panic!("{}: {}", file, e));
                let wrong: Vec<&String> = probes
                    .iter()
                    .filter(|(probe, matched)| set.matches(&facts(probe), false) != **matched)
                    .map(|(probe, _)| probe)
                    .collect();
                assert!(
                    wrong.is_empty(),
                    "{}: {} wrong: {:?}",
                    file,
                    wrong.len(),
                    wrong
                );
            }
        }
    }

    /// The published rule-sets, against what sing-box said of them: a
    /// directory with `<name>.srs` and `real-expected.json`, in
    /// `SAIL_REAL_RULE_SETS`.
    #[test]
    #[ignore]
    fn published_rule_sets_match_as_sing_box_does() {
        let dir = std::env::var("SAIL_REAL_RULE_SETS").expect("SAIL_REAL_RULE_SETS");
        let expected: HashMap<String, HashMap<String, bool>> =
            serde_json::from_slice(&std::fs::read(format!("{}/real-expected.json", dir)).unwrap())
                .unwrap();
        for (name, probes) in &expected {
            let file = format!("{}/{}.srs", dir, name);
            let set = RuleSet::read(&std::fs::read(&file).unwrap(), RuleSetFormat::Binary)
                .unwrap_or_else(|e| panic!("{}: {}", file, e));
            let wrong: Vec<&String> = probes
                .iter()
                .filter(|(probe, matched)| set.matches(&facts(probe), false) != **matched)
                .map(|(probe, _)| probe)
                .collect();
            assert!(
                wrong.is_empty(),
                "{}: {} wrong: {:?}",
                file,
                wrong.len(),
                wrong
            );
        }
    }

    /// A rule of `route` naming the inline rule-sets `sets`, by tag.
    fn rule(route_rule: serde_json::Value, sets: serde_json::Value) -> Matcher {
        let rule: crate::config::model::Rule = serde_json::from_value(route_rule).unwrap();
        let configs: Vec<config::RuleSet> = serde_json::from_value(sets).unwrap();
        let env = RuntimeEnv::default();
        let sets = RuleSets::load(&configs, &HttpClients::default(), &env).unwrap();
        Matcher::new(&rule, &mut Default::default(), &env, &sets).unwrap()
    }

    fn at(domain: &str, port: u16, network: crate::session::Network) -> Facts {
        Facts::new(
            &Session {
                destination: SocksAddr::Domain(domain.into(), port),
                network,
                ..Default::default()
            },
            &[],
        )
    }

    use crate::app::router::matcher::Matcher;
    use crate::session::Network::{Tcp, Udp};

    /// sing-box's TestRuleSetShapeBoundary: one plain rule merges with the
    /// outer conditions, two do not.
    #[test]
    fn a_set_of_one_rule_merges_with_the_outer_conditions() {
        let outer = serde_json::json!({
            "domain": "extra.example.org", "port": 443, "rule_set": "s", "outbound": "x"
        });
        let single = rule(
            outer.clone(),
            serde_json::json!([{ "tag": "s", "rules": [
                { "domain_suffix": ["a.example.com", "b.example.com"] }
            ] }]),
        );
        let multi = rule(
            outer,
            serde_json::json!([{ "tag": "s", "rules": [
                { "domain_suffix": "a.example.com" }, { "domain_suffix": "b.example.com" }
            ] }]),
        );
        for (domain, port, single_result, multi_result) in [
            ("www.b.example.com", 443, true, false),
            ("extra.example.org", 443, true, false),
            ("other.example.net", 443, false, false),
            ("www.b.example.com", 80, false, false),
        ] {
            let facts = at(domain, port, Tcp);
            assert_eq!(single.matches(&facts), single_result, "single {}", domain);
            assert_eq!(multi.matches(&facts), multi_result, "multi {}", domain);
        }
    }

    #[test]
    fn rule_sets_are_alternatives_and_other_conditions_still_hold() {
        // A later set can satisfy what an earlier one did not.
        let m = rule(
            serde_json::json!({ "ip_cidr": "203.0.113.0/24", "rule_set": ["net", "dom"],
                                "outbound": "x" }),
            serde_json::json!([
                { "tag": "net", "rules": [{ "network": "tcp" }] },
                { "tag": "dom", "rules": [{ "domain_suffix": "example.com" }] }
            ]),
        );
        assert!(m.matches(&at("www.example.com", 443, Tcp)));
        // The outer rule's network stays a condition of its own.
        let m = rule(
            serde_json::json!({ "network": "udp", "rule_set": "dom", "outbound": "x" }),
            serde_json::json!([{ "tag": "dom", "rules": [{ "domain_suffix": "example.com" }] }]),
        );
        assert!(!m.matches(&at("www.example.com", 443, Tcp)));
        assert!(m.matches(&at("www.example.com", 443, Udp)));
        // And the set's, however the outer conditions match.
        let m = rule(
            serde_json::json!({ "domain_suffix": "example.com", "rule_set": "net",
                                "outbound": "x" }),
            serde_json::json!([{ "tag": "net", "rules": [{ "network": "udp" }] }]),
        );
        assert!(!m.matches(&at("www.example.com", 443, Tcp)));
    }

    #[test]
    fn an_empty_set_never_matches_and_an_inverted_one_is_its_own() {
        let m = rule(
            serde_json::json!({ "domain_suffix": "example.com", "rule_set": "empty",
                                "outbound": "x" }),
            serde_json::json!([{ "tag": "empty", "rules": [] }]),
        );
        assert!(!m.matches(&at("www.example.com", 443, Tcp)));
        let m = rule(
            serde_json::json!({ "rule_set": "not", "outbound": "x" }),
            serde_json::json!([{ "tag": "not", "rules": [
                { "domain_suffix": "blocked.example", "invert": true }
            ] }]),
        );
        assert!(m.matches(&at("good.example.org", 443, Tcp)));
        assert!(!m.matches(&at("www.blocked.example", 443, Tcp)));
    }

    #[test]
    fn logical_rules_combine() {
        let m = rule(
            serde_json::json!({ "rule_set": "l", "outbound": "x" }),
            serde_json::json!([{ "tag": "l", "rules": [{
                "type": "logical", "mode": "and", "rules": [
                    { "domain_suffix": "example.com" },
                    { "type": "logical", "mode": "or", "invert": true, "rules": [
                        { "port": 80 }, { "network": "udp" }
                    ] }
                ]
            }] }]),
        );
        assert!(m.matches(&at("a.example.com", 443, Tcp)));
        assert!(!m.matches(&at("a.example.com", 80, Tcp)));
        assert!(!m.matches(&at("a.example.com", 443, Udp)));
        assert!(!m.matches(&at("a.example.org", 443, Tcp)));
    }

    #[test]
    fn a_rule_set_s_ip_cidr_can_match_the_source() {
        let sets =
            serde_json::json!([{ "tag": "lan", "rules": [{ "ip_cidr": "192.168.0.0/16" }] }]);
        let by_source = rule(
            serde_json::json!({ "rule_set": "lan", "rule_set_ip_cidr_match_source": true,
                                "outbound": "x" }),
            sets.clone(),
        );
        let by_destination = rule(
            serde_json::json!({ "rule_set": "lan", "outbound": "x" }),
            sets,
        );
        let facts = Facts::new(
            &Session {
                source: "192.168.1.5:5000".parse().unwrap(),
                destination: SocksAddr::Ip("8.8.8.8:53".parse().unwrap()),
                ..Default::default()
            },
            &[],
        );
        assert!(by_source.matches(&facts));
        assert!(!by_destination.matches(&facts));
    }

    #[test]
    fn unsupported_conditions_are_refused_with_their_name() {
        let configs: Vec<config::RuleSet> = serde_json::from_value(serde_json::json!([
            { "tag": "w", "rules": [{ "wifi_ssid": "home" }] }
        ]))
        .unwrap();
        let err = RuleSets::load(&configs, &HttpClients::default(), &RuntimeEnv::default())
            .err()
            .unwrap();
        assert!(
            format!("{:#}", err).contains("wifi_ssid: sail does not match it yet"),
            "{:#}",
            err
        );
    }

    #[test]
    fn a_damaged_binary_is_an_error_not_a_panic() {
        let data = std::fs::read(format!("{}/domains.srs", FIXTURES)).unwrap();
        assert!(RuleSet::read(&data[..data.len() / 2], RuleSetFormat::Binary).is_err());
        assert!(RuleSet::read(b"SRS\x09", RuleSetFormat::Binary).is_err());
        assert!(RuleSet::read(b"XYZ\x01", RuleSetFormat::Binary).is_err());
        // Each byte flipped in turn: never a panic.
        for i in 4..data.len().min(600) {
            let mut bad = data.clone();
            bad[i] ^= 0x5a;
            let _ = RuleSet::read(&bad, RuleSetFormat::Binary);
        }
    }
}
