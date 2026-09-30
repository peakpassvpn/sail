//! Rule-sets: rules kept apart from the routing and DNS rules that name
//! them, inline, in a local file or downloaded, in sing-box's source
//! (JSON) or binary (`.srs`) format.

use std::collections::HashMap;
use std::sync::Arc;

use crate::runtime::resource::HotResource;
use anyhow::{anyhow, Context, Result};

use crate::app::dispatcher::Dispatcher;
use crate::app::http::HttpClients;
use crate::app::router::matcher::{Condition, Facts, Groups, Needs};
use crate::config::rule_set::{
    self as config, ClashBehavior, RuleSetFormat, RuleSetKind, MAX_VERSION,
};
use crate::runtime::RuntimeEnv;

mod clash;
pub(crate) mod domain_set;
mod mrs;
mod reader;
pub(crate) mod remote;
pub(crate) mod rule;
mod srs;
pub(crate) mod succinct;
mod surge;

/// The domains of a binary rule-set, matched in their compact form:
/// sing-box's (`.srs`) or Mihomo's (`.mrs`).
pub(crate) enum SuccinctSet {
    Sing(succinct::Succinct),
    Mihomo(domain_set::DomainSet),
}

impl SuccinctSet {
    pub(crate) fn matches(&self, domain: &str) -> bool {
        match self {
            SuccinctSet::Sing(set) => set.matches(domain),
            SuccinctSet::Mihomo(set) => set.matches(domain),
        }
    }

    /// How many domains and suffixes it holds.
    pub(crate) fn len(&self) -> usize {
        match self {
            SuccinctSet::Sing(set) => set.len(),
            SuccinctSet::Mihomo(set) => set.len(),
        }
    }
}

/// A rule-set of at most this many domains, and no addresses, is narrow.
pub(crate) const NARROW_DOMAINS: usize = 2000;

/// The rules of one rule-set.
pub(crate) struct RuleSet {
    rules: Vec<Condition>,
    /// Whether it names a few sites rather than a region or a category:
    /// some domains, at most `NARROW_DOMAINS`, and no addresses. The smart
    /// group keeps the sites of a narrow rule-set on one member.
    narrow: bool,
    /// What its rules need learnt of a connection, as the rule naming it
    /// matches them: with their `ip_cidr` on the destination, and on the
    /// source.
    needs: [Needs; 2],
}

impl RuleSet {
    pub(crate) fn new(rules: Vec<Condition>) -> Self {
        let mut domains = 0usize;
        let mut addresses = false;
        for rule in &rules {
            match rule.domain_count() {
                Some(n) => domains += n,
                None => addresses = true,
            }
        }
        let narrow = !addresses && (1..=NARROW_DOMAINS).contains(&domains);
        let needs = [false, true].map(|source| {
            rules
                .iter()
                .fold(Needs::default(), |n, r| n.or(r.needs(source)))
        });
        Self {
            rules,
            narrow,
            needs,
        }
    }

    /// The rules of the source format, of `env`'s data files.
    pub(crate) fn from_rules(rules: &[config::HeadlessRule], env: &RuntimeEnv) -> Result<Self> {
        let rules = rules
            .iter()
            .enumerate()
            .map(|(i, r)| rule::from_source(r, &format!("rules[{}]", i), env))
            .collect::<Result<_>>()?;
        Ok(Self::new(rules))
    }

    /// How many entries it has, as Mihomo counts a rule-set's: its
    /// domains and address ranges, or else its rules.
    #[cfg(feature = "clash-api")]
    pub(crate) fn size(&self) -> usize {
        let domains: usize = self.rules.iter().filter_map(|r| r.domain_count()).sum();
        match domains + self.ip_ranges().len() {
            0 => self.rules.len(),
            n => n,
        }
    }

    /// Whether it is narrow: see `narrow`.
    pub(crate) fn is_narrow(&self) -> bool {
        self.narrow
    }

    /// What its rules need learnt of a connection, their `ip_cidr` on the
    /// source when `ip_match_source`.
    pub(crate) fn needs(&self, ip_match_source: bool) -> Needs {
        self.needs[usize::from(ip_match_source)]
    }

    /// Reads a rule-set of `format` from `data`; one of Clash's formats is
    /// of `behavior`. The data files its rules name are `env`'s.
    pub(crate) fn read(
        data: &[u8],
        format: RuleSetFormat,
        behavior: Option<ClashBehavior>,
        env: &RuntimeEnv,
    ) -> Result<Self> {
        match format {
            RuleSetFormat::Mrs | RuleSetFormat::ClashYaml | RuleSetFormat::ClashText => {
                let behavior = behavior.ok_or_else(|| anyhow!("behavior: missing"))?;
                Ok(Self::new(clash::read(data, format, behavior, env)?))
            }
            RuleSetFormat::SurgeText => {
                let behavior = behavior.ok_or_else(|| anyhow!("behavior: missing"))?;
                Ok(Self::new(surge::read(data, behavior, env)?))
            }
            RuleSetFormat::Binary => Ok(Self::new(srs::read(data, env)?)),
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
                Self::from_rules(&source.rules, env)
            }
        }
    }

    /// The destination `ip_cidr` ranges of its rules, for sets kept
    /// outside sail (auto_redirect's `route_address_set`).
    #[allow(dead_code)]
    pub(crate) fn ip_ranges(&self) -> Vec<(std::net::IpAddr, std::net::IpAddr)> {
        let mut ranges = Vec::new();
        self.rules.iter().for_each(|r| r.ip_ranges(&mut ranges));
        ranges
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

/// A rule-set, as the Clash API lists it.
#[cfg(feature = "clash-api")]
pub(crate) struct Listed {
    pub tag: String,
    pub kind: RuleSetKind,
    pub format: Option<RuleSetFormat>,
    pub behavior: Option<ClashBehavior>,
    /// Its entries, see `RuleSet::size`.
    pub size: usize,
    /// When a remote one was downloaded, or last found unchanged.
    pub updated: Option<std::time::SystemTime>,
}

/// A rule-set by tag, replaced whole when a download brings a new one.
pub(crate) type SharedRuleSet = HotResource<RuleSet>;

/// The rule-sets of `route.rule_set`, by tag.
#[derive(Default, Clone)]
pub(crate) struct RuleSets {
    sets: HashMap<String, SharedRuleSet>,
    remotes: Vec<Arc<remote::Remote>>,
    /// Each rule-set's tag and configuration, in order, for the Clash API.
    #[cfg(feature = "clash-api")]
    configs: Vec<(String, Arc<config::RuleSet>)>,
    #[cfg(feature = "auto-reload")]
    files: Vec<std::path::PathBuf>,
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
        #[cfg(feature = "auto-reload")]
        let mut files = Vec::new();
        #[cfg(feature = "clash-api")]
        let mut listed = Vec::new();
        for (i, config) in configs.iter().enumerate() {
            #[cfg(feature = "clash-api")]
            let shared = Arc::new(config.clone());
            for tag in &config.tag {
                #[cfg(feature = "clash-api")]
                listed.push((tag.clone(), shared.clone()));
                #[cfg(feature = "auto-reload")]
                if config.kind == RuleSetKind::Local {
                    files.push(
                        env.data_path(&config::RuleSet::for_tag(
                            config.path.as_deref().unwrap_or_default(),
                            tag,
                        ))
                        .into(),
                    );
                }
                let context = || format!("route.rule_set[{}]: [{}]", i, tag);
                let set = if config.kind == RuleSetKind::Remote {
                    let client = clients
                        .client(
                            config.http_client.as_ref(),
                            config.download_detour.as_deref(),
                        )
                        .with_context(context)?;
                    let remote = Arc::new(
                        remote::Remote::load(config, tag, client, env).with_context(context)?,
                    );
                    let set = remote.set.clone();
                    remotes.push(remote);
                    set
                } else {
                    HotResource::new(Self::load_one(config, tag, env).with_context(context)?)
                };
                sets.insert(tag.clone(), set);
            }
        }
        Ok(Self {
            sets,
            remotes,
            #[cfg(feature = "clash-api")]
            configs: listed,
            #[cfg(feature = "auto-reload")]
            files,
        })
    }

    #[cfg(feature = "auto-reload")]
    pub(crate) fn files(&self) -> Vec<std::path::PathBuf> {
        self.files.clone()
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
            RuleSetKind::Inline => RuleSet::from_rules(&config.rules, env),
            RuleSetKind::Local => {
                let path = env.data_path(&config::RuleSet::for_tag(
                    config.path.as_deref().unwrap_or_default(),
                    tag,
                ));
                read_file(&path, config, env)
            }
            RuleSetKind::Remote => unreachable!("remote rule-sets are loaded apart"),
        }
    }

    /// The destination address ranges of the rule-set `tag` as it is now.
    #[allow(dead_code)]
    pub(crate) fn ip_ranges(&self, tag: &str) -> Result<Vec<(std::net::IpAddr, std::net::IpAddr)>> {
        Ok(self.get(tag)?.load().ip_ranges())
    }

    /// Changes whenever the rule-set `tag` is replaced, by a download.
    #[allow(dead_code)]
    pub(crate) fn subscribe(&self, tag: &str) -> Result<tokio::sync::watch::Receiver<u64>> {
        Ok(self.get(tag)?.subscribe())
    }

    /// Each rule-set, in order, as the Clash API lists it.
    #[cfg(feature = "clash-api")]
    pub(crate) fn list(&self) -> Vec<Listed> {
        self.configs
            .iter()
            .map(|(tag, config)| Listed {
                tag: tag.clone(),
                kind: config.kind,
                format: config.format(),
                behavior: config.behavior,
                size: self.sets.get(tag).map_or(0, |set| set.load().size()),
                updated: self
                    .remotes
                    .iter()
                    .find(|r| r.tag == *tag)
                    .and_then(|r| r.updated()),
            })
            .collect()
    }

    /// Downloads the remote rule-set `tag` again; one of another kind is
    /// as it is. False when there is none so tagged.
    #[cfg(feature = "clash-api")]
    pub(crate) async fn update(&self, tag: &str, dispatcher: &Dispatcher) -> Result<bool> {
        if let Some(remote) = self.remotes.iter().find(|r| r.tag == tag) {
            remote.update(dispatcher).await?;
        }
        Ok(self.sets.contains_key(tag))
    }

    pub(crate) fn get(&self, tag: &str) -> Result<SharedRuleSet> {
        self.sets
            .get(tag)
            .cloned()
            .ok_or_else(|| anyhow!("rule-set [{}] does not exist", tag))
    }
}

fn read_file(path: &str, config: &config::RuleSet, env: &RuntimeEnv) -> Result<RuleSet> {
    let data = std::fs::read(path).map_err(|e| anyhow!("{}: {}", path, e))?;
    // Checked with the configuration.
    let format = config.format().unwrap_or(RuleSetFormat::Source);
    RuleSet::read(&data, format, config.behavior, env).map_err(|e| anyhow!("{}: {}", path, e))
}

#[cfg(test)]
mod tests {
    /// How long a rule-set takes to load into matchers: `SAIL_RS_FILE`, of
    /// `SAIL_RS_FORMAT` (`binary`, `mrs`) and `SAIL_RS_BEHAVIOR`. For
    /// measuring, not run by default; its peak memory is the process's.
    #[test]
    #[ignore]
    fn load_a_rule_set_for_measuring() {
        let file = std::env::var("SAIL_RS_FILE").unwrap();
        let format: RuleSetFormat =
            serde_json::from_value(serde_json::json!(std::env::var("SAIL_RS_FORMAT").unwrap()))
                .unwrap();
        let behavior = std::env::var("SAIL_RS_BEHAVIOR")
            .ok()
            .map(|b| serde_json::from_value(serde_json::json!(b)).unwrap());
        let data = std::fs::read(&file).unwrap();
        let start = std::time::Instant::now();
        let set = RuleSet::read(&data, format, behavior, &RuntimeEnv::default()).unwrap();
        println!("{}: loaded in {:?}", file, start.elapsed());
        std::hint::black_box(set);
    }

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
                let set = RuleSet::read(
                    &std::fs::read(&file).unwrap(),
                    format,
                    None,
                    &RuntimeEnv::default(),
                )
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
            let set = RuleSet::read(
                &std::fs::read(&file).unwrap(),
                RuleSetFormat::Binary,
                None,
                &RuntimeEnv::default(),
            )
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
        Matcher::new(&rule, &env, &sets).unwrap()
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

    /// Destination CIDRs of every default rule, nested in logical ones
    /// too, merged; source CIDRs and domains are not addresses to route.
    #[test]
    fn ip_ranges_are_the_destination_cidrs() {
        let configs: Vec<config::RuleSet> = serde_json::from_value(serde_json::json!([
            { "tag": "s", "rules": [
                { "ip_cidr": ["10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"] },
                { "source_ip_cidr": ["192.168.0.0/16"], "domain": ["example.com"] },
                { "type": "logical", "mode": "or", "rules": [
                    { "ip_cidr": ["1.1.1.1"] },
                    { "domain_suffix": ["example.org"] }
                ] }
            ] }
        ]))
        .unwrap();
        let sets =
            RuleSets::load(&configs, &HttpClients::default(), &RuntimeEnv::default()).unwrap();
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert_eq!(
            sets.ip_ranges("s").unwrap(),
            vec![
                (ip("10.0.0.0"), ip("10.255.255.255")),
                (
                    ip("2001:db8::"),
                    ip("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
                ),
                (ip("1.1.1.1"), ip("1.1.1.1")),
            ]
        );
        assert!(sets.ip_ranges("t").is_err());

        let version = sets.subscribe("s").unwrap();
        sets.get("s")
            .unwrap()
            .publish(Arc::new(RuleSet::new(Vec::new())));
        assert!(version.has_changed().unwrap());
        assert!(sets.ip_ranges("s").unwrap().is_empty());
        assert!(sets.subscribe("t").is_err());
    }

    /// A rule-set of a few domains and no addresses names sites; one of
    /// many domains, or with addresses, a region or a category. A rule
    /// that matched by a narrow one says which.
    #[test]
    fn narrow_rule_sets_name_the_sites_a_rule_matched() {
        let many: Vec<String> = (0..=NARROW_DOMAINS)
            .map(|i| format!("d{}.test", i))
            .collect();
        let m = rule(
            serde_json::json!({ "rule_set": ["broad", "addresses", "netflix", "logical"],
                                "outbound": "o" }),
            serde_json::json!([
                { "tag": "broad", "rules": [{ "domain_suffix": many }] },
                { "tag": "addresses", "rules": [
                    { "domain_suffix": ["example.com"], "ip_cidr": ["10.0.0.0/8"] }
                ] },
                { "tag": "netflix", "rules": [
                    { "domain_suffix": ["netflix.com", "nflxvideo.net", "example.com"] }
                ] },
                { "tag": "logical", "rules": [{ "type": "logical", "mode": "or", "rules": [
                    { "domain": ["a.example.org"] }, { "domain_keyword": ["example"] }
                ] }] }
            ]),
        );
        let site = |domain: &str| m.narrow_rule_set(&at(domain, 443, Tcp));
        assert_eq!(site("www.netflix.com").as_deref(), Some("netflix"));
        // Matched by the broad sets first, but they name no site.
        assert_eq!(site("example.com").as_deref(), Some("netflix"));
        assert_eq!(site("d7.test"), None);
        assert_eq!(site("a.example.org").as_deref(), Some("logical"));
        assert_eq!(site("nothing.test"), None);

        let narrow = |rules: serde_json::Value| {
            let rules: Vec<config::HeadlessRule> = serde_json::from_value(rules).unwrap();
            RuleSet::from_rules(&rules, &RuntimeEnv::default())
                .unwrap()
                .is_narrow()
        };
        assert!(narrow(serde_json::json!([{ "domain": ["a.test"] }])));
        assert!(!narrow(serde_json::json!([])));
        assert!(!narrow(serde_json::json!([{ "port": [443] }])));
        assert!(!narrow(
            serde_json::json!([{ "source_ip_cidr": ["10.0.0.0/8"] }])
        ));
        assert!(!narrow(serde_json::json!([{ "domain_suffix": many }])));
    }

    /// A download that brings a set of another size makes it narrow, or
    /// not, from then on.
    #[test]
    fn a_rule_set_replaced_is_measured_again() {
        let configs: Vec<config::RuleSet> = serde_json::from_value(serde_json::json!([
            { "tag": "s", "rules": [{ "domain_suffix": ["example.com"] }] }
        ]))
        .unwrap();
        let sets =
            RuleSets::load(&configs, &HttpClients::default(), &RuntimeEnv::default()).unwrap();
        let set = sets.get("s").unwrap();
        assert!(set.load().is_narrow());
        let many: Vec<String> = (0..=NARROW_DOMAINS)
            .map(|i| format!("d{}.test", i))
            .collect();
        let rules: Vec<config::HeadlessRule> =
            serde_json::from_value(serde_json::json!([{ "domain": many }])).unwrap();
        set.publish(Arc::new(
            RuleSet::from_rules(&rules, &RuntimeEnv::default()).unwrap(),
        ));
        assert!(!set.load().is_narrow());
    }

    /// The domains of binary sets are counted in their compact form.
    #[test]
    fn binary_sets_are_measured_too() {
        let read = |file: &str, format, behavior| {
            let data = std::fs::read(format!("{}/{}", FIXTURES, file)).unwrap();
            RuleSet::read(&data, format, behavior, &RuntimeEnv::default()).unwrap()
        };
        let count =
            |set: &RuleSet| -> usize { set.rules.iter().filter_map(|r| r.domain_count()).sum() };
        // Its source has 2073 domains, suffixes, keywords and regexes.
        let srs = read("domains.srs", RuleSetFormat::Binary, None);
        let source = read("domains.json", RuleSetFormat::Source, None);
        // The trie keeps a domain that is also a suffix once: about as many.
        let (binary, source) = (count(&srs) as f64, count(&source) as f64);
        assert!(
            (binary - source).abs() / source < 0.05,
            "{} {}",
            binary,
            source
        );
        assert!(!srs.is_narrow());
        let mrs = read(
            "geosite-telegram.mrs",
            RuleSetFormat::Mrs,
            Some(ClashBehavior::Domain),
        );
        let lines = std::fs::read_to_string(format!("{}/geosite-telegram.list", FIXTURES)).unwrap();
        let listed = lines.lines().filter(|l| !l.trim().is_empty()).count();
        // A suffix (`+.telegram.org`) is two keys there: the domain and
        // its subdomains.
        assert!(
            (listed..=2 * listed).contains(&count(&mrs)),
            "{}",
            count(&mrs)
        );
        assert!(mrs.is_narrow());
        assert!(!read("ips.srs", RuleSetFormat::Binary, None).is_narrow());
    }

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
    fn a_rule_set_s_autonomous_systems_are_its_data_directory_s() {
        use crate::app::router::matcher::tests::{asn_records, mmdb};
        let dir = std::env::temp_dir().join(format!("sail-rs-asn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (geolite, _) = asn_records(13335, "");
        std::fs::write(dir.join("asn.mmdb"), mmdb(&[("1.0.0.0/8", geolite)])).unwrap();
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                data_dir: Some(dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let rules = [serde_json::from_value(serde_json::json!({ "ip_asn": 13335 })).unwrap()];
        let set = RuleSet::from_rules(&rules, &env).unwrap();
        let at = |ip: &str| {
            let sess = crate::session::Session {
                destination: crate::session::SocksAddr::from((
                    ip.parse::<std::net::IpAddr>().unwrap(),
                    443,
                )),
                ..Default::default()
            };
            set.matches(&Facts::new(&sess, &[]), false)
        };
        assert!(at("1.1.1.1"));
        assert!(!at("9.9.9.9"));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(RuleSet::from_rules(&rules, &RuntimeEnv::default()).is_err());
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
            { "tag": "w", "rules": [{ "default_interface_address": "10.0.0.0/8" }] }
        ]))
        .unwrap();
        let err = RuleSets::load(&configs, &HttpClients::default(), &RuntimeEnv::default())
            .err()
            .unwrap();
        assert!(
            format!("{:#}", err).contains("default_interface_address: sail does not match it yet"),
            "{:#}",
            err
        );
    }

    fn on_network(state: serde_json::Value) -> Facts {
        at("a.example", 443, Tcp).with_network(std::sync::Arc::new(
            crate::net::network::NetworkState::from_json(&state.to_string()).unwrap(),
        ))
    }

    /// A rule-set's rules match the network the host is on, as a routing
    /// rule's do, and the rule naming it needs the network then.
    #[test]
    fn a_rule_set_matches_the_network() {
        let m = rule(
            serde_json::json!({ "rule_set": "home", "outbound": "x" }),
            serde_json::json!([{ "tag": "home", "rules": [
                { "wifi_ssid": "Home", "network_type": "wifi" }
            ] }]),
        );
        assert!(m.needs().network);
        assert!(m.matches(&on_network(
            serde_json::json!({ "type": "wifi", "ssid": "Home" })
        )));
        assert!(!m.matches(&on_network(
            serde_json::json!({ "type": "wifi", "ssid": "Cafe" })
        )));
        assert!(!m.matches(&at("a.example", 443, Tcp)));
    }

    /// A binary rule of sing-box's: `wifi_ssid` Home, `network_type`
    /// wifi (0), `network_is_expensive`.
    #[test]
    fn a_binary_rule_set_matches_the_network() {
        let mut rules = vec![1u8, 0];
        rules.extend([14, 1, 4]);
        rules.extend(b"Home");
        rules.extend([18, 1, 0]);
        rules.extend([19]);
        rules.extend([0xff, 0]);
        let mut data = b"SRS\x03".to_vec();
        data.extend(miniz_oxide::deflate::compress_to_vec_zlib(&rules, 6));
        let set =
            RuleSet::read(&data, RuleSetFormat::Binary, None, &RuntimeEnv::default()).unwrap();
        assert!(set.needs(false).network);
        let home = |expensive: bool| {
            on_network(serde_json::json!({
                "type": "wifi", "ssid": "Home", "expensive": expensive
            }))
        };
        assert!(set.matches(&home(true), false));
        assert!(!set.matches(&home(false), false));
        assert!(!set.matches(&at("a.example", 443, Tcp), false));

        // A kind of network sing-box does not number is an error.
        let mut data = b"SRS\x03".to_vec();
        data.extend(miniz_oxide::deflate::compress_to_vec_zlib(
            &[1, 0, 18, 1, 9, 0xff, 0],
            6,
        ));
        assert!(RuleSet::read(&data, RuleSetFormat::Binary, None, &RuntimeEnv::default()).is_err());
    }

    #[test]
    fn a_damaged_binary_is_an_error_not_a_panic() {
        let data = std::fs::read(format!("{}/domains.srs", FIXTURES)).unwrap();
        assert!(RuleSet::read(
            &data[..data.len() / 2],
            RuleSetFormat::Binary,
            None,
            &RuntimeEnv::default()
        )
        .is_err());
        assert!(RuleSet::read(
            b"SRS\x09",
            RuleSetFormat::Binary,
            None,
            &RuntimeEnv::default()
        )
        .is_err());
        assert!(RuleSet::read(
            b"XYZ\x01",
            RuleSetFormat::Binary,
            None,
            &RuntimeEnv::default()
        )
        .is_err());
        // Each byte flipped in turn: never a panic.
        for i in 4..data.len().min(600) {
            let mut bad = data.clone();
            bad[i] ^= 0x5a;
            let _ = RuleSet::read(&bad, RuleSetFormat::Binary, None, &RuntimeEnv::default());
        }
    }
}
