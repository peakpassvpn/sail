//! sing-box headless rule-sets for a host to match its own sessions with,
//! as a host outbound kind routing on a table of the host's does: the
//! rule-sets sail's router reads, read and matched by the same code.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use super::kinds::SessionInfo;
use super::{Error, ErrorKind};
use crate::app::router::matcher::Facts;
use crate::app::router::rule_set::rule::Parts;
use crate::config::rule_set::{HeadlessRule, SourceRuleSet};
use crate::runtime::RuntimeEnv;
use crate::session::Network;

/// The format of a rule-set's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleSetFormat {
    /// sing-box's binary format, `.srs`.
    Binary,
    /// sing-box's source format, JSON, `.json`.
    Source,
}

/// The conditions a host's session can be matched on: `MatchInput`'s.
/// A rule with any other is refused as the rule-set is read, rather than
/// never matching.
const MATCHED: &[&str] = &[
    "type",
    "mode",
    "rules",
    "invert",
    "no_resolve",
    "network",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "source_ip_cidr",
    "port",
    "port_range",
    "source_port",
    "source_port_range",
];

/// A sing-box headless rule-set, read once and matched as often as the
/// host likes, from any thread. Cheap to clone; its clones are one.
#[derive(Clone)]
pub struct RuleSet(Arc<crate::app::router::rule_set::RuleSet>);

impl std::fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RuleSet({})", self.0.size())
    }
}

impl RuleSet {
    /// The rule-set `data` is, in `format`. `InvalidArgument` when it does
    /// not read, or a rule has a condition `MatchInput` cannot carry: the
    /// message names the rule and the condition.
    pub fn from_bytes(data: &[u8], format: RuleSetFormat) -> Result<Self, Error> {
        let invalid = |e: anyhow::Error| Error::new(ErrorKind::InvalidArgument, format!("{:#}", e));
        let env = RuntimeEnv::default();
        let set = match format {
            RuleSetFormat::Binary => crate::app::router::rule_set::RuleSet::new(
                crate::app::router::rule_set::srs::read_checked(data, &env, &refused_parts)
                    .map_err(invalid)?,
            ),
            RuleSetFormat::Source => {
                let source: SourceRuleSet = serde_json::from_slice(data).map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidArgument,
                        format!("invalid source rule-set: {}", e),
                    )
                })?;
                for (i, rule) in source.rules.iter().enumerate() {
                    refused_rule(rule, &format!("rules[{}]", i)).map_err(invalid)?;
                }
                crate::app::router::rule_set::RuleSet::read(
                    data,
                    crate::config::rule_set::RuleSetFormat::Source,
                    None,
                    &env,
                )
                .map_err(invalid)?
            }
        };
        Ok(RuleSet(Arc::new(set)))
    }

    /// The rule-set in the file `path`, of the format its extension says:
    /// `.srs` binary, `.json` source. `InvalidArgument` for any other, `Io`
    /// when it cannot be read.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let format = match path.extension().and_then(|e| e.to_str()) {
            Some("srs") => RuleSetFormat::Binary,
            Some("json") => RuleSetFormat::Source,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "{}: the format is not known by its extension, .srs or .json",
                        path.display()
                    ),
                ))
            }
        };
        Self::from_path_as(path, format)
    }

    /// The rule-set in the file `path`, in `format`.
    pub fn from_path_as(path: impl AsRef<Path>, format: RuleSetFormat) -> Result<Self, Error> {
        let path = path.as_ref();
        let data = std::fs::read(path)
            .map_err(|e| Error::new(ErrorKind::Io, format!("{}: {}", path.display(), e)))?;
        Self::from_bytes(&data, format)
            .map_err(|e| Error::new(e.kind(), format!("{}: {}", path.display(), e.message())))
    }

    /// Whether any of its rules matches `input`, as the rule-set matches
    /// in a routing rule: `ip_cidr` on the addresses given, `source_*` on
    /// the source.
    pub fn matches(&self, input: &MatchInput) -> bool {
        let facts = Facts::of_host(
            input.network,
            input.domain.as_deref(),
            &input.ips,
            input.port,
            input.source,
        );
        self.0.matches(&facts, false)
    }

    /// How many entries it has, as Mihomo counts a rule-set's: its domains
    /// and address ranges, or else its rules.
    pub fn len(&self) -> usize {
        self.0.size()
    }

    /// Whether it has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a session is matched on: where it goes, by name, addresses and
/// port, its network and its source.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MatchInput {
    pub network: Network,
    /// The domain, sniffed or asked for.
    pub domain: Option<String>,
    /// The destination's address, and those its domain resolved to: what
    /// `ip_cidr` matches. sail resolves nothing.
    pub ips: Vec<IpAddr>,
    pub port: u16,
    /// What `source_ip_cidr` and `source_port` match; an unspecified
    /// address and port 0 when not given.
    pub source: SocketAddr,
}

impl MatchInput {
    /// A TCP session to `port`, nothing else known.
    pub fn new(port: u16) -> Self {
        MatchInput {
            network: Network::Tcp,
            domain: None,
            ips: Vec::new(),
            port,
            source: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
    }

    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// An address the destination is: given again for each.
    pub fn ip(mut self, ip: IpAddr) -> Self {
        self.ips.push(ip);
        self
    }

    pub fn source(mut self, source: SocketAddr) -> Self {
        self.source = source;
        self
    }
}

impl From<&SessionInfo> for MatchInput {
    /// The session a host outbound is asked for: the domain known for it,
    /// else its destination's name; its destination's address.
    fn from(session: &SessionInfo) -> Self {
        let mut input = MatchInput::new(session.destination.port())
            .network(session.network)
            .source(session.source);
        input.domain = session
            .domain
            .clone()
            .or_else(|| session.destination.domain().cloned());
        input.ips.extend(session.destination.ip());
        input
    }
}

/// The first condition of `rule`, at `path`, or of a rule within, that a
/// host's input cannot carry, as an error.
fn refused_rule(rule: &HeadlessRule, path: &str) -> anyhow::Result<()> {
    if let Some(field) = refused_field(rule) {
        return Err(anyhow::anyhow!(
            "{}.{}: an embed rule-set does not match it",
            path,
            field
        ));
    }
    for (i, inner) in rule.rules.iter().enumerate() {
        refused_rule(inner, &format!("{}.rules[{}]", path, i))?;
    }
    Ok(())
}

/// The first condition set in `rule` itself that is not `MATCHED`: the
/// rule as it is written out has only the conditions set.
fn refused_field(rule: &HeadlessRule) -> Option<String> {
    let written = serde_json::to_value(HeadlessRule {
        rules: Vec::new(),
        ..rule.clone()
    })
    .ok()?;
    written
        .as_object()?
        .keys()
        .find(|field| !MATCHED.contains(&field.as_str()))
        .cloned()
}

/// `refused_rule` of a binary rule-set's plain rule.
fn refused_parts(parts: &Parts) -> anyhow::Result<()> {
    if !parts.query_types.is_empty() {
        return Err(anyhow::anyhow!(
            "query_type: an embed rule-set does not match it"
        ));
    }
    match refused_field(&parts.rule) {
        Some(field) => Err(anyhow::anyhow!(
            "{}: an embed rule-set does not match it",
            field
        )),
        None => Ok(()),
    }
}
