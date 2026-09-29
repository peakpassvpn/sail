//! The rules of a rule-set, compiled to the conditions routing rules
//! compile to: sing-box matches a headless rule as it matches the
//! conditions of a routing rule.

use std::net::IpAddr;

use anyhow::{anyhow, Result};

use super::SuccinctSet;
use crate::app::router::matcher::{query_type, Condition, Conditions, Context, Extras, MAX_DEPTH};
use crate::config::model;
use crate::config::rule_set::HeadlessRule;
use crate::runtime::RuntimeEnv;

/// What a default rule is made of, before it is compiled: the conditions
/// of a source rule, and those a binary one gives in forms of its own.
#[derive(Default)]
pub(crate) struct Parts {
    pub rule: HeadlessRule,
    pub succinct: Option<SuccinctSet>,
    pub ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub source_ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub query_types: Vec<u16>,
}

/// Compiles a rule of the source format, found at `path`; the data files
/// its conditions name (`ip_asn`'s) are `env`'s.
pub(crate) fn from_source(rule: &HeadlessRule, path: &str, env: &RuntimeEnv) -> Result<Condition> {
    compile(rule, path, 0, env)
}

fn compile(rule: &HeadlessRule, path: &str, depth: usize, env: &RuntimeEnv) -> Result<Condition> {
    if depth > MAX_DEPTH {
        return Err(anyhow!("{}: logical rules nested too deep", path));
    }
    if rule.no_resolve && !rule.on_addresses() {
        return Err(anyhow!(
            "{}.no_resolve: the rule has no condition on the destination's addresses",
            path
        ));
    }
    match rule.kind.as_deref() {
        None | Some("default") => {
            if rule.mode.is_some() || !rule.rules.is_empty() {
                return Err(anyhow!("{}: mode and rules are for a logical rule", path));
            }
            let query_types = rule
                .query_type
                .iter()
                .map(query_type)
                .collect::<Result<_>>()
                .map_err(|e| anyhow!("{}.query_type: {}", path, e))?;
            default(
                Parts {
                    rule: rule.clone(),
                    query_types,
                    ..Default::default()
                },
                path,
                env,
            )
        }
        Some("logical") => {
            let all = match rule.mode.as_deref() {
                Some("and") => true,
                Some("or") => false,
                Some(other) => return Err(anyhow!("{}.mode: unknown mode \"{}\"", path, other)),
                None => return Err(anyhow!("{}.mode: missing", path)),
            };
            if rule.rules.is_empty() {
                return Err(anyhow!("{}.rules: a logical rule needs some", path));
            }
            let rules = rule
                .rules
                .iter()
                .enumerate()
                .map(|(i, r)| compile(r, &format!("{}.rules[{}]", path, i), depth + 1, env))
                .collect::<Result<_>>()?;
            Ok(Condition::Logical {
                all,
                rules,
                invert: rule.invert,
                no_resolve: rule.no_resolve,
                response: None,
            })
        }
        Some(other) => Err(anyhow!("{}.type: unknown rule type \"{}\"", path, other)),
    }
}

/// Compiles a default rule, found at `path`, of `env`'s data files.
pub(crate) fn default(parts: Parts, path: &str, env: &RuntimeEnv) -> Result<Condition> {
    let rule = &parts.rule;
    if let Some(field) = rule.unsupported() {
        return Err(anyhow!("{}.{}: sail does not match it yet", path, field));
    }
    // The conditions a headless rule shares with a routing rule.
    let conditions = model::Rule {
        network: rule.network.clone(),
        domain: rule.domain.clone(),
        domain_suffix: rule.domain_suffix.clone(),
        domain_keyword: rule.domain_keyword.clone(),
        domain_regex: rule.domain_regex.clone(),
        source_ip_cidr: rule.source_ip_cidr.clone(),
        ip_cidr: rule.ip_cidr.clone(),
        ip_asn: rule.ip_asn.clone(),
        http_user_agent: rule.http_user_agent.clone(),
        url_regex: rule.url_regex.clone(),
        source_port: rule.source_port.clone(),
        source_port_range: rule.source_port_range.clone(),
        port: rule.port.clone(),
        port_range: rule.port_range.clone(),
        process_name: rule.process_name.clone(),
        process_path: rule.process_path.clone(),
        process_path_regex: rule.process_path_regex.clone(),
        process_name_regex: rule.process_name_regex.clone(),
        package_name: rule.package_name.clone(),
        package_name_regex: rule.package_name_regex.clone(),
        no_resolve: rule.no_resolve,
        invert: rule.invert,
        ..Default::default()
    };
    let extras = Extras {
        succinct: parts.succinct,
        ip_ranges: parts.ip_ranges,
        source_ip_ranges: parts.source_ip_ranges,
        query_types: parts.query_types,
    };
    let mut ctx = Context {
        env,
        rule_sets: &Default::default(),
    };
    let compiled = Conditions::compile(&conditions, extras, path, &mut ctx)?;
    Ok(Condition::Default(Box::new(compiled)))
}
