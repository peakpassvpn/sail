//! Clash / Mihomo's YAML, read as Mihomo 1.19 reads it, lowered to sail's
//! model: the same configuration sing-box's JSON reads into.
//!
//! What Mihomo takes and sail does not implement is sorted out as for
//! sing-box's JSON: an error when ignoring it would route or secure traffic
//! otherwise, else a warning. Unlike sing-box, Mihomo passes over a field it
//! does not know, and templates lean on that, keeping anchors under keys of
//! their own; sail warns of such a field, but for one holding an anchor.
//!
//! Where sail does what Mihomo does otherwise, and the configuration cannot
//! say it: a proxy without `udp: true` carries UDP too, where in Mihomo UDP
//! to it passes to the next rule.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::model::Config;

mod dns;
mod fields;
mod general;
mod group;
mod hosts;
mod listeners;
mod node;
/// The rule-sets rules name, which Surge's rules name too.
pub(in crate::config) mod provider;
mod proxy;
mod proxy_provider;
mod rule;
mod sniffer;
/// What outbound providers read.
#[cfg(feature = "outbound-provider")]
pub(crate) mod subscription;
mod tun;

use fields::Fields;

/// Reads a Clash / Mihomo configuration.
pub fn parse(s: &str) -> Result<Config> {
    let root = node::parse(s)?;
    let holders = node::anchor_holders(s);
    let mut doc = Fields::of(root, "")?;
    let mut warnings = Vec::new();
    let mut out = Lowered::default();
    let fake_ip = tun::fake_ip_address(&mut doc);
    general::lower(&mut doc, &mut out, &mut warnings)?;
    let proxies = proxy::lower(&mut doc, &mut out, &mut warnings)?;
    let providers = proxy_provider::lower(&mut doc, &mut out, &mut warnings)?;
    let groups = group::lower(&mut doc, &proxies, &providers, &mut out, &mut warnings)?;
    let mut sets = provider::lower(&mut doc, &groups, &mut out, &mut warnings)?;
    let hosts = hosts::read(&mut doc, &mut warnings)?;
    dns::lower(&mut doc, &groups, &mut sets, &mut out, &mut warnings)?;
    hosts.apply(&mut out)?;
    let listeners = listeners::lower(&mut doc, &groups, &mut out, &mut warnings)?;
    sets.set_inbounds(listeners.kinds.clone());
    rule::lower(&mut doc, &groups, &mut sets, &mut out, &mut warnings)?;
    listeners.apply(&mut out);
    sniffer::lower(&mut doc, &mut sets, &mut out, &mut warnings)?;
    tun::lower(&mut doc, fake_ip, &mut sets, &mut out, &mut warnings)?;
    // Before every other rule, sniffing among them.
    if let Some(rule) = listeners::lan_rule(&out) {
        out.rules.insert(0, rule);
    }
    out.rule_sets.extend(sets.into_geo_sets());
    doc.finish(general::TOP, |key| holders.contains(key), &mut warnings)?;

    let value = out.into_json();
    let mut config: Config = serde_path_to_error::deserialize(value).map_err(|e| {
        anyhow!(
            "{}: {} (as sail reads it)",
            super::model::path(&e),
            e.inner()
        )
    })?;
    config.validate()?;
    config.warnings = warnings;
    Ok(config)
}

/// A line of a classical rule-provider, a Clash rule without its target,
/// as a rule-set's rule.
#[cfg(feature = "rule-set")]
pub(crate) fn headless(line: &str) -> Result<super::rule_set::HeadlessRule> {
    let rule = rule::headless(line)?;
    serde_json::from_value(Value::Object(rule)).map_err(|e| anyhow!("{}", e))
}

/// The `payload`, or `rules`, of a YAML rule-provider.
#[cfg(feature = "rule-set")]
pub(crate) fn payload(s: &str) -> Result<Vec<String>> {
    let mut doc = Fields::of(node::parse(s)?, "")?;
    let payload = doc.strings("payload")?;
    if !payload.is_empty() {
        return Ok(payload);
    }
    doc.strings("rules")
}

/// The configuration being built, in sing-box's shape.
#[derive(Default)]
pub struct Lowered {
    pub log: Map<String, Value>,
    pub dns: Map<String, Value>,
    pub inbounds: Vec<Value>,
    pub outbounds: Vec<Value>,
    pub endpoints: Vec<Value>,
    pub outbound_providers: Vec<Value>,
    pub rules: Vec<Value>,
    pub rule_sets: Vec<Value>,
    pub route: Map<String, Value>,
    /// Mihomo's `mode`, which the Clash API may change.
    pub mode: Option<String>,
    /// What is kept across restarts, as `profile` says.
    pub cache_file: Option<Map<String, Value>>,
    /// The users of `authentication`, which listeners take too.
    pub authentication: Vec<Value>,
    /// The inbounds that authenticate as `authentication` says, which
    /// `lan-allowed-ips` and `lan-disallowed-ips` keep to.
    pub lan_inbounds: Vec<String>,
    /// `lan-allowed-ips`, unless it allows everyone.
    pub lan_allowed: Option<Vec<String>>,
    pub lan_disallowed: Vec<String>,
}

impl Lowered {
    pub(in crate::config) fn into_json(self) -> Value {
        let mut route = self.route;
        route.insert("rules".into(), Value::Array(self.rules));
        if !self.rule_sets.is_empty() {
            route.insert("rule_set".into(), Value::Array(self.rule_sets));
        }
        let mut config = json!({
            "log": self.log,
            "dns": self.dns,
            "inbounds": self.inbounds,
            "outbounds": self.outbounds,
            "route": route,
        });
        if !self.endpoints.is_empty() {
            config["endpoints"] = Value::Array(self.endpoints);
        }
        if !self.outbound_providers.is_empty() {
            config["outbound_providers"] = Value::Array(self.outbound_providers);
        }
        let mut experimental = Map::new();
        if let Some(mode) = self.mode {
            experimental.insert("clash_api".into(), json!({ "default_mode": mode }));
        }
        if let Some(cache) = self.cache_file {
            experimental.insert("cache_file".into(), Value::Object(cache));
        }
        if !experimental.is_empty() {
            config["experimental"] = Value::Object(experimental);
        }
        config
    }
}

#[cfg(test)]
mod tests;
