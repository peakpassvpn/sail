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
mod node;
mod provider;
mod proxy;
mod proxy_provider;
mod rule;
mod sniffer;
/// What outbound providers read.
#[cfg(feature = "outbound-provider")]
pub(crate) mod subscription;

use fields::Fields;

/// Reads a Clash / Mihomo configuration.
pub fn parse(s: &str) -> Result<Config> {
    let root = node::parse(s)?;
    let holders = node::anchor_holders(s);
    let mut doc = Fields::of(root, "")?;
    let mut warnings = Vec::new();
    let mut out = Lowered::default();
    general::lower(&mut doc, &mut out, &mut warnings)?;
    let proxies = proxy::lower(&mut doc, &mut out, &mut warnings)?;
    let providers = proxy_provider::lower(&mut doc, &mut out, &mut warnings)?;
    let groups = group::lower(&mut doc, &proxies, &providers, &mut out, &mut warnings)?;
    let mut sets = provider::lower(&mut doc, &groups, &mut out, &mut warnings)?;
    dns::lower(&mut doc, &groups, &mut sets, &mut out, &mut warnings)?;
    rule::lower(&mut doc, &groups, &mut sets, &mut out, &mut warnings)?;
    sniffer::lower(&mut doc, &mut sets, &mut out, &mut warnings)?;
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
    pub outbound_providers: Vec<Value>,
    pub rules: Vec<Value>,
    pub rule_sets: Vec<Value>,
    pub route: Map<String, Value>,
    /// Mihomo's `mode`, which the Clash API may change.
    pub mode: Option<String>,
}

impl Lowered {
    fn into_json(self) -> Value {
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
        if !self.outbound_providers.is_empty() {
            config["outbound_providers"] = Value::Array(self.outbound_providers);
        }
        if let Some(mode) = self.mode {
            config["experimental"] = json!({ "clash_api": { "default_mode": mode } });
        }
        config
    }
}

#[cfg(test)]
mod tests;
