//! Surge 5's profiles, read as Surge reads them (manual.nssurge.com),
//! lowered to sail's model: the same configuration sing-box's JSON reads
//! into.
//!
//! What Surge takes and sail does not implement is sorted out as for the
//! other formats: an error when ignoring it would route or secure traffic
//! otherwise, else a warning; what means something only on Surge's
//! platforms or in its interface is passed over. Surge passes over keys,
//! parameters and sections it does not know; sail warns of them. HTTP
//! processing (MITM, rewrites, scripts but for rule and DNS ones) is
//! warned of once a section.
//!
//! It reads the listeners, the proxies, the groups, with the policies of
//! their `policy-path` as outbound providers, the rules and the rule-sets
//! they name, and DNS with `[Host]`.
//!
//! Where sail does otherwise, the profile cannot say it:
//! - A group tests its members with `proxy-test-url`, not each member's
//!   `test-url`.
//! - `udp-policy-not-supported-behaviour` holds for a rule whose policy is,
//!   or is a group all of whose members are, proxies without UDP; a group
//!   of some with UDP and some without carries UDP through whichever it
//!   picks, as the proxy may or may not relay it.
//! - `FINAL,dns-failed`: a name that does not resolve matches no IP rule,
//!   and the rules after go on; Surge goes to FINAL at once.
//! - A sniffed domain is what domain rules match from the sniff on (see
//!   the rule module), and a rule-set file is taken to hold IP and HTTP
//!   rules until read; the DNS module says what its answers do
//!   otherwise.
//! - `IP-ASN` needs `asn.mmdb` (GeoLite2-ASN's format) in the asset
//!   directory, where Surge has its own.

use std::path::Path;

use anyhow::{anyhow, Result};
use serde_json::Value;

use super::clash::Lowered;
use super::model::Config;

mod dns;
mod general;
mod group;
mod params;
mod proxy;
mod requirement;
mod rule;
mod sections;
mod sets;
mod text;

pub(crate) use proxy::external;
use text::Profile;

/// Reads a Surge profile, which includes no files.
pub fn parse(s: &str) -> Result<Config> {
    parse_in(s, None)
}

/// Reads a Surge profile in the directory `dir`, which the files it
/// includes are named relative to.
pub fn parse_in(s: &str, dir: Option<&Path>) -> Result<Config> {
    let mut warnings = Vec::new();
    let mut profile = Profile::read(s, dir, &mut warnings)?;
    let mut out = Lowered::default();
    let mut general = general::lower(profile.take("General"), &mut out, &mut warnings)?;
    let proxies = proxy::lower(&mut profile, &mut out, &mut warnings)?;
    let policies = group::lower(
        profile.take("Proxy Group"),
        &proxies,
        &general,
        dir,
        &mut out,
        &mut warnings,
    )?;
    let mut sets = sets::Sets::new(dir, profile.take_named("Ruleset"));
    rule::lower(
        profile.take("Rule"),
        &policies,
        &general,
        &mut sets,
        &mut out,
        &mut warnings,
    )?;
    let host = profile.take("Host");
    sections::lower(profile, &policies, &mut out, &mut warnings)?;
    if let Some(dns) = general.dns.take() {
        dns::host(host, dns, &mut sets, &mut out, &mut warnings)?;
    }
    general.apply(&mut out);
    out.rule_sets.extend(sets.into_rule_sets());

    let value: Value = out.into_json();
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

/// A line of a Surge rule-set's file, a rule without its policy, as a
/// rule-set's rule.
#[cfg(feature = "rule-set")]
pub(crate) fn headless(line: &str) -> Result<super::rule_set::HeadlessRule> {
    let rule = rule::headless(line)?;
    serde_json::from_value(Value::Object(rule)).map_err(|e| anyhow!("{}", e))
}

#[cfg(test)]
mod tests;
