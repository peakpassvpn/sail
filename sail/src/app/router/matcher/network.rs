//! Conditions on the network the host is on (`wifi_ssid`, `network_type`,
//! …), compiled once and matched against the state of the network at the
//! time. Routing rules, rule-sets, DNS rules and the `network` group all
//! compile them here, so that they match alike everywhere.

use std::net::IpAddr;

use anyhow::{anyhow, Result};

use super::{at, Pattern};
use crate::config::model;
use crate::net::network::{normalize_bssid, NetworkState, NetworkType};

/// The conditions of a rule on the network. As in sing-box, each is an
/// item of its own that must match, and one listing several values matches
/// when any of them does. A condition on something not known of the
/// network (no Wi-Fi name, no gateway) does not match.
#[derive(Default)]
pub(crate) struct NetworkConditions {
    ssid: Vec<String>,
    ssid_regex: Vec<Pattern>,
    /// Written `aa:bb:cc:dd:ee:ff`, as the state has them.
    bssid: Vec<String>,
    bssid_regex: Vec<Pattern>,
    types: Vec<NetworkType>,
    expensive: bool,
    constrained: bool,
    gateways: Vec<IpAddr>,
    mcc_mnc: Vec<String>,
}

impl NetworkConditions {
    /// Compiles the conditions on the network of `rule`, found at `path`;
    /// errors name the field and the value at fault.
    pub(crate) fn compile(rule: &model::Rule, path: &str) -> Result<Self> {
        let field = |f: &str| at(path, f);
        let bssid = rule
            .wifi_bssid
            .iter()
            .map(|b| {
                normalize_bssid(b).ok_or_else(|| {
                    anyhow!(
                        "{}: \"{}\" is no MAC address, aa:bb:cc:dd:ee:ff",
                        field("wifi_bssid"),
                        b
                    )
                })
            })
            .collect::<Result<_>>()?;
        let types = rule
            .network_type
            .iter()
            .map(|t| {
                serde_json::from_value(serde_json::Value::String(t.to_ascii_lowercase())).map_err(
                    |_| {
                        anyhow!(
                            "{}: unknown network type \"{}\", not wifi, cellular, ethernet or other",
                            field("network_type"),
                            t
                        )
                    },
                )
            })
            .collect::<Result<_>>()?;
        let gateways = rule
            .network_gateway
            .iter()
            .map(|g| {
                g.parse::<IpAddr>()
                    .map(|ip| ip.to_canonical())
                    .map_err(|_| {
                        anyhow!("{}: \"{}\" is no IP address", field("network_gateway"), g)
                    })
            })
            .collect::<Result<_>>()?;
        for code in &rule.network_mcc_mnc {
            if !(5..=6).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_digit()) {
                return Err(anyhow!(
                    "{}: \"{}\" is not an MCC and MNC, 5 or 6 digits",
                    field("network_mcc_mnc"),
                    code
                ));
            }
        }
        Ok(NetworkConditions {
            ssid: rule.wifi_ssid.to_vec(),
            ssid_regex: super::patterns(&field("wifi_ssid_regex"), &rule.wifi_ssid_regex)?,
            bssid,
            bssid_regex: caseless(&field("wifi_bssid_regex"), &rule.wifi_bssid_regex)?,
            types,
            expensive: rule.network_is_expensive,
            constrained: rule.network_is_constrained,
            gateways,
            mcc_mnc: rule.network_mcc_mnc.to_vec(),
        })
    }

    /// Whether there are none.
    pub(crate) fn is_empty(&self) -> bool {
        self.ssid.is_empty()
            && self.ssid_regex.is_empty()
            && self.bssid.is_empty()
            && self.bssid_regex.is_empty()
            && self.types.is_empty()
            && !self.expensive
            && !self.constrained
            && self.gateways.is_empty()
            && self.mcc_mnc.is_empty()
    }

    /// Whether matching them needs the state of the network: whether there
    /// are any.
    pub(crate) fn needs(&self) -> bool {
        !self.is_empty()
    }

    /// Whether the network `state` tells of matches them; with none told,
    /// only no conditions match.
    pub(crate) fn matches(&self, state: Option<&NetworkState>) -> bool {
        if self.is_empty() {
            return true;
        }
        let Some(state) = state else {
            return false;
        };
        let ssid = state.ssid.as_deref();
        let bssid = state.bssid.as_deref();
        (self.ssid.is_empty() || ssid.is_some_and(|s| self.ssid.iter().any(|w| w == s)))
            && (self.ssid_regex.is_empty()
                || ssid.is_some_and(|s| self.ssid_regex.iter().any(|r| r.is_match(s))))
            && (self.bssid.is_empty() || bssid.is_some_and(|b| self.bssid.iter().any(|w| w == b)))
            && (self.bssid_regex.is_empty()
                || bssid.is_some_and(|b| self.bssid_regex.iter().any(|r| r.is_match(b))))
            && (self.types.is_empty() || state.kind.is_some_and(|k| self.types.contains(&k)))
            && (!self.expensive || state.expensive)
            && (!self.constrained || state.constrained)
            && (self.gateways.is_empty()
                || state
                    .gateway
                    .is_some_and(|g| self.gateways.contains(&g.to_canonical())))
            && (self.mcc_mnc.is_empty()
                || (state.kind != Some(NetworkType::Wifi)
                    && state
                        .mcc_mnc
                        .as_deref()
                        .is_some_and(|c| self.mcc_mnc.iter().any(|w| w == c))))
    }
}

/// Regular expressions matched whatever the case.
fn caseless(field: &str, values: &[String]) -> Result<Vec<Pattern>> {
    #[cfg(feature = "regex")]
    {
        values
            .iter()
            .map(|v| {
                regex::RegexBuilder::new(v)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| anyhow!("{}: \"{}\": {}", field, v, e))
            })
            .collect()
    }
    #[cfg(not(feature = "regex"))]
    super::patterns(field, values)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(rule: serde_json::Value) -> Result<NetworkConditions> {
        let rule: model::Rule = serde_json::from_value(rule).unwrap();
        NetworkConditions::compile(&rule, "rules[0]")
    }

    fn conditions(rule: serde_json::Value) -> NetworkConditions {
        compile(rule).unwrap()
    }

    fn state(json: serde_json::Value) -> NetworkState {
        NetworkState::from_json(&json.to_string()).unwrap()
    }

    fn home() -> NetworkState {
        state(serde_json::json!({
            "interface": "en0", "type": "wifi", "ssid": "Home",
            "bssid": "AA:BB:CC:DD:EE:01", "gateway": "192.168.1.1"
        }))
    }

    fn cellular() -> NetworkState {
        state(serde_json::json!({
            "interface": "pdp_ip0", "type": "cellular", "mcc_mnc": "46001",
            "expensive": true, "constrained": true
        }))
    }

    #[test]
    fn no_conditions_match_whatever_is_known() {
        let c = conditions(serde_json::json!({}));
        assert!(!c.needs());
        assert!(c.matches(None));
        assert!(c.matches(Some(&NetworkState::default())));
    }

    #[test]
    fn the_wi_fi_name_matches_whole_and_with_case() {
        let c = conditions(serde_json::json!({ "wifi_ssid": ["Home", "Office"] }));
        assert!(c.needs());
        assert!(c.matches(Some(&home())));
        let mut other = home();
        other.ssid = Some("home".into());
        assert!(!c.matches(Some(&other)));
        other.ssid = Some("Home 5G".into());
        assert!(!c.matches(Some(&other)));
        // Nothing known: no match, and no state at all neither.
        assert!(!c.matches(Some(&NetworkState::default())));
        assert!(!c.matches(None));
    }

    #[test]
    #[cfg(feature = "regex")]
    fn the_wi_fi_name_by_pattern_keeps_case() {
        let c = conditions(serde_json::json!({ "wifi_ssid_regex": "^Ho" }));
        assert!(c.matches(Some(&home())));
        let mut other = home();
        other.ssid = Some("house".into());
        assert!(!c.matches(Some(&other)));
        assert!(!c.matches(Some(&cellular())));
    }

    #[test]
    fn access_points_are_compared_normalized() {
        for written in ["aa:bb:cc:dd:ee:01", "AA-BB-CC-DD-EE-01", "aabbccddee01"] {
            let c = conditions(serde_json::json!({ "wifi_bssid": written }));
            assert!(c.matches(Some(&home())), "{}", written);
        }
        let c = conditions(serde_json::json!({ "wifi_bssid": "aa:bb:cc:dd:ee:02" }));
        assert!(!c.matches(Some(&home())));
        assert!(!c.matches(Some(&cellular())));
    }

    #[test]
    #[cfg(feature = "regex")]
    fn access_points_by_pattern_whatever_the_case() {
        let c = conditions(serde_json::json!({ "wifi_bssid_regex": "^AA:BB:" }));
        assert!(c.matches(Some(&home())));
        assert!(!c.matches(Some(&cellular())));
    }

    #[test]
    fn network_types_expense_and_constraint() {
        let c = conditions(serde_json::json!({ "network_type": ["cellular", "Ethernet"] }));
        assert!(c.matches(Some(&cellular())));
        assert!(!c.matches(Some(&home())));
        assert!(!c.matches(Some(&NetworkState::default())));

        let c = conditions(serde_json::json!({ "network_is_expensive": true }));
        assert!(c.matches(Some(&cellular())));
        assert!(!c.matches(Some(&home())));
        let c = conditions(serde_json::json!({ "network_is_constrained": true }));
        assert!(c.matches(Some(&cellular())));
        assert!(!c.matches(Some(&home())));
    }

    #[test]
    fn the_gateway_matches_by_address() {
        let c = conditions(serde_json::json!({ "network_gateway": ["192.168.1.1", "fe80::1"] }));
        assert!(c.matches(Some(&home())));
        let mut other = home();
        other.gateway = Some("::ffff:192.168.1.1".parse().unwrap());
        assert!(c.matches(Some(&other)));
        other.gateway = Some("192.168.0.1".parse().unwrap());
        assert!(!c.matches(Some(&other)));
        assert!(!c.matches(Some(&cellular())));
    }

    #[test]
    fn the_carrier_matches_only_off_wi_fi() {
        let c = conditions(serde_json::json!({ "network_mcc_mnc": "46001" }));
        assert!(c.matches(Some(&cellular())));
        // On Wi-Fi, though the phone still has its carrier.
        let mut wifi = home();
        wifi.mcc_mnc = Some("46001".into());
        assert!(!c.matches(Some(&wifi)));
        // Of a kind not known, the carrier alone decides.
        let mut unknown = cellular();
        unknown.kind = None;
        assert!(c.matches(Some(&unknown)));
        unknown.mcc_mnc = None;
        assert!(!c.matches(Some(&unknown)));
    }

    #[test]
    fn every_condition_must_match() {
        let c = conditions(serde_json::json!({
            "network_type": "wifi", "wifi_ssid": "Home", "network_gateway": "192.168.1.1"
        }));
        assert!(c.matches(Some(&home())));
        let mut other = home();
        other.gateway = Some("10.0.0.1".parse().unwrap());
        assert!(!c.matches(Some(&other)));
    }

    #[test]
    fn mistakes_name_the_field_and_the_value() {
        for (rule, message) in [
            (
                serde_json::json!({ "wifi_bssid": "aa:bb:cc" }),
                "rules[0].wifi_bssid: \"aa:bb:cc\" is no MAC address",
            ),
            (
                serde_json::json!({ "network_type": "wimax" }),
                "rules[0].network_type: unknown network type \"wimax\"",
            ),
            (
                serde_json::json!({ "network_gateway": "router" }),
                "rules[0].network_gateway: \"router\" is no IP address",
            ),
            (
                serde_json::json!({ "network_mcc_mnc": "4600" }),
                "rules[0].network_mcc_mnc: \"4600\" is not an MCC and MNC",
            ),
            (
                serde_json::json!({ "wifi_ssid_regex": "(" }),
                if cfg!(feature = "regex") {
                    "rules[0].wifi_ssid_regex: \"(\""
                } else {
                    "rules[0].wifi_ssid_regex: not supported"
                },
            ),
        ] {
            let err = compile(rule.clone()).err().unwrap().to_string();
            assert!(err.starts_with(message), "{}: {}", rule, err);
        }
    }
}
