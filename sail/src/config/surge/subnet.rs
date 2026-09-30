//! Subnet expressions: the network the host is on, as `SUBNET` rules and
//! `subnet` groups match it: `SSID:`, `BSSID:` (with `*` and `?`),
//! `ROUTER:`, `TYPE:` and `MCCMNC:`, and a bare value, as sail's network
//! conditions.

use std::net::IpAddr;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::rule::glob;

/// The conditions of `expression`. A bare value, which Surge compares with
/// the SSID, the BSSID and the router's address alike, is the one of them
/// it can be: an address, a MAC address, else an SSID.
pub(super) fn conditions(expression: &str) -> Result<Map<String, Value>> {
    let expression = expression.trim();
    let mut c = Map::new();
    let (prefix, value) = match expression.split_once(':') {
        Some((prefix, value))
            if ["SSID", "BSSID", "ROUTER", "TYPE", "MCCMNC"]
                .iter()
                .any(|p| p.eq_ignore_ascii_case(prefix)) =>
        {
            (prefix.to_ascii_uppercase(), value.trim())
        }
        _ => (String::new(), expression),
    };
    if value.is_empty() {
        return Err(anyhow!("{:?}: no value", expression));
    }
    let wild = value.contains(['*', '?']);
    match prefix.as_str() {
        "SSID" => ssid(value, &mut c),
        "BSSID" => bssid(value, &mut c)?,
        "ROUTER" => {
            let ip: IpAddr = value
                .parse()
                .map_err(|_| anyhow!("{:?}: {:?} is no IP address", expression, value))?;
            c.insert("network_gateway".into(), json!([ip.to_string()]));
        }
        "TYPE" => {
            let kind = match value.to_ascii_uppercase().as_str() {
                "WIFI" => "wifi",
                "WIRED" => "ethernet",
                "CELLULAR" => "cellular",
                _ => {
                    return Err(anyhow!(
                        "{:?}: {:?} is none of WIFI, WIRED and CELLULAR",
                        expression,
                        value
                    ))
                }
            };
            c.insert("network_type".into(), json!([kind]));
        }
        "MCCMNC" => mcc_mnc(value, &mut c)?,
        _ if wild => ssid(value, &mut c),
        _ => {
            if let Ok(ip) = value.parse::<IpAddr>() {
                c.insert("network_gateway".into(), json!([ip.to_string()]));
            } else if let Some(bssid) = crate::net::network::normalize_bssid(value) {
                c.insert("wifi_bssid".into(), json!([bssid]));
            } else {
                ssid(value, &mut c);
            }
        }
    }
    Ok(c)
}

/// The cellular carrier, `MCCMNC:` and `CELLULAR-CARRIER`: matched only off
/// Wi-Fi.
pub(super) fn mcc_mnc(value: &str, c: &mut Map<String, Value>) -> Result<()> {
    if !(5..=6).contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!("{:?} is not an MCC and MNC, 5 or 6 digits", value));
    }
    c.insert("network_mcc_mnc".into(), json!([value]));
    Ok(())
}

/// With case; `*` and `?` as a pattern.
fn ssid(value: &str, c: &mut Map<String, Value>) {
    match value.contains(['*', '?']) {
        true => c.insert("wifi_ssid_regex".into(), json!([glob(value)])),
        false => c.insert("wifi_ssid".into(), json!([value])),
    };
}

/// Without case; `*` and `?` as a pattern on the `aa:bb:…` form.
fn bssid(value: &str, c: &mut Map<String, Value>) -> Result<()> {
    if value.contains(['*', '?']) {
        c.insert(
            "wifi_bssid_regex".into(),
            json!([glob(&value.to_ascii_lowercase().replace('-', ":"))]),
        );
        return Ok(());
    }
    let bssid = crate::net::network::normalize_bssid(value)
        .ok_or_else(|| anyhow!("BSSID:{}: {:?} is no MAC address", value, value))?;
    c.insert("wifi_bssid".into(), json!([bssid]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expressions_are_network_conditions() {
        for (expression, expected) in [
            ("SSID:Home", json!({ "wifi_ssid": ["Home"] })),
            (
                "ssid:Office-*",
                json!({ "wifi_ssid_regex": ["^Office\\-.*$"] }),
            ),
            (
                "BSSID:AA:BB:CC:DD:EE:FF",
                json!({ "wifi_bssid": ["aa:bb:cc:dd:ee:ff"] }),
            ),
            (
                "BSSID:aa:BB:*",
                json!({ "wifi_bssid_regex": ["^aa:bb:.*$"] }),
            ),
            (
                "ROUTER:192.168.1.1",
                json!({ "network_gateway": ["192.168.1.1"] }),
            ),
            ("TYPE:wired", json!({ "network_type": ["ethernet"] })),
            ("TYPE:CELLULAR", json!({ "network_type": ["cellular"] })),
            ("MCCMNC:46001", json!({ "network_mcc_mnc": ["46001"] })),
            // Bare, the one of the three the value can be.
            ("Voyager", json!({ "wifi_ssid": ["Voyager"] })),
            ("617", json!({ "wifi_ssid": ["617"] })),
            ("10.0.0.1", json!({ "network_gateway": ["10.0.0.1"] })),
            (
                "58:c6:7e:df:2d:51",
                json!({ "wifi_bssid": ["58:c6:7e:df:2d:51"] }),
            ),
            ("Cafe?", json!({ "wifi_ssid_regex": ["^Cafe.$"] })),
        ] {
            assert_eq!(
                Value::Object(conditions(expression).unwrap()),
                expected,
                "{}",
                expression
            );
        }
        for (bad, message) in [
            ("ROUTER:router", "no IP address"),
            ("TYPE:ETHERNET", "none of WIFI"),
            ("MCCMNC:4600", "5 or 6 digits"),
            ("BSSID:aa:bb", "no MAC address"),
            ("SSID:", "no value"),
        ] {
            let err = conditions(bad).unwrap_err().to_string();
            assert!(err.contains(message), "{}: {}", bad, err);
        }
    }
}
