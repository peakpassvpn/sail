//! sing-box's binary rule-set format, `.srs`: `SRS`, a version byte, then
//! zlib-compressed rules, each a list of typed items. Versions up to 5,
//! sing-box 1.14's, are read.

use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};

use super::reader::Reader;
use super::rule::Parts;
use super::succinct::Succinct;
use super::SuccinctSet;
use crate::app::router::matcher::Condition;
use crate::config::rule_set::MAX_VERSION;

const MAGIC: &[u8; 3] = b"SRS";
/// The most a rule-set may inflate to: well past the largest published
/// ones, short of what a malicious file could make a device run out of.
const MAX_INFLATED: usize = 256 << 20;
const MAX_DEPTH: usize = 100;

// Item types, in the order sing-box numbers them.
const QUERY_TYPE: u8 = 0;
const NETWORK: u8 = 1;
const DOMAIN: u8 = 2;
const DOMAIN_KEYWORD: u8 = 3;
const DOMAIN_REGEX: u8 = 4;
const SOURCE_IP_CIDR: u8 = 5;
const IP_CIDR: u8 = 6;
const SOURCE_PORT: u8 = 7;
const SOURCE_PORT_RANGE: u8 = 8;
const PORT: u8 = 9;
const PORT_RANGE: u8 = 10;
const PROCESS_NAME: u8 = 11;
const PROCESS_PATH: u8 = 12;
const PACKAGE_NAME: u8 = 13;
const PROCESS_PATH_REGEX: u8 = 17;
const PACKAGE_NAME_REGEX: u8 = 23;
const FINAL: u8 = 0xff;

/// The names of the item types sail does not match yet, by type.
fn unsupported(item: u8) -> Option<&'static str> {
    Some(match item {
        14 => "wifi_ssid",
        15 => "wifi_bssid",
        16 => "adguard_domain",
        18 => "network_type",
        19 => "network_is_expensive",
        20 => "network_is_constrained",
        21 => "network_interface_address",
        22 => "default_interface_address",
        _ => return None,
    })
}

pub(crate) fn read(data: &[u8]) -> Result<Vec<Condition>> {
    let rest = data
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| anyhow!("not a sing-box binary rule-set"))?;
    let (&version, compressed) = rest.split_first().ok_or_else(|| anyhow!("no version"))?;
    if version > MAX_VERSION {
        return Err(anyhow!(
            "version {}: newer than sail reads, {}",
            version,
            MAX_VERSION
        ));
    }
    let inflated =
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(compressed, MAX_INFLATED).map_err(
            |e| match e.status {
                miniz_oxide::inflate::TINFLStatus::HasMoreOutput => {
                    anyhow!("inflates to more than {} bytes", MAX_INFLATED)
                }
                status => anyhow!("inflate: {:?}", status),
            },
        )?;
    let mut reader = Reader::new(&inflated);
    let count = reader.count(1)?;
    (0..count)
        .map(|i| read_rule(&mut reader, &format!("rules[{}]", i), 0))
        .collect()
}

fn read_rule(reader: &mut Reader, path: &str, depth: usize) -> Result<Condition> {
    if depth > MAX_DEPTH {
        return Err(anyhow!("{}: logical rules nested too deep", path));
    }
    match reader.u8().with_context(|| path.to_string())? {
        0 => super::rule::default(read_plain(reader).with_context(|| path.to_string())?, path),
        1 => {
            let all = match reader.u8()? {
                0 => true,
                1 => false,
                mode => return Err(anyhow!("{}: unknown logical mode {}", path, mode)),
            };
            let count = reader.count(1)?;
            let rules = (0..count)
                .map(|i| read_rule(reader, &format!("{}.rules[{}]", path, i), depth + 1))
                .collect::<Result<_>>()?;
            let invert = reader.bool()?;
            Ok(Condition::Logical { all, rules, invert })
        }
        kind => Err(anyhow!("{}: unknown rule type {}", path, kind)),
    }
}

fn read_plain(reader: &mut Reader) -> Result<Parts> {
    let mut parts = Parts::default();
    loop {
        let item = reader.u8()?;
        let rule = &mut parts.rule;
        match item {
            QUERY_TYPE => parts.query_types = reader.u16_slice()?,
            NETWORK => rule.network = reader.strings()?,
            DOMAIN => parts.succinct = Some(SuccinctSet::Sing(Succinct::read(reader)?)),
            DOMAIN_KEYWORD => rule.domain_keyword = reader.strings()?,
            DOMAIN_REGEX => rule.domain_regex = reader.strings()?,
            SOURCE_IP_CIDR => parts.source_ip_ranges = Some(read_ip_set(reader)?),
            IP_CIDR => parts.ip_ranges = Some(read_ip_set(reader)?),
            SOURCE_PORT => rule.source_port = reader.u16_slice()?,
            SOURCE_PORT_RANGE => rule.source_port_range = reader.strings()?,
            PORT => rule.port = reader.u16_slice()?,
            PORT_RANGE => rule.port_range = reader.strings()?,
            PROCESS_NAME => rule.process_name = reader.strings()?,
            PROCESS_PATH => rule.process_path = reader.strings()?,
            PACKAGE_NAME => rule.package_name = reader.strings()?,
            PROCESS_PATH_REGEX => rule.process_path_regex = reader.strings()?,
            PACKAGE_NAME_REGEX => rule.package_name_regex = reader.strings()?,
            FINAL => {
                rule.invert = reader.bool()?;
                return Ok(parts);
            }
            other => {
                return Err(match unsupported(other) {
                    Some(field) => anyhow!("{}: sail does not match it yet", field),
                    None => anyhow!("unknown item type {}", other),
                })
            }
        }
    }
}

/// An address set as sing-box writes one: version 1, a big-endian u64
/// count, then each range's first and last address.
fn read_ip_set(reader: &mut Reader) -> Result<Vec<(IpAddr, IpAddr)>> {
    let version = reader.u8()?;
    if version != 1 {
        return Err(anyhow!("unknown address set version {}", version));
    }
    let count = reader.u64_be()?;
    let mut ranges = Vec::new();
    for _ in 0..count {
        ranges.push((reader.addr()?, reader.addr()?));
    }
    Ok(ranges)
}
