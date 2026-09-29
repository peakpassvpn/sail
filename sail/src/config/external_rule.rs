//! Rule conditions that live in data files: GeoIP databases (`.mmdb`) and
//! site lists (`site.dat`).

use std::fs::File;
use std::io::BufReader;

use anyhow::{anyhow, Result};

use super::geosite;
use crate::assets::Kind as AssetKind;
use crate::runtime::RuntimeEnv;

/// How a domain condition compares against a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainKind {
    /// The domain contains the value.
    Keyword,
    /// The domain is the value or a subdomain of it.
    Suffix,
    /// The domain is exactly the value.
    Full,
}

/// The GeoIP database `geoip` and `mmdb:<code>` read, in the data
/// directory.
pub const GEOIP_FILE: &str = "geo.mmdb";
/// The site lists `geosite` and `site:<code>` read, in the data directory.
pub const GEOSITE_FILE: &str = "site.dat";

/// A country in a GeoIP database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mmdb {
    /// As given: a relative one is in the data directory.
    pub file: String,
    pub country_code: String,
}

/// What an external rule adds to a rule.
pub enum External {
    Mmdb(Mmdb),
    Domains(Vec<(DomainKind, String)>),
}

/// `code` in the default GeoIP database.
pub fn geoip(code: &str) -> Mmdb {
    Mmdb {
        file: GEOIP_FILE.to_string(),
        country_code: code.to_string(),
    }
}

/// The site group `code` in the default site list.
pub fn geosite(code: &str, env: &RuntimeEnv) -> Result<Vec<(DomainKind, String)>> {
    load_site_group(&env.data_path(GEOSITE_FILE), code)
}

/// `mmdb:<code>`, `mmdb:<file>:<code>`, `site:<code>` or `site:<file>:<code>`:
/// what it reads (a relative file is in the data directory), the file,
/// and the code.
pub fn parse(filter: &str) -> Result<(AssetKind, &str, &str)> {
    let parts: Vec<&str> = filter.split(':').collect();
    let (kind, file, code) = match parts.as_slice() {
        [kind, code] => (*kind, None, *code),
        [kind, file, code] => (*kind, Some(*file), *code),
        _ => return Err(anyhow!("invalid external rule \"{}\"", filter)),
    };
    match kind {
        "mmdb" => Ok((AssetKind::Mmdb, file.unwrap_or(GEOIP_FILE), code)),
        "site" => Ok((AssetKind::Site, file.unwrap_or(GEOSITE_FILE), code)),
        _ => Err(anyhow!(
            "invalid external rule \"{}\": expected mmdb:... or site:...",
            filter
        )),
    }
}

/// What the external rule `filter` adds.
pub fn load(filter: &str, env: &RuntimeEnv) -> Result<External> {
    match parse(filter)? {
        (AssetKind::Mmdb, file, code) => Ok(External::Mmdb(Mmdb {
            file: file.to_string(),
            country_code: code.to_string(),
        })),
        (AssetKind::Site, file, code) => Ok(External::Domains(load_site_group(
            &env.data_path(file),
            code,
        )?)),
    }
}

/// The tag that starts each site group of a list: field 1, length
/// delimited.
const SITE_GROUP_TAG: u8 = 0x0a;

/// The domains of the site group `code` in `file`.
fn load_site_group(file: &str, code: &str) -> Result<Vec<(DomainKind, String)>> {
    // Loads SiteGroup objects one by one instead of loading the whole list.
    let mut reader = BufReader::with_capacity(
        2048,
        File::open(file).map_err(|e| crate::assets::open_error("site list", file, e))?,
    );
    let mut input = protobuf::CodedInputStream::new(&mut reader);
    while !input.eof()? {
        let _ = input.read_raw_byte()?; // SITE_GROUP_TAG
        let mut site_group = input.read_message::<geosite::SiteGroup>()?;
        if site_group.tag != code.to_uppercase() {
            continue;
        }
        let mut domains = Vec::with_capacity(site_group.domain.len());
        for domain in site_group.domain.iter_mut() {
            let kind = match domain.type_.enum_value() {
                Ok(geosite::domain::Type::Plain) => DomainKind::Keyword,
                Ok(geosite::domain::Type::Domain) => DomainKind::Suffix,
                Ok(geosite::domain::Type::Full) => DomainKind::Full,
                // Regular expressions are not supported.
                _ => continue,
            };
            domains.push((kind, std::mem::take(&mut domain.value)));
        }
        tracing::debug!(
            "loaded {} domain rules from [{}] for tag [{}]",
            domains.len(),
            file,
            code
        );
        return Ok(domains);
    }
    Err(anyhow!("no site group [{}] in {}", code, file))
}

/// How many site groups `data`, a whole site list, holds; an error if it
/// is not one, or holds none.
pub(crate) fn count_site_groups(data: &[u8]) -> Result<usize> {
    let mut input = protobuf::CodedInputStream::from_bytes(data);
    let mut groups = 0;
    while !input.eof()? {
        if input.read_raw_byte()? != SITE_GROUP_TAG {
            return Err(anyhow!("not a site list"));
        }
        input.read_message::<geosite::SiteGroup>()?;
        groups += 1;
    }
    match groups {
        0 => Err(anyhow!("no site group")),
        n => Ok(n),
    }
}
