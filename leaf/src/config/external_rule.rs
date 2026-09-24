//! Rule conditions that live in data files: GeoIP databases (`.mmdb`) and
//! site lists (`site.dat`).

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::{anyhow, Result};

use super::geosite;

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

/// A country in a GeoIP database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mmdb {
    pub file: String,
    pub country_code: String,
}

/// What an external rule adds to a rule.
pub enum External {
    Mmdb(Mmdb),
    Domains(Vec<(DomainKind, String)>),
}

fn asset(file: &str) -> String {
    if Path::new(file).is_absolute() {
        return file.to_string();
    }
    Path::new(&*crate::option::ASSET_LOCATION)
        .join(file)
        .to_string_lossy()
        .to_string()
}

/// `code` in the default GeoIP database.
pub fn geoip(code: &str) -> Mmdb {
    Mmdb {
        file: asset("geo.mmdb"),
        country_code: code.to_string(),
    }
}

/// The site group `code` in the default site list.
pub fn geosite(code: &str) -> Result<Vec<(DomainKind, String)>> {
    load_site_group(&asset("site.dat"), code)
}

/// `mmdb:<code>`, `mmdb:<file>:<code>`, `site:<code>` or `site:<file>:<code>`.
/// A relative file is looked up in the asset directory.
pub fn load(filter: &str) -> Result<External> {
    let parts: Vec<&str> = filter.split(':').collect();
    let (kind, file, code) = match parts.as_slice() {
        [kind, code] => (*kind, None, *code),
        [kind, file, code] => (*kind, Some(*file), *code),
        _ => return Err(anyhow!("invalid external rule \"{}\"", filter)),
    };
    match kind {
        "mmdb" => Ok(External::Mmdb(Mmdb {
            file: asset(file.unwrap_or("geo.mmdb")),
            country_code: code.to_string(),
        })),
        "site" => Ok(External::Domains(load_site_group(
            &asset(file.unwrap_or("site.dat")),
            code,
        )?)),
        _ => Err(anyhow!(
            "invalid external rule \"{}\": expected mmdb:... or site:...",
            filter
        )),
    }
}

/// The domains of the site group `code` in `file`.
fn load_site_group(file: &str, code: &str) -> Result<Vec<(DomainKind, String)>> {
    // Loads SiteGroup objects one by one instead of loading the whole list.
    let mut reader = BufReader::with_capacity(
        2048,
        File::open(file).map_err(|e| anyhow!("open site list {} failed: {}", file, e))?,
    );
    let mut input = protobuf::CodedInputStream::new(&mut reader);
    while !input.eof()? {
        let _ = input.read_raw_byte()?; // skip
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
