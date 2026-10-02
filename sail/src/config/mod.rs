//! Configuration: the model the runtime is built from, and the formats it is
//! read from. sing-box's JSON is sail's own; Clash / Mihomo YAML and Surge
//! configurations are to be read as they are, too.

use std::path::Path;

use anyhow::{anyhow, Result};

#[cfg(feature = "config-clash")]
pub mod clash;
pub mod external_rule;
pub mod geosite;
pub mod model;
pub mod rule_set;
pub mod share_link;
pub mod singbox;
#[cfg(feature = "config-surge")]
pub mod surge;

pub use model::{Config, Dns, Inbound, Log, Outbound, Route, Rule, UserLimits};

/// A configuration format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    SingBox,
    Clash,
    Surge,
}

impl Format {
    /// The format a file's extension names.
    pub fn of_file(path: &str) -> Result<Self> {
        match Path::new(path).extension().and_then(|e| e.to_str()) {
            Some("json") => Ok(Format::SingBox),
            Some("yaml" | "yml") => Ok(Format::Clash),
            Some("conf") => Ok(Format::Surge),
            _ => Err(anyhow!(
                "config files use extension .json (sing-box), .yaml or .yml (Clash) or \
                 .conf (Surge)"
            )),
        }
    }

    /// The format a configuration is written in: a JSON object is
    /// sing-box's, text with Surge's sections is Surge's, anything else is
    /// taken for Clash's YAML.
    pub fn of_text(s: &str) -> Self {
        // Past any comment before it.
        if singbox::jsonc::strip(s).trim_start().starts_with('{') {
            Format::SingBox
        } else if s
            .lines()
            .any(|l| matches!(l.trim(), "[General]" | "[Proxy]" | "[Rule]"))
        {
            Format::Surge
        } else {
            Format::Clash
        }
    }

    /// Reads a configuration written in this format: a Surge profile
    /// includes the files in `dir` and those `host` fetched. Every reading
    /// of a configuration comes here, a file's or a host's text.
    #[cfg_attr(not(feature = "config-surge"), allow(unused_variables))]
    fn read(self, s: &str, dir: Option<&Path>, host: &crate::runtime::Host) -> Result<Config> {
        match self {
            Format::SingBox => singbox::parse(s),
            #[cfg(feature = "config-clash")]
            Format::Clash => clash::parse_in(s, Some(&host.data_dir())),
            #[cfg(not(feature = "config-clash"))]
            Format::Clash => Err(anyhow!(
                "Clash configurations need the config-clash feature, which is not compiled in"
            )),
            #[cfg(feature = "config-surge")]
            Format::Surge => {
                let fetched = host.cache_dir.as_deref().map(surge::includes_dir);
                surge::parse_with(s, dir, fetched.as_deref(), Some(&host.data_dir()))
            }
            #[cfg(not(feature = "config-surge"))]
            Format::Surge => Err(anyhow!(
                "Surge configurations need the config-surge feature, which is not compiled in"
            )),
        }
    }
}

/// Reads a configuration, in the format its content shows.
pub fn from_string(s: &str) -> Result<Config> {
    from_string_for(s, &crate::runtime::Host::default())
}

/// Reads a configuration, as `from_string`, for `host`: as a file of it
/// would read, a Surge profile including the URLs the host fetched.
pub fn from_string_for(s: &str, host: &crate::runtime::Host) -> Result<Config> {
    Format::of_text(s).read(s, None, host)
}

/// Reads a configuration file, in the format its extension names. A Surge
/// profile includes files next to it.
pub fn from_file(path: &str) -> Result<Config> {
    from_file_for(path, &crate::runtime::Host::default())
}

/// Reads a configuration file, as `from_file`, for `host`: a Surge
/// profile includes the URLs the host fetched into its cache directory.
pub fn from_file_for(path: &str, host: &crate::runtime::Host) -> Result<Config> {
    let format = Format::of_file(path)?;
    let text = std::fs::read_to_string(path)?;
    format.read(&text, Path::new(path).parent(), host)
}

/// A certificate's SHA-256 hash as a front-end writes it (colons, spaces,
/// either case), as `certificate_sha256` has it: lowercase hex alone.
#[cfg(any(feature = "config-clash", feature = "config-surge"))]
pub(crate) fn certificate_hash(hash: &str) -> String {
    hash.chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_error_is_not_retried_as_another_format() {
        let err = from_string(r#"{ "outbounds": [ { "tag": "x" } ] }"#).unwrap_err();
        assert!(err.to_string().contains("outbounds[0]"), "{}", err);
    }

    /// A host's text reads as its file would: a Surge profile includes
    /// the URLs the host fetched.
    #[cfg(feature = "config-surge")]
    #[test]
    fn a_host_s_text_includes_what_it_fetched() {
        let cache = std::env::temp_dir().join(format!("sail-config-text-{}", std::process::id()));
        let dir = surge::includes_dir(&cache);
        std::fs::create_dir_all(&dir).unwrap();
        let url = "https://example.com/proxies.conf";
        std::fs::write(surge::include_path(&dir, url), "[Proxy]\nA = direct\n").unwrap();
        let text = format!("[Proxy]\n#!include {}\n[Rule]\nFINAL,A\n", url);
        let host = crate::runtime::Host {
            cache_dir: Some(cache.clone()),
            ..Default::default()
        };
        let read = from_string_for(&text, &host);
        let _ = std::fs::remove_dir_all(&cache);
        let config = read.unwrap();
        assert!(
            config.outbounds.iter().any(|o| o.tag == "A"),
            "{:?}",
            config.outbounds
        );
        // Without the host, nothing was fetched.
        assert!(from_string(&text).is_err());
    }

    #[test]
    fn formats_are_told_apart() {
        assert_eq!(Format::of_text("  {}"), Format::SingBox);
        assert_eq!(
            Format::of_text("// sing-box\n/* too */ {}"),
            Format::SingBox
        );
        assert_eq!(
            Format::of_text("# a comment\n[General]\nloglevel = info\n"),
            Format::Surge
        );
        assert_eq!(
            Format::of_text("mixed-port: 7890\nproxies: []\n"),
            Format::Clash
        );
        assert_eq!(Format::of_file("a/b.yml").unwrap(), Format::Clash);
        assert_eq!(Format::of_file("b.conf").unwrap(), Format::Surge);
        assert!(Format::of_file("b.toml").is_err());
    }
}
