//! Configuration: the model the runtime is built from, and the formats it is
//! read from. sing-box's JSON is sail's own; Clash / Mihomo YAML and Surge
//! configurations are to be read as they are, too.

use std::path::Path;

use anyhow::{anyhow, Result};

pub mod external_rule;
pub mod geosite;
pub mod model;
pub mod rule_set;
pub mod singbox;

pub use model::{Config, Dns, Inbound, Log, Outbound, Route, Rule};

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

    /// Reads a configuration written in this format.
    pub fn parse(self, s: &str) -> Result<Config> {
        match self {
            Format::SingBox => singbox::parse(s),
            Format::Clash => Err(anyhow!("sail does not read Clash configurations yet")),
            Format::Surge => Err(anyhow!("sail does not read Surge configurations yet")),
        }
    }
}

/// Reads a configuration, in the format its content shows.
pub fn from_string(s: &str) -> Result<Config> {
    Format::of_text(s).parse(s)
}

/// Reads a configuration file, in the format its extension names.
pub fn from_file(path: &str) -> Result<Config> {
    let format = Format::of_file(path)?;
    format.parse(&std::fs::read_to_string(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_error_is_not_retried_as_another_format() {
        let err = from_string(r#"{ "outbounds": [ { "tag": "x" } ] }"#).unwrap_err();
        assert!(err.to_string().contains("outbounds[0]"), "{}", err);
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
