//! Configuration: the model every input format is turned into, and the
//! formats themselves.

use std::path::Path;

use anyhow::{anyhow, Result};

pub mod external_rule;
pub mod geosite;
pub mod model;

#[cfg(feature = "config-conf")]
pub mod conf;

pub use model::{Config, Dns, Inbound, Log, Outbound, Route, Rule};

/// Reads a configuration in any supported format: JSON when it is a JSON
/// object, `.conf` otherwise.
pub fn from_string(s: &str) -> Result<Config> {
    if s.trim_start().starts_with('{') {
        Config::from_json(s)
    } else {
        from_conf_string(s)
    }
}

/// Reads a configuration file, in the format its extension names.
pub fn from_file(path: &str) -> Result<Config> {
    let ext = Path::new(path).extension().and_then(|e| e.to_str());
    match ext {
        Some("json") => Config::from_json(&std::fs::read_to_string(path)?),
        #[cfg(feature = "config-conf")]
        Some("conf") => conf::from_file(path),
        _ => Err(anyhow!(
            "config files use extension .json{}",
            if cfg!(feature = "config-conf") {
                " or .conf"
            } else {
                ""
            }
        )),
    }
}

#[cfg(feature = "config-conf")]
fn from_conf_string(s: &str) -> Result<Config> {
    conf::from_string(s)
}

#[cfg(not(feature = "config-conf"))]
fn from_conf_string(_s: &str) -> Result<Config> {
    Err(anyhow!(
        "not a JSON configuration, and .conf support is not compiled in"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_error_is_not_retried_as_conf() {
        let err = from_string(r#"{ "outbounds": [ { "tag": "x" } ] }"#).unwrap_err();
        assert!(err.to_string().contains("outbounds[0]"), "{}", err);
    }
}
