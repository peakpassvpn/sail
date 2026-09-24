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
    let config = if s.trim_start().starts_with('{') {
        Config::from_json(s)?
    } else {
        from_conf_string(s)?
    };
    apply_env(&config);
    Ok(config)
}

/// Reads a configuration file, in the format its extension names.
pub fn from_file(path: &str) -> Result<Config> {
    let ext = Path::new(path).extension().and_then(|e| e.to_str());
    let config = match ext {
        Some("json") => Config::from_json(&std::fs::read_to_string(path)?)?,
        #[cfg(feature = "config-conf")]
        Some("conf") => conf::from_file(path)?,
        _ => {
            return Err(anyhow!(
                "config files use extension .json{}",
                if cfg!(feature = "config-conf") {
                    " or .conf"
                } else {
                    ""
                }
            ))
        }
    };
    apply_env(&config);
    Ok(config)
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

fn apply_env(config: &Config) {
    for (k, v) in &config.env {
        if !k.trim().is_empty() {
            std::env::set_var(k, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_in_a_configuration_sets_the_process_environment() {
        let key = "LEAF_TEST_ENV_FROM_CONFIG";
        from_string(&format!(r#"{{ "env": {{ "{}": "yes" }} }}"#, key)).unwrap();
        assert_eq!(std::env::var(key).unwrap(), "yes");
    }

    #[test]
    fn a_json_error_is_not_retried_as_conf() {
        let err = from_string(r#"{ "outbounds": [ { "tag": "x" } ] }"#).unwrap_err();
        assert!(err.to_string().contains("outbounds[0]"), "{}", err);
    }
}
