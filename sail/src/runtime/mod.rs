//! What an instance runs with besides its configuration: tuning, and what
//! the host provides.

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod options;
pub mod platform;

pub use options::{Profile, RuntimeOptions};
pub use platform::{Platform, PlatformRef};

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

/// Where the host keeps things, and what it does for the instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    /// Data files (`geo.mmdb`, `site.dat`), certificates given by relative
    /// path, and the cache live here. Defaults to the executable's directory.
    pub data_dir: Option<PathBuf>,
    /// Keeps state across restarts, such as selected outbounds, when set.
    pub cache_dir: Option<PathBuf>,
    /// Sends logs to the platform's system log rather than to standard
    /// output; needs a platform.
    pub log_to_system: bool,
    /// How outbound sockets are kept out of the VPN (Android), when the
    /// platform does not do it.
    pub socket_protect: Option<crate::net::dial::SocketProtect>,
    /// What the embedding host does for the instance.
    pub platform: Option<PlatformRef>,
}

/// Everything an instance runs with that is not its configuration.
#[derive(Debug, Clone, Default)]
pub struct RuntimeEnv {
    pub options: RuntimeOptions,
    pub host: Host,
}

pub type SyncRuntimeEnv = Arc<RuntimeEnv>;

impl RuntimeEnv {
    /// The directory data files are looked up in.
    pub fn data_dir(&self) -> PathBuf {
        self.host.data_dir.clone().unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf))
                .unwrap_or_default()
        })
    }

    /// `path` in the data directory, unless it is absolute.
    pub fn data_path(&self, path: &str) -> String {
        let p = Path::new(path);
        if p.is_absolute() {
            return path.to_string();
        }
        self.data_dir().join(p).to_string_lossy().to_string()
    }

    /// A certificate or key given inline or as a path; a relative path is
    /// looked up in the data directory.
    ///
    /// The two halves of a keypair are configured the same way and have to
    /// be read the same way. They were not: a certificate was recognised
    /// inline and a key never was, so an inline key became a path under the
    /// data directory made of PEM, and what the operator saw was "no private
    /// keys found" about a key that was right there in the configuration.
    pub fn certificate(&self, value: &str) -> String {
        if value.contains("-----BEGIN") {
            return value.to_string();
        }
        self.data_path(value)
    }
}

/// How a host describes the tuning and host options of an instance in one
/// piece, for hosts that pass them as text (FFI):
///
/// ```json
/// { "profile": "mobile", "set": ["relay.buffer_size=32"],
///   "data_dir": "/var/lib/sail", "cache_dir": "/var/cache/sail",
///   "log_to_system": true, "socket_protect": "/data/protect.sock" }
/// ```
#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct StartSettings {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub set: Vec<String>,
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    /// Whether to log to the platform's system log; the host decides when
    /// unset.
    #[serde(default)]
    pub log_to_system: Option<bool>,
    /// A Unix socket path, or an `address:port` to connect to over TCP.
    #[serde(default)]
    pub socket_protect: Option<String>,
}

impl StartSettings {
    pub fn from_json(json: &str) -> Result<Self> {
        let de = &mut serde_json::Deserializer::from_str(json);
        serde_path_to_error::deserialize(de)
            .map_err(|e| anyhow!("start settings: {}: {}", e.path(), e.inner()))
    }

    /// The tuning and host these settings describe.
    pub fn resolve(self) -> Result<(RuntimeOptions, Host)> {
        let profile = match &self.profile {
            Some(p) => p.parse()?,
            None => Profile::default(),
        };
        let mut options = RuntimeOptions::profile(profile);
        options.set_all(self.set.iter().map(String::as_str))?;
        let socket_protect = self.socket_protect.map(|p| match p.parse() {
            Ok(addr) => crate::net::dial::SocketProtect::Tcp(addr),
            Err(_) => crate::net::dial::SocketProtect::Unix(p),
        });
        Ok((
            options,
            Host {
                data_dir: self.data_dir,
                cache_dir: self.cache_dir,
                log_to_system: self.log_to_system.unwrap_or(false),
                socket_protect,
                platform: None,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n";

    fn env() -> RuntimeEnv {
        RuntimeEnv {
            host: Host {
                data_dir: Some(PathBuf::from("/data")),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn an_inline_key_is_not_mistaken_for_a_path() {
        assert_eq!(env().certificate(INLINE_KEY), INLINE_KEY);
    }

    /// What counts as absolute is the platform's business, and the test has
    /// to ask the same question the code does.
    #[test]
    fn an_absolute_path_is_left_alone() {
        let absolute = if cfg!(windows) {
            r"C:\sail\cert.pem"
        } else {
            "/etc/sail/cert.pem"
        };
        assert_eq!(env().certificate(absolute), absolute);
    }

    #[test]
    fn a_relative_path_is_in_the_data_directory() {
        let resolved = env().certificate("cert.pem");
        assert_eq!(
            PathBuf::from(resolved),
            PathBuf::from("/data").join("cert.pem")
        );
    }

    #[test]
    fn start_settings_resolve_to_tuning_and_host() {
        let (options, host) = StartSettings::from_json(
            r#"{ "profile": "router", "set": ["relay.buffer_size=2"],
                 "data_dir": "/d", "socket_protect": "127.0.0.1:9000" }"#,
        )
        .unwrap()
        .resolve()
        .unwrap();
        assert_eq!(options.relay.buffer_size, 2);
        assert_eq!(
            options.relay.buffer_max_size,
            RuntimeOptions::profile(Profile::Router)
                .relay
                .buffer_max_size
        );
        assert_eq!(host.data_dir, Some(PathBuf::from("/d")));
        assert_eq!(
            host.socket_protect,
            Some(crate::net::dial::SocketProtect::Tcp(
                "127.0.0.1:9000".parse().unwrap()
            ))
        );
        let err = StartSettings::from_json(r#"{ "profile": "mobile", "sett": [] }"#).unwrap_err();
        assert!(err.to_string().contains("sett"), "{}", err);
    }
}
