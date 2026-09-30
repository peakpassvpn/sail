//! What an instance runs with besides its configuration: tuning, and what
//! the host provides.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod cache_file;
pub mod options;
pub mod platform;
pub(crate) mod resource;
#[cfg(feature = "auto-reload")]
pub(crate) mod watch;

pub use options::{Profile, RuntimeOptions};
pub use platform::{Platform, PlatformRef, TunRequest};

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

/// Where the host keeps things, and what it does for the instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    /// Data files (`geo.mmdb`, `site.dat`), certificates given by relative
    /// path, and the cache live here. Defaults to the executable's directory.
    pub data_dir: Option<PathBuf>,
    /// Where the cache file is when the configuration gives it no absolute
    /// path, and remote rule-sets are kept; the data directory's when
    /// unset.
    pub cache_dir: Option<PathBuf>,
    /// Sends logs to the platform's system log rather than to standard
    /// output; needs a platform.
    pub log_to_system: bool,
    /// How outbound sockets are kept out of the VPN (Android), when the
    /// platform does not do it.
    pub socket_protect: Option<crate::net::dial::SocketProtect>,
    /// What the embedding host does for the instance.
    pub platform: Option<PlatformRef>,
    /// The base URL of the operator's own Sub-Store backend (its secret
    /// path, if any, included), which downloads from `sub.store` go to:
    /// see [`Host::download_url`].
    pub sub_store: Option<SubStore>,
    /// Where the Clash API's dashboard is downloaded from, a ZIP, when
    /// `external_ui` is empty and the configuration names no URL: the
    /// core has none of its own.
    pub ui_download_url: Option<String>,
    /// Where each asset (`sail::assets`) is downloaded from, by its name
    /// (`asn.mmdb`), for an update the runtime API is asked for without a
    /// URL. The operations plane's: the core has none.
    pub asset_sources: BTreeMap<String, String>,
    /// Where the instance's log lines go, the host's to read; one keeping
    /// none when unset.
    pub log: Option<crate::app::logger::InstanceLogRef>,
}

/// The base URL of a Sub-Store backend. It may carry a secret path, so it
/// prints as its host alone.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SubStore(pub String);

impl std::fmt::Debug for SubStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rest = self.0.split_once("://").map_or("", |(_, rest)| rest);
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        write!(f, "SubStore({:?}, path hidden)", host)
    }
}

/// Sub-Store's address inside Surge, Loon and Quantumult X, which only
/// those apps answer.
const SUB_STORE: &str = "sub.store";

impl Host {
    /// `url` as it is downloaded (outbound providers, remote rule-sets): one
    /// whose host is `sub.store` from `sub_store`, its path and query
    /// kept; any other as it is. Without `sub_store`, one of `sub.store`
    /// is an error that says what to do. Errors name the host alone, as
    /// `sub_store` may hold a secret.
    pub fn download_url(&self, url: &str) -> Result<String> {
        let Some((scheme, rest)) = url.split_once("://") else {
            return Ok(url.to_string());
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let host = authority.rsplit('@').next().unwrap_or_default();
        // An IPv6 address is not it; else up to the port.
        let host = match host.starts_with('[') {
            true => host,
            false => host.split(':').next().unwrap_or_default(),
        };
        if !host.trim_end_matches('.').eq_ignore_ascii_case(SUB_STORE)
            || !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
        {
            return Ok(url.to_string());
        }
        let base = self
            .sub_store
            .as_ref()
            .map(|s| s.0.as_str())
            .ok_or_else(|| {
                anyhow!(
                    "{}: sub.store is Sub-Store's address inside Surge, Loon and Quantumult X, \
                 which only they answer; set sub_store (sail --sub-store, or the host's start \
                 settings) to the address of a Sub-Store backend of your own, or use the \
                 subscription's own URL",
                    SUB_STORE
                )
            })?;
        let base_host = base
            .split_once("://")
            .filter(|(scheme, rest)| {
                matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
                    && !rest.is_empty()
                    && !rest.starts_with('/')
            })
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
            .ok_or_else(|| anyhow!("sub_store: not an http(s) URL"))?;
        if base.contains(['?', '#']) {
            return Err(anyhow!(
                "sub_store: {}: a base URL has no query or fragment",
                base_host
            ));
        }
        Ok(format!("{}{}", base.trim_end_matches('/'), tail))
    }
}

/// Everything an instance runs with that is not its configuration.
#[derive(Debug, Clone, Default)]
pub struct RuntimeEnv {
    pub options: RuntimeOptions,
    pub host: Host,
    /// The Clash API's mode, which rules can match: what the instance
    /// runs in, not what it is configured with.
    pub clash_mode: crate::app::clash_mode::ClashMode,
    /// The network the host is on, which rules and groups match; kept
    /// across reloads.
    pub network: crate::net::network::Network,
    /// `experimental.cache_file`: what is kept across restarts, when
    /// enabled.
    pub cache_file: cache_file::CacheFileSlot,
    /// The root certificates servers are checked against, as the
    /// configuration's `certificate` chose them.
    #[cfg(feature = "tls")]
    pub tls_roots: crate::transport::tls::roots::TrustRoots,
    /// The mark on the sockets sail listens with (Linux): the TUN's
    /// auto_redirect output mark, which keeps replies to clients out of
    /// its redirection, as it keeps the outbounds' connections out.
    pub listen_mark: Option<u32>,
    /// The users inbounds authenticate, by name; kept across reloads.
    pub users: crate::user::UserRegistry,
    /// The LAN devices, by address, when a rule or DNS server needs them;
    /// kept across reloads.
    pub neighbors: crate::net::neighbor::Neighbors,
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
///   "log_to_system": true, "socket_protect": "/data/protect.sock",
///   "sub_store": "https://sub.example.com/secret",
///   "asset_sources": { "asn.mmdb": "https://example.com/asn.mmdb" } }
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
    /// The base URL of a Sub-Store backend, which `sub.store` stands for.
    #[serde(default)]
    pub sub_store: Option<SubStore>,
    /// Where the Clash API's dashboard is downloaded from by default.
    #[serde(default)]
    pub ui_download_url: Option<String>,
    /// Where each asset is downloaded from, by its name.
    #[serde(default)]
    pub asset_sources: BTreeMap<String, String>,
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
                sub_store: self.sub_store,
                ui_download_url: self.ui_download_url,
                asset_sources: self.asset_sources,
                log: None,
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
                 "data_dir": "/d", "socket_protect": "127.0.0.1:9000",
                 "asset_sources": { "asn.mmdb": "https://example.com/asn.mmdb" } }"#,
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
            host.asset_sources["asn.mmdb"],
            "https://example.com/asn.mmdb"
        );
        assert_eq!(
            host.socket_protect,
            Some(crate::net::dial::SocketProtect::Tcp(
                "127.0.0.1:9000".parse().unwrap()
            ))
        );
        let err = StartSettings::from_json(r#"{ "profile": "mobile", "sett": [] }"#).unwrap_err();
        assert!(err.to_string().contains("sett"), "{}", err);
    }

    #[test]
    fn sub_store_is_the_operator_s_backend() {
        let host = |base: Option<&str>| Host {
            sub_store: base.map(|b| SubStore(b.to_string())),
            ..Default::default()
        };
        let url = "https://sub.store/download/collection/all?target=Surge";
        let secret = host(Some("https://sub.example.com:8443/s3cret/"));
        assert_eq!(
            secret.download_url(url).unwrap(),
            "https://sub.example.com:8443/s3cret/download/collection/all?target=Surge"
        );
        assert_eq!(
            secret.download_url("http://SUB.STORE:80").unwrap(),
            "https://sub.example.com:8443/s3cret"
        );
        // Others as they are.
        for other in [
            "https://sub.store.example.com/a",
            "https://a.example/sub.store",
        ] {
            assert_eq!(secret.download_url(other).unwrap(), other);
        }
        let err = host(None).download_url(url).unwrap_err().to_string();
        assert!(err.contains("set sub_store"), "{}", err);
        let err = host(Some("sub.example.com/s3cret"))
            .download_url(url)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("s3cret"), "{}", err);
        let debug = format!("{:?}", secret);
        assert!(
            debug.contains("sub.example.com") && !debug.contains("s3cret"),
            "{}",
            debug
        );
    }
}
