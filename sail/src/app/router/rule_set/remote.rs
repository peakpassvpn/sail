//! Rule-sets downloaded, kept in the cache directory, and downloaded again
//! as `update_interval` says. A download that fails, or that holds no valid
//! rule-set, leaves the one in use as it is.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::runtime::resource::HotResource;
use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::{RuleSet, SharedRuleSet};
use crate::app::dispatcher::Dispatcher;
use crate::app::http::{self, file_name, write_atomically};
use crate::config::rule_set::{self as config, RuleSetFormat};
use crate::runtime::RuntimeEnv;

const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after a failed download the next one is tried.
const RETRY: Duration = Duration::from_secs(5 * 60);

pub(crate) struct Remote {
    pub tag: String,
    url: String,
    format: RuleSetFormat,
    behavior: Option<crate::config::rule_set::ClashBehavior>,
    interval: Duration,
    client: http::Client,
    /// Where the downloaded copy is kept; none when there is nowhere to.
    cache: Option<PathBuf>,
    /// Whose data files its rules name.
    env: RuntimeEnv,
    pub set: SharedRuleSet,
    state: Mutex<State>,
}

/// What is known of the copy in use.
#[derive(Default, Serialize, Deserialize)]
struct State {
    /// Whether there is one at all.
    #[serde(skip)]
    loaded: bool,
    etag: Option<String>,
    /// When it was downloaded, or last found unchanged.
    #[serde(default)]
    updated: Option<SystemTime>,
    /// The last download's failure, until one succeeds.
    #[serde(skip)]
    failed: Option<crate::control::Failure>,
}

impl Remote {
    /// The rule-set `tag` of `config`, from its cached copy or its
    /// `initial_path`, or empty until the first download.
    pub(crate) fn load(
        config: &config::RuleSet,
        tag: &str,
        client: http::Client,
        env: &RuntimeEnv,
    ) -> Result<Self> {
        let format = config.format().unwrap_or(RuleSetFormat::Binary);
        let extension = match format {
            RuleSetFormat::Binary => "srs",
            RuleSetFormat::Source => "json",
            RuleSetFormat::Mrs => "mrs",
            RuleSetFormat::ClashYaml => "yaml",
            RuleSetFormat::ClashText => "txt",
            RuleSetFormat::SurgeText => "list",
        };
        // Kept across restarts only where the host keeps things.
        let cache = env.host.cache_dir.as_ref().map(|dir| {
            dir.join("rule-set")
                .join(format!("{}.{}", file_name(tag), extension))
        });
        let mut remote = Remote {
            tag: tag.to_string(),
            url: env
                .host
                .download_url(&config::RuleSet::for_tag(
                    config.url.as_deref().unwrap_or_default(),
                    tag,
                ))
                .map_err(|e| anyhow!("url: {}", e))?,
            format,
            behavior: config.behavior,
            interval: config.update_interval.unwrap_or(DEFAULT_INTERVAL),
            client,
            cache: cache.clone(),
            env: env.clone(),
            set: HotResource::new(RuleSet::new(Vec::new())),
            state: Mutex::new(State::default()),
        };
        // A cached copy that does not read is as good as none.
        if let Some(Ok(data)) = cache.as_ref().map(std::fs::read) {
            let cache = cache.as_ref().expect("read from it");
            match RuleSet::read(&data, format, config.behavior, env) {
                Ok(set) => {
                    let mut state: State = std::fs::read(meta_path(cache))
                        .ok()
                        .and_then(|m| serde_json::from_slice(&m).ok())
                        .unwrap_or_default();
                    state.loaded = true;
                    remote.set.publish(Arc::new(set));
                    *remote.state.get_mut().unwrap_or_else(|e| e.into_inner()) = state;
                    debug!("rule-set [{}]: from {}", tag, cache.display());
                    return Ok(remote);
                }
                Err(e) => warn!("rule-set [{}]: cached {}: {}", tag, cache.display(), e),
            }
        }
        if let Some(initial) = &config.initial_path {
            let path = env.data_path(&config::RuleSet::for_tag(initial, tag));
            let data =
                std::fs::read(&path).map_err(|e| anyhow!("initial_path: {}: {}", path, e))?;
            let set = RuleSet::read(&data, format, config.behavior, env)
                .map_err(|e| anyhow!("initial_path: {}: {}", path, e))?;
            remote.set.publish(Arc::new(set));
            remote
                .state
                .get_mut()
                .unwrap_or_else(|e| e.into_inner())
                .loaded = true;
        }
        Ok(remote)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// When it was downloaded, or last found unchanged.
    pub(crate) fn updated(&self) -> Option<SystemTime> {
        self.state().updated
    }

    /// The last download's failure, until one succeeds.
    pub(crate) fn failure(&self) -> Option<crate::control::Failure> {
        self.state().failed.clone()
    }

    pub(crate) fn is_loaded(&self) -> bool {
        self.state().loaded
    }

    /// How long until it is due for a download; zero when due now.
    pub(crate) fn due_in(&self, now: SystemTime) -> Duration {
        let state = self.state();
        if let Some(failed) = &state.failed {
            return RETRY.saturating_sub(now.duration_since(failed.at).unwrap_or_default());
        }
        match state.updated {
            None => Duration::ZERO,
            Some(updated) => self
                .interval
                .saturating_sub(now.duration_since(updated).unwrap_or_default()),
        }
    }

    /// Downloads it, and puts the new rules in place when they read.
    pub(crate) async fn update(&self, dispatcher: &Dispatcher) -> Result<()> {
        let result = self.download(dispatcher).await;
        let mut state = self.state();
        state.failed = result.as_ref().err().map(crate::control::Failure::now);
        result
    }

    async fn download(&self, dispatcher: &Dispatcher) -> Result<()> {
        let via = match &self.client.via {
            Some(via) => via.clone(),
            None => http::Via::Outbound(
                dispatcher
                    .default_outbound()
                    .ok_or_else(|| anyhow!("no outbound to download through"))?,
            ),
        };
        let etag = {
            let state = self.state();
            state.loaded.then(|| state.etag.clone()).flatten()
        };
        match http::get(
            dispatcher,
            &via,
            &self.client.headers,
            &self.url,
            etag.as_deref(),
        )
        .await?
        {
            http::Response::NotModified => {
                debug!("rule-set [{}]: unchanged", self.tag);
                self.state().updated = Some(SystemTime::now());
            }
            http::Response::Body { data, etag, .. } => {
                let set = RuleSet::read(&data, self.format, self.behavior, &self.env)?;
                self.set.publish(Arc::new(set));
                {
                    let mut state = self.state();
                    state.loaded = true;
                    state.etag = etag;
                    state.updated = Some(SystemTime::now());
                }
                info!("rule-set [{}]: downloaded, {} bytes", self.tag, data.len());
                if let Err(e) = self.save(&data) {
                    warn!("rule-set [{}]: not cached: {}", self.tag, e);
                }
            }
        }
        if let Err(e) = self.save_meta() {
            warn!("rule-set [{}]: not cached: {}", self.tag, e);
        }
        Ok(())
    }

    /// Writes the copy whole or not at all: to a file beside it, then in
    /// its place.
    fn save(&self, data: &[u8]) -> Result<()> {
        let Some(path) = &self.cache else {
            return Ok(());
        };
        write_atomically(path, data)
    }

    fn save_meta(&self) -> Result<()> {
        let Some(path) = &self.cache else {
            return Ok(());
        };
        let meta = serde_json::to_vec(&*self.state())?;
        write_atomically(&meta_path(path), &meta)
    }
}

fn meta_path(cache: &std::path::Path) -> PathBuf {
    cache.with_extension("meta.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cached_copy_is_used_until_due() {
        let dir = std::env::temp_dir().join(format!(
            "sail-rule-set-cache-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                cache_dir: Some(dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let config: config::RuleSet = serde_json::from_value(serde_json::json!({
            "type": "remote", "tag": "s", "url": "https://example.com/s.json",
            "update_interval": "1h"
        }))
        .unwrap();
        let remote = Remote::load(&config, "s", Default::default(), &env).unwrap();
        assert!(!remote.is_loaded());
        assert!(remote.due_in(SystemTime::now()).is_zero());

        remote
            .save(br#"{ "version": 3, "rules": [{ "domain": "a.example" }] }"#)
            .unwrap();
        remote.state().updated = Some(SystemTime::now());
        remote.save_meta().unwrap();
        let again = Remote::load(&config, "s", Default::default(), &env).unwrap();
        assert!(again.is_loaded());
        let due = again.due_in(SystemTime::now());
        assert!(
            due > Duration::from_secs(3500) && due <= Duration::from_secs(3600),
            "{:?}",
            due
        );
        let facts = crate::app::router::matcher::Facts::new(
            &crate::session::Session {
                destination: crate::session::SocksAddr::Domain("a.example".into(), 443),
                ..Default::default()
            },
            &[],
        );
        assert!(again.set.load().matches(&facts, false));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_tag_cannot_leave_the_cache_directory() {
        assert_eq!(file_name("geosite-cn"), "geosite-cn");
        assert_eq!(file_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(file_name(".."), "_");
        assert_eq!(file_name("a/b\\c:d"), "a_b_c_d");
    }
}
