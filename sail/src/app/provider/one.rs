//! One outbound provider: where its outbounds come from, the copy kept of
//! a remote one, and its members.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info, warn};

use super::Retired;
use crate::adapter::registry::{self, OutboundBuildState};
use crate::adapter::AnyOutboundHandler;
use crate::app::dispatcher::Dispatcher;
use crate::app::router::rule_set::remote::{file_name, write_atomically};
use crate::app::router::rule_set::{http, HttpClients};
use crate::app::SyncDnsClient;
use crate::config::clash::subscription::{self, Selection};
use crate::config::model::{Outbound, OutboundProvider, OutboundProviderKind};
use crate::net::DialOptions;
use crate::protocol::group::members::{Member, MemberKey, Members};
use crate::protocol::group::merge::{mihomo_type, Sources};
use crate::runtime::RuntimeEnv;

/// How often a remote provider is downloaded again by default: Mihomo's
/// and sing-box's rule-sets' day.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after a failed update the next one is tried.
const RETRY: Duration = Duration::from_secs(5 * 60);

pub(crate) struct Provider {
    pub tag: Arc<str>,
    config: OutboundProvider,
    source: Source,
    /// Which of what it holds it takes, and what it changes in them.
    selection: Selection,
    /// What its members dial with where their dial fields leave off.
    dial_defaults: Arc<DialOptions>,
    members: Arc<Members>,
    state: Mutex<State>,
    /// One update at a time.
    updating: tokio::sync::Mutex<()>,
    retired: Arc<Retired>,
}

enum Source {
    Remote {
        url: String,
        client: http::Client,
        interval: Duration,
        /// Where the downloaded copy is kept; none when there is nowhere
        /// to.
        cache: Option<PathBuf>,
    },
    Local {
        path: String,
        interval: Option<Duration>,
    },
    Inline,
}

/// What is known of what it holds.
#[derive(Clone, Default)]
struct State {
    /// Whether it holds anything yet.
    loaded: bool,
    /// Its outbounds, each by name, as last read.
    proxies: Arc<Vec<(String, Value)>>,
    /// A hash of the file last read, to tell whether it changed.
    read: Option<u64>,
    meta: Meta,
    /// When an update last failed.
    failed: Option<SystemTime>,
    /// Its members, as built from `proxies`.
    built: Vec<Built>,
}

/// What is kept beside a remote provider's copy.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Meta {
    etag: Option<String>,
    /// When it was downloaded, or last found unchanged; for a local one,
    /// when the file was last read.
    #[serde(default)]
    updated: Option<SystemTime>,
}

/// A member, as built.
#[derive(Clone)]
struct Built {
    name: Arc<str>,
    /// The outbound it was built from, to tell whether it changed.
    outbound: Value,
    handler: AnyOutboundHandler,
    tasks: Vec<AbortHandle>,
}

impl Provider {
    /// The provider of `config`, read as `Providers::load` says.
    pub(super) fn load(
        config: &OutboundProvider,
        clients: &HttpClients,
        dial_defaults: Arc<DialOptions>,
        env: &RuntimeEnv,
        previous: Option<&Provider>,
        retired: Arc<Retired>,
    ) -> Result<Self> {
        let source = match config.kind {
            OutboundProviderKind::Remote => Source::Remote {
                url: env
                    .host
                    .download_url(config.url.as_deref().unwrap_or_default())
                    .map_err(|e| anyhow!("url: {}", e))?,
                client: clients.client(
                    config.http_client.as_ref(),
                    config.download_detour.as_deref(),
                )?,
                interval: config.update_interval.unwrap_or(DEFAULT_INTERVAL),
                // Kept across restarts only where the host keeps things.
                cache: env
                    .host
                    .cache_dir
                    .as_ref()
                    .map(|dir| dir.join("provider").join(file_name(&config.tag))),
            },
            OutboundProviderKind::Local => Source::Local {
                path: env.data_path(config.path.as_deref().unwrap_or_default()),
                interval: config.update_interval,
            },
            OutboundProviderKind::Inline => Source::Inline,
        };
        let mut warnings = Vec::new();
        let selection = Selection::of(
            &config.filter,
            &config.exclude_filter,
            &config.exclude_type,
            config.detour.as_deref(),
            config.overrides.as_ref(),
            &mut warnings,
        )?;
        let mut provider = Provider {
            tag: config.tag.as_str().into(),
            config: config.clone(),
            source,
            selection,
            dial_defaults,
            members: Members::of(Vec::new()),
            state: Mutex::new(State::default()),
            updating: tokio::sync::Mutex::new(()),
            retired,
        };
        for warning in warnings {
            warn!("outbound provider [{}]: {}", provider.tag, warning);
        }
        // Configured as it was: it goes on as it is.
        if let Some(previous) = previous {
            provider.members = previous.members.clone();
            *provider.state.get_mut().unwrap_or_else(|e| e.into_inner()) = previous.state().clone();
            return Ok(provider);
        }
        match &provider.source {
            Source::Remote { cache, .. } => {
                // A cached copy that does not read is as good as none.
                if let Some(cache) = cache {
                    if let Ok(body) = std::fs::read(cache) {
                        match provider.read(&body) {
                            Ok(proxies) => {
                                let meta = std::fs::read(meta_path(cache))
                                    .ok()
                                    .and_then(|m| serde_json::from_slice(&m).ok())
                                    .unwrap_or_default();
                                let state =
                                    provider.state.get_mut().unwrap_or_else(|e| e.into_inner());
                                state.proxies = Arc::new(proxies);
                                state.loaded = true;
                                state.meta = meta;
                                debug!(
                                    "outbound provider [{}]: from {}",
                                    provider.tag,
                                    cache.display()
                                );
                            }
                            Err(e) => warn!(
                                "outbound provider [{}]: cached {}: {:#}",
                                provider.tag,
                                cache.display(),
                                e
                            ),
                        }
                    }
                }
            }
            Source::Local { path, .. } => {
                let body = std::fs::read(path).map_err(|e| anyhow!("path: {}: {}", path, e))?;
                let proxies = provider
                    .read(&body)
                    .map_err(|e| anyhow!("path: {}: {:#}", path, e))?;
                let state = provider.state.get_mut().unwrap_or_else(|e| e.into_inner());
                state.proxies = Arc::new(proxies);
                state.loaded = true;
                state.read = Some(hash(&body));
                state.meta.updated = Some(SystemTime::now());
            }
            Source::Inline => {
                let proxies = config
                    .outbounds
                    .iter()
                    .map(|o| Ok((o.tag.clone(), serde_json::to_value(o)?)))
                    .collect::<Result<Vec<_>>>()?;
                let state = provider.state.get_mut().unwrap_or_else(|e| e.into_inner());
                state.proxies = Arc::new(proxies);
                state.loaded = true;
            }
        }
        Ok(provider)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn config(&self) -> &OutboundProvider {
        &self.config
    }

    pub(crate) fn members(&self) -> Arc<Members> {
        self.members.clone()
    }

    /// Where it comes from, as Mihomo names it: `HTTP`, `File`, `Inline`.
    #[cfg(feature = "clash-api")]
    pub(crate) fn vehicle(&self) -> &'static str {
        match self.source {
            Source::Remote { .. } => "HTTP",
            Source::Local { .. } => "File",
            Source::Inline => "Inline",
        }
    }

    /// When it was last downloaded, or found unchanged, or its file read.
    #[cfg(feature = "clash-api")]
    pub(crate) fn updated(&self) -> Option<SystemTime> {
        self.state().meta.updated
    }

    pub(super) fn is_loaded(&self) -> bool {
        self.state().loaded
    }

    /// The outbounds `body` holds, as Mihomo reads a provider's; its
    /// warnings are logged, naming the provider.
    fn read(&self, body: &[u8]) -> Result<Vec<(String, Value)>> {
        let body = String::from_utf8_lossy(body);
        let read = subscription::read(&body, &self.selection)?;
        for warning in &read.warnings {
            warn!("outbound provider [{}]: {}", self.tag, warning);
        }
        Ok(read.proxies)
    }

    /// How long until it is due for an update, zero when due now; none
    /// when it is never updated.
    pub(super) fn due_in(&self, now: SystemTime) -> Option<Duration> {
        let interval = match &self.source {
            Source::Remote { interval, .. } => *interval,
            Source::Local {
                interval: Some(interval),
                ..
            } => *interval,
            Source::Local { interval: None, .. } | Source::Inline => return None,
        };
        let state = self.state();
        if let Some(failed) = state.failed {
            return Some(RETRY.saturating_sub(now.duration_since(failed).unwrap_or_default()));
        }
        Some(match state.meta.updated {
            None => Duration::ZERO,
            Some(updated) => {
                interval.saturating_sub(now.duration_since(updated).unwrap_or_default())
            }
        })
    }

    /// Downloads it, or reads its file, again, and builds and publishes
    /// the members of what it now holds, if that changed.
    pub(crate) async fn update(&self, dispatcher: &Dispatcher) -> Result<()> {
        let _updating = self.updating.lock().await;
        let result = match &self.source {
            Source::Remote { .. } => self.download(dispatcher).await,
            Source::Local { path, .. } => self.read_again(path),
            Source::Inline => Ok(false),
        };
        self.state().failed = result.is_err().then(SystemTime::now);
        if result? {
            let manager = dispatcher.outbound_manager.load();
            self.build(
                manager.handler_map(),
                &dispatcher.dns_client(),
                dispatcher.env(),
            )?;
            self.retired.check();
            // The groups that take its members, at once rather than when
            // their tasks come to it.
            manager.merge_groups();
        }
        Ok(())
    }

    /// Downloads it; whether what it holds changed.
    async fn download(&self, dispatcher: &Dispatcher) -> Result<bool> {
        let Source::Remote {
            url, client, cache, ..
        } = &self.source
        else {
            unreachable!("a remote provider is downloaded")
        };
        let via = match &client.via {
            Some(via) => via.clone(),
            None => http::Via::Outbound(
                dispatcher
                    .default_outbound()
                    .ok_or_else(|| anyhow!("no outbound to download through"))?,
            ),
        };
        let etag = {
            let state = self.state();
            state.loaded.then(|| state.meta.etag.clone()).flatten()
        };
        let changed =
            match http::get(dispatcher, &via, &client.headers, url, etag.as_deref()).await? {
                http::Response::NotModified => {
                    debug!("outbound provider [{}]: unchanged", self.tag);
                    self.state().meta.updated = Some(SystemTime::now());
                    false
                }
                http::Response::Body { data, etag } => {
                    let proxies = self.read(&data)?;
                    {
                        let mut state = self.state();
                        state.proxies = Arc::new(proxies);
                        state.loaded = true;
                        state.meta = Meta {
                            etag,
                            updated: Some(SystemTime::now()),
                        };
                    }
                    info!(
                        "outbound provider [{}]: downloaded, {} bytes",
                        self.tag,
                        data.len()
                    );
                    if let Some(cache) = cache {
                        if let Err(e) = write_atomically(cache, &data) {
                            warn!("outbound provider [{}]: not cached: {}", self.tag, e);
                        }
                    }
                    true
                }
            };
        if let Some(cache) = cache {
            let meta = serde_json::to_vec(&self.state().meta)?;
            if let Err(e) = write_atomically(&meta_path(cache), &meta) {
                warn!("outbound provider [{}]: not cached: {}", self.tag, e);
            }
        }
        Ok(changed)
    }

    /// Reads its file again; whether what it holds changed.
    fn read_again(&self, path: &str) -> Result<bool> {
        let body = std::fs::read(path).map_err(|e| anyhow!("{}: {}", path, e))?;
        let read = hash(&body);
        if self.state().read == Some(read) {
            self.state().meta.updated = Some(SystemTime::now());
            return Ok(false);
        }
        let proxies = self.read(&body).map_err(|e| anyhow!("{}: {:#}", path, e))?;
        let mut state = self.state();
        state.proxies = Arc::new(proxies);
        state.read = Some(read);
        state.meta.updated = Some(SystemTime::now());
        Ok(true)
    }

    /// Builds its members onto `handlers`, the outbounds they may dial
    /// through, and publishes them. A member that is as it was and dials
    /// through no other outbound keeps its handler; one that does not
    /// build is left out, with a warning, but of an inline provider,
    /// whose outbounds are the configuration's, it is an error.
    pub(super) fn build(
        &self,
        handlers: &HashMap<String, AnyOutboundHandler>,
        dns_client: &SyncDnsClient,
        env: &RuntimeEnv,
    ) -> Result<()> {
        let mut state = self.state();
        let proxies = state.proxies.clone();
        let mut before: HashMap<Arc<str>, Built> =
            state.built.drain(..).map(|b| (b.name.clone(), b)).collect();
        let mut handlers = handlers.clone();
        let mut built: Vec<Built> = Vec::with_capacity(proxies.len());
        let mut failed = Vec::new();
        for (name, outbound) in proxies.iter() {
            if built.iter().any(|b| &*b.name == name) {
                failed.push(format!("{:?}: another is so named", name));
                continue;
            }
            if let Some(kept) = before.remove(name.as_str()) {
                if kept.outbound == *outbound && outbound.get("detour").is_none() {
                    built.push(kept);
                    continue;
                }
                self.retired.add(kept.handler, kept.tasks);
            }
            match self.build_one(name, outbound, &mut handlers, dns_client, env) {
                Ok((handler, tasks)) => built.push(Built {
                    name: name.as_str().into(),
                    outbound: outbound.clone(),
                    handler,
                    tasks,
                }),
                Err(e) if self.config.kind == OutboundProviderKind::Inline => {
                    return Err(anyhow!("outbound_providers: [{}]: {:#}", self.tag, e));
                }
                Err(e) => failed.push(format!("{:?}: {:#}", name, e)),
            }
        }
        for gone in before.into_values() {
            self.retired.add(gone.handler, gone.tasks);
        }
        if !failed.is_empty() {
            warn!(
                "outbound provider [{}]: {} outbounds left out: {}",
                self.tag,
                failed.len(),
                failed.join("; ")
            );
        }
        let members = built
            .iter()
            .map(|b| Member {
                key: MemberKey {
                    source: Some(self.tag.clone()),
                    name: b.name.clone(),
                },
                handler: b.handler.clone(),
                kind: b
                    .outbound
                    .get("type")
                    .and_then(Value::as_str)
                    .map(mihomo_type)
                    .unwrap_or("Unknown"),
            })
            .collect();
        state.built = built;
        drop(state);
        self.members.publish(members);
        Ok(())
    }

    /// Builds the member `name` of `outbound` onto `handlers`, under a tag
    /// of its own, and takes it out again: members do not dial through
    /// each other.
    fn build_one(
        &self,
        name: &str,
        outbound: &Value,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        dns_client: &SyncDnsClient,
        env: &RuntimeEnv,
    ) -> Result<(AnyOutboundHandler, Vec<AbortHandle>)> {
        let mut outbound: Outbound = serde_json::from_value(outbound.clone())?;
        // A plugin's library would be unloaded with what builds it here.
        if crate::config::model::GROUP_PROTOCOLS.contains(&outbound.protocol.as_str())
            || outbound.protocol == "plugin"
        {
            return Err(anyhow!("a group or a plugin is not a provider's outbound"));
        }
        let tag = format!("{}/{}", self.tag, name);
        outbound.tag = tag.clone();
        let mut abort_handles = HashMap::new();
        #[cfg(feature = "outbound-select")]
        let mut selectors = Default::default();
        #[cfg(feature = "plugin")]
        let mut external_handlers = crate::app::outbound::plugin::ExternalHandlers::new();
        registry::build_outbounds(
            &crate::include::OUTBOUNDS,
            &crate::include::ENDPOINTS,
            std::slice::from_ref(&outbound),
            &[],
            OutboundBuildState {
                dns_client,
                dial_defaults: &self.dial_defaults,
                env,
                handlers,
                abort_handles: &mut abort_handles,
                dependencies: &mut HashMap::new(),
                endpoints: &mut HashMap::new(),
                #[cfg(feature = "outbound-select")]
                selectors: &mut selectors,
                #[cfg(feature = "plugin")]
                external_handlers: &mut external_handlers,
                providers: &mut Sources::default(),
            },
        )?;
        let handler = handlers
            .remove(&tag)
            .ok_or_else(|| anyhow!("[{}] outbound: not built", tag))?;
        Ok((handler, abort_handles.remove(&tag).unwrap_or_default()))
    }

    /// Retires all its members, as it is gone.
    pub(super) fn retire_all(&self, retired: &Retired) {
        for built in self.state().built.iter() {
            retired.add(built.handler.clone(), built.tasks.clone());
        }
    }
}

fn meta_path(cache: &std::path::Path) -> PathBuf {
    let mut path = cache.as_os_str().to_owned();
    path.push(".meta.json");
    path.into()
}

fn hash(body: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_client() -> SyncDnsClient {
        crate::app::dns::DnsClient::new(
            &Default::default(),
            Arc::new(DialOptions::default()),
            &Default::default(),
        )
        .unwrap()
        .into_shared()
    }

    fn config(json: serde_json::Value) -> OutboundProvider {
        serde_json::from_value(json).unwrap()
    }

    fn load(config: &OutboundProvider, env: &RuntimeEnv, previous: Option<&Provider>) -> Provider {
        Provider::load(
            config,
            &HttpClients::default(),
            Arc::new(DialOptions::default()),
            env,
            previous,
            Default::default(),
        )
        .unwrap()
    }

    fn names(provider: &Provider) -> Vec<String> {
        let snapshot = provider.members().load();
        snapshot
            .members
            .iter()
            .map(|m| m.key.name.to_string())
            .collect()
    }

    fn handler(provider: &Provider, name: &str) -> AnyOutboundHandler {
        provider
            .members()
            .load()
            .find(name)
            .unwrap()
            .handler
            .clone()
    }

    #[test]
    fn a_cached_copy_is_read_until_due() {
        let dir = std::env::temp_dir().join(format!(
            "sail-provider-cache-{}-{:?}",
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
        let config = config(serde_json::json!({
            "type": "remote", "tag": "sub/1", "url": "https://example.com/s",
            "update_interval": "1h", "exclude_filter": "JP"
        }));
        let provider = load(&config, &env, None);
        assert!(!provider.is_loaded());
        assert!(provider.due_in(SystemTime::now()).unwrap().is_zero());

        let cache = dir.join("provider").join("sub_1");
        write_atomically(
            &cache,
            b"proxies:\n  - { name: HK, type: socks5, server: a.example, port: 1080 }\n  \
              - { name: JP, type: socks5, server: b.example, port: 1080 }\n",
        )
        .unwrap();
        let meta = Meta {
            etag: Some("\"x\"".into()),
            updated: Some(SystemTime::now()),
        };
        write_atomically(&meta_path(&cache), &serde_json::to_vec(&meta).unwrap()).unwrap();
        let provider = load(&config, &env, None);
        assert!(provider.is_loaded());
        let due = provider.due_in(SystemTime::now()).unwrap();
        assert!(due > Duration::from_secs(3500), "{:?}", due);
        assert_eq!(provider.state().meta.etag.as_deref(), Some("\"x\""));
        let proxies = provider.state().proxies.clone();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].0, "HK");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Members as they were keep their handlers; those replaced or gone
    /// are retired, and their tasks stop once nothing holds them.
    #[cfg(all(feature = "outbound-anytls", feature = "outbound-direct"))]
    #[tokio::test]
    async fn members_unchanged_are_kept_and_the_others_retired() {
        let env = RuntimeEnv::default();
        let dns = dns_client();
        let anytls = serde_json::json!({
            "type": "anytls", "tag": "any", "server": "127.0.0.1", "server_port": 1,
            "password": "p", "tls": { "enabled": true, "server_name": "localhost" }
        });
        let config = config(serde_json::json!({
            "type": "inline", "tag": "p",
            "outbounds": [anytls, { "type": "direct", "tag": "d" }]
        }));
        let provider = load(&config, &env, None);
        provider.build(&HashMap::new(), &dns, &env).unwrap();
        assert_eq!(names(&provider), ["any", "d"]);
        let key = provider.members().load().members[0].key.clone();
        assert_eq!(key.source.as_deref(), Some("p"));
        assert_eq!(provider.members().load().members[0].kind, "AnyTLS");
        let any = handler(&provider, "any");
        let direct = handler(&provider, "d");
        assert_eq!(any.tag(), "p/any");
        let tasks = provider.state().built[0].tasks.clone();
        assert!(!tasks.is_empty(), "anytls spawns its cleanup");

        // Built again from the same outbounds: the same handlers.
        provider.build(&HashMap::new(), &dns, &env).unwrap();
        assert!(Arc::ptr_eq(&any, &handler(&provider, "any")));
        assert!(Arc::ptr_eq(&direct, &handler(&provider, "d")));

        // Without it: retired, its tasks going on while it is held.
        let rest = provider.state().proxies[1..].to_vec();
        provider.state().proxies = Arc::new(rest);
        provider.build(&HashMap::new(), &dns, &env).unwrap();
        assert_eq!(names(&provider), ["d"]);
        assert!(Arc::ptr_eq(&direct, &handler(&provider, "d")));
        provider.retired.check();
        assert!(!tasks[0].is_aborted(), "held here still");
        drop(any);
        provider.retired.check();
        assert!(tasks[0].is_aborted());
    }

    /// A reload keeps a provider configured as it was, members and all.
    #[cfg(feature = "outbound-direct")]
    #[test]
    fn a_provider_configured_as_it_was_goes_on() {
        let env = RuntimeEnv::default();
        let dns = dns_client();
        let config = config(serde_json::json!({
            "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "d" }]
        }));
        let first = load(&config, &env, None);
        first.build(&HashMap::new(), &dns, &env).unwrap();
        let next = load(&config, &env, Some(&first));
        assert!(Arc::ptr_eq(&first.members(), &next.members()));
        next.build(&HashMap::new(), &dns, &env).unwrap();
        assert_eq!(names(&next), ["d"]);
        assert!(Arc::ptr_eq(&handler(&first, "d"), &handler(&next, "d")));
    }

    #[cfg(feature = "outbound-direct")]
    #[test]
    fn an_inline_outbound_that_does_not_build_is_an_error() {
        let env = RuntimeEnv::default();
        let config = config(serde_json::json!({
            "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "d", "no_such_field": 1 }]
        }));
        let err = load(&config, &env, None)
            .build(&HashMap::new(), &dns_client(), &env)
            .unwrap_err();
        assert!(err.to_string().contains("[p]"), "{:#}", err);
    }

    /// A provider of `sub.store` is downloaded from the host's Sub-Store,
    /// and fails without one.
    #[test]
    fn sub_store_is_the_host_s() {
        let config = config(serde_json::json!({
            "type": "remote", "tag": "s", "url": "https://sub.store/download/all?target=Surge"
        }));
        let err = Provider::load(
            &config,
            &HttpClients::default(),
            Arc::new(DialOptions::default()),
            &RuntimeEnv::default(),
            None,
            Default::default(),
        )
        .err()
        .unwrap();
        assert!(format!("{:#}", err).contains("set sub_store"), "{:#}", err);
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                sub_store: Some(crate::runtime::SubStore(
                    "https://sub.example.com/secret".into(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };
        let Source::Remote { url, .. } = load(&config, &env, None).source else {
            unreachable!("a remote provider")
        };
        assert_eq!(
            url,
            "https://sub.example.com/secret/download/all?target=Surge"
        );
    }
}
