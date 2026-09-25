use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use protobuf::Message;
use tokio::sync::watch;
use tracing::warn;

use anyhow::{anyhow, Result};

use crate::runtime::RuntimeEnv;

/// The file selections are kept in: in the host's cache directory when it
/// gives one, in the instance's data directory otherwise. Both belong to
/// the instance, so two instances with their own directories never share
/// selections.
pub fn cache_file(env: &RuntimeEnv) -> PathBuf {
    env.host
        .cache_dir
        .clone()
        .unwrap_or_else(|| env.data_dir())
        .join("selector.cache")
}

/// Serialises the read-modify-write of the cache file: every selector of
/// the process writes to it, and two writing at once would lose one.
static CACHE_FILE_LOCK: Mutex<()> = Mutex::new(());

pub fn get_selected_from_cache(cache_file: &Path, id: &str) -> Result<Option<String>> {
    let _guard = CACHE_FILE_LOCK.lock().map_err(|_| anyhow!("poisoned"))?;
    if !cache_file.exists() {
        return Ok(None);
    }
    let content = std::fs::read(cache_file)?;
    let cache = super::selector_cache::SelectorCache::parse_from_bytes(&content)?;
    Ok(cache.items.get(id).map(Clone::clone))
}

pub fn persist_selected_to_cache(cache_file: &Path, id: String, selected: String) -> Result<()> {
    let _guard = CACHE_FILE_LOCK.lock().map_err(|_| anyhow!("poisoned"))?;
    // A cache that cannot be read is replaced rather than kept broken.
    let mut cache = std::fs::read(cache_file)
        .ok()
        .and_then(|content| super::selector_cache::SelectorCache::parse_from_bytes(&content).ok())
        .unwrap_or_default();
    cache.items.insert(id, selected);
    let content = cache.write_to_bytes()?;
    if let Some(dir) = cache_file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Written aside and renamed, so a crash mid-write leaves the old file.
    let tmp = cache_file.with_extension("cache.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, cache_file)?;
    Ok(())
}

/// Which member a group sends its connections to, shared by the group's
/// handlers and its selector. Connections that should not outlive a
/// change of member watch it, see `subscribe`.
pub struct Selection {
    index: AtomicUsize,
    changed: watch::Sender<usize>,
}

impl Selection {
    pub fn new(index: usize) -> Self {
        Self {
            index: AtomicUsize::new(index),
            changed: watch::Sender::new(index),
        }
    }

    pub fn get(&self) -> usize {
        self.index.load(Ordering::Relaxed)
    }

    pub fn set(&self, index: usize) {
        self.index.store(index, Ordering::Relaxed);
        self.changed.send_if_modified(|current| {
            let modified = *current != index;
            *current = index;
            modified
        });
    }

    /// The selection as it changes.
    pub fn subscribe(&self) -> watch::Receiver<usize> {
        self.changed.subscribe()
    }
}

/// The latency of each member of a group, as its last check measured
/// it; `None` for a member that failed it or was not checked yet.
pub type MemberLatencies = Arc<RwLock<Vec<Option<Duration>>>>;

/// How a group's member comes to be selected.
pub enum SelectedBy {
    /// By hand, through the API; the choice is kept across restarts in
    /// the file given, if any.
    Hand { cache_file: Option<PathBuf> },
    /// By the group itself, from its checks; it cannot be selected by
    /// hand.
    Checks,
}

/// The state of a group that sends its connections to one member at a
/// time, `selector` or `urltest`: its members, the one selected, and
/// their latencies where the group measures them.
pub struct OutboundSelector {
    id: String,
    handlers: Vec<String>,
    selected: Arc<Selection>,
    selected_by: SelectedBy,
    latencies: Option<MemberLatencies>,
}

impl OutboundSelector {
    pub fn new(
        id: String,
        handlers: Vec<String>,
        selected: Arc<Selection>,
        selected_by: SelectedBy,
        latencies: Option<MemberLatencies>,
    ) -> Self {
        Self {
            id,
            handlers,
            selected,
            selected_by,
            latencies,
        }
    }

    pub fn get_available_tags(&self) -> Vec<String> {
        self.handlers.clone()
    }

    pub fn get_selected_tag(&self) -> String {
        self.handlers
            .get(self.selected.get())
            .cloned()
            .unwrap_or_default()
    }

    /// Each member with its latency, for a group that measures them.
    pub fn get_latencies(&self) -> Option<Vec<(String, Option<Duration>)>> {
        let latencies = self.latencies.as_ref()?;
        let latencies = latencies.read().ok()?;
        Some(
            self.handlers
                .iter()
                .cloned()
                .zip(latencies.iter().copied())
                .collect(),
        )
    }

    /// Whether a member can be selected by hand.
    pub fn is_selectable(&self) -> bool {
        matches!(self.selected_by, SelectedBy::Hand { .. })
    }

    /// Selects the member `tag` by hand, and keeps the choice.
    pub fn set_selected(&mut self, tag: &str) -> Result<()> {
        let SelectedBy::Hand { cache_file } = &self.selected_by else {
            return Err(anyhow!(
                "[{}] selects its outbound by itself, not by hand",
                self.id
            ));
        };
        let Some(i) = self.handlers.iter().position(|x| x == tag) else {
            return Err(anyhow!("[{}] has no outbound [{}]", self.id, tag));
        };
        self.selected.set(i);
        if let Some(cache_file) = cache_file {
            if let Err(e) = persist_selected_to_cache(cache_file, self.id.clone(), tag.to_string())
            {
                warn!("[{}] selection will not be kept: {}", self.id, e);
            }
        }
        Ok(())
    }
}
