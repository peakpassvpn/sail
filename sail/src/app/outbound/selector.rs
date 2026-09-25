use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use protobuf::Message;
use tracing::warn;

use anyhow::{anyhow, Result};

/// The file selections are kept in: in `cache_dir` when the host gives one,
/// in the user's cache directory otherwise.
pub fn cache_file(cache_dir: Option<&Path>) -> Result<PathBuf> {
    let cache_loc = match cache_dir {
        Some(dir) => dir.to_owned(),
        None => directories::ProjectDirs::from("com", "peakpassvpn", "sail")
            .ok_or_else(|| anyhow!("no home directory"))?
            .cache_dir()
            .to_owned(),
    };
    if !cache_loc.exists() {
        std::fs::create_dir_all(&cache_loc)?;
    }
    Ok(cache_loc.join("selector.cache"))
}

pub fn get_selected_from_cache(cache_file: &Path, id: &str) -> Result<Option<String>> {
    let content = std::fs::read(cache_file)?;
    let cache = super::selector_cache::SelectorCache::parse_from_bytes(&content)?;
    Ok(cache.items.get(id).map(Clone::clone))
}

pub fn persist_selected_to_cache(cache_file: &Path, id: String, selected: String) -> Result<()> {
    let mut cache = if cache_file.exists() {
        let content = std::fs::read(cache_file)?;
        super::selector_cache::SelectorCache::parse_from_bytes(&content)?
    } else {
        super::selector_cache::SelectorCache::new()
    };
    cache.items.insert(id, selected);
    let content = cache.write_to_bytes()?;
    std::fs::write(cache_file, content)?;
    Ok(())
}

type OutboundList = Vec<String>;
type OutboundIndex = Arc<AtomicUsize>;

/// OutboundSelector typically associates to a `select` outbound.
pub struct OutboundSelector {
    id: String,
    handlers: OutboundList,
    selected: OutboundIndex,
    /// Where the selection is kept across restarts, if anywhere.
    cache_file: Option<PathBuf>,
}

impl OutboundSelector {
    pub fn new(
        id: String,
        handlers: OutboundList,
        selected: OutboundIndex,
        cache_file: Option<PathBuf>,
    ) -> Self {
        Self {
            id,
            handlers,
            selected,
            cache_file,
        }
    }

    pub fn get_available_tags(&self) -> Vec<String> {
        self.handlers.clone()
    }

    pub fn get_selected_tag(&self) -> String {
        self.handlers[self.selected.load(Ordering::Relaxed)].to_owned()
    }

    pub fn set_selected(&mut self, tag: &str) -> Result<()> {
        if let Some(i) = self.handlers.iter().position(|x| x == tag) {
            self.selected.store(i, Ordering::Relaxed);
            if let Some(cache_file) = &self.cache_file {
                if let Err(e) =
                    persist_selected_to_cache(cache_file, self.id.clone(), tag.to_string())
                {
                    warn!("persist selector state failed: {}", e);
                }
            }
            Ok(())
        } else {
            Err(anyhow!("handler not exists"))
        }
    }
}
