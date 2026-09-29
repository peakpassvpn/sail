//! The mode of Clash's API (`Rule`, `Global`, `Direct`, or any other a rule
//! names), which `clash_mode` in routing and DNS rules matches: switched at
//! run time, as dashboards switch it.

use std::sync::Arc;

use arc_swap::ArcSwapOption;

/// The instance's mode, shared by its rules. None when there is no Clash
/// API, as in sing-box: a `clash_mode` condition then never matches.
#[derive(Clone, Default)]
pub struct ClashMode(Arc<ArcSwapOption<String>>);

impl std::fmt::Debug for ClashMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClashMode({:?})", self.get())
    }
}

impl ClashMode {
    pub fn get(&self) -> Option<String> {
        self.0.load().as_deref().cloned()
    }

    pub fn set(&self, mode: Option<String>) {
        self.0.store(mode.map(Arc::new));
    }

    /// Whether the mode is `mode`, however its case is written.
    pub fn is(&self, mode: &str) -> bool {
        self.0
            .load()
            .as_deref()
            .is_some_and(|current| current.eq_ignore_ascii_case(mode))
    }

    /// The mode a configuration starts in: the one the cache file kept,
    /// else its Clash API's `default_mode`, `Rule` when unset, as in
    /// sing-box; none without the API. A reload keeps the mode it finds,
    /// while there is still an API.
    pub fn configure(
        &self,
        clash_api: Option<&crate::config::model::ClashApi>,
        cache: Option<&crate::runtime::cache_file::CacheFile>,
    ) {
        match clash_api {
            None => self.set(None),
            Some(_) if self.get().is_some() => {}
            Some(api) => {
                let kept = cache.and_then(|cache| {
                    cache
                        .load_mode()
                        .inspect_err(|e| tracing::warn!("cache_file: clash mode: {}", e))
                        .ok()
                        .flatten()
                });
                self.set(Some(kept.unwrap_or_else(|| {
                    api.default_mode
                        .clone()
                        .unwrap_or_else(|| "Rule".to_string())
                })))
            }
        }
    }

    /// Switches to `mode`, as the Clash API does, and keeps it in the cache
    /// file, if there is one, for the next start.
    pub fn switch(&self, mode: &str, cache: Option<&crate::runtime::cache_file::CacheFile>) {
        self.set(Some(mode.to_owned()));
        if let Some(cache) = cache {
            if let Err(e) = cache.store_mode(mode) {
                tracing::warn!("cache_file: clash mode not kept: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mode_is_set_by_the_api_and_matched_whatever_the_case() {
        let mode = ClashMode::default();
        assert!(!mode.is("Rule"));
        mode.configure(Some(&Default::default()), None);
        assert!(mode.is("rule"));
        mode.set(Some("Global".into()));
        // A reload keeps it.
        mode.configure(
            Some(&crate::config::model::ClashApi {
                default_mode: Some("Direct".into()),
                ..Default::default()
            }),
            None,
        );
        assert!(mode.is("GLOBAL"));
        mode.configure(None, None);
        assert_eq!(mode.get(), None);
    }
}
