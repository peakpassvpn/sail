//! Watch containing directories so atomic rename-over replacements keep
//! working. Filter to resource paths and debounce a certificate/key pair.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

pub(crate) struct FileWatcher {
    _watcher: RecommendedWatcher,
}

/// Runtime-owned dirty queue, independent of native watcher replacements.
pub(crate) struct ReloadEvents {
    events: mpsc::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ReloadEvents {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FileWatcher {
    pub(crate) fn new(paths: Vec<PathBuf>, events: &ReloadEvents) -> Result<Self, crate::Error> {
        let cwd = std::env::current_dir().map_err(|e| crate::Error::Config(e.into()))?;
        let mut watched = HashSet::new();
        for path in paths {
            let path = if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            };
            if let Ok(resolved) = path.canonicalize() {
                watched.insert(resolved);
            }
            watched.insert(path);
        }
        let parents: HashSet<_> = watched
            .iter()
            .filter_map(|p| p.parent().map(PathBuf::from))
            .collect();
        let events = events.events.clone();
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| match event {
                Ok(event)
                    if !matches!(event.kind, notify::EventKind::Access(_))
                        && event.paths.iter().any(|p| watched.contains(p)) =>
                {
                    let _ = events.try_send(());
                }
                Err(error) => tracing::warn!("resource file watch failed: {}", error),
                _ => {}
            })
            .map_err(crate::Error::Watcher)?;
        for parent in parents {
            watcher
                .watch(&parent, RecursiveMode::NonRecursive)
                .map_err(crate::Error::Watcher)?;
        }
        Ok(Self { _watcher: watcher })
    }
}

impl ReloadEvents {
    pub(crate) fn new(reload: mpsc::Sender<SyncSender<Result<(), crate::Error>>>) -> Self {
        let (events, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            while rx.recv().await.is_some() {
                loop {
                    match tokio::time::timeout(Duration::from_millis(250), rx.recv()).await {
                        Ok(Some(())) => continue,
                        Ok(None) => return,
                        Err(_) => break,
                    }
                }
                let (tx, result) = std::sync::mpsc::sync_channel(1);
                if reload.send(tx).await.is_err() {
                    break;
                }
                // Never block the runtime or the notify callback on reload.
                if let Ok(Ok(Err(error))) = tokio::task::spawn_blocking(move || result.recv()).await
                {
                    tracing::warn!(
                        "resource file reload failed; keeping previous resources: {}",
                        error
                    );
                }
            }
        });
        Self { events, task }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rename_over_is_watched_and_unrelated_files_are_ignored() {
        let dir =
            std::env::temp_dir().join(format!("sail-resource-watch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, "old certificate").unwrap();
        std::fs::write(&key, "old key").unwrap();
        let (tx, mut requests) = mpsc::channel(1);
        let events = ReloadEvents::new(tx);
        let watcher = FileWatcher::new(vec![cert.clone(), key.clone()], &events).unwrap();
        std::fs::write(dir.join("unrelated"), "ignored").unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(600), requests.recv())
                .await
                .is_err()
        );
        for generation in ["first", "second"] {
            let staged = dir.join("staged.pem");
            std::fs::write(&staged, generation).unwrap();
            std::fs::rename(&staged, &cert).unwrap();
            std::fs::write(&key, generation).unwrap();
            let response = tokio::time::timeout(Duration::from_secs(5), requests.recv())
                .await
                .unwrap()
                .unwrap();
            response.send(Ok(())).unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(600), requests.recv())
                    .await
                    .is_err()
            );
        }
        drop(watcher);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn queued_change_survives_watcher_replacement_and_failed_reload() {
        let (tx, mut requests) = mpsc::channel(1);
        let events = ReloadEvents::new(tx);
        let mut watcher = FileWatcher::new(Vec::new(), &events).unwrap();
        for succeeds in [true, false] {
            events.events.try_send(()).unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(5), requests.recv())
                .await
                .unwrap()
                .unwrap();
            // A notification after candidate reads, before commit.
            events.events.try_send(()).unwrap();
            let candidate = FileWatcher::new(Vec::new(), &events).unwrap();
            if succeeds {
                watcher = candidate;
                reply.send(Ok(())).unwrap();
            } else {
                drop(candidate);
                reply
                    .send(Err(crate::Error::Config(anyhow::anyhow!(
                        "invalid candidate"
                    ))))
                    .unwrap();
            }
            let followup = tokio::time::timeout(Duration::from_secs(5), requests.recv())
                .await
                .unwrap()
                .unwrap();
            followup.send(Ok(())).unwrap();
        }
        drop(watcher);
    }
}
