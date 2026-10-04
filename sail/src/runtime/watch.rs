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

/// A file's size and time of modification, and when they were taken: what
/// a file is read against, taken just before it is read. A file is read
/// when what it configures is built, and watched only later, at a start
/// seconds later; a write in between raises no event, and without this
/// would never apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp {
    len: u64,
    modified: std::time::SystemTime,
    taken: std::time::SystemTime,
}

/// A file modified this close before its stamp was taken may be written
/// again without its time of modification changing, where a file system
/// keeps it to the second or to two (ext3, HFS+, FAT).
const STAMP_GRANULARITY: Duration = Duration::from_secs(2);

impl Stamp {
    pub(crate) fn of(path: &std::path::Path) -> Option<Self> {
        let taken = std::time::SystemTime::now();
        let meta = std::fs::metadata(path).ok()?;
        Some(Stamp {
            len: meta.len(),
            modified: meta.modified().ok()?,
            taken,
        })
    }

    /// Whether its time of modification is a whole second: a file system
    /// that keeps no finer one. One that does gives a whole second once in
    /// a great many writes, and the file is then read once more for
    /// nothing.
    fn coarse(&self) -> bool {
        self.modified
            .duration_since(std::time::UNIX_EPOCH)
            .is_ok_and(|since| since.subsec_nanos() == 0)
    }
}

/// Whether `path` may have been written since `read` was taken of it: it
/// is not as it was then; or it is there and was not; or, on a file system
/// that keeps times to the second, it was modified too close to then to
/// tell, as git treats a file as old as its index. A file that is gone or
/// cannot be looked at was not: reading it would only fail.
pub(crate) fn written_since(read: Option<Stamp>, path: &std::path::Path) -> bool {
    let Some(now) = Stamp::of(path) else {
        return false;
    };
    let Some(read) = read else {
        return true;
    };
    (now.len, now.modified) != (read.len, read.modified)
        || (read.coarse()
            && read
                .modified
                .checked_add(STAMP_GRANULARITY)
                .is_none_or(|settled| settled >= read.taken))
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
        let events = events.events.clone();
        Self::on_change(paths, move || {
            let _ = events.try_send(());
        })
    }

    /// Calls `changed` on the notify thread whenever one of `paths` is
    /// written, created, renamed over or removed.
    pub(crate) fn on_change(
        paths: Vec<PathBuf>,
        changed: impl Fn() + Send + 'static,
    ) -> Result<Self, crate::Error> {
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
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| match event {
                Ok(event)
                    if !matches!(event.kind, notify::EventKind::Access(_))
                        && event.paths.iter().any(|p| watched.contains(p)) =>
                {
                    changed();
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
    /// The configuration file changed: a reload, once it is quiet.
    pub(crate) fn changed(&self) {
        let _ = self.events.try_send(());
    }

    pub(crate) fn new(reload: mpsc::Sender<SyncSender<Result<(), crate::Error>>>) -> Self {
        let (events, mut rx) = mpsc::channel(1);
        let task = crate::runtime::scope::spawn_essential("config reload events", async move {
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
                if let Ok(Ok(Err(error))) =
                    crate::runtime::scope::spawn_blocking("config reload wait", move || {
                        result.recv()
                    })
                    .await
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

    /// A stamp tells a file written since from one left alone, and one
    /// that appeared; a file that is gone was not written.
    #[test]
    fn a_stamp_tells_a_file_written_since() {
        let dir = std::env::temp_dir().join(format!("sail-stamp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("file");
        assert!(!written_since(None, &path), "not there, then or now");
        std::fs::write(&path, "one").unwrap();
        assert!(written_since(None, &path), "there now, and was not");
        let read = Stamp::of(&path);
        // On a file system that keeps whole seconds it reads as written,
        // being this fresh: only one with finer times tells it was not.
        if !read.unwrap().coarse() {
            assert!(!written_since(read, &path), "left alone");
        }
        std::fs::write(&path, "another").unwrap();
        assert!(written_since(read, &path), "written since");
        std::fs::remove_file(&path).unwrap();
        assert!(!written_since(read, &path), "gone");
        std::fs::remove_dir_all(dir).unwrap();
    }

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
