//! The certificate files of the inbounds, followed as sing-box follows a
//! TLS server's (`common/tls/std_server.go`): always, whether or not the
//! configuration file is watched, and an inbound at a time. When its files
//! change, the inbound's resources are built again from its configuration,
//! which reads them anew, and published at once for the connections that
//! come next; those open go on. Files that do not make a certificate and
//! key that go together, a certificate written before its key, are logged
//! and the certificate in use is kept, until they do.
//!
//! What follows them is the instance's: it goes when the instance stops,
//! and each change of the inbounds takes the files they read now.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Weak;
use std::time::Duration;

use tracing::{info, warn};

use crate::runtime::watch::{written_since, FileWatcher, Stamp};
use crate::RuntimeManager;

/// The files of inbounds as they were just before they were read.
pub(crate) type Read = std::collections::HashMap<PathBuf, Option<Stamp>>;

/// The files `inbounds` read, the certificate and key each presents, as
/// they are now: taken just before the inbounds are built, for
/// `follow_certificates_read` to tell which were written before their
/// watch was set up.
pub(crate) fn about_to_read(
    inbounds: &[crate::config::Inbound],
    env: &crate::runtime::RuntimeEnv,
) -> Read {
    inbounds
        .iter()
        .flat_map(|inbound| super::resource::files(inbound, env))
        .map(|path| {
            let stamp = Stamp::of(&path);
            (path, stamp)
        })
        .collect()
}

/// How long the files of an inbound are quiet before they are read: a
/// certificate and its key are written one after the other.
const SETTLE: Duration = Duration::from_millis(250);

/// The watchers of the inbounds' files, and the task that reloads them.
pub(crate) struct CertFollow {
    files: Vec<(String, Vec<PathBuf>)>,
    _watchers: Vec<FileWatcher>,
    task: tokio::task::AbortHandle,
}

impl Drop for CertFollow {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RuntimeManager {
    /// Follows the certificate files of the inbounds as they are now; what
    /// followed others goes. Nothing changes when they read the same files.
    pub(crate) fn follow_certificates(&self) {
        self.follow_certificates_read(&Read::new());
    }

    /// `follow_certificates`, of inbounds built since `read` was taken of
    /// their files (`about_to_read`). The files were read when the
    /// inbounds were built and are watched only from here, at a start
    /// seconds later: an inbound whose file was written in between is
    /// built again now, once its watch is set up, or the certificate
    /// replaced then would be served stale until its next change.
    pub(crate) fn follow_certificates_read(&self, read: &Read) {
        let files = match self.inbound_manager.lock() {
            Ok(inbounds) => inbounds.resource_files(),
            Err(_) => return,
        };
        let mut follow = self.cert_follow.lock().unwrap_or_else(|e| e.into_inner());
        if follow.as_ref().map(|f| &f.files) == Some(&files) {
            return;
        }
        // The files watched until now, as they are: a write while their
        // watchers are replaced shows against this. `read` is from before
        // they were read, and tells more.
        let mut seen: Read = follow
            .iter()
            .flat_map(|f| f.files.iter().flat_map(|(_, paths)| paths))
            .map(|path| (path.clone(), Stamp::of(path)))
            .collect();
        seen.extend(read.iter().map(|(path, stamp)| (path.clone(), *stamp)));
        // The watchers of the files no longer read go first.
        *follow = None;
        if files.is_empty() {
            return;
        }
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(files.len() * 4);
        let mut watchers = Vec::new();
        for (tag, paths) in &files {
            let (tx, inbound) = (tx.clone(), tag.clone());
            match FileWatcher::on_change(paths.clone(), move || {
                let _ = tx.try_send(inbound.clone());
            }) {
                Ok(watcher) => watchers.push(watcher),
                Err(e) => warn!(
                    "[{}] inbound: its certificate files are not followed: {}",
                    tag, e
                ),
            }
        }
        // Watched from here: what was written before is built again.
        for (tag, paths) in &files {
            let written = paths.iter().any(|path| {
                seen.get(path)
                    .is_some_and(|read| written_since(*read, path))
            });
            if written {
                tracing::debug!(
                    "[{}] inbound: its certificate files were written since they were read",
                    tag
                );
                let _ = tx.try_send(tag.clone());
            }
        }
        drop(tx);
        let task = self
            .env
            .scope
            .spawn_essential_on(
                &self.handle,
                "certificate follow",
                reload_changed(self.this.clone(), rx),
            )
            .abort_handle();
        *follow = Some(CertFollow {
            files,
            _watchers: watchers,
            task,
        });
    }

    /// Stops following: the watchers and their task go now.
    pub(crate) fn stop_following_certificates(&self) {
        *self.cert_follow.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// How many inbounds' files are followed, for tests.
    #[doc(hidden)]
    pub fn certificates_followed(&self) -> usize {
        self.cert_follow
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(0, |f| f.files.len())
    }
}

/// Builds again, from its configuration, each inbound whose files changed,
/// once they are quiet; under the lock changes take, as any other change.
async fn reload_changed(
    manager: Weak<RuntimeManager>,
    mut changes: tokio::sync::mpsc::Receiver<String>,
) {
    while let Some(first) = changes.recv().await {
        let mut changed = BTreeSet::from([first]);
        loop {
            match tokio::time::timeout(SETTLE, changes.recv()).await {
                Ok(Some(tag)) => {
                    changed.insert(tag);
                }
                Ok(None) => return,
                Err(_) => break,
            }
        }
        let Some(manager) = manager.upgrade() else {
            return;
        };
        let _update = manager.update.lock().await;
        for tag in changed {
            let config = match manager.inbound_manager.lock() {
                Ok(inbounds) => inbounds.config(&tag),
                Err(_) => return,
            };
            let Some(config) = config else {
                continue;
            };
            match manager.update_inbound_resources_locked(&config) {
                Ok(()) => info!("[{}] inbound: certificate read again from its files", tag),
                Err(e) => warn!(
                    "[{}] inbound: its certificate files are not taken, the certificate in use is kept: {:#}",
                    tag, e
                ),
            }
        }
    }
}
