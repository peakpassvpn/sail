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

use crate::runtime::watch::FileWatcher;
use crate::RuntimeManager;

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
        let files = match self.inbound_manager.lock() {
            Ok(inbounds) => inbounds.resource_files(),
            Err(_) => return,
        };
        let mut follow = self.cert_follow.lock().unwrap_or_else(|e| e.into_inner());
        if follow.as_ref().map(|f| &f.files) == Some(&files) {
            return;
        }
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
        drop(tx);
        let task = self
            .handle
            .spawn(reload_changed(self.this.clone(), rx))
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
