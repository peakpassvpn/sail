//! `--managed-update`: a Surge profile's `#!MANAGED-CONFIG`, kept up to
//! date. Once its interval has passed, the profile is fetched again,
//! loaded as a start would load it, put in place of the file and reloaded.
//! One that does not load, or that the instance refuses, leaves the one in
//! place, and the update is tried again sooner than the interval. The
//! instance serves the profile in place meanwhile, strict or not: Surge
//! asks for an update to a strict profile past its interval before using
//! it, sail never stops serving for one (website/src/content/docs/cli.md).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sail::config::surge::Managed;

/// The shortest interval taken: a profile that asks for less is fetched
/// once a minute. A judgment value: often enough for a profile its
/// provider changes by the minute, and no more load on its server.
const SHORTEST: Duration = Duration::from_secs(60);

/// When an update that failed is tried again: after a minute, then each
/// time twice as late, up to the interval or an hour, whichever is
/// sooner. Judgment values: a server down for a moment is soon seen back,
/// one down for long is not asked every minute.
const FIRST_RETRY: Duration = Duration::from_secs(60);
const LATEST_RETRY: Duration = Duration::from_secs(3600);

/// The file in the cache directory that keeps when the profile was last
/// updated, and from where.
const STATE: &str = "managed-config.json";

pub(crate) struct Updater {
    config: PathBuf,
    cache_dir: PathBuf,
    env: sail::runtime::RuntimeEnv,
    fetch_includes: bool,
    managed: Managed,
    /// The updates that failed in a row.
    failures: u32,
    rt: tokio::runtime::Runtime,
}

impl Updater {
    /// The updater of the profile `config`, which must be a Surge profile
    /// with a `#!MANAGED-CONFIG` line; it keeps its state in `cache_dir`.
    pub(crate) fn new(
        config: &str,
        cache_dir: Option<&str>,
        env: sail::runtime::RuntimeEnv,
        fetch_includes: bool,
    ) -> Result<Updater, String> {
        if sail::config::Format::of_file(config).ok() != Some(sail::config::Format::Surge) {
            return Err(format!(
                "{}: only a Surge profile (.conf) is managed",
                config
            ));
        }
        let cache_dir = cache_dir
            .ok_or("when it was last updated is kept in --cache-dir, which is not given")?;
        let text = std::fs::read_to_string(config).map_err(|e| format!("{}: {}", config, e))?;
        let managed = sail::config::surge::managed(&text).ok_or_else(|| {
            format!(
                "{}: not a managed profile: it has no #!MANAGED-CONFIG line with a URL",
                config
            )
        })?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("cannot start a runtime: {}", e))?;
        Ok(Updater {
            config: config.into(),
            cache_dir: cache_dir.into(),
            env,
            fetch_includes,
            managed,
            failures: 0,
            rt,
        })
    }

    /// Before the instance starts: updates the profile if it is due. One
    /// that fails is said, and the profile in place is started with.
    pub(crate) fn update_at_start(&mut self) {
        if SystemTime::now() < self.due() {
            return;
        }
        match self.update(false) {
            Ok(Some(_)) => println!(
                "managed profile: updated from {}",
                sail::common::redact::url(&self.managed.url)
            ),
            Ok(None) => println!(
                "managed profile: the profile fetched from {} is no longer managed; it is not updated again",
                sail::common::redact::url(&self.managed.url)
            ),
            Err(e) => {
                self.failures += 1;
                println!("{}", self.failed(&e));
            }
        }
    }

    /// Updates the profile as it falls due, the instance running, until
    /// the profile fetched is no longer managed.
    pub(crate) fn run(mut self) {
        loop {
            std::thread::sleep(self.wait());
            match self.update(true) {
                Ok(Some(_)) => {
                    self.failures = 0;
                    tracing::info!(
                        "managed profile: updated from {} and reloaded",
                        sail::common::redact::url(&self.managed.url)
                    );
                }
                Ok(None) => {
                    tracing::info!(
                        "managed profile: the profile fetched from {} is no longer managed; it is not updated again",
                        sail::common::redact::url(&self.managed.url)
                    );
                    return;
                }
                Err(e) => {
                    self.failures += 1;
                    let said = self.failed(&e);
                    match self.managed.strict && SystemTime::now() >= self.due() {
                        true => tracing::error!("{}", said),
                        false => tracing::warn!("{}", said),
                    }
                }
            }
        }
    }

    /// How long until the next update: until it is due, or, after a
    /// failure, until it is tried again.
    fn wait(&self) -> Duration {
        match self.failures {
            0 => self
                .due()
                .duration_since(SystemTime::now())
                .unwrap_or_default(),
            n => retry_after(n, self.interval()),
        }
    }

    fn interval(&self) -> Duration {
        self.managed.interval.max(SHORTEST)
    }

    /// When the profile is next due: its interval after it was last
    /// updated from its URL; now, when it never was.
    fn due(&self) -> SystemTime {
        self.last_update()
            .map_or(UNIX_EPOCH, |at| at + self.interval())
    }

    fn last_update(&self) -> Option<SystemTime> {
        let state = std::fs::read(self.cache_dir.join(STATE)).ok()?;
        let state: serde_json::Value = serde_json::from_slice(&state).ok()?;
        if state["url"].as_str() != Some(self.managed.url.as_str()) {
            return None;
        }
        Some(UNIX_EPOCH + Duration::from_secs(state["updated"].as_u64()?))
    }

    fn record_update(&self) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let state = serde_json::json!({ "url": self.managed.url, "updated": now });
        let path = self.cache_dir.join(STATE);
        sail::fetch::write_atomically(&path, state.to_string().as_bytes())
            .map_err(|e| format!("{}: {:#}", path.display(), e))
    }

    /// What a failed update is said with.
    fn failed(&self, e: &str) -> String {
        let past_due = SystemTime::now() >= self.due();
        format!(
            "managed profile: the update from {} failed: {}; {}the profile in place goes on \
             serving, and the update is tried again in {} s",
            sail::common::redact::url(&self.managed.url),
            e,
            match (self.managed.strict, past_due) {
                (true, true) => "it is strict and past its interval: ",
                _ => "",
            },
            retry_after(self.failures.max(1), self.interval()).as_secs()
        )
    }

    /// Fetches the profile, loads it, and puts it in place of the file,
    /// reloading the instance when it is `running`. The profile in place
    /// is left as it was when any of these fails. What the profile put in
    /// place says of its updates: none when it is no longer managed.
    fn update(&mut self, running: bool) -> Result<Option<Managed>, String> {
        let url = self
            .env
            .host
            .download_url(&self.managed.url)
            .map_err(|e| format!("{:#}", e))?;
        let body = self
            .rt
            .block_on(sail::fetch::fetch(&url, &Default::default()))
            .map_err(|e| format!("{:#}", e))?;
        let text = String::from_utf8(body).map_err(|_| "what it gave is not text".to_string())?;
        // Beside the profile, as a .conf: what it names by path is found
        // where the profile's own is.
        let name = self
            .config
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let next = self
            .config
            .with_file_name(format!(".{}.managed.conf", name));
        std::fs::write(&next, &text).map_err(|e| format!("{}: {}", next.display(), e))?;
        let taken = self.take(&next, &text, running);
        let _ = std::fs::remove_file(&next);
        taken?;
        let managed = sail::config::surge::managed(&text);
        if let Some(managed) = &managed {
            self.managed = managed.clone();
        }
        self.record_update()?;
        Ok(managed)
    }

    /// Loads `next`, the profile fetched, and puts it in place.
    fn take(&self, next: &Path, text: &str, running: bool) -> Result<(), String> {
        let next = next.to_string_lossy();
        if self.fetch_includes {
            crate::fetch_includes(&next, self.cache_dir.to_str())?;
        }
        sail::test_config_with_warnings(&next, &self.env)
            .map_err(|e| format!("the profile fetched does not load: {:#}", e))?;
        let before =
            std::fs::read(&self.config).map_err(|e| format!("{}: {}", self.config.display(), e))?;
        sail::fetch::write_atomically(&self.config, text.as_bytes())
            .map_err(|e| format!("{}: {:#}", self.config.display(), e))?;
        if running {
            if let Err(e) = sail::reload(0) {
                sail::fetch::write_atomically(&self.config, &before)
                    .map_err(|e| format!("{}: {:#}", self.config.display(), e))?;
                return Err(format!(
                    "the instance did not take the profile fetched: {}; the one before is back in place",
                    e
                ));
            }
        }
        Ok(())
    }
}

/// How long after the `failures`th failure in a row an update is tried
/// again, for a profile updated every `interval`.
fn retry_after(failures: u32, interval: Duration) -> Duration {
    let latest = interval.min(LATEST_RETRY);
    FIRST_RETRY
        .checked_mul(1 << failures.saturating_sub(1).min(16))
        .unwrap_or(latest)
        .min(latest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_update_is_tried_again_sooner_and_sooner_less() {
        let day = Duration::from_secs(86_400);
        let minutes = |m: u64| Duration::from_secs(m * 60);
        assert_eq!(retry_after(1, day), minutes(1));
        assert_eq!(retry_after(2, day), minutes(2));
        assert_eq!(retry_after(6, day), minutes(32));
        assert_eq!(retry_after(7, day), minutes(60));
        assert_eq!(retry_after(1000, day), minutes(60));
        // Never later than the interval.
        assert_eq!(retry_after(3, minutes(3)), minutes(3));
        assert_eq!(retry_after(1, SHORTEST), SHORTEST);
    }
}
