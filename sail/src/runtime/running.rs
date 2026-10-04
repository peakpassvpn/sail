//! What an instance runs, kept to tell a reload that changes its inbounds
//! alone: then nothing else is rebuilt, and the outbounds, their sessions,
//! the groups and what they know, the DNS client and its cache are the
//! very ones that ran before.
//!
//! "The same" is said of the configuration as it is read, not of its text:
//! two files that differ in spacing, order of keys or defaults written out
//! are the same. What the comparison cannot see is a file the
//! configuration names whose content changed. Those sail watches itself
//! are taken as they change, with no reload: a local rule-set, where sail
//! is built to follow files (`auto-reload`). The others, read once when
//! what names them is built, are noted when they are read, by size and
//! time of modification, and a reload after one was written is no reload
//! of the inbounds alone: root certificates, an outbound's certificates
//! and keys, a provider's or a rule-set's file, the geo databases.

use std::path::PathBuf;

use super::stamp::{written_since, Stamp};
use super::RuntimeEnv;
use crate::config::Config;

pub(crate) struct Running {
    /// Without its inbounds and its users' limits, which a reload of the
    /// inbounds alone takes.
    config: Config,
    /// The files it names besides, as they were just before it was built.
    files: Vec<(PathBuf, Option<Stamp>)>,
}

/// `config` without what a reload of the inbounds alone changes.
fn but_inbounds(config: &Config) -> Config {
    let mut config = config.clone();
    config.inbounds.clear();
    config.user_limits.clear();
    config
}

impl Running {
    /// Of `config`, about to be built: its files are noted now, before
    /// they are read, so that one written while they are shows.
    pub(crate) fn of(config: &Config, env: &RuntimeEnv) -> Self {
        let config = but_inbounds(config);
        let files = files(&config, env)
            .into_iter()
            .map(|path| {
                let stamp = Stamp::of(&path);
                (path, stamp)
            })
            .collect();
        Running { config, files }
    }

    /// Whether `config` differs from what runs in its inbounds and its
    /// users' limits at most, with no file it names written since.
    pub(crate) fn differs_in_inbounds_alone(&self, config: &Config) -> bool {
        but_inbounds(config) == self.config
            && !self
                .files
                .iter()
                .any(|(path, read)| written_since(*read, path))
    }
}

/// The files `config`, without its inbounds, names and sail does not
/// watch: every `path` and `…_path` in it, and the geo databases its rules
/// read. Each as it stands and under the data directory: where one is
/// read from is its reader's to say, and a path that is not a file costs
/// nothing.
fn files(config: &Config, env: &RuntimeEnv) -> Vec<PathBuf> {
    let mut named = Vec::new();
    if let Ok(value) = serde_json::to_value(config) {
        walk(&value, &mut Vec::new(), &mut named);
    }
    let mut files: Vec<PathBuf> = named
        .iter()
        .flat_map(|name| [PathBuf::from(name), PathBuf::from(env.data_path(name))])
        .chain(
            crate::assets::required(config, env)
                .into_iter()
                .map(|asset| PathBuf::from(asset.path)),
        )
        .collect();
    files.sort();
    files.dedup();
    files
}

fn walk<'a>(value: &'a serde_json::Value, at: &mut Vec<&'a str>, named: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(fields) => {
            // The cache file is sail's own to write: it changes as it runs.
            if at.as_slice() == ["experimental", "cache_file"] {
                return;
            }
            // A local rule-set follows its file itself, where files are
            // followed: a write to it is taken already, with no reload.
            if cfg!(feature = "auto-reload")
                && at.as_slice() == ["route", "rule_set"]
                && fields.get("type").and_then(|t| t.as_str()) == Some("local")
            {
                return;
            }
            for (key, value) in fields {
                if key == "path" || key.ends_with("_path") {
                    match value {
                        serde_json::Value::String(path) => named.push(path.clone()),
                        serde_json::Value::Array(paths) => {
                            named.extend(paths.iter().filter_map(|p| p.as_str()).map(String::from))
                        }
                        _ => {}
                    }
                }
                at.push(key);
                walk(value, at, named);
                at.pop();
            }
        }
        // An entry of a list is at the list's place.
        serde_json::Value::Array(entries) => {
            for entry in entries {
                walk(entry, at, named);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: serde_json::Value) -> Config {
        Config::from_json(&json.to_string()).unwrap()
    }

    /// The inbounds and the users' limits may differ; anything else that
    /// does makes it another configuration, as does a file it names being
    /// written. The configuration is compared as read, not as written.
    #[test]
    fn only_the_inbounds_and_limits_may_differ() {
        let dir = std::env::temp_dir().join(format!("sail-running-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let roots = dir.join("roots.pem");
        std::fs::write(&roots, "first").unwrap();
        let with = |inbounds: serde_json::Value, rules: serde_json::Value| {
            config(serde_json::json!({
                "inbounds": inbounds,
                "outbounds": [{ "type": "direct", "tag": "direct" }],
                "route": { "rules": rules, "final": "direct" },
                "certificate": { "certificate_path": [roots] },
            }))
        };
        let socks =
            |tag: &str| serde_json::json!({ "type": "socks", "tag": tag, "listen_port": 0 });
        let env = RuntimeEnv::default();
        let none = serde_json::json!([]);
        let running = Running::of(&with(serde_json::json!([socks("a")]), none.clone()), &env);
        assert!(running
            .files
            .iter()
            .any(|(path, stamp)| path == &roots && stamp.is_some()));

        assert!(
            running.differs_in_inbounds_alone(&with(serde_json::json!([socks("a")]), none.clone()))
        );
        assert!(running.differs_in_inbounds_alone(&with(
            serde_json::json!([socks("a"), socks("b")]),
            none.clone()
        )));
        assert!(running.differs_in_inbounds_alone(&with(none.clone(), none.clone())));
        // A rule is not the inbounds.
        let rule = serde_json::json!([{ "port": [53], "outbound": "direct" }]);
        assert!(!running.differs_in_inbounds_alone(&with(serde_json::json!([socks("a")]), rule)));
        // A file it names, written since: what was read of it is stale.
        std::fs::write(&roots, "another, longer").unwrap();
        assert!(!running.differs_in_inbounds_alone(&with(serde_json::json!([socks("a")]), none)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The cache file, which sail writes as it runs, is not among the
    /// files a reload looks at; a path in a list is.
    #[test]
    fn the_files_named_are_those_sail_only_reads() {
        let mut named = Vec::new();
        let value = serde_json::json!({
            "experimental": { "cache_file": { "enabled": true, "path": "cache.db" } },
            "certificate": { "certificate_path": ["a.pem", "b.pem"] },
            "outbounds": [{ "tls": { "client_key_path": "key.pem" } }],
            "log": { "output": "sail.log" },
        });
        walk(&value, &mut Vec::new(), &mut named);
        named.sort();
        assert_eq!(named, ["a.pem", "b.pem", "key.pem"]);
    }
}
