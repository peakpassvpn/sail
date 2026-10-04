//! What an instance runs, kept to tell a reload that changes its inbounds
//! alone: then nothing else is rebuilt, and the outbounds, their sessions,
//! the groups and what they know, the DNS client and its cache are the
//! very ones that ran before.
//!
//! Only a digest of it is kept, 128 bits: the configuration itself, with
//! tens of thousands of rules, would be megabytes held for a comparison.
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

use std::hash::Hasher;
use std::path::PathBuf;

use super::stamp::{written_since, Stamp};
use super::RuntimeEnv;
use crate::config::{model::Rule, Config};

pub(crate) struct Running {
    /// Of the configuration without its inbounds and its users' limits,
    /// which a reload of the inbounds alone takes. None for one that could
    /// not be digested: nothing is then the same as it.
    digest: Option<(u64, u64)>,
    /// The files it names besides, as they were just before it was built.
    files: Vec<(PathBuf, Option<Stamp>)>,
}

/// Two hashes of all that is written to it, the second begun with a byte
/// the first is not: 128 bits together. A change of the configuration
/// that both miss is not a thing that happens; one that a single 64-bit
/// hash misses, among every reload of every instance, could be, and would
/// leave a real change unapplied without a word.
struct Digest(
    std::collections::hash_map::DefaultHasher,
    std::collections::hash_map::DefaultHasher,
);

impl Digest {
    fn new() -> Self {
        let mut second = std::collections::hash_map::DefaultHasher::new();
        second.write_u8(0x5a);
        Digest(std::collections::hash_map::DefaultHasher::new(), second)
    }

    fn finish(&self) -> (u64, u64) {
        (self.0.finish(), self.1.finish())
    }
}

impl std::io::Write for Digest {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf);
        self.1.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The digest of `config` without what a reload of the inbounds alone
/// changes: every other field as it is written out, and those that are
/// not written out besides. The fields are named one by one, with no
/// rest: one added to the configuration does not build until it is said
/// here whether it takes part.
fn digest(config: &Config) -> Option<(u64, u64)> {
    use std::io::Write;
    let Config {
        log,
        dns,
        inbounds: _,
        outbounds,
        endpoints,
        route,
        api,
        clash_api,
        experimental,
        certificate,
        http_clients,
        outbound_providers,
        user_limits: _,
        warnings,
    } = config;
    let mut digest = Digest::new();
    // Each under its name, so that what moves from one to another shows.
    macro_rules! written {
        ($($field:ident),*) => {$(
            digest.write_all(stringify!($field).as_bytes()).ok()?;
            serde_json::to_writer(&mut digest, $field).ok()?;
        )*};
    }
    written!(
        log,
        dns,
        outbounds,
        endpoints,
        route,
        api,
        clash_api,
        experimental,
        certificate,
        http_clients,
        outbound_providers,
        warnings
    );
    // What is not written out (`serde(skip)`, `skip_serializing`): the
    // test below counts those there are, and fails when one is added.
    serde_json::to_writer(&mut digest, &experimental.clash_api).ok()?;
    unwritten(&route.rules, &mut digest)?;
    Some(digest.finish())
}

/// The fields of route rules that are not written out, a DNS rule's own,
/// of `rules` and of the rules logical ones combine.
fn unwritten(rules: &[Rule], digest: &mut Digest) -> Option<()> {
    use std::io::Write;
    for rule in rules {
        write!(
            digest,
            "{:?}",
            (
                rule.ip_accept_any,
                &rule.response_rcode,
                &rule.response_answer,
                &rule.response_ns,
                &rule.response_extra,
                &rule.match_response,
                // Inline lines a Clash or Surge lowering merged, and the
                // index each rule had: what a match reports.
                &rule.lines,
                &rule.index,
            )
        )
        .ok()?;
        unwritten(&rule.rules, digest)?;
    }
    Some(())
}

impl Running {
    /// Of `config`, about to be built: its files are noted now, before
    /// they are read, so that one written while they are shows.
    pub(crate) fn of(config: &Config, env: &RuntimeEnv) -> Self {
        let files = files(config, env)
            .into_iter()
            .map(|path| {
                let stamp = Stamp::of(&path);
                (path, stamp)
            })
            .collect();
        Running {
            digest: digest(config),
            files,
        }
    }

    /// Whether `config` differs from what runs in its inbounds and its
    /// users' limits at most, with no file it names written since.
    pub(crate) fn differs_in_inbounds_alone(&self, config: &Config) -> bool {
        self.digest.is_some()
            && digest(config) == self.digest
            && !self
                .files
                .iter()
                .any(|(path, read)| written_since(*read, path))
    }
}

/// The files `config`, its inbounds aside, names and sail does not watch:
/// every `path` and `…_path` in it, and the geo databases its rules read.
/// Each as it stands and under the data directory: where one is read from
/// is its reader's to say, and a path that is not a file costs nothing.
/// The rules themselves name no file, and are not gone through: there may
/// be tens of thousands.
fn files(config: &Config, env: &RuntimeEnv) -> Vec<PathBuf> {
    let mut named = Vec::new();
    let mut look = |at: &'static str, value: serde_json::Result<serde_json::Value>| {
        if let Ok(value) = value {
            walk(&value, &mut vec![at], &mut named);
        }
    };
    look("log", serde_json::to_value(&config.log));
    look("dns", serde_json::to_value(&config.dns.servers));
    look("outbounds", serde_json::to_value(&config.outbounds));
    look("endpoints", serde_json::to_value(&config.endpoints));
    look("api", serde_json::to_value(&config.api));
    look("clash_api", serde_json::to_value(&config.clash_api));
    look("experimental", serde_json::to_value(&config.experimental));
    look("certificate", serde_json::to_value(&config.certificate));
    look("http_clients", serde_json::to_value(&config.http_clients));
    look(
        "outbound_providers",
        serde_json::to_value(&config.outbound_providers),
    );
    // A rule-set's files, each tag's: a local one that follows its file
    // itself, where files are followed, is taken as it changes already.
    for set in &config.route.rule_set {
        let followed = cfg!(feature = "auto-reload")
            && set.kind == crate::config::rule_set::RuleSetKind::Local;
        let paths = [(!followed).then_some(&set.path), Some(&set.initial_path)];
        for path in paths.into_iter().flatten().flatten() {
            for tag in &set.tag {
                named.push(crate::config::rule_set::RuleSet::for_tag(path, tag));
            }
        }
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

    /// Every field but the inbounds and the users' limits takes part in
    /// the digest: what an outbound is given, a rule, and what is not
    /// written out when the configuration is, a rule's own fields for a
    /// DNS response among them.
    #[test]
    fn the_digest_takes_every_field_but_the_inbounds() {
        let with = |inbounds: serde_json::Value, password: &str| {
            config(serde_json::json!({
                "inbounds": inbounds,
                "outbounds": [
                    { "type": "direct", "tag": "direct" },
                    { "type": "trojan", "tag": "t", "server": "192.0.2.1",
                      "server_port": 443, "password": password },
                ],
                "route": { "rules": [{ "port": [53], "outbound": "direct" }], "final": "direct" },
            }))
        };
        let none = serde_json::json!([]);
        let base = with(none.clone(), "one");
        let of = |config: &Config| digest(config).expect("a configuration is digested");
        // The inbounds and the limits take no part.
        let socks = serde_json::json!([{ "type": "socks", "tag": "a", "listen_port": 0 }]);
        assert_eq!(of(&with(socks, "one")), of(&base));
        let mut limited = base.clone();
        limited.user_limits.insert("u".into(), Default::default());
        assert_eq!(of(&limited), of(&base));
        // A secret does: it is digested as it is, not as it is shown.
        assert_ne!(of(&with(none, "another")), of(&base));
        // What is not written out does.
        let changed = |change: fn(&mut Config)| {
            let mut config = base.clone();
            change(&mut config);
            of(&config)
        };
        assert_ne!(
            changed(|c| c.route.rules[0].ip_accept_any = true),
            of(&base)
        );
        assert_ne!(
            changed(|c| c.route.rules[0].response_rcode = Some(3)),
            of(&base)
        );
        assert_ne!(
            changed(|c| c.route.rules[0].response_answer.push("a".into())),
            of(&base)
        );
        assert_ne!(changed(|c| c.warnings.push("w".into())), of(&base));
        // The same twice is the same, and the two halves differ.
        assert_eq!(of(&base), of(&base.clone()));
        assert_ne!(of(&base).0, of(&base).1);
    }

    /// The fields of the configuration that are not written out are
    /// digested by hand in `digest` and `unwritten`. One more of them, and
    /// this fails: say there what it is, then count it here.
    #[test]
    fn what_is_not_written_out_is_counted() {
        let model = include_str!("../config/model.rs");
        // `Config::warnings`, six fields of `Rule` that are a DNS rule's,
        // and `Rule::lines` and `Rule::index`, a lowering's merge.
        assert_eq!(model.matches("#[serde(skip)]").count(), 9);
        // `Experimental::clash_api`.
        assert_eq!(model.matches("skip_serializing)]").count(), 1);
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
