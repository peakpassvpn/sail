//! The corpus: configurations with the structure of public ones and every
//! value synthetic, each read and built as `sail -T` does, and what came of
//! it compared with `tests/corpus/expected.json`.
//!
//! A change to a front-end that changes an outcome shows here; when the
//! change is meant, `SAIL_CORPUS_UPDATE=1` writes the new outcomes.

#[cfg(all(
    feature = "config-surge",
    feature = "all-endpoints",
    feature = "rule-set",
    feature = "outbound-provider"
))]
#[test]
fn the_corpus_reads_as_expected() {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use serde_json::{json, Value};

    // What reading and building a configuration came to: read, with its
    // warnings counted, and built (`check`), or the first line of the
    // error; a panic is a bug.
    // Every way a configuration reaches sail reads it alike: a file (the
    // CLI, a reload, a check) and the same text from a host (the FFI's
    // start, reload and check), to the same configuration or the same
    // error. Compared here, from the read this test makes anyway; a Surge
    // profile that includes a file next to it is left out, as text has no
    // place to find one.
    fn alike(path: &Path, read: &anyhow::Result<sail::config::Config>) -> Option<String> {
        let text = std::fs::read_to_string(path).unwrap();
        if text
            .lines()
            .any(|l| l.trim_start().starts_with("#!include"))
        {
            return None;
        }
        let said = |r: &anyhow::Result<sail::config::Config>| match r {
            Ok(config) => format!("ok, warned {:?}", config.warnings),
            Err(e) => format!("{:#}", e),
        };
        let given = sail::config::from_string_for(&text, &sail::runtime::Host::default());
        let (file, given) = (said(read), said(&given));
        (file != given)
            .then(|| format!("{}: as a file {}; as text {}", path.display(), file, given))
    }

    fn outcome(path: &Path, differ: &mut Vec<String>) -> Value {
        // Relative paths are the data directory's: one of the entry's own,
        // as those with a cache file hold it locked while they build, and
        // written `<data_dir>`, for the outcome to be every machine's.
        let data_dir = std::env::temp_dir()
            .join("sail-corpus-data")
            .join(std::process::id().to_string())
            .join(path.file_name().unwrap());
        let host = sail::runtime::Host::default();
        let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sail::config::from_file_for(path.to_str().unwrap(), &host)
        }));
        if let Ok(read) = &read {
            differ.extend(alike(path, read));
        }
        let config = match read {
            Ok(Ok(config)) => config,
            Ok(Err(e)) => return json!({ "error": placed(&format!("{:#}", e), &data_dir) }),
            Err(panic) => return json!({ "panic": panic_message(panic) }),
        };
        let env = sail::runtime::RuntimeEnv {
            host: sail::runtime::Host {
                data_dir: Some(data_dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let placed = |e: anyhow::Error| placed(&format!("{:#}", e), &data_dir);
        let check = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sail::check_config(&config, &env)
        })) {
            Ok(Ok(())) => json!("ok"),
            Ok(Err(e)) => json!(placed(e)),
            Err(panic) => json!(format!("panic: {}", panic_message(panic))),
        };
        json!({ "ok": true, "warnings": config.warnings.len(), "check": check })
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files = Vec::new();
    for dir in ["sing-box", "clash", "surge"] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            let name = format!("{}/{}", dir, path.file_name().unwrap().to_string_lossy());
            files.push((name, path));
        }
    }
    // Read on every core: the files are many.
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut differ = Vec::new();
    let found: BTreeMap<String, Value> = std::thread::scope(|scope| {
        let workers: Vec<_> = files
            .chunks(files.len().div_ceil(threads).max(1))
            .map(|chunk| {
                scope.spawn(move || {
                    let mut differ = Vec::new();
                    let found = chunk
                        .iter()
                        .map(|(name, path)| (name.clone(), outcome(path, &mut differ)))
                        .collect::<Vec<_>>();
                    (found, differ)
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| {
                let (found, more) = w.join().unwrap();
                differ.extend(more);
                found
            })
            .collect()
    });
    assert!(differ.is_empty(), "{}", differ.join("\n"));
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir()
            .join("sail-corpus-data")
            .join(std::process::id().to_string()),
    );
    // An outcome that differs by system (a check only one system makes
    // comes first there) is kept for that system under `on`, beside the
    // one of the others.
    let expected_path = root.join("expected.json");
    let mut expected: BTreeMap<String, Value> =
        serde_json::from_str(&std::fs::read_to_string(&expected_path).unwrap()).unwrap();
    let os = std::env::consts::OS;
    let here = |entry: &Value| -> Value {
        match entry.get("on").and_then(|on| on.get(os)) {
            Some(variant) => variant.clone(),
            None => {
                let mut base = entry.clone();
                if let Some(map) = base.as_object_mut() {
                    map.remove("on");
                }
                base
            }
        }
    };
    if std::env::var_os("SAIL_CORPUS_UPDATE").is_some() {
        let mut written = BTreeMap::new();
        for (name, outcome) in &found {
            let entry = match expected.remove(name) {
                Some(mut entry) if entry.get("on").and_then(|on| on.get(os)).is_some() => {
                    entry["on"][os] = outcome.clone();
                    entry
                }
                Some(entry) => match entry.get("on") {
                    Some(on) => {
                        let mut entry = outcome.clone();
                        entry["on"] = on.clone();
                        entry
                    }
                    None => outcome.clone(),
                },
                None => outcome.clone(),
            };
            written.insert(name.clone(), entry);
        }
        let text = serde_json::to_string_pretty(&written).unwrap() + "\n";
        std::fs::write(&expected_path, text).unwrap();
        return;
    }
    let expected: BTreeMap<String, Value> =
        expected.iter().map(|(n, e)| (n.clone(), here(e))).collect();
    let names: BTreeSet<_> = expected.keys().chain(found.keys()).collect();
    let changed: Vec<_> = names
        .into_iter()
        .filter(|n| expected.get(*n) != found.get(*n))
        .map(|n| {
            format!(
                "{}: expected {}, found {}",
                n,
                expected.get(n).unwrap_or(&Value::Null),
                found.get(n).unwrap_or(&Value::Null)
            )
        })
        .collect();
    assert!(
        changed.is_empty(),
        "{} of the corpus read differently (SAIL_CORPUS_UPDATE=1 writes the new outcomes \
         when the change is meant):\n{}",
        changed.len(),
        changed.join("\n")
    );
}

#[cfg(all(
    feature = "config-surge",
    feature = "all-endpoints",
    feature = "rule-set",
    feature = "outbound-provider"
))]
/// An error's first line, the directories it names written as names: the
/// corpus's (a Surge profile's paths are its own) and the data directory.
fn placed(message: &str, data_dir: &std::path::Path) -> String {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    first_line(message)
        .replace(&corpus.display().to_string(), "<corpus>")
        .replace(&data_dir.display().to_string(), "<data_dir>")
}

#[cfg(all(
    feature = "config-surge",
    feature = "all-endpoints",
    feature = "rule-set",
    feature = "outbound-provider"
))]
fn first_line(message: &str) -> String {
    message.lines().next().unwrap_or_default().to_string()
}

#[cfg(all(
    feature = "config-surge",
    feature = "all-endpoints",
    feature = "rule-set",
    feature = "outbound-provider"
))]
fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    let message = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    first_line(&message)
}

/// The corpus's own examples (`own-*`), written here for the features the
/// upstream documentation shows: each is taken whole, read without a
/// warning and built, as its upstream takes it (reference.json).
#[cfg(all(
    feature = "config-surge",
    feature = "all-endpoints",
    feature = "rule-set",
    feature = "outbound-provider"
))]
#[test]
fn own_examples_are_taken_whole() {
    use std::path::Path;

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut problems = Vec::new();
    let mut seen = 0;
    for dir in ["sing-box", "clash", "surge"] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.starts_with("own-") {
                continue;
            }
            seen += 1;
            let data_dir = std::env::temp_dir()
                .join("sail-corpus-own")
                .join(std::process::id().to_string())
                .join(&name);
            let env = sail::runtime::RuntimeEnv {
                host: sail::runtime::Host {
                    data_dir: Some(data_dir),
                    ..Default::default()
                },
                ..Default::default()
            };
            match sail::config::from_file_for(path.to_str().unwrap(), &env.host) {
                Err(e) => problems.push(format!("{}/{}: {:#}", dir, name, e)),
                Ok(config) if !config.warnings.is_empty() => {
                    problems.push(format!("{}/{}: {}", dir, name, config.warnings.join("; ")))
                }
                Ok(config) => {
                    if let Err(e) = sail::check_config(&config, &env) {
                        problems.push(format!("{}/{}: {:#}", dir, name, e));
                    }
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir()
            .join("sail-corpus-own")
            .join(std::process::id().to_string()),
    );
    assert!(seen > 0, "no own example");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
