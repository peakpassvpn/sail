//! The corpus: configurations with the structure of public ones and every
//! value synthetic, each read as `sail -T` reads it short of building, and
//! what came of it compared with `tests/corpus/expected.json`.
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

    use sail::config::Format;
    use serde_json::{json, Value};

    // What reading a configuration came to: read, with its warnings
    // counted, or the first line of the error; a panic is a bug.
    fn outcome(format: Format, text: &str) -> Value {
        match std::panic::catch_unwind(|| format.parse(text)) {
            Ok(Ok(config)) => json!({ "ok": true, "warnings": config.warnings.len() }),
            Ok(Err(e)) => {
                let message = format!("{:#}", e);
                json!({ "error": message.lines().next().unwrap_or_default() })
            }
            Err(panic) => {
                let message = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                json!({ "panic": message.lines().next().unwrap_or_default() })
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files = Vec::new();
    for (dir, format) in [
        ("sing-box", Format::SingBox),
        ("clash", Format::Clash),
        ("surge", Format::Surge),
    ] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            let name = format!("{}/{}", dir, path.file_name().unwrap().to_string_lossy());
            files.push((name, format, path));
        }
    }
    // Read on every core: the files are many.
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let found: BTreeMap<String, Value> = std::thread::scope(|scope| {
        let workers: Vec<_> = files
            .chunks(files.len().div_ceil(threads).max(1))
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|(name, format, path)| {
                            let text = std::fs::read_to_string(path).unwrap();
                            (name.clone(), outcome(*format, &text))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect()
    });
    let expected_path = root.join("expected.json");
    if std::env::var_os("SAIL_CORPUS_UPDATE").is_some() {
        let text = serde_json::to_string_pretty(&found).unwrap() + "\n";
        std::fs::write(&expected_path, text).unwrap();
        return;
    }
    let expected: BTreeMap<String, Value> =
        serde_json::from_str(&std::fs::read_to_string(&expected_path).unwrap()).unwrap();
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
