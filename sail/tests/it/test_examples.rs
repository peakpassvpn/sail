//! The examples of the configuration reference (website/examples): each is
//! read and built as `sail -T` does, without a warning.

#[cfg(all(
    feature = "inbound-tun",
    feature = "outbound-provider",
    feature = "outbound-network-group",
    feature = "outbound-vless",
    feature = "outbound-hysteria2",
    feature = "inbound-vless"
))]
#[test]
fn the_examples_are_read_and_built_without_a_warning() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../website/examples");
    let mut seen = 0;
    let mut problems = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("website/examples") {
        let path = entry.expect("an entry").path();
        // index.json gives their titles; it is no configuration.
        if path.extension().and_then(|e| e.to_str()) != Some("json")
            || path.file_name().and_then(|n| n.to_str()) == Some("index.json")
        {
            continue;
        }
        seen += 1;
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let text = std::fs::read_to_string(&path).expect("read");
        match sail::config::from_string(&text) {
            Err(e) => problems.push(format!("{}: {:#}", name, e)),
            Ok(config) if !config.warnings.is_empty() => {
                problems.push(format!("{}: {}", name, config.warnings.join("; ")))
            }
            Ok(config) => {
                if let Err(e) = sail::check_config(&config, &Default::default()) {
                    problems.push(format!("{}: {:#}", name, e));
                }
            }
        }
    }
    assert!(seen > 0, "no example in {}", dir.display());
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
