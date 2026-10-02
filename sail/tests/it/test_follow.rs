//! What follows its own files does so without a reload of the whole
//! instance, as in sing-box: a local rule-set, even with the configuration
//! file watched; the configuration file itself still reloads it.
#![cfg(all(
    feature = "auto-reload",
    feature = "rule-set",
    feature = "outbound-direct"
))]

use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use serde_json::json;

use crate::common;

#[test]
fn a_local_rule_set_follows_its_file_without_a_reload() -> Result<()> {
    let dir = common::TempDir::new("follow-rule-set")?;
    let (config_path, rules_path) = (dir.join("config.json"), dir.join("ads.json"));
    let rules = |domains: &[&str]| {
        let rules: Vec<_> = domains.iter().map(|d| json!({ "domain": [d] })).collect();
        json!({ "version": 3, "rules": rules }).to_string()
    };
    std::fs::write(&rules_path, rules(&["a.example"]))?;
    let config = |level: &str| {
        json!({
            "log": { "level": level },
            "route": {
                "rule_set": [{ "type": "local", "tag": "ads", "format": "source", "path": rules_path }],
                "rules": [{ "rule_set": "ads", "action": "reject" }],
            },
            "outbounds": [{ "type": "direct" }],
        })
        .to_string()
    };
    std::fs::write(&config_path, config("info"))?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let id = 970;
    let path = config_path.to_string_lossy().to_string();
    let start = std::thread::spawn(move || {
        sail::start(
            id,
            sail::StartOptions {
                config: sail::Config::File(path),
                auto_reload: true,
                runtime_opt: sail::RuntimeOption::SingleThread,
                runtime: common::runtime_options(),
                host: Default::default(),
            },
        )
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sail::is_running(id) {
        ensure!(!start.is_finished(), "sail did not start");
        ensure!(Instant::now() < deadline, "sail did not start within 10s");
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = (|| {
        let manager = sail::runtime_manager(id).unwrap();
        let count = || -> usize {
            rt.block_on(manager.rule_sets())
                .iter()
                .find(|r| r.tag == "ads")
                .map_or(0, |r| r.rules)
        };
        ensure!(count() == 1, "the rule-set did not read");

        // The configuration file reloads it: how long a reload takes to
        // apply on this host is what the wait below scales from.
        let before = manager.reloads();
        let edited = Instant::now();
        std::fs::write(&config_path, config("warn"))?;
        let deadline = edited + Duration::from_secs(5);
        while manager.reloads() == before {
            ensure!(
                Instant::now() < deadline,
                "the configuration file did not reload it"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let took = edited.elapsed();
        let reloads = manager.reloads();

        // The rule-set file changes: that set alone is read again.
        std::fs::write(&rules_path, rules(&["a.example", "b.example"]))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while count() != 2 {
            ensure!(
                Instant::now() < deadline,
                "the rule-set did not follow its file"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // A reload it set off would have applied by now, with a margin.
        std::thread::sleep(Duration::from_secs(1).max(took * 10));
        ensure!(
            manager.reloads() == reloads,
            "a rule-set file reloaded the whole instance"
        );
        Ok(())
    })();
    sail::shutdown(id);
    let _ = start.join();
    result
}
