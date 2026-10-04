#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// A test that panics while an instance runs fails, rather than waiting for
// the instance forever as its runtime is dropped; and the instance is shut
// down when the test's thread ends.
#[cfg(feature = "outbound-direct")]
#[test]
fn a_test_that_panics_with_an_instance_running_fails_and_stops_it() {
    use std::time::Duration;
    let (tx, rx) = std::sync::mpsc::channel();
    let test = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let config = serde_json::json!({ "outbounds": [{ "type": "direct" }] });
        let ids = common::run_sail_instances(&rt, vec![config.to_string()]).unwrap();
        tx.send(ids[0]).unwrap();
        panic!("a failing assertion");
    });
    let id = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the instance started");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !test.is_finished() {
        assert!(
            std::time::Instant::now() < deadline,
            "the panicking test still runs after 20s"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(test.join().is_err(), "the test failed");
    assert!(!sail::is_running(id), "its instance was shut down");
}

/// The runtime IDs tests choose themselves are all in the harness's table,
/// no two of them equal, and none among those the harness hands out: two
/// instances under one ID, running at once, fail one another once in many
/// runs, and a clash is to fail here, every time.
#[test]
fn the_ids_tests_choose_are_their_own() {
    let ids = common::fixed_rt_id::ALL;
    for (i, id) in ids.iter().enumerate() {
        assert!(
            *id < common::FIRST_RT_ID,
            "{} is among the IDs the harness hands out",
            id
        );
        assert!(!ids[..i].contains(id), "{} is chosen twice", id);
    }
}

/// No test file names a runtime ID of its own: it takes one from
/// `common::next_rt_id`, or from the harness's table when the ID must be
/// known before the test runs. Read from the sources, where they are
/// (they are where the tests were built).
#[test]
fn no_test_names_a_runtime_id_of_its_own() {
    let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/it"));
    let Ok(files) = std::fs::read_dir(dir) else {
        return;
    };
    // With the whitespace taken out: an ID as a literal where an instance
    // is started or an ID is named.
    let named = [
        "sail::start(",
        "RuntimeId=",
        "letid=",
        "letrt_id=",
        "ID:u16=",
    ];
    for file in files.flatten() {
        let name = file.file_name().to_string_lossy().to_string();
        if !name.ends_with(".rs") || name == "common.rs" || name == "test_harness.rs" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(file.path()) else {
            continue;
        };
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        for what in named {
            for (at, _) in text.match_indices(what) {
                let next = text[at + what.len()..].chars().next();
                assert!(
                    !next.is_some_and(|c| c.is_ascii_digit()),
                    "{} names a runtime ID of its own (`{}` and a number): take it from \
                     common::next_rt_id, or put it in common::fixed_rt_id",
                    name,
                    what
                );
            }
        }
    }
}
