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
