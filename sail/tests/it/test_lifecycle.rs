//! Starting, stopping and reloading instances by id: a stop while an
//! instance starts, an id taken twice, and calls that must not wait on an
//! instance busy reloading.
#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "rule-set"
))]

use std::sync::mpsc;
use std::time::Duration;

use crate::common;

// These tests start their instances themselves, not through the harness:
// the start, its result and the ID it is given are what they test. Their
// IDs are the harness's table's, and each instance is shut down with its
// test's thread should the test fail before it stops it.
use crate::common::fixed_rt_id::{
    LIFECYCLE_BYSTANDER as BYSTANDER, LIFECYCLE_LOGGED_A as LOGGED_A,
    LIFECYCLE_LOGGED_B as LOGGED_B, LIFECYCLE_NO_MODES as NO_MODES,
    LIFECYCLE_RELOADING as RELOADING, LIFECYCLE_STOPPED_STARTING as STOPPED_STARTING,
    LIFECYCLE_TAKEN_TWICE as TAKEN_TWICE,
};

/// A server that takes connections and never answers: a download from it
/// hangs. Tells `accepted` of each connection.
fn hanging_server() -> (u16, mpsc::Receiver<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (accepted, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            held.push(stream);
            let _ = accepted.send(());
        }
    });
    (port, rx)
}

fn config(port: u16, rule_set_port: Option<u16>) -> serde_json::Value {
    let mut config = serde_json::json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct" }],
    });
    if let Some(rule_set_port) = rule_set_port {
        config["route"] = serde_json::json!({
            "rule_set": [{
                "type": "remote", "tag": "s", "format": "source",
                "url": format!("http://127.0.0.1:{}/s.json", rule_set_port),
            }],
            "rules": [{ "rule_set": "s", "action": "reject" }],
        });
    }
    config
}

fn options(config: sail::Config) -> sail::StartOptions {
    sail::StartOptions {
        config,
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: common::runtime_options(),
        host: Default::default(),
    }
}

/// Starts `id` with `log` for its log lines, on a multi-threaded runtime.
fn start_logged(
    id: sail::RuntimeId,
    config: String,
    log: std::sync::Arc<sail::app::logger::InstanceLog>,
) -> mpsc::Receiver<Result<(), sail::Error>> {
    let (tx, rx) = mpsc::channel();
    common::stops_with_its_thread(id);
    std::thread::spawn(move || {
        let mut options = options(sail::Config::Str(config));
        options.runtime_opt = sail::RuntimeOption::MultiThread(2, 2 * 1024 * 1024);
        options.host.log = Some(sail::app::logger::InstanceLogRef(log));
        let _ = tx.send(sail::start(id, options));
    });
    rx
}

/// Starts `id` on a thread of its own; its result comes on the receiver.
fn start(id: sail::RuntimeId, config: sail::Config) -> mpsc::Receiver<Result<(), sail::Error>> {
    let (tx, rx) = mpsc::channel();
    common::stops_with_its_thread(id);
    std::thread::spawn(move || {
        let _ = tx.send(sail::start(id, options(config)));
    });
    rx
}

fn wait_running(id: sail::RuntimeId) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !sail::is_running(id) {
        assert!(std::time::Instant::now() < deadline, "{} did not start", id);
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Stops `id` and waits for its start to return.
fn stop(id: sail::RuntimeId, started: mpsc::Receiver<Result<(), sail::Error>>) {
    assert!(sail::shutdown(id));
    started
        .recv_timeout(Duration::from_secs(10))
        .expect("the instance did not stop")
        .unwrap();
    assert!(!sail::is_running(id));
}

#[test]
fn a_stop_while_an_instance_starts_ends_the_start() {
    let (rule_set_port, accepted) = hanging_server();
    let [port] = common::free_ports();
    let started = start(
        STOPPED_STARTING,
        sail::Config::Str(config(port, Some(rule_set_port)).to_string()),
    );
    // Starting: waiting on its rule-set.
    accepted
        .recv_timeout(Duration::from_secs(10))
        .expect("the rule-set was not asked for");
    assert!(!sail::is_running(STOPPED_STARTING));
    assert!(sail::shutdown(STOPPED_STARTING), "the stop was not taken");
    let result = started
        .recv_timeout(Duration::from_secs(5))
        .expect("the start did not end");
    assert!(result.is_ok(), "{:?}", result);
    assert!(!sail::is_running(STOPPED_STARTING));
    // Nothing is left of it: the id starts again.
    let [port] = common::free_ports();
    let again = start(
        STOPPED_STARTING,
        sail::Config::Str(config(port, None).to_string()),
    );
    wait_running(STOPPED_STARTING);
    stop(STOPPED_STARTING, again);
}

#[test]
fn an_id_starting_or_running_is_not_taken_again() {
    let [port, other] = common::free_ports();
    let first = start(
        TAKEN_TWICE,
        sail::Config::Str(config(port, None).to_string()),
    );
    wait_running(TAKEN_TWICE);
    let second = sail::start(
        TAKEN_TWICE,
        options(sail::Config::Str(config(other, None).to_string())),
    );
    assert!(
        matches!(second, Err(sail::Error::InUse(TAKEN_TWICE))),
        "{:?}",
        second.map(|_| ())
    );
    // The first is untouched, and stops as before.
    assert!(sail::is_running(TAKEN_TWICE));
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
    stop(TAKEN_TWICE, first);
}

#[test]
fn an_instance_reloading_leaves_every_other_call_free() {
    let (rule_set_port, accepted) = hanging_server();
    let dir = common::TempDir::new("sail-reloading").unwrap();
    let path = dir.join("config.json");
    let [port, bystander_port] = common::free_ports();
    std::fs::write(&path, config(port, None).to_string()).unwrap();
    let reloading = start(
        RELOADING,
        sail::Config::File(path.to_str().unwrap().to_string()),
    );
    wait_running(RELOADING);
    let bystander = start(
        BYSTANDER,
        sail::Config::Str(config(bystander_port, None).to_string()),
    );
    wait_running(BYSTANDER);

    // A reload that hangs on its new rule-set.
    std::fs::write(&path, config(port, Some(rule_set_port)).to_string()).unwrap();
    let (reloaded_tx, reloaded) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = reloaded_tx.send(sail::reload(RELOADING));
    });
    accepted
        .recv_timeout(Duration::from_secs(10))
        .expect("the reload did not ask for its rule-set");

    // Meanwhile the registry answers, for this instance and another.
    let (answered_tx, answered) = mpsc::channel();
    std::thread::spawn(move || {
        let running = (sail::is_running(RELOADING), sail::is_running(BYSTANDER));
        let _ = answered_tx.send(running);
    });
    assert_eq!(
        answered.recv_timeout(Duration::from_secs(2)),
        Ok((true, true)),
        "the registry waited on the reload"
    );
    stop(BYSTANDER, bystander);

    // Stopped while it reloads: the reload ends, with an error.
    stop(RELOADING, reloading);
    let reload = reloaded
        .recv_timeout(Duration::from_secs(10))
        .expect("the reload did not end");
    assert!(reload.is_err());
}

#[test]
fn each_instance_logs_to_its_own_log() {
    use sail::app::logger::InstanceLog;
    let [port_a, port_b] = common::free_ports();
    let (log_a, log_b) = (InstanceLog::new(100), InstanceLog::new(100));
    let a = start_logged(LOGGED_A, config(port_a, None).to_string(), log_a.clone());
    let b = start_logged(LOGGED_B, config(port_b, None).to_string(), log_b.clone());
    wait_running(LOGGED_A);
    wait_running(LOGGED_B);
    // Lines logged on each instance's threads, a worker's and a blocking
    // one's, at a level no other test's configuration leaves out.
    for id in [LOGGED_A, LOGGED_B] {
        let handle = sail::runtime_manager(id).unwrap().handle().clone();
        handle.block_on(async move {
            tokio::spawn(async move { tracing::error!(target: "sail::test", "worker {}", id) })
                .await
                .unwrap();
            tokio::task::spawn_blocking(
                move || tracing::error!(target: "sail::test", "blocking {}", id),
            )
            .await
            .unwrap();
        });
    }
    let lines = |log: &InstanceLog| -> Vec<String> {
        log.follow().0.iter().map(|l| l.message.clone()).collect()
    };
    let (a_lines, b_lines) = (lines(&log_a), lines(&log_b));
    for (lines, own, other) in [
        (&a_lines, LOGGED_A, LOGGED_B),
        (&b_lines, LOGGED_B, LOGGED_A),
    ] {
        for kind in ["worker", "blocking"] {
            assert!(
                lines.contains(&format!("{} {}", kind, own)),
                "{} {} missing: {:?}",
                kind,
                own,
                lines
            );
            assert!(
                !lines.contains(&format!("{} {}", kind, other)),
                "{:?}",
                lines
            );
        }
    }
    stop(LOGGED_A, a);
    stop(LOGGED_B, b);
    // What a stopped instance logged stays the host's to read.
    assert!(lines(&log_a).contains(&format!("worker {}", LOGGED_A)));
}

/// As sing-box: without a Clash API in its configuration, an instance a
/// host does not give modes to (as sail-cli does not) has none, and a
/// `clash_mode` rule never matches.
#[test]
fn without_a_clash_api_an_instance_has_no_mode_unless_its_host_gives_it() {
    let [port] = common::free_ports();
    let config = serde_json::json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct" }],
        "route": { "rules": [{ "clash_mode": "Rule", "action": "reject" }] },
    })
    .to_string();
    let started = start(NO_MODES, sail::Config::Str(config));
    wait_running(NO_MODES);
    let rm = sail::runtime_manager(NO_MODES).unwrap();
    assert_eq!(rm.mode(), None);
    assert!(matches!(
        rm.set_mode("Rule"),
        Err(sail::control::ControlError::NoModes)
    ));
    // The rule names the mode a host with modes would start in: here it
    // never matches, so the connection goes through.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
        tokio::spawn(serve);
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(echo),
            ..Default::default()
        };
        // sail answers the SOCKS request before it routes: a rule that
        // rejects shows only in the data.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = common::new_socks_stream("127.0.0.1", port, &sess, None, None)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut back),
        )
        .await;
        assert!(
            matches!(read, Ok(Ok(_))) && &back == b"ping",
            "the clash_mode rule matched"
        );
    });
    stop(NO_MODES, started);
}
