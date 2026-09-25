use std::sync::mpsc;
use std::time::Duration;

/// An inbound whose port is taken fails the start, instead of the instance
/// running without it.
#[cfg(feature = "inbound-socks")]
#[test]
fn a_port_in_use_fails_the_start() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let config = format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {} }}],
            "outbounds": [{{ "type": "direct" }}]
        }}"#,
        port
    );

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let opts = leaf::StartOptions {
            config: leaf::Config::Str(config),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
            runtime: Default::default(),
            host: Default::default(),
        };
        let _ = tx.send(leaf::start(1000, opts));
    });

    // A successful start would run until shut down.
    let result = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the start should have failed instead of running");
    let err = result.err().expect("the start should have failed");
    assert!(
        err.to_string()
            .contains(&format!("listen tcp 127.0.0.1:{}", port)),
        "{}",
        err
    );
    drop(taken);
}
