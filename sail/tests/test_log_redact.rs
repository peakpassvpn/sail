//! `log.redact`: with destinations, sources and processes redacted, no
//! line at INFO or above tells where a real connection went or came from.
//! A process of its own, since redaction is the process's, as the log
//! level is.

#![cfg(all(feature = "inbound-mixed", feature = "outbound-direct"))]
// Tests drive tasks of their own.
#![allow(clippy::disallowed_methods)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// Through the SOCKS5 server at `proxy`, to `host:port`; what was sent
/// comes back.
fn through(proxy: u16, host: &str, port: u16) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend(host.as_bytes());
    request.extend(port.to_be_bytes());
    s.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "connect refused: {:?}", reply);
    s.write_all(b"ping").unwrap();
    let mut echoed = [0u8; 4];
    s.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"ping");
}

#[test]
fn no_line_at_info_or_above_tells_where_a_connection_went() {
    // A server that echoes, reached by name.
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in echo.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 64];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    let proxy = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = serde_json::json!({
        // DEBUG lines are written too, but not redacted, and not scanned.
        "log": { "level": "debug", "redact": ["destination", "source", "process"] },
        "inbounds": [{ "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": proxy }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "final": "direct" }
    });
    let parsed = sail::config::from_string(&config.to_string()).unwrap();
    let log = sail::app::logger::InstanceLog::new(100_000);
    let rt_id = 1;
    let opts = sail::StartOptions {
        signals: false,
        config: sail::Config::Internal(Box::new(parsed)),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: Default::default(),
        host: sail::runtime::Host {
            log: Some(sail::app::logger::InstanceLogRef(log.clone())),
            cache_dir: Some(std::env::temp_dir().join(format!("sail-log-redact-{}", proxy))),
            ..Default::default()
        },
    };
    let start = std::thread::spawn(move || sail::start(rt_id, opts));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !sail::is_running(rt_id) {
        assert!(!start.is_finished(), "sail stopped: {:?}", start.join());
        assert!(std::time::Instant::now() < deadline, "sail did not start");
        std::thread::sleep(Duration::from_millis(20));
    }

    through(proxy, "localhost", echo_port);
    let lines = || {
        log.follow()
            .0
            .iter()
            .filter(|l| l.level <= tracing::Level::INFO)
            .map(|l| l.message.clone())
            .collect::<Vec<_>>()
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let handled = loop {
        if let Some(line) = lines().into_iter().find(|l| l.starts_with("handled ")) {
            break line;
        }
        assert!(std::time::Instant::now() < deadline, "{:?}", lines());
        std::thread::sleep(Duration::from_millis(20));
    };
    sail::shutdown(rt_id);
    let _ = start.join();

    // The connection's line is there, redacted, with the port kept.
    assert!(handled.contains("src=*"), "{}", handled);
    assert!(
        handled.ends_with(&format!("dst=*:{}", echo_port)),
        "{}",
        handled
    );
    assert!(!handled.contains("process="), "{}", handled);
    // No line at INFO or above names where it went, under any key.
    for line in lines() {
        assert!(!line.contains("localhost"), "{}", line);
    }
}
