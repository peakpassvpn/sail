//! `inbound.max_connections`: the sessions living at once. One more waits
//! for a place and is then refused, with a warning; a place given back is
//! taken again.

#![cfg(all(feature = "inbound-socks", feature = "outbound-direct"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::common;

fn echo_server() -> u16 {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = echo.local_addr().unwrap().port();
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
    port
}

/// A SOCKS5 connection through `proxy` to 127.0.0.1:`port`. The proxy
/// replies once it has connected, which a session without a place never
/// does: it is closed instead, an error here.
fn connect(proxy: u16, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend(port.to_be_bytes());
    s.write_all(&request)?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    Ok(s)
}

/// The REP a SOCKS5 connect through `proxy` to 127.0.0.1:`port` is answered
/// with; none, closed without one.
fn socks_reply(proxy: u16, port: u16) -> Option<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.write_all(&[5, 1, 0]).ok()?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).ok()?;
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend(port.to_be_bytes());
    s.write_all(&request).ok()?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).ok()?;
    Some(reply[1])
}

fn echoes(s: &mut TcpStream) -> bool {
    if s.write_all(b"ping").is_err() {
        return false;
    }
    let mut buf = [0u8; 4];
    matches!(s.read_exact(&mut buf), Ok(()) if &buf == b"ping")
}

#[test]
fn sessions_beyond_the_limit_wait_then_are_refused() {
    let echo = echo_server();
    let proxy = common::free_port();
    let config = serde_json::json!({
        "log": { "level": "info" },
        "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": proxy }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "final": "direct" }
    });
    let mut runtime = common::runtime_options();
    runtime.set("inbound.max_connections", "2").unwrap();
    let log = sail::app::logger::InstanceLog::new(1000);
    let rt_id = common::next_rt_id();
    let opts = sail::StartOptions {
        config: sail::Config::Internal(Box::new(
            sail::config::from_string(&config.to_string()).unwrap(),
        )),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime,
        host: sail::runtime::Host {
            log: Some(sail::app::logger::InstanceLogRef(log.clone())),
            cache_dir: Some(std::env::temp_dir().join(format!("sail-session-cap-{}", proxy))),
            ..Default::default()
        },
    };
    let start = std::thread::spawn(move || sail::start(rt_id, opts));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sail::is_running(rt_id) {
        assert!(!start.is_finished(), "sail stopped: {:?}", start.join());
        assert!(Instant::now() < deadline, "sail did not start");
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut a = connect(proxy, echo).unwrap();
    let mut b = connect(proxy, echo).unwrap();
    assert!(echoes(&mut a) && echoes(&mut b));
    // A third waits for a place, about a second, and is then closed.
    let began = Instant::now();
    let reply = socks_reply(proxy, echo);
    assert_eq!(reply, Some(1), "a third session: REP 1, general failure");
    let waited = began.elapsed();
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_secs(4),
        "{:?}",
        waited
    );
    // A place given back is taken.
    drop(a);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut d = loop {
        if let Ok(mut d) = connect(proxy, echo) {
            if echoes(&mut d) {
                break d;
            }
        }
        assert!(Instant::now() < deadline, "the place was not given back");
    };
    assert!(echoes(&mut b) && echoes(&mut d));
    let (lines, _) = log.follow();
    assert!(
        lines.iter().any(|l| l.message.contains("refused")
            && l.message.contains("inbound.max_connections")),
        "no warning of the refusal"
    );
    sail::shutdown(rt_id);
    let _ = start.join();
}
