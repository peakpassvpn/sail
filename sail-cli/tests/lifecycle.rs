//! The CLI as a service manager drives it: SIGTERM with connections open,
//! a second signal, and SIGHUP reloading the configuration file.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A port nothing listens on now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A server that echoes each connection until it closes.
fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A connection to `to` through the SOCKS5 server on `socks`.
fn socks_connect(socks: u16, to: SocketAddr) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", socks))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    let SocketAddr::V4(to) = to else {
        unreachable!("the echo server is on 127.0.0.1")
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&to.ip().octets());
    request.extend_from_slice(&to.port().to_be_bytes());
    s.write_all(&request)?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("socks reply {}", reply[1])));
    }
    Ok(s)
}

/// Whether `stream` echoes what it is sent.
fn echoes(stream: &mut TcpStream) -> bool {
    let mut back = [0u8; 4];
    stream.write_all(b"ping").is_ok() && stream.read_exact(&mut back).is_ok() && &back == b"ping"
}

/// Whether a connection through `socks` to `to` echoes.
fn reaches(socks: u16, to: SocketAddr) -> bool {
    socks_connect(socks, to)
        .map(|mut s| echoes(&mut s))
        .unwrap_or(false)
}

struct Sail {
    child: Child,
    _dir: TempDir,
    config: PathBuf,
}

impl Sail {
    /// Runs the CLI on `config`, with `args` besides, until the SOCKS
    /// port `socks` takes connections.
    fn start(config: &str, socks: u16, args: &[&str]) -> Sail {
        let dir = TempDir::new();
        let path = dir.0.join("config.json");
        std::fs::write(&path, config).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_sail"))
            .arg("-c")
            .arg(&path)
            .args(args)
            .stdout(Stdio::from(
                std::fs::File::create(dir.0.join("out.log")).unwrap(),
            ))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let sail = Sail {
            child,
            _dir: dir,
            config: path,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", socks)).is_err() {
            assert!(Instant::now() < deadline, "sail did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        sail
    }

    /// What it wrote out.
    fn log(&self) -> String {
        std::fs::read_to_string(self.config.with_file_name("out.log")).unwrap_or_default()
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .arg(format!("-{}", name))
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Whether it exits within `within`.
    fn exits(&mut self, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        loop {
            if self.child.try_wait().unwrap().is_some() {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Sail {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sail-lifecycle-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A SOCKS inbound on `socks`, and `final` among a direct and a block
/// outbound.
fn config(socks: u16, last: &str) -> String {
    format!(
        r#"{{
  "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {socks} }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}, {{ "type": "block", "tag": "block" }}],
  "route": {{ "final": "{last}" }}
}}"#
    )
}

fn write(path: &Path, config: &str) {
    std::fs::write(path, config).unwrap();
}

/// SIGTERM with a drain timeout: no new connection is taken, the one open
/// goes on, and the process exits once it closes.
#[test]
fn sigterm_lets_the_connections_open_finish() {
    let echo = echo_server();
    let socks = free_port();
    let mut sail = Sail::start(
        &config(socks, "direct"),
        socks,
        &["--set", "lifecycle.drain_timeout=10s"],
    );
    let mut open = socks_connect(socks, echo).unwrap();
    assert!(echoes(&mut open));

    sail.signal("TERM");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        TcpStream::connect(("127.0.0.1", socks)).is_err(),
        "no new connection is taken"
    );
    assert!(echoes(&mut open), "the open one goes on");
    assert!(!sail.exits(Duration::from_millis(500)), "it waits for it");

    drop(open);
    assert!(
        sail.exits(Duration::from_secs(3)),
        "and exits once it closes"
    );
    // The last line, logged as it exits, is written out.
    let log = sail.log();
    assert!(
        log.contains("stopping: every connection finished"),
        "{}",
        log
    );
}

/// Without a drain timeout, the default outside the server profile,
/// SIGTERM stops at once.
#[test]
fn sigterm_without_a_drain_timeout_stops_at_once() {
    let echo = echo_server();
    let socks = free_port();
    let mut sail = Sail::start(&config(socks, "direct"), socks, &[]);
    let mut open = socks_connect(socks, echo).unwrap();
    assert!(echoes(&mut open));
    sail.signal("TERM");
    assert!(sail.exits(Duration::from_secs(3)));
}

/// A second signal while draining stops at once.
#[test]
fn a_second_signal_stops_the_drain() {
    let echo = echo_server();
    let socks = free_port();
    let mut sail = Sail::start(
        &config(socks, "direct"),
        socks,
        &["--set", "lifecycle.drain_timeout=60s"],
    );
    let mut open = socks_connect(socks, echo).unwrap();
    assert!(echoes(&mut open));
    sail.signal("TERM");
    assert!(!sail.exits(Duration::from_millis(500)));
    sail.signal("INT");
    assert!(sail.exits(Duration::from_secs(3)));
}

/// SIGHUP reloads the file: a good configuration takes over, a broken one
/// leaves the one before running.
#[test]
fn sighup_reloads_and_keeps_the_last_good_configuration() {
    let echo = echo_server();
    let socks = free_port();
    let mut sail = Sail::start(&config(socks, "block"), socks, &[]);
    assert!(!reaches(socks, echo), "blocked");

    write(&sail.config, &config(socks, "direct"));
    sail.signal("HUP");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !reaches(socks, echo) {
        assert!(Instant::now() < deadline, "the reload let it through");
        std::thread::sleep(Duration::from_millis(100));
    }

    std::fs::write(&sail.config, b"{ not json").unwrap();
    sail.signal("HUP");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !sail.exits(Duration::ZERO),
        "a broken file does not stop it"
    );
    assert!(reaches(socks, echo), "the configuration before runs on");
}
