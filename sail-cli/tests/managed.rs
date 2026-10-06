//! `--managed-update` at a start: a managed Surge profile past due is
//! fetched again and started with; one fetched that does not load leaves
//! the profile in place, which is started with, strict or not.

#![cfg(unix)]
// A test, never built for mips.
#![allow(clippy::disallowed_types)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{free_port, TempDir};

/// A server that answers every request with what `body` makes of its
/// URL; the URL.
fn serve(body: impl FnOnce(&str) -> String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/profile.conf", listener.local_addr().unwrap());
    let body = body(&url);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });
    url
}

/// A managed profile from `url` with a SOCKS listener on `socks`.
fn profile(url: &str, strict: bool, socks: u16) -> String {
    format!(
        "#!MANAGED-CONFIG {url} interval=86400 strict={strict}\n\
         [General]\n\
         socks5-listen = 127.0.0.1:{socks}\n\
         [Rule]\n\
         FINAL,DIRECT\n"
    )
}

struct Sail {
    child: Child,
    out: PathBuf,
}

impl Sail {
    /// Runs the CLI on `config` with --managed-update until the SOCKS port
    /// `socks` takes connections.
    fn start(config: &Path, cache: &Path, socks: u16) -> Sail {
        let out = config.with_file_name("out.log");
        let child = Command::new(env!("CARGO_BIN_EXE_sail"))
            .arg("-c")
            .arg(config)
            .arg("--cache-dir")
            .arg(cache)
            .arg("--managed-update")
            .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let sail = Sail { child, out };
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", socks)).is_err() {
            assert!(
                Instant::now() < deadline,
                "sail did not listen on {}: {}",
                socks,
                sail.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        sail
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.out).unwrap_or_default()
    }
}

impl Drop for Sail {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_managed_profile_never_updated_is_fetched_and_started_with() {
    let dir = TempDir::new();
    let (before, after) = (free_port(), free_port());
    // The profile served names the URL it is served from, as Surge asks.
    let url = serve(|url| profile(url, false, after));
    let served = profile(&url, false, after);
    let config = dir.0.join("profile.conf");
    std::fs::write(&config, profile(&url, false, before)).unwrap();

    let sail = Sail::start(&config, &dir.0, after);
    assert_eq!(std::fs::read_to_string(&config).unwrap(), served);
    assert!(TcpStream::connect(("127.0.0.1", before)).is_err());
    let state = std::fs::read_to_string(dir.0.join("managed-config.json")).unwrap();
    assert!(state.contains(&url), "{}", state);
    assert!(
        sail.log().contains("managed profile: updated"),
        "{}",
        sail.log()
    );
    // No copy of the profile fetched is left beside it.
    let left: Vec<_> = std::fs::read_dir(&dir.0)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".managed.conf"))
        .collect();
    assert!(left.is_empty(), "{:?}", left);
}

#[test]
fn a_profile_fetched_that_does_not_load_leaves_the_one_in_place_even_strict() {
    let dir = TempDir::new();
    let socks = free_port();
    let url = serve(|_| "[Rule]\nFINAL,NoSuchPolicy\n".to_string());
    let config = dir.0.join("profile.conf");
    let in_place = profile(&url, true, socks);
    std::fs::write(&config, &in_place).unwrap();

    let sail = Sail::start(&config, &dir.0, socks);
    assert_eq!(std::fs::read_to_string(&config).unwrap(), in_place);
    let log = sail.log();
    assert!(
        log.contains("does not load") && log.contains("strict and past its interval"),
        "{}",
        log
    );
    assert!(!dir.0.join("managed-config.json").exists());
}

#[test]
fn a_profile_that_is_not_managed_is_refused() {
    let dir = TempDir::new();
    let config = dir.0.join("profile.conf");
    std::fs::write(&config, "[Rule]\nFINAL,DIRECT\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sail"))
        .arg("-c")
        .arg(&config)
        .arg("--cache-dir")
        .arg(&dir.0)
        .arg("--managed-update")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.contains("not a managed profile"), "{}", said);
}
