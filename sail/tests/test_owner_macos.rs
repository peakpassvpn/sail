//! Rules on who opened a connection, found by sail itself on macOS (the
//! kernel's socket list and libproc, roadmap 2.8): curl, by its name, and
//! the user nobody are refused; python as root is let through.
//!
//! As root, on a machine of its own: CI's tun-macos job. A test range,
//! 198.18.0.0/15, is routed into the utun, and its connections are sent on
//! to an echo server on this host (`override_address`).
#![cfg(all(
    target_os = "macos",
    feature = "inbound-tun",
    feature = "outbound-direct",
    feature = "rule-process-name"
))]

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use sail::embed::{Config, Instance, Options, RunDir};

/// An echo server on 127.0.0.1, on a thread of its own: its port.
fn echo_server() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
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
    Ok(port)
}

/// What `client` (argv) gets back from the echo server through the TUN.
fn echoed(client: &[&str]) -> Result<String> {
    let output = Command::new(client[0])
        .args(&client[1..])
        .stdin(Stdio::null())
        .output()
        .with_context(|| client.join(" "))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// A Python TCP client: sends `hello` to 198.18.0.1:`port` and prints
/// what comes back, nothing when the connection is refused or reset.
fn python(port: u16) -> String {
    format!(
        r#"
import socket, sys
try:
    s = socket.create_connection(("198.18.0.1", {port}), timeout=3)
    s.sendall(b"hello")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(64)
        if not chunk:
            break
        data += chunk
    sys.stdout.write(data.decode())
except OSError:
    pass
"#
    )
}

#[test]
#[ignore = "needs root and a utun: CI's tun-macos"]
fn rules_on_who_opened_a_connection_are_matched() -> Result<()> {
    let port = echo_server()?;
    let config = format!(
        r#"{{
        "log": {{ "level": "debug" }},
        "inbounds": [{{
            "type": "tun", "tag": "tun-in", "address": ["172.31.237.1/30"],
            "auto_route": true, "route_address": ["198.18.0.0/15"]
        }}],
        "outbounds": [{{ "type": "direct", "tag": "direct" }}],
        "route": {{ "rules": [
            {{ "process_name": ["curl"], "action": "reject" }},
            {{ "user": ["nobody"], "action": "reject" }},
            {{ "ip_cidr": ["198.18.0.0/15"], "action": "route-options",
               "override_address": "127.0.0.1" }}
        ] }}
    }}"#
    );
    let dir = std::env::temp_dir().join(format!("sail-owner-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let sail = Instance::new(Options::new().run_dir(RunDir::Dir(dir.join("run"))))?;
    sail.blocking_start(Config::Json(config))?;
    let script = python(port);
    let result = (|| -> Result<()> {
        anyhow::ensure!(
            echoed(&["python3", "-c", &script])? == "hello",
            "python as root was not let through"
        );
        let curl = format!("printf hello | curl -s --max-time 3 telnet://198.18.0.1:{port}");
        let refused = echoed(&["sh", "-c", &curl])?;
        anyhow::ensure!(refused.is_empty(), "curl was let through: {refused:?}");
        let nobody = echoed(&["sudo", "-u", "nobody", "python3", "-c", &script])?;
        anyhow::ensure!(
            nobody.is_empty(),
            "the user nobody was let through: {nobody:?}"
        );
        anyhow::ensure!(
            echoed(&["python3", "-c", &script])? == "hello",
            "python as root, again"
        );
        Ok(())
    })();
    sail.blocking_stop(Duration::from_secs(10))?;
    let _ = std::fs::remove_dir_all(&dir);
    result
}
