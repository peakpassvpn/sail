//! The FFI's numbers for the performance regression checks (roadmap 5.4):
//! an instance made, started, loaded and stopped through the C ABI as an
//! app does, with the mobile profile and one thread, its defaults.
//!
//!   cargo test -p sail-ffi --release --features alloc-stats --lib \
//!     perf_tests -- --ignored --nocapture
//!
//! prints one line, `PERF {...}`, which tools/perf reads: the time to start
//! and to stop, the memory the instance adds when idle and per connection
//! held, and the allocations per connection and per MiB relayed.
//! Allocations are the whole process's, the load's own included: that is
//! the same work at every commit, so what changes is sail's.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::alloc_stats::counts;
use crate::*;

// Loads, as the design gives them (judgment, calibrated at its step 1).
const SHORT_CONNECTIONS: usize = 200;
const SHORT_BYTES: usize = 1024;
const BULK_STREAMS: usize = 4;
const BULK_MIB: usize = 64;
const HELD: usize = 2000;
const SETTLE: Duration = Duration::from_secs(3);

fn ok(what: &str, f: impl FnOnce(*mut *mut c_char) -> i32) {
    let mut err = std::ptr::null_mut();
    let code = f(&mut err);
    if code != SAIL_OK {
        let message = if err.is_null() {
            String::new()
        } else {
            let s = unsafe { CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned();
            unsafe { sail_free_string(err) };
            s
        };
        panic!("{}: {} {}", what, code, message);
    }
}

/// The process's resident memory in KiB, on Linux (VmRSS); none
/// elsewhere: macOS's compressed memory makes its RSS swing between runs,
/// and its footprint is the number there.
fn rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// On macOS, the process's phys_footprint in KiB, what iOS limits a
/// Network Extension by; elsewhere none.
fn footprint_kb() -> Option<u64> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let out = std::process::Command::new("footprint")
        .args(["-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    // "… phys_footprint: 12 MB" or "… 12345 KB".
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("phys_footprint:"))?;
    let mut words = line.split("phys_footprint:").nth(1)?.split_whitespace();
    let n: f64 = words.next()?.parse().ok()?;
    let unit = words.next().unwrap_or("KB");
    Some(match unit {
        "B" => n / 1024.0,
        "KB" => n,
        "MB" => n * 1024.0,
        "GB" => n * 1024.0 * 1024.0,
        _ => return None,
    } as u64)
}

/// A connection through the SOCKS inbound at `socks` to 127.0.0.1:`port`.
fn through(socks: u16, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&port.to_be_bytes());
    s.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "the SOCKS inbound refused");
    s
}

/// An echo server, a thread a connection, until `done`.
fn echo(done: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    thread::spawn(move || {
                        let mut buf = vec![0u8; 64 * 1024];
                        while let Ok(n) = s.read(&mut buf) {
                            if n == 0 || s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    });
                }
                Err(_) => thread::sleep(Duration::from_millis(1)),
            }
        }
    });
    port
}

/// A server that accepts and keeps each connection, reading nothing.
fn keeper(kept: Arc<Mutex<Vec<TcpStream>>>, done: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((s, _)) => kept.lock().unwrap().push(s),
                Err(_) => thread::sleep(Duration::from_millis(1)),
            }
        }
    });
    port
}

/// `n` bytes there and back over `s`.
fn round_trip(s: &mut TcpStream, n: usize) {
    let chunk = vec![7u8; 64 * 1024];
    let mut writer = s.try_clone().unwrap();
    let sender = thread::spawn(move || {
        let mut left = n;
        while left > 0 {
            let k = left.min(chunk.len());
            writer.write_all(&chunk[..k]).unwrap();
            left -= k;
        }
    });
    let mut buf = vec![0u8; 64 * 1024];
    let mut got = 0;
    while got < n {
        let k = s.read(&mut buf).unwrap();
        assert!(k > 0, "the relay closed after {} of {} bytes", got, n);
        got += k;
    }
    sender.join().unwrap();
}

#[test]
#[ignore = "a measurement: tools/perf runs it, in a release build"]
fn measure() {
    let done = Arc::new(AtomicBool::new(false));
    let echo_port = echo(done.clone());
    let kept = Arc::new(Mutex::new(Vec::new()));
    let keep_port = keeper(kept.clone(), done.clone());
    let socks = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = CString::new(
        serde_json::json!({
            "log": { "level": "warn" },
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks }],
            "outbounds": [{ "type": "direct" }],
        })
        .to_string(),
    )
    .unwrap();
    thread::sleep(SETTLE);
    let rss_before = rss_kb();
    let footprint_before = footprint_kb();

    let mut instance = 0;
    ok("new", |err| unsafe {
        sail_instance_new(std::ptr::null(), std::ptr::null(), &mut instance, err)
    });
    let begun = Instant::now();
    ok("start", |err| unsafe {
        sail_instance_start(instance, config.as_ptr(), err)
    });
    let start_ms = begun.elapsed().as_secs_f64() * 1000.0;
    thread::sleep(SETTLE);
    let idle_rss_kb = rss_kb()
        .zip(rss_before)
        .map(|(now, before)| now.saturating_sub(before));
    let idle_footprint_kb = footprint_kb()
        .zip(footprint_before)
        .map(|(now, before)| now.saturating_sub(before));

    // Held: many open connections, idle. First, before any load: memory a
    // load freed would take them in without the process growing.
    let rss_idle = rss_kb();
    let footprint_idle = footprint_kb();
    let held: Vec<_> = (0..HELD).map(|_| through(socks, keep_port)).collect();
    thread::sleep(SETTLE);
    let held_kb_per_connection = rss_kb()
        .zip(rss_idle)
        .map(|(now, before)| now.saturating_sub(before) as f64 / HELD as f64);
    let held_footprint_kb_per_connection = footprint_kb()
        .zip(footprint_idle)
        .map(|(now, before)| now.saturating_sub(before) as f64 / HELD as f64);
    drop(held);
    thread::sleep(Duration::from_millis(500));

    // Short connections: each a small echo, one after another.
    let before = counts();
    for _ in 0..SHORT_CONNECTIONS {
        let mut s = through(socks, echo_port);
        round_trip(&mut s, SHORT_BYTES);
    }
    thread::sleep(Duration::from_millis(500));
    let short = counts();
    let allocations_per_connection = (short.0 - before.0) as f64 / SHORT_CONNECTIONS as f64;

    // Bulk: a few streams, many MiB each way.
    let before = counts();
    let streams: Vec<_> = (0..BULK_STREAMS)
        .map(|_| {
            thread::spawn(move || {
                let mut s = through(socks, echo_port);
                round_trip(&mut s, BULK_MIB << 20);
            })
        })
        .collect();
    for stream in streams {
        stream.join().unwrap();
    }
    thread::sleep(Duration::from_millis(500));
    let bulk = counts();
    let mib = (BULK_STREAMS * BULK_MIB * 2) as f64;
    let allocations_per_mib = (bulk.0 - before.0) as f64 / mib;
    let allocated_bytes_per_mib = (bulk.1 - before.1) as f64 / mib;

    let begun = Instant::now();
    ok("stop", |err| sail_instance_stop(instance, 10_000, err));
    let stop_ms = begun.elapsed().as_secs_f64() * 1000.0;
    sail_instance_free(instance);
    done.store(true, Ordering::Relaxed);
    kept.lock().unwrap().clear();

    println!(
        "PERF {}",
        serde_json::json!({
            "start_ms": start_ms,
            "stop_ms": stop_ms,
            "idle_rss_kb": idle_rss_kb,
            "idle_footprint_kb": idle_footprint_kb,
            "held_kb_per_connection": held_kb_per_connection,
            "held_footprint_kb_per_connection": held_footprint_kb_per_connection,
            "allocations_per_connection": allocations_per_connection,
            "allocations_per_mib": allocations_per_mib,
            "allocated_bytes_per_mib": allocated_bytes_per_mib,
        })
    );
}
