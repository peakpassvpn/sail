//! What the CLI's tests share.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;

/// Held while `free_port` has a port open, and while a process is
/// spawned: a child spawned then holds a copy of every socket the test
/// process has, until it runs its program, a while under load. A copy of
/// the listener `free_port` tries the port with would take the
/// connections meant for the sail started on it, and reset them as it
/// closes.
static SOCKETS: Mutex<()> = Mutex::new(());

/// `command` spawned with no `free_port` socket open for it to inherit.
pub fn spawn(command: &mut Command) -> Child {
    let _held = SOCKETS.lock().unwrap_or_else(|e| e.into_inner());
    command.spawn().unwrap()
}

/// A port on 127.0.0.1 that nothing has now, for TCP and UDP. From below
/// the range the system gives the sockets that ask for no port, so that
/// no connection these tests make is given it before it is bound, and in
/// turn, so that none is given twice here: the rule of sail's test
/// harness (`free_port` in sail/tests/it/common.rs), which this follows.
pub fn free_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    const FROM: u16 = 10_000;
    // Linux gives 32768 and up unless told otherwise, which is read;
    // macOS and Windows 49152 and up.
    let mut below = 32_768;
    #[cfg(target_os = "linux")]
    if let Some(low) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse::<u16>().ok())
    {
        if low >= FROM + 5_000 {
            below = below.min(low);
        }
    }
    let count = usize::from(below - FROM);
    // Where this process begins: far from where another does, most often.
    let first = (std::process::id() as usize).wrapping_mul(7919);
    for _ in 0..count {
        let turn = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let port = FROM + (first.wrapping_add(turn) % count) as u16;
        let _held = SOCKETS.lock().unwrap_or_else(|e| e.into_inner());
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
            && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
        {
            return port;
        }
    }
    panic!("no free port on 127.0.0.1");
}

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sail-cli-test-{}-{}",
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
