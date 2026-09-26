#![allow(dead_code)]

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::future::abortable;

use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tracing::info;

use sail::adapter::*;
use sail::session::Session;

static NEXT_RT_ID: AtomicU16 = AtomicU16::new(0);

// ---------------------------------------------------------------------------
// Ports and files
//
// Tests never use fixed ports or paths, so that any number of test binaries,
// and whole suites in other checkouts, can run at the same time.
// ---------------------------------------------------------------------------

/// A port on 127.0.0.1 that is free for both TCP and UDP, as sail inbounds
/// bind both on the port they are given. The OS picks it, from its
/// ephemeral range, and no port is handed out twice in one process.
///
/// The port is free when returned, but not held: another process may take
/// it before the test binds it. `retry_port_clash` covers that.
pub fn free_port() -> u16 {
    static TAKEN: std::sync::Mutex<Option<std::collections::HashSet<u16>>> =
        std::sync::Mutex::new(None);
    for _ in 0..1000 {
        let Ok(tcp) = std::net::TcpListener::bind("127.0.0.1:0") else {
            continue;
        };
        let Ok(port) = tcp.local_addr().map(|a| a.port()) else {
            continue;
        };
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_err() {
            continue;
        }
        let mut taken = TAKEN.lock().unwrap_or_else(|e| e.into_inner());
        if taken.get_or_insert_with(Default::default).insert(port) {
            return port;
        }
    }
    panic!("no free port on 127.0.0.1");
}

/// `N` distinct free ports.
pub fn free_ports<const N: usize>() -> [u16; N] {
    std::array::from_fn(|_| free_port())
}

/// Whether `e` says an address was in use: a port from `free_port` that
/// someone else took before the test bound it.
pub fn is_port_clash(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::AddrInUse {
                return true;
            }
        }
        let message = cause.to_string().to_ascii_lowercase();
        message.contains("address already in use")
            || message.contains("address in use")
            || message.contains("os error 10048")
    })
}

/// Runs `f` until it does not fail for a port clash, a few times at most.
/// `f` takes its ports from `free_port`, so that each try has new ones.
pub fn retry_port_clash<T>(mut f: impl FnMut() -> anyhow::Result<T>) -> anyhow::Result<T> {
    const TRIES: usize = 5;
    for attempt in 1.. {
        match f() {
            Err(e) if attempt < TRIES && is_port_clash(&e) => {
                tracing::warn!("port clash, retrying with new ports: {:#}", e);
            }
            result => return result,
        }
    }
    unreachable!()
}

/// A directory of its own under the system's temporary directory, removed
/// with everything in it when dropped.
pub struct TempDir(std::path::PathBuf);

impl TempDir {
    /// A new directory, its name starting with `prefix`; unique to this
    /// process and call.
    pub fn new(prefix: &str) -> anyhow::Result<Self> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "sail-test-{}-{}-{}-{}",
            prefix,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            nanos
        ));
        std::fs::create_dir_all(&path)
            .map_err(|e| anyhow::anyhow!("create {}: {}", path.display(), e))?;
        Ok(TempDir(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join<P: AsRef<Path>>(&self, p: P) -> std::path::PathBuf {
        self.0.join(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// sing-box
// ---------------------------------------------------------------------------

/// sing-box: `$SING_BOX`, else Homebrew's, else the one on the PATH.
pub fn sing_box_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("SING_BOX") {
        return path.into();
    }
    let homebrew = Path::new("/opt/homebrew/bin/sing-box");
    if homebrew.exists() {
        homebrew.to_path_buf()
    } else {
        "sing-box".into()
    }
}

/// An external proxy process (sing-box, Xray), killed when dropped. Its
/// log goes to the test's stderr, but for the lines at level INFO.
pub struct Daemon {
    child: std::process::Child,
}

impl Daemon {
    /// Writes `config` to `dir/name.json` and runs sing-box on it. Returns
    /// once sing-box has started, every inbound listening: waiting on what
    /// sing-box says, not on probes, works for UDP inbounds too. An inbound
    /// that cannot listen fails it with sing-box's message, which
    /// `retry_port_clash` recognizes.
    pub fn sing_box(dir: &Path, name: &str, mut config: serde_json::Value) -> anyhow::Result<Self> {
        // "sing-box started" is at INFO.
        config["log"] = serde_json::json!({
            "level": "info",
            "timestamp": false,
        });
        let path = dir.join(format!("{}.json", name));
        std::fs::write(&path, config.to_string())?;
        let mut command = std::process::Command::new(sing_box_path());
        command.arg("run").arg("-c").arg(&path);
        Self::spawn(command, &format!("sing-box {}", name), |line| {
            line.contains("sing-box started")
        })
    }

    /// Runs `command`, its log on stderr, and returns once a line of it
    /// satisfies `ready`; it fails if the process exits first, or is not
    /// ready within 30s.
    pub fn spawn(
        mut command: std::process::Command,
        name: &str,
        ready: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        use std::io::BufRead;
        use std::process::Stdio;

        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("run {}: {}", name, e))?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        // Both streams are read to the end, so that the process never
        // blocks on a full pipe.
        let streams: Vec<Box<dyn std::io::Read + Send>> = vec![
            Box::new(child.stdout.take().expect("piped")),
            Box::new(child.stderr.take().expect("piped")),
        ];
        let ready = Arc::new(ready);
        for stream in streams {
            let ready = ready.clone();
            let ready_tx = ready_tx.clone();
            let name = name.to_string();
            std::thread::spawn(move || {
                let mut tail = std::collections::VecDeque::new();
                let mut signalled = false;
                for line in std::io::BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    if !line.contains("INFO") {
                        eprintln!("[{}] {}", name, line);
                    }
                    if !signalled {
                        if ready(&line) {
                            signalled = true;
                            let _ = ready_tx.send(Ok(()));
                        } else {
                            tail.push_back(line);
                            if tail.len() > 20 {
                                tail.pop_front();
                            }
                        }
                    }
                }
                if !signalled {
                    let tail: Vec<_> = tail.into_iter().collect();
                    let _ = ready_tx.send(Err(tail.join("\n")));
                }
            });
        }
        drop(ready_tx);
        let mut daemon = Daemon { child };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut logs = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match ready_rx.recv_timeout(left) {
                Ok(Ok(())) => return Ok(daemon),
                // One stream ended; the other may still say it is ready.
                Ok(Err(tail)) => logs.push(tail),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let status = daemon.child.wait()?;
                    anyhow::bail!("{} exited ({}): {}", name, status, logs.join("\n"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    anyhow::bail!("{} did not start within 30s", name);
                }
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Shuts the instances down and waits until each has stopped, so that
/// what they listened on is free again.
pub fn shutdown_instances(rt: &tokio::runtime::Runtime, ids: Vec<sail::RuntimeId>) {
    for id in ids {
        sail::shutdown(id);
        let stopped =
            rt.block_on(async { timeout(Duration::from_secs(10), wait_for_shutdown(id)).await });
        if stopped.is_err() {
            tracing::warn!("sail instance {} did not stop within 10s", id);
        }
    }
}

pub async fn run_tcp_echo_server(
    addr: &str,
) -> anyhow::Result<(
    std::net::SocketAddr,
    impl std::future::Future<Output = anyhow::Result<()>>,
)> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let fut = async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let (mut r, mut w) = stream.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("accept tcp failed: {}", e));
                }
            }
        }
    };
    Ok((local_addr, fut))
}

pub async fn run_udp_echo_server(
    addr: &str,
) -> anyhow::Result<(
    std::net::SocketAddr,
    impl std::future::Future<Output = anyhow::Result<()>>,
)> {
    let socket = UdpSocket::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind udp failed: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let fut = async move {
        let mut buf = vec![0u8; 2 * 1024];
        loop {
            let (n, raddr) = socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("recv udp failed: {}", e))?;
            let _ = socket
                .send_to(&buf[..n], &raddr)
                .await
                .map_err(|e| anyhow::anyhow!("send udp failed: {}", e))?;
        }
    };
    Ok((local_addr, fut))
}

/// The tuning test instances run with: short relay timeouts, so that the
/// half-close tests do not wait out the defaults.
pub fn runtime_options() -> sail::runtime::RuntimeOptions {
    let mut options = sail::runtime::RuntimeOptions::default();
    options
        .set_all(["relay.uplink_timeout=3s", "relay.downlink_timeout=3s"])
        .unwrap();
    options
}

// Runs multiple sail instances.
pub fn run_sail_instances(
    rt: &tokio::runtime::Runtime,
    configs: Vec<String>,
) -> anyhow::Result<Vec<sail::RuntimeId>> {
    let mut sail_rt_ids = Vec::new();
    for config in configs {
        let rt_id = NEXT_RT_ID.fetch_add(1, Ordering::Relaxed);
        let config = sail::config::from_string(&config)
            .map_err(|e| anyhow::anyhow!("parse config failed: {}", e))?;
        let opts = sail::StartOptions {
            config: sail::Config::Internal(config),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: sail::RuntimeOption::SingleThread,
            runtime: runtime_options(),
            host: Default::default(),
        };
        let start = rt.spawn_blocking(move || sail::start(rt_id, opts));
        // Returns once the instance runs, or with the error it failed with:
        // a start that fails must fail the test, not leave it waiting.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let failure = loop {
            if sail::is_running(rt_id) {
                break None;
            }
            if start.is_finished() {
                break Some(match rt.block_on(start) {
                    Ok(Err(e)) => anyhow::anyhow!("start sail failed: {}", e),
                    Ok(Ok(())) => anyhow::anyhow!("sail stopped as soon as it started"),
                    Err(e) => anyhow::anyhow!("start sail panicked: {}", e),
                });
            }
            if std::time::Instant::now() > deadline {
                break Some(anyhow::anyhow!("sail did not start within 10s"));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if let Some(e) = failure {
            for id in &sail_rt_ids {
                sail::shutdown(*id);
            }
            return Err(e);
        }
        sail_rt_ids.push(rt_id);
    }
    Ok(sail_rt_ids)
}

fn new_socks_outbound(
    socks_addr: &str,
    socks_port: u16,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<AnyOutboundHandler> {
    // Make use of a socks outbound to initiate a socks request to a sail instance.
    let mut socks = serde_json::json!({
        "type": "socks",
        "tag": "socks",
        "server": socks_addr,
        "server_port": socks_port,
    });
    if let Some(username) = username {
        socks["username"] = username.into();
    }
    if let Some(password) = password {
        socks["password"] = password.into();
    }
    let config =
        sail::config::Config::from_json(&serde_json::json!({ "outbounds": [socks] }).to_string())?;
    let dial_defaults = sail::net::DialOptions::default();
    let dns_client = sail::app::dns_client::DnsClient::new(
        &config.dns,
        Arc::new(dial_defaults.clone()),
        Default::default(),
    )?
    .into_shared();
    let outbound_manager = sail::app::outbound::manager::OutboundManager::new(
        &config.outbounds,
        &dial_defaults,
        &sail::runtime::RuntimeEnv::default(),
        dns_client,
    )?;

    Ok((outbound_manager
        .get("socks")
        .ok_or_else(|| anyhow::anyhow!("socks outbound not found"))?) as _)
}

pub async fn new_socks_stream(
    socks_addr: &str,
    socks_port: u16,
    sess: &Session,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<AnyStream> {
    // Use a socks outbound to simulate a client request.
    let handler = new_socks_outbound(socks_addr, socks_port, username, password)?;
    let stream = tokio::net::TcpStream::connect(format!("{}:{}", socks_addr, socks_port)).await?;
    timeout(
        Duration::from_secs(10),
        handler.stream().map_err(|e| anyhow::anyhow!(e))?.handle(
            sess,
            None,
            Some(Box::new(stream)),
        ),
    )
    .await?
    .map_err(|e| anyhow::anyhow!(e))
}

pub async fn new_socks_datagram(
    socks_addr: &str,
    socks_port: u16,
    sess: &Session,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<AnyOutboundDatagram> {
    // Use a socks outbound to simulate a client request.
    let handler = new_socks_outbound(socks_addr, socks_port, username, password)?;
    timeout(
        Duration::from_secs(10),
        handler
            .datagram()
            .map_err(|e| anyhow::anyhow!(e))?
            .handle(sess, None),
    )
    .await?
    .map_err(|e| anyhow::anyhow!(e))
}

pub fn test_tcp_half_close_on_configs(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
) -> anyhow::Result<()> {
    info!("testing tcp half close");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;
    let sail_rt_ids = run_sail_instances(&rt, configs)?;
    let socks_addr = socks_addr.to_string();
    let res = rt.block_on(rt.spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
        let mut sess = sail::session::Session::default();
        sess.destination = sail::session::SocksAddr::Ip(local_addr);
        let mut client_stream =
            new_socks_stream(&socks_addr, socks_port, &sess, None, None).await?;
        let (mut server_stream, _) = listener
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("accept tcp failed: {}", e))?;

        // client <-> server
        //
        // Ensure both directions work.
        //
        // When testing with proxy protocols need additional info from the other
        // side to initialize itself, such as shadowsocks needs a salt from the
        // other side, we must forward some payload first.
        client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| anyhow::anyhow!("write hello failed: {}", e))?;
        let mut buf = Vec::new();
        let n = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read hello failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world failed: {}", e))?;
        let mut buf = Vec::new();
        let n = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read world failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");

        // client(shutdown) <-> server
        //
        // The case client performs a shutdown.
        //
        // The expected behaiver is, the client socket is no longer writable
        // after the shutdown, but can still read data from server socket.
        // The server socket can write data to client, a read on the server socket
        // will return zero bytes (EOF) immediately. After TCP_DOWNLINK_TIMEOUT and
        // reading out all previous transferred data, a read on client socket should
        // also return zero bytes immediately even though we havn't explicitly
        // shutdown the server socket, this verifies TCP_DOWNLINK_TIMEOUT works as
        // expected.
        client_stream
            .shutdown()
            .await
            .map_err(|e| anyhow::anyhow!("shutdown client failed: {}", e))?;
        let res = client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| e.kind());
        assert!(res.is_err());
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world after shutdown failed: {}", e))?;
        let mut buf = Vec::new();
        let n = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read world after shutdown failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");
        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(2), server_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read failed: {}", e))?;
        assert_eq!(n, 0);
        tokio::time::sleep(
            runtime_options()
                .relay
                .downlink_timeout
                .checked_sub(Duration::from_secs(1))
                .ok_or_else(|| anyhow::anyhow!("duration sub failed"))?,
        )
        .await;
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world after timeout failed: {}", e))?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let res = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read buf after timeout failed: {}", e))?;
        assert_eq!(res, 5);
        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(2), client_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read 2 failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read 2 failed: {}", e))?;
        assert_eq!(n, 0);

        let mut client_stream =
            new_socks_stream(&socks_addr, socks_port, &sess, None, None).await?;
        let (mut server_stream, _) = listener
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("accept 2 failed: {}", e))?;

        // Another direction.
        //
        // client <-> server
        //
        // Ensure both directions work.
        //
        // When testing with proxy protocols need additional info from the other
        // side to initialize itself, such as shadowsocks needs a salt from the
        // other side, we must forward some payload first.
        client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| anyhow::anyhow!("write hello 2 failed: {}", e))?;
        let mut buf = Vec::new();
        let n = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read hello 2 failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world 2 failed: {}", e))?;
        let mut buf = Vec::new();
        let n = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read world 2 failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");

        server_stream
            .shutdown()
            .await
            .map_err(|e| anyhow::anyhow!("shutdown server failed: {}", e))?;
        client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| anyhow::anyhow!("write hello 3 failed: {}", e))?;
        let mut buf = Vec::new();
        let n = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read hello 3 failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        let res = server_stream
            .write_all(b"world")
            .await
            .map_err(|e| e.kind());
        assert!(res.is_err());
        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(2), client_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read 3 failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read 3 failed: {}", e))?;
        assert_eq!(n, 0);
        tokio::time::sleep(
            runtime_options()
                .relay
                .uplink_timeout
                .checked_sub(Duration::from_millis(500))
                .ok_or_else(|| anyhow::anyhow!("duration sub failed"))?,
        )
        .await;
        client_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world 3 failed: {}", e))?;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let res = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read buf 3 failed: {}", e))?;
        assert_eq!(res, 5);
        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(2), server_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read 4 failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read 4 failed: {}", e))?;
        assert_eq!(n, 0);
        Ok::<(), anyhow::Error>(())
    }));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow::anyhow!("task join error: {}", e)),
    }
}

async fn file_hash<P: AsRef<Path>>(p: P) -> anyhow::Result<Box<[u8]>> {
    let mut src = tokio::fs::File::open(p)
        .await
        .map_err(|e| anyhow::anyhow!("open file failed: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = src
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read file failed: {}", e))?;
        if n == 0 {
            break;
        }
        hasher
            .write_all(&buf[..n])
            .map_err(|e| anyhow::anyhow!("write hasher failed: {}", e))?;
    }
    Ok(hasher.finalize().as_slice().to_owned().into_boxed_slice())
}

pub fn test_data_transfering_reliability_on_configs(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
) -> anyhow::Result<()> {
    info!("testing data transfering reliability");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;
    // Files of this call's own, removed when it returns.
    let dir = TempDir::new("transfer")?;
    let src_file = "source_random_bytes.bin";
    let dst_file = "destination_random_bytes.bin";
    let source = dir.join(src_file);
    let dst = dir.join(dst_file);
    let path = dir.path().to_path_buf();
    let mut rng = StdRng::from_entropy();
    let mut data = vec![0u8; 2 * 1024 * 1024];
    rng.fill_bytes(&mut data);
    let mut f = std::fs::File::create(&source)
        .map_err(|e| anyhow::anyhow!("create source failed: {}", e))?;
    f.write_all(&data)
        .map_err(|e| anyhow::anyhow!("write source failed: {}", e))?;
    f.sync_all()
        .map_err(|e| anyhow::anyhow!("sync source failed: {}", e))?;

    // TCP uplink
    let listener = rt
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        let (mut stream, _) = timeout(Duration::from_secs(10), listener.accept())
            .await
            .map_err(|e| anyhow::anyhow!("accept timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("accept failed: {}", e))?;
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let n = timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut stream, &mut dst_file),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata failed: {}", e))?
                .len(),
            n
        );
        let src_hash = file_hash(source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let send_task = async move {
        let source = path.join(src_file);
        let mut sess = sail::session::Session::default();
        sess.destination = sail::session::SocksAddr::Ip(local_addr);
        let mut stream =
            new_socks_stream(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut src, &mut stream),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        Ok::<(), anyhow::Error>(())
    };
    let sail_rt_ids = run_sail_instances(&rt, configs.clone())?;
    let mut futs: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(anyhow::anyhow!("task join error: {}", e)),
    }

    // TCP downlink
    let listener = rt
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        let mut sess = sail::session::Session::default();
        sess.destination = sail::session::SocksAddr::Ip(local_addr);
        let mut stream =
            new_socks_stream(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let n = timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut stream, &mut dst_file),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata failed: {}", e))?
                .len(),
            n
        );
        let src_hash = file_hash(source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let _socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let send_task = async move {
        let source = path.join(src_file);
        let (mut stream, _) = timeout(Duration::from_secs(10), listener.accept())
            .await
            .map_err(|e| anyhow::anyhow!("accept timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("accept failed: {}", e))?;
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut src, &mut stream),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        Ok::<(), anyhow::Error>(())
    };
    let sail_rt_ids = run_sail_instances(&rt, configs.clone())?;
    let mut futs: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(anyhow::anyhow!("task join error: {}", e)),
    }

    // UDP uplink
    let socket = rt
        .block_on(UdpSocket::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind udp failed: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;

    let path = dir.path().to_path_buf();
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let expected_total_bytes = tokio::fs::File::open(&source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?
            .metadata()
            .await
            .map_err(|e| anyhow::anyhow!("metadata source failed: {}", e))?
            .len() as usize;
        let mut recvd_bytes: usize = 0;
        let mut buf = vec![0u8; 1500];
        let mut recvd_data = Vec::new();
        loop {
            assert!(recvd_bytes <= expected_total_bytes);
            if recvd_bytes == expected_total_bytes {
                break;
            }
            let (n, _) = timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("recv timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("recv failed: {}", e))?;
            recvd_data.push(buf[..n].to_vec());
            recvd_bytes += n;
        }
        for data in recvd_data.into_iter() {
            dst_file
                .write_all(&data)
                .await
                .map_err(|e| anyhow::anyhow!("write dst failed: {}", e))?;
        }
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata dst failed: {}", e))?
                .len() as usize,
            expected_total_bytes
        );
        let src_hash = file_hash(&source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let send_task = async move {
        let source = path.join(src_file);
        let mut sess = sail::session::Session::default();
        sess.destination = sail::session::SocksAddr::Ip(local_addr);
        let dgram = new_socks_datagram(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        let (_, mut s) = dgram.split();
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        let mut buf = vec![0u8; 1500];
        loop {
            // Since UDP is unordered and unreliable, even tests on local could
            // fail, make some delay to mitigate this.
            tokio::time::sleep(Duration::from_millis(1)).await;
            let n = timeout(Duration::from_secs(2), src.read(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("read timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("read failed: {}", e))?;
            if n > 0 {
                let _n = timeout(
                    Duration::from_secs(2),
                    s.send_to(&buf[..n], &sess.destination),
                )
                .await
                .map_err(|e| anyhow::anyhow!("send timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("send failed: {}", e))?;
            } else {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let sail_rt_ids = run_sail_instances(&rt, configs.clone())?;
    let mut futs: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(anyhow::anyhow!("task join error: {}", e)),
    }

    // UDP downlink
    let socket = rt
        .block_on(UdpSocket::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind udp failed: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;

    let socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let recv_task = async move {
        let mut sess = sail::session::Session::default();
        sess.destination = sail::session::SocksAddr::Ip(local_addr);
        let dgram = new_socks_datagram(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        let (mut r, mut s) = dgram.split();
        let source = path.join(src_file);
        let _buf = vec![0u8; 1500];
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let expected_total_bytes = tokio::fs::File::open(&source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?
            .metadata()
            .await
            .map_err(|e| anyhow::anyhow!("metadata source failed: {}", e))?
            .len() as usize;
        let mut recvd_bytes: usize = 0;
        let mut buf = vec![0u8; 1500];
        let mut recvd_data = Vec::new();
        // Send a datagram to establish the session.
        s.send_to(b"hello", &sess.destination)
            .await
            .map_err(|e| anyhow::anyhow!("send hello failed: {}", e))?;
        loop {
            assert!(recvd_bytes <= expected_total_bytes);
            if recvd_bytes == expected_total_bytes {
                break;
            }
            let (n, _) = timeout(Duration::from_secs(10), r.recv_from(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("recv timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("recv failed: {}", e))?;
            recvd_data.push(buf[..n].to_vec());
            recvd_bytes += n;
        }
        for data in recvd_data.into_iter() {
            dst_file
                .write_all(&data)
                .await
                .map_err(|e| anyhow::anyhow!("write dst failed: {}", e))?;
        }
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata dst failed: {}", e))?
                .len() as usize,
            expected_total_bytes
        );
        let src_hash = file_hash(&source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let _socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let send_task = async move {
        let source = path.join(src_file);
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        let mut buf = vec![0u8; 1500];
        // Receive a single packet to decide the remote peer.
        let (_, raddr) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("recv initial failed: {}", e))?;
        loop {
            // Since UDP is unordered and unreliable, even tests on local could
            // fail, make some delay to mitigate this.
            tokio::time::sleep(Duration::from_millis(1)).await;
            let n = timeout(Duration::from_secs(2), src.read(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("read timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("read failed: {}", e))?;
            if n > 0 {
                let _n = timeout(Duration::from_secs(2), socket.send_to(&buf[..n], &raddr))
                    .await
                    .map_err(|e| anyhow::anyhow!("send timeout: {}", e))?
                    .map_err(|e| anyhow::anyhow!("send failed: {}", e))?;
            } else {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let sail_rt_ids = run_sail_instances(&rt, configs.clone())?;
    let mut futs: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow::anyhow!("task join error: {}", e)),
    }
}

// Runs multiple sail instances, thereafter a socks request will be sent to the
// given socks server to test the proxy chain. The proxy chain is expected to
// correctly handle the request to it's destination.
pub fn test_configs(configs: Vec<String>, socks_addr: &str, socks_port: u16) -> anyhow::Result<()> {
    test_configs_with_auth(configs, socks_addr, socks_port, None, None)
}

pub fn test_configs_with_auth(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<()> {
    info!("testing configs");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;

    // Use an echo server as the destination of the socks request.
    let mut bg_tasks: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    let (tcp_addr, tcp_fut) = rt.block_on(run_tcp_echo_server("127.0.0.1:0"))?;
    let (udp_addr, udp_fut) = rt.block_on(run_udp_echo_server("127.0.0.1:0"))?;
    bg_tasks.push(Box::pin(tcp_fut));
    bg_tasks.push(Box::pin(udp_fut));
    let (bg_task, bg_task_handle) = abortable(futures::future::try_join_all(bg_tasks));

    let sail_rt_ids = run_sail_instances(&rt, configs)?;

    // Simulates an application request.
    let socks_addr = socks_addr.to_string();
    let app_task = async move {
        let mut sess = sail::session::Session::default();
        sess.destination = sail::session::SocksAddr::Ip(tcp_addr);
        let mut s = timeout(
            Duration::from_secs(10),
            new_socks_stream(
                &socks_addr,
                socks_port,
                &sess,
                username.clone(),
                password.clone(),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("connect socks stream timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("connect socks stream failed: {}", e))?;

        timeout(Duration::from_secs(10), s.write_all(b"abc"))
            .await
            .map_err(|e| anyhow::anyhow!("write to stream timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("write to stream failed: {}", e))?;

        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(10), s.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("read from stream timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("read from stream failed: {}", e))?;

        if "abc" != String::from_utf8_lossy(&buf[..n]) {
            return Err(anyhow::anyhow!(
                "stream echo mismatch: expected 'abc', got '{}'",
                String::from_utf8_lossy(&buf[..n])
            ));
        }

        // Test UDP
        sess.destination = sail::session::SocksAddr::Ip(udp_addr);
        let dgram = timeout(
            Duration::from_secs(10),
            new_socks_datagram(
                &socks_addr,
                socks_port,
                &sess,
                username.clone(),
                password.clone(),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("create socks datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("create socks datagram failed: {}", e))?;

        let (mut r, mut s) = dgram.split();
        let msg = b"def";
        let n = timeout(
            Duration::from_secs(10),
            s.send_to(msg.as_ref(), &sess.destination),
        )
        .await
        .map_err(|e| anyhow::anyhow!("send datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("send datagram failed: {}", e))?;

        if msg.len() != n {
            return Err(anyhow::anyhow!(
                "send datagram partial write: expected {}, got {}",
                msg.len(),
                n
            ));
        }

        let mut buf = vec![0u8; 2 * 1024];
        let (n, raddr) = timeout(Duration::from_secs(10), r.recv_from(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("recv datagram timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("recv datagram failed: {}", e))?;

        if msg != &buf[..n] {
            return Err(anyhow::anyhow!(
                "datagram echo mismatch: expected {:?}, got {:?}",
                msg,
                &buf[..n]
            ));
        }
        if &raddr != &sess.destination {
            return Err(anyhow::anyhow!(
                "datagram source mismatch: expected {:?}, got {:?}",
                sess.destination,
                raddr
            ));
        }

        // Test if we can handle a second UDP session. This can fail in stream
        // transports if the stream ID has not been correctly set.
        let dgram2 = timeout(
            Duration::from_secs(10),
            new_socks_datagram(
                &socks_addr,
                socks_port,
                &sess,
                username.clone(),
                password.clone(),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("create second socks datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("create second socks datagram failed: {}", e))?;

        let (mut r, mut s) = dgram2.split();
        let msg = b"ghi";
        let n = timeout(
            Duration::from_secs(10),
            s.send_to(msg.as_ref(), &sess.destination),
        )
        .await
        .map_err(|e| anyhow::anyhow!("send second datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("send second datagram failed: {}", e))?;

        if msg.len() != n {
            return Err(anyhow::anyhow!(
                "send second datagram partial write: expected {}, got {}",
                msg.len(),
                n
            ));
        }

        let mut buf = vec![0u8; 2 * 1024];
        let (n, raddr) = timeout(Duration::from_secs(10), r.recv_from(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("recv second datagram timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("recv second datagram failed: {}", e))?;

        if msg != &buf[..n] {
            return Err(anyhow::anyhow!(
                "second datagram echo mismatch: expected {:?}, got {:?}",
                msg,
                &buf[..n]
            ));
        }
        if &raddr != &sess.destination {
            return Err(anyhow::anyhow!(
                "second datagram source mismatch: expected {:?}, got {:?}",
                sess.destination,
                raddr
            ));
        }

        // Cancel the background task.
        bg_task_handle.abort();
        Ok::<(), anyhow::Error>(())
    };
    let bg_task = async move {
        match bg_task.await {
            Ok(res) => res.map(|_| ()),
            Err(_) => Ok(()), // Aborted
        }
    };
    let mut futs = Vec::new();
    futs.push(rt.spawn(bg_task));
    futs.push(rt.spawn(app_task));
    let res = rt.block_on(async {
        timeout(Duration::from_secs(60), futures::future::select_all(futs))
            .await
            .map_err(|e| anyhow::anyhow!("test timeout: {}", e))
    });

    shutdown_instances(&rt, sail_rt_ids);

    match res {
        Ok((result, _, _)) => {
            // result is Result<Result<(), Error>, JoinError>
            match result {
                Ok(inner_res) => inner_res,
                Err(e) => Err(anyhow::anyhow!("task join failed: {:?}", e)),
            }
        }
        Err(e) => Err(anyhow::anyhow!("test execution failed: {:?}", e)),
    }
}

pub async fn wait_for_shutdown(id: sail::RuntimeId) {
    loop {
        if !sail::is_running(id) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
