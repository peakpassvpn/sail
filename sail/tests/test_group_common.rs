//! What the group tests share: members that are local HTTP servers, each
//! reached through a `redirect` outbound and answering with its name after
//! a delay of its own, so a group's choice and latencies can be told apart
//! without the internet. The servers listen on ports the OS assigns.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::future::{abortable, AbortHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use sail::adapter::AnyStream;
use sail::app::outbound::manager::OutboundManager;
use sail::session::{Session, SocksAddr};

pub fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// An instance environment whose selections are kept in a directory of
/// the test's own, empty at first.
pub fn env(name: &str) -> sail::runtime::RuntimeEnv {
    let dir = std::env::temp_dir().join(format!("sail-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    sail::runtime::RuntimeEnv {
        host: sail::runtime::Host {
            cache_dir: Some(dir),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn manager(
    outbounds: serde_json::Value,
    env: &sail::runtime::RuntimeEnv,
) -> Result<OutboundManager> {
    let config = sail::config::Config::from_json(
        &serde_json::json!({ "outbounds": outbounds }).to_string(),
    )?;
    let dial_defaults = sail::net::DialOptions::default();
    let dns_client = sail::app::dns_client::DnsClient::new(
        &config.dns,
        Arc::new(dial_defaults.clone()),
        Default::default(),
    )?
    .into_shared();
    OutboundManager::new(&config.outbounds, &dial_defaults, env, dns_client)
}

/// A `redirect` outbound to the member server on `port`.
pub fn member(tag: &str, port: u16) -> serde_json::Value {
    serde_json::json!({
        "type": "redirect",
        "tag": tag,
        "server": "127.0.0.1",
        "server_port": port,
    })
}

/// A port for members that are never connected to.
pub const UNSERVED: u16 = 9;

/// Serves HTTP on a port of its own, which it returns: every request is
/// answered, after `delay`, with a 204 naming `name`. Stops, closing the
/// port, when the handle is aborted.
pub async fn serve(name: &str, delay: Duration) -> (AbortHandle, u16) {
    let (handle, _, port) = serve_adjustable(name, delay).await;
    (handle, port)
}

/// Like `serve`, with a delay that can be changed as it runs, in
/// milliseconds.
pub async fn serve_adjustable(name: &str, delay: Duration) -> (AbortHandle, Arc<AtomicU64>, u16) {
    let (handle, delay, port, _) = serve_counted(name, delay).await;
    (handle, delay, port)
}

/// Like `serve_adjustable`, counting the requests answered.
pub async fn serve_counted(
    name: &str,
    delay: Duration,
) -> (AbortHandle, Arc<AtomicU64>, u16, Arc<AtomicU64>) {
    let delay = Arc::new(AtomicU64::new(delay.as_millis() as u64));
    let delay_ms = delay.clone();
    let requests = Arc::new(AtomicU64::new(0));
    let counted = requests.clone();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let name = name.to_string();
    let (task, handle) = abortable(async move {
        let mut conns = AbortOnDrop(Vec::new());
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let name = name.clone();
            let delay = delay_ms.clone();
            let counted = counted.clone();
            // The connections go when the server does.
            let (conn, conn_handle) = abortable(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(end) = find(&buf, b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        counted.fetch_add(1, Ordering::Relaxed);
                        let ms = delay.load(Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        let response = format!(
                            "HTTP/1.1 204 No Content\r\nX-Member: {}\r\nContent-Length: 0\r\n\r\n",
                            name
                        );
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                }
            });
            tokio::spawn(conn);
            conns.0.push(conn_handle);
        }
    });
    tokio::spawn(async move {
        let _ = task.await;
    });
    (handle, delay, port, requests)
}

/// Aborts its tasks when dropped, as a server's task is when it stops.
struct AbortOnDrop(Vec<AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Asks on `stream` which member it reached.
pub async fn which(stream: &mut AnyStream) -> Result<String> {
    stream
        .write_all(b"GET /which HTTP/1.1\r\nHost: member\r\n\r\n")
        .await?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    while find(&buf, b"\r\n\r\n").is_none() {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await??;
        if n == 0 {
            return Err(anyhow!("EOF"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&buf);
    text.lines()
        .find_map(|l| l.strip_prefix("X-Member: "))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow!("no member named in {:?}", text))
}

/// A connection through the outbound `tag` of `m`, for `sess`.
pub async fn connect(m: &OutboundManager, tag: &str, sess: &Session) -> Result<AnyStream> {
    let handler = m.get(tag).ok_or_else(|| anyhow!("no outbound [{}]", tag))?;
    let dns_client = sail::app::dns_client::DnsClient::new(
        &Default::default(),
        Arc::new(sail::net::DialOptions::default()),
        Default::default(),
    )?
    .into_shared();
    let stream = sail::net::connect_stream_outbound(sess, dns_client, &handler).await?;
    Ok(handler.stream()?.handle(sess, None, stream).await?)
}

/// A session from `source` to `destination`, port 80.
pub fn session(source: &str, destination: &str) -> Session {
    let destination = match destination.parse() {
        Ok(ip) => SocksAddr::Ip(std::net::SocketAddr::new(ip, 80)),
        Err(_) => SocksAddr::Domain(destination.to_string(), 80),
    };
    Session {
        source: format!("{}:40000", source).parse().unwrap(),
        destination,
        ..Default::default()
    }
}

/// Which member a new connection through `tag` reaches.
pub async fn reached(m: &OutboundManager, tag: &str, sess: &Session) -> Result<String> {
    let mut stream = connect(m, tag, sess).await?;
    which(&mut stream).await
}

/// Waits up to `within` for `f` to hold.
pub async fn eventually(within: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    f()
}

/// The member the group `tag` has selected.
pub fn selected(m: &OutboundManager, tag: &str) -> String {
    let selector = m.get_selector(tag).expect("a selector");
    let s = selector.try_read().expect("not locked").get_selected_tag();
    s
}

/// The latency of each member of the group `tag`, as last tested.
pub fn latencies(m: &OutboundManager, tag: &str) -> Vec<(String, Option<Duration>)> {
    let selector = m.get_selector(tag).expect("a selector");
    let l = selector
        .try_read()
        .expect("not locked")
        .get_latencies()
        .expect("latencies");
    l
}
