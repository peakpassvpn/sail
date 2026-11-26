//! Sail/1 between sail instances (sail#60): streams share one TLS
//! connection, the server's padding scheme reaches the client, a user the
//! rules refuse and a target that refuses fail fast, a half-close
//! carries through, and UDP goes over the same session's streams.
//!
//! A counting TCP forwarder in front of the server shows the client's
//! connections to it.

#![cfg(all(
    feature = "inbound-sail",
    feature = "outbound-sail",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

/// The 32 bytes 0x5a and 0x33, as tokens.
const ALICE: &str = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo";
const BOB: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM";
/// A token no user has: 32 bytes of 0x11.
const NOBODY: &str = "ERERERERERERERERERERERERERERERERERERERERERE";

struct Certs {
    cert: String,
    key: String,
    _dir: common::TempDir,
}

fn certs(name: &str) -> anyhow::Result<Certs> {
    let dir = common::TempDir::new(&format!("sail-{}", name))?;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    Ok(Certs {
        cert: common::json_path(&cert_path),
        key: common::json_path(&key_path),
        _dir: dir,
    })
}

/// A TCP forwarder to `target`, and the count of its connections.
async fn counting_forwarder(target: u16) -> anyhow::Result<(u16, Arc<AtomicUsize>)> {
    slow_forwarder(target, Duration::ZERO).await
}

/// A counting forwarder that holds each connection `delay` before it
/// forwards anything: a dial that takes that long.
async fn slow_forwarder(target: u16, delay: Duration) -> anyhow::Result<(u16, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", target)).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    Ok((port, count))
}

fn session_to(addr: SocketAddr) -> Session {
    Session {
        destination: SocksAddr::from(addr),
        ..Default::default()
    }
}

/// Echoes `len` bytes through a new stream from the SOCKS server at
/// `socks_port`.
async fn echo_stream(
    socks_port: u16,
    echo: SocketAddr,
    seed: u8,
    len: usize,
) -> anyhow::Result<()> {
    let mut stream = timeout(
        Duration::from_secs(5),
        common::new_socks_stream("127.0.0.1", socks_port, &session_to(echo), None, None),
    )
    .await??;
    let data: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect();
    let (mut r, mut w) = tokio::io::split(&mut stream);
    let write = async {
        w.write_all(&data).await?;
        anyhow::Ok(())
    };
    let read = async {
        let mut back = vec![0u8; len];
        r.read_exact(&mut back).await?;
        anyhow::Ok(back)
    };
    let (written, back) =
        timeout(Duration::from_secs(10), async { tokio::join!(write, read) }).await?;
    written?;
    anyhow::ensure!(back? == data, "stream {} echoed something else", seed);
    Ok(())
}

/// Echoes a few packets through each of two UDP associations: UoT over
/// Sail/1 streams, each packet naming its address.
async fn echo_datagrams(socks_port: u16, echo: SocketAddr) -> anyhow::Result<()> {
    let sess = session_to(echo);
    for round in 0..2u8 {
        let dgram = timeout(
            Duration::from_secs(5),
            common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None),
        )
        .await??;
        let (mut r, mut s) = dgram.split();
        for i in 0..3u8 {
            let msg = vec![round * 16 + i; 100 + i as usize * 500];
            s.send_to(&msg, &sess.destination).await?;
            let mut buf = vec![0u8; 4096];
            let (n, from) = timeout(Duration::from_secs(5), r.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("udp round {} packet {}: no echo", round, i))??;
            anyhow::ensure!(buf[..n] == msg[..], "udp echo mismatch");
            anyhow::ensure!(from == sess.destination, "udp echo from {}", from);
        }
    }
    Ok(())
}

fn socks_to_sail(socks_port: u16, server_port: u16, token: &str, certs: &Certs) -> String {
    serde_json::json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [{
            "type": "sail",
            "server": "127.0.0.1",
            "server_port": server_port,
            "token": token,
            "tls": {
                "enabled": true,
                "server_name": "localhost",
                "certificate_path": certs.cert,
            }
        }]
    })
    .to_string()
}

/// A server that lets only `alice` through: the user's name has to reach
/// routing for anything to work.
fn sail_server(port: u16, certs: &Certs) -> String {
    serde_json::json!({
        "inbounds": [{
            "type": "sail",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [
                { "name": "alice", "token": ALICE },
                { "name": "bob", "token": BOB }
            ],
            "padding_scheme": ["stop=4", "0=10-20", "1=200-300", "2=100-200,c,300-400", "3=50-60"],
            "tls": {
                "enabled": true,
                "certificate_path": certs.cert,
                "key_path": certs.key,
                "alpn": ["h2", "http/1.1"]
            }
        }],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" }
        ],
        "route": {
            "rules": [{ "auth_user": ["alice"], "outbound": "direct" }],
            "final": "block"
        }
    })
    .to_string()
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

/// A server that reads to its peer's FIN, then answers how much it read
/// and closes: only a half-close lets the answer come back.
async fn counting_server() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut all = Vec::new();
                if conn.read_to_end(&mut all).await.is_ok() {
                    let _ = conn.write_all(format!("{}", all.len()).as_bytes()).await;
                }
            });
        }
    });
    Ok(addr)
}

// app(socks) -> sail(sail) -> forwarder -> sail(sail, alice only) -> targets
#[test]
fn test_sail_to_sail() -> anyhow::Result<()> {
    let certs = certs("sail")?;
    common::retry_port_clash(|| {
        let [server, socks, nobody, bob, closed] = common::free_ports();
        let rt = runtime()?;
        let (forwarder, connections) = rt.block_on(counting_forwarder(server))?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                sail_server(server, &certs),
                socks_to_sail(socks, forwarder, ALICE, &certs),
                socks_to_sail(nobody, server, NOBODY, &certs),
                socks_to_sail(bob, server, BOB, &certs),
            ],
        )?;
        let result = rt.block_on(async {
            let (echo, echo_server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_server = tokio::spawn(echo_server);
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Sequential streams, then concurrent ones: one connection for
            // all of them, streams sharing it (6 concurrent stays below
            // STREAMS_PER_SESSION = 8 while the last sequential SOCKS stream
            // finishes closing).
            for i in 0..5u8 {
                echo_stream(socks, echo, i, 1000 + 40_000 * i as usize).await?;
            }
            let concurrent: Vec<_> = (0..6u8)
                .map(|i| tokio::spawn(echo_stream(socks, echo, 100 + i, 300_000)))
                .collect();
            for task in concurrent {
                task.await??;
            }
            anyhow::ensure!(
                connections.load(Ordering::SeqCst) == 1,
                "{} connections for 11 streams, not 1",
                connections.load(Ordering::SeqCst)
            );

            // A half-close reaches the target, and its answer comes back.
            let counter = counting_server().await?;
            let mut stream =
                common::new_socks_stream("127.0.0.1", socks, &session_to(counter), None, None)
                    .await?;
            stream.write_all(&[9u8; 70_000]).await?;
            stream.shutdown().await?;
            let mut answer = String::new();
            timeout(Duration::from_secs(5), stream.read_to_string(&mut answer)).await??;
            anyhow::ensure!(answer == "70000", "the target answered {:?}", answer);

            // A target that refuses: the stream fails at once, not when
            // some timeout is up.
            let start = Instant::now();
            let refused = SocketAddr::from(([127, 0, 0, 1], closed));
            let result = echo_stream(socks, refused, 1, 10).await;
            anyhow::ensure!(result.is_err(), "a refused target echoed");
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(3),
                "a refused target took {:?}",
                start.elapsed()
            );

            // A token no user has, and a user the rules do not let through.
            for port in [nobody, bob] {
                let result = echo_stream(port, echo, 1, 10).await;
                anyhow::ensure!(result.is_err(), "port {}: expected a failure", port);
            }
            // The refused stream did not take the session down.
            echo_stream(socks, echo, 7, 5000).await?;

            // UDP, over streams of the same session.
            let (udp_echo, udp_server) = common::run_udp_echo_server("127.0.0.1:0").await?;
            let udp_server = tokio::spawn(udp_server);
            let udp = echo_datagrams(socks, udp_echo).await;
            udp_server.abort();
            udp?;
            anyhow::ensure!(
                connections.load(Ordering::SeqCst) == 1,
                "UDP opened {} connections in all, not 1",
                connections.load(Ordering::SeqCst)
            );
            echo_server.abort();
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// A burst of streams on cold pools, each dial held 300 ms: 6 share one
// session's dial, and 20 three, with STREAMS_PER_SESSION at 8. Each burst
// through a client of its own.
#[test]
fn test_sail_cold_pool_shares_dials() -> anyhow::Result<()> {
    let certs = certs("sail-cold")?;
    common::retry_port_clash(|| {
        let [server, six, twenty] = common::free_ports();
        let rt = runtime()?;
        let (to6, count6) = rt.block_on(slow_forwarder(server, Duration::from_millis(300)))?;
        let (to20, count20) = rt.block_on(slow_forwarder(server, Duration::from_millis(300)))?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                sail_server(server, &certs),
                socks_to_sail(six, to6, ALICE, &certs),
                socks_to_sail(twenty, to20, ALICE, &certs),
            ],
        )?;
        let result = rt.block_on(async {
            let (echo, echo_server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_server = tokio::spawn(echo_server);
            tokio::time::sleep(Duration::from_millis(200)).await;
            for (port, streams, count, want) in [(six, 6u8, &count6, 1), (twenty, 20, &count20, 3)]
            {
                let burst: Vec<_> = (0..streams)
                    .map(|i| tokio::spawn(echo_stream(port, echo, i, 20_000)))
                    .collect();
                for task in burst {
                    task.await??;
                }
                anyhow::ensure!(
                    count.load(Ordering::SeqCst) == want,
                    "{} streams at once on a cold pool: {} connections, not {}",
                    streams,
                    count.load(Ordering::SeqCst),
                    want
                );
            }
            echo_server.abort();
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

/// Captures outer TLS 1.3 `0x17` Application Data record body lengths in
/// both directions without decrypting or altering TCP framing.
#[derive(Default)]
struct TlsRecordTap {
    connections: AtomicUsize,
    close_on_drain: AtomicBool,
    c2s_by_conn: Mutex<Vec<Vec<usize>>>,
    c2s_phase: Mutex<Vec<usize>>,
    s2c_phase: Mutex<Vec<usize>>,
}

impl TlsRecordTap {
    fn clear_phase(&self) {
        self.c2s_phase.lock().unwrap().clear();
        self.s2c_phase.lock().unwrap().clear();
    }

    fn take_phase(&self) -> (Vec<usize>, Vec<usize>) {
        (
            std::mem::take(&mut *self.c2s_phase.lock().unwrap()),
            std::mem::take(&mut *self.s2c_phase.lock().unwrap()),
        )
    }
}

struct RecordScanner {
    head: [u8; 5],
    head_len: usize,
    skip_body: usize,
}

impl RecordScanner {
    fn new() -> Self {
        Self {
            head: [0; 5],
            head_len: 0,
            skip_body: 0,
        }
    }

    fn feed(&mut self, mut bytes: &[u8], mut on_app_data: impl FnMut(usize)) {
        while !bytes.is_empty() {
            if self.skip_body > 0 {
                let take = self.skip_body.min(bytes.len());
                self.skip_body -= take;
                bytes = &bytes[take..];
                continue;
            }
            let need = 5 - self.head_len;
            let take = need.min(bytes.len());
            self.head[self.head_len..self.head_len + take].copy_from_slice(&bytes[..take]);
            self.head_len += take;
            bytes = &bytes[take..];
            if self.head_len == 5 {
                let kind = self.head[0];
                let body_len = u16::from_be_bytes([self.head[3], self.head[4]]) as usize;
                self.head_len = 0;
                self.skip_body = body_len;
                if kind == 0x17 {
                    on_app_data(body_len);
                }
            }
        }
    }
}

async fn tapping_forwarder(target: u16) -> anyhow::Result<(u16, Arc<TlsRecordTap>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let tap = Arc::new(TlsRecordTap::default());
    let shared = tap.clone();
    tokio::spawn(async move {
        while let Ok((inbound, _)) = listener.accept().await {
            let idx = shared.connections.fetch_add(1, Ordering::SeqCst);
            shared.c2s_by_conn.lock().unwrap().push(Vec::new());
            let tap = shared.clone();
            tokio::spawn(async move {
                let Ok(outbound) = TcpStream::connect(("127.0.0.1", target)).await else {
                    return;
                };
                let (mut ir, mut iw) = inbound.into_split();
                let (mut or, mut ow) = outbound.into_split();
                let tap_c2s = tap.clone();
                let c2s = async move {
                    let mut buf = vec![0u8; 32 * 1024];
                    let mut scan = RecordScanner::new();
                    loop {
                        if tap_c2s.close_on_drain.load(Ordering::SeqCst) {
                            break;
                        }
                        match timeout(Duration::from_millis(25), ir.read(&mut buf)).await {
                            Ok(Ok(0)) | Ok(Err(_)) => break,
                            Ok(Ok(n)) => {
                                scan.feed(&buf[..n], |len| {
                                    tap_c2s.c2s_by_conn.lock().unwrap()[idx].push(len);
                                    tap_c2s.c2s_phase.lock().unwrap().push(len);
                                });
                                if ow.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    let _ = ow.shutdown().await;
                };
                let tap_s2c = tap.clone();
                let s2c = async move {
                    let mut buf = vec![0u8; 32 * 1024];
                    let mut scan = RecordScanner::new();
                    loop {
                        if tap_s2c.close_on_drain.load(Ordering::SeqCst) {
                            break;
                        }
                        match timeout(Duration::from_millis(25), or.read(&mut buf)).await {
                            Ok(Ok(0)) | Ok(Err(_)) => break,
                            Ok(Ok(n)) => {
                                scan.feed(&buf[..n], |len| {
                                    tap_s2c.s2c_phase.lock().unwrap().push(len);
                                });
                                if iw.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    let _ = iw.shutdown().await;
                };
                let _ = tokio::join!(c2s, s2c);
            });
        }
    });
    Ok((port, tap))
}

fn sail_server_with_scheme(port: u16, certs: &Certs, scheme: Option<&[&str]>) -> String {
    let mut inbound = serde_json::json!({
        "type": "sail",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "name": "alice", "token": ALICE }],
        "tls": {
            "enabled": true,
            "certificate_path": certs.cert,
            "key_path": certs.key,
            "alpn": ["h2", "http/1.1"]
        }
    });
    if let Some(lines) = scheme {
        inbound["padding_scheme"] = serde_json::json!(lines);
    }
    serde_json::json!({
        "inbounds": [inbound],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    })
    .to_string()
}

// Verifies Phase-4 outer TLS 1.3 `0x17` record-size properties (sail#60):
// (a) Built-in default scheme widens packet 0 to 16..=96 bytes (outer
//     record 76..=156 B, non-fixed across fresh sessions);
// (b) Reopening a stream on an idle warm session (`pkt >= stop`,
//     `active_streams == 1`) pads the opening burst in both directions,
//     whereas concurrent streams (`active_streams > 1`) and bulk MAX_DATA
//     transfers run unpadded in 16,401 B outer records;
// (c) Configuring `padding_scheme: ["stop=0"]` disables warm-burst padding.
#[test]
fn test_sail_phase4_padding_and_warm_idle_burst() -> anyhow::Result<()> {
    let certs = certs("sail-pad")?;
    common::retry_port_clash(|| {
        let [default_srv, zero_srv, default_socks, zero_socks] = common::free_ports();
        let rt = runtime()?;
        let (default_fwd, default_tap) = rt.block_on(tapping_forwarder(default_srv))?;
        let (zero_fwd, zero_tap) = rt.block_on(tapping_forwarder(zero_srv))?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                sail_server_with_scheme(default_srv, &certs, None),
                sail_server_with_scheme(zero_srv, &certs, Some(&["stop=0"])),
                socks_to_sail(default_socks, default_fwd, ALICE, &certs),
                socks_to_sail(zero_socks, zero_fwd, ALICE, &certs),
            ],
        )?;
        let result = rt.block_on(async {
            let (echo, echo_server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_server = tokio::spawn(echo_server);
            tokio::time::sleep(Duration::from_millis(200)).await;

            // (a) Fresh sessions with the built-in default scheme: the
            // client's second `0x17` record (after TLS 1.3 Finished = 53 B)
            // carries the 43 B prelude head + 16..=96 B pad + 17 B AEAD =
            // 76..=156 B, varying across sessions instead of fixed 90 B.
            let mut prelude_records = BTreeSet::new();
            for i in 0..10u8 {
                echo_stream(default_socks, echo, i, 64).await?;
                if i < 9 {
                    default_tap.close_on_drain.store(true, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    default_tap.close_on_drain.store(false, Ordering::SeqCst);
                }
            }
            {
                let by_conn = default_tap.c2s_by_conn.lock().unwrap();
                anyhow::ensure!(
                    by_conn.len() == 10,
                    "expected 10 fresh sessions, got {}",
                    by_conn.len()
                );
                for (idx, recs) in by_conn.iter().enumerate() {
                    anyhow::ensure!(
                        recs.len() >= 2 && recs[0] == 53,
                        "conn {idx}: unexpected initial 0x17 records {recs:?}"
                    );
                    let prelude_rec = recs[1];
                    anyhow::ensure!(
                        (76..=156).contains(&prelude_rec),
                        "conn {idx}: prelude outer record {prelude_rec} not in 76..=156"
                    );
                    prelude_records.insert(prelude_rec);
                }
            }
            anyhow::ensure!(
                prelude_records.len() > 1,
                "prelude outer record did not vary across 10 sessions: {prelude_records:?}"
            );

            // Warm the current pooled session (conn 9) well past `stop=8`
            // on both client and server, then let all streams close so
            // `active_streams == 0`.
            for i in 0..4u8 {
                echo_stream(default_socks, echo, 30 + i, 4096).await?;
            }
            tokio::time::sleep(Duration::from_millis(80)).await;

            // (b1) Reopen streams on the idle warm session (`0 -> 1` active
            // streams): no bare 33 B (`SYN+hdr`) or 23 B (`Status`) record
            // appears, opening records are padded (`>= 117 B`) and vary.
            let mut warm_c2s_first = BTreeSet::new();
            let mut warm_s2c_first = BTreeSet::new();
            for round in 0..6u8 {
                default_tap.clear_phase();
                let mut s = timeout(
                    Duration::from_secs(5),
                    common::new_socks_stream(
                        "127.0.0.1",
                        default_socks,
                        &session_to(echo),
                        None,
                        None,
                    ),
                )
                .await??;
                // Simulate an inner TLS handshake flight (~1,971 B) + follow-up.
                let flight: Vec<u8> = (0..1971)
                    .map(|k| (k as u8).wrapping_mul(17) ^ round)
                    .collect();
                s.write_all(&flight).await?;
                let mut echoed = vec![0u8; flight.len()];
                s.read_exact(&mut echoed).await?;
                anyhow::ensure!(echoed == flight, "warm round {round} echo mismatch");
                drop(s);
                tokio::time::sleep(Duration::from_millis(60)).await;

                let (c2s, s2c) = default_tap.take_phase();
                anyhow::ensure!(
                    !c2s.is_empty() && !s2c.is_empty(),
                    "warm round {round}: empty tap c2s={c2s:?} s2c={s2c:?}"
                );
                // Opening c2s SYN (`100..400` + 17 B AEAD) and stream header
                // (`500..1000` + 17 B AEAD), plus s2c Status (`100..400` + 17 B).
                anyhow::ensure!(
                    c2s[0] >= 117 && c2s.get(1).copied().unwrap_or(0) >= 517,
                    "warm round {round}: c2s opening records not padded: {c2s:?}"
                );
                anyhow::ensure!(
                    s2c[0] >= 117,
                    "warm round {round}: s2c status record not padded: {s2c:?}"
                );
                warm_c2s_first.insert(c2s[0]);
                warm_s2c_first.insert(s2c[0]);
            }
            anyhow::ensure!(
                warm_c2s_first.len() > 1 && warm_s2c_first.len() > 1,
                "warm opening records did not vary: c2s={warm_c2s_first:?} s2c={warm_s2c_first:?}"
            );
            anyhow::ensure!(
                default_tap.connections.load(Ordering::SeqCst) == 10,
                "warm rounds dialled extra connections: {}",
                default_tap.connections.load(Ordering::SeqCst)
            );

            // (b2) Hold one stream active (`active_streams == 1`) and open
            // a concurrent stream transferring 256 KiB: no warm-burst
            // padding arms on the concurrent stream, and bulk MAX_DATA
            // frames pack into exact 16,401 B single TLS records.
            let mut held = common::new_socks_stream(
                "127.0.0.1",
                default_socks,
                &session_to(echo),
                None,
                None,
            )
            .await?;
            held.write_all(b"keep-active").await?;
            let mut held_back = [0u8; 11];
            held.read_exact(&mut held_back).await?;
            // Drain the held stream's own opening burst before measuring the
            // concurrent bulk stream.
            for _ in 0..3 {
                held.write_all(b"x").await?;
                let mut one = [0u8; 1];
                held.read_exact(&mut one).await?;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            default_tap.clear_phase();

            echo_stream(default_socks, echo, 0x77, 256 * 1024).await?;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let (bulk_c2s, _) = default_tap.take_phase();
            let full_records = bulk_c2s.iter().filter(|&&n| n == 16_401).count();
            anyhow::ensure!(
                full_records >= 14,
                "expected >= 14 full 16,401 B bulk records on concurrent stream, got {full_records} in {bulk_c2s:?}"
            );
            // Concurrent stream's opening record is unpadded (< 100 B).
            anyhow::ensure!(
                bulk_c2s[0] < 100,
                "concurrent stream unexpectedly armed warm padding: {bulk_c2s:?}"
            );
            drop(held);

            // (c) With `padding_scheme: ["stop=0"]`, warm idle reopenings
            // never arm padding on either end once the server's scheme
            // has been received.
            for i in 0..4u8 {
                echo_stream(zero_socks, echo, 90 + i, 512).await?;
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
            zero_tap.clear_phase();
            echo_stream(zero_socks, echo, 99, 10).await?;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let (off_c2s, off_s2c) = zero_tap.take_phase();
            anyhow::ensure!(
                !off_c2s.is_empty()
                    && !off_s2c.is_empty()
                    && off_c2s.iter().all(|&n| n < 100)
                    && off_s2c.iter().all(|&n| n < 100),
                "stop=0 warm session unexpectedly padded small echo: c2s={off_c2s:?} s2c={off_s2c:?}"
            );

            echo_server.abort();
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}
