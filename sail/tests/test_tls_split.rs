//! A TLS stream whose read and write halves are driven from different tasks.
//!
//! Each half must keep its own wakeup: when the reader flushed queued records
//! with its own waker, the transport woke the reader instead of a writer
//! blocked on it, and the writer never ran again. These tests push heavy
//! traffic both ways through split streams and fail on a stall instead of
//! hanging.

#![cfg(feature = "tls")]

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use btls::pkey::PKey;
use btls::ssl::{Ssl, SslAcceptor, SslMethod, SslVersion};
use btls::x509::X509;
use foreign_types::ForeignTypeRef;
use sail::transport::tls::{BoringConnection, TlsClient};
use sail::transport::tls_stream::TlsStream;
use sail::transport::vision::VisionState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

type Tls<S> = TlsStream<BoringConnection, S>;

/// Long enough for debug builds; a stall never ends.
const DEADLINE: Duration = Duration::from_secs(20);

const CHUNK: usize = 64 * 1024;

struct Server {
    acceptor: SslAcceptor,
    cert_pem: String,
}

fn server(max_version: SslVersion) -> Server {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder
        .set_certificate(&X509::from_pem(cert.pem().as_bytes()).unwrap())
        .unwrap();
    builder
        .set_private_key(&PKey::private_key_from_pem(key_pair.serialize_pem().as_bytes()).unwrap())
        .unwrap();
    builder.set_max_proto_version(Some(max_version)).unwrap();
    Server {
        acceptor: builder.build(),
        cert_pem: cert.pem(),
    }
}

async fn handshake<S>(max_version: SslVersion, c: S, s: S, vision: bool) -> (Tls<S>, Tls<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server = server(max_version);
    let client = TlsClient::new(&[], Some(&server.cert_pem), false, None).unwrap();
    let vision = || {
        vision.then(|| {
            // Started but never switched: reads stay exact, one record each.
            let v = VisionState::default();
            v.start();
            v
        })
    };
    let ssl = Ssl::new(server.acceptor.context()).unwrap();
    let mut s = TlsStream::new(BoringConnection::server(ssl).unwrap(), s, vision());
    let (c, s_done) = tokio::join!(
        client.connect("localhost", c, vision(), None),
        s.handshake()
    );
    s_done.unwrap();
    let c = c.unwrap();
    let expected = match max_version {
        SslVersion::TLS1_2 => "TLSv1.2",
        _ => "TLSv1.3",
    };
    assert_eq!(c.conn().ssl().version_str(), expected);
    (c, s)
}

async fn tcp_pair(port: u16) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let (c, s) = tokio::join!(TcpStream::connect(("127.0.0.1", port)), listener.accept());
    let (c, s) = (c.unwrap(), s.unwrap().0);
    c.set_nodelay(true).unwrap();
    s.set_nodelay(true).unwrap();
    (c, s)
}

/// The byte at `pos` of the stream seeded with `seed`.
fn pattern(seed: u8, pos: u64) -> u8 {
    (pos.wrapping_mul(31) ^ (pos >> 11)) as u8 ^ seed
}

/// One TLS stream shared by a reader and a writer half, each locking it per
/// poll, as `tokio::io::split` does. Unlike tokio's halves, it lets the
/// writer reach the connection between writes (to request KeyUpdates).
struct Half<S>(Arc<Mutex<S>>);

impl<S: AsyncRead + Unpin> AsyncRead for Half<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Half<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock().unwrap()).poll_shutdown(cx)
    }
}

/// Writes `total` pattern bytes, requesting a TLS 1.3 KeyUpdate every
/// `key_update_every` chunks, then closes.
async fn send<S>(mut w: Half<Tls<S>>, seed: u8, total: u64, key_update_every: Option<u64>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0; CHUNK];
    let mut pos = 0u64;
    let mut chunks = 0u64;
    while pos < total {
        let n = (total - pos).min(CHUNK as u64) as usize;
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = pattern(seed, pos + i as u64);
        }
        if key_update_every.is_some_and(|every| chunks % every == every - 1) {
            let tls = w.0.lock().unwrap();
            // SAFETY: the SSL is alive and owned by the locked stream;
            // SSL_key_update only queues a message for the next write.
            let ok = unsafe {
                btls_sys::SSL_key_update(tls.conn().ssl().as_ptr(), 1 /* REQUESTED */)
            };
            assert_eq!(ok, 1, "SSL_key_update");
        }
        w.write_all(&buf[..n]).await.unwrap();
        pos += n as u64;
        chunks += 1;
    }
    w.flush().await.unwrap();
    w.shutdown().await.unwrap();
}

/// Reads `total` pattern bytes and then the peer's close_notify.
async fn recv<S>(mut r: Half<Tls<S>>, seed: u8, total: u64)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0; CHUNK];
    let mut pos = 0u64;
    loop {
        let n = r.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        for (i, b) in buf[..n].iter().enumerate() {
            assert_eq!(*b, pattern(seed, pos + i as u64), "byte {}", pos + i as u64);
        }
        pos += n as u64;
    }
    assert_eq!(pos, total, "stream ended early");
}

/// Sends `total` bytes each way at once, with each end's reader and writer in
/// tasks of their own. Panics if the transfer stalls.
async fn exchange<S>(c: Tls<S>, s: Tls<S>, total: u64, key_update_every: Option<u64>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let c = Arc::new(Mutex::new(c));
    let s = Arc::new(Mutex::new(s));
    let tasks = [
        tokio::spawn(send(Half(c.clone()), 1, total, key_update_every)),
        tokio::spawn(send(Half(s.clone()), 2, total, key_update_every)),
        tokio::spawn(recv(Half(c), 2, total)),
        tokio::spawn(recv(Half(s), 1, total)),
    ];
    let all = futures::future::try_join_all(tasks);
    match tokio::time::timeout(DEADLINE, all).await {
        Ok(done) => {
            done.unwrap();
        }
        Err(_) => panic!("split TLS transfer stalled"),
    }
}

const TOTAL: u64 = 32 * 1024 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_tls_split_tcp_tls13() {
    let (c, s) = tcp_pair(33300).await;
    let (c, s) = handshake(SslVersion::TLS1_3, c, s, false).await;
    exchange(c, s, TOTAL, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_tls_split_tcp_tls12() {
    let (c, s) = tcp_pair(33301).await;
    let (c, s) = handshake(SslVersion::TLS1_2, c, s, false).await;
    exchange(c, s, TOTAL, None).await;
}

// KeyUpdates both ways: each side's reply is queued while reading and goes
// out with its next write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_tls_split_tcp_key_update() {
    let (c, s) = tcp_pair(33302).await;
    let (c, s) = handshake(SslVersion::TLS1_3, c, s, false).await;
    exchange(c, s, TOTAL, Some(16)).await;
}

// Exact reads, one record at a time, as while Vision is pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_tls_split_tcp_vision_exact() {
    let (c, s) = tcp_pair(33303).await;
    let (c, s) = handshake(SslVersion::TLS1_3, c, s, true).await;
    exchange(c, s, TOTAL, None).await;
}

// A small in-memory pipe blocks writes all the time, on a single thread.
#[tokio::test]
async fn test_tls_split_duplex() {
    let (c, s) = tokio::io::duplex(4096);
    let (c, s) = handshake(SslVersion::TLS1_3, c, s, false).await;
    exchange(c, s, 8 * 1024 * 1024, None).await;
}

// The peer's last records and its close_notify arrive together while this
// side still has records queued for a full transport. Reading must deliver
// those records before the end of the stream, and not wait for the queued
// writes.
#[tokio::test]
async fn test_tls_close_while_writes_queued() {
    let (c, s) = tokio::io::duplex(4096);
    let (mut c, mut s) = handshake(SslVersion::TLS1_3, c, s, false).await;

    // The client never reads, so the server's records back up.
    let big = vec![0u8; 1024 * 1024];
    let blocked = tokio::time::timeout(Duration::from_millis(200), s.write_all(&big)).await;
    assert!(blocked.is_err(), "the transport should be full");

    c.write_all(b"last words").await.unwrap();
    c.shutdown().await.unwrap();

    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut got))
        .await
        .expect("read stalled")
        .unwrap();
    assert_eq!(got, b"last words");
}

const BENCH_SIZE: usize = 64 * 1024 * 1024;

/// Seconds to send `BENCH_SIZE` bytes one way.
async fn one_way(port: u16) -> f64 {
    let (c, s) = tcp_pair(port).await;
    let (mut c, mut s) = handshake(SslVersion::TLS1_3, c, s, false).await;
    let start = Instant::now();
    let writer = async {
        let buf = vec![7u8; CHUNK];
        for _ in 0..BENCH_SIZE / CHUNK {
            c.write_all(&buf).await.unwrap();
        }
        c.flush().await.unwrap();
    };
    let reader = async {
        let mut buf = vec![0u8; CHUNK];
        let mut got = 0;
        while got < BENCH_SIZE {
            got += s.read(&mut buf).await.unwrap();
        }
    };
    tokio::join!(writer, reader);
    start.elapsed().as_secs_f64()
}

/// Seconds to send `BENCH_SIZE` bytes each way at once, each end reading and
/// writing from one task.
async fn both_ways(port: u16) -> f64 {
    let (c, s) = tcp_pair(port).await;
    let (c, s) = handshake(SslVersion::TLS1_3, c, s, false).await;
    let end = |mut t: Tls<TcpStream>| async move {
        let wbuf = vec![7u8; CHUNK];
        let mut rbuf = vec![0u8; CHUNK];
        let (mut r, mut w) = tokio::io::split(&mut t);
        let writer = async {
            for _ in 0..BENCH_SIZE / CHUNK {
                w.write_all(&wbuf).await.unwrap();
            }
            w.flush().await.unwrap();
        };
        let reader = async {
            let mut got = 0;
            while got < BENCH_SIZE {
                got += r.read(&mut rbuf).await.unwrap();
            }
        };
        tokio::join!(writer, reader);
        // Closed once both ends are done, so no data is lost to a reset.
        t
    };
    let start = Instant::now();
    let _ends = tokio::join!(end(c), end(s));
    start.elapsed().as_secs_f64()
}

/// Throughput over loopback, the median of several runs: 64 MiB one way, then
/// 64 MiB each way at once. Run with
/// `cargo test --release --test test_tls_split bench -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_tls_throughput() {
    const RUNS: u16 = 9;
    let mib = (BENCH_SIZE / (1024 * 1024)) as f64;
    let median = |mut v: Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    };
    let mut one = Vec::new();
    let mut both = Vec::new();
    for i in 0..RUNS {
        one.push(mib / one_way(33320 + i).await);
        both.push(2.0 * mib / both_ways(33340 + i).await);
    }
    println!(
        "one way:   median {:.0} MiB/s of {one:.0?}",
        median(one.clone())
    );
    println!(
        "both ways: median {:.0} MiB/s of {both:.0?}",
        median(both.clone())
    );
}
