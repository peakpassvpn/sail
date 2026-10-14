//! The keepalive on a connection set up as the outbound and the inbound set
//! theirs up, the two ends joined by an in-memory pipe.
//!
//! A pong late behind what the peer sends does not end the connection;
//! nothing at all from the peer does, after `ping_timeout`. Time paused.
//!
//! Stalls: h2 reads no frame while one it owes (a pong, its own ping, a
//! settings ack) waits for room, and there is none while a DATA frame is
//! half written. With bulk sent both ways over a pipe too small for it,
//! each end can be stuck writing with a frame owed, neither reading again
//! until `ping_timeout` ends the connection. Which ends ping decides
//! whether that can happen; `survey` shows what each choice comes to.
//! It needs real time on threads of its own: paused, a ping goes out only
//! once every task waits, so never in the midst of a transfer, and with a
//! paced link between the pipes no stall came either, the reader always
//! leaving the writer room.

use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::future::{abortable, AbortHandle, Aborted};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::gun::GunStream;
use super::{inbound, keepalive, Counted};

/// The pipe each way: small, so that writes block.
const PIPE: usize = 64 * 1024;

/// One end of a connection.
struct End {
    /// Its side of each call, in the order the client made them.
    calls: Vec<GunStream>,
    received: std::sync::Arc<portable_atomic::AtomicU64>,
    ping_pong: Option<h2::PingPong>,
    /// The task running the connection: `Aborted` once given up.
    task: JoinHandle<Result<(), Aborted>>,
    abort: AbortHandle,
    /// The client's: with every one gone, h2 ends the connection once its
    /// calls do.
    _send: Option<h2::client::SendRequest<Bytes>>,
}

impl End {
    /// Pings every `interval` as `keepalive` does, the round skipped
    /// unless `wanted`.
    fn ping(
        &mut self,
        interval: Duration,
        timeout: Duration,
        wanted: impl Fn() -> bool + Send + 'static,
    ) {
        keepalive(
            self.ping_pong.take().unwrap(),
            self.received.clone(),
            interval,
            timeout,
            wanted,
            self.abort.clone(),
        );
    }
}

impl Drop for End {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

/// A connection over `client_io` and `server_io` carrying `calls` calls,
/// each end set up as sail sets it up, without the keepalive.
async fn connect<C, S>(client_io: C, server_io: S, calls: usize) -> (End, End)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client_io, client_received) = Counted::new(client_io);
    let (server_io, server_received) = Counted::new(server_io);
    let handshake = tokio::spawn(async move {
        inbound::stream::builder()
            .handshake::<_, Bytes>(server_io)
            .await
            .unwrap()
    });
    let (send, mut client) = super::client_builder()
        .handshake::<_, Bytes>(client_io)
        .await
        .unwrap();
    let mut server = handshake.await.unwrap();

    let client_ping = client.ping_pong();
    let (running, client_abort) = abortable(async move {
        let _ = client.await;
    });
    let client_task = tokio::spawn(running);

    let server_ping = server.ping_pong();
    let (accepted, mut accepting) = mpsc::unbounded_channel();
    let (running, server_abort) = abortable(async move {
        while let Some(Ok((request, mut respond))) = server.accept().await {
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let _ = accepted.send(GunStream::server(send, request.into_body()));
        }
    });
    let server_task = tokio::spawn(running);

    let mut client_calls = Vec::new();
    for _ in 0..calls {
        let mut ready = send.clone().ready().await.unwrap();
        let request = http::Request::post("http://localhost/Test/Tun")
            .body(())
            .unwrap();
        let (response, stream) = ready.send_request(request, false).unwrap();
        client_calls.push(GunStream::client(stream, response));
    }
    let mut server_calls = Vec::new();
    for _ in 0..calls {
        server_calls.push(accepting.recv().await.unwrap());
    }
    let client = End {
        calls: client_calls,
        received: client_received,
        ping_pong: client_ping,
        task: client_task,
        abort: client_abort,
        _send: Some(send),
    };
    let server = End {
        calls: server_calls,
        received: server_received,
        ping_pong: server_ping,
        task: server_task,
        abort: server_abort,
        _send: None,
    };
    (client, server)
}

/// Joins `client` to `server`, passing everything on as it is but the
/// server's pongs: those are held back `delay`, or dropped with none.
fn relay(client: DuplexStream, server: DuplexStream, delay: Option<Duration>) {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
    });
    let (frames, mut to_client) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(frame) = to_client.recv().await {
            if client_write.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
    // The server sends nothing but frames: a nine-byte header, the length
    // in its first three bytes, then the payload.
    tokio::spawn(async move {
        loop {
            let mut frame = vec![0u8; 9];
            if server_read.read_exact(&mut frame).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes([0, frame[0], frame[1], frame[2]]) as usize;
            frame.resize(9 + len, 0);
            if server_read.read_exact(&mut frame[9..]).await.is_err() {
                break;
            }
            // PING, with ACK.
            let pong = frame[3] == 0x6 && frame[4] & 0x1 != 0;
            if !pong {
                if frames.send(frame).is_err() {
                    break;
                }
                continue;
            }
            if let Some(delay) = delay {
                let frames = frames.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = frames.send(frame);
                });
            }
        }
    });
}

/// A pong ten seconds late, `ping_timeout` three, a kilobyte from the
/// server every half second: the client's connection stays, as long as
/// the bytes keep coming.
#[tokio::test(start_paused = true)]
async fn a_late_pong_behind_data_keeps_the_connection() {
    let (client_io, relayed_client) = tokio::io::duplex(PIPE);
    let (relayed_server, server_io) = tokio::io::duplex(PIPE);
    relay(
        relayed_client,
        relayed_server,
        Some(Duration::from_secs(10)),
    );
    let (mut client, mut server) = connect(client_io, server_io, 1).await;
    client.ping(Duration::from_secs(1), Duration::from_secs(3), || true);

    let mut down = client.calls.pop().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while matches!(down.read(&mut buf).await, Ok(n) if n > 0) {}
    });
    let mut up = server.calls.pop().unwrap();
    for _ in 0..40 {
        up.write_all(&[7; 1024]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        !client.task.is_finished(),
        "the connection was given up while bytes kept arriving"
    );
}

/// Nothing from the server, pongs dropped: the client's connection is
/// given up `ping_timeout` after its ping, not before.
#[tokio::test(start_paused = true)]
async fn nothing_from_the_peer_ends_the_connection() {
    let (client_io, relayed_client) = tokio::io::duplex(PIPE);
    let (relayed_server, server_io) = tokio::io::duplex(PIPE);
    relay(relayed_client, relayed_server, None);
    let (mut client, _server) = connect(client_io, server_io, 1).await;
    client.ping(Duration::from_secs(1), Duration::from_secs(3), || true);

    // The ping at one second, given up at four.
    tokio::time::sleep(Duration::from_millis(3900)).await;
    assert!(!client.task.is_finished(), "given up before ping_timeout");
    let ended = tokio::time::timeout(Duration::from_millis(200), &mut client.task).await;
    assert!(
        matches!(ended, Ok(Ok(Err(Aborted)))),
        "not given up after ping_timeout: {:?}",
        ended
    );
}

/// Which ends start pings.
#[derive(Clone, Copy, Debug)]
enum Pings {
    /// Both, every interval: what sail does.
    Both,
    Client,
    Server,
    /// The client every interval; the server only after this long with
    /// nothing at all from the client, as grpc-go's server keepalive.
    IdleServer(Duration),
}

/// What an end sends on each call.
#[derive(Clone, Copy, Debug)]
struct Shape {
    /// Nothing before then.
    start: Duration,
    /// A burst this big, written as fast as it goes,
    burst: usize,
    /// one each this long; zero: one burst, all of it.
    every: Duration,
}

impl Shape {
    const BULK: Shape = Shape {
        start: Duration::ZERO,
        burst: usize::MAX,
        every: Duration::ZERO,
    };

    /// `burst` KiB every `every_ms`.
    const fn bursts(burst: usize, every_ms: u64) -> Self {
        Shape {
            start: Duration::ZERO,
            burst: burst * 1024,
            every: Duration::from_millis(every_ms),
        }
    }

    const fn starting(self, start_ms: u64) -> Self {
        Shape {
            start: Duration::from_millis(start_ms),
            ..self
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Load {
    pings: Pings,
    /// Each way, over all the calls.
    bytes: usize,
    calls: usize,
    up: Shape,
    down: Shape,
    /// The client's keepalive interval, and the server's under `Both` and
    /// `Server`.
    interval: Duration,
    /// How much later the server's keepalive starts than the client's.
    offset: Duration,
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Done,
    /// What had arrived each way when nothing moved any more.
    Stalled {
        up: u64,
        down: u64,
    },
}

/// What a run came to, and the pings each end sent.
#[derive(Debug)]
struct Ran {
    outcome: Outcome,
    client_pings: u64,
    server_pings: u64,
}

/// No byte moving either way for this long is a stall: far longer than
/// any pause in a load, far shorter than the ping timeout.
const PATIENCE: Duration = Duration::from_secs(2);

/// Long enough that no stall here is ended by it.
const PING_TIMEOUT: Duration = Duration::from_secs(30);

static CHUNK: [u8; 16 * 1024] = [0x5a; 16 * 1024];

async fn send(mut to: impl AsyncWrite + Unpin, mut left: usize, shape: Shape) {
    tokio::time::sleep(shape.start).await;
    let mut next = Instant::now();
    while left > 0 {
        let mut burst = shape.burst.min(left);
        left -= burst;
        while burst > 0 {
            let n = burst.min(CHUNK.len());
            if to.write_all(&CHUNK[..n]).await.is_err() {
                return;
            }
            burst -= n;
        }
        next += shape.every;
        tokio::time::sleep_until(next).await;
    }
}

async fn count(mut from: impl AsyncRead + Unpin, counted: Arc<portable_atomic::AtomicU64>) {
    let mut buf = vec![0u8; 64 * 1024];
    while let Ok(n) = from.read(&mut buf).await {
        if n == 0 {
            break;
        }
        counted.fetch_add(n as u64, Relaxed);
    }
}

/// Starts `end`'s keepalive after `after`, each round taken only if
/// `wanted`; the pings it sends counted in `sent`.
fn ping(
    end: &mut End,
    after: Duration,
    interval: Duration,
    wanted: impl Fn() -> bool + Send + 'static,
    sent: Arc<portable_atomic::AtomicU64>,
) {
    let ping_pong = end.ping_pong.take().unwrap();
    let received = end.received.clone();
    let abort = end.abort.clone();
    let wanted = move || {
        let wanted = wanted();
        if wanted {
            sent.fetch_add(1, Relaxed);
        }
        wanted
    };
    tokio::spawn(async move {
        tokio::time::sleep(after).await;
        keepalive(ping_pong, received, interval, PING_TIMEOUT, wanted, abort);
    });
}

/// `load` over a pipe of `PIPE` each way, as far as it goes.
async fn run(load: Load) -> Ran {
    let (client_io, server_io) = tokio::io::duplex(PIPE);
    let (mut client, mut server) = connect(client_io, server_io, load.calls).await;

    let client_pings = Arc::new(portable_atomic::AtomicU64::new(0));
    let server_pings = Arc::new(portable_atomic::AtomicU64::new(0));
    if !matches!(load.pings, Pings::Server) {
        ping(
            &mut client,
            Duration::ZERO,
            load.interval,
            || true,
            client_pings.clone(),
        );
    }
    match load.pings {
        Pings::Client => {}
        Pings::Both | Pings::Server => ping(
            &mut server,
            load.offset,
            load.interval,
            || true,
            server_pings.clone(),
        ),
        Pings::IdleServer(idle) => {
            // A round finding nothing received since the last one.
            let received = server.received.clone();
            let last = portable_atomic::AtomicU64::new(0);
            let idle_since_last = move || {
                let now = received.load(Relaxed);
                last.swap(now, Relaxed) == now
            };
            ping(
                &mut server,
                load.offset,
                idle,
                idle_since_last,
                server_pings.clone(),
            );
        }
    }

    let up = Arc::new(portable_atomic::AtomicU64::new(0));
    let down = Arc::new(portable_atomic::AtomicU64::new(0));
    let each = load.bytes / load.calls;
    let calls = client.calls.drain(..).zip(server.calls.drain(..));
    for (client_call, server_call) in calls {
        let (client_read, client_write) = tokio::io::split(client_call);
        let (server_read, server_write) = tokio::io::split(server_call);
        tokio::spawn(count(client_read, down.clone()));
        tokio::spawn(count(server_read, up.clone()));
        tokio::spawn(send(client_write, each, load.up));
        tokio::spawn(send(server_write, each, load.down));
    }

    let total = (each * load.calls) as u64;
    let mut moved = (0, 0);
    let mut since = Instant::now();
    let outcome = loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let now = (up.load(Relaxed), down.load(Relaxed));
        if now.0 >= total && now.1 >= total {
            break Outcome::Done;
        }
        if now != moved {
            moved = now;
            since = Instant::now();
        } else if since.elapsed() >= PATIENCE {
            break Outcome::Stalled {
                up: now.0,
                down: now.1,
            };
        }
    };
    Ran {
        outcome,
        client_pings: client_pings.load(Relaxed),
        server_pings: server_pings.load(Relaxed),
    }
}

/// `load` as `vary` makes it for each of `0..runs`: how many stalled.
async fn sweep(name: &str, runs: usize, vary: impl Fn(usize) -> Load) -> usize {
    let mut stalled = 0;
    let (mut client_pings, mut server_pings) = (0, 0);
    for i in 0..runs {
        let load = vary(i);
        let ran = run(load).await;
        client_pings += ran.client_pings;
        server_pings += ran.server_pings;
        if let Outcome::Stalled { up, down } = ran.outcome {
            stalled += 1;
            println!("{name} run {i} stalled, up {up} down {down}");
        }
    }
    println!(
        "{name}: {stalled} of {runs} stalled; pings sent: client {client_pings}, server {server_pings}"
    );
    stalled
}

/// Each choice of pings under four loads, 32 MiB each way over one call
/// or four, pings every 5 ms, twenty runs each, in real time on four
/// threads: what stalls, printed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a survey: run with --ignored --nocapture"]
async fn survey() {
    let loads = [
        ("bulk both ways", Shape::BULK, Shape::BULK),
        // A MiB up every 20 ms, so idle in between past the server's
        // idle time, the download bulk.
        ("bursty upload", Shape::bursts(1024, 20), Shape::BULK),
        // The download alone for 100 ms, then both.
        ("late upload", Shape::BULK.starting(100), Shape::BULK),
        // Pings alone for 50 ms, then both at once.
        (
            "idle then both",
            Shape::BULK.starting(50),
            Shape::BULK.starting(50),
        ),
    ];
    for (name, pings) in [
        ("A both", Pings::Both),
        ("B client", Pings::Client),
        ("C server", Pings::Server),
        (
            "D idle server 5ms",
            Pings::IdleServer(Duration::from_millis(5)),
        ),
        (
            "D idle server 2ms",
            Pings::IdleServer(Duration::from_millis(2)),
        ),
    ] {
        for (load_name, up, down) in loads {
            sweep(&format!("{name}, {load_name}"), 20, |i| Load {
                pings,
                bytes: 32 << 20,
                calls: [1, 4][i % 2],
                up,
                down,
                interval: Duration::from_millis(5),
                offset: Duration::from_millis((i % 5) as u64),
            })
            .await;
        }
    }
}
