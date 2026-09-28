//! A served sing-mux connection whose streams are not read, as when their
//! outbounds are still dialing or their targets read nothing: the other
//! streams should go on, and a client that resets the connection should
//! end it. Served as `app::inbound::magic` serves it, the server's streams
//! taken until `accept` gives none.
//!
//! smux has no window of its own, so its streams share `MAX_BUFFERED`;
//! yamux and h2mux have a window a stream, and a window or a budget the
//! connection. The ones ignored fail today.

use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use crate::adapter::AnyStream;
use crate::session::SocksAddr;

use super::h2mux::H2Client;
use super::server::{read_stream, Server};
use super::session::{Flavor, FrameSession};
use super::{encode_request, Protocol, StreamRequest};

/// Written at once.
const CHUNK: usize = 16 << 10;
/// How long another stream or the end of the connection may take.
const PATIENCE: Duration = Duration::from_secs(5);
/// Echoed on the stream that should go on.
const ECHO: usize = 64 << 10;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// A server for one connection: the streams it hands on, and a signal
/// once it takes no more.
async fn serve() -> (u16, mpsc::Receiver<AnyStream>, oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (streams_tx, streams_rx) = mpsc::channel(64);
    let (ended_tx, ended_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let mut server = Server::start(Box::new(conn)).await.unwrap();
        while let Some(stream) = server.accept().await {
            let streams_tx = streams_tx.clone();
            tokio::spawn(async move {
                if let Ok((_, stream)) = read_stream(stream).await {
                    let _ = streams_tx.send(stream).await;
                }
            });
        }
        let _ = ended_tx.send(());
    });
    (port, streams_rx, ended_rx)
}

enum Client {
    Frames(FrameSession),
    H2(H2Client),
}

type ClientStream = Box<dyn ClientIo>;
trait ClientIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClientIo for T {}

impl Client {
    /// A client connection to `port`, which resets when it is closed.
    async fn connect(port: u16, protocol: Protocol) -> Client {
        let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        socket2::SockRef::from(&conn)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        conn.write_all(&encode_request(protocol, false))
            .await
            .unwrap();
        match protocol {
            Protocol::Smux => Client::Frames(FrameSession::new(conn, Flavor::Smux, false).0),
            Protocol::Yamux => Client::Frames(FrameSession::new(conn, Flavor::Yamux, false).0),
            Protocol::H2Mux => Client::H2(H2Client::new(conn).await.unwrap()),
        }
    }

    /// Opens a TCP stream; its request goes with the first write.
    async fn open(&self) -> ClientStream {
        let mut stream: ClientStream = match self {
            Client::Frames(session) => Box::new(session.open().unwrap()),
            Client::H2(client) => Box::new(
                timeout(PATIENCE, client.open())
                    .await
                    .expect("no stream could be opened")
                    .unwrap(),
            ),
        };
        let mut request = BytesMut::new();
        StreamRequest::Tcp(SocksAddr::Domain("target.test".into(), 80)).encode(&mut request);
        timeout(PATIENCE, stream.write_all(&request))
            .await
            .expect("a stream's request could not be written")
            .unwrap();
        stream
    }

    fn close(&self) {
        match self {
            Client::Frames(session) => session.close(),
            Client::H2(client) => client.close(),
        }
    }
}

/// Opens `count` streams and writes `flood` bytes on each, which the server
/// takes and never reads.
async fn stall(
    client: &Client,
    streams: &mut mpsc::Receiver<AnyStream>,
    count: usize,
    flood: usize,
) -> (Vec<AnyStream>, Vec<tokio::task::JoinHandle<()>>) {
    let mut stuck = Vec::new();
    let mut floods = Vec::new();
    for _ in 0..count {
        let mut a = client.open().await;
        stuck.push(
            timeout(PATIENCE, streams.recv())
                .await
                .expect("a stream to stall was not accepted")
                .unwrap(),
        );
        floods.push(tokio::spawn(async move {
            let chunk = vec![0u8; CHUNK];
            for _ in 0..flood / CHUNK {
                if a.write_all(&chunk).await.is_err() {
                    return;
                }
            }
            std::future::pending::<()>().await;
        }));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    (stuck, floods)
}

/// Another stream opens and echoes while `count` streams are stuck.
async fn others_go_on(protocol: Protocol, count: usize, flood: usize) {
    let (port, mut streams, _ended) = serve().await;
    let client = Client::connect(port, protocol).await;
    let (_stuck, _floods) = stall(&client, &mut streams, count, flood).await;

    let b = client.open().await;
    let served = timeout(PATIENCE, streams.recv())
        .await
        .expect("a new stream was not accepted while others were stuck")
        .unwrap();
    tokio::spawn(async move {
        let (mut r, mut w) = tokio::io::split(served);
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });
    // More than the few bytes a window may have left: the status, then
    // the echo.
    let (mut r, mut w) = tokio::io::split(b);
    let data = vec![7u8; ECHO];
    tokio::spawn(async move {
        let _ = w.write_all(&data).await;
        std::future::pending::<()>().await;
    });
    let mut echo = vec![0u8; 1 + ECHO];
    timeout(PATIENCE, r.read_exact(&mut echo))
        .await
        .expect("a new stream got no echo while others were stuck")
        .unwrap();
    assert!(echo[1..].iter().all(|b| *b == 7));
}

/// A reset ends the connection while `count` streams are stuck.
async fn a_reset_ends_it(protocol: Protocol, count: usize, flood: usize) {
    let (port, mut streams, ended) = serve().await;
    let client = Client::connect(port, protocol).await;
    let (_stuck, floods) = stall(&client, &mut streams, count, flood).await;
    for flood in floods {
        flood.abort();
    }
    client.close();
    timeout(PATIENCE, ended)
        .await
        .expect("the served connection outlived its connection")
        .unwrap();
}

#[test]
#[ignore = "fails: smux streams share MAX_BUFFERED, which one unread stream fills"]
fn smux_a_stuck_stream_does_not_stall_the_others() {
    runtime().block_on(others_go_on(Protocol::Smux, 1, 8 << 20));
}

#[test]
#[ignore = "fails: a full MAX_BUFFERED stops the reader, which then misses a reset"]
fn smux_a_reset_ends_a_stalled_connection() {
    runtime().block_on(a_reset_ends_it(Protocol::Smux, 1, 8 << 20));
}

#[test]
fn yamux_a_stuck_stream_does_not_stall_the_others() {
    runtime().block_on(others_go_on(Protocol::Yamux, 1, 2 << 20));
}

#[test]
fn yamux_a_reset_ends_a_connection_with_a_stuck_stream() {
    runtime().block_on(a_reset_ends_it(Protocol::Yamux, 1, 2 << 20));
}

/// Seventeen full windows of 256 KiB are more than `MAX_BUFFERED`.
#[test]
#[ignore = "fails: 17 unread yamux streams fill MAX_BUFFERED and stop the reader"]
fn yamux_seventeen_stuck_streams_do_not_stall_the_others() {
    runtime().block_on(others_go_on(Protocol::Yamux, 17, 1 << 20));
}

#[test]
#[ignore = "fails: 17 unread yamux streams fill MAX_BUFFERED; a reset goes unnoticed"]
fn yamux_a_reset_ends_a_connection_with_seventeen_stuck_streams() {
    runtime().block_on(a_reset_ends_it(Protocol::Yamux, 17, 1 << 20));
}

#[test]
fn h2mux_a_stuck_stream_does_not_stall_the_others() {
    runtime().block_on(others_go_on(Protocol::H2Mux, 1, 4 << 20));
}

/// Five full stream windows of 1 MiB are more than the connection's.
#[test]
#[ignore = "fails: 5 unread h2mux streams take the whole 4 MiB connection window"]
fn h2mux_five_stuck_streams_do_not_stall_the_others() {
    runtime().block_on(others_go_on(Protocol::H2Mux, 5, 2 << 20));
}

#[test]
fn h2mux_a_reset_ends_a_connection_with_stuck_streams() {
    runtime().block_on(a_reset_ends_it(Protocol::H2Mux, 5, 2 << 20));
}
