//! A server session whose one stream is not read, as when its outbound is
//! still dialing or its target reads nothing: the other streams of the
//! session should go on, and a client that resets the connection should
//! end the session. The sing-anytls server (v0.0.11 to v0.0.13) did
//! neither, its one receive loop waiting on the stream with no timeout.
//!
//! Served as the inbound serves it: the streams come out of the handler's
//! `Incoming`, which the listener drives until it ends. AnyTLS has no
//! window: the stuck stream holds the session's reader until it is reset
//! for stalling, here after a second.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::BytesMut;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use crate::adapter::{AnyStream, BaseInboundTransport, InboundStreamHandler, InboundTransport};
use crate::session::{Session as ProxySession, SocksAddr, SocksAddrWireType};
use crate::transport::muxcore::Tuning;

use super::inbound::StreamHandler;
use super::padding::PaddingScheme;
use super::session::{auth, PaddingCell, Session, Stream};

const PASSWORD: &str = "stall";
/// Written on the stream nobody reads: well past every buffer on the way.
const FLOOD: usize = 8 << 20;
/// Written at once: a frame's length is 16 bits.
const CHUNK: usize = 16 << 10;
/// How long another stream or the end of the session may take.
const PATIENCE: Duration = Duration::from_secs(5);

/// AnyTLS has no window: a stuck stream holds the reader until it is
/// reset, here after a second rather than a minute.
fn tuning() -> Tuning {
    Tuning {
        stall_timeout: Duration::from_secs(1),
        ..Tuning::default()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// A server for one connection: the streams it hands on, and a signal
/// once its `Incoming` has ended.
async fn serve() -> (u16, mpsc::Receiver<AnyStream>, oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (streams_tx, streams_rx) = mpsc::channel(16);
    let (ended_tx, ended_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let hash: [u8; 32] = Sha256::digest(PASSWORD.as_bytes()).into();
        let handler = StreamHandler::new(
            HashMap::from([(hash, None)]),
            Arc::new(PaddingScheme::default_scheme()),
            Duration::from_secs(10),
            None,
            tuning(),
        );
        let transport = handler
            .handle(ProxySession::default(), Box::new(conn))
            .await
            .unwrap();
        let InboundTransport::Incoming(mut incoming) = transport else {
            panic!("not a session");
        };
        while let Some(transport) = incoming.next().await {
            if let BaseInboundTransport::Stream(stream, _) = transport {
                let _ = streams_tx.send(stream).await;
            }
        }
        let _ = ended_tx.send(());
    });
    (port, streams_rx, ended_rx)
}

/// A client session to `port`, over a connection that resets when it is
/// closed.
async fn client(port: u16) -> Arc<Session> {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket2::SockRef::from(&conn)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    let hash: [u8; 32] = Sha256::digest(PASSWORD.as_bytes()).into();
    conn.write_all(&auth(&hash, 0)).await.unwrap();
    let padding: PaddingCell = Arc::new(RwLock::new(Arc::new(PaddingScheme::default_scheme())));
    Session::client(Box::new(conn), padding, tuning(), "test")
}

async fn open(client: &Arc<Session>) -> Stream {
    let mut first = BytesMut::new();
    SocksAddr::Domain("target.test".into(), 80).write_buf(&mut first, SocksAddrWireType::PortLast);
    timeout(PATIENCE, client.open_stream(&first))
        .await
        .expect("no stream could be opened")
        .unwrap()
}

/// Opens a stream and writes `FLOOD` on it, which the server takes and
/// never reads: the stream stays open, its consumer stuck.
async fn stall(
    client: &Arc<Session>,
    streams: &mut mpsc::Receiver<AnyStream>,
) -> (AnyStream, tokio::task::JoinHandle<()>) {
    let mut a = open(client).await;
    let stuck = timeout(PATIENCE, streams.recv())
        .await
        .expect("the first stream was not accepted")
        .unwrap();
    let flood = tokio::spawn(async move {
        let chunk = vec![0u8; CHUNK];
        for _ in 0..FLOOD / CHUNK {
            if a.write_all(&chunk).await.is_err() {
                return;
            }
        }
        // Kept open, as a client whose download has not ended keeps it.
        std::future::pending::<()>().await;
    });
    // Time for the flood to fill what it can.
    tokio::time::sleep(Duration::from_millis(500)).await;
    (stuck, flood)
}

/// Another stream of the session opens and echoes while the first is stuck.
#[test]
fn a_stuck_stream_does_not_stall_the_others() {
    runtime().block_on(async {
        let (port, mut streams, _ended) = serve().await;
        let client = client(port).await;
        let (_stuck, _flood) = stall(&client, &mut streams).await;

        // A version 2 client gives up on a session whose SYNACK does not
        // come in 3 s, and closes it: the server never gets to the SYN.
        let mut b = open(&client).await;
        let served = timeout(PATIENCE, streams.recv())
            .await
            .expect("a second stream was not accepted while the first was stuck")
            .unwrap();
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(served);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        timeout(PATIENCE, b.write_all(b"ping"))
            .await
            .expect("the second stream could not write while the first was stuck")
            .unwrap();
        let mut echo = [0u8; 4];
        timeout(PATIENCE, b.read_exact(&mut echo))
            .await
            .expect("the second stream got no echo while the first was stuck")
            .unwrap();
        assert_eq!(&echo, b"ping");
    });
}

/// A client that resets its connection ends the session, and with it the
/// inbound's `Incoming`, while a stream's consumer is stuck.
#[test]
fn a_reset_ends_a_stalled_session() {
    runtime().block_on(async {
        let (port, mut streams, ended) = serve().await;
        let client = client(port).await;
        let (_stuck, flood) = stall(&client, &mut streams).await;

        flood.abort();
        client.close();
        timeout(PATIENCE, ended)
            .await
            .expect("the server session outlived its connection")
            .unwrap();
    });
}

/// The control: with nothing stuck, a reset ends the session.
#[test]
fn a_reset_ends_an_idle_session() {
    runtime().block_on(async {
        let (port, mut streams, ended) = serve().await;
        let client = client(port).await;
        let _a = open(&client).await;
        let _served = timeout(PATIENCE, streams.recv()).await.unwrap().unwrap();
        client.close();
        timeout(PATIENCE, ended)
            .await
            .expect("the server session outlived its connection")
            .unwrap();
    });
}
