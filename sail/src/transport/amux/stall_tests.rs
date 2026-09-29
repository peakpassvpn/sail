//! An amux acceptor whose one stream is not read, as when its outbound is
//! still dialing or its target reads nothing: the other streams should go
//! on, and a client that resets the connection should end the acceptor.
//! Each stream has a window, so the reader never waits for one.

use std::time::Duration;

use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use super::{MuxConnector, MuxSession, MuxStream};
use crate::transport::muxcore::Tuning;

/// Written on the stream nobody reads: well past its queue.
const FLOOD: usize = 8 << 20;
const CHUNK: usize = 16 << 10;
const PATIENCE: Duration = Duration::from_secs(5);

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// An acceptor for one connection: its streams, and a signal once it
/// gives no more.
async fn serve() -> (u16, mpsc::Receiver<MuxStream>, oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (streams_tx, streams_rx) = mpsc::channel(16);
    let (ended_tx, ended_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let mut acceptor = MuxSession::acceptor(conn, Tuning::default(), "test");
        while let Some(stream) = acceptor.next().await {
            let _ = streams_tx.send(stream).await;
        }
        let _ = ended_tx.send(());
    });
    (port, streams_rx, ended_rx)
}

/// A connector to `port`, over a connection that resets when it is
/// dropped.
async fn connect(port: u16) -> MuxConnector {
    let conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket2::SockRef::from(&conn)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    MuxSession::connector(conn, 128, 16, 0, 0, Tuning::default(), "test")
}

/// Opens a stream, which the acceptor sees with its first data, writes
/// `FLOOD` on it and never reads it on the server.
async fn stall(
    connector: &mut MuxConnector,
    streams: &mut mpsc::Receiver<MuxStream>,
) -> (MuxStream, tokio::task::JoinHandle<()>) {
    let mut a = connector.new_stream().await.unwrap();
    timeout(PATIENCE, a.write_all(b"a")).await.unwrap().unwrap();
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
        std::future::pending::<()>().await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    (stuck, flood)
}

#[test]
fn a_stuck_stream_does_not_stall_the_others() {
    runtime().block_on(async {
        let (port, mut streams, _ended) = serve().await;
        let mut connector = connect(port).await;
        let (_stuck, _flood) = stall(&mut connector, &mut streams).await;

        let mut b = connector.new_stream().await.unwrap();
        timeout(PATIENCE, b.write_all(b"ping"))
            .await
            .expect("the second stream could not write while the first was stuck")
            .unwrap();
        let served = timeout(PATIENCE, streams.recv())
            .await
            .expect("a second stream was not accepted while the first was stuck")
            .unwrap();
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(served);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        let mut echo = [0u8; 4];
        timeout(PATIENCE, b.read_exact(&mut echo))
            .await
            .expect("the second stream got no echo while the first was stuck")
            .unwrap();
        assert_eq!(&echo, b"ping");
    });
}

#[test]
fn a_reset_ends_a_stalled_acceptor() {
    runtime().block_on(async {
        let (port, mut streams, ended) = serve().await;
        let mut connector = connect(port).await;
        let (_stuck, flood) = stall(&mut connector, &mut streams).await;
        flood.abort();
        drop(connector);
        timeout(PATIENCE, ended)
            .await
            .expect("the acceptor outlived its connection")
            .unwrap();
    });
}

/// The control: with nothing stuck, a reset ends the acceptor.
#[test]
fn a_reset_ends_an_idle_acceptor() {
    runtime().block_on(async {
        let (port, mut streams, ended) = serve().await;
        let mut connector = connect(port).await;
        let mut a = connector.new_stream().await.unwrap();
        a.write_all(b"a").await.unwrap();
        let _served = timeout(PATIENCE, streams.recv()).await.unwrap().unwrap();
        drop(a);
        drop(connector);
        timeout(PATIENCE, ended)
            .await
            .expect("the acceptor outlived its connection")
            .unwrap();
    });
}
