//! smux and yamux sessions against each other, over a pipe.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::transport::muxcore::{Codec, Session};

use super::smux::Smux;
use super::yamux::Yamux;

#[derive(Clone, Copy)]
enum Flavor {
    Smux,
    Yamux,
}

impl Flavor {
    fn codec(self) -> Arc<dyn Codec> {
        match self {
            Flavor::Smux => Arc::new(Smux),
            Flavor::Yamux => Arc::new(Yamux),
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Streams echo on the server; each client stream sends `size` bytes
/// and reads them back.
async fn echo(flavor: Flavor, streams: usize, size: usize) {
    let (a, b) = tokio::io::duplex(64 << 10);
    let (client, _) = Session::new(a, flavor.codec(), false);
    let (_server, accept) = Session::new(b, flavor.codec(), true);
    let mut accept = accept.unwrap();
    tokio::spawn(async move {
        while let Some(stream) = accept.recv().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
                // smux cannot half-close: keep the stream until the
                // client is done with it.
                tokio::time::sleep(Duration::from_millis(500)).await;
            });
        }
    });
    let mut tasks = Vec::new();
    for i in 0..streams {
        let stream = client.open().unwrap();
        tasks.push(tokio::spawn(async move {
            let data: Vec<u8> = (0..size).map(|j| (i + j) as u8).collect();
            let (mut r, mut w) = tokio::io::split(stream);
            let expected = data.clone();
            let writer = tokio::spawn(async move {
                w.write_all(&data).await.unwrap();
                w
            });
            let mut got = vec![0u8; size];
            r.read_exact(&mut got).await.unwrap();
            assert!(got == expected, "stream {} garbled", i);
            drop(writer.await.unwrap());
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[test]
fn smux_streams_carry_data_both_ways() {
    runtime().block_on(echo(Flavor::Smux, 16, 300 << 10));
}

#[test]
fn yamux_streams_carry_more_than_a_window() {
    runtime().block_on(echo(Flavor::Yamux, 16, 1 << 20));
}

#[test]
fn yamux_half_close_and_reset() {
    runtime().block_on(async {
        let (a, b) = tokio::io::duplex(64 << 10);
        let (client, _) = Session::new(a, Flavor::Yamux.codec(), false);
        let (_server, accept) = Session::new(b, Flavor::Yamux.codec(), true);
        let mut accept = accept.unwrap();
        let mut stream = client.open().unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut served = accept.recv().await.unwrap();
        let mut got = Vec::new();
        served.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");
        // Still writable after the client finished.
        served.write_all(b"pong").await.unwrap();
        served.shutdown().await.unwrap();
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"pong");
        // Dropped before the peer finished: reset.
        let stream = client.open().unwrap();
        let mut served = accept.recv().await.unwrap();
        drop(stream);
        let err = served.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(client.num_streams(), 1);
    });
}

#[test]
fn a_closed_connection_fails_the_streams() {
    runtime().block_on(async {
        let (a, b) = tokio::io::duplex(64 << 10);
        let (client, _) = Session::new(a, Flavor::Smux.codec(), false);
        let mut stream = client.open().unwrap();
        drop(b);
        let err = stream.read(&mut [0u8; 4]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(client.is_closed());
        assert!(client.open().is_err());
    });
}
