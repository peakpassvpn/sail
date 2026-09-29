//! smux and yamux sessions against each other, over a pipe.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::transport::muxcore::{Codec, Session, Tuning};

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
    let (client, _) = Session::new(a, flavor.codec(), false, Tuning::default(), "test");
    let (_server, accept) = Session::new(b, flavor.codec(), true, Tuning::default(), "test");
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
        let (client, _) = Session::new(a, Flavor::Yamux.codec(), false, Tuning::default(), "test");
        let (_server, accept) =
            Session::new(b, Flavor::Yamux.codec(), true, Tuning::default(), "test");
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
        let (client, _) = Session::new(a, Flavor::Smux.codec(), false, Tuning::default(), "test");
        let mut stream = client.open().unwrap();
        drop(b);
        let err = stream.read(&mut [0u8; 4]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(client.is_closed());
        assert!(client.open().is_err());
    });
}

/// A client and a server session over a pipe, and a stream between them:
/// the client's end, and the server's.
async fn pair(
    flavor: Flavor,
    tuning: Tuning,
) -> (
    Session,
    Session,
    crate::transport::muxcore::Stream,
    crate::transport::muxcore::Stream,
) {
    let (a, b) = tokio::io::duplex(64 << 10);
    let (client, _) = Session::new(a, flavor.codec(), false, tuning, "test");
    let (server, accept) = Session::new(b, flavor.codec(), true, tuning, "test");
    let mut accept = accept.unwrap();
    let mut stream = client.open().unwrap();
    // smux opens a stream the peer sees only once it is written to.
    stream.write_all(b"x").await.unwrap();
    let mut served = accept.recv().await.unwrap();
    let mut first = [0u8; 1];
    served.read_exact(&mut first).await.unwrap();
    (client, server, stream, served)
}

/// Writes on `stream` for as long as it takes, and says when writing
/// failed.
fn flood(
    mut stream: crate::transport::muxcore::Stream,
) -> tokio::task::JoinHandle<(tokio::time::Instant, io::Error)> {
    tokio::spawn(async move {
        let chunk = vec![7u8; 16 << 10];
        loop {
            if let Err(e) = stream.write_all(&chunk).await {
                return (tokio::time::Instant::now(), e);
            }
        }
    })
}

/// A stream read a little every 10 s for two minutes is never taken to
/// have stalled, with a window or without.
#[tokio::test(start_paused = true)]
async fn a_slow_but_steady_reader_is_never_reset() {
    for flavor in [Flavor::Smux, Flavor::Yamux] {
        let (_client, _server, stream, mut served) = pair(flavor, Tuning::default()).await;
        let writer = flood(stream);
        let start = tokio::time::Instant::now();
        let mut buf = [0u8; 1024];
        while start.elapsed() < Duration::from_secs(120) {
            tokio::time::sleep(Duration::from_secs(10)).await;
            served.read_exact(&mut buf).await.unwrap();
            assert!(buf.iter().all(|b| *b == 7));
        }
        assert!(!writer.is_finished());
        writer.abort();
    }
}

/// A stream nothing reads is reset once its data has waited the stall
/// timeout, and its peer told.
#[tokio::test(start_paused = true)]
async fn a_stuck_stream_is_reset_after_the_stall_timeout() {
    for flavor in [Flavor::Smux, Flavor::Yamux] {
        let (_client, _server, stream, mut served) = pair(flavor, Tuning::default()).await;
        let start = tokio::time::Instant::now();
        let writer = flood(stream);
        tokio::time::sleep(Duration::from_secs(55)).await;
        assert!(!writer.is_finished());
        let (failed, e) = writer.await.unwrap();
        let after = failed - start;
        assert!(
            after >= Duration::from_secs(60) && after <= Duration::from_secs(66),
            "reset after {:?}",
            after
        );
        let kind = match flavor {
            // No reset in smux: its FIN ends the stream both ways.
            Flavor::Smux => io::ErrorKind::BrokenPipe,
            Flavor::Yamux => io::ErrorKind::ConnectionReset,
        };
        assert_eq!(e.kind(), kind);
        let err = served.read(&mut [0u8; 16]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}

/// A thousand streams opened at once, before the server takes any, are
/// all accepted and served.
#[test]
fn a_burst_of_a_thousand_streams_is_all_accepted() {
    for flavor in [Flavor::Smux, Flavor::Yamux] {
        runtime().block_on(async {
            let (a, b) = tokio::io::duplex(64 << 10);
            let (client, _) = Session::new(a, flavor.codec(), false, Tuning::default(), "test");
            let (_server, accept) =
                Session::new(b, flavor.codec(), true, Tuning::default(), "test");
            let mut accept = accept.unwrap();
            let mut clients = Vec::new();
            for i in 0..1000u32 {
                let mut stream = client.open().unwrap();
                clients.push(tokio::spawn(async move {
                    stream.write_all(&i.to_be_bytes()).await?;
                    let mut echo = [0u8; 4];
                    stream.read_exact(&mut echo).await?;
                    assert_eq!(u32::from_be_bytes(echo), i);
                    Ok::<_, io::Error>(stream)
                }));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            tokio::spawn(async move {
                while let Some(mut stream) = accept.recv().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4];
                        stream.read_exact(&mut buf).await?;
                        stream.write_all(&buf).await?;
                        std::future::pending::<()>().await;
                        Ok::<_, io::Error>(())
                    });
                }
            });
            let mut served = 0;
            for task in clients {
                tokio::time::timeout(Duration::from_secs(10), task)
                    .await
                    .expect("a stream of the burst was not served")
                    .unwrap()
                    .unwrap();
                served += 1;
            }
            assert_eq!(served, 1000);
        });
    }
}

/// A session whose handle is dropped carries its streams on until they
/// end, then ends.
#[test]
fn a_dropped_session_keeps_its_streams_until_they_end() {
    for flavor in [Flavor::Smux, Flavor::Yamux] {
        runtime().block_on(async {
            let (a, b) = tokio::io::duplex(64 << 10);
            let (client, _) = Session::new(a, flavor.codec(), false, Tuning::default(), "test");
            let (_server, accept) =
                Session::new(b, flavor.codec(), true, Tuning::default(), "test");
            let mut accept = accept.unwrap();
            let mut stream = client.open().unwrap();
            stream.write_all(b"x").await.unwrap();
            let mut served = accept.recv().await.unwrap();
            drop(client);
            // The stream goes on both ways.
            let data = vec![3u8; 1 << 20];
            let expected = data.clone();
            let (mut r, mut w) = tokio::io::split(stream);
            let writer = tokio::spawn(async move {
                w.write_all(&data).await.unwrap();
                w
            });
            let mut got = vec![0u8; 1 + (1 << 20)];
            served.read_exact(&mut got).await.unwrap();
            assert_eq!(&got[1..], &expected[..]);
            served.write_all(b"done").await.unwrap();
            let mut done = [0u8; 4];
            r.read_exact(&mut done).await.unwrap();
            assert_eq!(&done, b"done");
            // Once it ends, so does the session: the server takes no more.
            drop(r.unsplit(writer.await.unwrap()));
            let next = tokio::time::timeout(Duration::from_secs(5), accept.recv())
                .await
                .expect("the session outlived its last stream");
            assert!(next.is_none());
        });
    }
}

/// A stream whose window is read faster than a round trip lets it in has
/// it doubled, up to the largest allowed; one read slower keeps it.
#[test]
fn windows_grow_while_read_fast() {
    for (rtt, grown) in [
        (Duration::from_secs(1), 2 << 20),
        (Duration::from_nanos(1), 256 << 10),
    ] {
        runtime().block_on(async {
            let tuning = Tuning {
                window_max: 2 << 20,
                ..Tuning::default()
            };
            let (_client, _server, stream, mut served) = pair(Flavor::Yamux, tuning).await;
            served.pin_rtt(rtt);
            let writer = flood(stream);
            let mut buf = vec![0u8; 64 << 10];
            for _ in 0..(16 << 20) / buf.len() {
                served.read_exact(&mut buf).await.unwrap();
            }
            assert_eq!(served.window(), grown, "with a round trip of {:?}", rtt);
            writer.abort();
        });
    }
}

/// Sends `len` bytes on `stream`, then keeps it open, idle.
fn send(
    mut stream: crate::transport::muxcore::Stream,
    len: usize,
) -> tokio::task::JoinHandle<crate::transport::muxcore::Stream> {
    tokio::spawn(async move {
        let chunk = vec![7u8; 16 << 10];
        for _ in 0..len / chunk.len() {
            stream.write_all(&chunk).await.unwrap();
        }
        stream
    })
}

/// A download on a new stream: the server sends 16 MiB and the client
/// reads it all, fast enough for its window to grow. Both ends are kept.
async fn download(
    client: &Session,
    accept: &mut tokio::sync::mpsc::UnboundedReceiver<crate::transport::muxcore::Stream>,
) -> (
    crate::transport::muxcore::Stream,
    crate::transport::muxcore::Stream,
) {
    let mut stream = client.open().unwrap();
    stream.write_all(b"x").await.unwrap();
    stream.pin_rtt(Duration::from_secs(1));
    let served = accept.recv().await.unwrap();
    let sender = send(served, 16 << 20);
    let mut buf = vec![0u8; 64 << 10];
    for _ in 0..(16 << 20) / buf.len() {
        stream.read_exact(&mut buf).await.unwrap();
    }
    (stream, sender.await.unwrap())
}

/// Windows that grew on streams now idle go back to the session's growth
/// budget once another stream needs it: a keep-alive connection that once
/// downloaded fast does not keep the next download at a small window.
#[tokio::test(start_paused = true)]
async fn idle_streams_give_their_grown_windows_back() {
    const MAX: u32 = 2 << 20;
    let tuning = Tuning {
        window_max: MAX,
        ..Tuning::default()
    };
    let (a, b) = tokio::io::duplex(64 << 10);
    let (client, _) = Session::new(a, Flavor::Yamux.codec(), false, tuning, "test");
    let (_server, accept) = Session::new(b, Flavor::Yamux.codec(), true, tuning, "test");
    let mut accept = accept.unwrap();
    // As many as the budget lets grow all the way, then left idle.
    let mut idle = Vec::new();
    for _ in 0..4 {
        let (stream, served) = download(&client, &mut accept).await;
        assert_eq!(stream.window(), MAX);
        idle.push((stream, served));
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
    let (stream, _served) = download(&client, &mut accept).await;
    assert_eq!(stream.window(), MAX, "the budget went to idle streams");
    // A stream whose window was taken back still reads all it is sent,
    // its peer held to what it was granted.
    let taken = idle
        .iter()
        .position(|(stream, _)| stream.window() == 256 << 10)
        .expect("no idle stream gave its window back");
    let (mut stream, served) = idle.swap_remove(taken);
    let sender = send(served, 16 << 20);
    let mut buf = vec![0u8; 64 << 10];
    for _ in 0..(16 << 20) / buf.len() {
        stream.read_exact(&mut buf).await.unwrap();
    }
    sender.await.unwrap();
}
