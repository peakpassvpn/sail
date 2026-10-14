//! The keepalive on a connection set up as the outbound and the inbound set
//! theirs up, the two ends joined by an in-memory pipe, time paused.
//!
//! A pong late behind what the peer sends does not end the connection;
//! nothing at all from the peer does, after `ping_timeout`.

use std::time::Duration;

use bytes::Bytes;
use futures::future::{abortable, AbortHandle, Aborted};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::gun::GunStream;
use super::{inbound, keepalive, outbound, Counted};

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
    let (send, mut client) = outbound::pool::builder()
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
