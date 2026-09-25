//! What smux and yamux share: streams over one connection, read by one
//! task and written by another, with every buffer bounded.
//!
//! A stream's data waits in its slot until the stream is read. The reader
//! stops reading the connection while more than `MAX_BUFFERED` bytes wait
//! across all streams, as smux does with its token bucket; yamux also
//! grants each stream a window it may not overrun. What streams write
//! waits in one queue for the writer; a stream stops being accepted writes
//! while the queue holds `OUT_SOFT_LIMIT`, and a peer that makes it grow
//! past `OUT_HARD_LIMIT` with control frames it never reads loses the
//! session.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use bytes::{Buf, Bytes, BytesMut};
use futures::future::{abortable, AbortHandle};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, trace};

use super::{smux, yamux};

/// Bytes received and not yet read, across a session's streams, before
/// the session stops reading its connection.
pub const MAX_BUFFERED: usize = 4 << 20;
/// The largest data frame sent.
pub const MAX_FRAME_DATA: usize = 32 << 10;
/// Queued for the connection: past this, streams wait to write.
const OUT_SOFT_LIMIT: usize = 1 << 20;
/// Queued for the connection: past this, the session is closed.
const OUT_HARD_LIMIT: usize = 8 << 20;
/// Written to the connection at once, at most.
const WRITE_BATCH: usize = 64 << 10;
/// Streams one session carries at once.
pub const MAX_STREAMS: usize = 1024;
/// Streams accepted and not yet taken by the server.
const ACCEPT_QUEUE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Smux,
    Yamux,
}

/// One stream's state.
pub struct Slot {
    recv: VecDeque<Bytes>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// The peer is done sending: smux FIN, yamux FIN.
    pub remote_fin: bool,
    /// Sent a yamux FIN.
    local_fin: bool,
    /// The peer reset the stream (yamux RST).
    pub reset: bool,
    /// yamux: what may still be sent.
    pub send_window: u32,
    /// yamux: what the peer may still send.
    pub recv_window: u32,
    /// yamux: read since the last window update.
    consumed: u32,
}

impl Slot {
    fn new() -> Self {
        Slot {
            recv: VecDeque::new(),
            read_waker: None,
            write_waker: None,
            remote_fin: false,
            local_fin: false,
            reset: false,
            send_window: yamux::WINDOW,
            recv_window: yamux::WINDOW,
            consumed: 0,
        }
    }

    pub fn wake(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }
}

/// Frames waiting for the writer.
#[derive(Default)]
pub struct Out {
    queue: VecDeque<Bytes>,
    bytes: usize,
}

impl Out {
    pub fn push(&mut self, frame: Bytes) {
        self.bytes += frame.len();
        self.queue.push_back(frame);
    }
}

pub struct State {
    pub streams: HashMap<u32, Slot>,
    pub out: Out,
    /// Why the session ended, once it has.
    pub error: Option<String>,
    /// The peer asked for no more streams (yamux GoAway).
    pub going_away: bool,
    next_id: u32,
    /// Received and not yet read, across all streams.
    pub buffered: usize,
    /// Where accepted streams go, on a server.
    accept: Option<mpsc::Sender<MuxStream>>,
}

pub struct Shared {
    pub flavor: Flavor,
    state: Mutex<State>,
    /// Wakes the writer.
    writer: Notify,
    /// Wakes the reader waiting for buffered data to be read.
    reader: Notify,
}

impl Shared {
    pub fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock cannot leave the state worse than
        // any other failure would: carry on with it.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn wake_writer(&self) {
        self.writer.notify_one();
    }

    /// Ends the session: every stream fails, or reads what it has and
    /// then fails.
    pub fn fail(&self, reason: String) {
        let mut state = self.lock();
        if state.error.is_none() {
            debug!("mux session closed: {}", reason);
            state.error = Some(reason);
        }
        state.accept = None;
        for slot in state.streams.values_mut() {
            slot.wake();
        }
        drop(state);
        self.writer.notify_one();
        self.reader.notify_one();
    }

    /// Checks the queue against the hard limit after a control frame.
    pub fn check_out(&self, state: &mut State) -> io::Result<()> {
        if state.out.bytes > OUT_HARD_LIMIT {
            return Err(io::Error::other("peer does not read what it asks for"));
        }
        Ok(())
    }

    /// Waits until the streams have read enough for more to be received.
    pub async fn wait_for_room(&self) {
        loop {
            let notified = self.reader.notified();
            {
                let state = self.lock();
                if state.buffered < MAX_BUFFERED || state.error.is_some() {
                    return;
                }
            }
            notified.await;
        }
    }

    /// Hands data received for stream `id` to it; dropped if the stream is
    /// gone.
    pub fn deliver(&self, state: &mut State, id: u32, data: Bytes) {
        if let Some(slot) = state.streams.get_mut(&id) {
            state.buffered += data.len();
            slot.recv.push_back(data);
            if let Some(w) = slot.read_waker.take() {
                w.wake();
            }
        }
    }

    /// Takes a stream the peer opened, as a server. False if refused: too
    /// many streams, or not a server.
    pub fn accept(self: &Arc<Self>, state: &mut State, id: u32) -> bool {
        let Some(accept) = state.accept.as_ref() else {
            return false;
        };
        if state.streams.len() >= MAX_STREAMS || state.streams.contains_key(&id) {
            return false;
        }
        let Ok(permit) = accept.try_reserve() else {
            return false;
        };
        state.streams.insert(id, Slot::new());
        permit.send(MuxStream {
            id,
            shared: self.clone(),
        });
        true
    }
}

/// A session over one connection, closed when dropped.
pub struct FrameSession {
    shared: Arc<Shared>,
    tasks: Vec<AbortHandle>,
}

impl FrameSession {
    /// Starts a session over `conn`; a server also gets the streams the
    /// peer opens.
    pub fn new<S>(
        conn: S,
        flavor: Flavor,
        server: bool,
    ) -> (Self, Option<mpsc::Receiver<MuxStream>>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (accept_tx, accept_rx) = if server {
            let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let next_id = match (flavor, server) {
            (Flavor::Smux, false) => 1,
            (Flavor::Yamux, false) => 1,
            (_, true) => 2,
        };
        let shared = Arc::new(Shared {
            flavor,
            state: Mutex::new(State {
                streams: HashMap::new(),
                out: Out::default(),
                error: None,
                going_away: false,
                next_id,
                buffered: 0,
                accept: accept_tx,
            }),
            writer: Notify::new(),
            reader: Notify::new(),
        });
        // Read and written by one task: a connection's halves polled from
        // two tasks may each take the other's wakeup, as a TLS stream that
        // writes while it reads does.
        let (r, w) = tokio::io::split(conn);
        let (driver, handle) = abortable({
            let shared = shared.clone();
            async move {
                let r = tokio::io::BufReader::new(r);
                let reader = async {
                    match flavor {
                        Flavor::Smux => smux::read_loop(&shared, r).await,
                        Flavor::Yamux => yamux::read_loop(&shared, r).await,
                    }
                };
                let reason = tokio::select! {
                    result = reader => match result {
                        Ok(()) => "connection closed".to_string(),
                        Err(e) => e.to_string(),
                    },
                    reason = write_loop(&shared, w) => reason,
                };
                shared.fail(reason);
            }
        });
        tokio::spawn(driver);
        (
            FrameSession {
                shared,
                tasks: vec![handle],
            },
            accept_rx,
        )
    }

    /// Opens a stream.
    pub fn open(&self) -> io::Result<MuxStream> {
        let mut state = self.shared.lock();
        if let Some(e) = &state.error {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, e.clone()));
        }
        if state.going_away {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "mux: going away"));
        }
        if state.streams.len() >= MAX_STREAMS {
            return Err(io::Error::other("mux: too many streams"));
        }
        let id = match self.shared.flavor {
            // smux counts from 1 and opens with the next.
            Flavor::Smux => state.next_id.checked_add(2),
            Flavor::Yamux => Some(state.next_id),
        }
        .filter(|id| *id < u32::MAX - 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "mux: stream ids exhausted"))?;
        state.next_id = match self.shared.flavor {
            Flavor::Smux => id,
            Flavor::Yamux => id + 2,
        };
        state.streams.insert(id, Slot::new());
        let frame = match self.shared.flavor {
            Flavor::Smux => smux::frame(smux::CMD_SYN, id, &[]),
            Flavor::Yamux => yamux::window_update(yamux::FLAG_SYN, id, 0),
        };
        state.out.push(frame);
        drop(state);
        self.shared.wake_writer();
        Ok(MuxStream {
            id,
            shared: self.shared.clone(),
        })
    }

    pub fn num_streams(&self) -> usize {
        self.shared.lock().streams.len()
    }

    pub fn is_closed(&self) -> bool {
        let state = self.shared.lock();
        state.error.is_some() || state.going_away
    }

    pub fn close(&self) {
        self.shared.fail("closed".to_string());
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Drop for FrameSession {
    fn drop(&mut self) {
        self.close();
    }
}

/// Writes what the streams queue until the session ends, and says why.
async fn write_loop<W: AsyncWrite + Unpin>(shared: &Shared, mut w: W) -> String {
    let mut batch = BytesMut::with_capacity(WRITE_BATCH);
    loop {
        let notified = shared.writer.notified();
        let mut taken = 0;
        let ended = {
            let mut state = shared.lock();
            while let Some(frame) = state.out.queue.front() {
                if !batch.is_empty() && batch.len() + frame.len() > WRITE_BATCH {
                    break;
                }
                let frame = state.out.queue.pop_front().unwrap_or_default();
                taken += frame.len();
                batch.extend_from_slice(&frame);
            }
            state.error.is_some()
        };
        if batch.is_empty() {
            if ended {
                let _ = w.shutdown().await;
                return "closed".to_string();
            }
            notified.await;
            continue;
        }
        let result = async {
            w.write_all(&batch).await?;
            w.flush().await
        }
        .await;
        batch.clear();
        if let Err(e) = result {
            return format!("write: {}", e);
        }
        trace!("mux wrote {} bytes", taken);
        let mut state = shared.lock();
        state.out.bytes -= taken;
        if state.out.bytes < OUT_SOFT_LIMIT {
            for slot in state.streams.values_mut() {
                if let Some(w) = slot.write_waker.take() {
                    w.wake();
                }
            }
        }
    }
}

/// One stream of a session.
pub struct MuxStream {
    id: u32,
    shared: Arc<Shared>,
}

fn closed(state: &State) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!(
            "mux session closed: {}",
            state.error.as_deref().unwrap_or("unknown")
        ),
    )
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        let mut guard = shared.lock();
        let state = &mut *guard;
        let Some(slot) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed(state)));
        };
        if let Some(front) = slot.recv.front_mut() {
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front[..n]);
            front.advance(n);
            if front.is_empty() {
                slot.recv.pop_front();
            }
            let was_full = state.buffered >= MAX_BUFFERED;
            state.buffered -= n;
            if was_full && state.buffered < MAX_BUFFERED {
                shared.reader.notify_one();
            }
            if shared.flavor == Flavor::Yamux && !slot.reset && state.error.is_none() {
                slot.consumed += n as u32;
                if slot.consumed >= yamux::WINDOW / 2 {
                    let delta = slot.consumed;
                    slot.consumed = 0;
                    slot.recv_window += delta;
                    state.out.push(yamux::window_update(0, self.id, delta));
                    shared.wake_writer();
                }
            }
            return Poll::Ready(Ok(()));
        }
        if slot.remote_fin {
            return Poll::Ready(Ok(()));
        }
        if slot.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if state.error.is_some() {
            return Poll::Ready(Err(closed(state)));
        }
        slot.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let shared = &self.shared;
        let mut guard = shared.lock();
        let state = &mut *guard;
        if state.error.is_some() {
            return Poll::Ready(Err(closed(state)));
        }
        let Some(slot) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed(state)));
        };
        if slot.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        // smux has no half-close: a stream the peer finished is closed.
        if slot.local_fin || (shared.flavor == Flavor::Smux && slot.remote_fin) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if state.out.bytes >= OUT_SOFT_LIMIT
            || (shared.flavor == Flavor::Yamux && slot.send_window == 0)
        {
            slot.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut n = buf.len().min(MAX_FRAME_DATA);
        let frame = match shared.flavor {
            Flavor::Smux => smux::frame(smux::CMD_PSH, self.id, &buf[..n]),
            Flavor::Yamux => {
                n = n.min(slot.send_window as usize);
                slot.send_window -= n as u32;
                yamux::data(0, self.id, &buf[..n])
            }
        };
        state.out.push(frame);
        drop(guard);
        shared.wake_writer();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// yamux sends a FIN, and can still read. smux cannot half-close, so
    /// its streams are finished when dropped instead.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shared.flavor == Flavor::Smux {
            return Poll::Ready(Ok(()));
        }
        let mut guard = self.shared.lock();
        let state = &mut *guard;
        if state.error.is_some() {
            return Poll::Ready(Ok(()));
        }
        if let Some(slot) = state.streams.get_mut(&self.id) {
            if !slot.local_fin && !slot.reset {
                slot.local_fin = true;
                state
                    .out
                    .push(yamux::window_update(yamux::FLAG_FIN, self.id, 0));
                drop(guard);
                self.shared.wake_writer();
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let mut guard = self.shared.lock();
        let state = &mut *guard;
        let Some(slot) = state.streams.remove(&self.id) else {
            return;
        };
        let unread: usize = slot.recv.iter().map(Bytes::len).sum();
        let was_full = state.buffered >= MAX_BUFFERED;
        state.buffered -= unread;
        if was_full && state.buffered < MAX_BUFFERED {
            self.shared.reader.notify_one();
        }
        if state.error.is_some() {
            return;
        }
        let frame = match self.shared.flavor {
            Flavor::Smux => Some(smux::frame(smux::CMD_FIN, self.id, &[])),
            // Abandoned before the peer finished: reset, so that it stops
            // sending. Otherwise finish, if not done yet.
            Flavor::Yamux if !slot.remote_fin && !slot.reset => {
                Some(yamux::window_update(yamux::FLAG_RST, self.id, 0))
            }
            Flavor::Yamux if !slot.local_fin && !slot.reset => {
                Some(yamux::window_update(yamux::FLAG_FIN, self.id, 0))
            }
            Flavor::Yamux => None,
        };
        if let Some(frame) = frame {
            state.out.push(frame);
            drop(guard);
            self.shared.wake_writer();
        }
    }
}

/// What turns away a stream the peer opened and this end does not take.
pub fn refuse_frame(flavor: Flavor, id: u32) -> Bytes {
    match flavor {
        Flavor::Smux => smux::frame(smux::CMD_FIN, id, &[]),
        Flavor::Yamux => yamux::window_update(yamux::FLAG_RST, id, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

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
        let (client, _) = FrameSession::new(a, flavor, false);
        let (_server, accept) = FrameSession::new(b, flavor, true);
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

    use std::time::Duration;

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
            let (client, _) = FrameSession::new(a, Flavor::Yamux, false);
            let (_server, accept) = FrameSession::new(b, Flavor::Yamux, true);
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
            let (client, _) = FrameSession::new(a, Flavor::Smux, false);
            let mut stream = client.open().unwrap();
            drop(b);
            let err = stream.read(&mut [0u8; 4]).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
            assert!(client.is_closed());
            assert!(client.open().is_err());
        });
    }
}
