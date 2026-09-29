//! A session: the streams of one connection, and the task that reads and
//! writes it.
//!
//! A stream's data waits in its slot until the stream is read. The reader
//! stops reading the connection while more than `MAX_BUFFERED` bytes wait
//! across all streams; a protocol with windows also grants each stream a
//! window it may not overrun. What streams write waits in one queue for
//! the writer; a stream stops being accepted writes while the queue holds
//! `OUT_SOFT_LIMIT`, and a peer that makes it grow past `OUT_HARD_LIMIT`
//! with control frames it never reads loses the session.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use bytes::{Buf, Bytes, BytesMut};
use futures::future::{abortable, AbortHandle};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, trace};

use super::{Closing, Codec, Event, Flow};

/// Bytes received and not yet read, across a session's streams, before
/// the session stops reading its connection.
const MAX_BUFFERED: usize = 4 << 20;
/// Queued for the connection: past this, streams wait to write.
const OUT_SOFT_LIMIT: usize = 1 << 20;
/// Queued for the connection: past this, the session is closed.
const OUT_HARD_LIMIT: usize = 8 << 20;
/// Written to the connection at once, at most.
const WRITE_BATCH: usize = 64 << 10;
/// Read from the connection at once, at most.
const READ_BUFFER: usize = 64 << 10;
/// Streams one session carries at once.
pub const MAX_STREAMS: usize = 1024;
/// Streams accepted and not yet taken by the server.
const ACCEPT_QUEUE: usize = 256;
/// The largest window a stream may be granted, beyond which a peer is
/// taken to be misbehaving.
const MAX_WINDOW: u32 = 16 << 20;

/// One stream's state.
struct Slot {
    recv: VecDeque<Bytes>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// The peer is done sending.
    remote_fin: bool,
    /// Sent a FIN.
    local_fin: bool,
    /// The peer reset the stream.
    reset: bool,
    /// With windows: what may still be sent.
    send_window: u32,
    /// With windows: what the peer may still send.
    recv_window: u32,
    /// With windows: read since the last window update.
    consumed: u32,
}

impl Slot {
    fn new(flow: Flow) -> Self {
        let window = match flow {
            Flow::Window { initial } => initial,
            Flow::Pause => 0,
        };
        Slot {
            recv: VecDeque::new(),
            read_waker: None,
            write_waker: None,
            remote_fin: false,
            local_fin: false,
            reset: false,
            send_window: window,
            recv_window: window,
            consumed: 0,
        }
    }

    fn wake(&mut self) {
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
struct Out {
    queue: VecDeque<Bytes>,
    bytes: usize,
}

impl Out {
    fn push(&mut self, frame: Bytes) {
        self.bytes += frame.len();
        self.queue.push_back(frame);
    }
}

struct State {
    streams: HashMap<u32, Slot>,
    out: Out,
    /// Why the session ended, once it has.
    error: Option<String>,
    /// The peer asked for no more streams.
    going_away: bool,
    /// The id of the next stream this end opens.
    next_id: u32,
    /// Received and not yet read, across all streams.
    buffered: usize,
    /// Where accepted streams go, on a server.
    accept: Option<mpsc::Sender<Stream>>,
}

struct Shared {
    codec: Arc<dyn Codec>,
    flow: Flow,
    closing: Closing,
    server: bool,
    state: Mutex<State>,
    /// Wakes the writer.
    writer: Notify,
    /// Wakes the reader waiting for buffered data to be read.
    reader: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock cannot leave the state worse than
        // any other failure would: carry on with it.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wake_writer(&self) {
        self.writer.notify_one();
    }

    /// Ends the session: every stream fails, or reads what it has and
    /// then fails.
    fn fail(&self, reason: String) {
        let mut state = self.lock();
        if state.error.is_none() {
            debug!("{} session closed: {}", self.codec.name(), reason);
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

    /// Queues a control frame, which the peer makes this end send: a peer
    /// that never reads them loses the session.
    fn control(&self, state: &mut State, frame: Bytes) -> io::Result<()> {
        state.out.push(frame);
        if state.out.bytes > OUT_HARD_LIMIT {
            return Err(io::Error::other("peer does not read what it asks for"));
        }
        self.writer.notify_one();
        Ok(())
    }

    /// Waits until the streams have read enough for more to be received.
    async fn wait_for_room(&self) {
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

    /// Takes a stream the peer opened, as a server. False if refused: too
    /// many streams, or not a server.
    fn accept(self: &Arc<Self>, state: &mut State, id: u32) -> bool {
        let Some(accept) = state.accept.as_ref() else {
            return false;
        };
        if state.streams.len() >= MAX_STREAMS {
            return false;
        }
        let Ok(permit) = accept.try_reserve() else {
            return false;
        };
        state.streams.insert(id, Slot::new(self.flow));
        permit.send(Stream {
            id,
            shared: self.clone(),
        });
        true
    }

    /// Does what the peer's frames ask.
    fn apply(self: &Arc<Self>, event: Event) -> io::Result<()> {
        let mut guard = self.lock();
        let state = &mut *guard;
        match event {
            Event::Open(id) => {
                if state.streams.contains_key(&id) {
                    return Ok(());
                }
                let frame = match self.accept(state, id) {
                    true => self.codec.ack(id),
                    false => Some(self.codec.refuse(id)),
                };
                if let Some(frame) = frame {
                    self.control(state, frame)?;
                }
            }
            Event::Data(id, data) => {
                // A stream already gone: what comes for it is dropped.
                let Some(slot) = state.streams.get_mut(&id) else {
                    return Ok(());
                };
                if let Flow::Window { .. } = self.flow {
                    if data.len() as u32 > slot.recv_window {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("{}: stream {} sent past its window", self.codec.name(), id),
                        ));
                    }
                    slot.recv_window -= data.len() as u32;
                }
                state.buffered += data.len();
                slot.recv.push_back(data);
                if let Some(w) = slot.read_waker.take() {
                    w.wake();
                }
            }
            Event::Window(id, delta) => {
                if let Some(slot) = state.streams.get_mut(&id) {
                    slot.send_window = slot
                        .send_window
                        .checked_add(delta)
                        .filter(|w| *w <= MAX_WINDOW)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("{}: window overflows", self.codec.name()),
                            )
                        })?;
                    slot.wake();
                }
            }
            Event::Fin(id) => {
                if let Some(slot) = state.streams.get_mut(&id) {
                    slot.remote_fin = true;
                    slot.wake();
                }
            }
            Event::Reset(id) => {
                if let Some(slot) = state.streams.get_mut(&id) {
                    slot.reset = true;
                    slot.wake();
                }
            }
            Event::Ping(opaque) => {
                if let Some(frame) = self.codec.ping(true, opaque) {
                    self.control(state, frame)?;
                }
            }
            Event::Pong(_) => {}
            Event::GoAway => state.going_away = true,
        }
        Ok(())
    }
}

/// A session over one connection, closed when dropped.
pub struct Session {
    shared: Arc<Shared>,
    task: AbortHandle,
}

impl Session {
    /// Starts a session over `conn`; a server also gets the streams the
    /// peer opens.
    pub fn new<S>(
        conn: S,
        codec: Arc<dyn Codec>,
        server: bool,
    ) -> (Self, Option<mpsc::Receiver<Stream>>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (accept_tx, accept_rx) = if server {
            let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let shared = Arc::new(Shared {
            flow: codec.flow(),
            closing: codec.closing(),
            state: Mutex::new(State {
                streams: HashMap::new(),
                out: Out::default(),
                error: None,
                going_away: false,
                next_id: codec.first_id(server),
                buffered: 0,
                accept: accept_tx,
            }),
            codec,
            server,
            writer: Notify::new(),
            reader: Notify::new(),
        });
        // Read and written by one task: a connection's halves polled from
        // two tasks may each take the other's wakeup, as a TLS stream that
        // writes while it reads does.
        let (r, w) = tokio::io::split(conn);
        let (driver, task) = abortable({
            let shared = shared.clone();
            async move {
                let reason = tokio::select! {
                    result = read_loop(&shared, r) => match result {
                        Ok(()) => "connection closed".to_string(),
                        Err(e) => e.to_string(),
                    },
                    reason = write_loop(&shared, w) => reason,
                };
                shared.fail(reason);
            }
        });
        tokio::spawn(driver);
        (Session { shared, task }, accept_rx)
    }

    /// Opens a stream.
    pub fn open(&self) -> io::Result<Stream> {
        let mut state = self.shared.lock();
        if let Some(e) = &state.error {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, e.clone()));
        }
        if state.going_away {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("{}: going away", self.shared.codec.name()),
            ));
        }
        if state.streams.len() >= MAX_STREAMS {
            return Err(io::Error::other(format!(
                "{}: too many streams",
                self.shared.codec.name()
            )));
        }
        let id = state.next_id;
        state.next_id = id
            .checked_add(self.shared.codec.id_step())
            .filter(|id| *id < u32::MAX - 2)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("{}: stream ids exhausted", self.shared.codec.name()),
                )
            })?;
        state.streams.insert(id, Slot::new(self.shared.flow));
        state.out.push(self.shared.codec.open(id));
        drop(state);
        self.shared.wake_writer();
        Ok(Stream {
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
        self.task.abort();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

/// Reads the connection until it ends, and does what its frames ask.
async fn read_loop<R: AsyncRead + Unpin>(shared: &Arc<Shared>, mut r: R) -> io::Result<()> {
    let mut decoder = shared.codec.decoder(shared.server);
    let mut buf = BytesMut::with_capacity(READ_BUFFER);
    loop {
        while let Some(event) = decoder.decode(&mut buf)? {
            shared.apply(event)?;
        }
        shared.wait_for_room().await;
        buf.reserve(READ_BUFFER);
        if r.read_buf(&mut buf).await? == 0 {
            if buf.is_empty() {
                return Ok(());
            }
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
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
        trace!("{} wrote {} bytes", shared.codec.name(), taken);
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
pub struct Stream {
    id: u32,
    shared: Arc<Shared>,
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.id
    }
}

fn closed(shared: &Shared, state: &State) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!(
            "{} session closed: {}",
            shared.codec.name(),
            state.error.as_deref().unwrap_or("unknown")
        ),
    )
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        let mut guard = shared.lock();
        let state = &mut *guard;
        let Some(slot) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed(shared, state)));
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
            if let Flow::Window { initial } = shared.flow {
                if !slot.reset && state.error.is_none() {
                    slot.consumed += n as u32;
                    if slot.consumed >= initial / 2 {
                        let delta = slot.consumed;
                        slot.consumed = 0;
                        slot.recv_window += delta;
                        if let Some(frame) = shared.codec.window_update(self.id, delta) {
                            state.out.push(frame);
                            shared.wake_writer();
                        }
                    }
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
            return Poll::Ready(Err(closed(shared, state)));
        }
        slot.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let shared = &self.shared;
        let mut guard = shared.lock();
        let state = &mut *guard;
        if state.error.is_some() {
            return Poll::Ready(Err(closed(shared, state)));
        }
        let Some(slot) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(closed(shared, state)));
        };
        if slot.reset {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        // Without half-close, a stream the peer finished is closed.
        if slot.local_fin || (shared.closing == Closing::OnDrop && slot.remote_fin) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let windowed = matches!(shared.flow, Flow::Window { .. });
        if state.out.bytes >= OUT_SOFT_LIMIT || (windowed && slot.send_window == 0) {
            slot.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut n = buf.len().min(shared.codec.max_data());
        if windowed {
            n = n.min(slot.send_window as usize);
            slot.send_window -= n as u32;
        }
        state.out.push(shared.codec.data(self.id, &buf[..n]));
        drop(guard);
        shared.wake_writer();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// With half-close, sends a FIN, and can still read. Without, streams
    /// are finished when dropped instead.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shared.closing == Closing::OnDrop {
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
                state.out.push(self.shared.codec.fin(self.id));
                drop(guard);
                self.shared.wake_writer();
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
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
        let codec = &self.shared.codec;
        let frame = match self.shared.closing {
            Closing::OnDrop => Some(codec.fin(self.id)),
            // Abandoned before the peer finished: reset, so that it stops
            // sending. Otherwise finish, if not done yet.
            Closing::Half if !slot.remote_fin && !slot.reset => Some(codec.reset(self.id)),
            Closing::Half if !slot.local_fin && !slot.reset => Some(codec.fin(self.id)),
            Closing::Half => None,
        };
        if let Some(frame) = frame {
            state.out.push(frame);
            drop(guard);
            self.shared.wake_writer();
        }
    }
}
