//! A session: the streams of one connection, and the task that reads and
//! writes it.
//!
//! One task reads the connection, writes it, and looks for stalled streams
//! (`driver`). The reader hands what it reads to the streams' inboxes and
//! never waits for a stream to take it: with windows it has no need to,
//! and without, it stops reading the connection while an inbox is full,
//! which the stall timer ends in `Tuning::stall_timeout` at most. What
//! streams write waits in one queue, and a stream stops being taken writes
//! while that queue holds `OUT_SOFT_LIMIT`; control frames wait in one of
//! their own, written first, and a peer that makes it grow past
//! `CONTROL_LIMIT` with frames it never reads loses the session.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use futures::future::{abortable, AbortHandle};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use super::stats::{self, Counters};
use super::{Closing, Codec, Event, Flow, Tuning, INITIAL_WINDOW};

/// Stream data queued for the connection: past this, streams wait to
/// write.
const OUT_SOFT_LIMIT: usize = 1 << 20;
/// Control frames queued for the connection: past this, the peer does not
/// read what it asks for, and loses the session.
const CONTROL_LIMIT: usize = 1 << 20;
/// Written to the connection at once, at most.
const WRITE_BATCH: usize = 64 << 10;
/// Read from the connection at once, at most.
const READ_BUFFER: usize = 64 << 10;
/// Streams one session carries at once.
pub const MAX_STREAMS: usize = 1024;
/// The most a peer may grant a stream, beyond which it is taken to be
/// misbehaving.
const MAX_SEND_WINDOW: u32 = 1 << 30;
/// The windows of a session's streams grow, together, by no more than this
/// many times `Tuning::window_max`.
const SESSION_GROWTH: u64 = 4;
/// How long a closed session has to write what it has left.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// One stream's state.
struct Slot {
    /// What the stream received and has not read.
    recv: VecDeque<Bytes>,
    /// Bytes in `recv`.
    inbox: usize,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// The peer is done sending.
    remote_fin: bool,
    /// Sent a FIN.
    local_fin: bool,
    /// The peer reset the stream.
    reset: bool,
    /// Reset by this end, for nothing read what it received.
    stalled: bool,
    /// Since when what is in the inbox has waited unread: when data came
    /// into an empty inbox, or when the stream last read.
    progress: Instant,
    /// With windows: what may still be sent.
    send_window: u32,
    /// With windows: what the peer may still send.
    recv_window: u32,
    /// With windows: what `recv_window` is topped up to as the stream is
    /// read, which grows while it is read fast.
    window: u32,
    /// With windows: read since the last window update.
    consumed: u32,
    /// With windows: since when, and how much, the stream has read while
    /// its window stayed the same.
    epoch_start: Instant,
    epoch_read: u64,
}

impl Slot {
    fn new(flow: Flow) -> Self {
        let window = match flow {
            Flow::Window => INITIAL_WINDOW,
            Flow::Pause => 0,
        };
        let now = Instant::now();
        Slot {
            recv: VecDeque::new(),
            inbox: 0,
            read_waker: None,
            write_waker: None,
            remote_fin: false,
            local_fin: false,
            reset: false,
            stalled: false,
            progress: now,
            send_window: window,
            recv_window: window,
            window,
            consumed: 0,
            epoch_start: now,
            epoch_read: 0,
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
    /// Control frames, written first.
    control: Out,
    /// What the streams send: opening, data, finishing and resetting, in
    /// order.
    data: Out,
    /// Why the session ended, once it has.
    error: Option<String>,
    /// The peer asked for no more streams.
    going_away: bool,
    /// The handle is gone: no new streams, and the session ends with its
    /// last one.
    retired: bool,
    /// The id of the next stream this end opens.
    next_id: u32,
    /// Without windows: the streams whose inbox is full, which stop the
    /// reader.
    full: usize,
    /// With windows: what the streams' windows have grown by, together.
    grown: u64,
    /// With windows: the shortest round trip measured.
    rtt: Option<Duration>,
    /// With windows: `rtt` is set, not measured (tests).
    rtt_pinned: bool,
    /// With windows: the ping waiting for its answer, and when it went.
    ping: Option<(u32, Instant)>,
    pings: u32,
    /// Where accepted streams go, on a server.
    accept: Option<mpsc::UnboundedSender<Stream>>,
}

struct Shared {
    codec: Arc<dyn Codec>,
    flow: Flow,
    closing: Closing,
    server: bool,
    tuning: Tuning,
    /// Who the session serves, as its logs say it.
    label: Arc<str>,
    counters: Arc<Counters>,
    state: Mutex<State>,
    /// Wakes the writer.
    writer: Notify,
    /// Wakes the reader waiting for a full inbox to be read.
    reader: Notify,
    /// Stops the task that reads and writes the connection.
    task: Mutex<Option<AbortHandle>>,
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
    /// then fails. What is queued is still written, for a while.
    fn fail(&self, reason: String) {
        let mut state = self.lock();
        if state.error.is_none() {
            debug!("{} session closed: {}", self.codec.name(), reason);
            state.error = Some(reason);
            self.counters.session_closed();
        }
        let accept = state.accept.take();
        for slot in state.streams.values_mut() {
            slot.wake();
        }
        drop(state);
        drop(accept);
        self.writer.notify_one();
        self.reader.notify_one();
    }

    /// Ends the session at once.
    fn abort(&self, reason: &str) {
        self.fail(reason.to_string());
        let task = self.task.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(task) = task {
            task.abort();
        }
    }

    /// Queues a control frame. The peer makes this end send them: a peer
    /// that never reads them loses the session.
    fn control(&self, state: &mut State, frame: Bytes) -> io::Result<()> {
        state.control.push(frame);
        if state.control.bytes > CONTROL_LIMIT {
            return Err(io::Error::other("peer does not read what it asks for"));
        }
        self.writer.notify_one();
        Ok(())
    }

    /// Waits until no inbox is full.
    async fn wait_for_room(&self) {
        loop {
            let notified = self.reader.notified();
            {
                let state = self.lock();
                if state.full == 0 || state.error.is_some() {
                    return;
                }
            }
            notified.await;
        }
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
                if !self.server
                    || state.retired
                    || state.accept.is_none()
                    || state.streams.len() >= MAX_STREAMS
                {
                    self.counters.refused();
                    return self.control(state, self.codec.refuse(id));
                }
                state.streams.insert(id, Slot::new(self.flow));
                self.counters.stream_opened();
                if let Some(frame) = self.codec.ack(id) {
                    self.control(state, frame)?;
                }
                let accept = state.accept.clone();
                drop(guard);
                // Sent without the lock: a stream the server no longer
                // takes comes back and is dropped, which refuses it.
                if let Some(accept) = accept {
                    let _ = accept.send(Stream {
                        id,
                        shared: self.clone(),
                    });
                }
            }
            Event::Data(id, data) => self.deliver(state, id, data)?,
            Event::Window(id, delta) => {
                if let Some(slot) = state.streams.get_mut(&id) {
                    slot.send_window = slot
                        .send_window
                        .checked_add(delta)
                        .filter(|w| *w <= MAX_SEND_WINDOW)
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
            Event::Pong(opaque) => {
                if let Some((sent, at)) = state.ping {
                    if sent == opaque {
                        let rtt = at.elapsed();
                        if !state.rtt_pinned {
                            state.rtt = Some(state.rtt.map_or(rtt, |min| min.min(rtt)));
                        }
                        state.ping = None;
                    }
                }
            }
            Event::GoAway => state.going_away = true,
        }
        Ok(())
    }

    /// Puts data received for stream `id` in its inbox; dropped if the
    /// stream is gone.
    fn deliver(&self, state: &mut State, id: u32, data: Bytes) -> io::Result<()> {
        let Some(slot) = state.streams.get_mut(&id) else {
            return Ok(());
        };
        if self.flow == Flow::Window {
            if data.len() as u32 > slot.recv_window {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: stream {} sent past its window", self.codec.name(), id),
                ));
            }
            slot.recv_window -= data.len() as u32;
        }
        if slot.stalled {
            return Ok(());
        }
        if slot.recv.is_empty() {
            slot.progress = Instant::now();
        }
        let was_full = slot.inbox >= self.tuning.inbox;
        slot.inbox += data.len();
        slot.recv.push_back(data);
        if self.flow == Flow::Pause && !was_full && slot.inbox >= self.tuning.inbox {
            state.full += 1;
        }
        if let Some(w) = slot.read_waker.take() {
            w.wake();
        }
        Ok(())
    }

    /// Resets the streams whose data has waited unread for too long.
    fn check_stalls(&self) {
        let now = Instant::now();
        let mut guard = self.lock();
        let state = &mut *guard;
        if state.error.is_some() {
            return;
        }
        let mut stalled = Vec::new();
        for (id, slot) in state.streams.iter_mut() {
            if slot.inbox == 0 || slot.stalled {
                continue;
            }
            let idle = now.saturating_duration_since(slot.progress);
            if idle < self.tuning.stall_timeout {
                continue;
            }
            warn!(
                "event=stream_stalled protocol={} {} stream={} buffered={} idle={}s",
                self.codec.name(),
                self.label,
                id,
                slot.inbox,
                idle.as_secs()
            );
            if self.flow == Flow::Pause && slot.inbox >= self.tuning.inbox {
                state.full -= 1;
            }
            state.grown -= u64::from(slot.window.saturating_sub(INITIAL_WINDOW));
            slot.window = slot.window.min(INITIAL_WINDOW);
            slot.recv.clear();
            slot.inbox = 0;
            slot.stalled = true;
            slot.wake();
            stalled.push(*id);
        }
        if stalled.is_empty() {
            return;
        }
        for id in stalled {
            self.counters.stalled();
            state.data.push(self.codec.reset(id));
        }
        drop(guard);
        self.reader.notify_one();
        self.writer.notify_one();
    }

    /// Measures the round trip, which windows grow with.
    fn ping(&self) {
        if self.flow != Flow::Window {
            return;
        }
        let mut state = self.lock();
        if state.error.is_some() || state.ping.is_some_and(|(_, at)| at.elapsed() < CLOSE_GRACE) {
            return;
        }
        state.pings = state.pings.wrapping_add(1);
        let opaque = state.pings;
        if let Some(frame) = self.codec.ping(false, opaque) {
            state.ping = Some((opaque, Instant::now()));
            state.control.push(frame);
            drop(state);
            self.writer.notify_one();
        }
    }
}

/// A session over one connection. Its streams hold it: dropping the handle
/// takes no new streams, and ends the session once the last is done.
pub struct Session {
    shared: Arc<Shared>,
}

impl Session {
    /// Starts a session over `conn`; a server also gets the streams the
    /// peer opens. `label` says who the session serves in its logs, as
    /// `inbound=tag user=name` or `outbound=tag`.
    pub fn new<S>(
        conn: S,
        codec: Arc<dyn Codec>,
        server: bool,
        tuning: Tuning,
        label: impl Into<Arc<str>>,
    ) -> (Self, Option<mpsc::UnboundedReceiver<Stream>>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (accept_tx, accept_rx) = if server {
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let counters = stats::counters(codec.name());
        counters.session_opened();
        let shared = Arc::new(Shared {
            flow: codec.flow(),
            closing: codec.closing(),
            state: Mutex::new(State {
                streams: HashMap::new(),
                control: Out::default(),
                data: Out::default(),
                error: None,
                going_away: false,
                retired: false,
                next_id: codec.first_id(server),
                full: 0,
                grown: 0,
                rtt: None,
                rtt_pinned: false,
                ping: None,
                pings: 0,
                accept: accept_tx,
            }),
            codec,
            server,
            tuning,
            label: label.into(),
            counters,
            writer: Notify::new(),
            reader: Notify::new(),
            task: Mutex::new(None),
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
                    reason = tick_loop(&shared) => reason,
                };
                shared.fail(reason);
            }
        });
        *shared.task.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        tokio::spawn(driver);
        shared.ping();
        (Session { shared }, accept_rx)
    }

    /// Opens a stream.
    pub fn open(&self) -> io::Result<Stream> {
        let name = self.shared.codec.name();
        let mut state = self.shared.lock();
        if let Some(e) = &state.error {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, e.clone()));
        }
        if state.going_away || state.retired {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("{}: going away", name),
            ));
        }
        if state.streams.len() >= MAX_STREAMS {
            return Err(io::Error::other(format!("{}: too many streams", name)));
        }
        let id = state.next_id;
        state.next_id = id
            .checked_add(self.shared.codec.id_step())
            .filter(|id| *id < u32::MAX - 2)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("{}: stream ids exhausted", name),
                )
            })?;
        state.streams.insert(id, Slot::new(self.shared.flow));
        self.shared.counters.stream_opened();
        state.data.push(self.shared.codec.open(id));
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
        state.error.is_some() || state.going_away || state.retired
    }

    /// Ends the session and every stream on it, at once.
    pub fn close(&self) {
        self.shared.abort("closed");
    }

    /// Takes no new streams, and ends the session once the last stream is
    /// done.
    pub fn retire(&self) {
        let mut state = self.shared.lock();
        state.retired = true;
        let accept = state.accept.take();
        let idle = state.streams.is_empty();
        drop(state);
        drop(accept);
        if idle {
            self.shared.fail("retired".to_string());
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.retire();
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

/// Writes what is queued until the session ends and all of it is written,
/// and says why.
async fn write_loop<W: AsyncWrite + Unpin>(shared: &Shared, mut w: W) -> String {
    let mut batch = BytesMut::with_capacity(WRITE_BATCH);
    loop {
        let notified = shared.writer.notified();
        let (ended, control, data) = {
            let mut guard = shared.lock();
            let state = &mut *guard;
            let control = take(&mut state.control, &mut batch);
            let data = take(&mut state.data, &mut batch);
            (state.error.is_some(), control, data)
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
        trace!("{} wrote {} bytes", shared.codec.name(), control + data);
        let mut state = shared.lock();
        state.control.bytes -= control;
        state.data.bytes -= data;
        if data > 0 && state.data.bytes < OUT_SOFT_LIMIT {
            for slot in state.streams.values_mut() {
                if let Some(w) = slot.write_waker.take() {
                    w.wake();
                }
            }
        }
    }
}

/// Moves frames from `out` to `batch` while it has room, and says how many
/// bytes.
fn take(out: &mut Out, batch: &mut BytesMut) -> usize {
    let mut taken = 0;
    while let Some(frame) = out.queue.front() {
        if !batch.is_empty() && batch.len() + frame.len() > WRITE_BATCH {
            break;
        }
        taken += frame.len();
        batch.extend_from_slice(frame);
        out.queue.pop_front();
    }
    taken
}

/// Looks for stalled streams and measures the round trip, until the
/// session has ended and had its while to write what it had left.
async fn tick_loop(shared: &Shared) -> String {
    let every = shared.tuning.stall_check();
    loop {
        tokio::time::sleep(every).await;
        if shared.lock().error.is_some() {
            tokio::time::sleep(CLOSE_GRACE).await;
            return "closed, and could not write what it had left".to_string();
        }
        shared.check_stalls();
        if !shared.lock().streams.is_empty() {
            shared.ping();
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

    /// Takes the session's round trip to be `rtt`, whatever it measures.
    #[cfg(test)]
    pub fn pin_rtt(&self, rtt: Duration) {
        let mut state = self.shared.lock();
        state.rtt = Some(rtt);
        state.rtt_pinned = true;
    }

    /// The window this stream grants the peer, as it has grown.
    #[cfg(test)]
    pub fn window(&self) -> u32 {
        self.shared
            .lock()
            .streams
            .get(&self.id)
            .map_or(0, |slot| slot.window)
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

fn stalled(shared: &Shared) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "{}: stream reset, nothing read its data for {}s",
            shared.codec.name(),
            shared.tuning.stall_timeout.as_secs()
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
        if slot.stalled {
            return Poll::Ready(Err(stalled(shared)));
        }
        if let Some(front) = slot.recv.front_mut() {
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front[..n]);
            front.advance(n);
            if front.is_empty() {
                slot.recv.pop_front();
            }
            let now = Instant::now();
            let was_full = slot.inbox >= shared.tuning.inbox;
            slot.inbox -= n;
            slot.progress = now;
            if shared.flow == Flow::Pause && was_full && slot.inbox < shared.tuning.inbox {
                state.full -= 1;
                shared.reader.notify_one();
            }
            if shared.flow == Flow::Window && !slot.reset && state.error.is_none() {
                slot.consumed += n as u32;
                slot.epoch_read += n as u64;
                // As quic-go does: more window once a quarter of it is
                // read, and twice the window if half of it was read in
                // less than what it takes to come in two round trips.
                if slot.consumed >= slot.window / 4 {
                    let mut delta = slot.consumed;
                    if slot.epoch_read > u64::from(slot.window / 2) {
                        let budget = SESSION_GROWTH * u64::from(shared.tuning.window_max);
                        if let Some(rtt) = state.rtt {
                            let fraction = slot.epoch_read as f64 / f64::from(slot.window);
                            let fast = now.saturating_duration_since(slot.epoch_start)
                                < rtt.mul_f64(4.0 * fraction);
                            let grown = slot.window.saturating_mul(2).min(shared.tuning.window_max);
                            let growth = grown.saturating_sub(slot.window);
                            if fast && growth > 0 && state.grown + u64::from(growth) <= budget {
                                state.grown += u64::from(growth);
                                delta += growth;
                                slot.window = grown;
                            }
                        }
                        slot.epoch_start = now;
                        slot.epoch_read = 0;
                    }
                    slot.consumed = 0;
                    slot.recv_window += delta;
                    if let Some(frame) = shared.codec.window_update(self.id, delta) {
                        state.control.push(frame);
                        shared.wake_writer();
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
        if slot.stalled {
            return Poll::Ready(Err(stalled(shared)));
        }
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
        let windowed = shared.flow == Flow::Window;
        if state.data.bytes >= OUT_SOFT_LIMIT || (windowed && slot.send_window == 0) {
            slot.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut n = buf.len().min(shared.codec.max_data());
        if windowed {
            n = n.min(slot.send_window as usize);
            slot.send_window -= n as u32;
        }
        state.data.push(shared.codec.data(self.id, &buf[..n]));
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
            if !slot.local_fin && !slot.reset && !slot.stalled {
                slot.local_fin = true;
                state.data.push(self.shared.codec.fin(self.id));
                drop(guard);
                self.shared.wake_writer();
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let shared = &self.shared;
        let mut guard = shared.lock();
        let state = &mut *guard;
        let Some(slot) = state.streams.remove(&self.id) else {
            return;
        };
        shared.counters.stream_closed();
        if shared.flow == Flow::Pause && slot.inbox >= shared.tuning.inbox {
            state.full -= 1;
            shared.reader.notify_one();
        }
        state.grown -= u64::from(slot.window.saturating_sub(INITIAL_WINDOW));
        let last = state.retired && state.streams.is_empty();
        if state.error.is_none() && !slot.stalled {
            let codec = &shared.codec;
            let frame = match shared.closing {
                Closing::OnDrop => Some(codec.fin(self.id)),
                // Abandoned before the peer finished: reset, so that it
                // stops sending. Otherwise finish, if not done yet.
                Closing::Half if !slot.remote_fin && !slot.reset => Some(codec.reset(self.id)),
                Closing::Half if !slot.local_fin && !slot.reset => Some(codec.fin(self.id)),
                Closing::Half => None,
            };
            if let Some(frame) = frame {
                state.data.push(frame);
                shared.wake_writer();
            }
        }
        drop(guard);
        if last {
            shared.fail("retired, and its last stream is done".to_string());
        }
    }
}
