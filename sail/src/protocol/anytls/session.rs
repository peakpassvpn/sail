//! A session: many streams over one authenticated TLS connection.
//!
//! A reader task takes frames off the connection and hands stream data to
//! each stream's queue; a writer task owns the other half and writes what
//! the streams and the reader queue for it, padding the client's first
//! writes as the padding scheme says. Every queue is bounded, so a stream
//! whose reader falls behind stalls its session, as it does in the
//! reference implementation, rather than growing without limit.
//!
//! A stream closes whole: `FIN` tells the peer to close its end without
//! answering, so a stream that has sent one reads no further either, and
//! one that has received one writes no further.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf, WriteHalf,
};
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};
use tracing::{debug, trace, warn};

use crate::adapter::AnyStream;

use super::frame::{self, *};
use super::padding::{string_map, PaddingScheme, Size};

/// The padding scheme a client uses, which its server may replace. Shared
/// by all of the client's sessions.
pub type PaddingCell = Arc<RwLock<Arc<PaddingScheme>>>;

/// Frames or runs of frames queued for the writer.
const WRITE_QUEUE: usize = 64;
/// Data frames queued for a stream's reader.
const STREAM_QUEUE: usize = 32;
/// The most a stream writes into one frame. Smaller than a frame could be,
/// so that the write queue stays small.
const MAX_WRITE: usize = 16 * 1024;
/// The most the writer coalesces into one write once padding is over.
const MAX_COALESCE: usize = 64 * 1024;
/// Streams open at once on one session. A server refuses more.
pub const MAX_STREAMS: usize = 1024;
/// How long a client waits for a `SYNACK` on a reused session before it
/// takes the session to be stuck, as the reference client does.
const SYNACK_TIMEOUT: Duration = Duration::from_secs(3);

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "anytls stream closed")
}

/// What a stream and its session share.
#[derive(Default)]
struct StreamState {
    /// The peer sent `FIN`.
    fin_received: AtomicBool,
    /// The server failed to open the stream, and said why.
    error: Mutex<Option<String>>,
}

struct Slot {
    data: mpsc::Sender<Bytes>,
    state: Arc<StreamState>,
}

/// What the tasks and the session share.
struct Shared {
    streams: Mutex<HashMap<u32, Slot>>,
    cancel: CancellationToken,
    peer_version: AtomicU8,
    /// Bumped by every `SYNACK`, so that a pending timeout can tell whether
    /// one has come since it was armed.
    synack_generation: AtomicU64,
}

impl Shared {
    fn close(&self) {
        self.cancel.cancel();
        // Dropping the queues' senders ends every stream's reads.
        if let Ok(mut streams) = self.streams.lock() {
            streams.clear();
        }
    }

    fn remove(&self, sid: u32) -> Option<Slot> {
        self.streams.lock().ok()?.remove(&sid)
    }

    fn sender(&self, sid: u32) -> Option<mpsc::Sender<Bytes>> {
        self.streams
            .lock()
            .ok()?
            .get(&sid)
            .map(|slot| slot.data.clone())
    }
}

/// Called with every stream a client opens on a server's session.
pub type OnStream = Box<dyn Fn(Stream) + Send + Sync>;

enum Role {
    Client {
        padding: PaddingCell,
    },
    Server {
        padding: Arc<PaddingScheme>,
        on_stream: OnStream,
    },
}

pub struct Session {
    shared: Arc<Shared>,
    tx: mpsc::Sender<BytesMut>,
    next_sid: AtomicU32,
    /// The client's settings, sent with its first stream.
    settings: Mutex<Option<BytesMut>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shared.close();
    }
}

impl Session {
    /// A client session over `conn`, which has been authenticated.
    pub fn client(conn: AnyStream, padding: PaddingCell) -> Arc<Session> {
        let md5 = padding
            .read()
            .map(|p| p.md5().to_string())
            .unwrap_or_default();
        let settings = frame::encode(
            CMD_SETTINGS,
            0,
            &frame::settings(&[
                ("v", &VERSION.to_string()),
                ("client", CLIENT_NAME),
                ("padding-md5", &md5),
            ]),
        );
        Self::start(conn, Role::Client { padding }, Some(settings))
    }

    /// A server session over `conn`, which has been authenticated.
    pub fn server(
        conn: AnyStream,
        padding: Arc<PaddingScheme>,
        on_stream: OnStream,
    ) -> Arc<Session> {
        Self::start(conn, Role::Server { padding, on_stream }, None)
    }

    fn start(conn: AnyStream, role: Role, settings: Option<BytesMut>) -> Arc<Session> {
        let shared = Arc::new(Shared {
            streams: Mutex::new(HashMap::new()),
            cancel: CancellationToken::new(),
            peer_version: AtomicU8::new(0),
            synack_generation: AtomicU64::new(0),
        });
        let (tx, rx) = mpsc::channel(WRITE_QUEUE);
        let (r, w) = tokio::io::split(conn);
        let padding = match &role {
            Role::Client { padding } => Some(padding.clone()),
            Role::Server { .. } => None,
        };
        let session = Arc::new(Session {
            shared: shared.clone(),
            tx: tx.clone(),
            next_sid: AtomicU32::new(0),
            settings: Mutex::new(settings),
        });

        let writer_shared = shared.clone();
        tokio::spawn(async move {
            let cancel = writer_shared.cancel.clone();
            tokio::select! {
                result = write_loop(w, rx, padding) => {
                    if let Err(e) = result {
                        debug!("anytls session write failed: {}", e);
                    }
                }
                _ = cancel.cancelled() => {}
            }
            writer_shared.close();
        });

        let reader = Reader {
            shared: shared.clone(),
            tx,
            role,
            session: Arc::downgrade(&session),
        };
        tokio::spawn(async move {
            let cancel = shared.cancel.clone();
            tokio::select! {
                result = reader.run(BufReader::new(r)) => {
                    if let Err(e) = result {
                        debug!("anytls session read ended: {}", e);
                    }
                }
                _ = cancel.cancelled() => {}
            }
            shared.close();
        });
        session
    }

    pub fn is_closed(&self) -> bool {
        self.shared.cancel.is_cancelled()
    }

    pub fn close(&self) {
        self.shared.close();
    }

    /// Opens a stream whose first data is `first`: the destination, and
    /// whatever else is known to follow it.
    pub async fn open_stream(self: &Arc<Self>, first: &[u8]) -> io::Result<Stream> {
        if self.is_closed() {
            return Err(closed_error());
        }
        let sid = self
            .next_sid
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let (data_tx, data_rx) = mpsc::channel(STREAM_QUEUE);
        let state = Arc::new(StreamState::default());
        {
            let mut streams = self.shared.streams.lock().map_err(|_| closed_error())?;
            if streams.len() >= MAX_STREAMS {
                return Err(io::Error::other("anytls session has too many streams"));
            }
            streams.insert(
                sid,
                Slot {
                    data: data_tx,
                    state: state.clone(),
                },
            );
        }
        let stream = Stream::new(self.clone(), sid, data_rx, state);

        // Settings, SYN and the destination go out as one write, which is
        // what the padding scheme counts as the first.
        let mut unit = self
            .settings
            .lock()
            .ok()
            .and_then(|mut s| s.take())
            .unwrap_or_default();
        frame::put(&mut unit, CMD_SYN, sid, &[]);
        frame::put(&mut unit, CMD_PSH, sid, first);

        if sid >= 2 && self.shared.peer_version.load(Ordering::Relaxed) >= 2 {
            self.watch_synack();
        }
        self.tx.send(unit).await.map_err(|_| closed_error())?;
        Ok(stream)
    }

    /// Closes the session unless a `SYNACK` arrives in time: a reused
    /// session that has gone quiet is taken to be stuck.
    fn watch_synack(&self) {
        let generation = self
            .shared
            .synack_generation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let shared = Arc::downgrade(&self.shared);
        let cancel = self.shared.cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(SYNACK_TIMEOUT) => {}
                _ = cancel.cancelled() => return,
            }
            if let Some(shared) = shared.upgrade() {
                if shared.synack_generation.load(Ordering::Relaxed) == generation {
                    debug!("anytls session got no SYNACK in time, closing it");
                    shared.close();
                }
            }
        });
    }

    async fn send(&self, unit: BytesMut) -> io::Result<()> {
        self.tx.send(unit).await.map_err(|_| closed_error())
    }
}

struct Reader {
    shared: Arc<Shared>,
    tx: mpsc::Sender<BytesMut>,
    role: Role,
    session: Weak<Session>,
}

impl Reader {
    async fn send(&self, cmd: u8, sid: u32, data: &[u8]) -> io::Result<()> {
        self.tx
            .send(frame::encode(cmd, sid, data))
            .await
            .map_err(|_| closed_error())
    }

    async fn run<R: AsyncRead + Unpin>(&self, mut r: R) -> io::Result<()> {
        let mut settings_received = false;
        let mut raw = [0u8; HEADER_LEN];
        loop {
            r.read_exact(&mut raw).await?;
            let header = Header::decode(&raw);
            let sid = header.sid;
            let len = header.len as usize;
            match header.cmd {
                CMD_PSH => {
                    let data = read_data(&mut r, len).await?;
                    if data.is_empty() {
                        continue;
                    }
                    if let Some(sender) = self.shared.sender(sid) {
                        // A stream that has gone away drops its data.
                        let _ = sender.send(data).await;
                    }
                }
                CMD_SYN => {
                    let Role::Server { on_stream, .. } = &self.role else {
                        continue;
                    };
                    if !settings_received {
                        self.send(CMD_ALERT, 0, b"client did not send its settings")
                            .await?;
                        return Ok(());
                    }
                    let Some(session) = self.session.upgrade() else {
                        return Ok(());
                    };
                    let (data_tx, data_rx) = mpsc::channel(STREAM_QUEUE);
                    let state = Arc::new(StreamState::default());
                    let accepted = {
                        let mut streams = self.shared.streams.lock().map_err(|_| closed_error())?;
                        if streams.contains_key(&sid) {
                            continue;
                        }
                        if streams.len() >= MAX_STREAMS {
                            false
                        } else {
                            streams.insert(
                                sid,
                                Slot {
                                    data: data_tx,
                                    state: state.clone(),
                                },
                            );
                            true
                        }
                    };
                    if !accepted {
                        warn!("anytls session has too many streams, refusing one");
                        self.send(CMD_FIN, sid, &[]).await?;
                        continue;
                    }
                    trace!("anytls stream {} opened", sid);
                    on_stream(Stream::new(session, sid, data_rx, state));
                }
                CMD_SYNACK => {
                    self.shared
                        .synack_generation
                        .fetch_add(1, Ordering::Relaxed);
                    if len > 0 {
                        let data = read_data(&mut r, len).await?;
                        if let Some(slot) = self.shared.remove(sid) {
                            let message = String::from_utf8_lossy(&data).into_owned();
                            if let Ok(mut error) = slot.state.error.lock() {
                                *error = Some(message);
                            }
                        }
                    }
                }
                CMD_FIN => {
                    if let Some(slot) = self.shared.remove(sid) {
                        slot.state.fin_received.store(true, Ordering::Release);
                    }
                }
                CMD_WASTE => {
                    skip(&mut r, len).await?;
                }
                CMD_SETTINGS => {
                    if len == 0 {
                        continue;
                    }
                    let data = read_data(&mut r, len).await?;
                    if let Role::Server { padding, .. } = &self.role {
                        settings_received = true;
                        let settings = string_map(&data);
                        if settings.get("padding-md5").map(String::as_str) != Some(padding.md5()) {
                            self.send(CMD_UPDATE_PADDING_SCHEME, 0, padding.raw())
                                .await?;
                        }
                        if let Some(v) = settings.get("v").and_then(|v| v.parse::<u8>().ok()) {
                            if v >= 2 {
                                self.shared.peer_version.store(v, Ordering::Relaxed);
                                let settings = frame::settings(&[("v", &VERSION.to_string())]);
                                self.send(CMD_SERVER_SETTINGS, 0, &settings).await?;
                            }
                        }
                    }
                }
                CMD_ALERT => {
                    if len == 0 {
                        continue;
                    }
                    let data = read_data(&mut r, len).await?;
                    if matches!(self.role, Role::Client { .. }) {
                        warn!(
                            "anytls alert from server: {}",
                            String::from_utf8_lossy(&data)
                        );
                    }
                    return Ok(());
                }
                CMD_UPDATE_PADDING_SCHEME => {
                    if len == 0 {
                        continue;
                    }
                    let data = read_data(&mut r, len).await?;
                    if let Role::Client { padding } = &self.role {
                        match PaddingScheme::parse(&data) {
                            Some(scheme) => {
                                debug!("anytls padding scheme updated to {}", scheme.md5());
                                if let Ok(mut current) = padding.write() {
                                    *current = Arc::new(scheme);
                                }
                            }
                            None => {
                                warn!("anytls server sent a padding scheme that does not parse")
                            }
                        }
                    }
                }
                CMD_HEART_REQUEST => {
                    self.send(CMD_HEART_RESPONSE, sid, &[]).await?;
                }
                CMD_HEART_RESPONSE => {}
                CMD_SERVER_SETTINGS => {
                    if len == 0 {
                        continue;
                    }
                    let data = read_data(&mut r, len).await?;
                    if let Role::Client { .. } = &self.role {
                        let settings = string_map(&data);
                        if let Some(v) = settings.get("v").and_then(|v| v.parse::<u8>().ok()) {
                            self.shared.peer_version.store(v, Ordering::Relaxed);
                        }
                    }
                }
                // Unknown commands carry no data.
                _ => {}
            }
        }
    }
}

async fn read_data<R: AsyncRead + Unpin>(r: &mut R, len: usize) -> io::Result<Bytes> {
    let mut data = vec![0u8; len];
    r.read_exact(&mut data).await?;
    Ok(Bytes::from(data))
}

async fn skip<R: AsyncRead + Unpin>(r: &mut R, mut len: usize) -> io::Result<()> {
    let mut scratch = [0u8; 1024];
    while len > 0 {
        let n = len.min(scratch.len());
        r.read_exact(&mut scratch[..n]).await?;
        len -= n;
    }
    Ok(())
}

async fn write_loop(
    mut w: WriteHalf<AnyStream>,
    mut rx: mpsc::Receiver<BytesMut>,
    padding: Option<PaddingCell>,
) -> io::Result<()> {
    let mut pkt: u32 = 0;
    let mut padding = padding;
    while let Some(mut unit) = rx.recv().await {
        if let Some(cell) = &padding {
            pkt = pkt.wrapping_add(1);
            let scheme = cell
                .read()
                .map(|s| s.clone())
                .map_err(|_| io::Error::other("padding scheme poisoned"))?;
            if pkt < scheme.stop() {
                write_padded(&mut w, unit, &scheme.sizes(pkt)).await?;
                continue;
            }
            padding = None;
        }
        while unit.len() < MAX_COALESCE {
            match rx.try_recv() {
                Ok(more) => unit.extend_from_slice(&more),
                Err(_) => break,
            }
        }
        w.write_all(&unit).await?;
        w.flush().await?;
    }
    Ok(())
}

/// Writes `unit` in the records `sizes` asks for, as `writeConn` in the
/// reference does: payload first, padded out with waste frames where the
/// payload runs short.
async fn write_padded<W: AsyncWrite + Unpin>(
    w: &mut W,
    mut unit: BytesMut,
    sizes: &[Size],
) -> io::Result<()> {
    for size in sizes {
        let record = match *size {
            Size::Check if unit.is_empty() => break,
            Size::Check => continue,
            Size::Record(n) => n,
        };
        let remaining = unit.len();
        if remaining > record {
            let head = unit.split_to(record);
            w.write_all(&head).await?;
        } else if remaining > 0 {
            let padding = record as isize - remaining as isize - HEADER_LEN as isize;
            if padding > 0 {
                unit.extend_from_slice(&frame::waste(padding as usize));
            }
            w.write_all(&unit).await?;
            unit.clear();
        } else {
            w.write_all(&frame::waste(record)).await?;
        }
        w.flush().await?;
    }
    if !unit.is_empty() {
        w.write_all(&unit).await?;
        w.flush().await?;
    }
    Ok(())
}

/// One stream of a session.
pub struct Stream {
    session: Arc<Session>,
    sid: u32,
    rx: mpsc::Receiver<Bytes>,
    pending: Bytes,
    state: Arc<StreamState>,
    tx: PollSender<BytesMut>,
    fin_sent: bool,
    /// Run when the stream is dropped: how a client puts its session back.
    on_drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl Stream {
    fn new(
        session: Arc<Session>,
        sid: u32,
        rx: mpsc::Receiver<Bytes>,
        state: Arc<StreamState>,
    ) -> Self {
        let tx = PollSender::new(session.tx.clone());
        Stream {
            session,
            sid,
            rx,
            pending: Bytes::new(),
            state,
            tx,
            fin_sent: false,
            on_drop: None,
        }
    }

    pub fn id(&self) -> u32 {
        self.sid
    }

    pub fn set_on_drop(&mut self, on_drop: Box<dyn FnOnce() + Send + Sync>) {
        self.on_drop = Some(on_drop);
    }

    /// Tells a version 2 client whether the stream opened: `None` for
    /// success, or the error.
    pub async fn report(&self, error: Option<&str>) -> io::Result<()> {
        if self.session.shared.peer_version.load(Ordering::Relaxed) < 2 {
            return Ok(());
        }
        let data = error.map(str::as_bytes).unwrap_or_default();
        let data = &data[..data.len().min(MAX_DATA)];
        self.session
            .send(frame::encode(CMD_SYNACK, self.sid, data))
            .await
    }

    /// Stops taking data for this stream.
    fn detach(&mut self) {
        self.fin_sent = true;
        self.session.shared.remove(self.sid);
    }

    fn write_closed(&self) -> bool {
        self.fin_sent || self.state.fin_received.load(Ordering::Acquire) || self.session.is_closed()
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                let chunk = self.pending.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match ready!(self.rx.poll_recv(cx)) {
                Some(data) => self.pending = data,
                None => {
                    if let Some(error) = self.state.error.lock().ok().and_then(|e| e.clone()) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("anytls server: {}", error),
                        )));
                    }
                    if self.fin_sent || self.state.fin_received.load(Ordering::Acquire) {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "anytls session closed",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed() {
            return Poll::Ready(Err(closed_error()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.tx.poll_reserve(cx)).map_err(|_| closed_error())?;
        let n = buf.len().min(MAX_WRITE);
        let sid = self.sid;
        self.tx
            .send_item(frame::encode(CMD_PSH, sid, &buf[..n]))
            .map_err(|_| closed_error())?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.fin_sent {
            return Poll::Ready(Ok(()));
        }
        if self.write_closed() {
            self.detach();
            return Poll::Ready(Ok(()));
        }
        if ready!(self.tx.poll_reserve(cx)).is_ok() {
            let sid = self.sid;
            let _ = self.tx.send_item(frame::encode(CMD_FIN, sid, &[]));
        }
        self.detach();
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.write_closed() {
            let fin = frame::encode(CMD_FIN, self.sid, &[]);
            if let Err(mpsc::error::TrySendError::Full(fin)) = self.session.tx.try_send(fin) {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    let tx = self.session.tx.clone();
                    runtime.spawn(async move {
                        let _ = tx.send(fin).await;
                    });
                }
            }
        }
        self.session.shared.remove(self.sid);
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

/// Reads the authentication a client starts with: the password's SHA-256
/// and its padding. Returns the hash.
pub async fn read_auth<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<[u8; 32]> {
    let mut hash = [0u8; 32];
    r.read_exact(&mut hash).await?;
    let len = r.read_u16().await? as usize;
    skip(r, len).await?;
    Ok(hash)
}

/// The authentication a client starts with.
pub fn auth(hash: &[u8; 32], padding: usize) -> Vec<u8> {
    let padding = padding.min(u16::MAX as usize);
    let mut buf = Vec::with_capacity(32 + 2 + padding);
    buf.extend_from_slice(hash);
    buf.extend_from_slice(&(padding as u16).to_be_bytes());
    buf.resize(32 + 2 + padding, 0);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn cell() -> PaddingCell {
        Arc::new(RwLock::new(Arc::new(PaddingScheme::default_scheme())))
    }

    #[test]
    fn auth_round_trips() {
        runtime().block_on(async {
            let hash = [7u8; 32];
            let raw = auth(&hash, 30);
            assert_eq!(raw.len(), 64);
            let mut r = &raw[..];
            assert_eq!(read_auth(&mut r).await.unwrap(), hash);
            assert!(r.is_empty());
        });
    }

    #[test]
    fn padded_writes_follow_the_sizes() {
        runtime().block_on(async {
            let mut out = Vec::new();
            // Payload longer than the first record, then padded out.
            write_padded(
                &mut out,
                BytesMut::from(&[1u8; 30][..]),
                &[Size::Record(20), Size::Record(40)],
            )
            .await
            .unwrap();
            // 20 bytes, then 10 bytes and a waste frame of 40 - 10 - 7.
            assert_eq!(out.len(), 20 + 10 + HEADER_LEN + 23);
            assert_eq!(out[30], CMD_WASTE);

            // Nothing left at a check: stop.
            let mut out = Vec::new();
            write_padded(
                &mut out,
                BytesMut::from(&[1u8; 5][..]),
                &[Size::Record(100), Size::Check, Size::Record(100)],
            )
            .await
            .unwrap();
            assert_eq!(out.len(), 100);

            // No payload at all before a record: all padding.
            let mut out = Vec::new();
            write_padded(&mut out, BytesMut::new(), &[Size::Record(9)])
                .await
                .unwrap();
            assert_eq!(out.len(), HEADER_LEN + 9);
        });
    }

    /// A client and a server session over a pipe, the server echoing every
    /// stream.
    #[test]
    fn sessions_carry_streams_both_ways() {
        runtime().block_on(async {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let server = Session::server(
                Box::new(b),
                Arc::new(PaddingScheme::parse(b"stop=1").unwrap()),
                Box::new(|mut stream: Stream| {
                    tokio::spawn(async move {
                        stream.report(None).await.unwrap();
                        let mut buf = vec![0u8; 4096];
                        loop {
                            let n = stream.read(&mut buf).await.unwrap();
                            if n == 0 {
                                break;
                            }
                            stream.write_all(&buf[..n]).await.unwrap();
                        }
                    });
                }),
            );
            let padding = cell();
            let client = Session::client(Box::new(a), padding.clone());
            for i in 0..3u8 {
                let mut stream = client.open_stream(&[i]).await.unwrap();
                let mut echo = [0u8; 1];
                stream.read_exact(&mut echo).await.unwrap();
                assert_eq!(echo[0], i);
                let data = vec![i; 100_000];
                stream.write_all(&data).await.unwrap();
                let mut back = vec![0u8; data.len()];
                stream.read_exact(&mut back).await.unwrap();
                assert_eq!(back, data);
                stream.shutdown().await.unwrap();
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).await.unwrap();
            }
            // The server's scheme differs from the default, so it was sent.
            assert_eq!(padding.read().unwrap().stop(), 1);
            assert!(!client.is_closed());
            drop(server);
        });
    }
}
