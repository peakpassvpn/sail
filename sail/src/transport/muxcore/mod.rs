//! What every stream multiplexer sail speaks has in common: many streams
//! over one connection, read by one task and written by another, with
//! every buffer bounded (`session`).
//!
//! A protocol is only its frames (`Codec`): how a stream is opened,
//! carries data, is finished or reset, how more window is granted, and
//! what it reads off the connection, decoded into `Event`s. The session
//! does the rest the same way for all of them:
//!
//! - The reader never waits for a stream. What a stream receives waits in
//!   its inbox. With windows (yamux), the peer sends no more than the
//!   window; windows start at `INITIAL_WINDOW` and grow, as quic-go's do,
//!   while a stream is read faster than its window lets data come in one
//!   round trip, up to `Tuning::window_max`; a session's windows together
//!   grow by a bounded budget, and a stream idle for a while gives its
//!   growth back when another needs it. Without windows (smux), the
//!   reader stops reading the connection while a stream holds
//!   `Tuning::inbox` unread, and TCP holds the peer back.
//! - A stream whose inbox holds data that nothing has read for
//!   `Tuning::stall_timeout` is reset, alone: its data dropped, the peer
//!   told as the protocol tells it. A stream that is read, however slowly,
//!   never is.
//! - Control frames -- acknowledgements, window updates, pings -- go out
//!   ahead of data, in a queue of their own the reader never waits on.
//! - Streams the peer opens are never turned away for being many at
//!   once, only past `MAX_STREAMS`.
//! - A stream holds its session: dropping the session's handle takes no
//!   new streams and closes it once the last stream is done.
//!
//! How many sessions and streams there are, and how many were reset for
//! stalling, is counted per protocol (`stats`).

// Without a protocol on the core, only the stall timer is used (QUIC).
#![cfg_attr(
    not(any(
        feature = "mux",
        feature = "inbound-amux",
        feature = "outbound-amux",
        feature = "inbound-anytls",
        feature = "outbound-anytls"
    )),
    allow(dead_code, unused_imports)
)]

use std::io;
use std::time::Duration;

use bytes::{Bytes, BytesMut};

mod session;
pub mod stall;
pub mod stats;

pub use session::{Session, Stream, MAX_STREAMS};

/// The window every stream starts with, where there are windows.
pub const INITIAL_WINDOW: u32 = 256 << 10;

/// What sessions run with: `runtime::options::Mux`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// The largest a stream's receive window grows to.
    pub window_max: u32,
    /// Without windows: what a stream holds unread before its session
    /// stops reading the connection.
    pub inbox: usize,
    /// A stream whose data nothing has read for this long is reset.
    pub stall_timeout: Duration,
    /// h2mux: every stream's window, which does not grow; the
    /// connection's is eight times as much.
    pub h2_stream_window: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning::from(&crate::runtime::options::Mux::default())
    }
}

impl From<&crate::runtime::options::Mux> for Tuning {
    fn from(mux: &crate::runtime::options::Mux) -> Self {
        Tuning {
            window_max: u32::try_from(mux.stream_window_max.saturating_mul(1024))
                .unwrap_or(u32::MAX)
                .max(INITIAL_WINDOW),
            inbox: mux.stream_buffer.saturating_mul(1024).max(16 << 10),
            stall_timeout: mux.stall_timeout.max(Duration::from_secs(1)),
            // A quarter of what a window grows to: 4 MiB, 2 on the mobile
            // profile, 1 on the router one.
            h2_stream_window: u32::try_from(mux.stream_window_max.saturating_mul(1024) / 4)
                .unwrap_or(u32::MAX)
                .max(1 << 20),
        }
    }
}

impl Tuning {
    /// How often streams are checked for stalling.
    fn stall_check(&self) -> Duration {
        stall::check_interval(self.stall_timeout)
    }
}

/// How a protocol keeps what a stream has received and not read bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// The peer sends a stream no more than its window, which grows as
    /// the stream is read (yamux, amux).
    Window,
    /// No window: the session stops reading its connection while a
    /// stream's inbox is full (smux, AnyTLS).
    Pause,
}

/// What finishing a stream means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closing {
    /// A FIN ends one direction; the other goes on (yamux).
    Half,
    /// There is no half-close: shutting a stream down does nothing, it is
    /// finished when dropped, and a FIN ends it both ways (smux).
    OnDrop,
    /// A FIN ends a stream both ways, sent when it is shut down: what
    /// comes after is dropped, what came before is still read (AnyTLS).
    Whole,
}

/// What a decoder makes of the frames it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The peer opens a stream.
    Open(u32),
    /// Data on a stream, all of a frame's or part of it.
    Data(u32, Bytes),
    /// The peer is done sending on a stream.
    Fin(u32),
    /// The peer abandons a stream.
    Reset(u32),
    /// The peer grants a stream more window.
    Window(u32, u32),
    /// The peer asks for its ping to be answered.
    Ping(u32),
    /// The peer answers a ping.
    Pong(u32),
    /// The peer takes no more streams.
    GoAway,
    /// The peer failed to open a stream this end opened, and says why.
    Refused(u32, String),
    /// A frame the protocol answers with, sent ahead of stream data.
    Reply(Bytes),
    /// The session is over, as the protocol says why.
    Close(String),
}

/// A protocol's frames.
pub trait Codec: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn flow(&self) -> Flow;
    fn closing(&self) -> Closing;
    /// The most data one frame carries.
    fn max_data(&self) -> usize;
    /// The id of the first stream this end opens; the next are `id_step`
    /// apart.
    fn first_id(&self, server: bool) -> u32;
    fn id_step(&self) -> u32 {
        2
    }
    /// The largest id a stream may have.
    fn max_id(&self) -> u32 {
        u32::MAX - 2
    }

    /// Opens stream `id` with `first` as its first data, which is no more
    /// than the initial window, as one write.
    fn open(&self, id: u32, first: &[u8]) -> Bytes;
    /// Acknowledges a stream the peer opened, if the protocol does.
    fn ack(&self, _id: u32) -> Option<Bytes> {
        None
    }
    /// Turns away a stream the peer opened.
    fn refuse(&self, id: u32) -> Bytes;
    fn data(&self, id: u32, data: &[u8]) -> Bytes;
    fn fin(&self, id: u32) -> Bytes;
    fn reset(&self, id: u32) -> Bytes;
    /// Grants the peer `delta` more window on stream `id`.
    fn window_update(&self, _id: u32, _delta: u32) -> Option<Bytes> {
        None
    }
    /// A ping, or its answer, if the protocol has them.
    fn ping(&self, _ack: bool, _opaque: u32) -> Option<Bytes> {
        None
    }

    /// Reads frames, for a server or a client.
    fn decoder(&self, server: bool) -> Box<dyn Decoder>;
    /// Shapes what the session writes, if the protocol does.
    fn shaper(&self) -> Option<Box<dyn Shaper>> {
        None
    }
}

/// Shapes the writes of a session, as AnyTLS pads the first of them.
pub trait Shaper: Send {
    /// Whether writes are still shaped. While they are, each frame, or run
    /// of frames queued at once, is a write of its own.
    fn active(&mut self) -> bool;
    /// The records one write is made of, each written and flushed on its
    /// own.
    fn shape(&mut self, write: BytesMut) -> Vec<BytesMut>;
}

/// Reads a protocol's frames off what the connection has given so far.
pub trait Decoder: Send {
    /// The next event in `buf`, taking what it read from it; `None` if more
    /// has to be read first. Data comes out as it arrives, a frame's in as
    /// many pieces as it was read in.
    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Event>>;
}

/// Where a decoder is between frames: the events a frame's header gave,
/// the data that follows it, and the events after that data.
#[derive(Default)]
pub struct Framing {
    before: std::collections::VecDeque<Event>,
    /// The stream, and how much of its frame's data is still to come.
    data: Option<(u32, usize)>,
    /// Data to be skipped, for frames of no use.
    skip: usize,
    after: Vec<Event>,
}

impl Framing {
    /// A frame's header has been read: `before`, then `len` bytes of data
    /// for stream `id`, then `after`.
    pub fn frame(&mut self, before: &[Event], data: Option<(u32, usize)>, after: &[Event]) {
        self.before.extend(before.iter().cloned());
        self.data = data.filter(|(_, len)| *len > 0);
        match self.data {
            Some(_) => self.after.extend(after.iter().cloned()),
            None => self.before.extend(after.iter().cloned()),
        }
    }

    /// Skips the next `len` bytes.
    pub fn skip(&mut self, len: usize) {
        self.skip += len;
    }

    /// Whether a header is to be read next.
    pub fn at_header(&self) -> bool {
        self.before.is_empty() && self.data.is_none() && self.skip == 0
    }

    /// What is left of the frame being read, if it is not done: `Some(None)`
    /// while more has to be read first.
    pub fn next(&mut self, buf: &mut BytesMut) -> Option<Option<Event>> {
        use bytes::Buf;
        if let Some(event) = self.before.pop_front() {
            return Some(Some(event));
        }
        if self.skip > 0 {
            let n = self.skip.min(buf.len());
            buf.advance(n);
            self.skip -= n;
            if self.skip > 0 {
                return Some(None);
            }
        }
        if let Some((id, left)) = self.data {
            if buf.is_empty() {
                return Some(None);
            }
            let n = left.min(buf.len());
            let data = Bytes::copy_from_slice(&buf[..n]);
            buf.advance(n);
            if n == left {
                self.data = None;
                self.before.extend(self.after.drain(..));
            } else {
                self.data = Some((id, left - n));
            }
            return Some(Some(Event::Data(id, data)));
        }
        None
    }
}
