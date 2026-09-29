//! What every stream multiplexer sail speaks has in common: many streams
//! over one connection, read by one task and written by another, with
//! every buffer bounded (`session`).
//!
//! A protocol is only its frames (`Codec`): how a stream is opened,
//! carries data, is finished or reset, how more window is granted, and
//! what it reads off the connection, decoded into `Event`s. The session
//! does the rest the same way for all of them: the stream table, what a
//! stream has received and not yet read, flow control, and the queue of
//! what goes out.

use std::io;

use bytes::{Bytes, BytesMut};

mod session;

pub use session::{Session, Stream, MAX_STREAMS};

/// How a protocol keeps what a stream has received and not read bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// The peer sends a stream no more than its window, which grows as
    /// the stream is read (yamux).
    Window {
        /// The window every stream starts with.
        initial: u32,
    },
    /// No window: the session stops reading its connection while too much
    /// waits unread (smux).
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

    /// Opens stream `id`.
    fn open(&self, id: u32) -> Bytes;
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
