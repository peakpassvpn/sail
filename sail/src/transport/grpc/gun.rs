//! "gun", the gRPC Xray and sing-box carry a stream over: one call to
//! `/<service_name>/Tun`, each way a stream of gRPC messages, each message a
//! protobuf `Hunk { bytes data = 1; }` holding the next bytes.
//!
//! A gRPC message is a flag byte (compressed or not), a big-endian `u32`
//! length, and that many bytes. `Hunk` is a single length-delimited field,
//! tag `0x0a`. Nothing needs a protobuf library for that, and a message is
//! decoded as it arrives, never held whole.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{ready, FutureExt};
use h2::{RecvStream, SendStream};
use http::HeaderMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The most a single write puts in one message. Big enough that the five
/// and a few bytes of framing are noise, small enough not to hold a stream's
/// window for long.
const MAX_HUNK: usize = 32 * 1024;

/// The longest message accepted. Xray and sing-box send far smaller ones;
/// gRPC's own default limit is 4 MiB.
const MAX_MESSAGE: u32 = 4 * 1024 * 1024;

/// The framing in front of a hunk of `len` bytes, at most.
const MAX_FRAMING: usize = 5 + 1 + 10;

fn varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn put_varint(buf: &mut BytesMut, mut value: u64) {
    while value >= 0x80 {
        buf.put_u8((value as u8) | 0x80);
        value >>= 7;
    }
    buf.put_u8(value as u8);
}

/// `data` as a gRPC message holding a `Hunk`.
pub fn encode_hunk(data: &[u8]) -> Bytes {
    let field = 1 + varint_len(data.len() as u64) + data.len();
    let mut buf = BytesMut::with_capacity(5 + field);
    buf.put_u8(0);
    buf.put_u32(field as u32);
    buf.put_u8(0x0a);
    put_varint(&mut buf, data.len() as u64);
    buf.put_slice(data);
    buf.freeze()
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("gun: {}", what))
}

/// A varint being read, a byte at a time.
#[derive(Debug, Default)]
struct Varint {
    value: u64,
    shift: u32,
}

impl Varint {
    /// Takes `byte`; the value once it is the last.
    fn push(&mut self, byte: u8) -> io::Result<Option<u64>> {
        if self.shift >= 64 {
            return Err(invalid("varint too long"));
        }
        self.value |= u64::from(byte & 0x7f) << self.shift;
        self.shift += 7;
        if byte & 0x80 == 0 {
            let value = self.value;
            *self = Varint::default();
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
enum State {
    /// The five bytes in front of a message.
    Prefix { buf: [u8; 5], filled: usize },
    /// A field's tag.
    Tag(Varint),
    /// A length-delimited field's length; `data` when it is `Hunk.data`.
    Length { data: bool, varint: Varint },
    /// `Hunk.data` itself.
    Data,
    /// Some other field's bytes, which are skipped.
    Skip,
    /// A varint field, which is skipped.
    SkipVarint,
}

/// Turns received bytes back into what the hunks held.
#[derive(Debug)]
pub struct Decoder {
    state: State,
    /// What is left of the current message.
    message: u64,
    /// What is left of the current field.
    field: u64,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder {
            state: State::Prefix {
                buf: [0; 5],
                filled: 0,
            },
            message: 0,
            field: 0,
        }
    }
}

impl Decoder {
    /// Whether it stands between two messages, where a stream may end.
    pub fn at_boundary(&self) -> bool {
        matches!(self.state, State::Prefix { filled: 0, .. })
    }

    /// The next field, or the next message when this one is done.
    fn next_field(&mut self) {
        self.state = if self.message == 0 {
            State::Prefix {
                buf: [0; 5],
                filled: 0,
            }
        } else {
            State::Tag(Varint::default())
        };
    }

    /// Takes a byte of the current message.
    fn message_byte(&mut self, input: &mut Bytes) -> io::Result<u8> {
        if self.message == 0 {
            return Err(invalid("field runs past its message"));
        }
        self.message -= 1;
        Ok(input.get_u8())
    }

    /// Decodes what it can of `input` into `out`, until one or the other is
    /// used up.
    pub fn decode(&mut self, input: &mut Bytes, out: &mut ReadBuf<'_>) -> io::Result<()> {
        while input.has_remaining() && out.remaining() > 0 {
            match &mut self.state {
                State::Prefix { buf, filled } => {
                    let n = (5 - *filled).min(input.len());
                    buf[*filled..*filled + n].copy_from_slice(&input[..n]);
                    input.advance(n);
                    *filled += n;
                    if *filled == 5 {
                        if buf[0] != 0 {
                            return Err(invalid("compressed messages are not supported"));
                        }
                        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                        if len > MAX_MESSAGE {
                            return Err(invalid("message too long"));
                        }
                        self.message = u64::from(len);
                        self.next_field();
                    }
                }
                State::Tag(varint) => {
                    let byte = input[0];
                    let tag = varint.push(byte)?;
                    self.message_byte(input)?;
                    if let Some(tag) = tag {
                        self.state = match (tag >> 3, tag & 7) {
                            (1, 2) => State::Length {
                                data: true,
                                varint: Varint::default(),
                            },
                            (_, 2) => State::Length {
                                data: false,
                                varint: Varint::default(),
                            },
                            (_, 0) => State::SkipVarint,
                            (_, 1) => {
                                self.field = 8;
                                State::Skip
                            }
                            (_, 5) => {
                                self.field = 4;
                                State::Skip
                            }
                            _ => return Err(invalid("unsupported protobuf wire type")),
                        };
                    }
                }
                State::Length { data, varint } => {
                    let data = *data;
                    let byte = input[0];
                    let len = varint.push(byte)?;
                    self.message_byte(input)?;
                    if let Some(len) = len {
                        if len > self.message {
                            return Err(invalid("field runs past its message"));
                        }
                        self.field = len;
                        self.state = if data { State::Data } else { State::Skip };
                        if len == 0 {
                            self.next_field();
                        }
                    }
                }
                State::Data => {
                    let n = (self.field as usize).min(input.len()).min(out.remaining());
                    out.put_slice(&input[..n]);
                    input.advance(n);
                    self.field -= n as u64;
                    self.message -= n as u64;
                    if self.field == 0 {
                        self.next_field();
                    }
                }
                State::Skip => {
                    if self.field > self.message {
                        return Err(invalid("field runs past its message"));
                    }
                    let n = (self.field as usize).min(input.len());
                    input.advance(n);
                    self.field -= n as u64;
                    self.message -= n as u64;
                    if self.field == 0 {
                        self.next_field();
                    }
                }
                State::SkipVarint => {
                    if self.message_byte(input)? & 0x80 == 0 {
                        self.next_field();
                    }
                }
            }
        }
        Ok(())
    }
}

fn h2_error(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io()
            .unwrap_or_else(|| io::Error::other("gun: h2 i/o error"))
    } else {
        io::Error::new(io::ErrorKind::BrokenPipe, format!("gun: {}", e))
    }
}

/// What a stream is received from.
enum Receiving {
    /// The client's: the response has not come yet.
    Response(h2::client::ResponseFuture),
    Body(RecvStream),
}

/// How a side ends its half of the call.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// With an empty DATA frame ending the stream.
    Client,
    /// With the trailers a gRPC call ends with: `grpc-status: 0`.
    Server,
}

/// One gun call as a byte stream.
pub struct GunStream {
    send: SendStream<Bytes>,
    recv: Receiving,
    side: Side,
    decoder: Decoder,
    /// Received and not yet decoded.
    pending: Bytes,
    shut: bool,
}

impl GunStream {
    /// The client's end of the call `response` answers.
    pub fn client(send: SendStream<Bytes>, response: h2::client::ResponseFuture) -> Self {
        Self::new(send, Receiving::Response(response), Side::Client)
    }

    /// The server's end of the call whose request body `recv` is.
    pub fn server(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self::new(send, Receiving::Body(recv), Side::Server)
    }

    fn new(send: SendStream<Bytes>, recv: Receiving, side: Side) -> Self {
        GunStream {
            send,
            recv,
            side,
            decoder: Decoder::default(),
            pending: Bytes::new(),
            shut: false,
        }
    }
}

impl AsyncRead for GunStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.pending.has_remaining() {
                let before = buf.filled().len();
                this.decoder.decode(&mut this.pending, buf)?;
                if buf.filled().len() > before {
                    return Poll::Ready(Ok(()));
                }
                // Framing only; there is more to read.
                continue;
            }
            match &mut this.recv {
                Receiving::Response(response) => {
                    let response = ready!(response.poll_unpin(cx)).map_err(h2_error)?;
                    if response.status() != http::StatusCode::OK {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "gun: server answered {}",
                            response.status()
                        ))));
                    }
                    this.recv = Receiving::Body(response.into_body());
                }
                Receiving::Body(body) => match ready!(body.poll_data(cx)) {
                    Some(Ok(data)) => {
                        // Room for more as soon as it is out of h2's hands:
                        // what waits here is bounded by the one chunk.
                        let _ = body.flow_control().release_capacity(data.len());
                        this.pending = data;
                    }
                    Some(Err(e)) => return Poll::Ready(Err(h2_error(e))),
                    None if this.decoder.at_boundary() => return Poll::Ready(Ok(())),
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "gun: stream ended inside a message",
                        )))
                    }
                },
            }
        }
    }
}

impl AsyncWrite for GunStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        let want = buf.len().min(MAX_HUNK);
        // Flow control: a hunk goes out when the window has room for it, so
        // that nothing piles up in h2's buffers.
        this.send.reserve_capacity(want + MAX_FRAMING);
        loop {
            if this.send.capacity() > MAX_FRAMING {
                break;
            }
            match ready!(this.send.poll_capacity(cx)) {
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(h2_error(e))),
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "gun: stream closed",
                    )))
                }
            }
        }
        let n = want.min(this.send.capacity() - MAX_FRAMING);
        this.send
            .send_data(encode_hunk(&buf[..n]), false)
            .map_err(h2_error)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The connection's task writes what is sent.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.shut {
            this.shut = true;
            match this.side {
                Side::Client => this.send.send_data(Bytes::new(), true),
                Side::Server => {
                    let mut trailers = HeaderMap::new();
                    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                    this.send.send_trailers(trailers)
                }
            }
            .map_err(h2_error)?;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(decoder: &mut Decoder, mut input: Bytes) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 7];
        while input.has_remaining() {
            let mut read = ReadBuf::new(&mut buf);
            decoder.decode(&mut input, &mut read)?;
            out.extend_from_slice(read.filled());
        }
        Ok(out)
    }

    #[test]
    fn test_encode_hunk() {
        assert_eq!(
            &encode_hunk(b"abc")[..],
            &[0, 0, 0, 0, 5, 0x0a, 3, b'a', b'b', b'c'][..]
        );
        // A length over 127 takes two varint bytes.
        let hunk = encode_hunk(&[7u8; 300]);
        assert_eq!(&hunk[..8], &[0, 0, 0, 1, 47, 0x0a, 0xac, 0x02][..]);
        assert_eq!(hunk.len(), 8 + 300);
    }

    #[test]
    fn test_decode_across_any_split() {
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut wire = Vec::new();
        for chunk in data.chunks(300) {
            wire.extend_from_slice(&encode_hunk(chunk));
        }
        // An empty message, as `Hunk {}` encodes, between two others.
        wire.extend_from_slice(&[0, 0, 0, 0, 0]);
        wire.extend_from_slice(&encode_hunk(b"end"));
        let mut expected = data.clone();
        expected.extend_from_slice(b"end");

        for split in [1, 2, 3, 5, 6, 7, 64, 301, wire.len()] {
            let mut decoder = Decoder::default();
            let mut out = Vec::new();
            for piece in wire.chunks(split) {
                out.extend(decode_all(&mut decoder, Bytes::copy_from_slice(piece)).unwrap());
            }
            assert_eq!(out, expected, "split {}", split);
            assert!(decoder.at_boundary());
        }
    }

    #[test]
    fn test_decode_skips_other_fields() {
        // field 2 (bytes "xy"), field 3 (varint 300), field 4 (fixed32),
        // then data.
        let field = [
            0x12, 2, b'x', b'y', 0x18, 0xac, 0x02, 0x25, 1, 2, 3, 4, 0x0a, 2, b'o', b'k',
        ];
        let mut wire = vec![0, 0, 0, 0, field.len() as u8];
        wire.extend_from_slice(&field);
        let out = decode_all(&mut Decoder::default(), Bytes::from(wire)).unwrap();
        assert_eq!(out, b"ok");
    }

    #[test]
    fn test_decode_refuses_malformed() {
        // Compressed.
        let wire = Bytes::from_static(&[1, 0, 0, 0, 1, 0]);
        assert!(decode_all(&mut Decoder::default(), wire).is_err());
        // Too long.
        let wire = Bytes::from_static(&[0, 0xff, 0xff, 0xff, 0xff]);
        assert!(decode_all(&mut Decoder::default(), wire).is_err());
        // A field longer than its message.
        let wire = Bytes::from_static(&[0, 0, 0, 0, 3, 0x0a, 5, b'a']);
        assert!(decode_all(&mut Decoder::default(), wire).is_err());
        // Wire type 3, a group.
        let wire = Bytes::from_static(&[0, 0, 0, 0, 1, 0x0b]);
        assert!(decode_all(&mut Decoder::default(), wire).is_err());
    }

    #[test]
    fn test_boundary() {
        let mut decoder = Decoder::default();
        let hunk = encode_hunk(b"abc");
        decode_all(&mut decoder, hunk.slice(..4)).unwrap();
        assert!(!decoder.at_boundary());
        decode_all(&mut decoder, hunk.slice(4..)).unwrap();
        assert!(decoder.at_boundary());
    }
}
