//! The VLESS request and response headers, and the streams that carry them.
//!
//! A request is the version (0), the user's UUID, its addons -- a protobuf
//! message whose field 1 is the flow -- behind a one-byte length, the
//! command, and for TCP and UDP the destination, port first. The response is
//! the version and addons of its own, which no server fills.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use futures::ready;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::protocol::vmess::xudp::{read_addr_port, write_addr_port};
use crate::session::SocksAddr;

pub const VERSION: u8 = 0;

/// XTLS Vision, the one flow there is.
pub const FLOW_VISION: &str = "xtls-rprx-vision";

pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
/// Mux.Cool, which sail speaks as XUDP only.
pub const COMMAND_MUX: u8 = 3;

/// The flow a user or an outbound is configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    None,
    Vision,
}

impl Flow {
    pub fn parse(flow: &str) -> Result<Self, String> {
        match flow {
            "" => Ok(Flow::None),
            FLOW_VISION => Ok(Flow::Vision),
            other => Err(format!(
                "unsupported flow \"{}\", expected \"\" or \"{}\"",
                other, FLOW_VISION
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Flow::None => "",
            Flow::Vision => FLOW_VISION,
        }
    }
}

/// Encodes a request. A Mux request has no destination.
pub fn encode_request(
    uuid: &[u8; 16],
    flow: Flow,
    command: u8,
    destination: Option<&SocksAddr>,
) -> BytesMut {
    let mut buf = BytesMut::with_capacity(64);
    buf.put_u8(VERSION);
    buf.put_slice(uuid);
    let flow = flow.as_str();
    if flow.is_empty() {
        buf.put_u8(0);
    } else {
        // Field 1, length-delimited; the flow is shorter than 128 bytes, so
        // its varint length is one byte.
        buf.put_u8(2 + flow.len() as u8);
        buf.put_u8(0x0a);
        buf.put_u8(flow.len() as u8);
        buf.put_slice(flow.as_bytes());
    }
    buf.put_u8(command);
    if let Some(destination) = destination {
        write_addr_port(&mut buf, destination);
    }
    buf
}

/// A request as a server reads it.
#[derive(Debug)]
pub struct Request {
    pub uuid: [u8; 16],
    /// The flow as the client sent it, not yet checked.
    pub flow: String,
    pub command: u8,
    /// None for Mux.
    pub destination: Option<SocksAddr>,
}

fn invalid(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// Reads a request, up to the UUID first: `known` tells whether a UUID
/// belongs to a user, and reading stops right there if not.
pub async fn read_request<R, F>(r: &mut R, known: F) -> io::Result<Request>
where
    R: AsyncRead + Unpin,
    F: FnOnce(&[u8; 16]) -> bool,
{
    let version = r.read_u8().await?;
    if version != VERSION {
        return Err(invalid(format!("unknown version {}", version)));
    }
    let mut uuid = [0u8; 16];
    r.read_exact(&mut uuid).await?;
    if !known(&uuid) {
        return Err(invalid(format!(
            "unknown user {}",
            uuid::Uuid::from_bytes(uuid)
        )));
    }
    let addons_len = r.read_u8().await? as usize;
    let mut addons = [0u8; 255];
    r.read_exact(&mut addons[..addons_len]).await?;
    let flow = parse_addons(&addons[..addons_len])?;
    let command = r.read_u8().await?;
    let destination = match command {
        COMMAND_TCP | COMMAND_UDP => Some(read_addr_port(r).await?),
        COMMAND_MUX => None,
        other => return Err(invalid(format!("unknown command {}", other))),
    };
    Ok(Request {
        uuid,
        flow,
        command,
        destination,
    })
}

fn read_varint(buf: &[u8], pos: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *buf
            .get(*pos)
            .ok_or_else(|| invalid("truncated addons".to_string()))?;
        *pos += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("bad varint in addons".to_string()))
}

/// The flow in the addons: field 1. Field 2, the seed of the old XTLS
/// flows, is skipped; anything else is an error, as it is to Xray.
fn parse_addons(buf: &[u8]) -> io::Result<String> {
    let mut flow = String::new();
    let mut pos = 0;
    while pos < buf.len() {
        let key = read_varint(buf, &mut pos)?;
        let len = read_varint(buf, &mut pos)? as usize;
        let value = buf
            .get(pos..pos.saturating_add(len))
            .ok_or_else(|| invalid("truncated addons".to_string()))?;
        pos += len;
        match key {
            0x0a => {
                flow = String::from_utf8(value.to_vec())
                    .map_err(|_| invalid("flow is not UTF-8".to_string()))?
            }
            0x12 => {}
            other => return Err(invalid(format!("unknown addons field {:#x}", other))),
        }
    }
    Ok(flow)
}

/// The client's stream after a request without Vision: it strips the
/// response header from what the server sends.
pub struct ClientStream<S> {
    inner: S,
    // Response header bytes still to strip: the version and addons length,
    // then the addons.
    header: [u8; 2],
    header_read: usize,
    addons_left: usize,
}

impl<S> ClientStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 2],
            header_read: 0,
            addons_left: 0,
        }
    }

    fn header_done(&self) -> bool {
        self.header_read == 2 && self.addons_left == 0
    }

    /// Takes the header bytes at the start of `data`; returns how many.
    fn strip(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut used = 0;
        while used < data.len() && !self.header_done() {
            if self.header_read < 2 {
                self.header[self.header_read] = data[used];
                self.header_read += 1;
                used += 1;
                if self.header_read == 2 {
                    if self.header[0] != VERSION {
                        return Err(invalid(format!(
                            "unknown response version {}",
                            self.header[0]
                        )));
                    }
                    self.addons_left = self.header[1] as usize;
                }
            } else {
                let n = self.addons_left.min(data.len() - used);
                self.addons_left -= n;
                used += n;
            }
        }
        Ok(used)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let start = buf.filled().len();
            ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
            if this.header_done() {
                return Poll::Ready(Ok(()));
            }
            let end = buf.filled().len();
            if end == start {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "no VLESS response",
                )));
            }
            let used = this.strip(&buf.filled()[start..end])?;
            buf.filled_mut().copy_within(start + used..end, start);
            buf.set_filled(end - used);
            if end - used > start {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ClientStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The server's stream: it puts the response header in front of the first
/// bytes it writes, so the header does not travel alone.
pub struct ServerStream<S> {
    inner: S,
    header_sent: bool,
    // Bytes taken from the caller but not written yet: pending[pos..].
    pending: Vec<u8>,
    pos: usize,
}

impl<S> ServerStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header_sent: false,
            pending: Vec::new(),
            pos: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> ServerStream<S> {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.header_sent {
            self.header_sent = true;
            self.pending.splice(0..0, [VERSION, 0]);
        }
        while self.pos < self.pending.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pos += n;
        }
        self.pending = Vec::new();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ServerStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ServerStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.header_sent {
            ready!(this.poll_pending(cx))?;
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // The header goes out with these bytes; they count as written once
        // queued behind it.
        this.pending.extend_from_slice(buf);
        if let Poll::Ready(Err(e)) = this.poll_pending(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Reads one length-prefixed packet into `buf`, dropping what does not fit.
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let len = r.read_u16().await? as usize;
    let n = len.min(buf.len());
    r.read_exact(&mut buf[..n]).await?;
    if len > n {
        tokio::io::copy(&mut r.take((len - n) as u64), &mut tokio::io::sink()).await?;
    }
    Ok(n)
}

/// Writes one length-prefixed packet.
pub async fn write_packet<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> io::Result<()> {
    let len = u16::try_from(buf.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
    let mut packet = Vec::with_capacity(2 + buf.len());
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(buf);
    w.write_all(&packet).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [7; 16];

    #[tokio::test]
    async fn test_request_round_trip() {
        let dest = SocksAddr::try_from(("example.com", 443)).unwrap();
        for (flow, command, destination) in [
            (Flow::Vision, COMMAND_TCP, Some(&dest)),
            (Flow::None, COMMAND_UDP, Some(&dest)),
            (Flow::Vision, COMMAND_MUX, None),
        ] {
            let wire = encode_request(&UUID, flow, command, destination);
            let mut r = &wire[..];
            let request = read_request(&mut r, |u| *u == UUID).await.unwrap();
            assert!(r.is_empty());
            assert_eq!(request.flow, flow.as_str());
            assert_eq!(request.command, command);
            assert_eq!(request.destination.as_ref(), destination);
        }
    }

    // As sing-box and Xray write it.
    #[test]
    fn test_vision_request_bytes() {
        let wire = encode_request(
            &UUID,
            Flow::Vision,
            COMMAND_TCP,
            Some(&SocksAddr::try_from(("1.2.3.4", 80)).unwrap()),
        );
        let mut expected = vec![0];
        expected.extend_from_slice(&UUID);
        expected.extend_from_slice(&[18, 0x0a, 16]);
        expected.extend_from_slice(FLOW_VISION.as_bytes());
        expected.extend_from_slice(&[1, 0, 80, 1, 1, 2, 3, 4]);
        assert_eq!(&wire[..], &expected[..]);
    }

    #[tokio::test]
    async fn test_bad_requests() {
        let dest = SocksAddr::try_from(("1.2.3.4", 80)).unwrap();
        let wire = encode_request(&UUID, Flow::None, COMMAND_TCP, Some(&dest));
        // Unknown user.
        assert!(read_request(&mut &wire[..], |_| false).await.is_err());
        // Every truncation fails cleanly.
        for cut in 0..wire.len() {
            assert!(read_request(&mut &wire[..cut], |_| true).await.is_err());
        }
        // Unknown command, unknown addons field.
        let mut bad = wire.to_vec();
        bad[18] = 9;
        assert!(read_request(&mut &bad[..], |_| true).await.is_err());
        assert!(parse_addons(&[0x1a, 0]).is_err());
        assert!(parse_addons(&[0x0a, 5, b'a']).is_err());
        assert_eq!(parse_addons(&[0x12, 1, 9, 0x0a, 1, b'x']).unwrap(), "x");
    }

    #[tokio::test]
    async fn test_response_header_both_ways() {
        let (a, b) = tokio::io::duplex(1024);
        let mut server = ServerStream::new(a);
        let mut client = ClientStream::new(b);
        server.write_all(b"hello").await.unwrap();
        server.write_all(b" world").await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello world");

        // A response with addons, arriving a byte at a time.
        let (mut a, b) = tokio::io::duplex(1);
        let mut client = ClientStream::new(b);
        tokio::spawn(async move { a.write_all(&[0, 3, 9, 9, 9, b'o', b'k']).await });
        let mut got = [0u8; 2];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ok");
    }
}
