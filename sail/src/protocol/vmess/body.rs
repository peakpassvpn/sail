//! The VMess body: the chunks both directions are cut into.
//!
//! With the chunk stream option each chunk is a two-byte size -- XORed with
//! a SHAKE128 stream of the body IV under chunk masking -- then the payload,
//! sealed unless the security is none, then random padding whose length
//! comes from the same SHAKE128 stream under global padding. A chunk with
//! an empty payload ends the direction. Without the option the body is the
//! bare stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use btls::aead::{AeadCtx, Algorithm};
use bytes::{Buf, BytesMut};
use futures::ready;
use md5::{Digest, Md5};
use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::header::*;

const TAG_LEN: usize = 16;

/// The most plaintext a stream chunk carries: sing-box reads chunks into
/// 16 KiB buffers, tag included, and writes at most 15000 bytes.
const MAX_STREAM_CHUNK: usize = 15000;

/// The most a UDP packet can be: a chunk's size, less the tag and the most
/// padding there can be.
pub const MAX_PACKET: usize = u16::MAX as usize - TAG_LEN - 63;

/// Read from the transport at a time.
const READ_SIZE: usize = 16 * 1024;

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("vmess: {}", what))
}

/// The security a request asks for, as the body applies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

impl Security {
    pub fn from_wire(security: u8) -> io::Result<Self> {
        match security {
            SECURITY_AES128_GCM => Ok(Security::Aes128Gcm),
            SECURITY_CHACHA20_POLY1305 => Ok(Security::Chacha20Poly1305),
            SECURITY_NONE => Ok(Security::None),
            other => Err(invalid(&format!("unsupported security {}", other))),
        }
    }

    pub fn wire(self) -> u8 {
        match self {
            Security::Aes128Gcm => SECURITY_AES128_GCM,
            Security::Chacha20Poly1305 => SECURITY_CHACHA20_POLY1305,
            Security::None => SECURITY_NONE,
        }
    }
}

/// One direction of a body: its cipher, nonce count and SHAKE stream.
struct Direction {
    aead: Option<AeadCtx>,
    iv: [u8; 16],
    count: u16,
    shake: Option<sha3::Shake128Reader>,
    masking: bool,
    padding: bool,
}

impl Direction {
    fn new(security: Security, option: u8, key: &[u8; 16], iv: &[u8; 16]) -> io::Result<Self> {
        let aead = match security {
            Security::Aes128Gcm => Some(AeadCtx::new_default_tag(&Algorithm::aes_128_gcm(), key)),
            Security::Chacha20Poly1305 => {
                let first = Md5::digest(key);
                let second = Md5::digest(first);
                let key = [first, second].concat();
                Some(AeadCtx::new_default_tag(
                    &Algorithm::chacha20_poly1305(),
                    &key,
                ))
            }
            Security::None => None,
        }
        .transpose()
        .map_err(io::Error::other)?;
        let masking = option & OPTION_CHUNK_MASKING != 0;
        let padding = option & OPTION_GLOBAL_PADDING != 0;
        // Masking and padding draw from one stream, padding first.
        let shake = (masking || padding).then(|| {
            let mut shake = Shake128::default();
            shake.update(iv);
            shake.finalize_xof()
        });
        Ok(Direction {
            aead,
            iv: *iv,
            count: 0,
            shake,
            masking,
            padding,
        })
    }

    fn overhead(&self) -> usize {
        if self.aead.is_some() {
            TAG_LEN
        } else {
            0
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        if let Some(shake) = &mut self.shake {
            shake.read(&mut b);
        }
        u16::from_be_bytes(b)
    }

    fn next_padding(&mut self) -> usize {
        if self.padding {
            (self.next_u16() % 64) as usize
        } else {
            0
        }
    }

    fn mask(&mut self, size: u16) -> u16 {
        if self.masking {
            size ^ self.next_u16()
        } else {
            size
        }
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        self.count = self.count.wrapping_add(1);
        nonce
    }

    /// Appends one chunk carrying `payload` to `out`.
    fn put_chunk(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> io::Result<()> {
        let padding = self.next_padding();
        let size = payload.len() + self.overhead() + padding;
        let size = u16::try_from(size).map_err(|_| invalid("chunk too large"))?;
        let size = self.mask(size);
        out.extend_from_slice(&size.to_be_bytes());
        let start = out.len();
        out.extend_from_slice(payload);
        if self.aead.is_some() {
            let nonce = self.nonce();
            let mut tag = [0u8; TAG_LEN];
            let aead = self.aead.as_mut().expect("checked above");
            aead.seal_in_place_mut(&nonce, &mut out[start..], &mut tag, &[])
                .map_err(io::Error::other)?;
            out.extend_from_slice(&tag);
        }
        let end = out.len();
        out.resize(end + padding, 0);
        rand::thread_rng().fill_bytes(&mut out[end..]);
        Ok(())
    }

    /// Opens a chunk's sealed payload in place; the plaintext is what is
    /// left.
    fn open(&mut self, data: &mut BytesMut) -> io::Result<()> {
        if self.aead.is_none() {
            return Ok(());
        }
        if data.len() < TAG_LEN {
            return Err(invalid("chunk shorter than its tag"));
        }
        let nonce = self.nonce();
        let tag = data.split_off(data.len() - TAG_LEN);
        let aead = self.aead.as_mut().expect("checked above");
        aead.open_in_place_mut(&nonce, data, &tag, &[])
            .map_err(|_| invalid("chunk does not open"))
    }
}

/// A VMess body in both directions over `inner`: the client's or the
/// server's end.
pub struct VmessStream<S> {
    inner: S,
    chunked: bool,
    read: Direction,
    write: Direction,
    // The client waits for the response header before any body; this is
    // its request.
    response_for: Option<RequestHeader>,
    // Read from the transport, not yet parsed.
    rbuf: BytesMut,
    // The size and padding of the chunk being read, once its size is.
    chunk: Option<(usize, usize)>,
    // A chunk's plaintext not yet handed out.
    plain: BytesMut,
    read_done: bool,
    // Each read returns one chunk and drops what does not fit: one UDP
    // packet per chunk.
    packets: bool,
    // The server's response header, sent with the first bytes written.
    prefix: Option<Vec<u8>>,
    // Written by the caller, not yet by the transport: wbuf[wpos..].
    wbuf: Vec<u8>,
    wpos: usize,
    max_chunk: usize,
    write_done: bool,
}

impl<S> VmessStream<S> {
    fn new(
        inner: S,
        request: &RequestHeader,
        read: Direction,
        write: Direction,
        packets: bool,
    ) -> io::Result<Self> {
        let chunked = request.option & OPTION_CHUNK_STREAM != 0;
        if request.option & OPTION_AUTHENTICATED_LENGTH != 0 {
            return Err(invalid("authenticated length is not supported"));
        }
        if packets && !chunked {
            return Err(invalid("UDP needs the chunk stream option"));
        }
        Ok(VmessStream {
            inner,
            chunked,
            read,
            write,
            response_for: None,
            rbuf: BytesMut::new(),
            chunk: None,
            plain: BytesMut::new(),
            read_done: false,
            packets,
            prefix: None,
            wbuf: Vec::new(),
            wpos: 0,
            max_chunk: if packets {
                MAX_PACKET
            } else {
                MAX_STREAM_CHUNK
            },
            write_done: false,
        })
    }

    /// The client's end, after it has sent `request`. With `packets`, each
    /// write is one chunk and each read one chunk, as UDP is carried.
    pub fn client(inner: S, request: &RequestHeader, packets: bool) -> io::Result<Self> {
        let security = Security::from_wire(request.security)?;
        let (response_key, response_iv) = request.response_keys();
        let write = Direction::new(
            security,
            request.option,
            &request.body_key,
            &request.body_iv,
        )?;
        let read = Direction::new(security, request.option, &response_key, &response_iv)?;
        let mut stream = Self::new(inner, request, read, write, packets)?;
        stream.response_for = Some(request.clone());
        Ok(stream)
    }

    /// The server's end of `request`.
    pub fn server(inner: S, request: &RequestHeader, packets: bool) -> io::Result<Self> {
        let security = Security::from_wire(request.security)?;
        let (response_key, response_iv) = request.response_keys();
        let read = Direction::new(
            security,
            request.option,
            &request.body_key,
            &request.body_iv,
        )?;
        let write = Direction::new(security, request.option, &response_key, &response_iv)?;
        let mut stream = Self::new(inner, request, read, write, packets)?;
        stream.prefix = Some(request.seal_response()?);
        Ok(stream)
    }

    /// Parses what `rbuf` holds. Returns whether it made progress.
    fn parse(&mut self) -> io::Result<bool> {
        if let Some(request) = &self.response_for {
            return match open_response(request, &self.rbuf)? {
                Some(n) => {
                    self.rbuf.advance(n);
                    self.response_for = None;
                    Ok(true)
                }
                None => Ok(false),
            };
        }
        if !self.chunked {
            if self.rbuf.is_empty() {
                return Ok(false);
            }
            self.plain = self.rbuf.split();
            return Ok(true);
        }
        if self.chunk.is_none() {
            if self.rbuf.len() < 2 {
                return Ok(false);
            }
            let padding = self.read.next_padding();
            let size = self.read.mask(self.rbuf.get_u16()) as usize;
            if size < padding + self.read.overhead() {
                return Err(invalid("bad chunk size"));
            }
            self.chunk = Some((size, padding));
        }
        let (size, padding) = self.chunk.expect("set above");
        if self.rbuf.len() < size {
            return Ok(false);
        }
        self.chunk = None;
        let mut data = self.rbuf.split_to(size - padding);
        self.rbuf.advance(padding);
        self.read.open(&mut data)?;
        if data.is_empty() {
            self.read_done = true;
        } else {
            self.plain = data;
        }
        Ok(true)
    }

    fn mid_chunk(&self) -> bool {
        self.response_for.is_none() && (self.chunk.is_some() || !self.rbuf.is_empty())
    }
}

impl<S: AsyncWrite + Unpin> VmessStream<S> {
    /// Writes out `wbuf`, and the response header if it is still to go.
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(prefix) = self.prefix.take() {
            self.wbuf.splice(0..0, prefix);
        }
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        if self.wbuf.capacity() > 2 * MAX_STREAM_CHUNK {
            self.wbuf = Vec::new();
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.plain.is_empty() {
                let n = this.plain.len().min(buf.remaining());
                buf.put_slice(&this.plain.split_to(n));
                if this.packets {
                    this.plain.clear();
                }
                return Poll::Ready(Ok(()));
            }
            if this.read_done {
                return Poll::Ready(Ok(()));
            }
            if this.parse()? {
                continue;
            }
            this.rbuf.reserve(READ_SIZE);
            let mut chunk = [0u8; READ_SIZE];
            let mut read_buf = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read_buf))?;
            if read_buf.filled().is_empty() {
                if this.response_for.is_some() || this.mid_chunk() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vmess: truncated",
                    )));
                }
                // Closed without the empty chunk: an end all the same.
                this.read_done = true;
                continue;
            }
            this.rbuf.extend_from_slice(read_buf.filled());
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.chunked {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if this.packets && buf.len() > this.max_chunk {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmess: packet too large",
            )));
        }
        let n = buf.len().min(this.max_chunk);
        this.write.put_chunk(&mut this.wbuf, &buf[..n])?;
        // The chunk is taken; what the transport does not accept now goes
        // out on the next write or flush.
        if let Poll::Ready(Err(e)) = this.poll_pending(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.chunked && !this.write_done {
            this.write_done = true;
            this.write.put_chunk(&mut this.wbuf, &[])?;
        }
        ready!(this.poll_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn options() -> Vec<(u8, u8)> {
        let full = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING;
        vec![
            (SECURITY_AES128_GCM, full),
            (SECURITY_CHACHA20_POLY1305, full),
            (
                SECURITY_AES128_GCM,
                OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING,
            ),
            (SECURITY_CHACHA20_POLY1305, OPTION_CHUNK_STREAM),
            (SECURITY_NONE, full),
            (SECURITY_NONE, OPTION_CHUNK_STREAM),
            (SECURITY_NONE, 0),
        ]
    }

    #[tokio::test]
    async fn test_body_both_ways() {
        for (security, option) in options() {
            let request = RequestHeader::new(option, security, COMMAND_TCP, None);
            let (a, b) = tokio::io::duplex(4096);
            let mut client = VmessStream::client(a, &request, false).unwrap();
            let mut server = VmessStream::server(b, &request, false).unwrap();
            let mut up = vec![0u8; 100_000];
            rand::thread_rng().fill_bytes(&mut up);
            let down = up.iter().rev().copied().collect::<Vec<_>>();
            let (up2, down2) = (up.clone(), down.clone());
            let client_task = tokio::spawn(async move {
                client.write_all(&up2).await.unwrap();
                client.shutdown().await.unwrap();
                let mut got = Vec::new();
                client.read_to_end(&mut got).await.unwrap();
                got
            });
            let mut got = Vec::new();
            server.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, up, "security {} option {}", security, option);
            server.write_all(&down2).await.unwrap();
            server.shutdown().await.unwrap();
            assert_eq!(client_task.await.unwrap(), down);
        }
    }

    #[tokio::test]
    async fn test_packets_keep_their_boundaries() {
        let request = RequestHeader::new(
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
            SECURITY_CHACHA20_POLY1305,
            COMMAND_UDP,
            None,
        );
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut client = VmessStream::client(a, &request, true).unwrap();
        let mut server = VmessStream::server(b, &request, true).unwrap();
        for size in [1, 1500, 30_000, MAX_PACKET] {
            client.write_all(&vec![7u8; size]).await.unwrap();
        }
        let mut buf = vec![0u8; 65536];
        for size in [1, 1500, 30_000, MAX_PACKET] {
            assert_eq!(server.read(&mut buf).await.unwrap(), size);
        }
        assert!(client.write_all(&vec![0u8; MAX_PACKET + 1]).await.is_err());
        // A packet larger than the reader's buffer loses its tail, not its
        // boundary.
        server.write_all(&[1u8; 100]).await.unwrap();
        server.write_all(&[2u8; 10]).await.unwrap();
        let mut small = [0u8; 50];
        assert_eq!(client.read(&mut small).await.unwrap(), 50);
        assert_eq!(client.read(&mut small).await.unwrap(), 10);
        assert_eq!(&small[..10], &[2u8; 10]);
    }

    #[tokio::test]
    async fn test_tampered_chunk_is_an_error() {
        let request = RequestHeader::new(
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING,
            SECURITY_AES128_GCM,
            COMMAND_TCP,
            None,
        );
        let mut wire = Vec::new();
        {
            let mut client = VmessStream::client(&mut wire, &request, false).unwrap();
            client.write_all(b"hello").await.unwrap();
            client.flush().await.unwrap();
        }
        wire[4] ^= 1;
        let mut server = VmessStream::server(&wire[..], &request, false).unwrap();
        let mut buf = [0u8; 16];
        assert!(server.read(&mut buf).await.is_err());
    }

    #[test]
    fn test_authenticated_length_is_refused() {
        let request = RequestHeader::new(
            OPTION_CHUNK_STREAM | OPTION_AUTHENTICATED_LENGTH,
            SECURITY_AES128_GCM,
            COMMAND_TCP,
            None,
        );
        assert!(VmessStream::server(tokio::io::empty(), &request, false).is_err());
    }
}
