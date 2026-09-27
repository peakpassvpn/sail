//! `tls_fragment` and `tls_record_fragment`: the first thing written to an
//! outbound stream, when it is a TLS ClientHello, goes out cut in its
//! server name, so that a middlebox reading one segment or one record
//! does not see the whole name. As sing-box's `tf.Conn`, the cut falls at
//! random within the name's first label.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::session::TlsFragment;

const RECORD_HEADER_LEN: usize = 5;

/// Where the server name is in a ClientHello record, and the name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ServerName {
    pub index: usize,
    pub name: String,
}

/// The server name of `payload`, when it is a whole TLS record holding a
/// ClientHello, as sing-box's `IndexTLSServerName` finds it.
pub(crate) fn index_server_name(payload: &[u8]) -> Option<ServerName> {
    if payload.len() < RECORD_HEADER_LEN || payload[0] != 22 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < RECORD_HEADER_LEN + record_len {
        return None;
    }
    let handshake = &payload[RECORD_HEADER_LEN..];
    // Type, length, version, random, session id length.
    if handshake.len() < 4 + 2 + 32 + 1 || handshake[0] != 1 {
        return None;
    }
    let handshake_len =
        (handshake[1] as usize) << 16 | (handshake[2] as usize) << 8 | handshake[3] as usize;
    if handshake.len() - 4 != handshake_len {
        return None;
    }
    let version = u16::from_be_bytes([handshake[4], handshake[5]]);
    if version & 0xfffc != 0x0300 && version != 0x0304 {
        return None;
    }
    let mut at = 4 + 2 + 32 + 1 + handshake[38] as usize;
    let suites_len = u16::from_be_bytes([*handshake.get(at)?, *handshake.get(at + 1)?]) as usize;
    at += 2 + suites_len;
    let compressions = *handshake.get(at)? as usize;
    at += 1 + compressions;
    let extensions_len =
        u16::from_be_bytes([*handshake.get(at)?, *handshake.get(at + 1)?]) as usize;
    at += 2;
    let extensions = handshake.get(at..at + extensions_len)?;
    let mut offset = 0;
    while offset + 4 <= extensions.len() {
        let kind = u16::from_be_bytes([extensions[offset], extensions[offset + 1]]);
        let len = u16::from_be_bytes([extensions[offset + 2], extensions[offset + 3]]) as usize;
        let body = extensions.get(offset + 4..offset + 4 + len)?;
        if kind == 0 {
            // A list length, a name type (a host name), the name's length.
            if body.len() < 5 || body[2] != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([body[3], body[4]]) as usize;
            let name = std::str::from_utf8(body.get(5..5 + name_len)?).ok()?;
            return Some(ServerName {
                index: RECORD_HEADER_LEN + at + offset + 4 + 5,
                name: name.to_string(),
            });
        }
        offset += 4 + len;
    }
    None
}

/// `hello` cut as `how` says: the pieces to write one after the other.
pub(crate) fn cut(hello: &[u8], how: TlsFragment) -> Option<Vec<Vec<u8>>> {
    let sni = index_server_name(hello)?;
    let first_label = sni.name.split('.').next().unwrap_or_default().len();
    if first_label == 0 {
        return None;
    }
    let at = sni.index + rand::thread_rng().gen_range(0..first_label);
    let pieces = [&hello[..at], &hello[at..]];
    match how {
        TlsFragment::Segments(_) => Some(pieces.iter().map(|p| p.to_vec()).collect()),
        TlsFragment::Records => {
            // Each piece of the handshake in a record of its own, with the
            // first record's type and version.
            let mut records = Vec::with_capacity(hello.len() + RECORD_HEADER_LEN);
            for (i, piece) in pieces.iter().enumerate() {
                let piece = if i == 0 {
                    &piece[RECORD_HEADER_LEN..]
                } else {
                    piece
                };
                records.extend_from_slice(&hello[..3]);
                records.extend_from_slice(&(piece.len() as u16).to_be_bytes());
                records.extend_from_slice(piece);
            }
            Some(vec![records])
        }
    }
}

/// A stream whose first write, a ClientHello, goes out cut.
pub(crate) struct FragmentStream<S> {
    inner: S,
    how: TlsFragment,
    first: bool,
    /// The pieces not written yet, and how much of the front one is.
    pending: VecDeque<Vec<u8>>,
    written: usize,
    /// The length of the write the pieces stand for.
    accepted: usize,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> FragmentStream<S> {
    pub(crate) fn new(inner: S, how: TlsFragment) -> Self {
        FragmentStream {
            inner,
            how,
            first: true,
            pending: VecDeque::new(),
            written: 0,
            accepted: 0,
            delay: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.first && !buf.is_empty() {
            this.first = false;
            if let Some(pieces) = cut(buf, this.how) {
                this.pending = pieces.into();
                this.accepted = buf.len();
            }
        }
        while let Some(piece) = this.pending.front() {
            if let Some(delay) = this.delay.as_mut() {
                futures::ready!(delay.as_mut().poll(cx));
                this.delay = None;
            }
            if this.written < piece.len() {
                let n = futures::ready!(
                    Pin::new(&mut this.inner).poll_write(cx, &piece[this.written..])
                )?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                this.written += n;
                continue;
            }
            // Each piece is flushed, to go out in a segment of its own.
            futures::ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
            this.pending.pop_front();
            this.written = 0;
            if let (false, TlsFragment::Segments(delay)) = (this.pending.is_empty(), this.how) {
                this.delay = Some(Box::pin(tokio::time::sleep(delay)));
            }
            if this.pending.is_empty() {
                return Poll::Ready(Ok(this.accepted));
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A ClientHello for `name`, as a client would send it.
    fn client_hello(name: &str) -> Vec<u8> {
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name.as_bytes());
        let mut extensions = Vec::new();
        // An extension before the name, to be skipped.
        extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0];
        handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn the_server_name_is_found() {
        let hello = client_hello("www.example.com");
        let sni = index_server_name(&hello).unwrap();
        assert_eq!(sni.name, "www.example.com");
        assert_eq!(&hello[sni.index..sni.index + 15], b"www.example.com");
        assert!(index_server_name(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(index_server_name(&hello[..hello.len() - 1]).is_none());
        // Nothing past the end, whatever the bytes.
        for i in 0..hello.len() {
            let mut bad = hello.clone();
            bad[i] ^= 0xa5;
            let _ = index_server_name(&bad);
        }
    }

    #[test]
    fn segments_are_the_hello_cut_in_the_first_label() {
        let hello = client_hello("www.example.com");
        let index = index_server_name(&hello).unwrap().index;
        for _ in 0..20 {
            let pieces = cut(&hello, TlsFragment::Segments(Duration::ZERO)).unwrap();
            assert_eq!(pieces.len(), 2);
            assert_eq!(pieces.concat(), hello);
            assert!((index..index + 3).contains(&pieces[0].len()));
        }
    }

    #[test]
    fn records_carry_the_handshake_in_two() {
        let hello = client_hello("www.example.com");
        let records = cut(&hello, TlsFragment::Records).unwrap().concat();
        assert_eq!(records.len(), hello.len() + RECORD_HEADER_LEN);
        let first_len = u16::from_be_bytes([records[3], records[4]]) as usize;
        let second = &records[RECORD_HEADER_LEN + first_len..];
        assert_eq!(&second[..3], &hello[..3]);
        let second_len = u16::from_be_bytes([second[3], second[4]]) as usize;
        assert_eq!(second.len(), RECORD_HEADER_LEN + second_len);
        let mut handshake = records[RECORD_HEADER_LEN..RECORD_HEADER_LEN + first_len].to_vec();
        handshake.extend_from_slice(&second[RECORD_HEADER_LEN..]);
        assert_eq!(handshake, hello[RECORD_HEADER_LEN..]);
    }

    #[tokio::test]
    async fn the_stream_writes_the_pieces_then_the_rest_as_is() {
        for how in [
            TlsFragment::Segments(Duration::from_millis(20)),
            TlsFragment::Records,
        ] {
            let (near, mut far) = tokio::io::duplex(1 << 16);
            let mut stream = FragmentStream::new(near, how);
            let hello = client_hello("example.com");
            let start = tokio::time::Instant::now();
            stream.write_all(&hello).await.unwrap();
            stream.write_all(b"after").await.unwrap();
            drop(stream);
            let mut got = Vec::new();
            far.read_to_end(&mut got).await.unwrap();
            assert!(got.ends_with(b"after"));
            match how {
                TlsFragment::Segments(delay) => {
                    assert_eq!(&got[..hello.len()], hello);
                    assert!(start.elapsed() >= delay);
                }
                TlsFragment::Records => assert_eq!(got.len(), hello.len() + 5 + 5),
            }
        }
        // What is not a ClientHello goes as it is.
        let (near, mut far) = tokio::io::duplex(1024);
        let mut stream = FragmentStream::new(near, TlsFragment::Records);
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        drop(stream);
        let mut got = Vec::new();
        far.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"GET / HTTP/1.1\r\n\r\n");
    }
}
