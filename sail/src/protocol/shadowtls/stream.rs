//! The data phase: each side's data in application-data records whose
//! first four bytes chain an HMAC over what that side has sent.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, BytesMut};
use hmac::Mac;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    tag, HmacSha1, SiteRecords, ALERT, APPLICATION_DATA, HEADER_LEN, MAX_PAYLOAD, TAGGED_HEADER_LEN,
};

/// Appends `data` to `out` as one record, chaining `add` over it.
pub(super) fn frame(add: &mut HmacSha1, data: &[u8], out: &mut Vec<u8>) {
    add.update(data);
    let tag = tag(add);
    add.update(&tag);
    out.extend_from_slice(&[APPLICATION_DATA, 3, 3]);
    out.extend_from_slice(&((data.len() + tag.len()) as u16).to_be_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(data);
}

/// A connection after the handshake, from one side.
pub struct VerifiedStream<S> {
    inner: S,
    /// Chains what this side sends.
    add: HmacSha1,
    /// Chains what the other side sends.
    verify: HmacSha1,
    /// The client's, for the site's records the server relayed before it
    /// stopped relaying them: skipped while they carry its marks.
    site: Option<SiteRecords>,
    /// Read, not yet a whole record.
    rx: BytesMut,
    /// Data of a record, not yet read out.
    plain: BytesMut,
    eof: bool,
    /// Records not yet written: tx[tx_pos..].
    tx: Vec<u8>,
    tx_pos: usize,
}

impl<S> VerifiedStream<S> {
    /// Over `inner`, of which `rx` is read already. `plain` is data of the
    /// other side's that was read with the handshake.
    pub(super) fn new(
        inner: S,
        add: HmacSha1,
        verify: HmacSha1,
        site: Option<SiteRecords>,
        rx: BytesMut,
        plain: BytesMut,
    ) -> Self {
        Self {
            inner,
            add,
            verify,
            site,
            rx,
            plain,
            eof: false,
            tx: Vec::new(),
            tx_pos: 0,
        }
    }

    /// The data of `record`, empty for one to skip; `None` at the other
    /// side's alert, its close.
    fn open(&mut self, mut record: BytesMut) -> io::Result<Option<BytesMut>> {
        match record[0] {
            ALERT => Ok(None),
            APPLICATION_DATA => {
                if let Some(site) = &mut self.site {
                    if record[1..3] == [3, 3] && site.check(&record) {
                        return Ok(Some(BytesMut::new()));
                    }
                    self.site = None;
                }
                if record.len() < TAGGED_HEADER_LEN || record[1..3] != [3, 3] {
                    return Err(invalid("a data record too short for its HMAC"));
                }
                self.verify.update(&record[TAGGED_HEADER_LEN..]);
                let tag = tag(&self.verify);
                if tag != record[HEADER_LEN..TAGGED_HEADER_LEN] {
                    return Err(invalid("a data record failed its HMAC"));
                }
                self.verify.update(&tag);
                Ok(Some(record.split_off(TAGGED_HEADER_LEN)))
            }
            other => Err(invalid(&format!("unexpected TLS record type {}", other))),
        }
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("shadowtls: {}", what))
}

impl<S: AsyncWrite + Unpin> VerifiedStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.tx_pos < self.tx.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.tx[self.tx_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.tx_pos += n;
        }
        self.tx.clear();
        self.tx_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VerifiedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.plain.is_empty() {
                let n = this.plain.len().min(buf.remaining());
                buf.put_slice(&this.plain[..n]);
                this.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.rx.len() >= HEADER_LEN {
                let len = HEADER_LEN + u16::from_be_bytes([this.rx[3], this.rx[4]]) as usize;
                if this.rx.len() >= len {
                    let record = this.rx.split_to(len);
                    match this.open(record)? {
                        Some(data) => this.plain = data,
                        None => this.eof = true,
                    }
                    continue;
                }
                this.rx.reserve(len - this.rx.len());
            } else {
                this.rx.reserve(MAX_PAYLOAD);
            }
            let spare = this.rx.spare_capacity_mut();
            let mut read = ReadBuf::uninit(spare);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let n = read.filled().len();
            if n == 0 {
                if this.rx.is_empty() {
                    this.eof = true;
                    continue;
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            // SAFETY: `n` bytes of the spare capacity were just filled.
            unsafe { this.rx.set_len(this.rx.len() + n) };
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VerifiedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_PAYLOAD);
        frame(&mut this.add, &buf[..n], &mut this.tx);
        // Taken: what the transport does not take now goes out with the
        // next write or flush.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::data_hmac;
    use super::*;

    fn pair() -> (
        VerifiedStream<tokio::io::DuplexStream>,
        VerifiedStream<tokio::io::DuplexStream>,
    ) {
        let random = [5u8; 32];
        let (a, b) = tokio::io::duplex(1024);
        let client = VerifiedStream::new(
            a,
            data_hmac(b"pw", &random, b"C"),
            data_hmac(b"pw", &random, b"S"),
            None,
            BytesMut::new(),
            BytesMut::new(),
        );
        let server = VerifiedStream::new(
            b,
            data_hmac(b"pw", &random, b"S"),
            data_hmac(b"pw", &random, b"C"),
            None,
            BytesMut::new(),
            BytesMut::new(),
        );
        (client, server)
    }

    #[tokio::test]
    async fn test_both_ways_in_records_of_at_most_16k() {
        let (mut client, mut server) = pair();
        let big: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        let sent = big.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&sent).await.unwrap();
            client.flush().await.unwrap();
            let mut back = [0u8; 2];
            client.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"ok");
            client.shutdown().await.unwrap();
        });
        let mut got = vec![0u8; big.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);
        server.write_all(b"ok").await.unwrap();
        server.flush().await.unwrap();
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_a_tampered_record_is_an_error() {
        let random = [5u8; 32];
        let mut add = data_hmac(b"pw", &random, b"C");
        let mut records = Vec::new();
        frame(&mut add, b"one", &mut records);
        frame(&mut add, b"two", &mut records);
        let n = records.len();
        records[n - 1] ^= 1;
        let mut server = VerifiedStream::new(
            &records[..],
            data_hmac(b"pw", &random, b"S"),
            data_hmac(b"pw", &random, b"C"),
            None,
            BytesMut::new(),
            BytesMut::new(),
        );
        let mut one = [0u8; 3];
        server.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"one");
        let err = server.read(&mut one).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
