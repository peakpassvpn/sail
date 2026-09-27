use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::{timeout_at, Instant};

use crate::session::SniffedProtocol;

use super::{dns, http, misc, tls, Protocols, Sniff, Sniffed, MAX_SNIFF_LEN};

/// What the stream protocols among `protocols` make of the first bytes of a
/// connection, `buf`.
pub fn sniff_stream(protocols: Protocols, buf: &[u8]) -> Sniffed {
    let mut more = false;
    for protocol in protocols.stream().iter() {
        let sniff = match protocol {
            SniffedProtocol::Tls => tls::sniff(buf),
            SniffedProtocol::Http => http::sniff(buf),
            SniffedProtocol::Dns => dns::stream_query(buf),
            SniffedProtocol::Bittorrent => misc::bittorrent_stream(buf),
            _ => Sniff::NotMatch,
        };
        match sniff {
            Sniff::Found(domain) => return Sniffed::Found(protocol, domain),
            Sniff::NeedMore => more = true,
            Sniff::NotMatch => {}
        }
    }
    if more {
        Sniffed::NeedMore
    } else {
        Sniffed::NotMatch
    }
}

/// A stream whose first bytes are read looking for its protocol, and then
/// read again by whoever reads the stream.
pub struct SniffingStream<T> {
    inner: T,
    buf: BytesMut,
    /// The peer has closed its side: nothing more will come to sniff.
    eof: bool,
}

impl<T> SniffingStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: T) -> Self {
        SniffingStream {
            inner,
            buf: BytesMut::with_capacity(2 * 1024),
            eof: false,
        }
    }

    /// Looks for `protocols` in the first bytes, reading more for at most
    /// `wait` while one of them may yet be found. A second sniff, for other
    /// protocols, looks at what the first read before it reads more.
    pub async fn sniff(
        &mut self,
        protocols: Protocols,
        wait: Duration,
    ) -> io::Result<Option<(SniffedProtocol, Option<String>)>> {
        let deadline = Instant::now() + wait;
        loop {
            if !self.buf.is_empty() {
                match sniff_stream(protocols, &self.buf) {
                    Sniffed::Found(protocol, domain) => return Ok(Some((protocol, domain))),
                    Sniffed::NotMatch => return Ok(None),
                    Sniffed::NeedMore => {}
                }
            }
            let room = MAX_SNIFF_LEN.saturating_sub(self.buf.len());
            if self.eof || room == 0 {
                return Ok(None);
            }
            let mut room = (&mut self.buf).limit(room);
            match timeout_at(deadline, self.inner.read_buf(&mut room)).await {
                Ok(Ok(0)) => self.eof = true,
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(None),
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SniffingStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.buf.is_empty() {
            let to_read = min(buf.remaining(), self.buf.len());
            let for_read = self.buf.split_to(to_read);
            buf.put_slice(&for_read[..to_read]);
            Poll::Ready(Ok(()))
        } else {
            AsyncRead::poll_read(Pin::new(&mut self.inner), cx, buf)
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SniffingStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write_vectored(Pin::new(&mut self.inner), cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn what_was_read_is_read_again() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_all(&request[..10]).await.unwrap();
        let mut stream = SniffingStream::new(server);
        let wait = Duration::from_millis(300);
        let sniff = tokio::spawn(async move {
            let found = stream.sniff(Protocols::ALL, wait).await.unwrap();
            (found, stream)
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        client.write_all(&request[10..]).await.unwrap();
        let (found, mut stream) = sniff.await.unwrap();
        assert_eq!(
            found,
            Some((SniffedProtocol::Http, Some("example.com".into())))
        );
        client.shutdown().await.unwrap();
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.unwrap();
        assert_eq!(read, request);
    }

    #[tokio::test]
    async fn a_second_sniff_looks_again() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(b"\x13BitTorrent protocol").await.unwrap();
        let mut stream = SniffingStream::new(server);
        let wait = Duration::from_millis(50);
        let tls = Protocols::NONE.with(SniffedProtocol::Tls);
        assert_eq!(stream.sniff(tls, wait).await.unwrap(), None);
        assert_eq!(
            stream.sniff(Protocols::ALL, wait).await.unwrap(),
            Some((SniffedProtocol::Bittorrent, None))
        );
    }

    #[tokio::test]
    async fn a_silent_client_is_waited_for_no_longer_than_the_timeout() {
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(b"GET / HT").await.unwrap();
        let mut stream = SniffingStream::new(server);
        let start = Instant::now();
        let wait = Duration::from_millis(100);
        assert_eq!(stream.sniff(Protocols::ALL, wait).await.unwrap(), None);
        assert!(start.elapsed() >= wait);
        assert!(start.elapsed() < wait * 10);
    }

    #[tokio::test]
    async fn no_more_than_the_limit_is_read() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut request = b"GET / HTTP/1.1\r\n".to_vec();
        request.resize(MAX_SNIFF_LEN + 1000, b'a');
        client.write_all(&request).await.unwrap();
        let mut stream = SniffingStream::new(server);
        let wait = Duration::from_secs(5);
        assert_eq!(stream.sniff(Protocols::ALL, wait).await.unwrap(), None);
        assert_eq!(stream.buf.len(), MAX_SNIFF_LEN);
    }
}
