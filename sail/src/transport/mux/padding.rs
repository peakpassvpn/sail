//! sing-mux padding: the first 16 writes each way of a padded connection
//! are framed as `length u16 | padding u16 | data | padding random bytes`,
//! and everything after goes as it is.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How many writes each way are padded.
const PADDED_FRAMES: usize = 16;
/// The most data one padded frame carries.
const MAX_FRAME_DATA: usize = u16::MAX as usize;

pub struct PaddingStream<S> {
    inner: S,
    /// Padded frames read so far.
    frames_read: usize,
    /// Header bytes of the frame being read.
    header: [u8; 4],
    header_len: usize,
    /// Data left in the frame being read, then its padding.
    data_left: usize,
    padding_left: usize,
    /// Padded frames written so far.
    frames_written: usize,
    /// A padded frame accepted but not yet all written.
    pending: BytesMut,
}

impl<S> PaddingStream<S> {
    pub fn new(inner: S) -> Self {
        PaddingStream {
            inner,
            frames_read: 0,
            header: [0; 4],
            header_len: 0,
            data_left: 0,
            padding_left: 0,
            frames_written: 0,
            pending: BytesMut::new(),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PaddingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if me.data_left > 0 {
                let want = me.data_left.min(buf.remaining());
                let mut limited = ReadBuf::new(buf.initialize_unfilled_to(want));
                ready!(Pin::new(&mut me.inner).poll_read(cx, &mut limited))?;
                let n = limited.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                buf.advance(n);
                me.data_left -= n;
                return Poll::Ready(Ok(()));
            }
            if me.padding_left > 0 {
                let mut scratch = [0u8; 1024];
                let want = me.padding_left.min(scratch.len());
                let mut limited = ReadBuf::new(&mut scratch[..want]);
                ready!(Pin::new(&mut me.inner).poll_read(cx, &mut limited))?;
                let n = limited.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                me.padding_left -= n;
                continue;
            }
            if me.frames_read >= PADDED_FRAMES {
                return Pin::new(&mut me.inner).poll_read(cx, buf);
            }
            // A frame header, possibly over several reads.
            let mut limited = ReadBuf::new(&mut me.header[me.header_len..]);
            ready!(Pin::new(&mut me.inner).poll_read(cx, &mut limited))?;
            let n = limited.filled().len();
            if n == 0 {
                if me.header_len == 0 {
                    // A clean end between frames.
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            me.header_len += n;
            if me.header_len < me.header.len() {
                continue;
            }
            me.header_len = 0;
            me.frames_read += 1;
            me.data_left = u16::from_be_bytes([me.header[0], me.header[1]]) as usize;
            me.padding_left = u16::from_be_bytes([me.header[2], me.header[3]]) as usize;
            // Then its data; an empty frame is skipped rather than read as
            // the end.
        }
    }
}

impl<S: AsyncWrite + Unpin> PaddingStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        ready!(me.poll_drain(cx))?;
        if me.frames_written >= PADDED_FRAMES || buf.is_empty() {
            return Pin::new(&mut me.inner).poll_write(cx, buf);
        }
        let data = &buf[..buf.len().min(MAX_FRAME_DATA)];
        let padding: usize = rand::thread_rng().gen_range(256..768);
        me.pending.reserve(4 + data.len() + padding);
        me.pending.put_u16(data.len() as u16);
        me.pending.put_u16(padding as u16);
        me.pending.put_slice(data);
        me.pending.put_bytes(0, padding);
        me.frames_written += 1;
        // Accepted: the frame goes out on the next write or flush if not now.
        if let Poll::Ready(Err(e)) = me.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_drain(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_drain(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn padded_writes_read_back_and_turn_plain() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (a, b) = tokio::io::duplex(1 << 20);
                let mut writer = PaddingStream::new(a);
                let mut expected = Vec::new();
                for i in 0..20u8 {
                    let chunk = vec![i; 100 + i as usize];
                    writer.write_all(&chunk).await.unwrap();
                    expected.extend_from_slice(&chunk);
                }
                writer.shutdown().await.unwrap();
                drop(writer);

                // On the wire: 16 frames, each with 256..768 padding bytes.
                let mut raw = Vec::new();
                let (c, d) = tokio::io::duplex(1 << 20);
                let mut writer = PaddingStream::new(c);
                writer.write_all(b"xy").await.unwrap();
                writer.shutdown().await.unwrap();
                drop(writer);
                let mut d = d;
                d.read_to_end(&mut raw).await.unwrap();
                assert_eq!(&raw[..2], &[0, 2]);
                let padding = u16::from_be_bytes([raw[2], raw[3]]) as usize;
                assert!((256..768).contains(&padding));
                assert_eq!(raw.len(), 4 + 2 + padding);

                let mut reader = PaddingStream::new(b);
                let mut got = Vec::new();
                reader.read_to_end(&mut got).await.unwrap();
                assert_eq!(got, expected);
                assert_eq!(reader.frames_read, PADDED_FRAMES);
            });
    }
}
