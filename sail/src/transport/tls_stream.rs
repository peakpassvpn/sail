//! A TLS stream that can hand the transport over to XTLS Vision's direct copy:
//! reading or writing the raw transport once Vision switches. It drives a
//! BoringSSL connection without IO of its own.

use std::io::{self, ErrorKind, IoSlice, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::net::relay::{acquire_buffer, release_buffer};
use crate::transport::vision::VisionState;

/// Size of the ciphertext buffer used for exact reads; holds any record.
const RX_SIZE: usize = 64 * 1024;

/// The parts of a TLS connection the stream drives, in the shape of a rustls
/// connection.
pub trait TlsConnection: Unpin {
    fn is_handshaking(&self) -> bool;
    fn wants_read(&self) -> bool;
    fn wants_write(&self) -> bool;
    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize>;
    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize>;
    fn process_new_packets(&mut self) -> io::Result<()>;
    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn flush_plaintext(&mut self) -> io::Result<()>;
    fn send_close_notify(&mut self);
}

pub struct TlsStream<C, S> {
    conn: C,
    stream: S,
    vision: Option<VisionState>,
    read_raw: bool,
    write_raw: bool,
    // Ciphertext read from the transport but not yet handed to the connection:
    // rx[rx_pos..rx_len]. Borrowed from the relay buffer pool while in use.
    rx: Option<Box<[u8]>>,
    rx_pos: usize,
    rx_len: usize,
    records: RecordTracker,
}

/// Follows TLS record boundaries in the bytes read from the transport, so
/// reads can stop exactly at the end of a record: first the 5-byte header,
/// then the body length it announces.
#[derive(Default)]
struct RecordTracker {
    header: [u8; 5],
    header_len: usize,
    body_left: usize,
}

impl RecordTracker {
    /// Most bytes that can be read without crossing a record boundary.
    fn limit(&self) -> usize {
        if self.body_left > 0 {
            self.body_left
        } else {
            self.header.len() - self.header_len
        }
    }

    fn consume(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.body_left > 0 {
                let n = self.body_left.min(data.len());
                self.body_left -= n;
                data = &data[n..];
            } else {
                self.header[self.header_len] = data[0];
                self.header_len += 1;
                data = &data[1..];
                if self.header_len == self.header.len() {
                    self.body_left = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                    self.header_len = 0;
                }
            }
        }
    }
}

struct TlsBridge<'a, 'b, S> {
    stream: Pin<&'a mut S>,
    cx: &'a mut Context<'b>,
}

/// Lets the connection read the transport directly, keeping the record tracker in
/// step with every byte it takes.
struct TrackingReader<'a, 'b, S> {
    stream: Pin<&'a mut S>,
    cx: &'a mut Context<'b>,
    records: &'a mut RecordTracker,
}

impl<S: AsyncRead> Read for TrackingReader<'_, '_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut read_buf = ReadBuf::new(buf);
        match self.stream.as_mut().poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                self.records.consume(read_buf.filled());
                Ok(read_buf.filled().len())
            }
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
}

impl<S: AsyncRead> Read for TlsBridge<'_, '_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut read_buf = ReadBuf::new(buf);
        match self.stream.as_mut().poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
}

impl<S: AsyncWrite> Write for TlsBridge<'_, '_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream.as_mut().poll_write(self.cx, buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }

    // The connection hands over all queued records at once; pass them on as one writev.
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match self.stream.as_mut().poll_write_vectored(self.cx, bufs) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.stream.as_mut().poll_flush(self.cx) {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
}

impl<C: TlsConnection, S: AsyncRead + AsyncWrite + Unpin> TlsStream<C, S> {
    /// Wraps a fresh connection. With `vision`, the stream follows the Vision
    /// state of the session and advertises that it can switch to raw reads and
    /// writes.
    pub fn new(conn: C, stream: S, vision: Option<VisionState>) -> Self {
        if let Some(vision) = &vision {
            vision.set_raw_capable();
        }
        Self {
            conn,
            stream,
            vision,
            read_raw: false,
            write_raw: false,
            rx: None,
            rx_pos: 0,
            rx_len: 0,
            records: RecordTracker::default(),
        }
    }

    /// The TLS connection, for what the handshake negotiated.
    pub fn conn(&self) -> &C {
        &self.conn
    }

    pub async fn handshake(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut progress = false;
            // The last flight (the client's Finished) is written too: the peer
            // may be waiting for it before it sends anything.
            while self.conn.is_handshaking() || self.conn.wants_write() {
                while self.conn.wants_write() {
                    let mut bridge = TlsBridge {
                        stream: Pin::new(&mut self.stream),
                        cx,
                    };
                    match self.conn.write_tls(&mut bridge) {
                        Ok(n) if n > 0 => {
                            progress = true;
                        }
                        Ok(_) => {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::WriteZero,
                                "connection closed during TLS handshake",
                            )));
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }

                if self.conn.is_handshaking() && self.conn.wants_read() {
                    match self.pump_read(cx) {
                        Ok(false) => {}
                        Ok(true) => progress = true,
                        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "connection closed during TLS handshake",
                            )));
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }

                if !progress {
                    return Poll::Pending;
                }
                progress = false;
            }
            Pin::new(&mut self.stream).poll_flush(cx)
        })
        .await
    }

    /// Whether reads must stop at TLS record boundaries: while Vision is
    /// pending the server may switch to raw data right after any record.
    fn exact(&self) -> bool {
        self.vision.as_ref().is_some_and(|v| v.is_pending())
    }

    fn release_rx(&mut self) {
        if let Some(rx) = self.rx.take() {
            release_buffer(rx);
        }
        self.rx_pos = 0;
        self.rx_len = 0;
    }

    /// Reads ciphertext from the transport into `rx`, up to the end of the
    /// current record (the header, then the body, one read each). Returns
    /// Ok(false) if it would block.
    fn fill_rx(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        debug_assert_eq!(self.rx_pos, self.rx_len);
        let want = self.records.limit();
        if self.rx.is_none() {
            self.rx = Some(acquire_buffer(RX_SIZE)?);
        }
        let rx = self.rx.as_deref_mut().expect("buffer acquired above");
        let mut read_buf = ReadBuf::new(&mut rx[..want]);
        match Pin::new(&mut self.stream).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "EOF"));
                }
                self.records.consume(&rx[..n]);
                self.rx_pos = 0;
                self.rx_len = n;
                Ok(true)
            }
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => {
                // Nothing buffered while idle.
                self.release_rx();
                Ok(false)
            }
        }
    }

    /// Hands buffered ciphertext to the connection and processes it.
    fn feed_rx(&mut self) -> io::Result<()> {
        let rx = self.rx.as_deref().expect("rx holds unread ciphertext");
        let mut data = &rx[self.rx_pos..self.rx_len];
        let n = self.conn.read_tls(&mut data)?;
        if n == 0 {
            // close_notify received; whatever follows is not TLS data.
            self.rx_pos = self.rx_len;
        } else {
            self.rx_pos += n;
        }
        self.conn.process_new_packets()
    }

    /// Reads TLS data from the transport (or the ciphertext buffer) and
    /// processes it. Returns Ok(false) if the transport would block, and an
    /// UnexpectedEof error at EOF.
    fn pump_read(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        if !self.conn.wants_read() {
            return Ok(false);
        }
        // Exact reads go through `rx` so they can stop at a record boundary;
        // otherwise the connection reads the transport itself, saving a copy. Either
        // way the tracker follows every record, so exact reads stay aligned
        // once Vision starts later in the connection.
        if self.exact() || self.rx_pos < self.rx_len {
            if self.rx_pos == self.rx_len && !self.fill_rx(cx)? {
                return Ok(false);
            }
            self.feed_rx()?;
            return Ok(true);
        }
        let mut reader = TrackingReader {
            stream: Pin::new(&mut self.stream),
            cx,
            records: &mut self.records,
        };
        match self.conn.read_tls(&mut reader) {
            Ok(0) => Err(io::Error::new(ErrorKind::UnexpectedEof, "EOF")),
            Ok(_) => {
                self.conn.process_new_packets()?;
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Writes queued TLS data to the transport. Returns false if the transport
    /// would block (the waker is registered), true once everything is written.
    fn pump_write(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        while self.conn.wants_write() {
            let mut bridge = TlsBridge {
                stream: Pin::new(&mut self.stream),
                cx,
            };
            match self.conn.write_tls(&mut bridge) {
                Ok(0) => {
                    return Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "transport accepted no bytes",
                    ))
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    /// Switches writes to the raw transport once VLESS has sent
    /// PaddingDirect, after every TLS record queued before it is written.
    /// Returns Ok(false) if those records are still being written.
    fn poll_switch_write_raw(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        if !self.write_raw && self.vision.as_ref().is_some_and(|v| v.is_write_direct()) {
            self.conn.flush_plaintext()?;
            if !self.pump_write(cx)? {
                return Ok(false);
            }
            self.write_raw = true;
        }
        Ok(true)
    }
}

impl<C, S> Drop for TlsStream<C, S> {
    fn drop(&mut self) {
        if let Some(rx) = self.rx.take() {
            release_buffer(rx);
        }
    }
}

impl<C: TlsConnection, S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<C, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.read_raw && this.vision.as_ref().is_some_and(|v| v.is_direct_copy()) {
            // Exact reads stopped at the last TLS record, so nothing past it
            // has been buffered.
            debug_assert_eq!(this.rx_pos, this.rx_len);
            this.release_rx();
            this.read_raw = true;
        }
        if this.read_raw {
            return Pin::new(&mut this.stream).poll_read(cx, buf);
        }

        // Ensure any pending writes are flushed to network
        if !this.write_raw {
            let _ = this.pump_write(cx)?;
        }

        let start = buf.filled().len();
        loop {
            match this.conn.read_plaintext(buf.initialize_unfilled()) {
                Ok(n) if n > 0 => {
                    buf.advance(n);
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                // BoringSSL reports bad records here rather than while
                // processing them.
                Err(e) => return Poll::Ready(Err(e)),
            }

            // In exact mode stop after one record, so the VLESS layer sees a
            // Vision switch before anything past it is read. Otherwise keep
            // decrypting records while the transport has data.
            let delivered = buf.filled().len() > start;
            if delivered && this.exact() {
                return Poll::Ready(Ok(()));
            }

            if this.conn.wants_read() {
                if !this.pump_read(cx)? {
                    // Return what we have rather than wait for more.
                    return if delivered {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending // Awaits socket read wake
                    };
                }
            } else if this.conn.wants_write() && !this.write_raw {
                let _ = this.pump_write(cx)?;
                // wait for writes to clear, though want_read was false so it might still be pending
                return Poll::Pending;
            } else {
                // Reached EOF and cleanly terminated TLS?
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<C: TlsConnection, S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<C, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.poll_switch_write_raw(cx)? {
            return Poll::Pending;
        }
        if this.write_raw {
            return Pin::new(&mut this.stream).poll_write(cx, buf);
        }
        let mut pos = 0;
        loop {
            // Drain what the connection already holds first, so a full send buffer
            // turns into Pending (backpressure) instead of a zero-length write.
            if !this.pump_write(cx)? {
                return if pos == 0 {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(pos))
                };
            }
            if pos == buf.len() {
                return Poll::Ready(Ok(pos));
            }
            let n = this.conn.write_plaintext(&buf[pos..])?;
            if n == 0 {
                // Nothing queued, yet the connection takes nothing (e.g. after
                // close_notify).
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "tls connection accepts no more data",
                )));
            }
            pos += n;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.poll_switch_write_raw(cx)? {
            return Poll::Pending;
        }
        if !this.write_raw {
            this.conn.flush_plaintext()?;
            if !this.pump_write(cx)? {
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.poll_switch_write_raw(cx)? {
            return Poll::Pending;
        }
        // After the switch the transport carries raw data; a close_notify
        // record would corrupt it.
        if !this.write_raw {
            // No-op after the first call.
            this.conn.send_close_notify();
            if !this.pump_write(cx)? {
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::RecordTracker;

    fn record(len: usize) -> Vec<u8> {
        let mut r = vec![0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
        r.resize(5 + len, 0xaa);
        r
    }

    #[test]
    fn test_record_tracker_byte_by_byte() {
        let mut t = RecordTracker::default();
        let data = [record(7), record(0), record(2)].concat();
        let mut limits = vec![];
        for b in &data {
            limits.push(t.limit());
            t.consume(std::slice::from_ref(b));
        }
        assert_eq!(t.limit(), 5);
        // Header countdown, then the body countdown.
        assert_eq!(&limits[..12], &[5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1]);
        // An empty record goes straight to the next header.
        assert_eq!(&limits[12..17], &[5, 4, 3, 2, 1]);
    }

    #[test]
    fn test_record_tracker_limit_never_crosses_boundary() {
        let mut t = RecordTracker::default();
        let data = [record(16384), record(1), record(100)].concat();
        let mut pos = 0;
        let mut ends = vec![];
        while pos < data.len() {
            let n = t.limit().min(data.len() - pos);
            t.consume(&data[pos..pos + n]);
            pos += n;
            ends.push(pos);
        }
        // Each read ends exactly at a header or body end.
        assert_eq!(ends, vec![5, 16389, 16394, 16395, 16400, 16500]);
    }

    #[test]
    fn test_record_tracker_resumes_after_bulk_reads() {
        // Bulk reads that end mid-record still leave the tracker aligned.
        let mut t = RecordTracker::default();
        let data = [record(100), record(50)].concat();
        t.consume(&data[..107]);
        assert_eq!(t.limit(), 3); // rest of the second header
        t.consume(&data[107..110]);
        assert_eq!(t.limit(), 50);
    }
}
