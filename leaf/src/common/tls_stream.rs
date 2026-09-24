//! A client TLS stream over rustls that can hand the transport over to XTLS
//! Vision's direct copy: reading or writing the raw transport once Vision
//! switches, which tokio-rustls cannot do.

use std::io::{self, ErrorKind, IoSlice, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::io::{acquire_buffer, release_buffer};
use crate::session::VisionState;

/// Size of the ciphertext buffer used for exact reads; holds any record.
const RX_SIZE: usize = 64 * 1024;

/// The parts of a rustls client connection the stream drives. Implemented for
/// rustls and for the REALITY fork of it.
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

// The connection methods live on the types the connection derefs to; calling
// them through `Deref` keeps these impls from resolving to themselves.
macro_rules! impl_tls_connection {
    ($conn:ty) => {
        impl TlsConnection for $conn {
            fn is_handshaking(&self) -> bool {
                std::ops::Deref::deref(self).is_handshaking()
            }
            fn wants_read(&self) -> bool {
                std::ops::Deref::deref(self).wants_read()
            }
            fn wants_write(&self) -> bool {
                std::ops::Deref::deref(self).wants_write()
            }
            fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
                std::ops::DerefMut::deref_mut(self).read_tls(rd)
            }
            fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
                std::ops::DerefMut::deref_mut(self).write_tls(wr)
            }
            fn process_new_packets(&mut self) -> io::Result<()> {
                std::ops::DerefMut::deref_mut(self)
                    .process_new_packets()
                    .map(|_| ())
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("TLS Error: {}", e)))
            }
            fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                std::ops::DerefMut::deref_mut(self).reader().read(buf)
            }
            fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize> {
                std::ops::DerefMut::deref_mut(self).writer().write(buf)
            }
            fn flush_plaintext(&mut self) -> io::Result<()> {
                std::ops::DerefMut::deref_mut(self).writer().flush()
            }
            fn send_close_notify(&mut self) {
                std::ops::DerefMut::deref_mut(self).send_close_notify()
            }
        }
    };
}

#[cfg(feature = "outbound-reality")]
impl_tls_connection!(reality_rustls::ClientConnection);
#[cfg(all(feature = "outbound-tls", feature = "rustls-tls"))]
impl_tls_connection!(tokio_rustls::rustls::ClientConnection);

pub struct ClientTlsStream<C, S> {
    conn: C,
    stream: S,
    vision: Option<VisionState>,
    read_raw: bool,
    write_raw: bool,
    // Ciphertext read from the transport but not yet handed to rustls:
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

/// Lets rustls read the transport directly, keeping the record tracker in
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

    // rustls hands over all queued records at once; pass them on as one writev.
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

impl<C: TlsConnection, S: AsyncRead + AsyncWrite + Unpin> ClientTlsStream<C, S> {
    /// Wraps a fresh client connection. With `vision`, the stream follows the
    /// Vision state of the session and advertises that it can switch to raw
    /// reads and writes.
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

    pub async fn handshake(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut progress = false;
            while self.conn.is_handshaking() {
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

                if self.conn.wants_read() {
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
            Poll::Ready(Ok(()))
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

    /// Hands buffered ciphertext to rustls and processes it.
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
        // otherwise rustls reads the transport itself, saving a copy. Either
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

impl<C, S> Drop for ClientTlsStream<C, S> {
    fn drop(&mut self) {
        if let Some(rx) = self.rx.take() {
            release_buffer(rx);
        }
    }
}

impl<C: TlsConnection, S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientTlsStream<C, S> {
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
            if let Ok(n) = this.conn.read_plaintext(buf.initialize_unfilled()) {
                if n > 0 {
                    buf.advance(n);
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
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

impl<C: TlsConnection, S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClientTlsStream<C, S> {
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
            // Drain what rustls already holds first, so a full send buffer
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
                // Nothing queued, yet rustls takes nothing (e.g. after
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

    // Calls through the trait must reach rustls, not recurse into themselves.
    #[cfg(all(feature = "outbound-tls", feature = "rustls-tls"))]
    #[test]
    fn test_tls_connection_impl_reaches_rustls() {
        use super::TlsConnection;
        use std::sync::Arc;
        use tokio_rustls::rustls::{ClientConfig, ClientConnection, RootCertStore};

        let config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut conn =
            ClientConnection::new(Arc::new(config), "example.com".try_into().unwrap()).unwrap();
        assert!(TlsConnection::is_handshaking(&conn));
        assert!(TlsConnection::wants_write(&conn)); // the ClientHello
        let mut out = vec![];
        assert!(TlsConnection::write_tls(&mut conn, &mut out).unwrap() > 0);
        assert_eq!(out[0], 0x16);
        TlsConnection::process_new_packets(&mut conn).unwrap();
        TlsConnection::send_close_notify(&mut conn);
    }

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
