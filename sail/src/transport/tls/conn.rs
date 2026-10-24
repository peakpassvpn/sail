//! A BoringSSL connection driven without IO, in the shape of a rustls
//! connection, so [`TlsStream`](crate::transport::tls_stream::TlsStream) can
//! run it and hand the transport over to XTLS Vision.
//!
//! BoringSSL reads and writes ciphertext through [`MemIo`]: the stream puts
//! what it reads from the transport there and takes what BoringSSL wrote.

use std::io::{self, ErrorKind, Read, Write};

use btls::ssl::{ErrorCode, Ssl, SslStream};

use crate::net::relay::{acquire_buffer, release_buffer};
use crate::transport::tls_stream::TlsConnection;

/// One TLS record of any size, ciphertext.
const RECORD: usize = 5 + 16384 + 2048;

/// The most records one read from the transport takes. Reading one record
/// at a time, a bulk download made a system call for every 18 KB, sing-box
/// one for every 33-63 KB. Four, measured 2026-10-24 (Trojan through TUN,
/// mobile profile, 2 GiB, 3 rounds, against one): download CPU seconds a
/// GiB 2.19 to 1.94, its rate 3917 to 4412 Mbit/s (2.72 to 2.55 with two
/// workers). Four is a judgment beside the smallest profile's relay buffer
/// (64 KiB); more was not measured. The buffer grows only while reads fill it, as a relay's
/// does.
const RX_RECORDS: usize = 4;

/// Plaintext taken per write: one full record.
const MAX_PLAINTEXT: usize = 16384;

/// Ciphertext between the stream and BoringSSL. Both directions hold memory
/// only while they have data.
struct MemIo {
    // Read from the transport, not yet taken by BoringSSL: rx[rx_pos..rx_len].
    rx: Option<Box<[u8]>>,
    rx_pos: usize,
    rx_len: usize,
    // Records the next buffer holds: 1 to RX_RECORDS.
    rx_records: usize,
    // Written by BoringSSL, not yet written to the transport: tx[tx_pos..].
    tx: Vec<u8>,
    tx_pos: usize,
}

impl Default for MemIo {
    fn default() -> Self {
        Self {
            rx: None,
            rx_pos: 0,
            rx_len: 0,
            rx_records: 1,
            tx: Vec::new(),
            tx_pos: 0,
        }
    }
}

impl MemIo {
    fn rx_space(&self) -> usize {
        match &self.rx {
            Some(rx) => rx.len() - (self.rx_len - self.rx_pos),
            None => RECORD * self.rx_records,
        }
    }

    fn fill_from(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        if self.rx.is_none() {
            self.rx = Some(acquire_buffer(RECORD * self.rx_records)?);
        }
        let rx = self.rx.as_deref_mut().expect("buffer acquired above");
        if self.rx_pos > 0 {
            rx.copy_within(self.rx_pos..self.rx_len, 0);
            self.rx_len -= self.rx_pos;
            self.rx_pos = 0;
        }
        let space = rx.len() - self.rx_len;
        let read = rd.read(&mut rx[self.rx_len..]);
        if let Ok(n) = read {
            self.rx_len += n;
            // The next buffer: twice as large after a read that filled this
            // one, half after one that took a quarter of it or less.
            if n == space && self.rx_records < RX_RECORDS {
                self.rx_records *= 2;
            } else if n * 4 <= space && self.rx_records > 1 {
                self.rx_records /= 2;
            }
        }
        // Nothing buffered while idle.
        if self.rx_len == 0 {
            self.release_rx();
        }
        read
    }

    fn release_rx(&mut self) {
        if let Some(rx) = self.rx.take() {
            release_buffer(rx);
        }
        self.rx_pos = 0;
        self.rx_len = 0;
    }

    fn has_tx(&self) -> bool {
        self.tx_pos < self.tx.len()
    }

    fn drain_to(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        let n = wr.write(&self.tx[self.tx_pos..])?;
        self.tx_pos += n;
        if !self.has_tx() {
            // Idle connections keep no write buffer.
            self.tx = Vec::new();
            self.tx_pos = 0;
        }
        Ok(n)
    }
}

impl Read for MemIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rx_pos == self.rx_len {
            return Err(ErrorKind::WouldBlock.into());
        }
        let rx = self.rx.as_deref().expect("rx holds unread ciphertext");
        let n = buf.len().min(self.rx_len - self.rx_pos);
        buf[..n].copy_from_slice(&rx[self.rx_pos..self.rx_pos + n]);
        self.rx_pos += n;
        if self.rx_pos == self.rx_len {
            self.release_rx();
        }
        Ok(n)
    }
}

impl Write for MemIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // What the transport took goes before the buffer would grow: after
        // a partial write, growing copied it along with the rest, and kept
        // it until the buffer drained.
        if self.tx_pos > 0 && self.tx.len() + buf.len() > self.tx.capacity() {
            self.tx.drain(..self.tx_pos);
            self.tx_pos = 0;
        }
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for MemIo {
    fn drop(&mut self) {
        self.release_rx();
    }
}

/// A client or server TLS connection over BoringSSL.
pub struct BoringConnection {
    ssl: SslStream<MemIo>,
    handshaking: bool,
    // close_notify received: no more TLS data will be read.
    peer_closed: bool,
    close_sent: bool,
}

impl BoringConnection {
    /// A client connection. Its ClientHello is ready to be written.
    pub fn client(mut ssl: Ssl) -> io::Result<Self> {
        ssl.set_connect_state();
        let mut conn = Self::new(ssl)?;
        conn.drive_handshake()?;
        Ok(conn)
    }

    /// A server connection, waiting for the ClientHello.
    pub fn server(mut ssl: Ssl) -> io::Result<Self> {
        ssl.set_accept_state();
        Self::new(ssl)
    }

    fn new(ssl: Ssl) -> io::Result<Self> {
        // BoringSSL frees the configuration the SSL copied from its context
        // (its certificate, ALPS settings, verify parameters, ...) once the
        // handshake is done, instead of holding it for the connection's
        // life. Nothing reads or changes it after the handshake, and a
        // client never renegotiates, which would keep it.
        use foreign_types::ForeignType;
        // SAFETY: `ssl` is a live SSL that no handshake has used yet.
        unsafe { btls_sys::SSL_set_shed_handshake_config(ssl.as_ptr(), 1) };
        Ok(Self {
            ssl: SslStream::new(ssl, MemIo::default()).map_err(io::Error::other)?,
            handshaking: true,
            peer_closed: false,
            close_sent: false,
        })
    }

    pub fn ssl(&self) -> &btls::ssl::SslRef {
        self.ssl.ssl()
    }

    fn drive_handshake(&mut self) -> io::Result<()> {
        match self.ssl.do_handshake() {
            Ok(()) => {
                self.handshaking = false;
                Ok(())
            }
            Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                Ok(())
            }
            Err(e) => Err(match super::options::pin_failure(self.ssl.ssl()) {
                // BoringSSL's error says no more than that verification failed.
                Some(why) => io::Error::new(ErrorKind::InvalidData, format!("TLS Error: {}", why)),
                None => tls_error(e),
            }),
        }
    }
}

fn tls_error(e: btls::ssl::Error) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, format!("TLS Error: {}", e))
}

impl TlsConnection for BoringConnection {
    fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    fn wants_read(&self) -> bool {
        !self.peer_closed && self.ssl.get_ref().rx_space() > 0
    }

    fn wants_write(&self) -> bool {
        self.ssl.get_ref().has_tx()
    }

    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        self.ssl.get_mut().fill_from(rd)
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        self.ssl.get_mut().drain_to(wr)
    }

    fn process_new_packets(&mut self) -> io::Result<()> {
        // After the handshake BoringSSL processes records as they are read.
        if self.handshaking {
            self.drive_handshake()?;
        }
        Ok(())
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.peer_closed {
            return Ok(0);
        }
        match self.ssl.ssl_read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                self.peer_closed = true;
                Ok(0)
            }
            Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                Err(ErrorKind::WouldBlock.into())
            }
            Err(e) => Err(tls_error(e)),
        }
    }

    fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize> {
        let buf = &buf[..buf.len().min(MAX_PLAINTEXT)];
        self.ssl.ssl_write(buf).map_err(tls_error)
    }

    fn flush_plaintext(&mut self) -> io::Result<()> {
        // Records are written out as soon as they are sealed.
        Ok(())
    }

    fn send_close_notify(&mut self) {
        if !self.close_sent {
            self.close_sent = true;
            let _ = self.ssl.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport that has `left` bytes for the taking.
    struct Source {
        left: usize,
    }

    impl Read for Source {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.left);
            self.left -= n;
            Ok(n)
        }
    }

    /// Takes everything buffered, as BoringSSL does record by record.
    fn drain(io: &mut MemIo) {
        let mut sink = vec![0; RECORD];
        while io.read(&mut sink).is_ok() {}
    }

    #[test]
    fn reads_grow_to_four_records_on_a_bulk_transfer_and_back_when_it_ends() {
        let mut io = MemIo::default();
        let mut bulk = Source { left: usize::MAX };
        let mut sizes = Vec::new();
        for _ in 0..4 {
            sizes.push(io.fill_from(&mut bulk).unwrap());
            drain(&mut io);
        }
        assert_eq!(sizes, [RECORD, 2 * RECORD, 4 * RECORD, 4 * RECORD]);
        // A trickle: the buffer halves back to one record.
        for _ in 0..3 {
            io.fill_from(&mut Source { left: 100 }).unwrap();
            drain(&mut io);
        }
        assert_eq!(io.rx_records, 1);
        assert!(io.rx.is_none(), "an idle connection keeps no buffer");
    }

    /// Takes at most `limit` bytes a write, as a full socket does.
    struct Sink {
        taken: Vec<u8>,
        limit: usize,
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = buf.len().min(self.limit);
            self.taken.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writes_after_a_partial_drain_keep_only_what_is_left() {
        let mut io = MemIo::default();
        let mut sink = Sink {
            taken: Vec::new(),
            limit: 3 * RECORD,
        };
        let records: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; RECORD]).collect();
        for record in &records[..4] {
            io.write_all(record).unwrap();
        }
        io.drain_to(&mut sink).unwrap();
        for record in &records[4..] {
            io.write_all(record).unwrap();
        }
        // What the sink took is gone from the buffer, not carried along.
        assert_eq!(io.tx_pos, 0);
        assert_eq!(io.tx.len(), 5 * RECORD);
        while io.has_tx() {
            io.drain_to(&mut sink).unwrap();
        }
        assert_eq!(sink.taken, records.concat());
    }
}
