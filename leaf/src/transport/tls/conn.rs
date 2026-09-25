//! A BoringSSL connection driven without IO, in the shape of a rustls
//! connection, so [`TlsStream`](crate::transport::tls_stream::TlsStream) can
//! run it and hand the transport over to XTLS Vision.
//!
//! BoringSSL reads and writes ciphertext through [`MemIo`]: the stream puts
//! what it reads from the transport there and takes what BoringSSL wrote.

use std::io::{self, ErrorKind, Read, Write};

use btls::ssl::{ErrorCode, Ssl, SslStream};
use foreign_types::ForeignType;

use crate::net::relay::{acquire_buffer, release_buffer};
use crate::transport::tls_stream::TlsConnection;

/// Ciphertext buffer size: one TLS record of any size fits.
const RX_SIZE: usize = 5 + 16384 + 2048;

/// Plaintext taken per write: one full record.
const MAX_PLAINTEXT: usize = 16384;

/// Ciphertext between the stream and BoringSSL. Both directions hold memory
/// only while they have data.
#[derive(Default)]
struct MemIo {
    // Read from the transport, not yet taken by BoringSSL: rx[rx_pos..rx_len].
    rx: Option<Box<[u8]>>,
    rx_pos: usize,
    rx_len: usize,
    // Written by BoringSSL, not yet written to the transport: tx[tx_pos..].
    tx: Vec<u8>,
    tx_pos: usize,
}

impl MemIo {
    fn rx_space(&self) -> usize {
        match &self.rx {
            Some(rx) => rx.len() - (self.rx_len - self.rx_pos),
            None => RX_SIZE,
        }
    }

    fn fill_from(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        if self.rx.is_none() {
            self.rx = Some(acquire_buffer(RX_SIZE)?);
        }
        let rx = self.rx.as_deref_mut().expect("buffer acquired above");
        if self.rx_pos > 0 {
            rx.copy_within(self.rx_pos..self.rx_len, 0);
            self.rx_len -= self.rx_pos;
            self.rx_pos = 0;
        }
        let read = rd.read(&mut rx[self.rx_len..]);
        if let Ok(n) = read {
            self.rx_len += n;
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
    pub fn client(ssl: Ssl) -> io::Result<Self> {
        // SAFETY: `ssl` is a valid, owned SSL that has not started a handshake.
        // btls only offers this on `SslStreamBuilder`, which cannot hand the
        // stream over without starting the handshake.
        unsafe { btls_sys::SSL_set_connect_state(ssl.as_ptr()) };
        let mut conn = Self::new(ssl)?;
        conn.drive_handshake()?;
        Ok(conn)
    }

    /// A server connection, waiting for the ClientHello.
    pub fn server(ssl: Ssl) -> io::Result<Self> {
        // SAFETY: as in `client`.
        unsafe { btls_sys::SSL_set_accept_state(ssl.as_ptr()) };
        Self::new(ssl)
    }

    fn new(ssl: Ssl) -> io::Result<Self> {
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
            Err(e) => Err(tls_error(e)),
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
