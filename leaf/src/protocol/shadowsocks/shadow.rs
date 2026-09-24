use std::{cmp::min, io, pin::Pin};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{
    ready,
    task::{Context, Poll},
};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::common::crypto::{
    aead::{AeadCipher, AeadDecryptor, AeadEncryptor},
    Cipher, Decryptor, Encryptor, SizedCipher,
};

use super::crypto::{hkdf_sha1, kdf, ShadowsocksNonceSequence};

/// Ciphertext requested from the inner stream per read, so one syscall can
/// carry several chunks.
const READ_AHEAD: usize = 64 * 1024;
/// Plaintext sealed per write call; it is split into spec-sized chunks and
/// written out together.
const MAX_WRITE: usize = 64 * 1024;
/// 0x3fff is the mandatory maximum payload size in ss spec.
const MAX_CHUNK: usize = 0x3fff;

// What the next ciphertext read is waiting for.
enum ReadState {
    Salt,
    Length,
    Data(usize),
}

enum WriteState {
    WaitingSalt,
    WaitingChunk,
    PendingChunk(usize),
}

pub struct ShadowedStream<T> {
    inner: T,
    cipher: AeadCipher,
    psk: Vec<u8>,
    enc: Option<AeadEncryptor<ShadowsocksNonceSequence>>,
    dec: Option<AeadDecryptor<ShadowsocksNonceSequence>>,
    // Ciphertext read from the inner stream but not yet decrypted.
    read_buf: BytesMut,
    // Decrypted payload not yet handed to the caller.
    plain: BytesMut,
    write_buf: BytesMut,
    read_state: ReadState,
    write_state: WriteState,
    prefix: Option<Box<[u8]>>,
}

impl<T> ShadowedStream<T> {
    pub fn new(s: T, cipher: &str, password: &str, prefix: Option<Box<[u8]>>) -> io::Result<Self> {
        let cipher = AeadCipher::new(cipher)
            .map_err(|e| io::Error::other(format!("create AEAD cipher failed: {}", e)))?;
        let psk = kdf(password, cipher.key_len())
            .map_err(|e| io::Error::other(format!("derive key failed: {}", e)))?;
        if let Some(prefix) = prefix.as_ref() {
            if prefix.len() > cipher.key_len() {
                return Err(io::Error::other(format!(
                    "prefix length exceeding cipher key length: {} > {}",
                    prefix.len(),
                    cipher.key_len()
                )));
            }
        }
        Ok(ShadowedStream {
            inner: s,
            cipher,
            psk,
            enc: None,
            dec: None,

            read_buf: BytesMut::new(),
            plain: BytesMut::new(),
            write_buf: BytesMut::new(),

            read_state: ReadState::Salt,
            write_state: WriteState::WaitingSalt,
            prefix,
        })
    }
}

fn early_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
}

impl<T> ShadowedStream<T>
where
    T: AsyncRead + Unpin,
{
    // Read until `read_buf` holds at least `need` bytes, taking whatever else
    // the inner stream has ready in the same reads.
    fn poll_fill(&mut self, cx: &mut Context, need: usize) -> Poll<io::Result<()>> {
        while self.read_buf.len() < need {
            self.read_buf
                .reserve((need - self.read_buf.len()).max(READ_AHEAD));
            let mut buf = ReadBuf::uninit(self.read_buf.spare_capacity_mut());
            let ptr = buf.filled().as_ptr();
            match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Don't keep read-ahead memory around while the
                    // connection is idle.
                    if self.read_buf.is_empty() {
                        self.read_buf = BytesMut::new();
                    }
                    return Poll::Pending;
                }
            }
            assert_eq!(ptr, buf.filled().as_ptr());
            let n = buf.filled().len();
            if n == 0 {
                return Poll::Ready(Err(early_eof()));
            }
            // SAFETY: the inner reader initialized `n` bytes of spare capacity.
            unsafe { self.read_buf.set_len(self.read_buf.len() + n) };
        }
        Poll::Ready(Ok(()))
    }
}

pub fn crypto_err() -> io::Error {
    io::Error::other("crypto error")
}

impl<T> AsyncRead for ShadowedStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        let start = buf.filled().len();
        loop {
            // Hand out decrypted payload first.
            if !me.plain.is_empty() {
                let n = min(buf.remaining(), me.plain.len());
                buf.put_slice(&me.plain[..n]);
                me.plain.advance(n);
                if me.plain.is_empty() {
                    // Release the chunk's share of the read buffer.
                    me.plain = BytesMut::new();
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }

            let need = match me.read_state {
                ReadState::Salt => me.cipher.key_len(),
                ReadState::Length => 2 + me.cipher.tag_len(),
                ReadState::Data(n) => n + me.cipher.tag_len(),
            };
            if me.read_buf.len() < need {
                // Return what we already have rather than wait for more.
                if buf.filled().len() > start {
                    return Poll::Ready(Ok(()));
                }
                if let Err(e) = ready!(me.poll_fill(cx, need)) {
                    if e.kind() == io::ErrorKind::UnexpectedEof
                        && matches!(me.read_state, ReadState::Length)
                    {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(e));
                }
            }

            match me.read_state {
                ReadState::Salt => {
                    // read salt and create decryptor
                    let salt = me.read_buf.split_to(need);
                    let key = hkdf_sha1(
                        &me.psk,
                        &salt,
                        String::from("ss-subkey").as_bytes().to_vec(),
                        me.cipher.key_len(),
                    )
                    .map_err(|_| crypto_err())?;
                    let nonce = super::crypto::ShadowsocksNonceSequence::new(me.cipher.nonce_len());
                    let dec = me.cipher.decryptor(&key, nonce).map_err(|_| crypto_err())?;
                    me.dec.replace(dec);
                    me.read_state = ReadState::Length;
                }
                ReadState::Length => {
                    // decipher payload length
                    let mut length = me.read_buf.split_to(need);
                    let dec = me.dec.as_mut().expect("uninitialized cipher");
                    dec.decrypt(&mut length).map_err(|_| crypto_err())?;
                    let payload_len = u16::from_be_bytes([length[0], length[1]]) as usize;
                    me.read_state = ReadState::Data(payload_len);
                }
                ReadState::Data(n) => {
                    // decipher payload
                    let mut payload = me.read_buf.split_to(need);
                    let dec = me.dec.as_mut().expect("uninitialized cipher");
                    dec.decrypt(&mut payload).map_err(|_| crypto_err())?;
                    payload.truncate(n);
                    me.plain = payload;
                    me.read_state = ReadState::Length;
                }
            }
        }
    }
}

// Append one sealed chunk (encrypted length, then encrypted payload) to `out`.
fn seal_chunk(
    out: &mut BytesMut,
    enc: &mut AeadEncryptor<ShadowsocksNonceSequence>,
    data: &[u8],
) -> io::Result<()> {
    let mut sealed = out.split_off(out.len());
    sealed.put_slice(&(data.len() as u16).to_be_bytes());
    enc.encrypt(&mut sealed).map_err(|_| crypto_err())?;
    let mut payload = sealed.split_off(sealed.len());
    payload.put_slice(data);
    enc.encrypt(&mut payload).map_err(|_| crypto_err())?;
    sealed.unsplit(payload);
    out.unsplit(sealed);
    Ok(())
}

impl<T> AsyncWrite for ShadowedStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use tokio_util::io::poll_write_buf;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match self.write_state {
                WriteState::WaitingSalt => {
                    // generate random salt and create encryptor
                    let salt_size = self.cipher.key_len();
                    self.write_buf.reserve(salt_size);
                    unsafe { self.write_buf.set_len(salt_size) };
                    let mut rng = StdRng::from_entropy();
                    if let Some(prefix) = self.prefix.as_ref().cloned() {
                        self.write_buf[..prefix.len()].copy_from_slice(&prefix);
                        rng.fill_bytes(&mut self.write_buf[prefix.len()..salt_size]);
                    } else {
                        rng.fill_bytes(&mut self.write_buf[..salt_size]);
                    }
                    let key = hkdf_sha1(
                        &self.psk,
                        &self.write_buf[..salt_size],
                        String::from("ss-subkey").as_bytes().to_vec(),
                        self.cipher.key_len(),
                    )
                    .map_err(|_| crypto_err())?;
                    let nonce =
                        super::crypto::ShadowsocksNonceSequence::new(self.cipher.nonce_len());
                    let enc = self
                        .cipher
                        .encryptor(&key, nonce)
                        .map_err(|_| crypto_err())?;

                    self.enc.replace(enc);

                    self.write_state = WriteState::WaitingChunk;
                }
                WriteState::WaitingChunk => {
                    // Seal up to MAX_WRITE bytes as a run of chunks so they go
                    // out in a single write.
                    let me = &mut *self;
                    let total = min(buf.len(), MAX_WRITE);
                    let chunks = total.div_ceil(MAX_CHUNK);
                    let overhead = 2 + 2 * me.cipher.tag_len();
                    me.write_buf.reserve(total + chunks * overhead);
                    let enc = me.enc.as_mut().expect("uninitialized cipher");
                    for data in buf[..total].chunks(MAX_CHUNK) {
                        seal_chunk(&mut me.write_buf, enc, data)?;
                    }
                    me.write_state = WriteState::PendingChunk(total);
                }

                // consumed is the plaintext length we return to the caller once
                // all of its ciphertext is written.
                WriteState::PendingChunk(consumed) => {
                    let me = &mut *self;

                    // There would be trouble if the caller change the buf upon pending, but I
                    // believe that's not a usual use case.
                    while !me.write_buf.is_empty() {
                        let nw = ready!(poll_write_buf(
                            Pin::new(&mut me.inner),
                            cx,
                            &mut me.write_buf
                        ))?;
                        if nw == 0 {
                            return Err(early_eof()).into();
                        }
                    }
                    me.write_state = WriteState::WaitingChunk;
                    return Poll::Ready(Ok(consumed));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // The relay flushes when its reader goes idle; drop the write buffer
        // then so idle connections don't keep it.
        if self.write_buf.is_empty() && matches!(self.write_state, WriteState::WaitingChunk) {
            self.write_buf = BytesMut::new();
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn short_packet() -> io::Error {
    io::Error::other("short packet")
}

pub struct ShadowedDatagram {
    cipher: AeadCipher,
    psk: Vec<u8>,
}

impl ShadowedDatagram {
    pub fn new(cipher: &str, password: &str) -> io::Result<Self> {
        let cipher = AeadCipher::new(cipher)
            .map_err(|e| io::Error::other(format!("create AEAD cipher failed: {}", e)))?;
        let psk = kdf(password, cipher.key_len())
            .map_err(|e| io::Error::other(format!("derive key failed: {}", e)))?;
        Ok(ShadowedDatagram { cipher, psk })
    }

    /// Decrypts a message. On success, returns the plaintext.
    pub fn decrypt(&self, mut buf: BytesMut) -> io::Result<Bytes> {
        let salt_size = self.cipher.key_len();
        let tag_len = self.cipher.tag_len();
        let buf_len = buf.len();

        if buf.len() < salt_size {
            return Err(short_packet());
        }

        let salt = buf.split_to(salt_size);

        let key = hkdf_sha1(
            &self.psk,
            &salt,
            String::from("ss-subkey").as_bytes().to_vec(),
            self.cipher.key_len(),
        )
        .map_err(|_| crypto_err())?;
        let nonce = ShadowsocksNonceSequence::new(self.cipher.nonce_len());
        let mut dec = self
            .cipher
            .decryptor(&key, nonce)
            .map_err(|_| crypto_err())?;

        if buf.len() < tag_len {
            debug!("buffer size {}", buf.len());
            return Err(short_packet());
        }

        dec.decrypt(&mut buf).map_err(|_| crypto_err())?;

        let _ = buf.split_off(buf_len - salt_size - tag_len);

        Ok(buf.freeze())
    }

    /// Encrypts a message. On success, returns the ciphertext.
    pub fn encrypt(&self, mut buf: BytesMut) -> io::Result<Bytes> {
        if buf.is_empty() {
            return Ok(Bytes::new());
        }

        let salt_size = self.cipher.key_len();

        let mut buffer = BytesMut::new(); // TODO optimize
        buffer.resize(salt_size, 0);

        // generate random salt
        let mut rng = StdRng::from_entropy();
        for i in 0..salt_size {
            buffer[i] = rng.gen();
        }

        let key = hkdf_sha1(
            &self.psk,
            &buffer[..salt_size],
            String::from("ss-subkey").as_bytes().to_vec(),
            self.cipher.key_len(),
        )
        .map_err(|_| crypto_err())?;
        let nonce = ShadowsocksNonceSequence::new(self.cipher.nonce_len());
        let mut enc = self
            .cipher
            .encryptor(&key, nonce)
            .map_err(|_| crypto_err())?;

        enc.encrypt(&mut buf).map_err(|_| crypto_err())?;

        buffer.extend_from_slice(&buf[..]);

        Ok(buffer.freeze())
    }
}
