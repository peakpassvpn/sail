//! The Shadowsocks 2022 TCP stream.
//!
//! A request is: salt, identity headers when the server has users, the
//! sealed fixed-length header (type, timestamp, length of the next chunk),
//! the sealed variable-length header (address, padding, initial payload),
//! then length/payload chunk pairs. A response is: salt, the sealed
//! fixed-length header (type, timestamp, request salt, length of the first
//! payload chunk), that chunk, then length/payload chunk pairs. The request
//! and response header exchange is done by [`connect`] and [`accept`]; the
//! stream then carries chunks both ways, and writes the response header
//! itself on the server's first write.

use std::{cmp::min, io, pin::Pin, sync::Arc};

use bytes::{Buf, BytesMut};
use futures::{
    ready,
    task::{Context, Poll},
};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::session::{SocksAddr, SocksAddrWireType};

use super::{
    check_timestamp, crypto_err, identity_subkey, now_secs, padding_len, psk_hash, session_subkey,
    AesBlock, ChunkAead, Method, SaltPool, Users, EIH_LEN, HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER,
    MAX_PADDING, TAG_LEN,
};

/// Ciphertext requested from the inner stream per read, so one syscall can
/// carry several chunks.
const READ_AHEAD: usize = 64 * 1024;
/// Plaintext sealed per write call.
const MAX_WRITE: usize = 64 * 1024;
/// SIP022 raises the chunk payload limit to the full u16 range.
const MAX_CHUNK: usize = 0xffff;
/// Type, timestamp and length of the request's fixed-length header.
const REQUEST_FIXED_LEN: usize = 1 + 8 + 2;

enum ReadState {
    /// Client only: the response salt.
    Salt,
    /// Client only: the response's fixed-length header.
    ResponseHeader,
    Length,
    Data(usize),
}

enum WriteState {
    /// Server only: the response header goes out with the first payload.
    ResponseHeader,
    Ready,
    /// Plaintext bytes to report once `write_buf` is flushed.
    Pending(usize),
}

pub struct Ss2022Stream<T> {
    inner: T,
    method: Method,
    /// The key the response direction's subkey comes from: the user's.
    psk: Vec<u8>,
    /// The client checks the response echoes it, the server echoes it.
    request_salt: Vec<u8>,
    enc: Option<ChunkAead>,
    dec: Option<ChunkAead>,
    read_buf: BytesMut,
    plain: BytesMut,
    write_buf: Vec<u8>,
    write_pos: usize,
    read_state: ReadState,
    write_state: WriteState,
}

fn early_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Appends one sealed chunk, its length then its payload.
fn seal_chunk(out: &mut Vec<u8>, enc: &mut ChunkAead, data: &[u8]) -> io::Result<()> {
    let start = out.len();
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    enc.seal(out, start)?;
    let start = out.len();
    out.extend_from_slice(data);
    enc.seal(out, start)
}

fn random_salt(len: usize) -> Vec<u8> {
    let mut salt = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Opens a client stream: writes the request header to `inner`, with as
/// much of `payload` as fits in it and the rest as chunks.
///
/// `psks` is the key chain, the server's first and the user's last; every
/// key but the last makes an identity header for the next.
pub async fn connect<T>(
    mut inner: T,
    method: Method,
    psks: &[Vec<u8>],
    destination: &SocksAddr,
    payload: &[u8],
) -> io::Result<Ss2022Stream<T>>
where
    T: AsyncWrite + Unpin,
{
    let user_psk = psks.last().ok_or_else(|| io::Error::other("missing PSK"))?;
    let salt = random_salt(method.key_len());
    let mut out = Vec::with_capacity(1024 + payload.len());
    out.extend_from_slice(&salt);
    for pair in psks.windows(2) {
        let aes = AesBlock::new(&identity_subkey(&pair[0], &salt)).map_err(|_| crypto_err())?;
        let mut eih = psk_hash(&pair[1]);
        aes.encrypt(&mut eih)?;
        out.extend_from_slice(&eih);
    }
    let mut enc = ChunkAead::new(method, &session_subkey(user_psk, &salt))?;

    let padding = padding_len(payload.len());
    let room = MAX_CHUNK - destination.size() - 2 - padding;
    let (first, rest) = payload.split_at(min(payload.len(), room));
    let variable_len = destination.size() + 2 + padding + first.len();

    let start = out.len();
    out.push(HEADER_TYPE_CLIENT);
    out.extend_from_slice(&now_secs().to_be_bytes());
    out.extend_from_slice(&(variable_len as u16).to_be_bytes());
    enc.seal(&mut out, start)?;

    let start = out.len();
    let mut addr = BytesMut::new();
    destination.write_buf(&mut addr, SocksAddrWireType::PortLast);
    out.extend_from_slice(&addr);
    out.extend_from_slice(&(padding as u16).to_be_bytes());
    out.resize(out.len() + padding, 0);
    out.extend_from_slice(first);
    enc.seal(&mut out, start)?;

    for data in rest.chunks(MAX_CHUNK) {
        seal_chunk(&mut out, &mut enc, data)?;
    }
    inner.write_all(&out).await?;

    Ok(Ss2022Stream {
        inner,
        method,
        psk: user_psk.clone(),
        request_salt: salt,
        enc: Some(enc),
        dec: None,
        read_buf: BytesMut::new(),
        plain: BytesMut::new(),
        write_buf: Vec::new(),
        write_pos: 0,
        read_state: ReadState::Salt,
        write_state: WriteState::Ready,
    })
}

/// What a server needs to accept requests.
pub struct ServerConfig {
    pub method: Method,
    /// The server's PSK: the only key without users, the identity key with.
    pub psk: Vec<u8>,
    /// With users, every request carries an identity header naming one.
    pub users: Option<Users>,
    pub salts: SaltPool,
}

/// A request the server accepted.
pub struct Accepted<T> {
    pub stream: Ss2022Stream<T>,
    pub destination: SocksAddr,
    pub user: Option<Arc<str>>,
}

/// Reads and checks a request header from `inner`.
pub async fn accept<T>(mut inner: T, config: &ServerConfig) -> io::Result<Accepted<T>>
where
    T: AsyncRead + Unpin,
{
    let method = config.method;
    let mut salt = vec![0u8; method.key_len()];
    inner.read_exact(&mut salt).await?;

    let (psk, user) = match &config.users {
        None => (config.psk.clone(), None),
        Some(users) => {
            let mut eih = [0u8; EIH_LEN];
            inner.read_exact(&mut eih).await?;
            let aes =
                AesBlock::new(&identity_subkey(&config.psk, &salt)).map_err(|_| crypto_err())?;
            aes.decrypt(&mut eih)?;
            let (_, user) = users.find(&eih).ok_or_else(|| bad("unknown user"))?;
            (user.psk.clone(), user.name.clone())
        }
    };

    let mut dec = ChunkAead::new(method, &session_subkey(&psk, &salt))?;
    let mut fixed = [0u8; REQUEST_FIXED_LEN + TAG_LEN];
    inner.read_exact(&mut fixed).await?;
    dec.open(&mut fixed)?;
    if fixed[0] != HEADER_TYPE_CLIENT {
        return Err(bad("bad header type"));
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&fixed[1..9]);
    check_timestamp(u64::from_be_bytes(ts))?;
    // Recorded only once the header authenticates, so that garbage cannot
    // fill the pool.
    config.salts.check_and_insert(&salt)?;
    let variable_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;

    let mut variable = vec![0u8; variable_len + TAG_LEN];
    inner.read_exact(&mut variable).await?;
    let n = dec.open(&mut variable)?;
    variable.truncate(n);
    let destination = SocksAddr::try_from((&variable[..], SocksAddrWireType::PortLast))?;
    let mut rest = &variable[destination.size()..];
    if rest.len() < 2 {
        return Err(bad("short request header"));
    }
    let padding = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    rest = &rest[2..];
    if padding > MAX_PADDING || padding > rest.len() {
        return Err(bad("bad padding"));
    }
    let payload = &rest[padding..];
    if padding == 0 && payload.is_empty() {
        return Err(bad("request without padding or payload"));
    }

    let stream = Ss2022Stream {
        inner,
        method,
        psk,
        request_salt: salt,
        enc: None,
        dec: Some(dec),
        read_buf: BytesMut::new(),
        plain: BytesMut::from(payload),
        write_buf: Vec::new(),
        write_pos: 0,
        read_state: ReadState::Length,
        write_state: WriteState::ResponseHeader,
    };
    Ok(Accepted {
        stream,
        destination,
        user,
    })
}

impl<T> Ss2022Stream<T>
where
    T: AsyncRead + Unpin,
{
    // Reads until `read_buf` holds at least `need` bytes.
    fn poll_fill(&mut self, cx: &mut Context, need: usize) -> Poll<io::Result<()>> {
        while self.read_buf.len() < need {
            self.read_buf
                .reserve((need - self.read_buf.len()).max(READ_AHEAD));
            let mut buf = ReadBuf::uninit(self.read_buf.spare_capacity_mut());
            match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Don't keep read-ahead memory around while idle.
                    if self.read_buf.is_empty() {
                        self.read_buf = BytesMut::new();
                    }
                    return Poll::Pending;
                }
            }
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

impl<T> AsyncRead for Ss2022Stream<T>
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
            if !me.plain.is_empty() {
                let n = min(buf.remaining(), me.plain.len());
                buf.put_slice(&me.plain[..n]);
                me.plain.advance(n);
                if me.plain.is_empty() {
                    me.plain = BytesMut::new();
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }

            let key_len = me.method.key_len();
            let need = match me.read_state {
                ReadState::Salt => key_len,
                ReadState::ResponseHeader => 1 + 8 + key_len + 2 + TAG_LEN,
                ReadState::Length => 2 + TAG_LEN,
                ReadState::Data(n) => n + TAG_LEN,
            };
            if me.read_buf.len() < need {
                if buf.filled().len() > start {
                    return Poll::Ready(Ok(()));
                }
                if let Err(e) = ready!(me.poll_fill(cx, need)) {
                    // A clean end is one between chunks, or before the
                    // server said anything.
                    if e.kind() == io::ErrorKind::UnexpectedEof
                        && me.read_buf.is_empty()
                        && matches!(me.read_state, ReadState::Length | ReadState::Salt)
                    {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(e));
                }
            }

            let mut chunk = me.read_buf.split_to(need);
            match me.read_state {
                ReadState::Salt => {
                    let key = session_subkey(&me.psk, &chunk);
                    me.dec = Some(ChunkAead::new(me.method, &key)?);
                    me.read_state = ReadState::ResponseHeader;
                }
                ReadState::ResponseHeader => {
                    let dec = me.dec.as_mut().ok_or_else(crypto_err)?;
                    dec.open(&mut chunk)?;
                    if chunk[0] != HEADER_TYPE_SERVER {
                        return Poll::Ready(Err(bad("bad header type")));
                    }
                    let mut ts = [0u8; 8];
                    ts.copy_from_slice(&chunk[1..9]);
                    check_timestamp(u64::from_be_bytes(ts))?;
                    if chunk[9..9 + key_len] != me.request_salt[..] {
                        return Poll::Ready(Err(bad("bad request salt")));
                    }
                    let len = u16::from_be_bytes([chunk[9 + key_len], chunk[10 + key_len]]);
                    me.request_salt = Vec::new();
                    me.read_state = if len == 0 {
                        ReadState::Length
                    } else {
                        ReadState::Data(len as usize)
                    };
                }
                ReadState::Length => {
                    let dec = me.dec.as_mut().ok_or_else(crypto_err)?;
                    dec.open(&mut chunk)?;
                    let len = u16::from_be_bytes([chunk[0], chunk[1]]) as usize;
                    me.read_state = ReadState::Data(len);
                }
                ReadState::Data(n) => {
                    let dec = me.dec.as_mut().ok_or_else(crypto_err)?;
                    dec.open(&mut chunk)?;
                    chunk.truncate(n);
                    me.plain = chunk;
                    me.read_state = ReadState::Length;
                }
            }
        }
    }
}

impl<T> Ss2022Stream<T> {
    /// Seals up to [`MAX_WRITE`] bytes of `buf` into `write_buf`, after the
    /// response header if this is the server's first write. Returns how
    /// much of `buf` it took.
    fn seal(&mut self, buf: &[u8]) -> io::Result<usize> {
        let total = min(buf.len(), MAX_WRITE);
        let mut data = &buf[..total];
        self.write_buf.clear();
        self.write_pos = 0;
        self.write_buf
            .reserve(total + 512 + total.div_ceil(MAX_CHUNK) * (2 + 2 * TAG_LEN));
        if matches!(self.write_state, WriteState::ResponseHeader) {
            let salt = random_salt(self.method.key_len());
            let mut enc = ChunkAead::new(self.method, &session_subkey(&self.psk, &salt))?;
            let out = &mut self.write_buf;
            out.extend_from_slice(&salt);
            let (first, rest) = data.split_at(min(data.len(), MAX_CHUNK));
            let start = out.len();
            out.push(HEADER_TYPE_SERVER);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&self.request_salt);
            out.extend_from_slice(&(first.len() as u16).to_be_bytes());
            enc.seal(out, start)?;
            let start = out.len();
            out.extend_from_slice(first);
            enc.seal(out, start)?;
            data = rest;
            self.request_salt = Vec::new();
            self.enc = Some(enc);
        }
        let enc = self.enc.as_mut().ok_or_else(crypto_err)?;
        for chunk in data.chunks(MAX_CHUNK) {
            seal_chunk(&mut self.write_buf, enc, chunk)?;
        }
        Ok(total)
    }
}

impl<T> AsyncWrite for Ss2022Stream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let me = &mut *self;
        loop {
            match me.write_state {
                WriteState::ResponseHeader | WriteState::Ready => {
                    let n = me.seal(buf)?;
                    me.write_state = WriteState::Pending(n);
                }
                // As with the legacy stream, the caller is expected to
                // retry with the same buffer after Pending.
                WriteState::Pending(consumed) => {
                    while me.write_pos < me.write_buf.len() {
                        let n =
                            ready!(Pin::new(&mut me.inner)
                                .poll_write(cx, &me.write_buf[me.write_pos..]))?;
                        if n == 0 {
                            return Poll::Ready(Err(early_eof()));
                        }
                        me.write_pos += n;
                    }
                    me.write_state = WriteState::Ready;
                    return Poll::Ready(Ok(consumed));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // Drop the write buffer once idle so idle connections don't keep it.
        if matches!(self.write_state, WriteState::Ready) && self.write_buf.capacity() > 0 {
            self.write_buf = Vec::new();
            self.write_pos = 0;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::super::User;
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn server(method: Method, users: Option<Vec<User>>) -> ServerConfig {
        ServerConfig {
            method,
            psk: vec![0x11; method.key_len()],
            users: users.map(|u| Users::new(u).unwrap()),
            salts: SaltPool::new(),
        }
    }

    fn roundtrip(
        method: Method,
        psks: Vec<Vec<u8>>,
        config: ServerConfig,
        want_user: Option<&str>,
    ) {
        rt().block_on(async move {
            let (c, s) = duplex(1 << 20);
            let dest = SocksAddr::try_from(("example.com", 443)).unwrap();
            let big: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
            let client = connect(c, method, &psks, &dest, b"hello").await.unwrap();
            let accepted = accept(s, &config).await.unwrap();
            assert_eq!(accepted.destination, dest);
            assert_eq!(accepted.user.as_deref(), want_user);
            let (mut client, mut server) = (client, accepted.stream);

            let mut got = [0u8; 5];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello");

            let big2 = big.clone();
            let w = tokio::spawn(async move {
                server.write_all(&big2).await.unwrap();
                server.flush().await.unwrap();
                server
            });
            let mut back = vec![0u8; big.len()];
            client.read_exact(&mut back).await.unwrap();
            assert_eq!(back, big);
            let mut server = w.await.unwrap();

            client.write_all(&big).await.unwrap();
            let mut up = vec![0u8; big.len()];
            server.read_exact(&mut up).await.unwrap();
            assert_eq!(up, big);

            // A clean close reads as EOF.
            client.shutdown().await.unwrap();
            drop(client);
            let mut rest = Vec::new();
            server.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        });
    }

    #[test]
    fn single_user_all_methods() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
        ] {
            let config = server(method, None);
            roundtrip(method, vec![config.psk.clone()], config, None);
        }
    }

    #[test]
    fn multi_user() {
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let users = vec![
                User {
                    name: Some("alice".into()),
                    psk: vec![0x22; method.key_len()],
                },
                User {
                    name: Some("bob".into()),
                    psk: vec![0x33; method.key_len()],
                },
            ];
            let config = server(method, Some(users));
            let psks = vec![config.psk.clone(), vec![0x33; method.key_len()]];
            roundtrip(method, psks, config, Some("bob"));
        }
    }

    #[test]
    fn wrong_key_and_unknown_user_rejected() {
        rt().block_on(async {
            let method = Method::Aes128Gcm;
            let dest = SocksAddr::try_from(("example.com", 80)).unwrap();

            let config = server(method, None);
            let mut wire = Vec::new();
            connect(&mut wire, method, &[vec![0x99; 16]], &dest, b"x")
                .await
                .unwrap();
            assert!(accept(&wire[..], &config).await.is_err());

            let users = vec![User {
                name: None,
                psk: vec![0x22; 16],
            }];
            let config = server(method, Some(users));
            let mut wire = Vec::new();
            connect(
                &mut wire,
                method,
                &[config.psk.clone(), vec![0x44; 16]],
                &dest,
                b"x",
            )
            .await
            .unwrap();
            assert!(accept(&wire[..], &config).await.is_err());
        });
    }

    #[test]
    fn replayed_request_rejected() {
        rt().block_on(async {
            let method = Method::Aes256Gcm;
            let config = server(method, None);
            let dest = SocksAddr::try_from(("example.com", 80)).unwrap();
            let mut wire = Vec::new();
            connect(
                &mut wire,
                method,
                std::slice::from_ref(&config.psk),
                &dest,
                b"",
            )
            .await
            .unwrap();
            accept(&wire[..], &config).await.unwrap();
            let err = accept(&wire[..], &config).await.err().unwrap();
            assert!(err.to_string().contains("repeated salt"), "{}", err);
        });
    }

    // A request with a stale timestamp, sealed by hand.
    #[test]
    fn stale_timestamp_rejected() {
        rt().block_on(async {
            let method = Method::Aes128Gcm;
            let config = server(method, None);
            let salt = vec![5u8; 16];
            let mut enc = ChunkAead::new(method, &session_subkey(&config.psk, &salt)).unwrap();
            let mut wire = salt.clone();
            let start = wire.len();
            wire.push(HEADER_TYPE_CLIENT);
            wire.extend_from_slice(&(now_secs() - 31).to_be_bytes());
            wire.extend_from_slice(&10u16.to_be_bytes());
            enc.seal(&mut wire, start).unwrap();
            let err = accept(&wire[..], &config).await.err().unwrap();
            assert!(err.to_string().contains("timestamp"), "{}", err);
            // The salt of a rejected request is not recorded.
            assert!(config.salts.check_and_insert(&salt).is_ok());
        });
    }

    // A response must echo the request's salt.
    #[test]
    fn response_for_other_request_rejected() {
        rt().block_on(async {
            let method = Method::Aes128Gcm;
            let config = server(method, None);
            let dest = SocksAddr::try_from(("example.com", 80)).unwrap();
            let (c, s) = duplex(1 << 16);
            let mut client = connect(c, method, std::slice::from_ref(&config.psk), &dest, b"a")
                .await
                .unwrap();
            let mut accepted = accept(s, &config).await.unwrap();
            accepted.stream.request_salt = vec![0; 16];
            accepted.stream.write_all(b"b").await.unwrap();
            let mut got = [0u8; 1];
            let err = client.read_exact(&mut got).await.err().unwrap();
            assert!(err.to_string().contains("request salt"), "{}", err);
        });
    }
}
