//! The REALITY server over BoringSSL.
//!
//! It reads the ClientHello before BoringSSL sees anything. A client that
//! opens the session ID -- sealed with AES-256-GCM under a key from X25519
//! between its key share and our private key -- to a short ID we know and
//! a time close to ours gets TLS 1.3 from us, with a throwaway Ed25519
//! certificate whose signature is an HMAC under that key. Everyone else,
//! and everything that is not such a ClientHello, is relayed byte for byte
//! to the handshake server, so a prober talks to the real site.
//!
//! Unlike Xray's, this server does not dial the real site for clients it
//! serves, and does not shape its handshake records after the site's.
//!
//! Chrome's ClientHello, which REALITY clients imitate, does not offer
//! Ed25519 signatures, and BoringSSL signs only with what the client
//! offers. So for the time BoringSSL parses the ClientHello, the first
//! algorithm in its signature_algorithms is swapped for Ed25519, and put
//! back before the ClientHello enters the transcript: see
//! `select_certificate` and `restore_sigalgs`.

use std::collections::HashSet;
use std::io;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use btls::asn1::{Asn1Integer, Asn1Time};
use btls::bn::BigNum;
use btls::ex_data::Index;
use btls::hash::MessageDigest;
use btls::pkey::{Id, PKey, Private};
use btls::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion};
use btls::x509::{X509Builder, X509NameBuilder, X509};
use foreign_types::ForeignTypeRef;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{parse_key, parse_short_id};
use crate::adapter::*;
use crate::session::Session;
use crate::transport::tls::BoringConnection;
use crate::transport::tls_stream::TlsStream;
use crate::transport::vision::VisionState;

const X25519: u16 = 0x001d;
const X25519_MLKEM768: u16 = 0x11ec;
const MLKEM768_ENCAPSULATION_KEY: usize = 1184;
const SIGN_ED25519: [u8; 2] = [0x08, 0x07];

/// The most of a ClientHello we read before giving up on it.
const MAX_CLIENT_HELLO: usize = 64 * 1024;

pub struct Handler {
    server_names: HashSet<String>,
    private_key: [u8; 32],
    short_ids: HashSet<[u8; 8]>,
    max_time_difference: Option<Duration>,
    handshake: (String, u16),
    context: SslContext,
    key: PKey<Private>,
    public_key: [u8; 32],
    // The certificate, whose last 64 bytes -- the signature -- each
    // connection replaces.
    certificate: Vec<u8>,
}

/// The ClientHello bytes BoringSSL's signature_algorithms parse must see
/// differently, and where they were put in its buffer.
struct SigalgSwap {
    /// Of the first algorithm, from the start of the ClientHello body.
    offset: usize,
    original: [u8; 2],
    swapped_at: Mutex<Option<usize>>,
}

fn swap_index() -> Index<Ssl, SigalgSwap> {
    static INDEX: OnceLock<Index<Ssl, SigalgSwap>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("allocate an SSL ex_data index"))
}

/// Runs before BoringSSL parses the ClientHello's extensions: puts Ed25519
/// in place of the first signature algorithm.
unsafe extern "C" fn select_certificate(
    client_hello: *const btls_sys::SSL_CLIENT_HELLO,
) -> btls_sys::ssl_select_cert_result_t {
    // SAFETY: BoringSSL passes a valid SSL_CLIENT_HELLO whose body stays in
    // place, and writable, until the handshake next waits for IO; the
    // ClientHello is not hashed before `restore_sigalgs` runs.
    unsafe {
        let hello = &*client_hello;
        let ssl = btls::ssl::SslRef::from_ptr(hello.ssl);
        if let Some(swap) = ssl.ex_data(swap_index()) {
            if swap.offset + 2 <= hello.client_hello_len {
                let at = hello.client_hello.add(swap.offset) as *mut u8;
                let bytes = std::slice::from_raw_parts_mut(at, 2);
                if bytes == swap.original {
                    bytes.copy_from_slice(&SIGN_ED25519);
                    if let Ok(mut swapped) = swap.swapped_at.lock() {
                        *swapped = Some(at as usize);
                    }
                }
            }
        }
    }
    btls_sys::ssl_select_cert_result_t::ssl_select_cert_success
}

/// Runs after the extensions are parsed and before the ClientHello enters
/// the transcript: puts the swapped algorithm back.
unsafe extern "C" fn restore_sigalgs(
    ssl: *mut btls_sys::SSL,
    _arg: *mut std::os::raw::c_void,
) -> std::os::raw::c_int {
    // SAFETY: as in `select_certificate`; `swapped_at` points into the same
    // ClientHello, which has not moved.
    unsafe {
        let ssl = btls::ssl::SslRef::from_ptr(ssl);
        if let Some(swap) = ssl.ex_data(swap_index()) {
            if let Some(at) = swap.swapped_at.lock().ok().and_then(|mut s| s.take()) {
                std::ptr::copy_nonoverlapping(swap.original.as_ptr(), at as *mut u8, 2);
            }
        }
    }
    1
}

impl Handler {
    /// `private_key` is hex or base64url, each short ID up to 16 hex
    /// digits; `handshake` is the site clients that are not ours are
    /// relayed to.
    pub fn new(
        server_name: String,
        private_key: &str,
        short_ids: &[String],
        max_time_difference: Option<Duration>,
        handshake: (String, u16),
    ) -> Result<Self> {
        if server_name.is_empty() {
            return Err(anyhow!("server_name is required"));
        }
        let short_ids = short_ids
            .iter()
            .map(|id| parse_short_id(id))
            .collect::<Result<HashSet<_>>>()?;
        if short_ids.is_empty() {
            return Err(anyhow!("short_id: at least one is required"));
        }

        let key = PKey::generate(Id::ED25519)?;
        let mut public_key = [0u8; 32];
        key.raw_public_key(&mut public_key)?;
        let certificate = throwaway_certificate(&key)?;

        let mut builder = SslContextBuilder::new(SslMethod::tls())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_curves_list("X25519MLKEM768:X25519:P-256:P-384")?;
        // SAFETY: the context is valid; the callbacks only touch what their
        // comments say.
        unsafe {
            // A resumed session would skip the session ID check.
            btls_sys::SSL_CTX_set_num_tickets(builder.as_ptr(), 0);
            btls_sys::SSL_CTX_set_select_certificate_cb(builder.as_ptr(), Some(select_certificate));
            btls_sys::SSL_CTX_set_cert_cb(
                builder.as_ptr(),
                Some(restore_sigalgs),
                std::ptr::null_mut(),
            );
        }
        Ok(Handler {
            server_names: HashSet::from([server_name]),
            private_key: parse_key("private_key", private_key)?,
            short_ids,
            max_time_difference,
            handshake,
            context: builder.build(),
            key,
            public_key,
            certificate,
        })
    }

    /// The key a client authenticated with, if it did.
    fn authenticate(&self, hello: &ClientHello<'_>) -> Option<[u8; 32]> {
        if !hello.tls13 || !self.server_names.contains(hello.server_name.as_deref()?) {
            return None;
        }
        let auth_key = open_session_id(&self.private_key, hello)?;
        let plain = &auth_key.1;
        let time = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]) as u64;
        let short_id: [u8; 8] = plain[8..16].try_into().ok()?;
        if !self.short_ids.contains(&short_id) {
            return None;
        }
        if let Some(max) = self.max_time_difference {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            if now.abs_diff(time) > max.as_secs() {
                return None;
            }
        }
        Some(auth_key.0)
    }

    /// The certificate for a client authenticated with `auth_key`.
    fn certificate_for(&self, auth_key: &[u8; 32]) -> io::Result<X509> {
        let mut der = self.certificate.clone();
        let mut mac =
            <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("HMAC takes any key size");
        mac.update(&self.public_key);
        let signature = mac.finalize().into_bytes();
        let at = der.len() - signature.len();
        der[at..].copy_from_slice(&signature);
        X509::from_der(&der).map_err(io::Error::other)
    }

    fn connection(
        &self,
        auth_key: &[u8; 32],
        hello: &ClientHello<'_>,
    ) -> io::Result<BoringConnection> {
        let mut ssl = Ssl::new(&self.context).map_err(io::Error::other)?;
        let certificate = self.certificate_for(auth_key)?;
        ssl.set_certificate(&certificate)
            .map_err(io::Error::other)?;
        ssl.set_private_key(&self.key).map_err(io::Error::other)?;
        if let Some((offset, original)) = hello.sigalgs_to_swap {
            ssl.set_ex_data(
                swap_index(),
                SigalgSwap {
                    offset,
                    original,
                    swapped_at: Mutex::new(None),
                },
            );
        }
        BoringConnection::server(ssl)
    }
}

/// A self-signed Ed25519 certificate with no names: its signature is
/// replaced for each connection anyway.
fn throwaway_certificate(key: &PKey<Private>) -> Result<Vec<u8>> {
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    let serial: Asn1Integer = BigNum::from_u32(0)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    let name = X509NameBuilder::new()?.build();
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    let epoch = Asn1Time::from_unix(0)?;
    builder.set_not_before(&epoch)?;
    builder.set_not_after(&epoch)?;
    builder.set_pubkey(key)?;
    // SAFETY: a null digest is how Ed25519, which hashes by itself, signs.
    let no_digest = unsafe { MessageDigest::from_ptr(std::ptr::null()) };
    builder.sign(key, no_digest)?;
    let certificate = builder.build();
    let der = certificate.to_der()?;
    // The signature is the last thing in the DER.
    if !der.ends_with(certificate.signature().as_slice()) || certificate.signature().len() != 64 {
        return Err(anyhow!("unexpected certificate layout"));
    }
    Ok(der)
}

/// Opens the session ID: the key it was sealed with and the plaintext.
fn open_session_id(
    private_key: &[u8; 32],
    hello: &ClientHello<'_>,
) -> Option<([u8; 32], [u8; 32])> {
    let peer = hello.x25519?;
    let mut shared = [0u8; 32];
    // SAFETY: all three buffers are 32 bytes.
    if unsafe { btls_sys::X25519(shared.as_mut_ptr(), private_key.as_ptr(), peer.as_ptr()) } != 1 {
        return None;
    }
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&hello.random[..20]), &shared)
        .expand(b"REALITY", &mut key)
        .ok()?;
    let session_id: [u8; 32] = hello
        .message
        .get(SESSION_ID..SESSION_ID + 32)?
        .try_into()
        .ok()?;
    // The associated data is the ClientHello with its session ID zeroed.
    let mut aad = hello.message.to_vec();
    aad[SESSION_ID..SESSION_ID + 32].fill(0);
    let mut plain = session_id[..16].to_vec();
    let tag: [u8; 16] = session_id[16..].try_into().ok()?;
    Aes256Gcm::new(&key.into())
        .decrypt_in_place_detached(hello.random[20..].into(), &aad, &mut plain, (&tag).into())
        .ok()?;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&plain);
    Some((key, out))
}

/// Where the session ID starts in a ClientHello message: after the
/// four-byte header, the version, the random and the session ID's length.
const SESSION_ID: usize = 4 + 2 + 32 + 1;

/// What the server needs of a ClientHello.
#[derive(Debug, Default)]
struct ClientHello<'a> {
    /// The handshake message, header included.
    message: &'a [u8],
    random: [u8; 32],
    server_name: Option<String>,
    /// The client's X25519 share: its own, or that in X25519MLKEM768.
    x25519: Option<[u8; 32]>,
    tls13: bool,
    /// Where the first signature algorithm is, from the start of the body,
    /// and what it is, unless Ed25519 is offered already.
    sigalgs_to_swap: Option<(usize, [u8; 2])>,
}

/// A cursor over a ClientHello that fails rather than panics.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.buf.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

fn parse_client_hello(message: &[u8]) -> Option<ClientHello<'_>> {
    let mut hello = ClientHello {
        message,
        ..Default::default()
    };
    let mut r = Reader {
        buf: message,
        pos: 0,
    };
    if r.u8()? != 1 {
        return None;
    }
    r.take(3)?;
    r.u16()?; // legacy version
    hello.random = r.take(32)?.try_into().ok()?;
    if r.vec8()?.len() != 32 {
        return None;
    }
    r.vec16()?; // cipher suites
    r.vec8()?; // compression methods
    let extensions = r.vec16()?;
    let extensions_start = r.pos - extensions.len();
    let mut e = Reader {
        buf: extensions,
        pos: 0,
    };
    while e.pos < extensions.len() {
        let typ = e.u16()?;
        let data = e.vec16()?;
        let data_start = extensions_start + e.pos - data.len();
        let mut d = Reader { buf: data, pos: 0 };
        match typ {
            // server_name
            0 => {
                let mut list = Reader {
                    buf: d.vec16()?,
                    pos: 0,
                };
                if list.u8()? == 0 {
                    hello.server_name = String::from_utf8(list.vec16()?.to_vec()).ok();
                }
            }
            // signature_algorithms
            13 => {
                let list = d.vec16()?;
                if list.len() < 2 || list.len() % 2 != 0 {
                    return None;
                }
                if !list.chunks(2).any(|a| a == SIGN_ED25519) {
                    // After the list's two-byte length; the body starts
                    // after the four-byte header.
                    hello.sigalgs_to_swap = Some((data_start + 2 - 4, [list[0], list[1]]));
                }
            }
            // supported_versions
            43 => hello.tls13 = d.vec8()?.chunks(2).any(|v| v == [3, 4]),
            // key_share
            51 => {
                let mut shares = Reader {
                    buf: d.vec16()?,
                    pos: 0,
                };
                let mut mlkem = None;
                while shares.pos < shares.buf.len() {
                    let group = shares.u16()?;
                    let key = shares.vec16()?;
                    match group {
                        X25519 if key.len() == 32 && hello.x25519.is_none() => {
                            hello.x25519 = key.try_into().ok();
                        }
                        X25519_MLKEM768 if key.len() == MLKEM768_ENCAPSULATION_KEY + 32 => {
                            mlkem = key[MLKEM768_ENCAPSULATION_KEY..].try_into().ok();
                        }
                        _ => {}
                    }
                }
                // As a standalone X25519 share comes first for Xray too.
                hello.x25519 = hello.x25519.or(mlkem);
            }
            _ => {}
        }
    }
    Some(hello)
}

/// Reads until a whole ClientHello is in `raw`, which keeps every byte
/// read. Returns the message, or None if what came is not one.
async fn read_client_hello<S: AsyncRead + Unpin>(
    stream: &mut S,
    raw: &mut Vec<u8>,
) -> io::Result<Option<Vec<u8>>> {
    async fn fill<S: AsyncRead + Unpin>(
        s: &mut S,
        raw: &mut Vec<u8>,
        n: usize,
    ) -> io::Result<bool> {
        let mut buf = [0u8; 4096];
        while raw.len() < n {
            let got = s.read(&mut buf).await?;
            if got == 0 {
                return Ok(false);
            }
            raw.extend_from_slice(&buf[..got]);
        }
        Ok(true)
    }
    let mut message = Vec::new();
    let mut pos = 0;
    loop {
        if !fill(stream, raw, pos + 5).await? {
            return Ok(None);
        }
        let header = &raw[pos..pos + 5];
        if header[0] != 0x16 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len == 0 || len > 16384 + 256 {
            return Ok(None);
        }
        if !fill(stream, raw, pos + 5 + len).await? {
            return Ok(None);
        }
        message.extend_from_slice(&raw[pos + 5..pos + 5 + len]);
        pos += 5 + len;
        if message.len() >= 4 {
            let body = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
            if message[0] != 1 || body + 4 > MAX_CLIENT_HELLO {
                return Ok(None);
            }
            if message.len() >= body + 4 {
                message.truncate(body + 4);
                return Ok(Some(message));
            }
        }
        if raw.len() > MAX_CLIENT_HELLO {
            return Ok(None);
        }
    }
}

/// A stream that first yields bytes already read from it.
struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Relays a connection that is not ours to the handshake server: what
/// was read of it first, then both ways until either side is done.
async fn relay(mut stream: AnyStream, raw: Vec<u8>, target: (String, u16)) {
    let result = async {
        let mut remote = tokio::net::TcpStream::connect((target.0.as_str(), target.1)).await?;
        remote.write_all(&raw).await?;
        tokio::io::copy_bidirectional(&mut stream, &mut remote).await
    }
    .await;
    if let Err(e) = result {
        tracing::debug!("reality: relay to {}:{}: {}", target.0, target.1, e);
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        mut stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let mut raw = Vec::new();
        let message = read_client_hello(&mut stream, &mut raw).await?;
        let hello = message.as_deref().and_then(parse_client_hello);
        let Some((auth_key, hello)) =
            hello.and_then(|hello| Some((self.authenticate(&hello)?, hello)))
        else {
            // Relayed outside the handshake deadline: the site may take as
            // long as it takes.
            tokio::spawn(relay(stream, raw, self.handshake.clone()));
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "reality: not authenticated, relayed to the handshake server",
            ));
        };
        let connection = self.connection(&auth_key, &hello)?;
        let stream = Prefixed {
            prefix: raw,
            pos: 0,
            inner: stream,
        };
        let mut stream = TlsStream::new(connection, stream, Some(VisionState::of(&sess)));
        stream
            .handshake()
            .await
            .map_err(|e| io::Error::other(format!("reality handshake failed: {}", e)))?;
        Ok(InboundTransport::Stream(Box::new(stream), sess))
    }
}

#[cfg(all(test, feature = "outbound-reality"))]
mod tests {
    use super::*;
    use crate::transport::tls::Fingerprint;

    fn keys() -> ([u8; 32], [u8; 32]) {
        let private = [3u8; 32];
        let mut public = [0u8; 32];
        // SAFETY: both are 32 bytes.
        unsafe { btls_sys::X25519_public_from_private(public.as_mut_ptr(), private.as_ptr()) };
        (private, public)
    }

    fn server(max_time_difference: Option<Duration>) -> Handler {
        let (private, _) = keys();
        Handler::new(
            "www.example.com".to_string(),
            &hex::encode(private),
            &["ab12".to_string()],
            max_time_difference,
            ("127.0.0.1".to_string(), 1),
        )
        .unwrap()
    }

    // The ClientHello sail's REALITY client sends for `fingerprint`.
    fn client_hello(fingerprint: Fingerprint, short_id: &str, server_name: &str) -> Vec<u8> {
        let (_, public) = keys();
        let client = crate::transport::reality::outbound::Handler::new(
            server_name.to_string(),
            &hex::encode(public),
            short_id,
            fingerprint,
        )
        .unwrap();
        let mut conn = client.connection().unwrap();
        let mut wire = vec![];
        {
            use crate::transport::tls_stream::TlsConnection;
            while conn.wants_write() {
                conn.write_tls(&mut wire).unwrap();
            }
        }
        let mut raw = Vec::new();
        // Reading a slice never waits.
        futures::executor::block_on(read_client_hello(&mut &wire[..], &mut raw))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn test_authenticates_our_client() {
        let server = server(Some(Duration::from_secs(60)));
        for fingerprint in [
            Fingerprint::Chrome,
            Fingerprint::Firefox,
            Fingerprint::Safari,
        ] {
            let hello = client_hello(fingerprint, "ab12", "www.example.com");
            let parsed = parse_client_hello(&hello).unwrap();
            assert!(parsed.tls13);
            assert!(server.authenticate(&parsed).is_some(), "{:?}", fingerprint);
            // Chrome and Safari do not offer Ed25519; the swap is set up.
            if fingerprint != Fingerprint::Firefox {
                let (offset, original) = parsed.sigalgs_to_swap.unwrap();
                assert_eq!(&hello[4 + offset..4 + offset + 2], &original);
            }
        }
    }

    #[test]
    fn test_refuses_others() {
        let server = server(None);
        let wrong_id = client_hello(Fingerprint::Chrome, "cd", "www.example.com");
        assert!(server
            .authenticate(&parse_client_hello(&wrong_id).unwrap())
            .is_none());
        let wrong_name = client_hello(Fingerprint::Chrome, "ab12", "other.example.com");
        assert!(server
            .authenticate(&parse_client_hello(&wrong_name).unwrap())
            .is_none());
        // Any change to the ClientHello breaks the seal.
        let mut tampered = client_hello(Fingerprint::Chrome, "ab12", "www.example.com");
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(server
            .authenticate(&parse_client_hello(&tampered).unwrap())
            .is_none());
    }

    #[test]
    fn test_parse_never_panics_on_truncation() {
        let hello = client_hello(Fingerprint::Chrome, "ab12", "www.example.com");
        for cut in 0..hello.len() {
            let _ = parse_client_hello(&hello[..cut]);
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_across_records() {
        let hello = client_hello(Fingerprint::Chrome, "ab12", "www.example.com");
        let mut wire = Vec::new();
        for chunk in hello.chunks(300) {
            wire.extend_from_slice(&[0x16, 3, 1, (chunk.len() >> 8) as u8, chunk.len() as u8]);
            wire.extend_from_slice(chunk);
        }
        wire.extend_from_slice(b"after");
        let mut raw = Vec::new();
        let message = read_client_hello(&mut &wire[..], &mut raw).await.unwrap();
        assert_eq!(message.unwrap(), hello);
        assert!(wire.starts_with(&raw));

        let mut raw = Vec::new();
        let got = read_client_hello(&mut &b"GET / HTTP/1.1\r\n\r\n"[..], &mut raw)
            .await
            .unwrap();
        assert!(got.is_none());
        assert_eq!(raw, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn test_certificate_carries_the_hmac() {
        let server = server(None);
        let key = [9u8; 32];
        let cert = server.certificate_for(&key).unwrap();
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&key).unwrap();
        mac.update(&server.public_key);
        assert_eq!(
            cert.signature().as_slice(),
            &mac.finalize().into_bytes()[..]
        );
        assert_eq!(cert.public_key().unwrap().id(), Id::ED25519);
    }
}
