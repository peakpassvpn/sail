//! A btls client and server talking over an in-memory pipe.

use btls::pkey::PKey;
use btls::ssl::{Ssl, SslAcceptor, SslMethod};
use btls::x509::X509;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::{BoringConnection, TlsClient};
use crate::transport::tls_stream::TlsStream;
use crate::transport::vision::VisionState;

struct Server {
    acceptor: SslAcceptor,
    cert_pem: String,
    /// The pin of its certificate's key, as `certificate_public_key_sha256`
    /// takes it.
    pin: String,
}

/// The roots tests trust when they give no certificate: Mozilla's.
pub(crate) fn test_roots() -> super::roots::Roots {
    super::roots::Roots::of(crate::config::model::CertificateStore::Mozilla).unwrap()
}

/// A self-signed certificate for `localhost`, as PEM.
pub(crate) fn self_signed_pem() -> String {
    server().cert_pem
}

fn server() -> Server {
    server_with(|_| {})
}

/// `server`, `configure` run on its acceptor.
fn server_with(configure: impl FnOnce(&mut btls::ssl::SslAcceptorBuilder)) -> Server {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    configure(&mut builder);
    builder
        .set_certificate(&X509::from_pem(cert.pem().as_bytes()).unwrap())
        .unwrap();
    builder
        .set_private_key(&PKey::private_key_from_pem(key_pair.serialize_pem().as_bytes()).unwrap())
        .unwrap();
    Server {
        acceptor: builder.build(),
        cert_pem: cert.pem(),
        pin: spki_pin(&key_pair.public_key_der()),
    }
}

/// The pin of a SubjectPublicKeyInfo: its SHA-256, base64. What rcgen
/// writes, not what BoringSSL reads back, so that the two are checked
/// against each other.
pub(crate) fn spki_pin(spki_der: &[u8]) -> String {
    btls::base64::encode_block(&btls::sha::sha256(spki_der))
}

/// A client with `options`, trusting the bundled roots only, or any
/// certificate if `insecure`.
pub(crate) fn client_with(
    insecure: bool,
    fingerprint: Option<super::Fingerprint>,
    options: &super::ClientOptions,
) -> TlsClient {
    TlsClient::with_options(
        &[],
        None,
        insecure,
        fingerprint,
        &test_roots(),
        None,
        options,
    )
    .unwrap()
}

impl Server {
    async fn accept(
        &self,
        stream: DuplexStream,
        vision: Option<VisionState>,
    ) -> std::io::Result<TlsStream<BoringConnection, DuplexStream>> {
        let ssl = Ssl::new(self.acceptor.context()).unwrap();
        let mut stream = TlsStream::new(BoringConnection::server(ssl)?, stream, vision);
        stream.handshake().await?;
        Ok(stream)
    }
}

async fn pair(
    server: &Server,
    client: &TlsClient,
    server_name: &str,
    client_vision: Option<VisionState>,
    server_vision: Option<VisionState>,
) -> (
    std::io::Result<TlsStream<BoringConnection, DuplexStream>>,
    std::io::Result<TlsStream<BoringConnection, DuplexStream>>,
) {
    let (c, s) = tokio::io::duplex(64 * 1024);
    tokio::join!(
        client.connect(server_name, c, client_vision, None),
        server.accept(s, server_vision)
    )
}

/// Whether the SSL still holds its handshake configuration: setting ALPN
/// fails once BoringSSL has freed it.
fn holds_handshake_config(ssl: &btls::ssl::SslRef) -> bool {
    use foreign_types::ForeignTypeRef;
    let alpn = b"\x08http/1.1";
    // SAFETY: a live SSL; the list is copied. Returns 0 on success.
    unsafe { btls_sys::SSL_set_alpn_protos(ssl.as_ptr(), alpn.as_ptr(), alpn.len()) == 0 }
}

#[tokio::test]
async fn test_idle_connection_frees_handshake_config() {
    let server = server();
    let client = TlsClient::new(&[], Some(&server.cert_pem), false, None, &test_roots()).unwrap();
    let before = client.connection("localhost", None).unwrap();
    assert!(holds_handshake_config(before.ssl()));

    let (c, s) = pair(&server, &client, "localhost", None, None).await;
    let (mut c, mut s) = (c.unwrap(), s.unwrap());
    assert!(!holds_handshake_config(c.conn().ssl()), "client");
    assert!(!holds_handshake_config(s.conn().ssl()), "server");
    // What the handshake settled stays.
    assert!(c.conn().ssl().peer_certificate().is_some());
    c.write_all(b"ping").await.unwrap();
    c.flush().await.unwrap();
    let mut buf = [0; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn test_round_trip_and_close() {
    let server = server();
    let client = TlsClient::new(&[], Some(&server.cert_pem), false, None, &test_roots()).unwrap();
    let (c, s) = pair(&server, &client, "localhost", None, None).await;
    let (mut c, mut s) = (c.unwrap(), s.unwrap());

    let data: Vec<u8> = (0..1_000_000u32).map(|i| (i * 7) as u8).collect();
    let echo = tokio::spawn(async move {
        let mut buf = vec![0; 1_000_000];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
        s.flush().await.unwrap();
        // The client's close_notify ends the stream cleanly.
        assert_eq!(s.read(&mut buf).await.unwrap(), 0);
        s.shutdown().await.unwrap();
    });
    c.write_all(&data).await.unwrap();
    c.flush().await.unwrap();
    let mut back = vec![0; data.len()];
    c.read_exact(&mut back).await.unwrap();
    assert!(back == data);
    c.shutdown().await.unwrap();
    let mut rest = vec![];
    c.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    echo.await.unwrap();
}

/// A transport that tells whether its write side was shut down: whether a
/// FIN would have gone out.
struct Shutdowns {
    inner: DuplexStream,
    shut: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl tokio::io::AsyncRead for Shutdowns {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Shutdowns {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.shut.store(true, std::sync::atomic::Ordering::SeqCst);
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A client whose transport tells of its shutdown, and the server's stream.
async fn watched_pair() -> (
    TlsStream<BoringConnection, Shutdowns>,
    TlsStream<BoringConnection, DuplexStream>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let server = server();
    let client = TlsClient::new(&[], Some(&server.cert_pem), false, None, &test_roots()).unwrap();
    let (c, s) = tokio::io::duplex(64 * 1024);
    let shut = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let c = Shutdowns {
        inner: c,
        shut: std::sync::Arc::clone(&shut),
    };
    let (c, s) = tokio::join!(
        client.connect("localhost", c, None, None),
        server.accept(s, None)
    );
    (c.unwrap(), s.unwrap(), shut)
}

/// A half-close is the close_notify alone, as Go's CloseWrite: the peer reads
/// its end, and the transport's write side stays open (no FIN) until the
/// stream drops, so that the peer closes the TCP first.
#[tokio::test]
async fn a_half_close_sends_close_notify_and_no_fin() {
    let (mut c, mut s, shut) = watched_pair().await;
    c.shutdown().await.unwrap();
    let mut buf = [0; 16];
    assert_eq!(
        s.read(&mut buf).await.unwrap(),
        0,
        "the close_notify ends it"
    );
    assert!(!shut.load(std::sync::atomic::Ordering::SeqCst), "no FIN");
}

/// Dropped as soon as its half-close returns, a stream has still sent its
/// close_notify: the peer sees a clean end, not a truncation.
#[tokio::test]
async fn a_stream_dropped_after_its_half_close_has_sent_close_notify() {
    let (mut c, mut s, _) = watched_pair().await;
    c.shutdown().await.unwrap();
    drop(c);
    let mut buf = [0; 16];
    assert_eq!(s.read(&mut buf).await.unwrap(), 0);
}

/// After our close_notify, the peer may go on writing: we read all it sends
/// until its own end.
#[tokio::test]
async fn after_a_half_close_the_peer_is_read_to_its_end() {
    let (mut c, mut s, _) = watched_pair().await;
    c.shutdown().await.unwrap();
    let data: Vec<u8> = (0..200_000u32).map(|i| (i * 13) as u8).collect();
    let sent = data.clone();
    let peer = tokio::spawn(async move {
        let mut buf = [0; 16];
        assert_eq!(s.read(&mut buf).await.unwrap(), 0);
        s.write_all(&sent).await.unwrap();
        s.shutdown().await.unwrap();
    });
    let mut got = vec![];
    c.read_to_end(&mut got).await.unwrap();
    assert!(got == data);
    peer.await.unwrap();
}

#[tokio::test]
async fn test_certificate_verification() {
    let server = server();
    let trusting = TlsClient::new(&[], Some(&server.cert_pem), false, None, &test_roots()).unwrap();
    let (c, _) = pair(&server, &trusting, "example.com", None, None).await;
    assert!(c.is_err(), "the certificate is not for example.com");

    let bundled = TlsClient::new(&[], None, false, None, &test_roots()).unwrap();
    let (c, _) = pair(&server, &bundled, "localhost", None, None).await;
    assert!(c.is_err(), "a self-signed certificate is not trusted");

    let insecure = TlsClient::new(&[], None, true, None, &test_roots()).unwrap();
    let (c, s) = pair(&server, &insecure, "example.com", None, None).await;
    assert!(c.is_ok() && s.is_ok());
}

// Vision: after TLS records, both sides switch to the raw transport. Exact
// reads must not take raw bytes into BoringSSL.
#[tokio::test]
async fn test_vision_switch_to_raw() {
    let server = server();
    let client = TlsClient::new(&[], Some(&server.cert_pem), false, None, &test_roots()).unwrap();
    let (cv, sv) = (VisionState::default(), VisionState::default());
    cv.start();
    sv.start();
    let (c, s) = pair(
        &server,
        &client,
        "localhost",
        Some(cv.clone()),
        Some(sv.clone()),
    )
    .await;
    let (mut c, mut s) = (c.unwrap(), s.unwrap());

    // Server to client: a TLS record, then raw bytes right behind it.
    s.write_all(b"over tls").await.unwrap();
    sv.set_write_direct();
    s.write_all(b"raw from server").await.unwrap();
    s.flush().await.unwrap();

    let mut buf = [0; 8];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"over tls");
    cv.set_direct_copy();
    let mut buf = [0; 15];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"raw from server");

    // Client to server, the same.
    c.write_all(b"over tls").await.unwrap();
    cv.set_write_direct();
    c.write_all(b"raw from client").await.unwrap();
    c.flush().await.unwrap();

    let mut buf = [0; 8];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"over tls");
    sv.set_direct_copy();
    let mut buf = [0; 15];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"raw from client");
}

/// The ClientHello a client connection writes first.
pub(crate) fn first_hello(conn: &mut BoringConnection) -> super::hello::ClientHello {
    use crate::transport::tls_stream::TlsConnection;
    let mut wire = vec![];
    while conn.wants_write() {
        conn.write_tls(&mut wire).unwrap();
    }
    super::hello::ClientHello::from_records(&wire)
}

#[test]
fn test_chrome_client_hello_matches_capture() {
    use super::hello::{assert_same_hello, fixture};
    use super::Fingerprint;
    let chrome = fixture("chrome-154");
    let android = fixture("chrome-android-154");
    let client =
        TlsClient::new(&[], None, false, Some(Fingerprint::Chrome), &test_roots()).unwrap();
    // Several connections: GREASE and the extension order change each time.
    for _ in 0..8 {
        let mut conn = client.connection("localhost", None).unwrap();
        let hello = first_hello(&mut conn);
        assert_same_hello(&hello, &chrome);
        // Chrome on Android sends the same.
        assert_same_hello(&hello, &android);
    }
}

// Firefox and Safari keep one extension order; the ClientHello must too.
fn assert_same_order(ours: &super::hello::ClientHello, capture: &super::hello::ClientHello) {
    use super::hello::is_grease;
    let order = |h: &super::hello::ClientHello| {
        h.extension_types()
            .into_iter()
            .map(|t| if is_grease(t) { 0x0a0a } else { t })
            .collect::<Vec<_>>()
    };
    assert_eq!(order(ours), order(capture), "extension order");
    assert_eq!(
        ours.ciphers
            .iter()
            .map(|c| if is_grease(*c) { 0x0a0a } else { *c })
            .collect::<Vec<_>>(),
        capture
            .ciphers
            .iter()
            .map(|c| if is_grease(*c) { 0x0a0a } else { *c })
            .collect::<Vec<_>>(),
        "cipher order"
    );
}

#[test]
fn test_firefox_client_hello_matches_capture() {
    use super::hello::{assert_same_hello, fixture};
    use super::Fingerprint;
    let firefox = fixture("firefox-156");
    let client =
        TlsClient::new(&[], None, false, Some(Fingerprint::Firefox), &test_roots()).unwrap();
    for _ in 0..4 {
        let mut conn = client.connection("localhost", None).unwrap();
        let hello = first_hello(&mut conn);
        assert_same_hello(&hello, &firefox);
        assert_same_order(&hello, &firefox);
        // Firefox's ECH GREASE has one shape: KDF, AEAD, config ID aside, and
        // the lengths.
        let ech = |h: &super::hello::ClientHello| {
            let e = h.extension(super::hello::EXT_ECH).unwrap().to_vec();
            (e.len(), e[..5].to_vec())
        };
        assert_eq!(ech(&hello), ech(&firefox), "ECH GREASE");
    }
}

#[test]
fn test_android_client_hello_matches_capture() {
    use super::hello::{assert_same_hello, fixture};
    use super::Fingerprint;
    let okhttp = fixture("android-okhttp4");
    let client =
        TlsClient::new(&[], None, false, Some(Fingerprint::Android), &test_roots()).unwrap();
    for _ in 0..4 {
        let mut conn = client.connection("localhost", None).unwrap();
        let hello = first_hello(&mut conn);
        assert_same_hello(&hello, &okhttp);
        assert_same_order(&hello, &okhttp);
    }
}

// iOS sends the same ClientHello as macOS Safari, so `ios` is the Safari
// profile.
#[test]
fn test_safari_client_hello_matches_ios_capture() {
    use super::hello::{assert_same_hello, fixture};
    use super::Fingerprint;
    let ios = fixture("ios-26");
    assert_eq!(Fingerprint::from_name("ios").unwrap(), Fingerprint::Safari);
    let client =
        TlsClient::new(&[], None, false, Some(Fingerprint::Safari), &test_roots()).unwrap();
    let mut conn = client.connection("localhost", None).unwrap();
    let hello = first_hello(&mut conn);
    assert_same_hello(&hello, &ios);
    assert_same_order(&hello, &ios);
}

#[test]
fn test_safari_client_hello_matches_capture() {
    use super::hello::{assert_same_hello, fixture};
    use super::Fingerprint;
    let safari = fixture("safari-26");
    let client =
        TlsClient::new(&[], None, false, Some(Fingerprint::Safari), &test_roots()).unwrap();
    for _ in 0..4 {
        let mut conn = client.connection("localhost", None).unwrap();
        let hello = first_hello(&mut conn);
        assert_same_hello(&hello, &safari);
        assert_same_order(&hello, &safari);
    }
}

#[test]
fn test_no_fingerprint_is_not_chrome() {
    use super::hello::fixture;
    let client = TlsClient::new(&[], None, false, None, &test_roots()).unwrap();
    let mut conn = client.connection("localhost", None).unwrap();
    assert_ne!(first_hello(&mut conn).ja4(), fixture("chrome-154").ja4());
}

// The fingerprint survives a configured ALPN: Chrome's own is h2 then
// http/1.1, and without h2 there is no ALPS.
#[test]
fn test_chrome_with_configured_alpn() {
    use super::hello::EXT_ALPN;
    use super::Fingerprint;
    let client = TlsClient::new(
        &["http/1.1".to_string()],
        None,
        false,
        Some(Fingerprint::Chrome),
        &test_roots(),
    )
    .unwrap();
    let mut conn = client.connection("localhost", None).unwrap();
    let hello = first_hello(&mut conn);
    assert_eq!(
        hello.extension(EXT_ALPN),
        Some(&b"\x00\x09\x08http/1.1"[..])
    );
    assert!(hello.extension(17613).is_none());
}

// A Chrome client still completes handshakes with a plain BoringSSL server,
// and with h2 offered, BoringSSL's server picks it when it supports it.
#[tokio::test]
async fn test_chrome_client_handshakes() {
    use super::Fingerprint;
    let server = server();
    let client = TlsClient::new(
        &[],
        Some(&server.cert_pem),
        false,
        Some(Fingerprint::Chrome),
        &test_roots(),
    )
    .unwrap();
    let (c, s) = pair(&server, &client, "localhost", None, None).await;
    let (mut c, mut s) = (c.unwrap(), s.unwrap());
    c.write_all(b"ping").await.unwrap();
    c.flush().await.unwrap();
    let mut buf = [0; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

// Real sites, including BoringSSL servers that negotiate ALPS. Needs the
// network: `cargo test -- --ignored fingerprints_against_real_sites`.
#[tokio::test]
#[ignore]
async fn fingerprints_against_real_sites() {
    use super::Fingerprint;
    for fingerprint in [
        Fingerprint::Chrome,
        Fingerprint::Firefox,
        Fingerprint::Safari,
        Fingerprint::Android,
    ] {
        let client = TlsClient::new(&[], None, false, Some(fingerprint), &test_roots()).unwrap();
        for host in [
            "www.google.com",
            "www.cloudflare.com",
            "www.apple.com",
            "www.microsoft.com",
            "github.com",
        ] {
            let tcp = tokio::net::TcpStream::connect((host, 443)).await.unwrap();
            let mut tls = client
                .connect(host, tcp, None, None)
                .await
                .unwrap_or_else(|e| panic!("{}: {}", host, e));
            let alpn = tls
                .conn()
                .ssl()
                .selected_alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).to_string());
            // An HTTP/1.1 request when h2 is not picked; with h2, the preface.
            if alpn.as_deref() == Some("h2") {
                tls.write_all(
                    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00",
                )
                .await
                .unwrap();
            } else {
                tls.write_all(
                    format!(
                        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        host
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            }
            tls.flush().await.unwrap();
            let mut buf = [0u8; 16];
            let n = tls
                .read(&mut buf)
                .await
                .unwrap_or_else(|e| panic!("{}: {}", host, e));
            eprintln!(
                "{:?} {}: alpn={:?} read {} bytes",
                fingerprint, host, alpn, n
            );
            assert!(n > 0, "{}", host);
        }
    }
}

// `random` picks one of the browsers once, and keeps it.
#[test]
fn test_random_fingerprint_is_a_browser_kept_for_the_process() {
    use super::Fingerprint;
    let picked = Fingerprint::from_name("random").unwrap();
    assert!(matches!(
        picked,
        Fingerprint::Chrome | Fingerprint::Firefox | Fingerprint::Safari
    ));
    for _ in 0..16 {
        assert_eq!(Fingerprint::from_name("random").unwrap(), picked);
    }
    assert!(Fingerprint::from_name("randomized").is_err());
}

/// A CA, and a client certificate it issued with the certificate's key:
/// PEM, each.
pub(crate) struct ClientPki {
    pub ca: String,
    pub cert: String,
    pub key: String,
}

pub(crate) fn client_pki() -> ClientPki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name = rcgen::DistinguishedName::new();
    ca.distinguished_name
        .push(rcgen::DnType::CommonName, "sail test CA");
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut cert = rcgen::CertificateParams::new(vec!["client".into()]).unwrap();
    cert.distinguished_name = rcgen::DistinguishedName::new();
    cert.distinguished_name
        .push(rcgen::DnType::CommonName, "client");
    let cert = cert.signed_by(&key, &ca, &ca_key).unwrap();
    ClientPki {
        ca: ca.pem(),
        cert: cert.pem(),
        key: key.serialize_pem(),
    }
}

/// The identity of `pki`'s client certificate.
fn identity(pki: &ClientPki) -> super::client::Identity {
    super::client::Identity::new(
        X509::stack_from_pem(pki.cert.as_bytes()).unwrap(),
        PKey::private_key_from_pem(pki.key.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// A server that wants a client certificate `ca` issued.
fn server_asking(ca: &str) -> Server {
    let ca = X509::from_pem(ca.as_bytes()).unwrap();
    server_with(|builder| {
        use btls::ssl::SslVerifyMode;
        builder.cert_store_mut().add_cert(ca).unwrap();
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    })
}

#[tokio::test]
async fn test_client_certificate() {
    let pki = client_pki();
    let server = server_asking(&pki.ca);
    let client = TlsClient::with_identity(
        &[],
        Some(&server.cert_pem),
        false,
        Some(super::Fingerprint::Chrome),
        &test_roots(),
        Some(&identity(&pki)),
    )
    .unwrap();
    let (c, s) = pair(&server, &client, "localhost", None, None).await;
    let (mut c, mut s) = (c.unwrap(), s.unwrap());
    assert!(s.conn().ssl().peer_certificate().is_some());
    c.write_all(b"ping").await.unwrap();
    c.flush().await.unwrap();
    let mut buf = [0; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // Without one, the server fails the handshake.
    let client = TlsClient::new(&[], Some(&server.cert_pem), false, None, &test_roots()).unwrap();
    let (_, s) = pair(&server, &client, "localhost", None, None).await;
    assert!(s.is_err());

    // One of another CA is refused too.
    let other = client_pki();
    let client = TlsClient::with_identity(
        &[],
        Some(&server.cert_pem),
        false,
        None,
        &test_roots(),
        Some(&identity(&other)),
    )
    .unwrap();
    let (_, s) = pair(&server, &client, "localhost", None, None).await;
    assert!(s.is_err());
}

#[test]
fn test_identity_key_must_match() {
    let (a, b) = (client_pki(), client_pki());
    let err = super::client::Identity::new(
        X509::stack_from_pem(a.cert.as_bytes()).unwrap(),
        PKey::private_key_from_pem(b.key.as_bytes()).unwrap(),
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("not the certificate's"), "{}", err);
}

#[tokio::test]
async fn test_without_sni() {
    use btls::ssl::NameType;
    let server = server();
    let with = TlsClient::new(&[], Some(&server.cert_pem), false, None, &test_roots()).unwrap();
    let (c, s) = pair(&server, &with, "localhost", None, None).await;
    assert!(c.is_ok());
    assert_eq!(
        s.unwrap().conn().ssl().servername(NameType::HOST_NAME),
        Some("localhost")
    );

    let without = TlsClient::new(&[], Some(&server.cert_pem), false, None, &test_roots())
        .unwrap()
        .without_sni();
    let (c, s) = pair(&server, &without, "localhost", None, None).await;
    assert!(c.is_ok());
    assert_eq!(
        s.unwrap().conn().ssl().servername(NameType::HOST_NAME),
        None
    );
    // The certificate is still verified against the name.
    let (c, _) = pair(&server, &without, "example.com", None, None).await;
    assert!(c.is_err(), "the certificate is not for example.com");
}

// With a browser's ClientHello or BoringSSL's own, the extension is gone.
#[test]
fn test_client_hello_without_sni() {
    use super::hello::EXT_SERVER_NAME;
    use super::Fingerprint;
    for fingerprint in [
        None,
        Some(Fingerprint::Chrome),
        Some(Fingerprint::Firefox),
        Some(Fingerprint::Safari),
        Some(Fingerprint::Android),
    ] {
        let client = TlsClient::new(&[], None, false, fingerprint, &test_roots()).unwrap();
        let mut conn = client.connection("localhost", None).unwrap();
        assert!(first_hello(&mut conn).extension(EXT_SERVER_NAME).is_some());
        let client = client.without_sni();
        let mut conn = client.connection("localhost", None).unwrap();
        let hello = first_hello(&mut conn);
        assert!(
            hello.extension(EXT_SERVER_NAME).is_none(),
            "{:?}",
            fingerprint
        );
    }
}

/// Options pinning `pins`.
fn pinning(pins: &[&str]) -> super::ClientOptions {
    let pins: Vec<String> = pins.iter().map(|p| p.to_string()).collect();
    super::ClientOptions {
        pins: super::PublicKeyPins::parse(&pins)
            .unwrap()
            .map(super::Pins::PublicKeys),
        ..Default::default()
    }
}

// The server's certificate is taken by the key it pins, in place of the
// roots and of the name, as sing-box takes it: self-signed, and for
// localhost while example.com is asked for.
#[tokio::test]
async fn test_pinned_key_connects() {
    let server = server();
    let other = btls::base64::encode_block(&[9; 32]);
    for fingerprint in [None, Some(super::Fingerprint::Chrome)] {
        for insecure in [false, true] {
            let client = client_with(insecure, fingerprint, &pinning(&[&other, &server.pin]));
            for name in ["localhost", "example.com"] {
                let (c, s) = pair(&server, &client, name, None, None).await;
                let (mut c, mut s) = (c.unwrap(), s.unwrap());
                c.write_all(b"ping").await.unwrap();
                c.flush().await.unwrap();
                let mut buf = [0; 4];
                s.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
            }
        }
    }
}

// A key not pinned fails the handshake, saying which key it was; with
// `insecure` too, as in sing-box, where the pins are checked whatever
// `insecure` says.
#[tokio::test]
async fn test_unpinned_key_fails() {
    let server = server();
    let other = btls::base64::encode_block(&[9; 32]);
    for fingerprint in [None, Some(super::Fingerprint::Chrome)] {
        for insecure in [false, true] {
            let client = client_with(insecure, fingerprint, &pinning(&[&other]));
            let (c, s) = pair(&server, &client, "localhost", None, None).await;
            let err = c.err().expect("an unpinned key is refused").to_string();
            assert!(
                err.contains("certificate_public_key_sha256: the server's public key")
                    && err.contains(&server.pin)
                    && err.contains("is not pinned"),
                "{}",
                err
            );
            // The server is told, with an alert.
            assert!(s.is_err());
        }
    }
    // The certificate trusted, all the same.
    let client = TlsClient::with_options(
        &[],
        Some(&server.cert_pem),
        false,
        None,
        &test_roots(),
        None,
        &pinning(&[&other]),
    )
    .unwrap();
    let (c, _) = pair(&server, &client, "localhost", None, None).await;
    assert!(c.is_err());
}

/// The TLS version `client` and `server` settle on, or the handshake's
/// error.
async fn negotiated(server: &Server, client: &TlsClient) -> Result<&'static str, String> {
    let (c, s) = pair(server, client, "localhost", None, None).await;
    let c = c.map_err(|e| e.to_string())?;
    s.map_err(|e| e.to_string())?;
    Ok(c.conn().ssl().version_str())
}

#[tokio::test]
async fn test_version_range() {
    use super::options::Version;
    use super::TlsVersionRange;
    let insecure = |fingerprint, min, max| {
        client_with(
            true,
            fingerprint,
            &super::ClientOptions {
                versions: TlsVersionRange { min, max },
                pins: None,
            },
        )
    };
    let server = server();
    let tls12_server = server_with(|builder| {
        builder
            .set_max_proto_version(Some(btls::ssl::SslVersion::TLS1_2))
            .unwrap();
    });
    for fingerprint in [None, Some(super::Fingerprint::Chrome)] {
        let default = insecure(fingerprint, None, None);
        assert_eq!(negotiated(&server, &default).await, Ok("TLSv1.3"));
        assert_eq!(negotiated(&tls12_server, &default).await, Ok("TLSv1.2"));
        // A range set is kept to, the fingerprint's or not.
        let tls12 = insecure(fingerprint, None, Some(Version::Tls12));
        assert_eq!(negotiated(&server, &tls12).await, Ok("TLSv1.2"));
        let tls13 = insecure(fingerprint, Some(Version::Tls13), None);
        assert_eq!(negotiated(&server, &tls13).await, Ok("TLSv1.3"));
        assert!(negotiated(&tls12_server, &tls13).await.is_err());
    }
}

/// A root CA, an intermediate it issued and a leaf for `localhost` the
/// intermediate issued, with a CA that issued none of them; PEM, and the
/// `certificate_sha256` pin of each.
pub(crate) struct CertChain {
    pub leaf: String,
    pub leaf_key: String,
    pub intermediate: String,
    pub root: String,
    pub unrelated: String,
    pub leaf_pin: String,
    pub intermediate_pin: String,
    pub root_pin: String,
    pub unrelated_pin: String,
}

/// The pin of a certificate, `certificate_sha256`'s: the SHA-256 of its
/// DER, hex.
pub(crate) fn certificate_pin(der: &[u8]) -> String {
    btls::sha::sha256(der)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub(crate) fn cert_chain() -> CertChain {
    cert_chain_with(|_| {})
}

/// `cert_chain`, `validity` run on what the leaf is made from.
fn cert_chain_with(validity: impl FnOnce(&mut rcgen::CertificateParams)) -> CertChain {
    let ca = |name: &str| {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params
    };
    let root_key = rcgen::KeyPair::generate().unwrap();
    let root = ca("sail test root").self_signed(&root_key).unwrap();
    let intermediate_key = rcgen::KeyPair::generate().unwrap();
    let intermediate = ca("sail test intermediate")
        .signed_by(&intermediate_key, &root, &root_key)
        .unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    validity(&mut params);
    let leaf = params
        .signed_by(&leaf_key, &intermediate, &intermediate_key)
        .unwrap();
    let unrelated_key = rcgen::KeyPair::generate().unwrap();
    let unrelated = ca("sail test unrelated")
        .self_signed(&unrelated_key)
        .unwrap();
    CertChain {
        leaf_pin: certificate_pin(leaf.der()),
        intermediate_pin: certificate_pin(intermediate.der()),
        root_pin: certificate_pin(root.der()),
        unrelated_pin: certificate_pin(unrelated.der()),
        leaf: leaf.pem(),
        leaf_key: leaf_key.serialize_pem(),
        intermediate: intermediate.pem(),
        root: root.pem(),
        unrelated: unrelated.pem(),
    }
}

/// A server presenting `certs`, PEM, the leaf first, with the leaf's `key`.
fn server_presenting(certs: &[&str], key: &str) -> Server {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    let mut certs = certs
        .iter()
        .map(|pem| X509::from_pem(pem.as_bytes()).unwrap());
    builder.set_certificate(&certs.next().unwrap()).unwrap();
    for cert in certs {
        builder.add_extra_chain_cert(cert).unwrap();
    }
    builder
        .set_private_key(&PKey::private_key_from_pem(key.as_bytes()).unwrap())
        .unwrap();
    Server {
        acceptor: builder.build(),
        cert_pem: String::new(),
        pin: String::new(),
    }
}

/// Options pinning the certificates of `pins`.
fn pinning_certificates(pins: &[&str]) -> super::ClientOptions {
    let pins: Vec<String> = pins.iter().map(|p| p.to_string()).collect();
    super::ClientOptions {
        pins: super::CertificatePins::parse(&pins)
            .unwrap()
            .map(super::Pins::Certificates),
        ..Default::default()
    }
}

/// Whether a client with `options` completes a handshake with `server` as
/// `name`, and exchanges data; the client's error if not.
async fn connects(
    server: &Server,
    insecure: bool,
    fingerprint: Option<super::Fingerprint>,
    options: &super::ClientOptions,
    name: &str,
) -> Result<(), String> {
    let client = client_with(insecure, fingerprint, options);
    let (c, s) = pair(server, &client, name, None, None).await;
    let mut c = c.map_err(|e| e.to_string())?;
    let mut s = s.map_err(|e| format!("the server: {}", e))?;
    c.write_all(b"ping").await.unwrap();
    c.flush().await.unwrap();
    let mut buf = [0; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    Ok(())
}

// A pin of the leaf takes it outright: no CA, and no name either, the
// certificate being trusted for any server name; whatever `insecure`.
#[tokio::test]
async fn test_certificate_pin_of_the_leaf() {
    let chain = cert_chain();
    for server in [
        server_presenting(&[&chain.leaf], &chain.leaf_key),
        server_presenting(&[&chain.leaf, &chain.intermediate], &chain.leaf_key),
    ] {
        // Colons and upper case, as `openssl x509 -fingerprint` writes it.
        let colons = chain
            .leaf_pin
            .to_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|p| std::str::from_utf8(p).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        for pin in [&chain.leaf_pin, &colons] {
            let options = pinning_certificates(&[&chain.unrelated_pin, pin]);
            for fingerprint in [None, Some(super::Fingerprint::Chrome)] {
                for insecure in [false, true] {
                    for name in ["localhost", "example.com", "127.0.0.1"] {
                        let result = connects(&server, insecure, fingerprint, &options, name).await;
                        assert_eq!(result, Ok(()), "{} {}", name, insecure);
                    }
                }
            }
        }
    }
}

// A pin of a certificate after the leaf is the only CA the leaf is
// verified by, and the name is verified, whatever `insecure`.
#[tokio::test]
async fn test_certificate_pin_of_a_ca() {
    let chain = cert_chain();
    let full = server_presenting(
        &[&chain.leaf, &chain.intermediate, &chain.root],
        &chain.leaf_key,
    );
    for pin in [&chain.intermediate_pin, &chain.root_pin] {
        let options = pinning_certificates(&[pin]);
        for fingerprint in [None, Some(super::Fingerprint::Chrome)] {
            for insecure in [false, true] {
                assert_eq!(
                    connects(&full, insecure, fingerprint, &options, "localhost").await,
                    Ok(())
                );
                let err = connects(&full, insecure, fingerprint, &options, "example.com")
                    .await
                    .unwrap_err();
                assert!(
                    err.contains("certificate_sha256: the server's certificate")
                        && err.contains(&chain.leaf_pin)
                        && err.contains(&format!("is not verified by the pinned {}", pin))
                        && err.contains("Hostname mismatch"),
                    "{}",
                    err
                );
            }
        }
    }
    // Sent with the leaf, but not what issued it: the leaf does not chain
    // to it.
    let unrelated = server_presenting(&[&chain.leaf, &chain.unrelated], &chain.leaf_key);
    let options = pinning_certificates(&[&chain.unrelated_pin]);
    for insecure in [false, true] {
        let err = connects(&unrelated, insecure, None, &options, "localhost")
            .await
            .unwrap_err();
        assert!(
            err.contains("is not verified by the pinned")
                && err.contains("unable to get local issuer certificate"),
            "{}",
            err
        );
    }
    // The root pinned, the intermediate between not sent: no chain.
    let short = server_presenting(&[&chain.leaf, &chain.root], &chain.leaf_key);
    let options = pinning_certificates(&[&chain.root_pin]);
    assert!(connects(&short, false, None, &options, "localhost")
        .await
        .is_err());
}

/// Options from a client's `tls` block, `tls` the fields beside `enabled`.
fn tls_options(tls: serde_json::Value) -> super::ClientOptions {
    let mut json = serde_json::json!({ "enabled": true });
    json.as_object_mut()
        .unwrap()
        .extend(tls.as_object().unwrap().clone());
    serde_json::from_value::<crate::transport::layers::OutboundTls>(json)
        .unwrap()
        .client_options()
        .unwrap()
}

/// The `certificate_sha256` pin of a certificate as sing-box 1.15 writes
/// it: the SHA-256 of its DER, standard base64.
fn certificate_pin_base64(pem: &str) -> String {
    let der = X509::from_pem(pem.as_bytes()).unwrap().to_der().unwrap();
    btls::base64::encode_block(&btls::sha::sha256(&der))
}

// sing-box 1.15's base64 pins a certificate as the hex does: the leaf for
// any name, a CA in its chain for the leaf's name; a wrong one of either
// form fails.
#[tokio::test]
async fn test_certificate_pin_in_base64() {
    let chain = cert_chain();
    let full = server_presenting(
        &[&chain.leaf, &chain.intermediate, &chain.root],
        &chain.leaf_key,
    );
    let leaf = certificate_pin_base64(&chain.leaf);
    let root = certificate_pin_base64(&chain.root);
    let unrelated = certificate_pin_base64(&chain.unrelated);
    for (pins, name, taken) in [
        (vec![&leaf], "localhost", true),
        (vec![&leaf], "example.com", true),
        (vec![&chain.leaf_pin], "example.com", true),
        (vec![&root], "localhost", true),
        (vec![&root], "example.com", false),
        (vec![&unrelated], "localhost", false),
        (vec![&chain.unrelated_pin], "localhost", false),
        // The two forms mixed in one list.
        (vec![&chain.unrelated_pin, &leaf], "localhost", true),
        (vec![&unrelated, &chain.leaf_pin], "localhost", true),
    ] {
        let options = tls_options(serde_json::json!({ "certificate_sha256": pins }));
        for insecure in [false, true] {
            let result = connects(&full, insecure, None, &options, name).await;
            assert_eq!(result.is_ok(), taken, "{:?} {} {:?}", pins, name, result);
        }
    }
    let options = tls_options(serde_json::json!({ "certificate_sha256": [&unrelated] }));
    let err = connects(&full, false, None, &options, "localhost")
        .await
        .unwrap_err();
    assert!(
        err.contains(&leaf) && err.contains(&chain.leaf_pin),
        "{}",
        err
    );
}

// Both lists set, the server is taken if either takes it, as sing-box
// 1.15 takes it; neither, and the error says why for each.
#[tokio::test]
async fn test_certificate_and_key_pins_either() {
    let chain = cert_chain();
    let server = server_presenting(&[&chain.leaf, &chain.intermediate], &chain.leaf_key);
    let key = {
        let cert = X509::from_pem(chain.leaf.as_bytes()).unwrap();
        let spki = cert.public_key().unwrap().public_key_to_der().unwrap();
        btls::base64::encode_block(&super::PublicKeyPins::hash(&spki))
    };
    let other_key = btls::base64::encode_block(&[9; 32]);
    let leaf = certificate_pin_base64(&chain.leaf);
    let unrelated = certificate_pin_base64(&chain.unrelated);
    for (certificates, keys, taken) in [
        (&leaf, &other_key, true),
        (&unrelated, &key, true),
        (&leaf, &key, true),
        (&unrelated, &other_key, false),
    ] {
        let options = tls_options(serde_json::json!({
            "certificate_sha256": [certificates],
            "certificate_public_key_sha256": [keys],
        }));
        for fingerprint in [None, Some(super::Fingerprint::Chrome)] {
            for insecure in [false, true] {
                let result =
                    connects(&server, insecure, fingerprint, &options, "example.com").await;
                assert_eq!(
                    result.is_ok(),
                    taken,
                    "{} {} {:?}",
                    certificates,
                    keys,
                    result
                );
                if let Err(err) = result {
                    assert!(
                        err.contains("certificate_sha256: the server's certificate")
                            && err.contains(&leaf)
                            && err
                                .contains("certificate_public_key_sha256: the server's public key")
                            && err.contains(&key),
                        "{}",
                        err
                    );
                }
            }
        }
    }
}

/// A day in the one year `in_2100` makes a certificate valid for:
/// 2100-04-11, in seconds since 1970.
pub(crate) const IN_2100: u64 = 4_102_444_800 + 100 * 86_400;

/// Makes the certificate of `params` valid through the year 2100 alone.
fn in_2100(params: &mut rcgen::CertificateParams) {
    params.not_before = rcgen::date_time_ymd(2100, 1, 1);
    params.not_after = rcgen::date_time_ymd(2101, 1, 1);
}

/// A self-signed certificate for `localhost`, valid through the year 2100
/// alone, and its key; PEM.
pub(crate) fn valid_in_2100() -> (String, String) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    in_2100(&mut params);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

/// A scope whose time is `then`, in seconds since 1970, as an instance's
/// whose NTP server says so.
pub(crate) fn scope_at(then: u64) -> crate::runtime::scope::TaskScope {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let scope = crate::runtime::scope::TaskScope::default();
    scope.set_clock_offset((then as i64 - now as i64) * 1_000_000_000);
    scope
}

// A certificate's validity is checked at the instance's time (`ntp`), not
// by the system's clock: one valid in 2100 alone verifies in an instance
// whose time is then, and nowhere else; one valid today does not verify in
// an instance whose time is 1971.
#[tokio::test]
async fn a_certificate_is_valid_at_the_instance_s_time() {
    let (cert, key) = valid_in_2100();
    let server = server_presenting(&[&cert], &key);
    let client = TlsClient::new(&[], Some(&cert), false, None, &test_roots()).unwrap();
    let (c, _) = pair(&server, &client, "localhost", None, None).await;
    assert!(c.is_err(), "the certificate is not valid yet");
    let (c, s) = scope_at(IN_2100)
        .enter(pair(&server, &client, "localhost", None, None))
        .await;
    assert!(s.is_ok(), "the server");
    assert!(c.is_ok(), "{:?}", c.err());
    // The offset is the instance's, not the client's: none outside it.
    let (c, _) = pair(&server, &client, "localhost", None, None).await;
    assert!(c.is_err(), "the certificate is not valid yet");

    let server = self::server();
    let client = TlsClient::new(&[], Some(&server.cert_pem), false, None, &test_roots()).unwrap();
    let (c, _) = scope_at(365 * 86_400)
        .enter(pair(&server, &client, "localhost", None, None))
        .await;
    assert!(c.is_err(), "the certificate is not valid in 1971");
    let (c, s) = pair(&server, &client, "localhost", None, None).await;
    assert!(c.is_ok() && s.is_ok());
}

// As is one a pinned CA's certificate verifies.
#[tokio::test]
async fn a_pinned_ca_verifies_at_the_instance_s_time() {
    let chain = cert_chain_with(in_2100);
    let server = server_presenting(
        &[&chain.leaf, &chain.intermediate, &chain.root],
        &chain.leaf_key,
    );
    for pin in [&chain.intermediate_pin, &chain.root_pin] {
        let options = pinning_certificates(&[pin]);
        let err = connects(&server, false, None, &options, "localhost")
            .await
            .unwrap_err();
        assert!(err.contains("certificate is not yet valid"), "{}", err);
        let result = scope_at(IN_2100)
            .enter(connects(&server, false, None, &options, "localhost"))
            .await;
        assert_eq!(result, Ok(()));
    }
}

// A certificate pinned that the server does not send fails the handshake,
// naming the leaf's hash, in every mode.
#[tokio::test]
async fn test_certificate_pin_not_sent_fails() {
    let chain = cert_chain();
    let server = server_presenting(&[&chain.leaf, &chain.intermediate], &chain.leaf_key);
    // The root is the intermediate's issuer, but not sent.
    for pin in [&chain.unrelated_pin, &chain.root_pin] {
        let options = pinning_certificates(&[pin]);
        for fingerprint in [None, Some(super::Fingerprint::Chrome)] {
            for insecure in [false, true] {
                let err = connects(&server, insecure, fingerprint, &options, "localhost")
                    .await
                    .unwrap_err();
                assert!(
                    err.contains(&format!(
                        "certificate_sha256: the server's certificate, {} (base64 {}), is not \
                         pinned",
                        chain.leaf_pin,
                        certificate_pin_base64(&chain.leaf)
                    )),
                    "{}",
                    err
                );
            }
        }
    }
}

/// The ALPN the client settles on with a server that picks `pick`, or none;
/// or the handshake's error. The client offers h2 and http/1.1.
async fn alpn_with(pick: Option<&'static [u8]>) -> Result<Option<Vec<u8>>, String> {
    let server = server_with(|builder| {
        builder.set_alpn_select_callback(move |_, _| pick.ok_or(btls::ssl::AlpnError::NOACK));
    });
    let alpn = ["h2".to_string(), "http/1.1".to_string()];
    let client = TlsClient::new(&alpn, Some(&server.cert_pem), false, None, &test_roots()).unwrap();
    let (c, _) = pair(&server, &client, "localhost", None, None).await;
    let c = c.map_err(|e| e.to_string())?;
    Ok(c.conn().ssl().selected_alpn_protocol().map(<[u8]>::to_vec))
}

// A protocol the client did not offer fails the handshake; a server that
// picks none is taken as it is, as sing-box takes it, and a layer that needs
// one (h2 for DoH) checks for it itself.
#[tokio::test]
async fn test_negotiated_alpn() {
    assert_eq!(alpn_with(Some(b"h2")).await, Ok(Some(b"h2".to_vec())));
    assert_eq!(alpn_with(None).await, Ok(None));
    assert!(alpn_with(Some(b"h3")).await.is_err());
}

/// An ECHConfig for `public_name`, as the ECHConfigList a client offers,
/// and the keys a server decrypts what it encrypts with.
#[cfg(feature = "quic")]
pub(crate) struct EchKeys {
    /// The ECHConfigList, base64, as `tls.ech.config` takes it.
    pub config: String,
    keys: *mut btls_sys::SSL_ECH_KEYS,
}

#[cfg(feature = "quic")]
impl EchKeys {
    /// From the X25519 private key `private_key`; the server sends the
    /// config to retry with when it rejects ECH.
    pub(crate) fn new(public_name: &str, private_key: &[u8; 32]) -> Self {
        let name = std::ffi::CString::new(public_name).unwrap();
        // SAFETY: each pointer is checked, used while it lives, and freed
        // once; SSL_ECH_KEYS_add copies the key.
        unsafe {
            let key = btls_sys::EVP_HPKE_KEY_new();
            assert!(!key.is_null());
            assert_eq!(
                btls_sys::EVP_HPKE_KEY_init(
                    key,
                    btls_sys::EVP_hpke_x25519_hkdf_sha256(),
                    private_key.as_ptr(),
                    private_key.len(),
                ),
                1
            );
            let (mut out, mut out_len) = (std::ptr::null_mut(), 0);
            assert_eq!(
                btls_sys::SSL_marshal_ech_config(&mut out, &mut out_len, 1, key, name.as_ptr(), 0),
                1
            );
            let ech_config = std::slice::from_raw_parts(out, out_len).to_vec();
            btls_sys::OPENSSL_free(out.cast());
            let keys = btls_sys::SSL_ECH_KEYS_new();
            assert!(!keys.is_null());
            assert_eq!(
                btls_sys::SSL_ECH_KEYS_add(keys, 1, ech_config.as_ptr(), ech_config.len(), key),
                1
            );
            btls_sys::EVP_HPKE_KEY_free(key);
            let mut list = (ech_config.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&ech_config);
            Self {
                config: btls::base64::encode_block(&list),
                keys,
            }
        }
    }

    /// Decrypts with these keys on `ctx`, a server's.
    pub(crate) fn serve(&self, ctx: &btls::ssl::SslContextRef) {
        use foreign_types::ForeignTypeRef;
        // SAFETY: the context takes a reference of its own to the keys.
        assert_eq!(
            unsafe { btls_sys::SSL_CTX_set1_ech_keys(ctx.as_ptr(), self.keys) },
            1
        );
    }
}

#[cfg(feature = "quic")]
impl Drop for EchKeys {
    fn drop(&mut self) {
        // SAFETY: made by SSL_ECH_KEYS_new, freed only here.
        unsafe { btls_sys::SSL_ECH_KEYS_free(self.keys) }
    }
}

// ---------------------------------------------------------------------------
// Clients' certificates, as an inbound checks them (`ClientAuth`).
// ---------------------------------------------------------------------------

/// A CA of clients' certificates, and what it issues.
pub(crate) struct ClientCa {
    pub pem: String,
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

/// A client certificate and its key, PEM; its DER, and its key's
/// SubjectPublicKeyInfo.
pub(crate) struct ClientCert {
    pub pem: String,
    pub key: String,
    pub der: Vec<u8>,
    pub spki: Vec<u8>,
}

fn ca_params(name: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params
}

impl ClientCa {
    pub(crate) fn new(name: &str) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = ca_params(name).self_signed(&key).unwrap();
        Self {
            pem: cert.pem(),
            cert,
            key,
        }
    }

    /// An intermediate CA this one issues.
    pub(crate) fn intermediate(&self, name: &str) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = ca_params(name)
            .signed_by(&key, &self.cert, &self.key)
            .unwrap();
        Self {
            pem: cert.pem(),
            cert,
            key,
        }
    }

    /// A client certificate this CA issues, what it is made from changed
    /// by `tweak`.
    pub(crate) fn issue_with(
        &self,
        tweak: impl FnOnce(&mut rcgen::CertificateParams),
    ) -> ClientCert {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["client".into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "client");
        tweak(&mut params);
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        ClientCert {
            pem: cert.pem(),
            key: key.serialize_pem(),
            der: cert.der().to_vec(),
            spki: key.public_key_der(),
        }
    }

    pub(crate) fn issue(&self) -> ClientCert {
        self.issue_with(|_| {})
    }
}

impl ClientCert {
    /// The identity a client presents it with, `chain` sent after it.
    pub(crate) fn identity(&self, chain: &[&str]) -> super::client::Identity {
        let pem = std::iter::once(self.pem.as_str())
            .chain(chain.iter().copied())
            .collect::<Vec<_>>()
            .join("\n");
        super::client::Identity::new(
            X509::stack_from_pem(pem.as_bytes()).unwrap(),
            PKey::private_key_from_pem(self.key.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// Its `client_certificate_sha256` pin: base64, as sing-box 1.15's.
    pub(crate) fn pin(&self) -> String {
        btls::base64::encode_block(&btls::sha::sha256(&self.der))
    }

    /// Its `client_certificate_public_key_sha256` pin.
    pub(crate) fn key_pin(&self) -> String {
        spki_pin(&self.spki)
    }
}

/// An inbound's client-authentication fields, owned.
#[derive(Default)]
pub(crate) struct AuthFields {
    pub mode: Option<&'static str>,
    pub cas: Vec<String>,
    pub ca_files: Vec<String>,
    pub cert_pins: Vec<String>,
    pub key_pins: Vec<String>,
}

impl AuthFields {
    pub(crate) fn build(&self) -> anyhow::Result<(Option<super::ClientAuth>, Vec<String>)> {
        super::ClientAuth::new(&super::ClientAuthFields {
            mode: self.mode,
            certificate: &self.cas,
            certificate_path: &self.ca_files,
            certificate_sha256: &self.cert_pins,
            public_key_sha256: &self.key_pins,
        })
    }

    /// `build`, with no error or warning.
    pub(crate) fn auth(&self) -> Option<super::ClientAuth> {
        let (auth, warnings) = self.build().unwrap();
        assert!(warnings.is_empty(), "{:?}", warnings);
        auth
    }
}

/// A server that takes clients' certificates as `auth` says.
fn server_checking(auth: Option<&super::ClientAuth>) -> Server {
    server_with(|builder| {
        if let Some(auth) = auth {
            auth.apply(builder).unwrap();
        }
    })
}

/// Whether `server` takes a client presenting `identity`, if any, and the
/// two exchange data; the server's error if not.
async fn served(server: &Server, identity: Option<&super::client::Identity>) -> Result<(), String> {
    let client = TlsClient::with_identity(
        &[],
        Some(&server.cert_pem),
        false,
        None,
        &test_roots(),
        identity,
    )
    .unwrap();
    let (c, s) = pair(server, &client, "localhost", None, None).await;
    let mut s = s.map_err(|e| e.to_string())?;
    let mut c = c.map_err(|e| format!("the client: {}", e))?;
    c.write_all(b"ping").await.unwrap();
    c.flush().await.unwrap();
    let mut buf = [0; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    Ok(())
}

// Each mode, with a client that sends no certificate, one the CA issued,
// and one another CA did: sing-box's (Go's) table.
#[tokio::test]
async fn each_client_authentication_mode_takes_the_clients_it_should() {
    let ca = ClientCa::new("sail test client CA");
    let valid = ca.issue();
    let other = ClientCa::new("sail test other CA").issue();
    let (valid, other) = (valid.identity(&[]), other.identity(&[]));
    let with_ca = |mode| AuthFields {
        mode,
        cas: vec![ca.pem.clone()],
        ..Default::default()
    };
    let without = |mode| AuthFields {
        mode,
        ..Default::default()
    };
    for (fields, wanted) in [
        (without(None), [true, true, true]),
        (without(Some("no")), [true, true, true]),
        (without(Some("request")), [true, true, true]),
        (without(Some("require-any")), [false, true, true]),
        (with_ca(Some("verify-if-given")), [true, true, false]),
        (with_ca(Some("require-and-verify")), [false, true, false]),
        // CAs with no mode, or `no`, are require-and-verify.
        (with_ca(None), [false, true, false]),
        (with_ca(Some("no")), [false, true, false]),
    ] {
        let auth = fields.auth();
        let server = server_checking(auth.as_ref());
        let got = [
            served(&server, None).await,
            served(&server, Some(&valid)).await,
            served(&server, Some(&other)).await,
        ];
        let mode = (fields.mode, !fields.cas.is_empty());
        for ((got, wanted), client) in got.iter().zip(wanted).zip(["none", "valid", "other"]) {
            assert_eq!(
                got.is_ok(),
                wanted,
                "{:?}, {} certificate: {:?}",
                mode,
                client,
                got
            );
        }
        if let Err(e) = &got[2] {
            assert!(
                e.contains("client_certificate: the client's certificate (SHA-256 ")
                    && e.contains("is not verified by the CAs: unable to get local issuer"),
                "{}",
                e
            );
        }
    }
    let auth = AuthFields {
        cas: vec![ca.pem.clone()],
        ..Default::default()
    }
    .auth()
    .unwrap();
    assert_eq!(auth.mode(), super::ClientAuthMode::RequireAndVerify);
}

// A certificate expired, or for servers alone by its extended key usage,
// is refused as Go refuses it; one for clients is taken.
#[tokio::test]
async fn a_client_certificate_must_be_valid_and_for_clients() {
    let ca = ClientCa::new("sail test client CA");
    for mode in ["verify-if-given", "require-and-verify"] {
        let auth = AuthFields {
            mode: Some(mode),
            cas: vec![ca.pem.clone()],
            ..Default::default()
        }
        .auth();
        let server = server_checking(auth.as_ref());
        let expired = ca.issue_with(|params| {
            params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        });
        let err = served(&server, Some(&expired.identity(&[])))
            .await
            .unwrap_err();
        assert!(err.contains("certificate has expired"), "{}: {}", mode, err);
        let for_servers = ca.issue_with(|params| {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        });
        let err = served(&server, Some(&for_servers.identity(&[])))
            .await
            .unwrap_err();
        assert!(
            err.contains("unsupported certificate purpose"),
            "{}: {}",
            mode,
            err
        );
        let for_clients = ca.issue_with(|params| {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        });
        assert_eq!(
            served(&server, Some(&for_clients.identity(&[]))).await,
            Ok(())
        );
    }
}

// A client whose certificate an intermediate issued is taken when it
// sends the intermediate, and not when it leaves it out; an intermediate
// configured as the CA is an anchor of its own, as Go takes it.
#[tokio::test]
async fn a_client_certificate_chains_by_the_intermediates_it_sends() {
    let root = ClientCa::new("sail test client root");
    let intermediate = root.intermediate("sail test client intermediate");
    let cert = intermediate.issue();
    let server = server_checking(
        AuthFields {
            mode: Some("require-and-verify"),
            cas: vec![root.pem.clone()],
            ..Default::default()
        }
        .auth()
        .as_ref(),
    );
    assert_eq!(
        served(&server, Some(&cert.identity(&[&intermediate.pem]))).await,
        Ok(())
    );
    assert!(served(&server, Some(&cert.identity(&[]))).await.is_err());
    let server = server_checking(
        AuthFields {
            cas: vec![intermediate.pem.clone()],
            ..Default::default()
        }
        .auth()
        .as_ref(),
    );
    assert_eq!(served(&server, Some(&cert.identity(&[]))).await, Ok(()));
}

// Pins take a client by its leaf, whole or by its key, whoever issued it:
// either list passing, the certificate pins first, as in sing-box 1.15.
#[tokio::test]
async fn pins_take_a_client_by_its_certificate_or_its_key() {
    let cert = ClientCa::new("sail test client CA").issue();
    let other = ClientCa::new("sail test other CA").issue();
    let identity = cert.identity(&[]);
    let pinning = |cert_pins: &[&String], key_pins: &[&String]| {
        let auth = AuthFields {
            mode: Some("require-and-verify"),
            cert_pins: cert_pins.iter().map(|p| p.to_string()).collect(),
            key_pins: key_pins.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        }
        .auth();
        server_checking(auth.as_ref())
    };
    let (pin, key_pin) = (cert.pin(), cert.key_pin());
    let (other_pin, other_key_pin) = (other.pin(), other.key_pin());
    for (server, wanted) in [
        (pinning(&[&pin], &[]), true),
        (pinning(&[&other_pin, &pin], &[]), true),
        (pinning(&[], &[&key_pin]), true),
        (pinning(&[&other_pin], &[&key_pin]), true),
        (pinning(&[&pin], &[&other_key_pin]), true),
        (pinning(&[&other_pin], &[]), false),
        (pinning(&[], &[&other_key_pin]), false),
        (pinning(&[&other_pin], &[&other_key_pin]), false),
    ] {
        let got = served(&server, Some(&identity)).await;
        assert_eq!(got.is_ok(), wanted, "{:?}", got);
        // Without a certificate, require-and-verify refuses.
        assert!(served(&server, None).await.is_err());
    }
    // The leaf alone is pinned: a pin of its CA takes nobody.
    let ca = ClientCa::new("sail test pinned CA");
    let issued = ca.issue();
    let ca_pin = btls::base64::encode_block(&btls::sha::sha256(
        &X509::from_pem(ca.pem.as_bytes()).unwrap().to_der().unwrap(),
    ));
    let server = pinning(&[&ca_pin], &[]);
    let err = served(&server, Some(&issued.identity(&[&ca.pem])))
        .await
        .unwrap_err();
    assert!(
        err.contains(&format!(
            "client_certificate_sha256: the client's certificate, {} (base64 {}), is not \
             pinned",
            certificate_pin(&issued.der),
            issued.pin()
        )),
        "{}",
        err
    );
    let err = served(&pinning(&[&other_pin], &[&other_key_pin]), Some(&identity))
        .await
        .unwrap_err();
    assert!(
        err.contains("client_certificate_sha256: the client's certificate")
            && err.contains(&format!(
                "; client_certificate_public_key_sha256: the client's public key, {}, is not \
                 pinned",
                key_pin
            )),
        "{}",
        err
    );
}

// verify-if-given with pins takes a client that sends no certificate:
// sing-box 1.14 fails on it, and 1.15 takes it.
#[tokio::test]
async fn verify_if_given_with_pins_takes_a_client_without_a_certificate() {
    let cert = ClientCa::new("sail test client CA").issue();
    let other = ClientCa::new("sail test other CA").issue();
    for fields in [
        AuthFields {
            mode: Some("verify-if-given"),
            cert_pins: vec![cert.pin()],
            ..Default::default()
        },
        AuthFields {
            mode: Some("verify-if-given"),
            key_pins: vec![cert.key_pin()],
            ..Default::default()
        },
    ] {
        let server = server_checking(fields.auth().as_ref());
        assert_eq!(served(&server, None).await, Ok(()));
        assert_eq!(served(&server, Some(&cert.identity(&[]))).await, Ok(()));
        assert!(served(&server, Some(&other.identity(&[]))).await.is_err());
    }
}

// What sing-box ignores beside a field it prefers is ignored with a
// warning, and is not what clients are checked by: the inline CAs before
// the files, the CAs before the pins.
#[tokio::test]
async fn fields_sing_box_ignores_are_warned_of_and_ignored() {
    let (inline, file) = (
        ClientCa::new("sail test inline CA"),
        ClientCa::new("sail test file CA"),
    );
    let path = std::env::temp_dir().join(format!("sail-client-ca-{}.pem", std::process::id()));
    std::fs::write(&path, &file.pem).unwrap();
    let written = path.clone();
    let path = path.to_string_lossy().into_owned();
    let by_file = file.issue();

    let (auth, warnings) = AuthFields {
        cas: vec![inline.pem.clone()],
        ca_files: vec![path.clone()],
        ..Default::default()
    }
    .build()
    .unwrap();
    assert_eq!(
        warnings,
        [
            "client_certificate_path: ignored beside client_certificate, as sing-box ignores it: \
          clients are verified by the inline CAs alone"
        ]
    );
    let server = server_checking(auth.as_ref());
    assert_eq!(
        served(&server, Some(&inline.issue().identity(&[]))).await,
        Ok(())
    );
    assert!(served(&server, Some(&by_file.identity(&[]))).await.is_err());

    // The file's CAs, without inline ones, are the CAs.
    let server = server_checking(
        AuthFields {
            ca_files: vec![path.clone()],
            ..Default::default()
        }
        .auth()
        .as_ref(),
    );
    assert_eq!(served(&server, Some(&by_file.identity(&[]))).await, Ok(()));

    let pinned = ClientCa::new("sail test other CA").issue();
    for (cas, ca_files, field) in [
        (vec![inline.pem.clone()], vec![], "client_certificate"),
        (vec![], vec![path.clone()], "client_certificate_path"),
    ] {
        let (auth, warnings) = AuthFields {
            mode: Some("verify-if-given"),
            cas,
            ca_files,
            cert_pins: vec![pinned.pin()],
            key_pins: vec![pinned.key_pin()],
        }
        .build()
        .unwrap();
        assert_eq!(
            warnings,
            [format!(
                "client_certificate_sha256 and client_certificate_public_key_sha256: ignored \
                 beside {}, as sing-box ignores it: clients are verified by the CAs alone",
                field
            )]
        );
        let server = server_checking(auth.as_ref());
        let err = served(&server, Some(&pinned.identity(&[])))
            .await
            .unwrap_err();
        assert!(
            err.contains(&format!("{}: the client's certificate", field)),
            "{}",
            err
        );
    }
    std::fs::remove_file(written).unwrap();
}

// What would leave clients unchecked while it looks as if it checks them
// is an error, where sing-box takes it; so is a verifying mode with
// nothing to verify by, as in sing-box. Each names the field.
#[test]
fn client_authentication_that_checks_nothing_is_an_error() {
    let ca = ClientCa::new("sail test client CA");
    let pin = ca.issue().pin();
    let cas = || vec![ca.pem.clone()];
    let pins = || vec![pin.clone()];
    let err = |fields: AuthFields| fields.build().unwrap_err().to_string();
    for mode in [None, Some("no"), Some("")] {
        assert_eq!(
            err(AuthFields {
                mode,
                cert_pins: pins(),
                ..Default::default()
            }),
            "client_certificate_sha256: without client_authentication, or with no, no client \
             certificate is asked for, and none is checked; set it to verify-if-given or \
             require-and-verify"
        );
        assert!(err(AuthFields {
            mode,
            key_pins: pins_of_key(),
            ..Default::default()
        })
        .starts_with("client_certificate_public_key_sha256: without client_authentication"));
    }
    for mode in ["request", "require-any"] {
        assert_eq!(
            err(AuthFields {
                mode: Some(mode),
                cas: cas(),
                ..Default::default()
            }),
            format!(
                "client_certificate: client_authentication {} takes any client certificate \
                 and checks none; verify-if-given or require-and-verify check it",
                mode
            )
        );
        assert!(err(AuthFields {
            mode: Some(mode),
            ca_files: vec!["ca.pem".into()],
            ..Default::default()
        })
        .starts_with("client_certificate_path: client_authentication"));
        assert!(err(AuthFields {
            mode: Some(mode),
            cert_pins: pins(),
            ..Default::default()
        })
        .starts_with("client_certificate_sha256: client_authentication"));
    }
    for mode in ["verify-if-given", "require-and-verify"] {
        assert_eq!(
            err(AuthFields {
                mode: Some(mode),
                ..Default::default()
            }),
            format!(
                "client_authentication: {} needs client_certificate, client_certificate_path, \
                 client_certificate_sha256 or client_certificate_public_key_sha256 to verify \
                 clients by",
                mode
            )
        );
    }
    assert_eq!(
        err(AuthFields {
            mode: Some("required"),
            ..Default::default()
        }),
        "client_authentication: unknown value \"required\", one of no, request, require-any, \
         verify-if-given, require-and-verify"
    );
    assert_eq!(
        err(AuthFields {
            cas: vec!["not PEM".into()],
            ..Default::default()
        }),
        "client_certificate: not PEM certificates"
    );
    assert!(err(AuthFields {
        ca_files: vec!["/nonexistent/ca.pem".into()],
        ..Default::default()
    })
    .starts_with("client_certificate_path[0]: load certificates from /nonexistent/ca.pem"));
    // Pins are read, used or not.
    assert!(err(AuthFields {
        cas: cas(),
        key_pins: vec!["x".into()],
        ..Default::default()
    })
    .starts_with("client_certificate_public_key_sha256[0]: not base64"));
    // No field asks for a certificate: none is.
    assert!(AuthFields::default().build().unwrap().0.is_none());
    assert!(AuthFields {
        mode: Some("no"),
        ..Default::default()
    }
    .build()
    .unwrap()
    .0
    .is_none());
}

fn pins_of_key() -> Vec<String> {
    vec![spki_pin(b"a SubjectPublicKeyInfo")]
}
