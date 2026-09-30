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
        pins: super::PublicKeyPins::parse(&pins).unwrap(),
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
