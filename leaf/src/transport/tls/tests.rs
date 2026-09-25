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
}

fn server() -> Server {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder
        .set_certificate(&X509::from_pem(cert.pem().as_bytes()).unwrap())
        .unwrap();
    builder
        .set_private_key(&PKey::private_key_from_pem(key_pair.serialize_pem().as_bytes()).unwrap())
        .unwrap();
    Server {
        acceptor: builder.build(),
        cert_pem: cert.pem(),
    }
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
    let client = TlsClient::new(&[], Some(&server.cert_pem), false, None).unwrap();
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
    let trusting = TlsClient::new(&[], Some(&server.cert_pem), false, None).unwrap();
    let (c, _) = pair(&server, &trusting, "example.com", None, None).await;
    assert!(c.is_err(), "the certificate is not for example.com");

    let bundled = TlsClient::new(&[], None, false, None).unwrap();
    let (c, _) = pair(&server, &bundled, "localhost", None, None).await;
    assert!(c.is_err(), "a self-signed certificate is not trusted");

    let insecure = TlsClient::new(&[], None, true, None).unwrap();
    let (c, s) = pair(&server, &insecure, "example.com", None, None).await;
    assert!(c.is_ok() && s.is_ok());
}

// Vision: after TLS records, both sides switch to the raw transport. Exact
// reads must not take raw bytes into BoringSSL.
#[tokio::test]
async fn test_vision_switch_to_raw() {
    let server = server();
    let client = TlsClient::new(&[], Some(&server.cert_pem), false, None).unwrap();
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
    let chrome = fixture("chrome-153");
    let client = TlsClient::new(&[], None, false, Some(Fingerprint::Chrome)).unwrap();
    // Several connections: GREASE and the extension order change each time.
    for _ in 0..8 {
        let mut conn = client.connection("localhost", None).unwrap();
        assert_same_hello(&first_hello(&mut conn), &chrome);
    }
}

#[test]
fn test_no_fingerprint_is_not_chrome() {
    use super::hello::fixture;
    let client = TlsClient::new(&[], None, false, None).unwrap();
    let mut conn = client.connection("localhost", None).unwrap();
    assert_ne!(first_hello(&mut conn).ja4(), fixture("chrome-153").ja4());
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
// network: `cargo test -- --ignored chrome_against_real_sites`.
#[tokio::test]
#[ignore]
async fn chrome_against_real_sites() {
    use super::Fingerprint;
    let client = TlsClient::new(&[], None, false, Some(Fingerprint::Chrome)).unwrap();
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
            tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
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
        eprintln!("{}: alpn={:?} read {} bytes", host, alpn, n);
        assert!(n > 0, "{}", host);
    }
}
