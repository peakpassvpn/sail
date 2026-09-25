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
    let client = TlsClient::new(&[], Some(&server.cert_pem), false).unwrap();
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
    let trusting = TlsClient::new(&[], Some(&server.cert_pem), false).unwrap();
    let (c, _) = pair(&server, &trusting, "example.com", None, None).await;
    assert!(c.is_err(), "the certificate is not for example.com");

    let bundled = TlsClient::new(&[], None, false).unwrap();
    let (c, _) = pair(&server, &bundled, "localhost", None, None).await;
    assert!(c.is_err(), "a self-signed certificate is not trusted");

    let insecure = TlsClient::new(&[], None, true).unwrap();
    let (c, s) = pair(&server, &insecure, "example.com", None, None).await;
    assert!(c.is_ok() && s.is_ok());
}

// Vision: after TLS records, both sides switch to the raw transport. Exact
// reads must not take raw bytes into BoringSSL.
#[tokio::test]
async fn test_vision_switch_to_raw() {
    let server = server();
    let client = TlsClient::new(&[], Some(&server.cert_pem), false).unwrap();
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
