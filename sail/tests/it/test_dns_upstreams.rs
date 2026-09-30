//! The encrypted DNS servers, `tls`, `https`, `quic` and `h3`, against
//! servers started here.

#![cfg(all(feature = "tls", feature = "quic", feature = "dns-h3"))]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{rdata::A, RData, Record, RecordType};

use sail::app::dns_client::DnsClient;
use sail::config;
use sail::net::DialDefaults;

/// The answer every server here gives for an A query.
const ANSWER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);

pub(crate) struct Cert {
    pub(crate) cert_pem: String,
    key_pem: String,
    /// The pin of its key, as `certificate_public_key_sha256` takes it.
    pin: String,
}

impl Cert {
    fn new(names: &[&str]) -> Cert {
        let ck = rcgen::generate_simple_self_signed(
            names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        Cert {
            cert_pem: ck.cert.pem(),
            key_pem: ck.key_pair.serialize_pem(),
            pin: btls::base64::encode_block(&btls::sha::sha256(&ck.key_pair.public_key_der())),
        }
    }
}

/// A self-signed certificate for `localhost`.
pub(crate) fn cert() -> Cert {
    Cert::new(&["localhost"])
}

/// Answers `query` with `ANSWER`; `None` when it is not a query.
fn answer(query: &[u8]) -> Option<Vec<u8>> {
    let query = Message::from_vec(query).ok()?;
    let mut resp = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    for q in &query.queries {
        resp.add_query(q.clone());
        if q.query_type() == RecordType::A {
            resp.add_answer(Record::from_rdata(
                q.name().clone(),
                60,
                RData::A(A(ANSWER)),
            ));
        }
    }
    resp.to_vec().ok()
}

#[derive(Default)]
pub(crate) struct Counters {
    connections: AtomicUsize,
    pub(crate) queries: AtomicUsize,
    /// Queries whose ID was not 0, which DoQ and DoH3 must send.
    nonzero_ids: AtomicUsize,
}

impl Counters {
    fn count(&self, query: &[u8]) {
        self.queries.fetch_add(1, Ordering::SeqCst);
        if query.len() >= 2 && query[..2] != [0, 0] {
            self.nonzero_ids.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// A DoT server on a port of its own, on threads, and that port. With
/// `close_after_answer` it closes every connection once it has answered,
/// as a server whose idle timeout has passed would.
fn start_dot_server(cert: &Cert, close_after_answer: bool) -> (u16, Arc<Counters>) {
    start_dot_server_with(cert, close_after_answer, None, None)
}

/// The SNI each connection a server took sent, if any.
type Snis = Arc<std::sync::Mutex<Vec<Option<String>>>>;

/// `start_dot_server`, asking for a client certificate `client_ca`
/// issued, when given, and keeping the SNI of each connection in `snis`.
fn start_dot_server_with(
    cert: &Cert,
    close_after_answer: bool,
    client_ca: Option<&Cert>,
    snis: Option<Snis>,
) -> (u16, Arc<Counters>) {
    use btls::pkey::PKey;
    use btls::ssl::{NameType, SslAcceptor, SslMethod, SslVerifyMode};
    use btls::x509::X509;

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert.cert_pem.as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_pem(cert.key_pem.as_bytes()).unwrap())
        .unwrap();
    if let Some(ca) = client_ca {
        acceptor
            .cert_store_mut()
            .add_cert(X509::from_pem(ca.cert_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    if let Some(snis) = snis {
        acceptor.set_servername_callback(move |ssl, _| {
            snis.lock()
                .unwrap()
                .push(ssl.servername(NameType::HOST_NAME).map(str::to_owned));
            Ok(())
        });
    }
    let acceptor = Arc::new(acceptor.build());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let counters = Arc::new(Counters::default());
    let c = counters.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let acceptor = acceptor.clone();
            let c = c.clone();
            std::thread::spawn(move || {
                let Ok(mut tls) = acceptor.accept(stream) else {
                    return;
                };
                c.connections.fetch_add(1, Ordering::SeqCst);
                loop {
                    let mut len = [0u8; 2];
                    if tls.read_exact(&mut len).is_err() {
                        return;
                    }
                    let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
                    if tls.read_exact(&mut query).is_err() {
                        return;
                    }
                    c.queries.fetch_add(1, Ordering::SeqCst);
                    let Some(resp) = answer(&query) else { return };
                    let mut out = (resp.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&resp);
                    if tls.write_all(&out).is_err() || tls.flush().is_err() {
                        return;
                    }
                    if close_after_answer {
                        let _ = tls.shutdown();
                        return;
                    }
                }
            });
        }
    });
    (port, counters)
}

/// A QUIC server endpoint on a port of its own, and that port.
fn quic_server_endpoint(cert: &Cert, alpn: &[u8]) -> (u16, quinn::Endpoint) {
    quic_server_endpoint_with(cert, alpn, None)
}

/// `quic_server_endpoint`, asking for a client certificate `client_ca`
/// issued, when given.
fn quic_server_endpoint_with(
    cert: &Cert,
    alpn: &[u8],
    client_ca: Option<&Cert>,
) -> (u16, quinn::Endpoint) {
    use btls::pkey::PKey;
    use btls::x509::X509;
    use quinn_btls::QuicSslContext;

    let mut crypto = quinn_btls::ServerConfig::new().unwrap();
    let ctx = crypto.ctx_mut();
    ctx.set_certificate(X509::from_pem(cert.cert_pem.as_bytes()).unwrap())
        .unwrap();
    ctx.set_private_key(PKey::private_key_from_pem(cert.key_pem.as_bytes()).unwrap())
        .unwrap();
    if let Some(ca) = client_ca {
        ctx.cert_store_mut()
            .add_cert(X509::from_pem(ca.cert_pem.as_bytes()).unwrap())
            .unwrap();
    }
    crypto.set_alpn(&[alpn.to_vec()]).unwrap();
    // Asks for a certificate, and fails without one.
    if client_ca.is_some() {
        crypto.verify_peer(true);
    }
    let server_config = quinn_btls::helpers::server_config(Arc::new(crypto)).unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let endpoint = quinn::Endpoint::new(
        quinn_btls::helpers::default_endpoint_config(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    (port, endpoint)
}

/// A DoQ server, and its port: a stream per query, as RFC 9250 has it.
pub(crate) fn start_doq_server(cert: &Cert) -> (u16, Arc<Counters>) {
    start_doq_server_with(cert, None)
}

/// `start_doq_server`, asking for a client certificate `client_ca` issued.
fn start_doq_server_with(cert: &Cert, client_ca: Option<&Cert>) -> (u16, Arc<Counters>) {
    let (port, endpoint) = quic_server_endpoint_with(cert, b"doq", client_ca);
    let counters = Arc::new(Counters::default());
    let c = counters.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let c = c.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                c.connections.fetch_add(1, Ordering::SeqCst);
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let c = c.clone();
                    tokio::spawn(async move {
                        let Ok(data) = recv.read_to_end(65537).await else {
                            return;
                        };
                        if data.len() < 2 {
                            return;
                        }
                        let query = &data[2..];
                        c.count(query);
                        let Some(resp) = answer(query) else { return };
                        let mut out = (resp.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&resp);
                        let _ = send.write_all(&out).await;
                        let _ = send.finish();
                        let _ = send.stopped().await;
                    });
                }
            });
        }
    });
    (port, counters)
}

/// A DoH3 server, and its port, answering POSTs to `path`.
fn start_h3_server(cert: &Cert, path: &'static str) -> (u16, Arc<Counters>) {
    let (port, endpoint) = quic_server_endpoint(cert, b"h3");
    let counters = Arc::new(Counters::default());
    let c = counters.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let c = c.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                c.connections.fetch_add(1, Ordering::SeqCst);
                let Ok(mut h3_conn) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3_conn.accept().await {
                    let c = c.clone();
                    tokio::spawn(async move {
                        let Ok((req, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let mut query = Vec::new();
                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                            while chunk.has_remaining() {
                                let part = chunk.chunk().to_vec();
                                chunk.advance(part.len());
                                query.extend_from_slice(&part);
                            }
                        }
                        let ok = req.method() == http::Method::POST
                            && req.uri().path() == path
                            && req.headers().get("content-type").map(|v| v.as_bytes())
                                == Some(b"application/dns-message");
                        let resp = if ok { answer(&query) } else { None };
                        if resp.is_some() {
                            c.count(&query);
                        }
                        let status = if resp.is_some() { 200 } else { 400 };
                        let head = http::Response::builder()
                            .status(status)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        if stream.send_response(head).await.is_err() {
                            return;
                        }
                        if let Some(resp) = resp {
                            let _ = stream.send_data(Bytes::from(resp)).await;
                        }
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    (port, counters)
}

/// A server of type `kind` on 127.0.0.1, whose certificate is checked
/// against `localhost`.
fn server(kind: &str, port: u16, path: Option<&str>) -> serde_json::Value {
    let mut server = serde_json::json!({
        "type": kind,
        "server": "127.0.0.1",
        "server_port": port,
        "tls": { "server_name": "localhost" },
    });
    if let Some(path) = path {
        server["path"] = path.into();
    }
    server
}

/// A client of `servers`, which trust `cert` when it is given.
fn client(servers: &[serde_json::Value], cert: Option<&Cert>) -> DnsClient {
    client_with(servers, cert, Arc::new(DialDefaults::default()))
}

/// `client`, dialling over `dial`.
fn client_with(
    servers: &[serde_json::Value],
    cert: Option<&Cert>,
    dial: Arc<DialDefaults>,
) -> DnsClient {
    let mut servers = servers.to_vec();
    for (i, server) in servers.iter_mut().enumerate() {
        server["tag"] = format!("s{}", i).into();
        if let Some(cert) = cert {
            server["tls"]["certificate"] = cert.cert_pem.clone().into();
        }
    }
    let config = config::Config::from_json(
        // A queries alone, which the servers here count.
        &serde_json::json!({
            "dns": { "servers": servers, "timeout": "3s", "strategy": "ipv4_only" }
        })
        .to_string(),
    )
    .unwrap();
    DnsClient::new(&config.dns, dial, &Default::default()).unwrap()
}

async fn lookup(client: &DnsClient, host: &str) -> anyhow::Result<Vec<IpAddr>> {
    client.lookup(host).await
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_answers_and_keeps_its_connection() {
    let cert = cert();
    let (port, counters) = start_dot_server(&cert, false);
    let server = server("tls", port, None);
    let client = client(&[server], Some(&cert));
    for host in ["a.example", "b.example", "c.example"] {
        assert_eq!(
            lookup(&client, host).await.unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
    }
    assert_eq!(counters.queries.load(Ordering::SeqCst), 3);
    assert_eq!(counters.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_connects_again_when_the_server_closed_the_kept_connection() {
    let cert = cert();
    let (port, counters) = start_dot_server(&cert, true);
    let server = server("tls", port, None);
    let client = client(&[server], Some(&cert));
    for host in ["a.example", "b.example"] {
        // Lets the close reach the client before the next query.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            lookup(&client, host).await.unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
    }
    assert_eq!(counters.queries.load(Ordering::SeqCst), 2);
    assert_eq!(counters.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_rejects_an_untrusted_certificate() {
    let cert = cert();
    let (port, counters) = start_dot_server(&cert, false);
    // The bundled roots do not know the test certificate.
    let server = server("tls", port, None);
    let client = client(&[server], None);
    assert!(lookup(&client, "a.example").await.is_err());
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_rejects_a_certificate_for_another_name() {
    let cert = cert();
    let (port, counters) = start_dot_server(&cert, false);
    // The certificate is for localhost, not 127.0.0.1.
    let mut server = server("tls", port, None);
    server["tls"]["server_name"] = "127.0.0.1".into();
    let client = client(&[server], Some(&cert));
    assert!(lookup(&client, "a.example").await.is_err());
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

/// A client certificate, self-signed: the server trusts it as its own
/// issuer.
fn client_cert() -> Cert {
    Cert::new(&["client"])
}

/// `server`, presenting `identity` as its client certificate.
fn presenting(mut server: serde_json::Value, identity: &Cert) -> serde_json::Value {
    server["tls"]["client_certificate"] = identity.cert_pem.clone().into();
    server["tls"]["client_key"] = identity.key_pem.clone().into();
    server
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_presents_its_client_certificate() {
    let (cert, identity) = (cert(), client_cert());
    let (port, counters) = start_dot_server_with(&cert, false, Some(&identity), None);
    let client = client(
        &[presenting(server("tls", port, None), &identity)],
        Some(&cert),
    );
    assert_eq!(
        lookup(&client, "a.example").await.unwrap(),
        vec![IpAddr::V4(ANSWER)]
    );
    // Without one, the server fails the handshake.
    let bare = self::client(&[server("tls", port, None)], Some(&cert));
    assert!(lookup(&bare, "b.example").await.is_err());
    assert_eq!(counters.queries.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_sends_no_sni_with_disable_sni() {
    let cert = cert();
    let snis = Snis::default();
    let (port, _) = start_dot_server_with(&cert, false, None, Some(snis.clone()));
    let with = client(&[server("tls", port, None)], Some(&cert));
    lookup(&with, "a.example").await.unwrap();
    let mut without = server("tls", port, None);
    without["tls"]["disable_sni"] = true.into();
    let without = client(&[without], Some(&cert));
    lookup(&without, "b.example").await.unwrap();
    assert_eq!(*snis.lock().unwrap(), [Some("localhost".to_string()), None]);
    // The certificate is verified against the name all the same.
    let mut wrong = server("tls", port, None);
    wrong["tls"]["disable_sni"] = true.into();
    wrong["tls"]["server_name"] = "example.com".into();
    assert!(lookup(&client(&[wrong], Some(&cert)), "c.example")
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn doq_presents_its_client_certificate() {
    let (cert, identity) = (cert(), client_cert());
    let (port, counters) = start_doq_server_with(&cert, Some(&identity));
    let client = client(
        &[presenting(server("quic", port, None), &identity)],
        Some(&cert),
    );
    assert_eq!(
        lookup(&client, "a.example").await.unwrap(),
        vec![IpAddr::V4(ANSWER)]
    );
    assert_eq!(counters.queries.load(Ordering::SeqCst), 1);
}

/// A server pinned by its key is trusted without the certificate, and one
/// with another key is refused, over TCP and QUIC alike.
#[tokio::test(flavor = "multi_thread")]
async fn dot_and_doq_take_the_server_by_its_pinned_key() {
    let cert = cert();
    let (dot, dot_counters) = start_dot_server(&cert, false);
    let (doq, doq_counters) = start_doq_server(&cert);
    let pinned = |kind: &str, port: u16, pin: &str| {
        let mut server = server(kind, port, None);
        server["tls"]["certificate_public_key_sha256"] = serde_json::json!([pin]);
        server
    };
    for (kind, port) in [("tls", dot), ("quic", doq)] {
        let right = client(&[pinned(kind, port, &cert.pin)], None);
        assert_eq!(
            lookup(&right, "a.example").await.unwrap(),
            vec![IpAddr::V4(ANSWER)],
            "{}",
            kind
        );
        let other = Cert::new(&["localhost"]).pin;
        let wrong = client(&[pinned(kind, port, &other)], None);
        assert!(lookup(&wrong, "b.example").await.is_err(), "{}", kind);
    }
    assert_eq!(dot_counters.queries.load(Ordering::SeqCst), 1);
    assert_eq!(doq_counters.queries.load(Ordering::SeqCst), 1);
}

/// A server's TLS versions: the range DoT asks for is taken, one that DoT
/// cannot reach fails, and QUIC, TLS 1.3 only, refuses a range without it.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_offers_the_tls_versions_it_is_given() {
    let cert = cert();
    let (port, counters) = start_dot_server(&cert, false);
    let mut v12 = server("tls", port, None);
    v12["tls"]["max_version"] = "1.2".into();
    let v12 = client(&[v12], Some(&cert));
    assert_eq!(
        lookup(&v12, "a.example").await.unwrap(),
        vec![IpAddr::V4(ANSWER)]
    );
    assert_eq!(counters.queries.load(Ordering::SeqCst), 1);

    let error = |server: serde_json::Value| {
        let config = config::Config::from_json(
            &serde_json::json!({ "dns": { "servers": [server] } }).to_string(),
        )
        .unwrap();
        DnsClient::new(
            &config.dns,
            Arc::new(DialDefaults::default()),
            &Default::default(),
        )
        .err()
        .map(|e| format!("{:#}", e))
        .unwrap_or_default()
    };
    let err = error(serde_json::json!({
        "type": "quic", "tag": "q", "server": "127.0.0.1",
        "tls": { "max_version": "1.2" }
    }));
    assert!(
        err.contains("max_version") && err.contains("1.3"),
        "{}",
        err
    );
    let err = error(serde_json::json!({
        "type": "tls", "tag": "t", "server": "127.0.0.1",
        "tls": { "min_version": "1.4" }
    }));
    assert!(err.contains("tls.min_version"), "{}", err);
    let err = error(serde_json::json!({
        "type": "tls", "tag": "t", "server": "127.0.0.1",
        "tls": { "certificate": cert.cert_pem, "certificate_public_key_sha256": [cert.pin] }
    }));
    assert!(err.contains("certificate_public_key_sha256"), "{}", err);
}

#[test]
fn disable_sni_is_not_over_quic_yet() {
    let config = config::Config::from_json(
        &serde_json::json!({ "dns": { "servers": [{
            "type": "quic", "tag": "q", "server": "127.0.0.1",
            "tls": { "disable_sni": true }
        }] } })
        .to_string(),
    )
    .unwrap();
    let err = DnsClient::new(
        &config.dns,
        Arc::new(DialDefaults::default()),
        &Default::default(),
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("not over QUIC yet"), "{:#}", err);
}

#[tokio::test(flavor = "multi_thread")]
async fn doq_answers_on_one_connection_with_a_stream_per_query() {
    let cert = cert();
    let (port, counters) = start_doq_server(&cert);
    let server = server("quic", port, None);
    let client = client(&[server], Some(&cert));
    for host in ["a.example", "b.example", "c.example"] {
        assert_eq!(
            lookup(&client, host).await.unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
    }
    assert_eq!(counters.queries.load(Ordering::SeqCst), 3);
    assert_eq!(counters.nonzero_ids.load(Ordering::SeqCst), 0);
    assert_eq!(counters.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn doq_rejects_an_untrusted_certificate() {
    let cert = cert();
    let (port, counters) = start_doq_server(&cert);
    let server = server("quic", port, None);
    let client = client(&[server], None);
    let err = lookup(&client, "a.example").await.unwrap_err();
    println!("{}", err);
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn doh3_answers_on_one_connection() {
    let cert = cert();
    let (port, counters) = start_h3_server(&cert, "/custom-path");
    let server = server("h3", port, Some("/custom-path"));
    let client = client(&[server], Some(&cert));
    for host in ["a.example", "b.example", "c.example"] {
        assert_eq!(
            lookup(&client, host).await.unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
    }
    assert_eq!(counters.queries.load(Ordering::SeqCst), 3);
    assert_eq!(counters.nonzero_ids.load(Ordering::SeqCst), 0);
    assert_eq!(counters.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn doh3_fails_on_an_http_error() {
    let cert = cert();
    let (port, counters) = start_h3_server(&cert, "/dns-query");
    // The server answers 400 on any other path.
    let server = server("h3", port, Some("/wrong"));
    let client = client(&[server], Some(&cert));
    let err = lookup(&client, "a.example").await.unwrap_err();
    assert!(err.to_string().contains("http status 400"), "{}", err);
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

/// Servers with a `detour`, reached through that outbound: a direct one,
/// which carries DoT and DoH as streams and DoQ and DoH3 as datagrams.
#[cfg(feature = "outbound-direct")]
#[tokio::test(flavor = "multi_thread")]
async fn servers_are_reached_through_their_detour() {
    use sail::app::dispatcher::Dispatcher;
    use sail::app::outbound::manager::OutboundManager;
    use sail::app::router::Router;
    use sail::app::stat_manager::StatManager;

    let cert = cert();
    let (dot_port, dot) = start_dot_server(&cert, false);
    let (doq_port, doq) = start_doq_server(&cert);
    let (h3_port, h3) = start_h3_server(&cert, "/dns-query");

    #[allow(unused_mut)]
    let mut servers = vec![
        (server("tls", dot_port, None), dot),
        (server("quic", doq_port, None), doq),
        (server("h3", h3_port, None), h3),
    ];
    // The DoH server here is sail's TLS inbound.
    #[cfg(all(feature = "dns-doh", feature = "inbound-tls"))]
    {
        let (doh_port, doh) = doh::start_server(&cert, &["h2", "http/1.1"], doh::Reply::Answer);
        servers.push((server("https", doh_port, None), doh));
    }
    for (server, counters) in &servers {
        let dial = Arc::new(DialDefaults::default());
        let env = Arc::new(sail::runtime::RuntimeEnv::default());
        let mut server = server.clone();
        server["detour"] = "direct".into();
        let dns_client = client_with(&[server.clone()], Some(&cert), dial.clone()).into_shared();
        let outbounds = vec![config::Outbound {
            protocol: "direct".to_string(),
            tag: "direct".to_string(),
            options: Default::default(),
        }];
        let outbound_manager = Arc::new(arc_swap::ArcSwap::from_pointee(
            OutboundManager::new(&outbounds, &dial, &env, dns_client.clone()).unwrap(),
        ));
        // Where the servers' detour finds its outbound.
        dial.env.outbounds.set(&outbound_manager);
        let router = Arc::new(arc_swap::ArcSwap::from_pointee(
            Router::new(&config::Route::default(), dns_client.clone(), &env).unwrap(),
        ));
        let stat_manager = Arc::new(StatManager::default());
        let dispatcher = Arc::new(Dispatcher::new(
            outbound_manager,
            router,
            dns_client.clone(),
            stat_manager,
            env,
        ));
        dns_client
            .load()
            .set_dispatcher(Arc::downgrade(&dispatcher));

        for host in ["a.example", "b.example"] {
            let ips = dns_client
                .load()
                .lookup(host)
                .await
                .unwrap_or_else(|e| panic!("{}: {}", server, e));
            assert_eq!(ips, vec![IpAddr::V4(ANSWER)], "{}", server);
        }
        assert_eq!(counters.queries.load(Ordering::SeqCst), 2, "{}", server);
        assert_eq!(counters.connections.load(Ordering::SeqCst), 1, "{}", server);
    }
}

/// Public resolvers, over the internet: `cargo test -p sail --test
/// test_dns_upstreams -- --ignored public`. It depends on the network: a
/// proxy that refuses QUIC it can read the ClientHello of, or UDP 443, fails
/// it for reasons of its own.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn public_resolvers() {
    let mut failed = Vec::new();
    for (kind, address, name) in [
        // Addresses given, so a system resolver that hands out fake IPs (a
        // TUN proxy's) does not decide the result.
        ("tls", "1.1.1.1", "1.1.1.1"),
        ("tls", "8.8.8.8", "dns.google"),
        ("quic", "94.140.14.14", "dns.adguard-dns.com"),
        ("quic", "45.90.28.0", "dns.nextdns.io"),
        ("h3", "223.5.5.5", "dns.alidns.com"),
    ] {
        let server = serde_json::json!({
            "type": kind, "server": address, "tls": { "server_name": name }
        });
        let client = client(&[server], None);
        match lookup(&client, "example.com").await {
            Ok(ips) => println!("{} {}: {:?}", kind, name, ips),
            Err(e) => {
                println!("{} {}: {}", kind, name, e);
                failed.push(name);
            }
        }
    }
    assert!(failed.is_empty(), "failed: {:?}", failed);
}

/// DoH (`https://`) against servers that speak HTTP/2, HTTP/1.1 or both.
// The DoH server here is sail's TLS inbound.
#[cfg(all(feature = "dns-doh", feature = "inbound-tls"))]
mod doh {
    use super::*;

    use sail::adapter::{InboundStreamHandler, InboundTransport};
    use sail::session::Session;
    use sail::transport::tls::inbound::stream::Handler;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// What the server answers.
    #[derive(Clone, Copy, PartialEq)]
    pub(super) enum Reply {
        /// `ANSWER`.
        Answer,
        /// NXDOMAIN, which is an answer and not asked again.
        NxDomain,
        /// An answer longer than a DNS message can be.
        Oversized,
    }

    fn reply(query: &[u8], reply: Reply) -> Option<Vec<u8>> {
        let resp = answer(query)?;
        match reply {
            Reply::Answer => Some(resp),
            Reply::NxDomain => {
                let mut resp = Message::from_vec(&resp).ok()?;
                resp.answers.clear();
                resp.metadata.response_code = ResponseCode::NXDomain;
                resp.to_vec().ok()
            }
            Reply::Oversized => {
                let mut resp = resp;
                resp.resize(70_000, 0);
                Some(resp)
            }
        }
    }

    /// A DoH server on a port of its own, and that port. It offers `alpn`,
    /// most preferred first, and answers POSTs to `/dns-query`: on HTTP/2
    /// when the client and `alpn` agree on it, on HTTP/1.1 otherwise, with
    /// the connection kept alive. On HTTP/1.1 an oversized answer is sent
    /// chunked.
    pub(super) fn start_server(cert: &Cert, alpn: &[&str], kind: Reply) -> (u16, Arc<Counters>) {
        let handler = Arc::new(
            Handler::new(
                cert.cert_pem.clone(),
                cert.key_pem.clone(),
                alpn.iter().map(|p| p.to_string()).collect(),
                Default::default(),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let counters = Arc::new(Counters::default());
        let c = counters.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let handler = handler.clone();
                let c = c.clone();
                tokio::spawn(async move {
                    let Ok(InboundTransport::Stream(stream, sess)) =
                        handler.handle(Session::default(), Box::new(tcp)).await
                    else {
                        return;
                    };
                    c.connections.fetch_add(1, Ordering::SeqCst);
                    if sess.tls_alpn.as_deref() == Some("h2") {
                        serve_h2(stream, c, kind).await;
                    } else {
                        serve_http1(stream, c, kind).await;
                    }
                });
            }
        });
        (port, counters)
    }

    async fn serve_h2(stream: sail::adapter::AnyStream, c: Arc<Counters>, kind: Reply) {
        let Ok(mut conn) = h2::server::handshake(stream).await else {
            return;
        };
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let c = c.clone();
            tokio::spawn(async move {
                let ok = req.method() == http::Method::POST && req.uri().path() == "/dns-query";
                let mut body = req.into_body();
                let mut query = Vec::new();
                while let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    query.extend_from_slice(&chunk);
                }
                let resp = if ok { reply(&query, kind) } else { None };
                if resp.is_some() {
                    c.count(&query);
                }
                let head = http::Response::builder()
                    .status(if resp.is_some() { 200 } else { 400 })
                    .header("content-type", "application/dns-message")
                    .body(())
                    .unwrap();
                let Ok(mut send) = respond.send_response(head, false) else {
                    return;
                };
                let _ = send.send_data(Bytes::from(resp.unwrap_or_default()), true);
            });
        }
    }

    async fn serve_http1(mut stream: sail::adapter::AnyStream, c: Arc<Counters>, kind: Reply) {
        let mut buf = Vec::new();
        loop {
            let head_end = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            buf.drain(..head_end);
            let len = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while buf.len() < len {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let query: Vec<u8> = buf.drain(..len).collect();
            let Some(resp) = head
                .starts_with("POST /dns-query HTTP/1.1\r\n")
                .then(|| reply(&query, kind))
                .flatten()
            else {
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    .await;
                continue;
            };
            c.count(&query);
            let mut out = Vec::new();
            if kind == Reply::Oversized {
                out.extend_from_slice(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n",
                );
                for part in resp.chunks(16 * 1024) {
                    out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                    out.extend_from_slice(part);
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"0\r\n\r\n");
            } else {
                out.extend_from_slice(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                        resp.len()
                    )
                    .as_bytes(),
                );
                out.extend_from_slice(&resp);
            }
            if stream.write_all(&out).await.is_err() || stream.flush().await.is_err() {
                return;
            }
        }
    }

    async fn answers_on_one_connection(alpn: &[&str]) {
        let cert = cert();
        let (port, counters) = start_server(&cert, alpn, Reply::Answer);
        let server = server("https", port, None);
        let client = client(&[server], Some(&cert));
        for host in ["a.example", "b.example", "c.example"] {
            assert_eq!(
                lookup(&client, host).await.unwrap(),
                vec![IpAddr::V4(ANSWER)],
                "{:?}",
                alpn
            );
        }
        assert_eq!(counters.queries.load(Ordering::SeqCst), 3, "{:?}", alpn);
        assert_eq!(counters.nonzero_ids.load(Ordering::SeqCst), 0, "{:?}", alpn);
        assert_eq!(counters.connections.load(Ordering::SeqCst), 1, "{:?}", alpn);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn doh_answers_on_one_http2_connection() {
        answers_on_one_connection(&["h2", "http/1.1"]).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn doh_keeps_its_http1_connection() {
        answers_on_one_connection(&["http/1.1"]).await;
        // A server with no ALPN at all speaks HTTP/1.1.
        answers_on_one_connection(&[]).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn doh_queries_at_once_share_one_http2_connection() {
        let cert = cert();
        let (port, counters) = start_server(&cert, &["h2"], Reply::Answer);
        let server = server("https", port, None);
        let client = Arc::new(client(&[server], Some(&cert)));
        let tasks: Vec<_> = (0..8)
            .map(|i| {
                let client = client.clone();
                tokio::spawn(async move { lookup(&client, &format!("h{}.example", i)).await })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap(), vec![IpAddr::V4(ANSWER)]);
        }
        assert_eq!(counters.queries.load(Ordering::SeqCst), 8);
        assert_eq!(counters.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn doh_does_not_ask_again_on_nxdomain() {
        for alpn in [&["h2"][..], &["http/1.1"][..]] {
            let cert = cert();
            let (port, counters) = start_server(&cert, alpn, Reply::NxDomain);
            let server = server("https", port, None);
            let client = client(&[server], Some(&cert));
            let err = lookup(&client, "missing.example").await.unwrap_err();
            assert!(
                err.to_string().contains("missing.example does not exist"),
                "{:?}: {}",
                alpn,
                err
            );
            assert_eq!(counters.queries.load(Ordering::SeqCst), 1, "{:?}", alpn);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn doh_rejects_an_oversized_answer() {
        for alpn in [&["h2"][..], &["http/1.1"][..]] {
            let cert = cert();
            let (port, counters) = start_server(&cert, alpn, Reply::Oversized);
            let server = server("https", port, None);
            let client = client(&[server], Some(&cert));
            let err = lookup(&client, "a.example").await.unwrap_err();
            assert!(err.to_string().contains("too long"), "{:?}: {}", alpn, err);
            assert!(counters.queries.load(Ordering::SeqCst) >= 1, "{:?}", alpn);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn doh_fails_on_an_http_error() {
        let cert = cert();
        let (port, counters) = start_server(&cert, &["h2"], Reply::Answer);
        // The server answers 400 on any other path.
        let server = server("https", port, Some("/wrong"));
        let client = client(&[server], Some(&cert));
        let err = lookup(&client, "a.example").await.unwrap_err();
        assert!(err.to_string().contains("http status 400"), "{}", err);
        assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
    }

    /// A server without a detour is dialled directly: there is no
    /// dispatcher here at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn doh_without_a_detour_does_not_go_through_the_dispatcher() {
        let cert = cert();
        let (port, counters) = start_server(&cert, &["h2"], Reply::Answer);
        let server = server("https", port, None);
        let client = client(&[server], Some(&cert));
        assert_eq!(
            lookup(&client, "a.example").await.unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
        assert_eq!(counters.queries.load(Ordering::SeqCst), 1);
    }
}
