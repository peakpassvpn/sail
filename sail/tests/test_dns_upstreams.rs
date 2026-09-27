//! The encrypted DNS upstreams, `tls://`, `https://`, `quic://` and
//! `h3://`, against servers started here.

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
use sail::net::DialOptions;

/// The answer every server here gives for an A query.
const ANSWER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);

struct Cert {
    cert_pem: String,
    key_pem: String,
}

/// A self-signed certificate for `localhost`.
fn cert() -> Cert {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    Cert {
        cert_pem: ck.cert.pem(),
        key_pem: ck.key_pair.serialize_pem(),
    }
}

/// Answers `query` with `ANSWER`; `None` when it is not a query.
fn answer(query: &[u8]) -> Option<Vec<u8>> {
    let query = Message::from_vec(query).ok()?;
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(query.op_code());
    resp.set_recursion_desired(query.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::NoError);
    for q in query.queries() {
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
struct Counters {
    connections: AtomicUsize,
    queries: AtomicUsize,
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
    use btls::pkey::PKey;
    use btls::ssl::{SslAcceptor, SslMethod};
    use btls::x509::X509;

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert.cert_pem.as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_pem(cert.key_pem.as_bytes()).unwrap())
        .unwrap();
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
    use btls::pkey::PKey;
    use btls::x509::X509;
    use quinn_btls::QuicSslContext;

    let mut crypto = quinn_btls::ServerConfig::new().unwrap();
    let ctx = crypto.ctx_mut();
    ctx.set_certificate(X509::from_pem(cert.cert_pem.as_bytes()).unwrap())
        .unwrap();
    ctx.set_private_key(PKey::private_key_from_pem(cert.key_pem.as_bytes()).unwrap())
        .unwrap();
    crypto.set_alpn(&[alpn.to_vec()]).unwrap();
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
fn start_doq_server(cert: &Cert) -> (u16, Arc<Counters>) {
    let (port, endpoint) = quic_server_endpoint(cert, b"doq");
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

fn client(servers: &[&str], cert: Option<&Cert>) -> DnsClient {
    let dns = config::Dns {
        servers: servers.iter().map(|s| s.to_string()).collect(),
        timeout: Some(Duration::from_secs(3)),
        ..Default::default()
    };
    let client =
        DnsClient::new(&dns, Arc::new(DialOptions::default()), Default::default()).unwrap();
    match cert {
        Some(cert) => client.with_upstream_certificate(&cert.cert_pem).unwrap(),
        None => client,
    }
}

async fn lookup(client: &DnsClient, host: &str) -> anyhow::Result<Vec<IpAddr>> {
    client.direct_lookup(&host.to_string()).await
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_answers_and_keeps_its_connection() {
    let cert = cert();
    let (port, counters) = start_dot_server(&cert, false);
    let server = format!("direct:tls://localhost:{}@127.0.0.1", port);
    let client = client(&[&server], Some(&cert));
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
    let server = format!("direct:tls://localhost:{}@127.0.0.1", port);
    let client = client(&[&server], Some(&cert));
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
    let server = format!("direct:tls://localhost:{}@127.0.0.1", port);
    let client = client(&[&server], None);
    assert!(lookup(&client, "a.example").await.is_err());
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_rejects_a_certificate_for_another_name() {
    let cert = cert();
    let (port, counters) = start_dot_server(&cert, false);
    // The certificate is for localhost, not 127.0.0.1.
    let server = format!("direct:tls://127.0.0.1:{}", port);
    let client = client(&[&server], Some(&cert));
    assert!(lookup(&client, "a.example").await.is_err());
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn doq_answers_on_one_connection_with_a_stream_per_query() {
    let cert = cert();
    let (port, counters) = start_doq_server(&cert);
    let server = format!("direct:quic://localhost:{}@127.0.0.1", port);
    let client = client(&[&server], Some(&cert));
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
    let server = format!("direct:quic://localhost:{}@127.0.0.1", port);
    let client = client(&[&server], None);
    let err = lookup(&client, "a.example").await.unwrap_err();
    println!("{}", err);
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn doh3_answers_on_one_connection() {
    let cert = cert();
    let (port, counters) = start_h3_server(&cert, "/custom-path");
    let server = format!("direct:h3://localhost:{}/custom-path@127.0.0.1", port);
    let client = client(&[&server], Some(&cert));
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
    let server = format!("direct:h3://localhost:{}/wrong@127.0.0.1", port);
    let client = client(&[&server], Some(&cert));
    let err = lookup(&client, "a.example").await.unwrap_err();
    assert!(err.to_string().contains("http status 400"), "{}", err);
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

/// The servers without `direct:`, reached through the outbound the router
/// picks: a direct outbound, which carries DoT as a stream and DoQ and
/// DoH3 as datagrams.
#[cfg(feature = "outbound-direct")]
#[tokio::test(flavor = "multi_thread")]
async fn upstreams_are_reached_through_the_dispatcher() {
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
        (format!("tls://localhost:{}@127.0.0.1", dot_port), dot),
        (format!("quic://localhost:{}@127.0.0.1", doq_port), doq),
        (format!("h3://localhost:{}@127.0.0.1", h3_port), h3),
    ];
    #[cfg(feature = "dns-doh")]
    {
        let (doh_port, doh) = doh::start_server(&cert, &["h2", "http/1.1"], doh::Reply::Answer);
        servers.push((format!("https://localhost:{}@127.0.0.1", doh_port), doh));
    }
    for (server, counters) in &servers {
        let dial = Arc::new(DialOptions::default());
        let env = Arc::new(sail::runtime::RuntimeEnv::default());
        let dns_client = client(&[server.as_str()], Some(&cert)).into_shared();
        let outbounds = vec![config::Outbound {
            protocol: "direct".to_string(),
            tag: "direct".to_string(),
            options: Default::default(),
        }];
        let outbound_manager = Arc::new(arc_swap::ArcSwap::from_pointee(
            OutboundManager::new(&outbounds, &dial, &env, dns_client.clone()).unwrap(),
        ));
        let router = Arc::new(arc_swap::ArcSwap::from_pointee(
            Router::new(&config::Route::default(), dns_client.clone(), &env).unwrap(),
        ));
        let stat_manager = Arc::new(tokio::sync::RwLock::new(StatManager::new()));
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
                .lookup(&host.to_string())
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
    for server in [
        // Bootstrap addresses given, so a system resolver that hands out
        // fake IPs (a TUN proxy's) does not decide the result.
        "direct:tls://1.1.1.1",
        "direct:tls://dns.google@8.8.8.8",
        "direct:quic://dns.adguard-dns.com@94.140.14.14",
        "direct:quic://dns.nextdns.io@45.90.28.0",
        "direct:h3://dns.alidns.com@223.5.5.5",
    ] {
        let client = client(&[server], None);
        match lookup(&client, "example.com").await {
            Ok(ips) => println!("{}: {:?}", server, ips),
            Err(e) => {
                println!("{}: {}", server, e);
                failed.push(server);
            }
        }
    }
    assert!(failed.is_empty(), "failed: {:?}", failed);
}

/// DoH (`https://`) against servers that speak HTTP/2, HTTP/1.1 or both.
#[cfg(feature = "dns-doh")]
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
                resp.take_answers();
                resp.set_response_code(ResponseCode::NXDomain);
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
        let server = format!("direct:https://localhost:{}@127.0.0.1", port);
        let client = client(&[&server], Some(&cert));
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
        let server = format!("direct:https://localhost:{}@127.0.0.1", port);
        let client = Arc::new(client(&[&server], Some(&cert)));
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
            let server = format!("direct:https://localhost:{}@127.0.0.1", port);
            let client = client(&[&server], Some(&cert));
            let err = lookup(&client, "missing.example").await.unwrap_err();
            assert!(
                err.to_string().contains("Non-Existent Domain"),
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
            let server = format!("direct:https://localhost:{}@127.0.0.1", port);
            let client = client(&[&server], Some(&cert));
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
        let server = format!("direct:https://localhost:{}/wrong@127.0.0.1", port);
        let client = client(&[&server], Some(&cert));
        let err = lookup(&client, "a.example").await.unwrap_err();
        assert!(err.to_string().contains("http status 400"), "{}", err);
        assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
    }

    /// `doh:` is `https://`.
    #[tokio::test(flavor = "multi_thread")]
    async fn doh_short_form() {
        let cert = cert();
        let (port, counters) = start_server(&cert, &["h2"], Reply::Answer);
        let server = format!("direct:doh:localhost:{}@127.0.0.1", port);
        let client = client(&[&server], Some(&cert));
        assert_eq!(
            lookup(&client, "a.example").await.unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
        assert_eq!(counters.queries.load(Ordering::SeqCst), 1);
    }

    /// A direct lookup dials the server itself, even one not marked
    /// `direct:`: through the dispatcher, a lookup the dispatcher itself
    /// asked for could come back to it. Here there is no dispatcher at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn doh_direct_lookup_does_not_go_through_the_dispatcher() {
        let cert = cert();
        let (port, counters) = start_server(&cert, &["h2"], Reply::Answer);
        let server = format!("https://localhost:{}@127.0.0.1", port);
        let client = client(&[&server], Some(&cert));
        assert_eq!(
            lookup(&client, "a.example").await.unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
        assert_eq!(counters.queries.load(Ordering::SeqCst), 1);
    }
}
