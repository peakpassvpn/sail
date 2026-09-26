//! The encrypted DNS upstreams, `tls://`, `quic://` and `h3://`, against
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

/// A DoT server on `port`, on threads. With `close_after_answer` it closes
/// every connection once it has answered, as a server whose idle timeout
/// has passed would.
fn start_dot_server(port: u16, cert: &Cert, close_after_answer: bool) -> Arc<Counters> {
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
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
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
    counters
}

fn quic_server_endpoint(port: u16, cert: &Cert, alpn: &[u8]) -> quinn::Endpoint {
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
    let socket = std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap();
    quinn::Endpoint::new(
        quinn_btls::helpers::default_endpoint_config(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap()
}

/// A DoQ server on `port`: a stream per query, as RFC 9250 has it.
fn start_doq_server(port: u16, cert: &Cert) -> Arc<Counters> {
    let endpoint = quic_server_endpoint(port, cert, b"doq");
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
    counters
}

/// A DoH3 server on `port`, answering POSTs to `path`.
fn start_h3_server(port: u16, cert: &Cert, path: &'static str) -> Arc<Counters> {
    let endpoint = quic_server_endpoint(port, cert, b"h3");
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
    counters
}

fn client(servers: &[&str], cert: Option<&Cert>) -> DnsClient {
    let mut dns = config::Dns::default();
    dns.servers = servers.iter().map(|s| s.to_string()).collect();
    dns.timeout = Some(Duration::from_secs(3));
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
    let counters = start_dot_server(32601, &cert, false);
    let client = client(&["direct:tls://localhost:32601@127.0.0.1"], Some(&cert));
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
    let counters = start_dot_server(32602, &cert, true);
    let client = client(&["direct:tls://localhost:32602@127.0.0.1"], Some(&cert));
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
    let counters = start_dot_server(32603, &cert, false);
    // The bundled roots do not know the test certificate.
    let client = client(&["direct:tls://localhost:32603@127.0.0.1"], None);
    assert!(lookup(&client, "a.example").await.is_err());
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_rejects_a_certificate_for_another_name() {
    let cert = cert();
    let counters = start_dot_server(32604, &cert, false);
    // The certificate is for localhost, not 127.0.0.1.
    let client = client(&["direct:tls://127.0.0.1:32604"], Some(&cert));
    assert!(lookup(&client, "a.example").await.is_err());
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn doq_answers_on_one_connection_with_a_stream_per_query() {
    let cert = cert();
    let counters = start_doq_server(32611, &cert);
    let client = client(&["direct:quic://localhost:32611@127.0.0.1"], Some(&cert));
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
    let counters = start_doq_server(32612, &cert);
    let client = client(&["direct:quic://localhost:32612@127.0.0.1"], None);
    let err = lookup(&client, "a.example").await.unwrap_err();
    println!("{}", err);
    assert_eq!(counters.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn doh3_answers_on_one_connection() {
    let cert = cert();
    let counters = start_h3_server(32621, &cert, "/custom-path");
    let client = client(
        &["direct:h3://localhost:32621/custom-path@127.0.0.1"],
        Some(&cert),
    );
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
    let counters = start_h3_server(32622, &cert, "/dns-query");
    // The server answers 400 on any other path.
    let client = client(
        &["direct:h3://localhost:32622/wrong@127.0.0.1"],
        Some(&cert),
    );
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
    let dot = start_dot_server(32631, &cert, false);
    let doq = start_doq_server(32632, &cert);
    let h3 = start_h3_server(32633, &cert, "/dns-query");

    for (server, counters) in [
        ("tls://localhost:32631@127.0.0.1", &dot),
        ("quic://localhost:32632@127.0.0.1", &doq),
        ("h3://localhost:32633@127.0.0.1", &h3),
    ] {
        let dial = Arc::new(DialOptions::default());
        let env = Arc::new(sail::runtime::RuntimeEnv::default());
        let dns_client = client(&[server], Some(&cert)).into_shared();
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
