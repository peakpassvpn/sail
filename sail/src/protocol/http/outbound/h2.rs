//! An HTTP proxy over HTTP/2, as sing-box 1.15's: each tunnel is a CONNECT
//! request on one of the connections a pool keeps to the server
//! (`transport::h2pool`), which the outbound dials through its blocks,
//! running TLS itself to read the ALPN the server picked.
//!
//! The ALPN decides, as in sing-box: `h2` and the connection carries
//! HTTP/2. Anything else, and with the version fallback (the default) the
//! same connection carries an HTTP/1.1 CONNECT, and every tunnel after it
//! goes over HTTP/1.1 on a connection of its own, offering `http/1.1`
//! alone, until the network changes; without the fallback the tunnel fails
//! with `server does not support HTTP/2`. A refused CONNECT, or an HTTP/2
//! error, is the tunnel's error: no fallback, no second try.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue, PROXY_AUTHORIZATION};
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use tracing::debug;

use super::stream::Handler as Http1;
use crate::adapter::*;
use crate::protocol::http::h2::Settings;
use crate::session::{Network, Session, SocksAddr};
use crate::transport::h2connect::{h2_error, H2Inner};
use crate::transport::h2pool::{Call, Dial, Dialled, Keepalive, Names, Pool, Pooled, Requested};
use crate::transport::layers::TlsConnector;
use crate::transport::muxcore::stall::Guarded;
use crate::transport::muxcore::Tuning;

/// What its tasks are called, and what it logs under.
const NAMES: Names = Names {
    log: "http",
    connection: "http proxy connection",
    idle_check: "http proxy idle check",
    keepalive: "http proxy keepalive",
};

/// The error of a server that picks no `h2`, without the fallback, as
/// sing-box's.
const UNSUPPORTED: &str = "server does not support HTTP/2";

/// Headers HTTP/2 does not carry (RFC 9113 8.2.2).
const CONNECTION_SPECIFIC: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Dials the pool's connections: HTTP/2 where the server picks `h2`.
struct H2Dial(TlsConnector);

#[async_trait]
impl Dial for H2Dial {
    async fn dial(&self, sess: &Session) -> io::Result<Dialled> {
        let (stream, alpn) = self.0.connect(sess, false).await?;
        Ok(match alpn.as_deref() {
            Some(b"h2") => Dialled::H2(stream),
            _ => Dialled::Other(stream),
        })
    }

    fn network_changed(&self, change: &crate::net::network::NetworkChange) {
        self.0.network_changed(change);
    }

    fn close_idle(&self) {
        self.0.close_idle();
    }
}

pub struct Handler {
    /// CONNECT over HTTP/1.1, on a connection it is handed.
    http1: Http1,
    connector: TlsConnector,
    pool: Pool,
    /// Whether to fall back to HTTP/1.1 from a server that picks no `h2`.
    fallback: bool,
    /// The server picked no `h2`: HTTP/1.1 until the network changes.
    unsupported: AtomicBool,
    /// Sent with every CONNECT.
    headers: HeaderMap,
    stall_timeout: Duration,
    label: Arc<str>,
}

impl Handler {
    /// The outbound at `at` (`[tag] outbound`), over the connections
    /// `connector` makes.
    pub fn new(
        at: &str,
        http1: Http1,
        connector: TlsConnector,
        settings: Settings,
        fallback: bool,
        tuning: Tuning,
        idle_timeout: Duration,
    ) -> Result<Self> {
        let mut headers = HeaderMap::new();
        for (name, value) in &http1.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| anyhow!("{}: headers: {}: {}", at, name, e))?;
            if CONNECTION_SPECIFIC.contains(&name.as_str()) {
                return Err(anyhow!("{}: headers: {}: not carried by HTTP/2", at, name));
            }
            let value = HeaderValue::from_str(value)
                .map_err(|e| anyhow!("{}: headers: {}: {}", at, name, e))?;
            headers.append(name, value);
        }
        if let Some(authorization) = &http1.authorization {
            if !headers.contains_key(PROXY_AUTHORIZATION) {
                headers.insert(
                    PROXY_AUTHORIZATION,
                    HeaderValue::from_str(authorization)
                        .map_err(|e| anyhow!("{}: username: {}", at, e))?,
                );
            }
        }
        let pool = Pool::new(
            H2Dial(connector.clone()),
            settings.client(),
            Keepalive {
                idle_timeout: settings.keep_alive,
                ping_timeout: settings.ping_timeout,
                permit_without_stream: true,
                quiet: true,
            },
            idle_timeout,
            NAMES,
        )
        .with_max_streams(settings.max_streams as usize);
        Ok(Handler {
            http1,
            connector,
            pool,
            fallback,
            unsupported: AtomicBool::new(false),
            headers,
            stall_timeout: tuning.stall_timeout,
            label: at.into(),
        })
    }

    /// The CONNECT to `destination`.
    fn request(&self, destination: &SocksAddr) -> io::Result<Request<()>> {
        let uri = destination
            .to_string()
            .parse::<Uri>()
            .map_err(io::Error::other)?;
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .body(())
            .map_err(io::Error::other)?;
        *request.headers_mut() = self.headers.clone();
        Ok(request)
    }

    /// The tunnel `call` opens, once the server has answered `200`.
    async fn tunnel(&self, call: Call) -> io::Result<AnyStream> {
        let Call {
            send,
            response,
            slot,
        } = call;
        let response = response.await.map_err(|e| h2_error(NAMES.log, e))?;
        if response.status() != StatusCode::OK {
            return Err(io::Error::other(format!(
                "http proxy refused CONNECT: HTTP/2 {}",
                response.status()
            )));
        }
        let stream = H2Inner::new(NAMES.log, send, response.into_body());
        Ok(Box::new(Pooled {
            inner: Guarded::new(stream, NAMES.log, self.stall_timeout, self.label.clone()),
            _slot: slot,
        }))
    }

    /// The tunnel over HTTP/1.1, on a connection of its own offering
    /// `http/1.1` alone.
    async fn over_http1(&self, sess: &Session, server: &Session) -> io::Result<AnyStream> {
        let (stream, _) = self.connector.connect(server, true).await?;
        self.http1.handle(sess, None, Some(stream)).await
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn network_changed(&self, change: &crate::net::network::NetworkChange) {
        self.pool.network_changed(change);
        // The next network's server may speak HTTP/2, as sing-box's
        // `ResetConnections` finds out anew.
        self.unsupported.store(false, Ordering::Release);
    }

    fn close_idle(&self) {
        self.pool.close_idle();
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        if stream.is_some() {
            return Err(io::Error::other(
                "http: handed a connection; it dials its own",
            ));
        }
        // The connection is to the server, in a copy of the session.
        let mut server = sess.clone();
        server.network = Network::Tcp;
        server.destination = SocksAddr::try_from((&self.http1.address, self.http1.port))?;
        server.forget_sniffed();
        if self.unsupported.load(Ordering::Acquire) {
            return self.over_http1(sess, &server).await;
        }
        match self
            .pool
            .request(&server, || self.request(&sess.destination))
            .await?
        {
            Requested::Call(call) => self.tunnel(call).await,
            // The connection is dropped, and closed.
            Requested::Other(_) if !self.fallback => Err(io::Error::other(UNSUPPORTED)),
            Requested::Other(stream) => {
                debug!(
                    "http: {} picked no h2; HTTP/1.1 until the network changes",
                    server.destination
                );
                self.unsupported.store(true, Ordering::Release);
                self.http1.handle(sess, None, Some(stream)).await
            }
        }
    }
}

#[cfg(all(test, feature = "outbound-tls"))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::adapter::*;
    use crate::app::SyncDnsClient;
    use crate::session::{Session, SocksAddr};

    /// The ALPN lists the server was offered, as the wire lists them.
    type Offered = Arc<Mutex<Vec<Vec<u8>>>>;

    const H2_HTTP1: &[u8] = b"\x02h2\x08http/1.1";
    const HTTP1: &[u8] = b"\x08http/1.1";

    /// A proxy over TLS, and what it saw.
    struct Proxy {
        port: u16,
        /// Its certificate, PEM.
        cert: String,
        /// The connections it took.
        connections: Arc<AtomicUsize>,
        /// The ALPN lists it was offered.
        offered: Offered,
        /// What each CONNECT asked for: the authority over HTTP/2, the
        /// request line over HTTP/1.1.
        asked: Arc<Mutex<Vec<String>>>,
    }

    /// A proxy over TLS picking `pick` in ALPN, answering CONNECT over
    /// HTTP/2 or HTTP/1.1 as it picked, with `407` unless the request
    /// carries `authorization` when it is set, echoing each tunnel to its
    /// end.
    async fn proxy(pick: &'static [u8], authorization: Option<&'static str>) -> Proxy {
        let offered = Offered::default();
        let (acceptor, cert) =
            crate::transport::tls::tests::acceptor_picking(pick, offered.clone());
        let acceptor = Arc::new(acceptor);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (counted, seen) = (connections.clone(), asked.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let (acceptor, seen) = (acceptor.clone(), seen.clone());
                tokio::spawn(async move {
                    let Ok(tls) = crate::transport::tls::tests::accept(&acceptor, tcp).await else {
                        return;
                    };
                    let h2 = tls.conn().ssl().selected_alpn_protocol() == Some(b"h2");
                    if h2 {
                        serve_h2(tls, authorization, seen).await;
                    } else {
                        serve_http1(tls, seen).await;
                    }
                });
            }
        });
        Proxy {
            port,
            cert,
            connections,
            offered,
            asked,
        }
    }

    async fn serve_h2(
        tls: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        authorization: Option<&'static str>,
        seen: Arc<Mutex<Vec<String>>>,
    ) {
        let mut connection = h2::server::handshake(tls).await.unwrap();
        while let Some(Ok((request, mut respond))) = connection.accept().await {
            assert_eq!(request.method(), http::Method::CONNECT);
            seen.lock()
                .unwrap()
                .push(request.uri().authority().unwrap().to_string());
            let given = request
                .headers()
                .get(http::header::PROXY_AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            if authorization.is_some_and(|a| given != Some(a)) {
                let refused = http::Response::builder()
                    .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header("proxy-authenticate", "Basic realm=\"test\"")
                    .body(())
                    .unwrap();
                let _ = respond.send_response(refused, true);
                continue;
            }
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let mut body = request.into_body();
            tokio::spawn(async move {
                while let Some(Ok(data)) = body.data().await {
                    let _ = body.flow_control().release_capacity(data.len());
                    if send.send_data(data, false).is_err() {
                        return;
                    }
                }
                let _ = send.send_data(Bytes::new(), true);
            });
        }
    }

    async fn serve_http1(
        mut tls: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        seen: Arc<Mutex<Vec<String>>>,
    ) {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let Ok(byte) = tls.read_u8().await else {
                return;
            };
            head.push(byte);
        }
        let line = String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap()
            .to_string();
        seen.lock().unwrap().push(line);
        tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0; 4096];
        loop {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tls.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = tls.shutdown().await;
    }

    /// The outbound `fields` configure, to `proxy`.
    fn outbound(proxy: &Proxy, fields: serde_json::Value) -> (AnyOutboundHandler, SyncDnsClient) {
        let mut outbound = serde_json::json!({ "type": "http", "tag": "h",
            "version": 2,
            "server": "127.0.0.1", "server_port": proxy.port,
            "tls": { "enabled": true, "server_name": "localhost",
                     "certificate": proxy.cert } });
        outbound
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "outbounds": [outbound] }).to_string(),
        )
        .unwrap();
        let dial = crate::net::DialDefaults::default();
        let dns = crate::app::dns::DnsClient::new(
            &config.dns,
            std::sync::Arc::new(dial.clone()),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let manager = crate::app::outbound::manager::OutboundManager::new(
            &config.outbounds,
            &dial,
            &Default::default(),
            dns.clone(),
        )
        .unwrap();
        (manager.get("h").unwrap(), dns)
    }

    async fn tunnel(
        handler: &AnyOutboundHandler,
        dns: &SyncDnsClient,
        to: &str,
    ) -> std::io::Result<AnyStream> {
        let sess = Session {
            destination: SocksAddr::try_from((to, 443)).unwrap(),
            ..Default::default()
        };
        let stream = crate::net::connect_stream_outbound(&sess, dns.clone(), handler).await?;
        handler.stream()?.handle(&sess, None, stream).await
    }

    /// Writes `data`, ends the tunnel's sending half, and reads the echo to
    /// its end: the peer still sends after the half-close.
    async fn echo(mut stream: AnyStream, data: &[u8]) -> Vec<u8> {
        stream.write_all(data).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut back = Vec::new();
        stream.read_to_end(&mut back).await.unwrap();
        back
    }

    fn change() -> crate::net::network::NetworkChange {
        crate::net::network::NetworkChange {
            generation: 1,
            reason: crate::net::network::ChangeReason::HostPush,
            old: Default::default(),
            new: Default::default(),
        }
    }

    /// A tunnel is a CONNECT on HTTP/2 with the credentials, open once the
    /// proxy says `200`; its half-close ends the request's body, and the
    /// response's is read to its end.
    #[tokio::test]
    async fn a_tunnel_is_an_http2_connect() {
        let proxy = proxy(b"h2", Some("Basic dTpw")).await;
        let (handler, dns) = outbound(
            &proxy,
            serde_json::json!({ "username": "u", "password": "p" }),
        );
        let stream = tunnel(&handler, &dns, "example.com").await.unwrap();
        assert_eq!(echo(stream, b"hello").await, b"hello");
        assert_eq!(*proxy.asked.lock().unwrap(), ["example.com:443"]);
        assert_eq!(*proxy.offered.lock().unwrap(), [H2_HTTP1]);
        assert_eq!(proxy.connections.load(Ordering::SeqCst), 1);
    }

    /// A refused CONNECT fails the dial, as sing-box's, and gives its room
    /// on the connection back: with one tunnel a connection, refused ones
    /// one after another dial nothing new.
    #[tokio::test]
    async fn a_407_fails_the_dial() {
        let proxy = proxy(b"h2", Some("Basic dTpw")).await;
        let wrong = serde_json::json!({ "username": "u", "password": "x",
            "max_concurrent_streams": 1 });
        let (handler, dns) = outbound(&proxy, wrong);
        for _ in 0..3 {
            let err = tunnel(&handler, &dns, "example.com").await.err().unwrap();
            assert_eq!(
                err.to_string(),
                "http proxy refused CONNECT: HTTP/2 407 Proxy Authentication Required"
            );
        }
        assert_eq!(proxy.connections.load(Ordering::SeqCst), 1);
        let (handler, dns) = outbound(
            &proxy,
            serde_json::json!({ "username": "u", "password": "p" }),
        );
        let stream = tunnel(&handler, &dns, "example.com").await.unwrap();
        assert_eq!(echo(stream, b"x").await, b"x");
    }

    /// Tunnels open at once share one connection.
    #[tokio::test]
    async fn many_tunnels_share_one_connection() {
        let proxy = proxy(b"h2", None).await;
        let (handler, dns) = outbound(&proxy, serde_json::json!({}));
        // The first sets the connection up; the rest go on it.
        drop(tunnel(&handler, &dns, "a.example").await.unwrap());
        let echoes = futures::future::join_all((0..50).map(|i| {
            let (handler, dns) = (&handler, &dns);
            async move {
                let stream = tunnel(handler, dns, "example.com").await.unwrap();
                let data = format!("tunnel {}", i);
                assert_eq!(echo(stream, data.as_bytes()).await, data.as_bytes());
            }
        }));
        echoes.await;
        assert_eq!(proxy.connections.load(Ordering::SeqCst), 1);
    }

    /// A server that picks no `h2` gets the tunnel over HTTP/1.1 on the
    /// same connection, and every later one on a connection of its own
    /// offering `http/1.1` alone, until the network changes.
    #[tokio::test]
    async fn without_h2_http1_until_the_network_changes() {
        let proxy = proxy(b"http/1.1", None).await;
        let (handler, dns) = outbound(&proxy, serde_json::json!({}));
        for _ in 0..2 {
            let stream = tunnel(&handler, &dns, "example.com").await.unwrap();
            assert_eq!(echo(stream, b"one").await, b"one");
        }
        assert_eq!(*proxy.offered.lock().unwrap(), [H2_HTTP1, HTTP1]);
        assert_eq!(
            *proxy.asked.lock().unwrap(),
            [
                "CONNECT example.com:443 HTTP/1.1",
                "CONNECT example.com:443 HTTP/1.1"
            ]
        );
        assert_eq!(proxy.connections.load(Ordering::SeqCst), 2);
        handler.network_changed(&change());
        let stream = tunnel(&handler, &dns, "example.com").await.unwrap();
        assert_eq!(echo(stream, b"two").await, b"two");
        assert_eq!(proxy.offered.lock().unwrap()[2], H2_HTTP1);
    }

    /// Without the version fallback, a server that picks no `h2` is an
    /// error, sing-box's, every time.
    #[tokio::test]
    async fn without_h2_and_without_fallback_the_dial_fails() {
        let proxy = proxy(b"http/1.1", None).await;
        let (handler, dns) = outbound(
            &proxy,
            serde_json::json!({ "disable_version_fallback": true }),
        );
        for _ in 0..2 {
            let err = tunnel(&handler, &dns, "example.com").await.err().unwrap();
            assert_eq!(err.to_string(), "server does not support HTTP/2");
        }
        assert_eq!(*proxy.offered.lock().unwrap(), [H2_HTTP1, H2_HTTP1]);
        assert!(proxy.asked.lock().unwrap().is_empty());
    }
}
