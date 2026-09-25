//! Serving Hysteria2 connections: the HTTP/3 authentication, then proxied
//! TCP streams and UDP sessions, handed on as they arrive.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::Either;
use futures::stream::Stream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::adapter::*;
use crate::session::{DatagramSource, Network, Session, SocksAddr, StreamId};

use super::super::congestion::CongestionHandle;
use super::super::h3::{self, Field};
use super::super::proto::{self, Defragger, UdpMessage};
use super::super::quic::{self, QuicStream};
use super::super::salamander::Salamander;
use super::masquerade::Masquerade;

/// Streams and sessions accepted and not yet taken.
const ACCEPT_QUEUE: usize = 1024;
/// How long a stream may wait for room in the accept queue.
const ACCEPT_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
/// UDP sessions one connection may have at once.
const MAX_UDP_SESSIONS: usize = 1024;
/// Packets queued for a UDP session before more are dropped.
const UDP_SESSION_QUEUE: usize = 256;
/// A UDP session without packets from the client for this long is closed.
/// The client may go on using its ID; that starts a new session.
const UDP_SESSION_IDLE: Duration = Duration::from_secs(300);

/// What every connection of the inbound is served with.
pub struct Server {
    /// Users by password, with their names.
    pub users: HashMap<String, Option<Arc<str>>>,
    /// What we send at most at to a client, bytes per second; zero if
    /// unlimited.
    pub send_bps: u64,
    /// What we can receive at, told to clients; zero if unlimited.
    pub recv_bps: u64,
    pub ignore_client_bandwidth: bool,
    pub masquerade: Masquerade,
    pub handshake_timeout: Duration,
    pub tuning: crate::runtime::options::Quic,
}

pub struct DatagramHandler {
    server_config: quinn::ServerConfig,
    obfs: Option<Salamander>,
    server: Arc<Server>,
}

impl DatagramHandler {
    pub fn new(
        server_config: quinn::ServerConfig,
        obfs: Option<Salamander>,
        server: Arc<Server>,
    ) -> Self {
        Self {
            server_config,
            obfs,
            server,
        }
    }
}

struct Incoming(mpsc::Receiver<AnyBaseInboundTransport>);

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

#[async_trait]
impl InboundDatagramHandler for DatagramHandler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        let socket = socket.into_std()?;
        let local_addr = socket.local_addr()?;
        let socket = quic::wrap_socket(socket, self.obfs.as_ref())?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn_btls::helpers::default_endpoint_config(),
            Some(self.server_config.clone()),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
        let server = self.server.clone();
        let server_config = self.server_config.clone();
        tokio::spawn(async move {
            loop {
                let accept = std::pin::pin!(endpoint.accept());
                let closed = std::pin::pin!(tx.closed());
                let incoming = match futures::future::select(accept, closed).await {
                    Either::Left((incoming, _)) => incoming,
                    // Nobody takes what we accept any more.
                    Either::Right(_) => None,
                };
                let Some(incoming) = incoming else {
                    break;
                };
                let conn = Conn {
                    server: server.clone(),
                    tx: tx.clone(),
                    local_addr,
                };
                let config = server_config.clone();
                tokio::spawn(async move {
                    let remote = incoming.remote_address();
                    if let Err(e) = conn.serve(incoming, config).await {
                        debug!("hysteria2 connection from {}: {}", remote, e);
                    }
                });
            }
            endpoint.close(0u32.into(), b"");
        });
        Ok(InboundTransport::Incoming(Box::new(Incoming(rx))))
    }
}

struct Conn {
    server: Arc<Server>,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
    local_addr: SocketAddr,
}

impl Conn {
    async fn serve(self, incoming: quinn::Incoming, config: quinn::ServerConfig) -> io::Result<()> {
        // A controller of its own, which the authentication will set.
        let congestion = CongestionHandle::default();
        let mut config = config;
        config.transport_config(Arc::new(quic::transport_config(
            &self.server.tuning,
            true,
            &congestion,
        )));
        let conn = incoming
            .accept_with(Arc::new(config))
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        trace!(
            "hysteria2 accepted connection from {}",
            conn.remote_address()
        );
        let _control = quic::open_control_stream(&conn).await?;
        let drain = tokio::spawn(quic::drain_uni_streams(conn.clone()));

        let state = Arc::new(ConnState {
            server: self.server,
            tx: self.tx,
            local_addr: self.local_addr,
            conn: conn.clone(),
            congestion,
            user: OnceLock::new(),
            udp_started: AtomicBool::new(false),
            sessions: Arc::new(UdpSessions::default()),
        });
        let result = loop {
            match conn.accept_bi().await {
                Ok((send, recv)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = state.handle_stream(send, recv).await {
                            debug!("hysteria2 stream: {}", e);
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_))
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::TimedOut) => break Ok(()),
                Err(e) => break Err(io::Error::other(e)),
            }
        };
        drain.abort();
        result
    }
}

struct ConnState {
    server: Arc<Server>,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
    local_addr: SocketAddr,
    conn: quinn::Connection,
    congestion: CongestionHandle,
    /// Set once the connection authenticated: the user, by name.
    user: OnceLock<Option<Arc<str>>>,
    udp_started: AtomicBool,
    sessions: Arc<UdpSessions>,
}

impl ConnState {
    fn session(&self, network: Network) -> Session {
        Session {
            network,
            source: self.conn.remote_address(),
            local_addr: self.local_addr,
            user: self.user.get().cloned().flatten(),
            ..Default::default()
        }
    }

    async fn handle_stream(
        self: Arc<Self>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> io::Result<()> {
        let handshake = self.server.handshake_timeout;
        let ty = timeout(handshake, proto::read_varint(&mut recv))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "stream handshake"))??;
        if ty == proto::FRAME_TYPE_TCP_REQUEST {
            if self.user.get().is_none() {
                // Not a proxy connection; to a web server, a frame it does
                // not know on a request stream is an error.
                let _ = recv.stop(0u32.into());
                let _ = send.reset(0u32.into());
                return Err(io::Error::other("TCP request before authentication"));
            }
            let destination = timeout(handshake, proto::read_tcp_request(&mut recv))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP request"))??;
            // Answered before the outbound connects: the reference client
            // waits for the answer before it sends anything, and a failed
            // connection is a closed stream all the same.
            send.write_all(&proto::tcp_response(true, ""))
                .await
                .map_err(io::Error::other)?;
            let mut sess = self.session(Network::Tcp);
            sess.destination = destination;
            sess.stream_id = Some(StreamId::U64(send.id().index()));
            let stream = Box::new(QuicStream::new(send, recv));
            return match timeout(
                ACCEPT_QUEUE_TIMEOUT,
                self.tx.send(BaseInboundTransport::Stream(stream, sess)),
            )
            .await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Ok(()),
                Err(_) => Err(io::Error::other("accept queue full")),
            };
        }

        let fields = timeout(handshake, h3::read_headers(&mut recv, Some(ty)))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request headers"))??;
        if is_auth_request(&fields) {
            let password = h3::field(&fields, proto::HEADER_AUTH).unwrap_or_default();
            if let Some(user) = self.server.users.get(password) {
                return self.authenticated(user.clone(), &fields, send).await;
            }
        }
        self.server.masquerade.serve(fields, send, recv).await
    }

    /// Answers a good authentication, and makes the connection a proxy
    /// connection.
    async fn authenticated(
        self: &Arc<Self>,
        user: Option<Arc<str>>,
        fields: &[Field],
        mut send: quinn::SendStream,
    ) -> io::Result<()> {
        let server = &self.server;
        let _ = self.user.set(user);
        // As the reference server: we send at what the client says it can
        // receive, capped by what we may send at; not knowing, BBR.
        let client_rx: u64 = h3::field(fields, proto::HEADER_CC_RX)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let tx = if server.ignore_client_bandwidth {
            0
        } else if server.send_bps > 0 && client_rx > server.send_bps {
            server.send_bps
        } else {
            client_rx
        };
        if tx > 0 {
            debug!("hysteria2 sends with brutal at {} bytes/s", tx);
            self.congestion.set_brutal(tx);
        } else {
            self.congestion.set_bbr();
        }
        let rx = if server.ignore_client_bandwidth {
            "auto".to_string()
        } else {
            server.recv_bps.to_string()
        };
        let padding = proto::padding(proto::AUTH_RESPONSE_PADDING);
        let status = proto::STATUS_AUTH_OK.to_string();
        h3::write_headers(
            &mut send,
            &[
                (":status", &status),
                (proto::HEADER_UDP, "true"),
                (proto::HEADER_CC_RX, &rx),
                (proto::HEADER_PADDING, &padding),
            ],
        )
        .await?;
        let _ = send.finish();
        if !self.udp_started.swap(true, Ordering::Relaxed) {
            tokio::spawn(self.clone().serve_datagrams());
        }
        Ok(())
    }

    /// Hands the datagrams of the connection to their sessions, starting a
    /// session for an ID it has not seen or has closed.
    async fn serve_datagrams(self: Arc<Self>) {
        while let Ok(datagram) = self.conn.read_datagram().await {
            let msg = match UdpMessage::decode(&datagram) {
                Ok(msg) => msg,
                Err(e) => {
                    debug!("hysteria2: invalid UDP message: {}", e);
                    continue;
                }
            };
            let known = {
                let sessions = self.sessions.lock();
                if !sessions.contains_key(&msg.session_id) && sessions.len() >= MAX_UDP_SESSIONS {
                    continue;
                }
                sessions.contains_key(&msg.session_id)
            };
            // Not under the lock: a session dropped at once takes it too.
            if !known {
                let Some(entry) = self.new_udp_session(msg.session_id) else {
                    continue;
                };
                self.sessions.lock().insert(msg.session_id, entry);
            }
            let mut sessions = self.sessions.lock();
            let Some(entry) = sessions.get_mut(&msg.session_id) else {
                continue;
            };
            let Some(packet) = entry.defragger.feed(&msg) else {
                continue;
            };
            let destination = match proto::parse_addr(msg.addr) {
                Ok(destination) => destination,
                Err(e) => {
                    debug!("hysteria2: invalid UDP destination: {}", e);
                    continue;
                }
            };
            // A session that does not keep up loses packets, as UDP would;
            // one that is gone is forgotten, and the next packet starts
            // another.
            if let Err(mpsc::error::TrySendError::Closed(_)) =
                entry.tx.try_send((packet, destination))
            {
                sessions.remove(&msg.session_id);
            }
        }
        // The connection is gone: so are its sessions, whose halves see
        // the end at once instead of idling out.
        self.sessions.lock().clear();
    }

    /// Starts the UDP session `id`, handing it on.
    fn new_udp_session(&self, id: u32) -> Option<UdpSessionEntry> {
        let (tx, rx) = mpsc::channel(UDP_SESSION_QUEUE);
        let serial = self.sessions.next_serial.fetch_add(1, Ordering::Relaxed);
        let mut sess = self.session(Network::Udp);
        // Sessions from one client address are told apart by this.
        sess.stream_id = Some(StreamId::Uuid(uuid::Uuid::new_v4()));
        let datagram = Datagram {
            rx,
            source: DatagramSource::new(sess.source, sess.stream_id),
            guard: SessionGuard {
                sessions: self.sessions.clone(),
                id,
                serial,
            },
            sender: UdpSender {
                conn: self.conn.clone(),
                id,
                next_packet: AtomicU32::new(0),
            },
        };
        // Taken or not, never waited on: this is the datagram loop.
        self.tx
            .try_send(BaseInboundTransport::Datagram(
                Box::new(datagram),
                Some(sess),
            ))
            .ok()?;
        Some(UdpSessionEntry {
            tx,
            defragger: Defragger::default(),
            serial,
        })
    }
}

fn is_auth_request(fields: &[Field]) -> bool {
    h3::field(fields, ":method") == Some("POST")
        && h3::field(fields, ":authority") == Some(proto::AUTH_HOST)
        && h3::field(fields, ":path") == Some(proto::AUTH_PATH)
}

type Packet = (Vec<u8>, SocksAddr);

struct UdpSessionEntry {
    tx: mpsc::Sender<Packet>,
    defragger: Defragger,
    /// Tells this session from a later one under the same ID.
    serial: u64,
}

#[derive(Default)]
struct UdpSessions {
    map: Mutex<HashMap<u32, UdpSessionEntry>>,
    next_serial: AtomicU64,
}

impl UdpSessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u32, UdpSessionEntry>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Closes the session when its receiving half goes: packets for the ID
/// then start a new one.
struct SessionGuard {
    sessions: Arc<UdpSessions>,
    id: u32,
    serial: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut sessions = self.sessions.lock();
        if sessions
            .get(&self.id)
            .is_some_and(|e| e.serial == self.serial)
        {
            sessions.remove(&self.id);
        }
    }
}

struct UdpSender {
    conn: quinn::Connection,
    id: u32,
    next_packet: AtomicU32,
}

impl UdpSender {
    fn send(&self, payload: &[u8], from: &SocksAddr) -> io::Result<()> {
        let max = self
            .conn
            .max_datagram_size()
            .ok_or_else(|| io::Error::other("hysteria2: the client takes no datagrams"))?;
        let packet_id = self.next_packet.fetch_add(1, Ordering::Relaxed) as u16;
        let addr = proto::format_addr(from);
        for fragment in proto::fragment(self.id, packet_id, &addr, payload, max)? {
            self.conn
                .send_datagram(Bytes::from(fragment))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

/// One UDP session of a client.
struct Datagram {
    rx: mpsc::Receiver<Packet>,
    source: DatagramSource,
    guard: SessionGuard,
    sender: UdpSender,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf {
                rx: self.rx,
                source: self.source,
                _guard: self.guard,
            }),
            Box::new(DatagramSendHalf(self.sender)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("hysteria2 UDP session"))
    }
}

struct DatagramRecvHalf {
    rx: mpsc::Receiver<Packet>,
    source: DatagramSource,
    _guard: SessionGuard,
}

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let (packet, destination) = match timeout(UDP_SESSION_IDLE, self.rx.recv()).await {
            Ok(Some(p)) => p,
            Ok(None) => return Err(ProxyError::DatagramFatal(anyhow!("session closed"))),
            Err(_) => return Err(ProxyError::DatagramFatal(anyhow!("session idle"))),
        };
        if packet.len() > buf.len() {
            return Err(ProxyError::DatagramWarn(anyhow!(
                "UDP packet of {} bytes, buffer of {}",
                packet.len(),
                buf.len()
            )));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), self.source.clone(), destination))
    }
}

struct DatagramSendHalf(UdpSender);

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        self.0.send(buf, src_addr)?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::masquerade::{MasqueradeObject, MasqueradeOptions};
    use super::*;
    use futures::StreamExt;

    struct Fixture {
        endpoint: quinn::Endpoint,
        server: SocketAddr,
        incoming: AnyIncomingTransport,
    }

    async fn serve(masquerade: Masquerade) -> Fixture {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let alpns = quic::alpns(None);
        let config = quic::server_config(&cert.pem(), &key_pair.serialize_pem(), &alpns).unwrap();
        let server = Arc::new(Server {
            users: [("pw".to_string(), Some(Arc::from("alice")))].into(),
            send_bps: 0,
            recv_bps: 0,
            ignore_client_bandwidth: false,
            masquerade,
            handshake_timeout: Duration::from_secs(5),
            tuning: Default::default(),
        });
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let handler = DatagramHandler::new(config, None, server);
        let transport = handler
            .handle(Box::new(crate::net::SimpleInboundDatagram(socket)))
            .await
            .unwrap();
        let InboundTransport::Incoming(incoming) = transport else {
            panic!("not incoming");
        };
        let crypto = quic::client_crypto(Some(&cert.pem()), false, &alpns).unwrap();
        let mut endpoint = quinn::Endpoint::new(
            quinn_btls::helpers::default_endpoint_config(),
            None,
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        Fixture {
            endpoint,
            server: addr,
            incoming,
        }
    }

    impl Fixture {
        async fn connect(&self) -> quinn::Connection {
            self.endpoint
                .connect(self.server, "localhost")
                .unwrap()
                .await
                .unwrap()
        }
    }

    async fn request(conn: &quinn::Connection, fields: &[(&str, &str)]) -> (Vec<Field>, Vec<u8>) {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        h3::write_headers(&mut send, fields).await.unwrap();
        send.finish().unwrap();
        let headers = h3::read_headers(&mut recv, None).await.unwrap();
        let body = h3::read_body(&mut recv, 1 << 20).await.unwrap();
        (headers, body)
    }

    fn auth(password: &str) -> Vec<(&str, &str)> {
        vec![
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "hysteria"),
            (":path", "/auth"),
            ("hysteria-auth", password),
            ("hysteria-cc-rx", "0"),
        ]
    }

    const GET: [(&str, &str); 4] = [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/"),
    ];

    #[tokio::test]
    async fn strangers_see_a_web_server_that_has_nothing() {
        let f = serve(Masquerade::NotFound).await;
        let conn = f.connect().await;
        let (headers, _) = request(&conn, &GET).await;
        assert_eq!(h3::field(&headers, ":status"), Some("404"));
        let (headers, _) = request(&conn, &auth("wrong")).await;
        assert_eq!(h3::field(&headers, ":status"), Some("404"));

        // A TCP request before authenticating is refused.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&proto::tcp_request(
            &SocksAddr::try_from(("example.com", 80)).unwrap(),
            b"",
        ))
        .await
        .unwrap();
        assert!(proto::read_tcp_response(&mut recv).await.is_err());
    }

    #[tokio::test]
    async fn a_fixed_masquerade_answers_strangers() {
        let masquerade = Masquerade::new(MasqueradeOptions::Object(MasqueradeObject::String {
            status_code: Some(200),
            headers: [("Content-Type".to_string(), "text/plain".to_string())].into(),
            content: "hello".into(),
        }))
        .unwrap();
        let f = serve(masquerade).await;
        let conn = f.connect().await;
        let (headers, body) = request(&conn, &GET).await;
        assert_eq!(h3::field(&headers, ":status"), Some("200"));
        assert_eq!(h3::field(&headers, "content-type"), Some("text/plain"));
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn a_proxy_masquerade_passes_strangers_to_the_site_behind() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let site = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let site_addr = site.local_addr().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = site.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nX-Up: 1\r\nConnection: close\r\n\r\nupstream")
                .await
                .unwrap();
            let _ = seen_tx.send(String::from_utf8(request).unwrap());
        });
        let masquerade =
            Masquerade::new(MasqueradeOptions::Url(format!("http://{}/base", site_addr))).unwrap();
        let f = serve(masquerade).await;
        let conn = f.connect().await;
        let (headers, body) = request(&conn, &GET).await;
        assert_eq!(h3::field(&headers, ":status"), Some("200"));
        assert_eq!(h3::field(&headers, "x-up"), Some("1"));
        assert_eq!(h3::field(&headers, "connection"), None);
        assert_eq!(body, b"upstream");
        let seen = seen_rx.await.unwrap();
        assert!(seen.starts_with("GET /base/ HTTP/1.0\r\n"), "{}", seen);
        // The host asked for, as rewrite_host is off.
        assert!(seen.contains("host: example.com\r\n"), "{}", seen);
    }

    #[tokio::test]
    async fn an_authenticated_connection_proxies_tcp_as_the_user() {
        let mut f = serve(Masquerade::NotFound).await;
        let conn = f.connect().await;
        let (headers, _) = request(&conn, &auth("pw")).await;
        assert_eq!(h3::field(&headers, ":status"), Some("233"));
        assert_eq!(h3::field(&headers, "hysteria-udp"), Some("true"));
        assert_eq!(h3::field(&headers, "hysteria-cc-rx"), Some("0"));

        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let destination = SocksAddr::try_from(("example.com", 443)).unwrap();
        send.write_all(&proto::tcp_request(&destination, b"early"))
            .await
            .unwrap();
        proto::read_tcp_response(&mut recv).await.unwrap();
        let Some(BaseInboundTransport::Stream(mut stream, sess)) = f.incoming.next().await else {
            panic!("no stream");
        };
        assert_eq!(sess.destination, destination);
        assert_eq!(sess.user.as_deref(), Some("alice"));
        let mut buf = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"early");

        // A UDP message starts a session.
        let mut msg = bytes::BytesMut::new();
        UdpMessage {
            session_id: 7,
            packet_id: 0,
            fragment_id: 0,
            fragment_count: 1,
            addr: "1.2.3.4:53",
            payload: b"query",
        }
        .encode(&mut msg);
        conn.send_datagram(msg.freeze()).unwrap();
        let Some(BaseInboundTransport::Datagram(datagram, Some(sess))) = f.incoming.next().await
        else {
            panic!("no datagram");
        };
        assert_eq!(sess.user.as_deref(), Some("alice"));
        let (mut r, _s) = datagram.split();
        let mut buf = [0u8; 64];
        let (n, _, destination) = r.recv_from(&mut buf).await.ok().unwrap();
        assert_eq!(&buf[..n], b"query");
        assert_eq!(destination.to_string(), "1.2.3.4:53");
    }
}
