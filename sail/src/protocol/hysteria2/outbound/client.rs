//! The client's one QUIC connection to its server: dialled, authenticated
//! and shared by every stream and UDP session, and dialled again once it
//! is gone.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use futures::future::{AbortHandle, Abortable};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::app::SyncDnsClient;
use crate::net::dial::BoundInterface;
use crate::net::Dialer;
use crate::session::{Session, SocksAddr};
use crate::transport::quic::{endpoint_on, QuicStream, Side};

use super::super::congestion::CongestionHandle;
use super::super::h3;
use super::super::hop::HopSocket;
use super::super::proto::{self, Defragger, UdpMessage};
use super::super::quic;
use super::super::salamander::Salamander;

/// UDP sessions one connection carries at most.
const MAX_UDP_SESSIONS: usize = 1024;
/// Packets queued for a UDP session before more are dropped.
const UDP_SESSION_QUEUE: usize = 256;
/// What a connection closed for a network change is closed with.
const NETWORK_CHANGED_CODE: quinn::VarInt = quinn::VarInt::from_u32(0);
const NETWORK_CHANGED: &[u8] = b"network changed";

/// What the client is configured with.
pub struct ClientOptions {
    pub server: String,
    /// The port, or with hopping the ports, to reach the server on.
    pub ports: Vec<u16>,
    pub hop_interval: Option<Duration>,
    pub password: String,
    /// What we may send, bytes per second; zero if unknown.
    pub send_bps: u64,
    /// What we can receive, bytes per second; zero if unknown.
    pub recv_bps: u64,
    pub obfs: Option<Salamander>,
    pub server_name: String,
    pub crypto: Arc<quinn_btls::ClientConfig>,
    pub tuning: crate::runtime::options::Quic,
    pub dns_client: SyncDnsClient,
    pub dialer: Dialer,
}

pub struct Client {
    options: ClientOptions,
    /// The connection in use, and the network it was dialled on.
    conn: Mutex<Current>,
    /// Held while dialling, so that requests arriving meanwhile wait for
    /// the one connection being made.
    dialing: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Current {
    conn: Option<Arc<Connection>>,
    /// Counts the network changes; a connection dialled across one is
    /// not kept.
    network: u64,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        Self {
            options,
            conn: Mutex::default(),
            dialing: tokio::sync::Mutex::new(()),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Current> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The live connection, if there is one.
    fn live(&self) -> Option<Arc<Connection>> {
        let mut current = self.slot();
        let conn = current.conn.as_ref()?;
        if conn.conn.close_reason().is_none() {
            return Some(conn.clone());
        }
        debug!(
            "hysteria2 connection closed: {:?}",
            conn.conn.close_reason()
        );
        current.conn = None;
        None
    }

    /// The connection in use, if any.
    #[cfg(all(test, feature = "inbound-hysteria2"))]
    pub fn current(&self) -> Option<quinn::Connection> {
        self.slot().conn.as_ref().map(|c| c.conn.clone())
    }

    /// The live connection, dialling one if there is none.
    pub async fn connection(&self) -> io::Result<Arc<Connection>> {
        if let Some(conn) = self.live() {
            return Ok(conn);
        }
        let _dialing = self.dialing.lock().await;
        if let Some(conn) = self.live() {
            return Ok(conn);
        }
        let network = self.slot().network;
        let conn = Arc::new(
            self.connect()
                .await
                .map_err(|e| io::Error::other(format!("hysteria2 connect failed: {:#}", e)))?,
        );
        let mut current = self.slot();
        if current.network != network {
            conn.conn.close(NETWORK_CHANGED_CODE, NETWORK_CHANGED);
            return Err(io::Error::other("hysteria2: network changed"));
        }
        current.conn = Some(conn.clone());
        Ok(conn)
    }

    /// Forgets `conn` if it is the current connection, so that the next
    /// request dials a new one.
    pub fn discard(&self, conn: &Arc<Connection>) {
        let mut current = self.slot();
        if current.conn.as_ref().is_some_and(|c| Arc::ptr_eq(c, conn)) {
            current.conn = None;
        }
    }

    /// Closes the connection in use, whose streams and UDP sessions fail
    /// with it, and drops one being dialled, as sing-box's
    /// CloseWithError: the next request dials on the new network.
    pub fn network_changed(&self) {
        let mut current = self.slot();
        current.network += 1;
        if let Some(conn) = current.conn.take() {
            debug!("hysteria2: network changed, closing the connection");
            conn.conn.close(NETWORK_CHANGED_CODE, NETWORK_CHANGED);
        }
    }

    /// Opens a proxied TCP stream to where `sess` goes, with `payload` sent
    /// along with the request; where the connection went out recorded on
    /// `sess`. The stream is returned once the request is sent, and the
    /// server's answer read at its first read (`ProxiedStream`).
    pub async fn open_stream(&self, sess: &Session, payload: &[u8]) -> io::Result<ProxiedStream> {
        let conn = self.connection().await?;
        let (mut send, recv) = match conn.conn.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                self.discard(&conn);
                return Err(io::Error::other(e));
            }
        };
        send.write_all(&proto::tcp_request(&sess.destination, payload))
            .await
            .map_err(io::Error::other)?;
        conn.bound.onto(sess);
        Ok(ProxiedStream {
            inner: QuicStream::new(send, recv),
            response: Some(Vec::new()),
        })
    }

    async fn connect(&self) -> Result<Connection> {
        let o = &self.options;
        let targets = o
            .dialer
            .targets(&o.dns_client, &o.server, o.ports[0])
            .await
            .with_context(|| format!("lookup {}", o.server))?;
        let mut last_err = anyhow!("could not resolve {} to any address", o.server);
        for to in targets {
            match timeout(o.dialer.connect_timeout(), self.connect_to(&to)).await {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => last_err = e,
                Err(_) => last_err = anyhow!("connect {} timed out", to),
            }
        }
        Err(last_err)
    }

    async fn connect_to(&self, to: &SocksAddr) -> Result<Connection> {
        let o = &self.options;
        let (socket, peer, bound) =
            new_socket(&o.dialer, &o.dns_client, to, o.obfs.as_ref()).await?;
        let (socket, remote, hop): (Arc<dyn quinn::AsyncUdpSocket>, _, _) = if o.ports.len() > 1 {
            let hop = Arc::new(HopSocket::new(peer.ip(), o.ports.clone(), socket));
            let remote = hop.virtual_addr();
            (hop.clone(), remote, Some(hop))
        } else {
            (socket, peer, None)
        };
        let endpoint = endpoint_on(socket, None)?;
        let congestion = CongestionHandle::default();
        let mut config = quinn::ClientConfig::new(o.crypto.clone());
        config.transport_config(Arc::new(quic::transport_config(
            &o.tuning,
            Side::Client,
            &congestion,
        )));
        let conn = endpoint
            .connect_with(config, remote, &o.server_name)?
            .await
            .with_context(|| format!("quic connect {}", remote))?;
        trace!("hysteria2 connected to {}", remote);

        let mut tasks = Tasks::default();
        let control = quic::open_control_stream(&conn).await?;
        tasks.spawn(quic::drain_uni_streams(conn.clone()));

        let auth = self.authenticate(&conn).await?;
        // The server tells what it can receive, and we send at most that.
        // Brutal needs a rate of our own too: without `up_mbps`, BBR.
        let tx = match auth.rx {
            Some(rx) if rx > 0 && rx <= o.send_bps => rx,
            _ => o.send_bps,
        };
        if auth.rx.is_some() && tx > 0 {
            debug!("hysteria2 sends with brutal at {} bytes/s", tx);
            congestion.set_brutal(tx);
        } else {
            congestion.set_bbr();
        }

        let sessions = Arc::new(Sessions::default());
        if auth.udp {
            tasks.spawn(receive_datagrams(conn.clone(), sessions.clone()));
        }
        if let (Some(hop), Some(interval)) = (hop, o.hop_interval) {
            tasks.spawn(hop_ports(
                conn.clone(),
                hop,
                interval,
                to.clone(),
                o.dialer.clone(),
                o.dns_client.clone(),
                o.obfs.clone(),
            ));
        }
        Ok(Connection {
            conn,
            bound,
            _endpoint: endpoint,
            _control: control,
            udp: auth.udp,
            sessions,
            next_session: AtomicU32::new(0),
            next_packet: AtomicU32::new(0),
            _tasks: tasks,
        })
    }

    /// The HTTP/3 request that makes this connection a proxy connection.
    async fn authenticate(&self, conn: &quinn::Connection) -> Result<Auth> {
        let o = &self.options;
        let (mut send, mut recv) = conn.open_bi().await?;
        let rx = o.recv_bps.to_string();
        let padding = proto::padding(proto::AUTH_REQUEST_PADDING);
        h3::write_headers(
            &mut send,
            &[
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", proto::AUTH_HOST),
                (":path", proto::AUTH_PATH),
                (proto::HEADER_AUTH, &o.password),
                (proto::HEADER_CC_RX, &rx),
                (proto::HEADER_PADDING, &padding),
            ],
        )
        .await?;
        send.finish()?;
        let fields = h3::read_headers(&mut recv, None).await?;
        let status = h3::field(&fields, ":status").unwrap_or_default();
        if status != proto::STATUS_AUTH_OK.to_string() {
            return Err(anyhow!("authentication failed, status {}", status));
        }
        let udp =
            h3::field(&fields, proto::HEADER_UDP).is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let rx = match h3::field(&fields, proto::HEADER_CC_RX) {
            Some("auto") => None,
            Some(v) => Some(v.parse().unwrap_or(0)),
            None => Some(0),
        };
        Ok(Auth { udp, rx })
    }
}

/// A proxied TCP stream, whose TCPResponse is read at its first read, as
/// sing-box's client reads it (sing-quic, hysteria2/client.go,
/// `clientConn.Read`): a server need not answer before it has data to
/// send back, and Mihomo's does not (sing-quic's service answers at the
/// first write when HandshakeSuccess is not called). Writes go out before
/// the answer; a refusal fails the first read, and every read after it,
/// with the server's message.
///
/// A server that never answers holds the stream as one that never sends
/// does: until either side closes it, the relay's idle timeouts once one
/// has, or the connection's idle timeout once the server is gone.
pub struct ProxiedStream {
    inner: QuicStream,
    /// The response read so far, until it is whole and OK.
    response: Option<Vec<u8>>,
}

impl AsyncRead for ProxiedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while let Some(response) = &mut this.response {
            let Some(needs) = proto::tcp_response_needs(response)? else {
                this.response = None;
                break;
            };
            // Only what the response needs, so that what follows it is
            // left for `buf`.
            let at = response.len();
            response.resize(at + needs, 0);
            let mut part = ReadBuf::new(&mut response[at..]);
            let polled = Pin::new(&mut this.inner).poll_read(cx, &mut part);
            let read = part.filled().len();
            response.truncate(at + read);
            ready!(polled)?;
            if read == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "hysteria2: the stream ended before its TCP response",
                )));
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxiedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// What the server answered the authentication with.
struct Auth {
    udp: bool,
    /// What the server can receive, bytes per second, zero if unlimited;
    /// None if it asks us to find out ourselves ("auto").
    rx: Option<u64>,
}

/// Tasks of a connection, stopped with it.
#[derive(Default)]
struct Tasks(Vec<AbortHandle>);

impl Tasks {
    fn spawn<F: std::future::Future<Output = ()> + Send + 'static>(&mut self, task: F) {
        let (handle, registration) = AbortHandle::new_pair();
        crate::runtime::scope::spawn(
            "hysteria2 connection task",
            Abortable::new(task, registration),
        );
        self.0.push(handle);
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// A packet for a UDP session, and where it came from.
pub type Packet = (Vec<u8>, SocksAddr);

struct SessionEntry {
    tx: mpsc::Sender<Packet>,
    defragger: Defragger,
}

#[derive(Default)]
struct Sessions(Mutex<HashMap<u32, SessionEntry>>);

impl Sessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u32, SessionEntry>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub struct Connection {
    pub conn: quinn::Connection,
    /// Where it went out, which every stream and UDP session on it is
    /// given.
    pub bound: BoundInterface,
    _endpoint: quinn::Endpoint,
    /// Our HTTP/3 control stream, open while the connection is.
    _control: quinn::SendStream,
    udp: bool,
    sessions: Arc<Sessions>,
    next_session: AtomicU32,
    next_packet: AtomicU32,
    _tasks: Tasks,
}

impl Connection {
    /// A new UDP session: its ID, and where its packets arrive.
    pub fn open_session(self: &Arc<Self>) -> io::Result<(UdpSession, mpsc::Receiver<Packet>)> {
        if !self.udp {
            return Err(io::Error::other("hysteria2: UDP disabled by the server"));
        }
        let mut sessions = self.sessions.lock();
        if sessions.len() >= MAX_UDP_SESSIONS {
            return Err(io::Error::other("hysteria2: too many UDP sessions"));
        }
        let mut id = self.next_session.fetch_add(1, Ordering::Relaxed);
        while sessions.contains_key(&id) {
            id = self.next_session.fetch_add(1, Ordering::Relaxed);
        }
        let (tx, rx) = mpsc::channel(UDP_SESSION_QUEUE);
        sessions.insert(
            id,
            SessionEntry {
                tx,
                defragger: Defragger::default(),
            },
        );
        Ok((
            UdpSession {
                conn: self.clone(),
                id,
            },
            rx,
        ))
    }
}

/// A UDP session of a connection, closed when dropped.
pub struct UdpSession {
    conn: Arc<Connection>,
    id: u32,
}

impl UdpSession {
    pub fn send(&self, payload: &[u8], destination: &SocksAddr) -> io::Result<()> {
        let max = self
            .conn
            .conn
            .max_datagram_size()
            .ok_or_else(|| io::Error::other("hysteria2: the server takes no datagrams"))?;
        let packet_id = self.conn.next_packet.fetch_add(1, Ordering::Relaxed) as u16;
        let addr = proto::format_addr(destination);
        for fragment in proto::fragment(self.id, packet_id, &addr, payload, max)? {
            self.conn
                .conn
                .send_datagram(Bytes::from(fragment))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.conn.sessions.lock().remove(&self.id);
    }
}

/// Hands the datagrams of `conn` to their sessions.
async fn receive_datagrams(conn: quinn::Connection, sessions: Arc<Sessions>) {
    while let Ok(datagram) = conn.read_datagram().await {
        let msg = match UdpMessage::decode(&datagram) {
            Ok(msg) => msg,
            Err(e) => {
                debug!("hysteria2: invalid UDP message: {}", e);
                continue;
            }
        };
        let mut sessions = sessions.lock();
        let Some(entry) = sessions.get_mut(&msg.session_id) else {
            continue;
        };
        let Some(packet) = entry.defragger.feed(&msg) else {
            continue;
        };
        let from = match proto::parse_addr(msg.addr) {
            Ok(from) => from,
            Err(e) => {
                debug!("hysteria2: invalid UDP source: {}", e);
                continue;
            }
        };
        // A session that does not keep up loses packets, as UDP would.
        let _ = entry.tx.try_send((packet, from));
    }
    // The connection is gone: its sessions see the end at once.
    sessions.lock().clear();
}

/// What quinn talks to `to`, an address of the dialer's `targets`, over:
/// a socket of the dialer's or its detour's datagrams, obfuscated if
/// `obfs` is set; the address quinn is to connect to; and where it went
/// out.
async fn new_socket(
    dialer: &Dialer,
    dns_client: &SyncDnsClient,
    to: &SocksAddr,
    obfs: Option<&Salamander>,
) -> io::Result<(Arc<dyn quinn::AsyncUdpSocket>, SocketAddr, BoundInterface)> {
    let (socket, peer, bound) = dialer.quic_socket(dns_client, to).await?;
    Ok((quic::obfuscate(socket, obfs), peer, bound))
}

/// Moves to another port every `interval`, until the connection closes.
async fn hop_ports(
    conn: quinn::Connection,
    hop: Arc<HopSocket>,
    interval: Duration,
    to: SocksAddr,
    dialer: Dialer,
    dns_client: SyncDnsClient,
    obfs: Option<Salamander>,
) {
    loop {
        if timeout(interval, conn.closed()).await.is_ok() {
            return;
        }
        match new_socket(&dialer, &dns_client, &to, obfs.as_ref()).await {
            Ok((socket, ..)) => {
                hop.hop(socket);
                trace!("hysteria2: hopped ports");
            }
            Err(e) => debug!("hysteria2: port hop: {}", e),
        }
    }
}
