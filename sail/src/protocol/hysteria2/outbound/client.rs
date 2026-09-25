//! The client's one QUIC connection to its server: dialled, authenticated
//! and shared by every stream and UDP session, and dialled again once it
//! is gone.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use futures::future::{AbortHandle, Abortable};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::app::SyncDnsClient;
use crate::net::DialOptions;
use crate::session::SocksAddr;

use super::super::congestion::CongestionHandle;
use super::super::h3;
use super::super::hop::HopSocket;
use super::super::proto::{self, Defragger, UdpMessage};
use super::super::quic::{self, QuicStream};
use super::super::salamander::Salamander;

/// UDP sessions one connection carries at most.
const MAX_UDP_SESSIONS: usize = 1024;
/// Packets queued for a UDP session before more are dropped.
const UDP_SESSION_QUEUE: usize = 256;

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
    pub dial: Arc<DialOptions>,
}

pub struct Client {
    options: ClientOptions,
    conn: tokio::sync::Mutex<Option<Arc<Connection>>>,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        Self {
            options,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// The live connection, dialling one if there is none.
    pub async fn connection(&self) -> io::Result<Arc<Connection>> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            if conn.conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
            debug!(
                "hysteria2 connection closed: {:?}",
                conn.conn.close_reason()
            );
        }
        *guard = None;
        let conn = Arc::new(
            self.connect()
                .await
                .map_err(|e| io::Error::other(format!("hysteria2 connect failed: {:#}", e)))?,
        );
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Forgets `conn` if it is the current connection, so that the next
    /// request dials a new one.
    pub async fn discard(&self, conn: &Arc<Connection>) {
        let mut guard = self.conn.lock().await;
        if guard.as_ref().is_some_and(|c| Arc::ptr_eq(c, conn)) {
            *guard = None;
        }
    }

    /// Opens a proxied TCP stream to `destination`, with `payload` sent
    /// along with the request.
    pub async fn open_stream(
        &self,
        destination: &SocksAddr,
        payload: &[u8],
    ) -> io::Result<QuicStream> {
        let conn = self.connection().await?;
        let (mut send, mut recv) = match conn.conn.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                self.discard(&conn).await;
                return Err(io::Error::other(e));
            }
        };
        send.write_all(&proto::tcp_request(destination, payload))
            .await
            .map_err(io::Error::other)?;
        timeout(
            self.options.dial.connect_timeout,
            proto::read_tcp_response(&mut recv),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hysteria2 TCP response"))??;
        Ok(QuicStream::new(send, recv))
    }

    async fn connect(&self) -> Result<Connection> {
        let o = &self.options;
        let ips = o
            .dns_client
            .load_full()
            .direct_lookup(&o.server)
            .await
            .with_context(|| format!("lookup {}", o.server))?;
        let mut last_err = anyhow!("could not resolve {} to any address", o.server);
        for ip in ips {
            match timeout(o.dial.connect_timeout, self.connect_to(ip)).await {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => last_err = e,
                Err(_) => last_err = anyhow!("connect {} timed out", ip),
            }
        }
        Err(last_err)
    }

    async fn new_socket(&self, ip: IpAddr) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        let o = &self.options;
        let indicator = match ip {
            IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        let socket = crate::net::new_udp_socket(&indicator, &o.dial).await?;
        quic::wrap_socket(socket.into_std()?, o.obfs.as_ref())
    }

    async fn connect_to(&self, ip: IpAddr) -> Result<Connection> {
        let o = &self.options;
        let socket = self.new_socket(ip).await?;
        let (socket, remote, hop): (Arc<dyn quinn::AsyncUdpSocket>, _, _) = if o.ports.len() > 1 {
            let hop = Arc::new(HopSocket::new(ip, o.ports.clone(), socket));
            let remote = hop.virtual_addr();
            (hop.clone(), remote, Some(hop))
        } else {
            (socket, SocketAddr::new(ip, o.ports[0]), None)
        };
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn_btls::helpers::default_endpoint_config(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let congestion = CongestionHandle::default();
        let mut config = quinn::ClientConfig::new(o.crypto.clone());
        config.transport_config(Arc::new(quic::transport_config(
            &o.tuning,
            false,
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
                ip,
                o.dial.clone(),
                o.obfs.clone(),
            ));
        }
        Ok(Connection {
            conn,
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
        tokio::spawn(Abortable::new(task, registration));
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

/// Moves to another port every `interval`, until the connection closes.
async fn hop_ports(
    conn: quinn::Connection,
    hop: Arc<HopSocket>,
    interval: Duration,
    ip: IpAddr,
    dial: Arc<DialOptions>,
    obfs: Option<Salamander>,
) {
    let indicator = match ip {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    loop {
        if timeout(interval, conn.closed()).await.is_ok() {
            return;
        }
        let socket = match crate::net::new_udp_socket(&indicator, &dial).await {
            Ok(socket) => socket,
            Err(e) => {
                debug!("hysteria2: port hop: new socket: {}", e);
                continue;
            }
        };
        match socket
            .into_std()
            .and_then(|s| quic::wrap_socket(s, obfs.as_ref()))
        {
            Ok(socket) => {
                hop.hop(socket);
                trace!("hysteria2: hopped ports");
            }
            Err(e) => debug!("hysteria2: port hop: {}", e),
        }
    }
}
