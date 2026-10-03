//! The TUIC server: takes the inbound's UDP socket, runs a QUIC endpoint on
//! it, and hands on each `Connect` stream and each UDP association as a
//! transport of its own.

use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::Stream;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use crate::adapter::*;
use crate::session::{DatagramSource, Network, Session, SocksAddr, StreamId};
use crate::transport::quic::{endpoint, server_config, Side};

use super::super::common::{
    heartbeat, send_packet, token, tokens_equal, transport_config, ActiveGuard, Activity,
    CongestionControl, QuicStream, UdpRelayMode, ASSOCIATION_QUEUE, FRAGMENT_TIMEOUT,
    MAX_PENDING_PACKETS, UNI_STREAM_TIMEOUT,
};
use super::super::frag::Reassembler;
use super::super::proto::{
    decode_datagram, read_address, read_command, read_packet, Datagram, PacketHeader,
    CMD_AUTHENTICATE, CMD_CONNECT, CMD_DISSOCIATE, CMD_PACKET, TOKEN_LEN,
};

/// Transports accepted and not yet taken by the listener.
const ACCEPT_CHANNEL_SIZE: usize = 1024;
/// How long a connection may wait for room in the accept queue.
const ACCEPT_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
/// UDP associations one connection may hold.
const MAX_ASSOCIATIONS: usize = 256;
/// An association with no packet from the client for this long ends.
const ASSOCIATION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Tells UDP associations apart across connections.
static NEXT_ASSOCIATION: AtomicU64 = AtomicU64::new(1);

pub struct User {
    pub password: Vec<u8>,
    pub name: Option<crate::user::UserRef>,
}

struct Settings {
    /// The inbound's tag.
    tag: String,
    users: HashMap<[u8; 16], User>,
    auth_timeout: Duration,
    zero_rtt: bool,
    heartbeat: Duration,
    /// How long a client has to finish its handshake, without 0-RTT.
    handshake_timeout: Duration,
}

pub struct Server {
    resource: crate::runtime::resource::HotResource<Resources>,
}

pub(crate) struct Resources {
    server_config: quinn::ServerConfig,
    settings: Arc<Settings>,
}

impl Server {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: &str,
        users: HashMap<[u8; 16], User>,
        mut crypto: quinn_btls::ServerConfig,
        congestion: CongestionControl,
        auth_timeout: Duration,
        zero_rtt: bool,
        heartbeat: Duration,
        tuning: &crate::runtime::options::Quic,
    ) -> Result<Self> {
        use quinn_btls::QuicSslContext;
        crypto.ctx_mut().enable_early_data(zero_rtt);
        let mut server_config = server_config(crypto)?;
        server_config.transport_config(Arc::new(transport_config(
            congestion,
            tuning,
            Side::Server,
        )));
        Ok(Self {
            resource: crate::runtime::resource::HotResource::new(Resources {
                server_config,
                settings: Arc::new(Settings {
                    tag: tag.to_owned(),
                    users,
                    auth_timeout,
                    zero_rtt,
                    heartbeat,
                    handshake_timeout: tuning.server_handshake_timeout,
                }),
            }),
        })
    }

    pub(crate) fn reloadable(mut self, ctx: &crate::adapter::registry::InboundContext<'_>) -> Self {
        self.resource = ctx.resource(&ctx.state.tuic, self.resource.load());
        self
    }
}

#[async_trait]
impl InboundDatagramHandler for Server {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        let socket = socket.into_std()?;
        let local_addr = socket.local_addr()?;
        let endpoint = endpoint(socket, Some(self.resource.load().server_config.clone()))?;
        let (accepted, accepted_rx) = mpsc::channel(ACCEPT_CHANNEL_SIZE);
        let resource = self.resource.clone();
        crate::runtime::scope::spawn_essential("tuic accept", async move {
            // The connections, stopped when the inbound stops.
            let mut connections = JoinSet::new();
            loop {
                let incoming = tokio::select! {
                    incoming = endpoint.accept() => incoming,
                    // Nobody takes what is accepted any more.
                    _ = accepted.closed() => None,
                    Some(_) = connections.join_next(), if !connections.is_empty() => continue,
                };
                let Some(incoming) = incoming else {
                    break;
                };
                let generation = resource.load();
                let accepted = accepted.clone();
                crate::runtime::scope::spawn_child(
                    &mut connections,
                    "tuic connection",
                    async move {
                        let remote = incoming.remote_address();
                        if let Err(e) = serve(
                            generation.settings.clone(),
                            incoming,
                            generation.server_config.clone(),
                            accepted,
                            local_addr,
                        )
                        .await
                        {
                            debug!("tuic connection from {} failed: {}", remote, e);
                        }
                    },
                );
            }
            endpoint.close(quinn::VarInt::from_u32(0), b"");
        });
        Ok(InboundTransport::Incoming(Box::new(Incoming(accepted_rx))))
    }
}

struct Incoming(mpsc::Receiver<AnyBaseInboundTransport>);

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

/// The user a connection authenticated as, by name.
type Authed = Option<crate::user::UserRef>;

struct Association {
    packets: mpsc::Sender<(SocksAddr, Bytes)>,
    reassembler: Reassembler,
}

/// One client's QUIC connection.
struct Conn {
    conn: quinn::Connection,
    remote: SocketAddr,
    local_addr: SocketAddr,
    settings: Arc<Settings>,
    /// Set once, when `Authenticate` checks out.
    auth: watch::Sender<Option<Authed>>,
    /// Closes the connection when the user is shut out, or taken out.
    carrier: std::sync::OnceLock<crate::user::Carrier>,
    /// How many streams of each kind the client may hold open at once.
    bidi_streams: Arc<crate::transport::quic::StreamLimit>,
    uni_streams: Arc<crate::transport::quic::StreamLimit>,
    associations: Mutex<HashMap<u16, Association>>,
    activity: Activity,
    accepted: mpsc::Sender<AnyBaseInboundTransport>,
}

async fn serve(
    settings: Arc<Settings>,
    incoming: quinn::Incoming,
    server_config: quinn::ServerConfig,
    accepted: mpsc::Sender<AnyBaseInboundTransport>,
    local_addr: SocketAddr,
) -> Result<()> {
    let remote = incoming.remote_address();
    let connecting = incoming.accept_with(Arc::new(server_config))?;
    // What the connection runs besides its streams, stopped with it.
    let mut tasks = JoinSet::new();
    let conn = if settings.zero_rtt {
        // 0-RTT data is taken before the handshake is done; the
        // `Authenticate` it must wait for comes only after it anyway.
        match connecting.into_0rtt() {
            Ok((conn, accepted)) => {
                crate::runtime::scope::spawn_child(
                    &mut tasks,
                    "tuic connection task",
                    async move {
                        let accepted = accepted.await;
                        debug!(
                            "tuic 0-RTT from {} {}",
                            remote,
                            if accepted { "accepted" } else { "not used" }
                        );
                    },
                );
                conn
            }
            Err(connecting) => {
                crate::transport::quic::server_handshake(connecting, settings.handshake_timeout)
                    .await?
            }
        }
    } else {
        // With 0-RTT the authentication's own deadline bounds a silent
        // client; without, the handshake's does.
        crate::transport::quic::server_handshake(connecting, settings.handshake_timeout).await?
    };
    trace!("tuic connection from {}", remote);
    let bidi_streams = crate::transport::quic::StreamLimit::bidi(&conn);
    let uni_streams = crate::transport::quic::StreamLimit::uni(&conn);
    let conn = Arc::new(Conn {
        conn,
        remote,
        local_addr,
        settings: settings.clone(),
        auth: watch::Sender::new(None),
        carrier: std::sync::OnceLock::new(),
        bidi_streams,
        uni_streams,
        associations: Mutex::new(HashMap::new()),
        activity: Activity::default(),
        accepted,
    });

    crate::runtime::scope::spawn_child(
        &mut tasks,
        "tuic heartbeat",
        heartbeat(conn.conn.clone(), conn.activity.clone(), settings.heartbeat),
    );
    {
        let conn = conn.clone();
        crate::runtime::scope::spawn_child(&mut tasks, "tuic connection task", async move {
            tokio::select! {
                _ = tokio::time::sleep(conn.settings.auth_timeout) => {}
                _ = conn.conn.closed() => return,
            }
            if conn.auth.borrow().is_none() {
                debug!("tuic connection from {} did not authenticate", conn.remote);
                conn.conn
                    .close(quinn::VarInt::from_u32(0), b"authentication timeout");
            }
        });
    }

    tokio::join!(
        conn.clone().accept_uni(),
        conn.clone().accept_bi(),
        conn.clone().read_datagrams(),
    );
    // The associations end with the connection.
    conn.associations
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    Ok(())
}

impl Conn {
    /// The user, once authenticated; None if the connection closes first.
    async fn authed(&self) -> Option<Authed> {
        let mut rx = self.auth.subscribe();
        tokio::select! {
            authed = rx.wait_for(Option::is_some) => authed.ok().and_then(|a| a.clone()),
            _ = self.conn.closed() => None,
        }
    }

    /// The streams are read within the task that accepts them, so that
    /// stopping it lets them go: a stream kept keeps its connection open.
    async fn accept_uni(self: Arc<Self>) {
        let mut streams = JoinSet::new();
        loop {
            let recv = tokio::select! {
                accepted = self.conn.accept_uni() => match accepted {
                    Ok(recv) => recv,
                    Err(_) => return,
                },
                Some(_) = streams.join_next(), if !streams.is_empty() => continue,
            };
            let conn = self.clone();
            let counted = self.uni_streams.opened();
            crate::runtime::scope::spawn_child(&mut streams, "tuic stream", async move {
                let _counted = counted;
                if let Err(e) = conn.uni(recv).await {
                    debug!("tuic stream from {} failed: {}", conn.remote, e);
                }
            });
        }
    }

    async fn uni(&self, mut recv: quinn::RecvStream) -> io::Result<()> {
        let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "command timed out");
        let cmd = timeout(UNI_STREAM_TIMEOUT, read_command(&mut recv))
            .await
            .map_err(|_| timed_out())??;
        match cmd {
            CMD_AUTHENTICATE => {
                let mut body = [0u8; 16 + TOKEN_LEN];
                timeout(
                    UNI_STREAM_TIMEOUT,
                    AsyncReadExt::read_exact(&mut recv, &mut body),
                )
                .await
                .map_err(|_| timed_out())??;
                self.authenticate(&body)
            }
            CMD_PACKET => {
                let (header, payload) = timeout(UNI_STREAM_TIMEOUT, read_packet(&mut recv))
                    .await
                    .map_err(|_| timed_out())??;
                if let Some(user) = self.authed().await {
                    self.packet(header, payload, UdpRelayMode::Quic, user).await;
                }
                Ok(())
            }
            CMD_DISSOCIATE => {
                let assoc_id = timeout(UNI_STREAM_TIMEOUT, recv.read_u16())
                    .await
                    .map_err(|_| timed_out())??;
                if self.authed().await.is_some() {
                    trace!("tuic association {} dissociated", assoc_id);
                    self.associations
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&assoc_id);
                }
                Ok(())
            }
            other => Err(io::Error::other(format!(
                "unexpected command {:#04x} on a unidirectional stream",
                other
            ))),
        }
    }

    fn authenticate(&self, body: &[u8; 16 + TOKEN_LEN]) -> io::Result<()> {
        let fail = |why: &str| {
            self.conn
                .close(quinn::VarInt::from_u32(0), b"authentication failed");
            io::Error::new(io::ErrorKind::PermissionDenied, why.to_string())
        };
        if self.auth.borrow().is_some() {
            return Err(fail("authenticated twice"));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&body[..16]);
        let user = self.settings.users.get(&uuid);
        let Some(user) = user.filter(|user| !crate::user::shut_out(&user.name)) else {
            return Err(fail("unknown user"));
        };
        let expected = token(&self.conn, &uuid, &user.password)?;
        if !tokens_equal(&expected, &body[16..]) {
            return Err(fail("token mismatch"));
        }
        trace!(
            "tuic connection from {} authenticated as {:?}",
            self.remote,
            user.name
        );
        if let Some(name) = &user.name {
            let conn = self.conn.clone();
            let _ = self.carrier.set(name.carry(&self.settings.tag, move || {
                conn.close(quinn::VarInt::from_u32(0), b"")
            }));
        }
        // Its streams grow with its use from now on.
        self.bidi_streams.authenticated();
        self.uni_streams.authenticated();
        self.auth.send_replace(Some(user.name.clone()));
        Ok(())
    }

    /// Reads each stream's command, and hands the stream on; as with
    /// [`Conn::accept_uni`], within the task.
    async fn accept_bi(self: Arc<Self>) {
        let mut streams = JoinSet::new();
        loop {
            let (send, recv) = tokio::select! {
                accepted = self.conn.accept_bi() => match accepted {
                    Ok(stream) => stream,
                    Err(_) => return,
                },
                Some(_) = streams.join_next(), if !streams.is_empty() => continue,
            };
            let conn = self.clone();
            let counted = self.bidi_streams.opened();
            crate::runtime::scope::spawn_child(&mut streams, "tuic stream", async move {
                if let Err(e) = conn.bi(send, recv, counted).await {
                    debug!("tuic stream from {} failed: {}", conn.remote, e);
                }
            });
        }
    }

    async fn bi(
        &self,
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        counted: crate::transport::quic::StreamGuard,
    ) -> io::Result<()> {
        // Only the header is read before authentication, as the spec says.
        let header = async {
            let cmd = read_command(&mut recv).await?;
            if cmd != CMD_CONNECT {
                return Err(io::Error::other(format!(
                    "unexpected command {:#04x} on a bidirectional stream",
                    cmd
                )));
            }
            read_address(&mut recv)
                .await?
                .ok_or_else(|| io::Error::other("connect without an address"))
        };
        let destination = timeout(UNI_STREAM_TIMEOUT, header)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "command timed out"))??;
        let Some(user) = self.authed().await else {
            return Ok(());
        };
        let sess = Session {
            network: Network::Tcp,
            source: self.remote,
            local_addr: self.local_addr,
            destination,
            user,
            stream_id: Some(StreamId::U64(send.id().index())),
            ..Default::default()
        };
        let stream = QuicStream::guarded(send, recv, self.activity.start());
        let stream = crate::transport::quic::Counted::new(stream, counted);
        self.hand_on(BaseInboundTransport::Stream(Box::new(stream), sess))
            .await
    }

    async fn hand_on(&self, transport: AnyBaseInboundTransport) -> io::Result<()> {
        if self.accepted.capacity() == 0 {
            warn!("tuic accept queue full");
        }
        match timeout(ACCEPT_QUEUE_TIMEOUT, self.accepted.send(transport)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(io::Error::other("inbound closed")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "accept queue remained full",
            )),
        }
    }

    async fn read_datagrams(self: Arc<Self>) {
        let Some(user) = self.authed().await else {
            return;
        };
        while let Ok(data) = self.conn.read_datagram().await {
            match decode_datagram(data) {
                Ok(Datagram::Packet(header, payload)) => {
                    self.packet(header, payload, UdpRelayMode::Native, user.clone())
                        .await
                }
                Ok(Datagram::Heartbeat) => {}
                Err(e) => debug!("tuic datagram from {} dropped: {}", self.remote, e),
            }
        }
    }

    /// Takes a fragment for its association, starting the association if
    /// this is its first packet. Replies go the way this packet came.
    async fn packet(&self, header: PacketHeader, payload: Bytes, mode: UdpRelayMode, user: Authed) {
        let assoc_id = header.assoc_id;
        let new = {
            let mut associations = self.associations.lock().unwrap_or_else(|e| e.into_inner());
            let live = associations
                .get(&assoc_id)
                .is_some_and(|a| !a.packets.is_closed());
            let mut new = None;
            if !live {
                associations.retain(|_, a| !a.packets.is_closed());
                if associations.len() >= MAX_ASSOCIATIONS {
                    debug!(
                        "tuic connection from {} has too many associations",
                        self.remote
                    );
                    return;
                }
                let (tx, rx) = mpsc::channel(ASSOCIATION_QUEUE);
                associations.insert(
                    assoc_id,
                    Association {
                        packets: tx,
                        reassembler: Reassembler::new(MAX_PENDING_PACKETS, FRAGMENT_TIMEOUT),
                    },
                );
                new = Some(rx);
            }
            if let Some(association) = associations.get_mut(&assoc_id) {
                if let Some(packet) = association
                    .reassembler
                    .feed(header, payload, Instant::now())
                {
                    if association.packets.try_send(packet).is_err() {
                        trace!("tuic association {} queue full, packet dropped", assoc_id);
                    }
                }
            }
            new
        };
        let Some(packets) = new else {
            return;
        };
        let id = NEXT_ASSOCIATION.fetch_add(1, Ordering::Relaxed);
        let source = DatagramSource::new(self.remote, Some(StreamId::U64(id)));
        let sess = Session {
            network: Network::Udp,
            source: self.remote,
            local_addr: self.local_addr,
            user,
            stream_id: Some(StreamId::U64(id)),
            ..Default::default()
        };
        trace!(
            "tuic association {} from {} ({:?})",
            assoc_id,
            self.remote,
            mode
        );
        let datagram = AssociationDatagram {
            packets,
            conn: self.conn.clone(),
            assoc_id,
            mode,
            source,
            active: self.activity.start(),
        };
        if let Err(e) = self
            .hand_on(BaseInboundTransport::Datagram(
                Box::new(datagram),
                Some(sess),
            ))
            .await
        {
            debug!("tuic association {} not taken: {}", assoc_id, e);
        }
    }
}

/// One UDP association, as the NAT manager relays it.
struct AssociationDatagram {
    packets: mpsc::Receiver<(SocksAddr, Bytes)>,
    conn: quinn::Connection,
    assoc_id: u16,
    mode: UdpRelayMode,
    source: DatagramSource,
    active: ActiveGuard,
}

impl InboundDatagram for AssociationDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let active = Arc::new(self.active);
        (
            Box::new(AssociationRecvHalf {
                packets: self.packets,
                source: self.source,
                _active: active.clone(),
            }),
            Box::new(AssociationSendHalf {
                conn: self.conn,
                assoc_id: self.assoc_id,
                mode: self.mode,
                next_pkt_id: 0,
                _active: active,
            }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("tuic association"))
    }
}

struct AssociationRecvHalf {
    packets: mpsc::Receiver<(SocksAddr, Bytes)>,
    source: DatagramSource,
    _active: Arc<ActiveGuard>,
}

#[async_trait]
impl InboundDatagramRecvHalf for AssociationRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let (addr, payload) = match timeout(ASSOCIATION_IDLE_TIMEOUT, self.packets.recv()).await {
            Ok(Some(packet)) => packet,
            Ok(None) => return Err(ProxyError::DatagramFatal(anyhow!("dissociated"))),
            Err(_) => return Err(ProxyError::DatagramFatal(anyhow!("association idle"))),
        };
        if payload.len() > buf.len() {
            return Err(ProxyError::DatagramWarn(anyhow!(
                "packet of {} bytes exceeds the buffer",
                payload.len()
            )));
        }
        buf[..payload.len()].copy_from_slice(&payload);
        Ok((payload.len(), self.source.clone(), addr))
    }
}

struct AssociationSendHalf {
    conn: quinn::Connection,
    assoc_id: u16,
    mode: UdpRelayMode,
    next_pkt_id: u16,
    _active: Arc<ActiveGuard>,
}

#[async_trait]
impl InboundDatagramSendHalf for AssociationSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let pkt_id = self.next_pkt_id;
        self.next_pkt_id = self.next_pkt_id.wrapping_add(1);
        send_packet(&self.conn, self.mode, self.assoc_id, pkt_id, src_addr, buf).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
