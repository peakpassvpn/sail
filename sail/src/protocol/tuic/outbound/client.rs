//! The TUIC client: one QUIC connection to the server, reused by every
//! stream and UDP association until it closes.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::adapter::*;
use crate::app::SyncDnsClient;
use crate::net::{peek_tcp_one_off, DialOptions};
use crate::session::{Session, SocksAddr};
use crate::transport::quic::{bind, endpoint, ClientTls, Side};

use super::super::common::{
    heartbeat, send_packet, token, transport_config, ActiveGuard, Activity, CongestionControl,
    QuicStream, UdpRelayMode, ASSOCIATION_QUEUE, FRAGMENT_TIMEOUT, MAX_PENDING_PACKETS,
    UNI_STREAM_TIMEOUT,
};
use super::super::frag::Reassembler;
use super::super::proto::{
    decode_datagram, encode_authenticate, encode_connect, encode_dissociate, read_command,
    read_packet, Datagram, PacketHeader, CMD_PACKET,
};

/// UDP associations one connection may hold.
const MAX_ASSOCIATIONS: usize = 1024;

pub struct ClientOptions<'a> {
    pub server: String,
    pub port: u16,
    pub tls: ClientTls,
    pub uuid: [u8; 16],
    pub password: Vec<u8>,
    pub congestion: CongestionControl,
    pub udp_relay_mode: UdpRelayMode,
    pub zero_rtt: bool,
    pub heartbeat: Duration,
    pub dns_client: SyncDnsClient,
    pub dial: Arc<DialOptions>,
    pub tuning: &'a crate::runtime::options::Quic,
}

pub struct Client {
    server: String,
    port: u16,
    server_name: String,
    uuid: [u8; 16],
    password: Vec<u8>,
    udp_relay_mode: UdpRelayMode,
    zero_rtt: bool,
    heartbeat: Duration,
    dns_client: SyncDnsClient,
    dial: Arc<DialOptions>,
    client_config: quinn::ClientConfig,
    /// The connection in use. Held while dialling, so that requests
    /// arriving meanwhile wait for the one connection being made.
    conn: tokio::sync::Mutex<Option<Arc<ClientConn>>>,
}

impl Client {
    pub fn new(options: ClientOptions<'_>) -> Self {
        let mut client_config = quinn::ClientConfig::new(Arc::new(options.tls.crypto));
        client_config.transport_config(Arc::new(transport_config(
            options.congestion,
            options.tuning,
            Side::Client,
        )));
        Self {
            server: options.server,
            port: options.port,
            server_name: options.tls.server_name,
            uuid: options.uuid,
            password: options.password,
            udp_relay_mode: options.udp_relay_mode,
            zero_rtt: options.zero_rtt,
            heartbeat: options.heartbeat,
            dns_client: options.dns_client,
            dial: options.dial,
            client_config,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// The connection in use, or a new one if it has closed.
    async fn connection(&self) -> io::Result<Arc<ClientConn>> {
        let mut current = self.conn.lock().await;
        if let Some(conn) = current.as_ref() {
            if conn.conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
        let conn = self.connect().await?;
        *current = Some(conn.clone());
        Ok(conn)
    }

    async fn connect(&self) -> io::Result<Arc<ClientConn>> {
        let ips = self
            .dns_client
            .load_full()
            .direct_lookup(&self.server)
            .await
            .map_err(|e| io::Error::other(format!("lookup {} failed: {}", self.server, e)))?;
        let mut last_err = None;
        for ip in ips {
            match self.connect_to(SocketAddr::new(ip, self.port)).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    debug!("tuic connect to {} failed: {}", ip, e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| io::Error::other(format!("{} resolved to no address", self.server))))
    }

    async fn connect_to(&self, server: SocketAddr) -> io::Result<Arc<ClientConn>> {
        let endpoint = endpoint(bind(server.ip(), &self.dial).await?, None)?;
        let connecting = endpoint
            .connect_with(self.client_config.clone(), server, &self.server_name)
            .map_err(io::Error::other)?;
        let connect_timeout = self.dial.connect_timeout;
        let handshake = |connecting: quinn::Connecting| async move {
            timeout(connect_timeout, connecting)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic handshake timed out"))?
                .map_err(io::Error::from)
        };
        // With 0-RTT the connection is used at once, but the token can be
        // exported only when the handshake is done.
        let (conn, handshake_done) = if self.zero_rtt {
            match connecting.into_0rtt() {
                Ok((conn, accepted)) => (conn, Some(accepted)),
                Err(connecting) => (handshake(connecting).await?, None),
            }
        } else {
            (handshake(connecting).await?, None)
        };
        trace!("tuic connected to {}", server);

        let client = Arc::new(ClientConn {
            conn: conn.clone(),
            associations: Mutex::new(Associations {
                map: HashMap::new(),
                next_id: 0,
            }),
            activity: Activity::default(),
            _endpoint: endpoint,
        });

        let uuid = self.uuid;
        let password = self.password.clone();
        tokio::spawn(async move {
            if let Some(done) = handshake_done {
                done.await;
            }
            if let Err(e) = authenticate(&conn, &uuid, &password).await {
                debug!("tuic authenticate failed: {}", e);
                conn.close(quinn::VarInt::from_u32(0), b"");
            }
        });
        tokio::spawn(heartbeat(
            client.conn.clone(),
            client.activity.clone(),
            self.heartbeat,
        ));
        tokio::spawn(client.clone().read_datagrams());
        tokio::spawn(client.clone().accept_uni());
        Ok(client)
    }
}

async fn authenticate(
    conn: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> io::Result<()> {
    let token = token(conn, uuid, password)?;
    let mut send = conn.open_uni().await.map_err(io::Error::other)?;
    send.write_all(&encode_authenticate(uuid, &token)).await?;
    send.finish().map_err(io::Error::other)?;
    Ok(())
}

struct ClientAssociation {
    packets: mpsc::Sender<(SocksAddr, Bytes)>,
    reassembler: Reassembler,
}

struct Associations {
    map: HashMap<u16, ClientAssociation>,
    next_id: u16,
}

struct ClientConn {
    conn: quinn::Connection,
    associations: Mutex<Associations>,
    activity: Activity,
    _endpoint: quinn::Endpoint,
}

impl ClientConn {
    fn associate(&self) -> io::Result<(u16, mpsc::Receiver<(SocksAddr, Bytes)>)> {
        let mut associations = self.associations.lock().unwrap_or_else(|e| e.into_inner());
        if associations.map.len() >= MAX_ASSOCIATIONS {
            return Err(io::Error::other("tuic: too many UDP associations"));
        }
        let mut id = associations.next_id;
        while associations.map.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        associations.next_id = id.wrapping_add(1);
        let (tx, rx) = mpsc::channel(ASSOCIATION_QUEUE);
        associations.map.insert(
            id,
            ClientAssociation {
                packets: tx,
                reassembler: Reassembler::new(MAX_PENDING_PACKETS, FRAGMENT_TIMEOUT),
            },
        );
        Ok((id, rx))
    }

    fn packet(&self, header: PacketHeader, payload: Bytes) {
        let mut associations = self.associations.lock().unwrap_or_else(|e| e.into_inner());
        let assoc_id = header.assoc_id;
        let Some(association) = associations.map.get_mut(&assoc_id) else {
            trace!("tuic packet for unknown association {}", assoc_id);
            return;
        };
        if let Some(packet) = association
            .reassembler
            .feed(header, payload, Instant::now())
        {
            if association.packets.try_send(packet).is_err() {
                trace!("tuic association {} queue full, packet dropped", assoc_id);
            }
        }
    }

    async fn read_datagrams(self: Arc<Self>) {
        while let Ok(data) = self.conn.read_datagram().await {
            match decode_datagram(data) {
                Ok(Datagram::Packet(header, payload)) => self.packet(header, payload),
                Ok(Datagram::Heartbeat) => {}
                Err(e) => debug!("tuic datagram dropped: {}", e),
            }
        }
        // The connection is gone: its associations end, so that whoever
        // waits for their packets hears so.
        self.associations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .clear();
    }

    /// Packets the server sends back in `quic` mode.
    async fn accept_uni(self: Arc<Self>) {
        while let Ok(mut recv) = self.conn.accept_uni().await {
            let conn = self.clone();
            tokio::spawn(async move {
                let packet = async {
                    let cmd = read_command(&mut recv).await?;
                    if cmd != CMD_PACKET {
                        return Err(io::Error::other(format!(
                            "unexpected command {:#04x} from the server",
                            cmd
                        )));
                    }
                    read_packet(&mut recv).await
                };
                match timeout(UNI_STREAM_TIMEOUT, packet).await {
                    Ok(Ok((header, payload))) => conn.packet(header, payload),
                    Ok(Err(e)) => debug!("tuic stream from the server failed: {}", e),
                    Err(_) => debug!("tuic stream from the server timed out"),
                }
            });
        }
    }
}

pub struct StreamHandler(pub Arc<Client>);

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let conn = self.0.connection().await?;
        let (mut send, recv) = conn.conn.open_bi().await.map_err(io::Error::other)?;
        let payload = peek_tcp_one_off(lhs).await;
        send.write_all(&encode_connect(&sess.destination, &payload)?)
            .await?;
        Ok(Box::new(QuicStream::guarded(
            send,
            recv,
            conn.activity.start(),
        )))
    }
}

pub struct DatagramHandler(pub Arc<Client>);

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        match self.0.udp_relay_mode {
            UdpRelayMode::Native => DatagramTransportType::Unreliable,
            UdpRelayMode::Quic => DatagramTransportType::Reliable,
        }
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let conn = self.0.connection().await?;
        let (assoc_id, packets) = conn.associate()?;
        trace!("tuic association {} for {}", assoc_id, sess.destination);
        let association = Arc::new(AssociationGuard {
            active: conn.activity.start(),
            conn,
            assoc_id,
        });
        Ok(Box::new(ClientDatagram {
            association,
            packets,
            mode: self.0.udp_relay_mode,
            destination: sess
                .destination
                .is_domain()
                .then(|| sess.destination.clone()),
        }))
    }
}

/// Ends the association, telling the server, when both halves are gone.
struct AssociationGuard {
    conn: Arc<ClientConn>,
    assoc_id: u16,
    active: ActiveGuard,
}

impl Drop for AssociationGuard {
    fn drop(&mut self) {
        let _ = &self.active;
        self.conn
            .associations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .remove(&self.assoc_id);
        if self.conn.conn.close_reason().is_some() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let conn = self.conn.conn.clone();
        let assoc_id = self.assoc_id;
        runtime.spawn(async move {
            let dissociate = async {
                let mut send = conn.open_uni().await.map_err(io::Error::other)?;
                send.write_all(&encode_dissociate(assoc_id)).await?;
                send.finish().map_err(io::Error::other)
            };
            if let Err(e) = timeout(UNI_STREAM_TIMEOUT, dissociate)
                .await
                .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)))
            {
                trace!("tuic dissociate {} failed: {}", assoc_id, e);
            }
        });
    }
}

struct ClientDatagram {
    association: Arc<AssociationGuard>,
    packets: mpsc::Receiver<(SocksAddr, Bytes)>,
    mode: UdpRelayMode,
    /// The session's destination when it is a domain, which replies are
    /// said to come from, as the server can only say which address did.
    destination: Option<SocksAddr>,
}

impl OutboundDatagram for ClientDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (
            Box::new(ClientRecvHalf {
                _association: self.association.clone(),
                packets: self.packets,
                destination: self.destination,
            }),
            Box::new(ClientSendHalf {
                association: self.association,
                mode: self.mode,
                next_pkt_id: 0,
            }),
        )
    }
}

struct ClientRecvHalf {
    _association: Arc<AssociationGuard>,
    packets: mpsc::Receiver<(SocksAddr, Bytes)>,
    destination: Option<SocksAddr>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for ClientRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (addr, payload) =
            self.packets.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "tuic connection closed")
            })?;
        if payload.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "packet exceeds the buffer",
            ));
        }
        buf[..payload.len()].copy_from_slice(&payload);
        let from = self.destination.clone().unwrap_or(addr);
        Ok((payload.len(), from))
    }
}

struct ClientSendHalf {
    association: Arc<AssociationGuard>,
    mode: UdpRelayMode,
    next_pkt_id: u16,
}

#[async_trait]
impl OutboundDatagramSendHalf for ClientSendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        let pkt_id = self.next_pkt_id;
        self.next_pkt_id = self.next_pkt_id.wrapping_add(1);
        let association = &self.association;
        send_packet(
            &association.conn.conn,
            self.mode,
            association.assoc_id,
            pkt_id,
            dst_addr,
            buf,
        )
        .await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
