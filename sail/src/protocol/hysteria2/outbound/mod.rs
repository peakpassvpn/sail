//! The Hysteria2 outbound: TCP as QUIC streams and UDP as QUIC datagrams
//! over one authenticated connection to the server.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::sync::mpsc;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::*;
use crate::net::peek_tcp_one_off;
use crate::session::{Session, SocksAddr};
use crate::transport::layers::{Blocks, Listable, OutboundTls};

use super::hop;
use super::proto::MBPS_TO_BPS;
use super::quic;
use super::Obfs;

mod client;

use client::{Client, ClientOptions, Packet, UdpSession};

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "hysteria2",
        OutboundFactory::standalone(build).with_blocks(Blocks::DIAL),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hysteria2OutboundOptions {
    server: String,
    /// The one port; with `server_ports`, not needed.
    #[serde(default)]
    server_port: Option<u16>,
    /// Ports or ranges ("20000:30000") to hop between.
    #[serde(default)]
    server_ports: Option<Listable>,
    /// How often to hop, 30s unless set.
    #[serde(default, with = "crate::config::model::duration")]
    hop_interval: Option<Duration>,
    /// What we may send at; set, it selects Brutal.
    #[serde(default)]
    up_mbps: Option<u64>,
    /// What we can receive at, told to the server.
    #[serde(default)]
    down_mbps: Option<u64>,
    #[serde(default)]
    obfs: Option<Obfs>,
    password: String,
    tls: OutboundTls,
    /// "tcp" or "udp", or both, as unset.
    #[serde(default)]
    network: Option<Listable>,
}

const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);
/// sing-box's floor for `hop_interval`.
const MIN_HOP_INTERVAL: Duration = Duration::from_secs(5);

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: Hysteria2OutboundOptions = ctx.options()?;
    let tag = ctx.tag.to_owned();
    let err = |msg: String| anyhow!("[{}] outbound: {}", tag, msg);

    let ports = match (&options.server_ports, options.server_port) {
        (Some(ports), _) => hop::parse_ports(&ports.clone().into_vec())
            .map_err(|e| err(format!("server_ports: {}", e)))?,
        (None, Some(port)) => vec![port],
        (None, None) => return Err(err("server_port: missing".into())),
    };
    let hop_interval = match options.hop_interval {
        Some(interval) if interval < MIN_HOP_INTERVAL => {
            return Err(err(format!(
                "hop_interval: at least {:?}",
                MIN_HOP_INTERVAL
            )))
        }
        Some(interval) => Some(interval),
        None if ports.len() > 1 => Some(DEFAULT_HOP_INTERVAL),
        None => None,
    };

    let tls = options.tls;
    if !tls.enabled {
        return Err(err("tls: hysteria2 needs tls enabled".into()));
    }
    if tls.reality.as_ref().is_some_and(|r| r.enabled) {
        return Err(err("tls.reality: not supported over QUIC".into()));
    }
    if tls.ech.as_ref().is_some_and(|e| e.enabled) {
        return Err(err("tls.ech: not supported over QUIC".into()));
    }
    if tls.utls.as_ref().is_some_and(|u| u.enabled) {
        return Err(err("tls.utls: not supported over QUIC".into()));
    }
    let certificate = match (&tls.certificate, &tls.certificate_path) {
        (Some(inline), None) => Some(inline.clone().joined()),
        (None, Some(path)) => Some(ctx.env.data_path(path)),
        (None, None) => None,
        (Some(_), Some(_)) => {
            return Err(err(
                "tls: set at most one of certificate and certificate_path".into(),
            ))
        }
    };
    let crypto = quic::client_crypto(
        certificate.as_deref(),
        tls.insecure,
        &quic::alpns(tls.alpn.clone()),
    )
    .map_err(|e| err(format!("tls: {}", e)))?;

    let obfs = options
        .obfs
        .map(|o| o.salamander())
        .transpose()
        .map_err(|e| err(format!("obfs: {}", e)))?;

    let (mut tcp, mut udp) = (true, true);
    if let Some(network) = options.network {
        (tcp, udp) = (false, false);
        for n in network.into_vec() {
            match n.as_str() {
                "tcp" => tcp = true,
                "udp" => udp = true,
                other => return Err(err(format!("network: unknown network \"{}\"", other))),
            }
        }
    }

    let client = Arc::new(Client::new(ClientOptions {
        server_name: tls
            .server_name
            .clone()
            .unwrap_or_else(|| options.server.clone()),
        server: options.server,
        ports,
        hop_interval,
        password: options.password,
        send_bps: options.up_mbps.unwrap_or(0) * MBPS_TO_BPS,
        recv_bps: options.down_mbps.unwrap_or(0) * MBPS_TO_BPS,
        obfs,
        crypto: Arc::new(crypto),
        tuning: ctx.env.options.quic.clone(),
        dns_client: ctx.dns_client.clone(),
        dial: ctx.dial.clone(),
    }));

    let mut builder = HandlerBuilder::default().tag(ctx.tag.to_owned());
    if tcp {
        builder = builder.stream_handler(Arc::new(StreamHandler(client.clone())));
    }
    if udp {
        builder = builder.datagram_handler(Arc::new(DatagramHandler(client)));
    }
    Ok(builder.build())
}

struct StreamHandler(Arc<Client>);

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
        let payload = peek_tcp_one_off(lhs).await;
        let stream = self.0.open_stream(&sess.destination, &payload).await?;
        Ok(Box::new(stream))
    }
}

struct DatagramHandler(Arc<Client>);

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let conn = self.0.connection().await?;
        let (session, rx) = conn.open_session()?;
        Ok(Box::new(Datagram {
            session: Arc::new(session),
            rx,
        }))
    }
}

struct Datagram {
    session: Arc<UdpSession>,
    rx: mpsc::Receiver<Packet>,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf {
                rx: self.rx,
                _session: self.session.clone(),
            }),
            Box::new(DatagramSendHalf(Some(self.session))),
        )
    }
}

struct DatagramRecvHalf {
    rx: mpsc::Receiver<Packet>,
    /// Keeps the session registered while either half lives.
    _session: Arc<UdpSession>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (packet, from) = self
            .rx
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        if packet.len() > buf.len() {
            return Err(io::Error::other(format!(
                "hysteria2: UDP packet of {} bytes, buffer of {}",
                packet.len(),
                buf.len()
            )));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), from))
    }
}

struct DatagramSendHalf(Option<Arc<UdpSession>>);

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let session = self
            .0
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        session.send(buf, target)?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0 = None;
        Ok(())
    }
}
