use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use futures::stream::StreamExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tokio::time::timeout;
use tracing::{debug, info, trace, warn, Instrument};

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::{NatManager, UdpPacket};
use crate::session::{Network, Session, SocksAddr};
use crate::Runner;
use crate::{adapter::*, net::*};

#[cfg(feature = "inbound-nf")]
lazy_static::lazy_static! {
    pub static ref TCP_LISTENING_ADDRESSES: std::sync::RwLock<std::collections::HashMap<String, SocketAddr>> =
        std::sync::RwLock::new(std::collections::HashMap::new());
    pub static ref UDP_LISTENING_ADDRESSES: std::sync::RwLock<std::collections::HashMap<String, SocketAddr>> =
        std::sync::RwLock::new(std::collections::HashMap::new());
}

#[cfg(feature = "inbound-nf")]
pub fn get_network_listen_addr(tag: &str, kind: Network) -> Option<SocketAddr> {
    match kind {
        Network::Tcp => TCP_LISTENING_ADDRESSES.read().unwrap().get(tag).copied(),
        Network::Udp => UDP_LISTENING_ADDRESSES.read().unwrap().get(tag).copied(),
    }
}

// Handle an inbound datagram, which is similar to a UDP socket, managed by NAT
// manager.
async fn handle_inbound_datagram(
    inbound_tag: String,
    socket: Box<dyn InboundDatagram>,
    sess: Option<Session>,
    nat_manager: Arc<NatManager>,
) {
    let mut sess = sess.unwrap_or_default();
    sess.network = Network::Udp;
    let span = sess.span();
    handle_inbound_datagram_inner(inbound_tag, socket, sess, nat_manager)
        .instrument(span)
        .await
}

async fn handle_inbound_datagram_inner(
    inbound_tag: String,
    socket: Box<dyn InboundDatagram>,
    sess: Session,
    nat_manager: Arc<NatManager>,
) {
    // Left-hand side socket, it's usually encapsulated with inbound protocol
    // layers.
    let (mut lr, mut ls) = socket.split();

    // Datagrams read from the left-hand side socket would go through the NAT
    // manager first, which maintains UDP sessions, the NAT manager creates the
    // right-hand side socket by dispatching UDP sessions, then datagrams are sent
    // to the socket by the NAT manager. When the NAT manager reads some packets
    // from the right-hand side socket, they would be sent back here through a
    // channel, then we can send them to left-hand side socket.
    let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
        tokio_channel(nat_manager.env().options.udp.uplink_channel_size);

    tokio::spawn(
        async move {
            while let Some(pkt) = l_rx.recv().await {
                let dst_addr = pkt.dst_addr.must_ip();
                trace!("send udp packet dst={} len={}", &dst_addr, pkt.data.len());
                if let Err(e) = ls.send_to(&pkt.data[..], &pkt.src_addr, dst_addr).await {
                    debug!("send datagram failed: {}", e);
                }
            }
            if let Err(e) = ls.close().await {
                debug!("failed to close inbound datagram: {}", e);
            }
        }
        .instrument(sess.span()),
    );

    let mut buf = vec![0u8; nat_manager.env().options.udp.datagram_buffer_size * 1024];
    loop {
        match lr.recv_from(&mut buf).instrument(sess.span()).await {
            Err(ProxyError::DatagramFatal(e)) => {
                debug!("fatal error when receiving datagram: {}", e);
                break;
            }
            Err(ProxyError::DatagramWarn(e)) => {
                debug!("warning when receiving datagram: {}", e);
                continue;
            }
            Ok((n, dgram_src, dst_addr)) => {
                trace!("received udp packet src={} len={}", &dgram_src.address, n);
                let pkt = UdpPacket::new(
                    buf[..n].to_vec(),
                    SocksAddr::from(dgram_src.address),
                    dst_addr,
                );
                nat_manager
                    .send(Some(&sess), &dgram_src, &inbound_tag, &l_tx, pkt)
                    .instrument(sess.span())
                    .await;
            }
        }
    }
}

// Handle an inbound transport.
async fn handle_inbound_transport(
    transport: AnyInboundTransport,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
    match transport {
        // A reliable transport.
        InboundTransport::Stream(stream, sess) => {
            let span = sess.span();
            dispatcher
                .dispatch_stream(sess, stream)
                .instrument(span)
                .await;
        }
        // An unreliable transport.
        InboundTransport::Datagram(socket, sess) => {
            let span = sess.as_ref().map(|x| x.span());
            if let Some(span) = span {
                handle_inbound_datagram(handler.tag().clone(), socket, sess, nat_manager)
                    .instrument(span)
                    .await;
            } else {
                handle_inbound_datagram(handler.tag().clone(), socket, sess, nat_manager).await;
            }
        }
        // A multiplexed transport.
        InboundTransport::Incoming(mut incoming) => {
            while let Some(transport) = incoming.next().await {
                match transport {
                    BaseInboundTransport::Stream(stream, mut sess) => {
                        let dispatcher_cloned = dispatcher.clone();
                        sess.inbound_tag = handler.tag().clone();
                        tokio::spawn(async move {
                            dispatcher_cloned.dispatch_stream(sess, stream).await
                        });
                    }
                    BaseInboundTransport::Datagram(socket, sess) => {
                        tokio::spawn(handle_inbound_datagram(
                            handler.tag().clone(),
                            socket,
                            sess,
                            nat_manager.clone(),
                        ));
                    }
                    _ => (),
                }
            }
        }
        _ => (),
    }
}

// Handle an accepted inbound TCP stream.
async fn handle_inbound_tcp_stream(
    stream: TcpStream,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    // A connection without addresses has already gone away.
    let source = stream.peer_addr()?;
    let local_addr = stream.local_addr()?;
    let mut sess = Session {
        network: Network::Tcp,
        source,
        local_addr,
        inbound_tag: handler.tag().clone(),
        ..Default::default()
    };
    handler.accepted(socket2::SockRef::from(&stream), &mut sess)?;
    let span = sess.span();
    {
        let _g = span.enter();
        debug!(
            "handle inbound tcp stream src={} local={}",
            &source, &local_addr
        );
    }
    async move {
        // Transforms the TCP stream into an inbound transport.
        let transport = timeout(
            dispatcher.env().options.inbound.handshake_timeout,
            handler.stream()?.handle(sess, Box::new(stream)),
        )
        .instrument(tracing::Span::current())
        .await??;
        handle_inbound_transport(transport, handler, dispatcher, nat_manager)
            .instrument(tracing::Span::current())
            .await;
        Ok(())
    }
    .instrument(span)
    .await
}

// Handle inbounds which listen on TCP.
async fn handle_tcp_listen(
    listener: crate::net::TcpListener,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    let listen_addr = listener.io().local_addr()?;
    info!("listening tcp {}", &listen_addr);

    #[cfg(feature = "inbound-nf")]
    {
        TCP_LISTENING_ADDRESSES
            .write()
            .unwrap()
            .insert(handler.tag().clone(), listen_addr);
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let handler_cloned = handler.clone();
        let dispatcher_cloned = dispatcher.clone();
        let nat_manager_cloned = nat_manager.clone();
        tokio::spawn(async move {
            // Handle each TCP stream.
            if let Err(e) = handle_inbound_tcp_stream(
                stream,
                handler_cloned,
                dispatcher_cloned,
                nat_manager_cloned,
            )
            .await
            {
                debug!("handle inbound stream failed: {}", e);
            }
        });
    }
}

// Handle inbounds which bind on UDP.
async fn handle_udp_listen(
    socket: UdpSocket,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    let listen_addr = socket.local_addr()?;
    info!("listening udp {}", &listen_addr);

    #[cfg(feature = "inbound-nf")]
    {
        UDP_LISTENING_ADDRESSES
            .write()
            .unwrap()
            .insert(handler.tag().clone(), listen_addr);
    }

    // Transforms the UDP socket into an inbound transport.
    let transport = handler
        .datagram()?
        .handle(Box::new(SimpleInboundDatagram(socket)))
        .await?;
    handle_inbound_transport(transport, handler, dispatcher, nat_manager).await;
    Ok(())
}

pub struct NetworkInboundListener {
    pub address: SocketAddr,
    pub handler: AnyInboundHandler,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
}

impl NetworkInboundListener {
    /// Binds every socket the inbound listens on, failing if any cannot be
    /// bound, and returns the tasks that serve them. Must be called from
    /// within a Tokio runtime.
    pub fn listen(&self) -> Result<Vec<Runner>> {
        let tag = self.handler.tag();
        let listen_addr = self.address;
        let bind_failed = |network: &str, e: io::Error| {
            anyhow!(
                "[{}] inbound: listen {} {}: {}",
                tag,
                network,
                listen_addr,
                e
            )
        };
        let mut runners: Vec<Runner> = Vec::new();
        if self.handler.stream().is_ok() {
            let listener = crate::net::TcpListener::bind_now(&listen_addr)
                .map_err(|e| bind_failed("tcp", e))?
                .abort_on_close(self.dispatcher.env().options.inbound.tcp_abort_on_close);
            self.handler
                .prepare_listener(socket2::SockRef::from(listener.io()), Network::Tcp)
                .map_err(|e| bind_failed("tcp", e))?;
            let handler = self.handler.clone();
            let dispatcher = self.dispatcher.clone();
            let nat_manager = self.nat_manager.clone();
            runners.push(Box::pin(async move {
                if let Err(e) = handle_tcp_listen(listener, handler, dispatcher, nat_manager).await
                {
                    warn!("handler tcp listen failed: {}", e);
                }
            }));
        }
        if self.handler.datagram().is_ok() {
            let socket = std::net::UdpSocket::bind(listen_addr)
                .and_then(|socket| {
                    socket.set_nonblocking(true)?;
                    UdpSocket::from_std(socket)
                })
                .map_err(|e| bind_failed("udp", e))?;
            self.handler
                .prepare_listener(socket2::SockRef::from(&socket), Network::Udp)
                .map_err(|e| bind_failed("udp", e))?;
            let handler = self.handler.clone();
            let dispatcher = self.dispatcher.clone();
            let nat_manager = self.nat_manager.clone();
            runners.push(Box::pin(async move {
                if let Err(e) = handle_udp_listen(socket, handler, dispatcher, nat_manager).await {
                    warn!("handler udp listen failed: {}", e);
                }
            }));
        }
        Ok(runners)
    }
}
