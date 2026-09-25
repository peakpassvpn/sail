//! Shadowsocks 2022 outbound handlers.

use std::{convert::TryFrom, io, sync::Arc};

use async_trait::async_trait;

use crate::{adapter::*, net::*, session::*};

use super::sip022::{stream, udp, Method};

pub struct StreamHandler {
    pub address: String,
    pub port: u16,
    pub method: Method,
    /// The key chain: the server's first, the user's last.
    pub psks: Arc<Vec<Vec<u8>>>,
}

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound ss2022 stream");
        let stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        // The request header carries the first payload, so that it goes
        // out in one piece.
        let payload = peek_tcp_one_off(lhs).await;
        let stream =
            stream::connect(stream, self.method, &self.psks, &sess.destination, &payload).await?;
        Ok(Box::new(stream))
    }
}

pub struct DatagramHandler {
    pub address: String,
    pub port: u16,
    pub method: Method,
    pub psks: Arc<Vec<Vec<u8>>>,
}

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Udp, self.address.clone(), self.port)
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound ss2022 datagram");
        let server_addr = SocksAddr::try_from((&self.address, self.port))?;
        let Some(OutboundTransport::Datagram(socket)) = transport else {
            // A stream transport would lose the datagram boundaries.
            return Err(io::Error::other("invalid ss input"));
        };
        let (sender, receiver) = udp::client(self.method, &self.psks)?;
        let destination = match &sess.destination {
            SocksAddr::Domain(domain, port) => Some(SocksAddr::Domain(domain.to_owned(), *port)),
            _ => None,
        };
        Ok(Box::new(Datagram {
            sender,
            receiver,
            socket,
            destination,
            server_addr,
        }))
    }
}

struct Datagram {
    sender: udp::ClientSender,
    receiver: udp::ClientReceiver,
    socket: Box<dyn OutboundDatagram>,
    destination: Option<SocksAddr>,
    server_addr: SocksAddr,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, s) = self.socket.split();
        (
            Box::new(RecvHalf {
                receiver: self.receiver,
                inner: r,
                destination: self.destination,
                buf: Vec::new(),
            }),
            Box::new(SendHalf {
                sender: self.sender,
                inner: s,
                server_addr: self.server_addr,
            }),
        )
    }
}

struct RecvHalf {
    receiver: udp::ClientReceiver,
    inner: Box<dyn OutboundDatagramRecvHalf>,
    destination: Option<SocksAddr>,
    buf: Vec<u8>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        self.buf.resize(buf.len() + 1024, 0);
        loop {
            let (n, _) = self.inner.recv_from(&mut self.buf).await?;
            let packet = &mut self.buf[..n];
            // A packet that fails to authenticate or is a replay is
            // dropped, not an error on the whole association.
            let (src, range) = match self.receiver.decode(packet) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("drop ss2022 packet: {}", e);
                    continue;
                }
            };
            let payload = &packet[range];
            if payload.len() > buf.len() {
                tracing::debug!("drop ss2022 packet: too large");
                continue;
            }
            buf[..payload.len()].copy_from_slice(payload);
            return Ok((payload.len(), self.destination.clone().unwrap_or(src)));
        }
    }
}

struct SendHalf {
    sender: udp::ClientSender,
    inner: Box<dyn OutboundDatagramSendHalf>,
    server_addr: SocksAddr,
}

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let packet = self.sender.encode(target, buf)?;
        self.inner.send_to(&packet, &self.server_addr).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}
