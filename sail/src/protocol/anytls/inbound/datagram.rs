//! UDP over TCP on an inbound stream.

use std::io;
use std::net::SocketAddr;

use anyhow::anyhow;
use async_trait::async_trait;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};

use crate::adapter::*;
use crate::session::{DatagramSource, SocksAddr};

use super::super::session::Stream;
use super::super::uot;

pub struct Datagram {
    stream: Stream,
    /// The destination of every packet, in connect mode. Otherwise each
    /// packet names its own.
    connected: Option<SocksAddr>,
    source: DatagramSource,
}

impl Datagram {
    pub fn new(stream: Stream, connected: Option<SocksAddr>, source: DatagramSource) -> Self {
        Datagram {
            stream,
            connected,
            source,
        }
    }
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        let connected = self.connected.is_some();
        (
            Box::new(RecvHalf {
                r,
                connected: self.connected,
                source: self.source,
            }),
            Box::new(SendHalf { w, connected }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("stream transport"))
    }
}

struct RecvHalf {
    r: ReadHalf<Stream>,
    connected: Option<SocksAddr>,
    source: DatagramSource,
}

#[async_trait]
impl InboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let destination = match &self.connected {
            Some(destination) => destination.clone(),
            None => uot::read_addr(&mut self.r)
                .await
                .map_err(|e| ProxyError::DatagramFatal(e.into()))?,
        };
        match uot::read_payload(&mut self.r, buf)
            .await
            .map_err(|e| ProxyError::DatagramFatal(e.into()))?
        {
            Some(n) => Ok((n, self.source.clone(), destination)),
            None => Err(ProxyError::DatagramWarn(anyhow!(
                "anytls inbound dropped a UDP packet too large"
            ))),
        }
    }
}

struct SendHalf {
    w: WriteHalf<Stream>,
    connected: bool,
}

#[async_trait]
impl InboundDatagramSendHalf for SendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let addr = (!self.connected).then_some(src_addr);
        let packet = uot::encode_packet(addr, buf)?;
        self.w.write_all(&packet).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.w.shutdown().await
    }
}
