use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};

use super::association::Associations;
use crate::{
    adapter::*,
    session::{DatagramSource, SocksAddr, SocksAddrWireType},
};

pub struct Handler {
    associations: Arc<Associations>,
    /// Whether clients authenticate, so that a datagram outside any
    /// association is nobody's to take.
    authenticated: bool,
}

impl Handler {
    /// Serves the datagrams of `associations`. When `authenticated`, those
    /// of no association are dropped.
    pub fn new(associations: Arc<Associations>, authenticated: bool) -> Self {
        Handler {
            associations,
            authenticated,
        }
    }
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound datagram");
        Ok(InboundTransport::Datagram(
            Box::new(Datagram {
                socket,
                associations: self.associations.clone(),
                authenticated: self.authenticated,
            }),
            None,
        ))
    }
}

pub struct Datagram {
    socket: Box<dyn InboundDatagram>,
    associations: Arc<Associations>,
    authenticated: bool,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (rh, sh) = self.socket.split();
        (
            Box::new(DatagramRecvHalf {
                socket: rh,
                associations: self.associations,
                authenticated: self.authenticated,
            }),
            Box::new(DatagramSendHalf(sh)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        self.socket.into_std()
    }
}

pub struct DatagramRecvHalf {
    socket: Box<dyn InboundDatagramRecvHalf>,
    associations: Arc<Associations>,
    authenticated: bool,
}

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let mut recv_buf = vec![0u8; buf.len() + 512];
        let (n, src, _) = self.socket.recv_from(&mut recv_buf).await?;
        if n < 3 {
            return Err(ProxyError::DatagramWarn(anyhow!("Short message")));
        }
        // Fragments are not supported; RFC 1928 lets a server drop them.
        if recv_buf[2] != 0 {
            return Err(ProxyError::DatagramWarn(anyhow!(
                "Fragmented datagram dropped"
            )));
        }
        let dst_addr = SocksAddr::try_from((&recv_buf[3..n], SocksAddrWireType::PortLast))
            .map_err(|e| ProxyError::DatagramWarn(anyhow!("Parse target address failed: {}", e)))?;
        let header_size = 3 + dst_addr.size();
        let payload_size = n
            .checked_sub(header_size)
            .ok_or_else(|| ProxyError::DatagramWarn(anyhow!("Short message")))?;
        if payload_size > buf.len() {
            return Err(ProxyError::DatagramWarn(anyhow!(
                "Datagram of {} bytes exceeds the {}-byte buffer, dropped",
                payload_size,
                buf.len()
            )));
        }
        let src = match self.associations.find(src.address) {
            Some(found) => src.with_user(found.user),
            None if self.authenticated => {
                return Err(ProxyError::DatagramWarn(anyhow!(
                    "Datagram from {} of no association dropped",
                    src.address
                )));
            }
            None => src,
        };
        buf[..payload_size].copy_from_slice(&recv_buf[header_size..header_size + payload_size]);
        Ok((payload_size, src, dst_addr))
    }
}

pub struct DatagramSendHalf(Box<dyn InboundDatagramSendHalf>);

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let mut send_buf = BytesMut::new();
        send_buf.put_u16(0);
        send_buf.put_u8(0);
        src_addr.write_buf(&mut send_buf, SocksAddrWireType::PortLast);
        send_buf.put_slice(buf);
        self.0.send_to(&send_buf[..], src_addr, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hands out one datagram, as a socket would.
    struct OnePacket(Vec<u8>);

    #[async_trait]
    impl InboundDatagramRecvHalf for OnePacket {
        async fn recv_from(
            &mut self,
            buf: &mut [u8],
        ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
            let n = self.0.len().min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            let src = DatagramSource::new("127.0.0.1:1".parse().unwrap(), None);
            Ok((n, src, SocksAddr::any()))
        }
    }

    fn packet(frag: u8, payload: usize) -> Vec<u8> {
        let mut p = vec![0, 0, frag, 0x01, 1, 2, 3, 4, 0, 53];
        p.resize(p.len() + payload, 0xab);
        p
    }

    async fn recv(packet: Vec<u8>, buf_len: usize) -> ProxyResult<usize> {
        let mut half = DatagramRecvHalf {
            socket: Box::new(OnePacket(packet)),
            associations: Default::default(),
            authenticated: false,
        };
        let mut buf = vec![0u8; buf_len];
        half.recv_from(&mut buf).await.map(|(n, _, _)| n)
    }

    #[tokio::test]
    async fn payload_is_unwrapped() {
        assert_eq!(recv(packet(0, 100), 2048).await.unwrap(), 100);
    }

    #[tokio::test]
    async fn oversized_payload_is_dropped_not_a_panic() {
        assert!(matches!(
            recv(packet(0, 3000), 2048).await,
            Err(ProxyError::DatagramWarn(_))
        ));
    }

    #[tokio::test]
    async fn truncated_header_and_fragments_are_dropped() {
        let mut short = packet(0, 0);
        short.truncate(7);
        assert!(matches!(
            recv(short, 2048).await,
            Err(ProxyError::DatagramWarn(_))
        ));
        assert!(matches!(
            recv(packet(1, 10), 2048).await,
            Err(ProxyError::DatagramWarn(_))
        ));
    }
}
