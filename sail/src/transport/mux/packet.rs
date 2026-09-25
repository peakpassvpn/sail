//! UDP on a mux stream: packets of `length u16 | payload`, each after its
//! address (`destination | length u16 | payload`) when the stream asked
//! for addressed packets.
//!
//! The client here always asks for addressed packets, as sing-box does
//! for UDP it relays; the server takes both.

use std::io;
use std::net::SocketAddr;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::adapter::*;
use crate::session::{DatagramSource, SocksAddr, SocksAddrWireType};

use super::{read_status, STATUS_SUCCESS};

/// Reads a packet's length and payload into `buf`. A payload larger than
/// `buf` is read and dropped, and reported as `Ok(None)`, so that the
/// stream stays in step.
pub async fn read_payload<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
) -> io::Result<Option<usize>> {
    let len = r.read_u16().await? as usize;
    if len > buf.len() {
        let skipped = tokio::io::copy(&mut r.take(len as u64), &mut tokio::io::sink()).await?;
        if skipped != len as u64 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        return Ok(None);
    }
    r.read_exact(&mut buf[..len]).await?;
    Ok(Some(len))
}

/// A packet, with its address first if it has one.
pub fn encode(addr: Option<&SocksAddr>, payload: &[u8]) -> io::Result<BytesMut> {
    let len = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mux: packet too large"))?;
    let mut buf = BytesMut::with_capacity(1 + 1 + 255 + 2 + 2 + payload.len());
    if let Some(addr) = addr {
        addr.write_buf(&mut buf, SocksAddrWireType::PortLast);
    }
    buf.put_u16(len);
    buf.put_slice(payload);
    Ok(buf)
}

/// The client's end of a UDP stream, the request already sent.
pub struct ClientDatagram {
    pub stream: AnyStream,
}

impl OutboundDatagram for ClientDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(ClientRecvHalf {
                r,
                status_read: false,
            }),
            Box::new(ClientSendHalf(w)),
        )
    }
}

struct ClientRecvHalf {
    r: ReadHalf<AnyStream>,
    status_read: bool,
}

#[async_trait]
impl OutboundDatagramRecvHalf for ClientRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        if !self.status_read {
            read_status(&mut self.r).await?;
            self.status_read = true;
        }
        loop {
            let addr = SocksAddr::read_from(&mut self.r, SocksAddrWireType::PortLast).await?;
            match read_payload(&mut self.r, buf).await? {
                Some(n) => return Ok((n, addr)),
                None => tracing::debug!("mux dropped a UDP packet too large"),
            }
        }
    }
}

struct ClientSendHalf(WriteHalf<AnyStream>);

#[async_trait]
impl OutboundDatagramSendHalf for ClientSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        self.0.write_all(&encode(Some(target), buf)?).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

/// The server's end of a UDP stream, the request already read.
pub struct ServerDatagram {
    stream: AnyStream,
    /// The destination of every packet, when packets carry no address.
    fixed: Option<SocksAddr>,
    source: DatagramSource,
}

impl ServerDatagram {
    pub fn new(stream: AnyStream, fixed: Option<SocksAddr>, source: DatagramSource) -> Self {
        ServerDatagram {
            stream,
            fixed,
            source,
        }
    }
}

impl InboundDatagram for ServerDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        let addressed = self.fixed.is_none();
        (
            Box::new(ServerRecvHalf {
                r,
                fixed: self.fixed,
                source: self.source,
            }),
            Box::new(ServerSendHalf {
                w,
                addressed,
                status_written: false,
            }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("stream transport"))
    }
}

struct ServerRecvHalf {
    r: ReadHalf<AnyStream>,
    fixed: Option<SocksAddr>,
    source: DatagramSource,
}

#[async_trait]
impl InboundDatagramRecvHalf for ServerRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let fatal = |e: io::Error| ProxyError::DatagramFatal(e.into());
        let destination = match &self.fixed {
            Some(d) => d.clone(),
            None => SocksAddr::read_from(&mut self.r, SocksAddrWireType::PortLast)
                .await
                .map_err(fatal)?,
        };
        match read_payload(&mut self.r, buf).await.map_err(fatal)? {
            Some(n) => Ok((n, self.source.clone(), destination)),
            None => Err(ProxyError::DatagramWarn(anyhow!(
                "mux dropped a UDP packet too large"
            ))),
        }
    }
}

struct ServerSendHalf {
    w: WriteHalf<AnyStream>,
    addressed: bool,
    status_written: bool,
}

#[async_trait]
impl InboundDatagramSendHalf for ServerSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let packet = encode(self.addressed.then_some(src_addr), buf)?;
        if !self.status_written {
            let mut first = BytesMut::with_capacity(1 + packet.len());
            first.put_u8(STATUS_SUCCESS);
            first.put_slice(&packet);
            self.w.write_all(&first).await?;
            self.status_written = true;
        } else {
            self.w.write_all(&packet).await?;
        }
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.w.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_round_trip_and_oversized_ones_are_skipped() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let dest = SocksAddr::Domain("example.com".into(), 53);
                let mut wire = BytesMut::new();
                wire.extend_from_slice(&encode(Some(&dest), b"hello").unwrap());
                wire.extend_from_slice(&encode(Some(&dest), &[1; 100]).unwrap());
                wire.extend_from_slice(&encode(None, b"x").unwrap());
                let mut r = &wire[..];
                let mut buf = [0u8; 16];
                assert_eq!(
                    SocksAddr::read_from(&mut r, SocksAddrWireType::PortLast)
                        .await
                        .unwrap(),
                    dest
                );
                assert_eq!(read_payload(&mut r, &mut buf).await.unwrap(), Some(5));
                assert_eq!(&buf[..5], b"hello");
                SocksAddr::read_from(&mut r, SocksAddrWireType::PortLast)
                    .await
                    .unwrap();
                assert_eq!(read_payload(&mut r, &mut buf).await.unwrap(), None);
                assert_eq!(read_payload(&mut r, &mut buf).await.unwrap(), Some(1));
                assert!(r.is_empty());
                assert!(encode(None, &vec![0; 70000]).is_err());
            });
    }
}
