use crate::session::DatagramSource;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};

use crate::{
    adapter::*,
    session::{SocksAddr, SocksAddrWireType},
};

use super::{shadow, HotResource, LegacyResources};

const SESSION_TTL: Duration = Duration::from_secs(300);
const MAX_SESSIONS: usize = 16 * 1024;

struct Peer {
    resource: Arc<LegacyResources>,
    seen: Instant,
}

/// Legacy SS UDP has no session ID: pin a credential to its authenticated
/// source address until idle expiry. Invalid packets never create a pin.
#[derive(Default)]
pub(crate) struct Sessions(Mutex<HashMap<SocketAddr, Peer>>);

impl Sessions {
    fn resource(&self, address: &SocketAddr) -> io::Result<Option<Arc<LegacyResources>>> {
        let mut peers = self
            .0
            .lock()
            .map_err(|_| io::Error::other("SS UDP sessions poisoned"))?;
        if peers
            .get(address)
            .is_some_and(|p| p.seen.elapsed() >= SESSION_TTL)
        {
            peers.remove(address);
        }
        Ok(peers.get(address).map(|p| p.resource.clone()))
    }

    fn authenticated(&self, address: SocketAddr, resource: Arc<LegacyResources>) -> io::Result<()> {
        let mut peers = self
            .0
            .lock()
            .map_err(|_| io::Error::other("SS UDP sessions poisoned"))?;
        if !peers.contains_key(&address) && peers.len() >= MAX_SESSIONS {
            peers.retain(|_, p| p.seen.elapsed() < SESSION_TTL);
            // Never evict an active peer just to admit another: that could
            // silently change its reply credential during rotation.
            if peers.len() >= MAX_SESSIONS {
                return Err(io::Error::other("SS UDP sessions full"));
            }
        }
        peers.insert(
            address,
            Peer {
                resource,
                seen: Instant::now(),
            },
        );
        Ok(())
    }
}

pub struct Handler {
    pub(super) resource: HotResource<LegacyResources>,
    pub(super) sessions: Arc<Sessions>,
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound datagram");
        Ok(InboundTransport::Datagram(
            Box::new(Datagram {
                resource: self.resource.clone(),
                sessions: self.sessions.clone(),
                socket,
            }),
            None,
        ))
    }
}

pub struct Datagram {
    resource: HotResource<LegacyResources>,
    sessions: Arc<Sessions>,
    socket: AnyInboundDatagram,
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
                resource: self.resource,
                sessions: self.sessions.clone(),
                inner: rh,
                buf: Vec::new(),
            }),
            Box::new(DatagramSendHalf(self.sessions, sh)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("shadowsocks datagram"))
    }
}

/// The last field is the buffer a packet is read into, reused.
pub struct DatagramRecvHalf {
    resource: HotResource<LegacyResources>,
    sessions: Arc<Sessions>,
    inner: Box<dyn InboundDatagramRecvHalf>,
    buf: Vec<u8>,
}

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        self.buf.resize(buf.len() + 1024, 0);
        let (n, src_addr, _) = self.inner.recv_from(&mut self.buf).await?;
        let recv_buf = BytesMut::from(&self.buf[..n]);
        let resource = self
            .sessions
            .resource(&src_addr.address)
            .map_err(|e| ProxyError::DatagramWarn(anyhow!(e)))?
            .unwrap_or_else(|| self.resource.load());
        let plaintext = resource
            .datagram
            .decrypt(recv_buf)
            .map_err(|e| ProxyError::DatagramWarn(anyhow!("Decrypt payload failed: {}", e)))?;
        let dst_addr = SocksAddr::try_from((&plaintext[..], SocksAddrWireType::PortLast))
            .map_err(|e| ProxyError::DatagramWarn(anyhow!("Parse target address failed: {}", e)))?;
        let header_size = dst_addr.size();
        let payload_size = plaintext.len() - header_size;
        if buf.len() < payload_size {
            return Err(ProxyError::DatagramWarn(anyhow!("SS packet too large")));
        }
        self.sessions
            .authenticated(src_addr.address, resource)
            .map_err(|e| ProxyError::DatagramWarn(anyhow!(e)))?;
        buf[..payload_size].copy_from_slice(&plaintext[header_size..header_size + payload_size]);
        Ok((payload_size, src_addr, dst_addr))
    }
}

pub struct DatagramSendHalf(Arc<Sessions>, Box<dyn InboundDatagramSendHalf>);

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let mut send_buf = BytesMut::new();
        src_addr.write_buf(&mut send_buf, SocksAddrWireType::PortLast);
        send_buf.put_slice(buf);
        let resource = self
            .0
            .resource(dst_addr)?
            .ok_or_else(|| io::Error::other("no SS UDP session"))?;
        let ciphertext = resource
            .datagram
            .encrypt(send_buf)
            .map_err(|_| shadow::crypto_err())?;
        self.1.send_to(&ciphertext[..], src_addr, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.1.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pins_are_bounded_and_expire() {
        let sessions = Sessions::default();
        let generation = Arc::new(LegacyResources {
            cipher: "aes-128-gcm".into(),
            password: "old".into(),
            datagram: shadow::ShadowedDatagram::new("aes-128-gcm", "old").unwrap(),
        });
        for port in 1..=MAX_SESSIONS as u16 {
            sessions
                .authenticated(SocketAddr::from(([127, 0, 0, 1], port)), generation.clone())
                .unwrap();
        }
        let extra = SocketAddr::from(([127, 0, 0, 1], 65000));
        assert!(sessions.authenticated(extra, generation.clone()).is_err());
        let first = SocketAddr::from(([127, 0, 0, 1], 1));
        assert!(Arc::ptr_eq(
            &generation,
            &sessions.resource(&first).unwrap().unwrap()
        ));
        sessions.0.lock().unwrap().get_mut(&first).unwrap().seen = Instant::now() - SESSION_TTL;
        assert!(sessions.resource(&first).unwrap().is_none());
        sessions.authenticated(extra, generation).unwrap();
    }
}
