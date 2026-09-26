use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use tracing::{debug, warn};

use crate::{
    adapter::*,
    app::fake_dns::FakeDns,
    session::{DatagramSource, SocksAddr, SocksAddrWireType},
};

use super::packed::{SOCKADDR_IN, SOCKADDR_IN6};
use super::NfManager;

pub struct Handler {
    pub manager: Arc<NfManager>,
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound datagram");
        Ok(InboundTransport::Datagram(
            Box::new(Datagram {
                socket,
                fake_dns: self.manager.fake_dns.clone(),
            }),
            None,
        ))
    }
}

pub struct Datagram {
    socket: Box<dyn InboundDatagram>,
    fake_dns: Arc<FakeDns>,
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
            Box::new(DatagramRecvHalf(rh, self.fake_dns.clone())),
            Box::new(DatagramSendHalf(sh, self.fake_dns)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        self.socket.into_std()
    }
}

pub struct DatagramRecvHalf(Box<dyn InboundDatagramRecvHalf>, Arc<FakeDns>);

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let mut recv_buf = vec![0u8; buf.len()];
        let (n, mut src_addr, _) = self.0.recv_from(&mut recv_buf).await?;
        // Any local process can send here, not only udpSend.
        let recv_buf = &recv_buf[..n];
        let dst_addr = SocksAddr::try_from((recv_buf, SocksAddrWireType::PortLast))
            .map_err(|e| ProxyError::DatagramWarn(anyhow!("parse target address failed: {}", e)))?;
        let header_size = dst_addr.size() + 8;
        let Some(id) = recv_buf
            .get(dst_addr.size()..header_size)
            .and_then(|id| <[u8; 8]>::try_from(id).ok())
            .map(u64::from_be_bytes)
        else {
            return Err(ProxyError::DatagramWarn(anyhow!("short nf datagram")));
        };
        let real_payload = &recv_buf[header_size..];
        let payload_size = real_payload.len();
        if buf.len() < payload_size {
            return Err(ProxyError::DatagramWarn(anyhow!("nf datagram too large")));
        }

        let (local_addr, process_name) = if let Some(info) = super::UDP_LOCAL_INFO.lock().get(&id) {
            (info.local_address.clone(), info.process_name.clone())
        } else {
            return Err(ProxyError::DatagramWarn(anyhow!(format!(
                "local socket not found id={}",
                id
            ))));
        };

        // Override with real source address and process name.
        src_addr.address = local_addr;
        src_addr.process_name = process_name;

        if dst_addr.port() == 53 {
            match self.1.generate_fake_response(real_payload).await {
                Ok(resp) => {
                    match dst_addr.as_socket_addr() {
                        Some(dst) => {
                            if let Err(e) = udp_post_receive(&local_addr, *dst, &resp) {
                                warn!("send to local failed: {}", e);
                            }
                        }
                        None => warn!("fake dns reply to non-ip address {}", &dst_addr),
                    }
                    return Err(ProxyError::DatagramWarn(anyhow!(format!(
                        "responsed with fake ip, id={}",
                        id
                    ))));
                }
                Err(e) => {
                    debug!("generate fake ip failed: {}", e);
                }
            }
        }

        let dst_addr = match dst_addr {
            SocksAddr::Domain(domain, port) => SocksAddr::Domain(domain, port),
            SocksAddr::Ip(addr) => {
                if self.1.is_fake_ip(&addr.ip()).await {
                    if let Some(domain) = self.1.query_domain(&addr.ip()).await {
                        SocksAddr::Domain(domain, addr.port())
                    } else {
                        return Err(ProxyError::DatagramWarn(anyhow!(format!(
                            "paired domain not found ip={}",
                            &addr.ip()
                        ))));
                    }
                } else {
                    SocksAddr::Ip(addr)
                }
            }
        };

        buf[..payload_size].copy_from_slice(real_payload);
        Ok((payload_size, src_addr, dst_addr))
    }
}

pub struct DatagramSendHalf(Box<dyn InboundDatagramSendHalf>, Arc<FakeDns>);

fn udp_post_receive(
    local_addr: &SocketAddr,
    src_addr: SocketAddr,
    buf: &[u8],
) -> io::Result<usize> {
    if let Some(id) = super::UDP_ENDPOINT.lock().get(local_addr) {
        if let Some(options) = super::UDP_OPTIONS.lock().get(id) {
            let status = unsafe {
                match src_addr {
                    SocketAddr::V4(addr) => {
                        let addr: SOCKADDR_IN = addr.into();
                        let addr = &addr as *const SOCKADDR_IN as *const u8;
                        super::NF_UDP_POST_RECEIVE.expect(super::NF_FN_SET)(
                            *id,
                            addr,
                            buf.as_ptr(),
                            buf.len() as _,
                            options.as_ptr() as *const _ as *mut _,
                        )
                    }
                    SocketAddr::V6(addr) => {
                        let addr: SOCKADDR_IN6 = addr.into();
                        let addr = &addr as *const SOCKADDR_IN6 as *const u8;
                        super::NF_UDP_POST_RECEIVE.expect(super::NF_FN_SET)(
                            *id,
                            addr,
                            buf.as_ptr(),
                            buf.len() as _,
                            options.as_ptr() as *const _ as *mut _,
                        )
                    }
                }
            };
            if status != super::NF_STATUS_SUCCESS {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("status={}", status),
                ))
            } else {
                Ok(buf.len())
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("local socket not found, id={}", id),
            ))
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("local socket not found, local_addr={}", local_addr),
        ))
    }
}

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let src_addr = match src_addr {
            SocksAddr::Ip(a) => *a,
            SocksAddr::Domain(domain, port) => {
                if let Some(ip) = self.1.query_fake_ip(&domain).await {
                    SocketAddr::new(ip, *port)
                } else {
                    return Err(io::Error::other(format!(
                        "paired fake ip not found, addr={}:{}",
                        &domain, &port
                    )));
                }
            }
        };
        udp_post_receive(dst_addr, src_addr, buf)
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.close().await
    }
}
