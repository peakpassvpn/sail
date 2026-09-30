//! The `direct` inbound, as sing-box's: what is sent to its listener goes
//! to the listener's own address, or to `override_address` /
//! `override_port`, and is routed like any other connection. With a
//! `hijack-dns` rule for it, it is a DNS server: sing-box's way of serving
//! DNS to a network, and what Mihomo's `dns.listen` comes down to.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::net::UdpSocket;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::*;
use crate::net::accept::{self, AcceptBackoff};
use crate::session::{DatagramSource, Session, SocksAddr};

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("direct", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectInboundOptions {
    /// Only `tcp`, or only `udp`; both when unset.
    #[serde(default)]
    network: Option<DirectNetwork>,
    /// Where what comes in goes, instead of the listener's address.
    #[serde(default)]
    override_address: Option<String>,
    /// The port it goes to, instead of the listener's.
    #[serde(default)]
    override_port: Option<u16>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
enum DirectNetwork {
    Tcp,
    Udp,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: DirectInboundOptions = ctx.options()?;
    if options.override_address.as_deref() == Some("") {
        return Err(anyhow!(
            "[{}] inbound: direct: override_address is empty",
            ctx.tag
        ));
    }
    let target = Arc::new(Override {
        address: options.override_address,
        // sing-box takes a port of 0 as none.
        port: options.override_port.filter(|p| *p != 0),
    });
    let stream = (options.network != Some(DirectNetwork::Udp))
        .then(|| Arc::new(StreamHandler(target.clone())) as AnyInboundStreamHandler);
    let datagram = (options.network != Some(DirectNetwork::Tcp))
        .then(|| Arc::new(DatagramHandler(target)) as AnyInboundDatagramHandler);
    Ok(Arc::new(Handler::new(ctx.tag.to_owned(), stream, datagram)))
}

/// What replaces the listener's address as the destination.
struct Override {
    address: Option<String>,
    port: Option<u16>,
}

impl Override {
    /// The destination of what was sent to `local`.
    fn destination(&self, local: SocketAddr) -> SocksAddr {
        let port = self.port.unwrap_or(local.port());
        match &self.address {
            None => SocksAddr::from(SocketAddr::new(unmapped(local.ip()), port)),
            Some(address) => match address.parse::<IpAddr>() {
                Ok(ip) => SocksAddr::from(SocketAddr::new(ip, port)),
                Err(_) => SocksAddr::Domain(address.clone(), port),
            },
        }
    }
}

/// `ip`, as IPv4 if it is an IPv4-mapped IPv6 address, as a dual-stack
/// listener reports IPv4 peers.
fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// A connection goes to the address it was accepted on, as overridden.
struct StreamHandler(Arc<Override>);

#[async_trait]
impl InboundStreamHandler for StreamHandler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        sess.destination = self.0.destination(sess.local_addr);
        Ok(InboundTransport::Stream(stream, sess))
    }
}

/// Each datagram goes to the address the listener is bound to, as
/// overridden, as in sing-box; replies go back from the listener.
struct DatagramHandler(Arc<Override>);

#[async_trait]
impl InboundDatagramHandler for DatagramHandler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        let socket = UdpSocket::from_std(socket.into_std()?)?;
        let destination = self.0.destination(socket.local_addr()?);
        Ok(InboundTransport::Datagram(
            Box::new(Datagram {
                socket: Arc::new(socket),
                destination,
            }),
            None,
        ))
    }
}

struct Datagram {
    socket: Arc<UdpSocket>,
    destination: SocksAddr,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf {
                socket: self.socket.clone(),
                destination: self.destination,
                backoff: AcceptBackoff::new("direct: receive"),
            }),
            Box::new(DatagramSendHalf(self.socket)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Arc::try_unwrap(self.socket)
            .map_err(|_| io::Error::other("direct: socket is shared"))?
            .into_std()
    }
}

struct DatagramRecvHalf {
    socket: Arc<UdpSocket>,
    destination: SocksAddr,
    /// Waits out what fails for one datagram, so the inbound serves on.
    backoff: AcceptBackoff,
}

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let (n, source) = accept::recv_from(&self.socket, buf, &mut self.backoff)
            .await
            .map_err(|e| ProxyError::DatagramFatal(e.into()))?;
        Ok((
            n,
            DatagramSource::new(source, None),
            self.destination.clone(),
        ))
    }
}

struct DatagramSendHalf(Arc<UdpSocket>);

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        _src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        self.0.send_to(buf, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::adapter::registry::{build_inbounds, Handlers};
    use crate::config::Config;
    use crate::include;

    fn build(json: &str) -> anyhow::Result<Handlers<AnyInboundHandler>> {
        let config = Config::from_json(json)?;
        let mut handlers = HashMap::new();
        build_inbounds(
            &include::INBOUNDS,
            &config.inbounds,
            include::LISTENER_INBOUNDS,
            &crate::runtime::RuntimeEnv::default(),
            &mut handlers,
            &mut HashMap::new(),
            &mut HashMap::new(),
        )?;
        Ok(handlers)
    }

    #[test]
    fn network_picks_what_it_listens_on() {
        let handlers = build(
            r#"{ "inbounds": [
                { "type": "direct", "tag": "both", "listen_port": 1 },
                { "type": "direct", "tag": "tcp", "listen_port": 2, "network": "tcp" },
                { "type": "direct", "tag": "udp", "listen_port": 3, "network": "udp" }
            ] }"#,
        )
        .unwrap();
        let networks = |tag: &str| {
            let h = &handlers[tag];
            (h.stream().is_ok(), h.datagram().is_ok())
        };
        assert_eq!(networks("both"), (true, true));
        assert_eq!(networks("tcp"), (true, false));
        assert_eq!(networks("udp"), (false, true));
    }

    #[test]
    fn an_unknown_field_is_an_error() {
        let err =
            build(r#"{ "inbounds": [ { "type": "direct", "listen_port": 1, "users": [] } ] }"#)
                .err()
                .unwrap();
        assert!(err.to_string().contains("users"), "{}", err);
    }

    #[test]
    fn the_destination_is_the_listeners_address_as_overridden() {
        let local: SocketAddr = "[::ffff:192.0.2.1]:53".parse().unwrap();
        let to = |address: Option<&str>, port: Option<u16>| {
            Override {
                address: address.map(str::to_owned),
                port,
            }
            .destination(local)
            .to_string()
        };
        assert_eq!(to(None, None), "192.0.2.1:53");
        assert_eq!(to(None, Some(5353)), "192.0.2.1:5353");
        assert_eq!(to(Some("8.8.8.8"), None), "8.8.8.8:53");
        assert_eq!(to(Some("::1"), Some(54)), "[::1]:54");
        assert_eq!(to(Some("dns.google"), Some(853)), "dns.google:853");
    }
}
