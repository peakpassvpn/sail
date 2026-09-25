use std::io::{self};
use std::sync::Arc;

use async_recursion::async_recursion;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, Instrument};

use crate::{
    adapter::*,
    app::SyncDnsClient,
    net,
    session::*,
    sniff::{
        self,
        dns::{DnsSniffer, SniffingDatagram},
    },
};

use tokio::io::AsyncWriteExt;

async fn healthcheck_respond_simple<T>(stream: &mut T) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    stream.write_all(b"PONG").await?;
    stream.flush().await?;
    Ok(())
}

use crate::app::SyncStatManager;

use super::outbound::manager::OutboundManager;
use super::router::{Decision, NoSniffer, Router, SniffAction, Sniffer};

/// Sniffs a TCP connection the first time a rule asks, and keeps what it
/// read for whoever reads the connection next. A connection no rule sniffs
/// is left as it is.
struct StreamSniffer<T> {
    stream: Option<T>,
    sniffing: Option<sniff::SniffingStream<T>>,
}

impl<T> StreamSniffer<T>
where
    T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn new(stream: T) -> Self {
        StreamSniffer {
            stream: Some(stream),
            sniffing: None,
        }
    }

    fn into_stream(self) -> Box<dyn ProxyStream> {
        match (self.sniffing, self.stream) {
            (Some(sniffing), _) => Box::new(sniffing),
            (None, Some(stream)) => Box::new(stream),
            (None, None) => unreachable!("the stream is in one or the other"),
        }
    }
}

#[async_trait::async_trait]
impl<T> Sniffer for StreamSniffer<T>
where
    T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    async fn sniff(&mut self, sess: &mut Session, action: &SniffAction) -> io::Result<()> {
        // A connection is sniffed once, and one to a domain not at all.
        if self.sniffing.is_some() || sess.destination.is_domain() {
            return Ok(());
        }
        let Some(stream) = self.stream.take() else {
            return Ok(());
        };
        let sniffing = self.sniffing.insert(sniff::SniffingStream::new(stream));
        let Some((kind, domain)) = sniffing.sniff(action.timeout).await? else {
            return Ok(());
        };
        let wanted = match kind {
            sniff::SniffKind::Tls => action.tls,
            sniff::SniffKind::Http => action.http,
        };
        if !wanted {
            return Ok(());
        }
        debug!("sniffed domain={}", &domain);
        if action.override_destination {
            if let Ok(dest) = SocksAddr::try_from((domain.as_str(), sess.destination.port())) {
                debug!("override destination with sniffed domain={}", dest);
                sess.destination = dest;
            }
        }
        match kind {
            sniff::SniffKind::Tls => sess.tls_sniffed_domain = Some(domain),
            sniff::SniffKind::Http => sess.http_sniffed_domain = Some(domain),
        }
        Ok(())
    }
}

struct HealthcheckUdpRecvHalf {
    responded: bool,
    src_addr: SocksAddr,
}

#[async_trait::async_trait]
impl OutboundDatagramRecvHalf for HealthcheckUdpRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        if self.responded {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no more data"));
        }
        let pong = b"PONG";
        if buf.len() < pong.len() {
            return Err(io::Error::other("buffer too small"));
        }
        buf[..pong.len()].copy_from_slice(pong);
        self.responded = true;
        Ok((pong.len(), self.src_addr.clone()))
    }
}

struct HealthcheckUdpSendHalf;

#[async_trait::async_trait]
impl OutboundDatagramSendHalf for HealthcheckUdpSendHalf {
    async fn send_to(&mut self, buf: &[u8], _dst_addr: &SocksAddr) -> io::Result<usize> {
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct HealthcheckUdpDatagram {
    recv: HealthcheckUdpRecvHalf,
    send: HealthcheckUdpSendHalf,
}

impl OutboundDatagram for HealthcheckUdpDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(self.recv), Box::new(self.send))
    }
}

#[inline]
fn log_request(sess: &Session, outbound_tag: &str, handshake_time: Option<u128>) {
    let hs = handshake_time.map_or("failed".to_string(), |hs| format!("{}ms", hs));
    let network = sess.network.to_string();

    #[cfg(feature = "rule-process-name")]
    {
        let process_name = sess
            .process_name
            .as_ref()
            .map(|x| {
                std::path::Path::new(x)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(x)
            })
            .unwrap_or("");
        info!(
            "handled process={} src={} proto={} in={} out={} connect={} dst={}",
            process_name,
            sess.forwarded_source.unwrap_or_else(|| sess.source.ip()),
            network,
            &sess.inbound_tag,
            outbound_tag,
            hs,
            &sess.destination,
        );
    }

    #[cfg(not(feature = "rule-process-name"))]
    {
        info!(
            "handled src={} proto={} in={} out={} connect={} dst={}",
            sess.forwarded_source.unwrap_or_else(|| sess.source.ip()),
            network,
            &sess.inbound_tag,
            outbound_tag,
            hs,
            &sess.destination,
        );
    }
}

pub struct Dispatcher {
    pub(crate) outbound_manager: Arc<RwLock<OutboundManager>>,
    pub(crate) router: Arc<RwLock<Router>>,
    dns_client: SyncDnsClient,
    stat_manager: SyncStatManager,
    dns_sniffer: DnsSniffer,
    env: crate::runtime::SyncRuntimeEnv,
}

impl Dispatcher {
    pub fn new(
        outbound_manager: Arc<RwLock<OutboundManager>>,
        router: Arc<RwLock<Router>>,
        dns_client: SyncDnsClient,
        stat_manager: SyncStatManager,
        env: crate::runtime::SyncRuntimeEnv,
    ) -> Self {
        Dispatcher {
            outbound_manager,
            router,
            dns_client,
            stat_manager,
            dns_sniffer: DnsSniffer::new(),
            env,
        }
    }

    /// The tuning and host of the instance this dispatcher belongs to.
    pub fn env(&self) -> &crate::runtime::RuntimeEnv {
        &self.env
    }

    pub async fn dispatch_stream<T>(&self, sess: Session, lhs: T)
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        let span = sess.span();
        self.dispatch_stream_inner(sess, lhs).instrument(span).await
    }

    async fn dispatch_stream_inner<T>(&self, mut sess: Session, mut lhs: T)
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        debug!(
            "dispatch proto={} in={} src={} dst={}",
            &sess.network, &sess.inbound_tag, &sess.source, &sess.destination
        );

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.leaf" {
                if let Err(e) = healthcheck_respond_simple(&mut lhs).await {
                    debug!("healthcheck response failed: {}", e);
                }
                return;
            }
        }

        self.reverse_map(&mut sess).await;
        let mut sniffer = StreamSniffer::new(lhs);
        let outbound = match self.route(&mut sess, &mut sniffer).await {
            Ok(tag) => tag,
            Err(e) => {
                debug!(
                    "route src={} dst={}: {}",
                    &sess.source, &sess.destination, e
                );
                return;
            }
        };
        let mut lhs = sniffer.into_stream();

        sess.outbound_tag = outbound.clone();

        let h = if let Some(h) = self.outbound_manager.read().await.get(&outbound) {
            h
        } else {
            // FIXME use  the default handler
            warn!("handler not found");
            return;
        };

        let handshake_start = tokio::time::Instant::now();
        let stream =
            match crate::net::connect_stream_outbound(&sess, self.dns_client.clone(), &h).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(
                        "connect outbound src={} dst={} out={} err={}",
                        &sess.source,
                        &sess.destination,
                        &h.tag(),
                        e
                    );
                    log_request(&sess, h.tag(), None);
                    return;
                }
            };

        let (stream, stats_wrapped) = if let Some(s) = stream {
            let s = self.stat_manager.write().await.stat_stream(s, sess.clone());
            (Some(s), true)
        } else {
            lhs = self
                .stat_manager
                .write()
                .await
                .stat_inbound_stream(lhs, sess.clone());
            (None, true)
        };

        let th = match h.stream() {
            Ok(th) => th,
            Err(e) => {
                debug!("get stream handler, err={}", e);
                return;
            }
        };
        match th.handle(&sess, Some(&mut lhs), stream).await {
            Ok(mut rhs) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                log_request(&sess, h.tag(), Some(elapsed.as_millis()));

                if !stats_wrapped {
                    rhs = self
                        .stat_manager
                        .write()
                        .await
                        .stat_stream(rhs, sess.clone());
                }

                match net::relay::copy_buf_bidirectional_with_timeout(
                    &mut lhs,
                    &mut rhs,
                    self.env.options.relay.buffer_size * 1024,
                    self.env
                        .options
                        .relay
                        .buffer_max_size
                        .max(self.env.options.relay.buffer_size)
                        * 1024,
                    self.env.options.relay.uplink_timeout,
                    self.env.options.relay.downlink_timeout,
                )
                .await
                {
                    Ok(_) => {
                        debug!("transfer end");
                    }
                    Err(e) => {
                        debug!("transfer err={}", e);
                    }
                }
            }
            Err(e) => {
                debug!("outbound handle err={}", e);
                log_request(&sess, h.tag(), None);
            }
        }
    }

    pub async fn dispatch_stream_outbound(&self, mut sess: Session) -> io::Result<AnyStream> {
        let outbound = self.route(&mut sess, &mut NoSniffer).await?;

        sess.outbound_tag = outbound.clone();

        let h = if let Some(h) = self.outbound_manager.read().await.get(&outbound) {
            h
        } else {
            return Err(io::Error::other("handler not found"));
        };

        let stream =
            crate::net::connect_stream_outbound(&sess, self.dns_client.clone(), &h).await?;
        h.stream()?.handle(&sess, None, stream).await
    }

    #[async_recursion]
    pub async fn dispatch_datagram(
        &self,
        mut sess: Session,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        debug!(
            "dispatch proto={} in={} src={} dst={}",
            &sess.network, &sess.inbound_tag, &sess.source, &sess.destination
        );

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.leaf" {
                let recv = HealthcheckUdpRecvHalf {
                    responded: false,
                    src_addr: sess.destination.clone(),
                };
                let d = HealthcheckUdpDatagram {
                    recv,
                    send: HealthcheckUdpSendHalf,
                };
                let d: Box<dyn OutboundDatagram> = Box::new(d);
                return Ok(d);
            }
        }

        let reverse_mapping = self.reverse_map(&mut sess).await;
        let outbound = self.route(&mut sess, &mut NoSniffer).await?;

        sess.outbound_tag = outbound.clone();

        let h = if let Some(h) = self.outbound_manager.read().await.get(&outbound) {
            h
        } else {
            warn!("handler not found");
            return Err(io::Error::other("handler not found"));
        };

        let handshake_start = tokio::time::Instant::now();

        debug!("connect datagram outbound={}", h.tag());
        let transport =
            crate::net::connect_datagram_outbound(&sess, self.dns_client.clone(), &h).await?;

        match h.datagram()?.handle(&sess, transport).await {
            Ok(mut d) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                log_request(&sess, h.tag(), Some(elapsed.as_millis()));

                d = self
                    .stat_manager
                    .write()
                    .await
                    .stat_outbound_datagram(d, sess.clone());

                if reverse_mapping && sess.destination.port() == 53 {
                    d = Box::new(SniffingDatagram::new(d, self.dns_sniffer.clone()));
                }

                Ok(d)
            }
            Err(e) => {
                debug!("outbound handle err={}", e);
                log_request(&sess, h.tag(), None);
                Err(e)
            }
        }
    }

    /// With `dns.reverse_mapping`, takes the domain of an address from the
    /// DNS answers seen, and says whether it is on.
    async fn reverse_map(&self, sess: &mut Session) -> bool {
        if !self.dns_client.read().await.reverse_mapping() {
            return false;
        }
        if let Some(ip) = sess.destination.ip() {
            if let Some(domain) = self.dns_sniffer.get(&ip).await {
                debug!("dns reverse mapped domain={}", &domain);
                sess.dns_sniffed_domain = Some(domain);
            }
        }
        true
    }

    /// The outbound `sess` goes to, as the rules decide.
    async fn route(&self, sess: &mut Session, sniffer: &mut dyn Sniffer) -> io::Result<String> {
        let decision = self
            .router
            .read()
            .await
            .pick_route(sess, sniffer)
            .await
            .map_err(|e| io::Error::other(format!("pick route: {}", e)))?;
        let tag = match decision {
            Decision::Route(Some(tag)) => tag,
            Decision::Route(None) => self
                .outbound_manager
                .read()
                .await
                .default_handler()
                .ok_or_else(|| io::Error::other("no outbound found"))?,
            Decision::Reject => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "rejected by a rule",
                ))
            }
        };
        debug!(
            "picked route out={} src={} dst={}",
            tag, &sess.source, &sess.destination
        );
        Ok(tag)
    }

    pub async fn is_direct_outbound(&self, tag: &str) -> bool {
        if let Some(h) = self.outbound_manager.read().await.get(tag) {
            h.is_direct()
        } else {
            false
        }
    }
}
