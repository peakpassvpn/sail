use std::io::{self};

use crate::app::dns::FakeIp;
use async_recursion::async_recursion;
use tokio::io::{AsyncRead, AsyncWrite};
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

use super::nat_manager::UdpPacket;

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

use super::router::{Decision, NoSniffer, Passes, PreMatch, SniffAction, Sniffer};

/// Where routing sends a connection.
enum Routed {
    /// Through this outbound; `None`, through the implicit direct, where
    /// every rule and `final` passed the connection on.
    Outbound(Option<String>),
    /// To the DNS client, which answers the queries it carries.
    HijackDns,
    /// Nowhere, and it is left unanswered.
    Drop,
}

/// How long a dropped connection is held unanswered at most: past it, any
/// client has given up.
const DROP_HOLD: std::time::Duration = std::time::Duration::from_secs(60);
use super::{SyncOutboundManager, SyncRouter};

/// Records on `sess` what a `sniff` rule found: the protocol, and the
/// domain a TLS ClientHello, over TCP or QUIC, or an HTTP request names. A
/// DNS query's domain is not where it goes, and is left out.
fn record_sniffed(
    sess: &mut Session,
    action: &SniffAction,
    protocol: SniffedProtocol,
    domain: Option<String>,
) {
    sess.sniffed_protocol = Some(protocol);
    let from = match protocol {
        SniffedProtocol::Tls | SniffedProtocol::Quic => SniffedFrom::Tls,
        SniffedProtocol::Http => SniffedFrom::Http,
        _ => {
            debug!("sniffed protocol={}", protocol);
            return;
        }
    };
    let Some(domain) = domain else {
        debug!("sniffed protocol={}", protocol);
        return;
    };
    if action.skip.matches(&domain) {
        debug!(
            "sniffed protocol={} domain={}, not taken",
            protocol, &domain
        );
        return;
    }
    debug!("sniffed protocol={} domain={}", protocol, &domain);
    if action.override_destination {
        if let Ok(dest) = SocksAddr::try_from((domain.as_str(), sess.destination.port())) {
            debug!("override destination with sniffed domain={}", dest);
            sess.destination = dest;
        }
    }
    sess.set_sniffed_domain(from, domain);
}

/// Whether a `sniff` rule has nothing to do for `sess`: its protocol is
/// known already, or the server of its port speaks first.
fn sniffed_already(sess: &Session) -> bool {
    sess.sniffed_protocol.is_some() || sniff::skips_port(sess.destination.port())
}

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
        let protocols = action.protocols.stream();
        if protocols.is_empty() || sniffed_already(sess) {
            return Ok(());
        }
        let sniffing = match self.sniffing.as_mut() {
            Some(sniffing) => sniffing,
            None => {
                let Some(stream) = self.stream.take() else {
                    return Ok(());
                };
                self.sniffing.insert(sniff::SniffingStream::new(stream))
            }
        };
        if let Some((protocol, domain)) = sniffing.sniff(protocols, action.timeout).await? {
            record_sniffed(sess, action, protocol, domain);
            // What rules match of a plain HTTP request: its URL and
            // User-Agent, never logged.
            if protocol == SniffedProtocol::Http {
                let request = sniff::http::request(sniffing.buffered());
                sess.sniffed_http = Some(std::sync::Arc::new(request));
            }
        }
        Ok(())
    }
}

/// Sniffs a UDP session from the datagrams its client sends first, taken
/// off the session's uplink while it is routed; they are sent on once it
/// is.
pub(crate) struct DatagramSniffer<'a> {
    uplink: &'a mut tokio::sync::mpsc::Receiver<UdpPacket>,
    /// The datagrams taken off the uplink, in order.
    read: Vec<UdpPacket>,
    /// The uplink has closed.
    closed: bool,
}

impl<'a> DatagramSniffer<'a> {
    pub(crate) fn new(uplink: &'a mut tokio::sync::mpsc::Receiver<UdpPacket>) -> Self {
        DatagramSniffer {
            uplink,
            read: Vec::new(),
            closed: false,
        }
    }

    /// The datagrams sniffing took off the uplink, still to be sent.
    pub(crate) fn into_read(self) -> Vec<UdpPacket> {
        self.read
    }
}

#[async_trait::async_trait]
impl Sniffer for DatagramSniffer<'_> {
    async fn sniff(&mut self, sess: &mut Session, action: &SniffAction) -> io::Result<()> {
        let protocols = action.protocols.datagram();
        if protocols.is_empty() || sniffed_already(sess) {
            return Ok(());
        }
        let deadline = tokio::time::Instant::now() + action.timeout;
        let mut sniff = sniff::DatagramSniff::new(protocols);
        // Those read by an earlier sniff first, then more as they come. Only
        // those to the session's destination are the client's first ones.
        for next in 0.. {
            if next == self.read.len() {
                if self.closed || next >= sniff::MAX_SNIFF_DATAGRAMS {
                    break;
                }
                match tokio::time::timeout_at(deadline, self.uplink.recv()).await {
                    Ok(Some(packet)) => self.read.push(packet),
                    Ok(None) => {
                        self.closed = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            let packet = &self.read[next];
            if packet.dst_addr != sess.destination {
                continue;
            }
            match sniff.feed(&packet.data) {
                sniff::Sniffed::Found(protocol, domain) => {
                    record_sniffed(sess, action, protocol, domain);
                    return Ok(());
                }
                sniff::Sniffed::NeedMore => {}
                sniff::Sniffed::NotMatch => break,
            }
        }
        if let Some(protocol) = sniff.settle() {
            record_sniffed(sess, action, protocol, None);
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
    pub(crate) outbound_manager: SyncOutboundManager,
    pub(crate) router: SyncRouter,
    dns_client: SyncDnsClient,
    stat_manager: SyncStatManager,
    dns_sniffer: DnsSniffer,
    env: crate::runtime::SyncRuntimeEnv,
    /// The protocol of each inbound, by tag.
    inbound_types: std::sync::RwLock<std::collections::HashMap<String, &'static str>>,
}

impl Dispatcher {
    pub fn new(
        outbound_manager: SyncOutboundManager,
        router: SyncRouter,
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
            inbound_types: Default::default(),
        }
    }

    /// Records the protocol of the inbound `tag`, or forgets the inbound.
    pub fn set_inbound_type(&self, tag: &str, protocol: Option<&str>) {
        let mut types = self
            .inbound_types
            .write()
            .unwrap_or_else(|e| e.into_inner());
        match protocol.and_then(crate::include::inbound_protocol) {
            Some(protocol) => types.insert(tag.to_string(), protocol),
            None => types.remove(tag),
        };
    }

    /// Fills in what the session's inbound tells about it.
    fn identify_inbound(&self, sess: &mut Session) {
        if sess.inbound_type.is_empty() {
            if let Some(protocol) = self
                .inbound_types
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&sess.inbound_tag)
            {
                sess.inbound_type = protocol;
            }
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

    async fn dispatch_stream_inner<T>(&self, sess: Session, lhs: T)
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        // Routing, which may sniff and resolve, runs in a future of its own
        // that is freed once it decides: the one relaying for the life of
        // the connection does not keep room for it.
        let Some((mut sess, routed, mut lhs)) = Box::pin(self.route_stream(sess, lhs)).await else {
            return;
        };
        let outbound = match routed {
            Routed::Outbound(tag) => tag,
            Routed::HijackDns => {
                if let Err(e) =
                    super::router::hijack_dns::serve_stream(&self.dns_client, lhs, &sess).await
                {
                    debug!("hijack-dns: {}", e);
                }
                return;
            }
            Routed::Drop => {
                // Read and thrown away, and never answered, until the
                // client gives up.
                let _ = tokio::time::timeout(
                    DROP_HOLD,
                    tokio::io::copy(&mut lhs, &mut tokio::io::sink()),
                )
                .await;
                return;
            }
        };

        let Some(h) = self.outbound_manager.load().handler(outbound.as_deref()) else {
            warn!("handler not found");
            return;
        };
        sess.outbound_tag = h.tag().clone();
        // The groups on the way record the members they take here.
        sess.chain = Default::default();

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
            let s = self.stat_manager.stat_stream(s, sess.clone());
            (Some(s), true)
        } else {
            lhs = self.stat_manager.stat_inbound_stream(lhs, sess.clone());
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
                if let Some(how) = sess.route.tls_fragment {
                    rhs = Box::new(super::router::fragment::FragmentStream::new(rhs, how));
                }
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                log_request(&sess, h.tag(), Some(elapsed.as_millis()));

                if !stats_wrapped {
                    rhs = self.stat_manager.stat_stream(rhs, sess.clone());
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
                    net::relay::RelayTimeouts {
                        write_stall: self.env.options.relay.write_stall_timeout,
                        a_to_b_idle: self.env.options.relay.uplink_idle_timeout,
                        b_to_a_idle: self.env.options.relay.downlink_idle_timeout,
                    },
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
        match self.route(&mut sess, &mut NoSniffer).await? {
            Routed::Outbound(outbound) => self.stream_through(outbound.as_deref(), sess).await,
            Routed::HijackDns | Routed::Drop => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "not routed to an outbound",
            )),
        }
    }

    /// The outbound the rules pick for `sess`, which is not dialled: for
    /// a DNS server that respects the rules; `None` when every rule and
    /// `final` passed it on, and it goes direct. An error when they pick
    /// none.
    pub async fn outbound_for(&self, sess: &mut Session) -> io::Result<Option<String>> {
        match self.route(sess, &mut NoSniffer).await? {
            Routed::Outbound(outbound) => Ok(outbound),
            Routed::HijackDns | Routed::Drop => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "not routed to an outbound",
            )),
        }
    }

    /// The DNS client what dials directly resolves with.
    pub(crate) fn dns_client(&self) -> SyncDnsClient {
        self.dns_client.clone()
    }

    /// The outbound connections go to when nothing says otherwise.
    pub fn default_outbound(&self) -> Option<String> {
        self.outbound_manager.load().default_handler()
    }

    /// A stream to the session's destination through the outbound `tag`,
    /// whatever the rules say: for a DNS server's `detour`.
    pub async fn stream_via(&self, tag: &str, sess: Session) -> io::Result<AnyStream> {
        self.stream_through(Some(tag), sess).await
    }

    /// A stream to the session's destination through the outbound `tag`,
    /// or the implicit direct.
    async fn stream_through(&self, tag: Option<&str>, mut sess: Session) -> io::Result<AnyStream> {
        let h = self.outbound_manager.load().handler(tag).ok_or_else(|| {
            io::Error::other(format!("outbound [{}] not found", tag.unwrap_or_default()))
        })?;
        sess.outbound_tag = h.tag().clone();
        sess.chain = Default::default();
        let stream =
            crate::net::connect_stream_outbound(&sess, self.dns_client.clone(), &h).await?;
        h.stream()?.handle(&sess, None, stream).await
    }

    /// Datagrams to the session's destination through the outbound `tag`,
    /// whatever the rules say: for a DNS server's `detour`.
    pub async fn datagram_via(
        &self,
        tag: &str,
        mut sess: Session,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        sess.outbound_tag = tag.to_string();
        sess.chain = Default::default();
        let h = self
            .outbound_manager
            .load()
            .get(tag)
            .ok_or_else(|| io::Error::other(format!("outbound [{}] not found", tag)))?;
        let transport =
            crate::net::connect_datagram_outbound(&sess, self.dns_client.clone(), &h).await?;
        h.datagram()?.handle(&sess, transport).await
    }

    /// Datagrams to where the rules send the UDP session `sess`, which
    /// `sniffer` reads the first datagrams of for a `sniff` rule, and how
    /// long the session lasts idle when a rule says.
    #[async_recursion]
    pub async fn dispatch_datagram(
        &self,
        mut sess: Session,
        sniffer: &mut dyn Sniffer,
    ) -> io::Result<(Box<dyn OutboundDatagram>, Option<std::time::Duration>)> {
        debug!(
            "dispatch proto={} in={} src={} dst={}",
            &sess.network, &sess.inbound_tag, &sess.source, &sess.destination
        );

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.sail" {
                let recv = HealthcheckUdpRecvHalf {
                    responded: false,
                    src_addr: sess.destination.clone(),
                };
                let d = HealthcheckUdpDatagram {
                    recv,
                    send: HealthcheckUdpSendHalf,
                };
                let d: Box<dyn OutboundDatagram> = Box::new(d);
                return Ok((d, None));
            }
        }

        self.identify_inbound(&mut sess);
        let reverse_mapping = self.reverse_map(&mut sess).await;
        let origin = sess.destination.clone();
        let outbound = match self.route(&mut sess, sniffer).await? {
            Routed::Outbound(outbound) => outbound,
            Routed::HijackDns => {
                let udp_timeout = sess.route.udp_timeout;
                let d = super::router::hijack_dns::Datagram::new(self.dns_client.clone(), sess);
                return Ok((Box::new(d), udp_timeout));
            }
            Routed::Drop => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "dropped by a rule",
                ))
            }
        };

        let Some(h) = self.outbound_manager.load().handler(outbound.as_deref()) else {
            warn!("handler not found");
            return Err(io::Error::other("handler not found"));
        };
        sess.outbound_tag = h.tag().clone();
        // The groups on the way record the members they take here.
        sess.chain = Default::default();

        let handshake_start = tokio::time::Instant::now();

        debug!("connect datagram outbound={}", h.tag());
        let transport =
            crate::net::connect_datagram_outbound(&sess, self.dns_client.clone(), &h).await?;

        match h.datagram()?.handle(&sess, transport).await {
            Ok(mut d) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);

                log_request(&sess, h.tag(), Some(elapsed.as_millis()));

                d = self.stat_manager.stat_outbound_datagram(d, sess.clone());

                if reverse_mapping && sess.destination.port() == 53 {
                    d = Box::new(SniffingDatagram::new(d, self.dns_sniffer.clone()));
                }
                // A destination a sniff or a rule overrode answers as the
                // one asked for.
                if sess.destination != origin {
                    d = Box::new(sniff::OverriddenDatagram::new(
                        d,
                        origin,
                        sess.destination.clone(),
                    ));
                }

                Ok((d, sess.route.udp_timeout))
            }
            Err(e) => {
                debug!("outbound handle err={}", e);
                log_request(&sess, h.tag(), None);
                Err(e)
            }
        }
    }

    /// Where the connection `lhs` goes, with the session and the stream as
    /// routing left them; `None` when it goes nowhere.
    async fn route_stream<T>(
        &self,
        mut sess: Session,
        mut lhs: T,
    ) -> Option<(Session, Routed, Box<dyn ProxyStream>)>
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        debug!(
            "dispatch proto={} in={} src={} dst={}",
            &sess.network, &sess.inbound_tag, &sess.source, &sess.destination
        );

        if let Some(domain) = sess.destination.domain() {
            if domain == "healthcheck.sail" {
                if let Err(e) = healthcheck_respond_simple(&mut lhs).await {
                    debug!("healthcheck response failed: {}", e);
                }
                return None;
            }
        }

        self.identify_inbound(&mut sess);
        if let Err(e) = self.restore_fake_ip(&mut sess.destination) {
            debug!("src={}: {}", &sess.source, e);
            return None;
        }
        self.reverse_map(&mut sess).await;
        let mut sniffer = StreamSniffer::new(lhs);
        match self.route(&mut sess, &mut sniffer).await {
            Ok(tag) => Some((sess, tag, sniffer.into_stream())),
            Err(e) => {
                debug!(
                    "route src={} dst={}: {}",
                    &sess.source, &sess.destination, e
                );
                None
            }
        }
    }

    /// The fake IP handed out for `domain`, of the family asked for: where
    /// a reply from the domain appears to come from.
    pub fn fake_ip_of(&self, domain: &str, ipv6: bool) -> Option<std::net::IpAddr> {
        self.dns_client.load().fake_ip_of(domain, ipv6)
    }

    /// A destination that is a fake IP becomes the domain it was handed out
    /// for, as sing-box's router has it. One the fakeip server does not
    /// know, handed out before a restart say, is an error: it cannot go
    /// where it was meant to.
    pub fn restore_fake_ip(&self, destination: &mut SocksAddr) -> io::Result<()> {
        let Some(ip) = destination.ip() else {
            return Ok(());
        };
        match self.dns_client.load().fake_ip(ip) {
            FakeIp::NotFake => Ok(()),
            FakeIp::Domain(domain) => {
                debug!("fake ip {} is {}", ip, domain);
                *destination = SocksAddr::Domain(domain, destination.port());
                Ok(())
            }
            FakeIp::Unknown => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing fakeip record for {}", ip),
            )),
        }
    }

    /// With `dns.reverse_mapping`, takes the domain of an address from the
    /// DNS answers seen, and says whether it is on.
    async fn reverse_map(&self, sess: &mut Session) -> bool {
        if !self.dns_client.load().reverse_mapping() {
            return false;
        }
        if let Some(ip) = sess.destination.ip() {
            if let Some(domain) = self.dns_sniffer.get(&ip).await {
                debug!("dns reverse mapped domain={}", &domain);
                sess.set_sniffed_domain(SniffedFrom::Dns, domain);
            }
        }
        true
    }

    /// The pre-match of a connection not yet set up, from its first packet
    /// (TUN's auto_redirect). As sing-box, a fake IP stands for its domain
    /// and reverse mapping applies first; a fake IP nobody knows leaves the
    /// connection to be set up, where it fails.
    pub async fn pre_match(&self, sess: &mut Session) -> PreMatch {
        if self.restore_fake_ip(&mut sess.destination).is_err() {
            return PreMatch::Proceed;
        }
        self.reverse_map(sess).await;
        let outbounds = self.outbound_manager.load_full();
        self.router.load_full().pre_match(sess, &*outbounds).await
    }

    /// Where `sess` goes, as the rules decide; an error when a rule rejects
    /// it.
    async fn route(&self, sess: &mut Session, sniffer: &mut dyn Sniffer) -> io::Result<Routed> {
        let outbounds = self.outbound_manager.load_full();
        let decision = self
            .router
            .load_full()
            .pick_route(sess, sniffer, &*outbounds)
            .await
            .map_err(|e| io::Error::other(format!("pick route: {}", e)))?;
        let tag = match decision {
            Decision::Route(Some(tag)) => tag,
            // The default outbound, no `final` naming another, passes as
            // `final` would.
            Decision::Route(None) => {
                let tag = outbounds
                    .default_handler()
                    .ok_or_else(|| io::Error::other("no outbound found"))?;
                if outbounds.passes(&tag).await {
                    debug!("the default outbound [{}] passes: direct", tag);
                    return Ok(Routed::Outbound(None));
                }
                tag
            }
            Decision::Direct => return Ok(Routed::Outbound(None)),
            Decision::Reject { drop: false } => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "rejected by a rule",
                ))
            }
            Decision::Reject { drop: true } => return Ok(Routed::Drop),
            Decision::HijackDns => return Ok(Routed::HijackDns),
        };
        debug!(
            "picked route out={} src={} dst={}",
            tag, &sess.source, &sess.destination
        );
        Ok(Routed::Outbound(Some(tag)))
    }

    pub async fn is_direct_outbound(&self, tag: &str) -> bool {
        if let Some(h) = self.outbound_manager.load().get(tag) {
            h.is_direct()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::sniff::Protocols;

    fn to_ip(network: Network) -> Session {
        Session {
            network,
            destination: SocksAddr::from(("1.2.3.4".parse::<IpAddr>().unwrap(), 443)),
            ..Default::default()
        }
    }

    fn action(protocols: Protocols) -> SniffAction {
        SniffAction {
            protocols,
            timeout: Duration::from_millis(300),
            override_destination: true,
            skip: Default::default(),
        }
    }

    #[tokio::test]
    async fn a_stream_is_sniffed_once_its_protocol_is_known() {
        let (mut client, server) = tokio::io::duplex(4096);
        let request = b"GET /a HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t/1\r\n\r\n";
        client.write_all(request).await.unwrap();
        let mut sess = to_ip(Network::Tcp);
        let mut sniffer = StreamSniffer::new(server);
        let action = action(Protocols::ALL);
        sniffer.sniff(&mut sess, &action).await.unwrap();
        assert_eq!(sess.sniffed_protocol, Some(SniffedProtocol::Http));
        assert_eq!(
            sess.sniffed_domain_from(SniffedFrom::Http),
            Some("example.com")
        );
        // Its URL and User-Agent, for the rules.
        let http = sess.sniffed_http.clone().unwrap();
        assert_eq!(
            http.url.as_ref().and_then(|u| u.whole()),
            Some("http://example.com/a")
        );
        assert_eq!(
            http.user_agent.as_ref().and_then(|u| u.whole()),
            Some("t/1")
        );
        assert_eq!(
            sess.destination,
            SocksAddr::Domain("example.com".into(), 443)
        );
        // Nothing more is read for a second rule.
        sniffer.sniff(&mut sess, &action).await.unwrap();
        let mut stream = sniffer.into_stream();
        client.shutdown().await.unwrap();
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.unwrap();
        assert_eq!(read, request);
    }

    #[cfg(feature = "rule-set")]
    #[tokio::test]
    async fn a_domain_a_skip_rule_set_matches_is_not_taken() {
        let skip = crate::app::router::rule_set::RuleSet::from_rules(
            &[
                serde_json::from_value(serde_json::json!({ "domain_suffix": ["push.apple.com"] }))
                    .unwrap(),
            ],
            &Default::default(),
        )
        .unwrap();
        let action = SniffAction {
            skip: super::super::router::SniffSkip::of(vec![(
                "skip".to_string(),
                crate::runtime::resource::HotResource::new(skip),
            )]),
            ..action(Protocols::ALL)
        };
        for (host, taken) in [("a.push.apple.com", false), ("example.com", true)] {
            let (mut client, server) = tokio::io::duplex(4096);
            let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
            client.write_all(request.as_bytes()).await.unwrap();
            let mut sess = to_ip(Network::Tcp);
            StreamSniffer::new(server)
                .sniff(&mut sess, &action)
                .await
                .unwrap();
            assert_eq!(sess.sniffed_protocol, Some(SniffedProtocol::Http));
            assert_eq!(sess.sniffed_domain_from(SniffedFrom::Http).is_some(), taken);
            assert_eq!(matches!(sess.destination, SocksAddr::Domain(..)), taken);
        }
    }

    #[tokio::test]
    async fn a_server_first_port_is_not_waited_on() {
        let (_client, server) = tokio::io::duplex(4096);
        let mut sess = Session {
            destination: SocksAddr::from(("1.2.3.4".parse::<IpAddr>().unwrap(), 25)),
            ..Default::default()
        };
        let mut sniffer = StreamSniffer::new(server);
        let action = SniffAction {
            timeout: Duration::from_secs(30),
            ..action(Protocols::ALL)
        };
        tokio::time::timeout(Duration::from_secs(1), sniffer.sniff(&mut sess, &action))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sess.sniffed_protocol, None);
    }

    #[tokio::test]
    async fn a_udp_session_is_sniffed_from_its_first_datagrams() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let source = SocksAddr::from(("10.0.0.1".parse::<IpAddr>().unwrap(), 5353));
        let mut sess = to_ip(Network::Udp);
        let mut query = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        // A datagram to another destination is not the session's.
        let other = SocksAddr::from(("5.6.7.8".parse::<IpAddr>().unwrap(), 443));
        for (data, to) in [(vec![0xff; 40], other), (query, sess.destination.clone())] {
            tx.send(UdpPacket::new(data, source.clone(), to))
                .await
                .unwrap();
        }
        let mut sniffer = DatagramSniffer::new(&mut rx);
        sniffer
            .sniff(&mut sess, &action(Protocols::ALL))
            .await
            .unwrap();
        // DNS names no destination.
        assert_eq!(sess.sniffed_protocol, Some(SniffedProtocol::Dns));
        assert_eq!(sess.sniffed_domain(), None);
        assert!(!sess.destination.is_domain());
        assert_eq!(sniffer.into_read().len(), 2);
    }

    #[cfg(feature = "btls")]
    #[tokio::test]
    async fn quic_across_datagrams_overrides_the_destination() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let source = SocksAddr::from(("10.0.0.1".parse::<IpAddr>().unwrap(), 5353));
        let mut sess = to_ip(Network::Udp);
        let hello = crate::sniff::tls::tests::hello("example.com");
        let half = hello.len() / 2;
        // The second half first.
        for (i, (offset, data)) in [(half, &hello[half..]), (0, &hello[..half])]
            .into_iter()
            .enumerate()
        {
            let mut frames = vec![0x06, 0x40 | (offset >> 8) as u8, offset as u8];
            frames.extend_from_slice(&[0x40 | (data.len() >> 8) as u8, data.len() as u8]);
            frames.extend_from_slice(data);
            frames.resize(1100, 0);
            let initial = crate::sniff::quic::protect(1, &[3; 8], i as u32, &frames).unwrap();
            let packet = UdpPacket::new(initial, source.clone(), sess.destination.clone());
            tx.send(packet).await.unwrap();
        }
        let mut sniffer = DatagramSniffer::new(&mut rx);
        sniffer
            .sniff(&mut sess, &action(Protocols::ALL))
            .await
            .unwrap();
        assert_eq!(sess.sniffed_protocol, Some(SniffedProtocol::Quic));
        assert_eq!(
            sess.sniffed_domain_from(SniffedFrom::Tls),
            Some("example.com")
        );
        assert_eq!(
            sess.destination,
            SocksAddr::Domain("example.com".into(), 443)
        );
        assert_eq!(sniffer.into_read().len(), 2);
    }

    #[tokio::test]
    async fn a_udp_sniff_waits_no_longer_than_the_timeout() {
        let (_tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut sess = to_ip(Network::Udp);
        let mut sniffer = DatagramSniffer::new(&mut rx);
        let action = SniffAction {
            timeout: Duration::from_millis(50),
            ..action(Protocols::ALL)
        };
        tokio::time::timeout(Duration::from_secs(1), sniffer.sniff(&mut sess, &action))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sess.sniffed_protocol, None);
    }
}
