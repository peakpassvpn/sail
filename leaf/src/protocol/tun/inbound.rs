use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::{sink::SinkExt, stream::StreamExt};
use serde_derive::Deserialize;
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::{
    app::dispatcher::Dispatcher,
    app::fake_dns::{FakeDns, FakeDnsMode},
    app::nat_manager::NatManager,
    app::nat_manager::UdpPacket,
    config::model::{parse_options, Inbound},
    session::{DatagramSource, Network, Session, SocksAddr},
    Runner,
};

#[cfg(feature = "netstack-lwip")]
use super::netstack_lwip as lwip;
#[cfg(feature = "netstack-smoltcp")]
use super::netstack_smoltcp as smoltcp;

#[cfg(feature = "netstack-lwip")]
async fn handle_inbound_stream_lwip(
    stream: Pin<Box<lwip::TcpStream>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    inbound_tag: String,
    dispatcher: Arc<Dispatcher>,
    fakedns: Option<Arc<FakeDns>>,
) {
    let mut sess = Session {
        network: Network::Tcp,
        source: local_addr,
        local_addr: remote_addr,
        destination: SocksAddr::Ip(remote_addr),
        inbound_tag,
        ..Default::default()
    };
    // Whether to override the destination according to Fake DNS.
    if let Some(fakedns) = fakedns {
        if fakedns.is_fake_ip(&remote_addr.ip()).await {
            if let Some(domain) = fakedns.query_domain(&remote_addr.ip()).await {
                sess.destination = SocksAddr::Domain(domain, remote_addr.port());
            } else {
                // Although requests targeting fake IPs are assumed
                // never happen in real network traffic, which are
                // likely caused by poisoned DNS cache records, we
                // still have a chance to sniff the request domain
                // for TLS traffic in dispatcher.
                if remote_addr.port() != 443 && remote_addr.port() != 80 {
                    debug!(
                        "No paired domain found for this fake IP: {}, connection is rejected.",
                        &remote_addr.ip()
                    );
                    return;
                }
            }
        }
    }
    dispatcher.dispatch_stream(sess, stream).await;
}

#[cfg(feature = "netstack-smoltcp")]
async fn handle_inbound_stream_smoltcp(
    stream: Pin<Box<smoltcp::TcpStream>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    inbound_tag: String,
    dispatcher: Arc<Dispatcher>,
    fakedns: Option<Arc<FakeDns>>,
) {
    let mut sess = Session {
        network: Network::Tcp,
        source: local_addr,
        local_addr: remote_addr,
        destination: SocksAddr::Ip(remote_addr),
        inbound_tag,
        ..Default::default()
    };
    // Whether to override the destination according to Fake DNS.
    if let Some(fakedns) = fakedns {
        if fakedns.is_fake_ip(&remote_addr.ip()).await {
            if let Some(domain) = fakedns.query_domain(&remote_addr.ip()).await {
                sess.destination = SocksAddr::Domain(domain, remote_addr.port());
            } else {
                // Although requests targeting fake IPs are assumed
                // never happen in real network traffic, which are
                // likely caused by poisoned DNS cache records, we
                // still have a chance to sniff the request domain
                // for TLS traffic in dispatcher.
                if remote_addr.port() != 443 && remote_addr.port() != 80 {
                    debug!(
                        "No paired domain found for this fake IP: {}, connection is rejected.",
                        &remote_addr.ip()
                    );
                    return;
                }
            }
        }
    }
    dispatcher.dispatch_stream(sess, stream).await;
}

#[cfg(feature = "netstack-lwip")]
async fn handle_inbound_datagram_lwip(
    socket: Pin<Box<lwip::UdpSocket>>,
    inbound_tag: String,
    nat_manager: Arc<NatManager>,
    fakedns: Option<Arc<FakeDns>>,
) {
    // The socket to receive/send packets from/to the netstack.
    let (ls, mut lr) = socket.split();
    let ls = Arc::new(ls);

    // The channel for sending back datagrams from NAT manager to netstack.
    let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
        tokio_channel(nat_manager.env().options.udp.downlink_channel_size);

    // Receive datagrams from NAT manager and send back to netstack.
    let fakedns_cloned = fakedns.clone();
    let ls_cloned = ls.clone();
    tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            let src_addr = match pkt.src_addr {
                SocksAddr::Ip(a) => a,
                SocksAddr::Domain(domain, port) => {
                    if let Some(fakedns) = &fakedns_cloned {
                        if let Some(ip) = fakedns.query_fake_ip(&domain).await {
                            SocketAddr::new(ip, port)
                        } else {
                            warn!(
                                "Received datagram with source address {}:{} without paired fake IP found.",
                                &domain, &port
                            );
                            continue;
                        }
                    } else {
                        warn!(
                            "Received datagram with source address {}:{} but fake DNS is disabled.",
                            &domain, &port
                        );
                        continue;
                    }
                }
            };
            if let Err(e) = ls_cloned.send_to(&pkt.data[..], &src_addr, pkt.dst_addr.must_ip()) {
                warn!("A packet failed to send to the netstack: {}", e);
            }
        }
    });

    // Accept datagrams from netstack and send to NAT manager.
    loop {
        match lr.recv_from().await {
            Err(e) => {
                warn!("Failed to accept a datagram from netstack: {}", e);
            }
            Ok((data, src_addr, dst_addr)) => {
                // Fake DNS logic.
                if dst_addr.port() == 53 {
                    if let Some(fakedns) = &fakedns {
                        match fakedns.generate_fake_response(&data).await {
                            Ok(resp) => {
                                if let Err(e) = ls.send_to(resp.as_ref(), &dst_addr, &src_addr) {
                                    warn!("A packet failed to send to the netstack: {}", e);
                                }
                                continue;
                            }
                            Err(err) => {
                                debug!("generate fake ip failed: {}", err);
                            }
                        }
                    }
                }

                // Whether to override the destination according to Fake DNS.
                //
                // WARNING
                //
                // This allows datagram to have a domain name as destination,
                // but real UDP traffic are sent with IP address only. If the
                // outbound for this datagram is a direct one, the outbound
                // would resolve the domain to IP address before sending out
                // the datagram. If the outbound is a proxy one, it would
                // require a proxy server with the ability to handle datagrams
                // with domain name destination, leaf itself of course supports
                // this feature very well.
                let dst_addr = if let Some(fakedns) = &fakedns {
                    if fakedns.is_fake_ip(&dst_addr.ip()).await {
                        if let Some(domain) = fakedns.query_domain(&dst_addr.ip()).await {
                            SocksAddr::Domain(domain, dst_addr.port())
                        } else {
                            debug!(
                                "No paired domain found for this fake IP: {}, datagram is rejected.",
                                &dst_addr.ip()
                            );
                            continue;
                        }
                    } else {
                        SocksAddr::Ip(dst_addr)
                    }
                } else {
                    SocksAddr::Ip(dst_addr)
                };

                let dgram_src = DatagramSource::new(src_addr, None);
                let pkt = UdpPacket::new(data, SocksAddr::Ip(src_addr), dst_addr);
                nat_manager
                    .send(None, &dgram_src, &inbound_tag, &l_tx, pkt)
                    .await;
            }
        }
    }
}

#[cfg(feature = "netstack-smoltcp")]
async fn handle_inbound_datagram_smoltcp(
    socket: smoltcp::UdpSocket,
    inbound_tag: String,
    nat_manager: Arc<NatManager>,
    fakedns: Option<Arc<FakeDns>>,
) {
    // The socket to receive/send packets from/to the netstack.
    let (mut lr, ls) = socket.split();
    let ls = Arc::new(Mutex::new(ls));

    // The channel for sending back datagrams from NAT manager to netstack.
    let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
        tokio_channel(nat_manager.env().options.udp.downlink_channel_size);

    // Receive datagrams from NAT manager and send back to netstack.
    let fakedns_cloned = fakedns.clone();
    let ls_cloned = ls.clone();
    tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            let src_addr = match pkt.src_addr {
                SocksAddr::Ip(a) => a,
                SocksAddr::Domain(domain, port) => {
                    if let Some(fakedns) = &fakedns_cloned {
                        if let Some(ip) = fakedns.query_fake_ip(&domain).await {
                            SocketAddr::new(ip, port)
                        } else {
                            warn!(
                                "Received datagram with source address {}:{} without paired fake IP found.",
                                &domain, &port
                            );
                            continue;
                        }
                    } else {
                        warn!(
                            "Received datagram with source address {}:{} but fake DNS is disabled.",
                            &domain, &port
                        );
                        continue;
                    }
                }
            };
            if let Err(e) = ls_cloned
                .lock()
                .await
                .send((pkt.data, src_addr, *pkt.dst_addr.must_ip()))
                .await
            {
                warn!("A packet failed to send to the netstack: {}", e);
            }
        }
    });

    // Accept datagrams from netstack and send to NAT manager.
    while let Some(item) = lr.next().await {
        let (data, src_addr, dst_addr) = item;
        // Fake DNS logic.
        if dst_addr.port() == 53 {
            if let Some(fakedns) = &fakedns {
                match fakedns.generate_fake_response(&data).await {
                    Ok(resp) => {
                        if let Err(e) = ls.lock().await.send((resp, dst_addr, src_addr)).await {
                            warn!("A packet failed to send to the netstack: {}", e);
                        }
                        continue;
                    }
                    Err(err) => {
                        debug!("generate fake ip failed: {}", err);
                    }
                }
            }
        }

        // Whether to override the destination according to Fake DNS.
        //
        // WARNING
        //
        // This allows datagram to have a domain name as destination,
        // but real UDP traffic are sent with IP address only. If the
        // outbound for this datagram is a direct one, the outbound
        // would resolve the domain to IP address before sending out
        // the datagram. If the outbound is a proxy one, it would
        // require a proxy server with the ability to handle datagrams
        // with domain name destination, leaf itself of course supports
        // this feature very well.
        let dst_addr = if let Some(fakedns) = &fakedns {
            if fakedns.is_fake_ip(&dst_addr.ip()).await {
                if let Some(domain) = fakedns.query_domain(&dst_addr.ip()).await {
                    SocksAddr::Domain(domain, dst_addr.port())
                } else {
                    debug!(
                        "No paired domain found for this fake IP: {}, datagram is rejected.",
                        &dst_addr.ip()
                    );
                    continue;
                }
            } else {
                SocksAddr::Ip(dst_addr)
            }
        } else {
            SocksAddr::Ip(dst_addr)
        };

        let dgram_src = DatagramSource::new(src_addr, None);
        let pkt = UdpPacket::new(data, SocksAddr::Ip(src_addr), dst_addr);
        nat_manager
            .send(None, &dgram_src, &inbound_tag, &l_tx, pkt)
            .await;
    }
}

#[cfg(feature = "netstack-lwip")]
fn new_lwip(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    fakedns: Option<Arc<FakeDns>>,
    tun: tun::AsyncDevice,
) -> Result<Runner> {
    let (stack, mut tcp_listener, udp_socket) = lwip::NetStack::with_buffer_size(
        dispatcher.env().options.netstack.output_channel_size,
        dispatcher.env().options.netstack.udp_uplink_channel_size,
    )?;

    Ok(Box::pin(async move {
        let inbound_tag = inbound.tag.clone();
        let framed = tun.into_framed();
        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = Vec::new();

        // Reads packet from stack and sends to TUN.
        futs.push(Box::pin(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = tun_sink.send(pkt).await {
                            // TODO Return the error
                            error!("Sending packet to TUN failed: {}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        error!("Net stack erorr: {}", e);
                        return;
                    }
                }
            }
        }));

        // Reads packet from TUN and sends to stack.
        futs.push(Box::pin(async move {
            while let Some(pkt) = tun_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = stack_sink.send(pkt).await {
                            error!("Sending packet to NetStack failed: {}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        error!("TUN error: {}", e);
                        return;
                    }
                }
            }
        }));

        // Extracts TCP connections from stack and sends them to the dispatcher.
        let inbound_tag_cloned = inbound_tag.clone();
        let fakedns_cloned = fakedns.clone();
        futs.push(Box::pin(async move {
            while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
                tokio::spawn(handle_inbound_stream_lwip(
                    stream,
                    local_addr,
                    remote_addr,
                    inbound_tag_cloned.clone(),
                    dispatcher.clone(),
                    fakedns_cloned.clone(),
                ));
            }
        }));

        // Receive and send UDP packets between netstack and NAT manager. The NAT
        // manager would maintain UDP sessions and send them to the dispatcher.
        futs.push(Box::pin(async move {
            handle_inbound_datagram_lwip(udp_socket, inbound_tag, nat_manager, fakedns.clone())
                .await;
        }));

        info!("start tun inbound (lwip)");
        futures::future::select_all(futs).await;
    }))
}

#[cfg(feature = "netstack-smoltcp")]
fn new_smoltcp(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    fakedns: Option<Arc<FakeDns>>,
    tun: tun::AsyncDevice,
) -> Result<Runner> {
    let (stack, runner, udp_socket, tcp_listener) = smoltcp::StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .stack_buffer_size(dispatcher.env().options.netstack.output_channel_size)
        .udp_buffer_size(dispatcher.env().options.netstack.udp_uplink_channel_size)
        .tcp_buffer_size(dispatcher.env().options.netstack.udp_uplink_channel_size)
        .build()
        .map_err(|e| anyhow!("stack build failed: {}", e))?;

    if let Some(runner) = runner {
        tokio::spawn(runner);
    }

    let mut tcp_listener = tcp_listener.ok_or_else(|| anyhow!("no tcp listener"))?;
    let udp_socket = udp_socket.ok_or_else(|| anyhow!("no udp socket"))?;

    Ok(Box::pin(async move {
        let inbound_tag = inbound.tag.clone();
        let framed = tun.into_framed();
        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = Vec::new();

        // Reads packet from stack and sends to TUN.
        futs.push(Box::pin(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = tun_sink.send(pkt).await {
                            error!("Sending packet to TUN failed: {}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        error!("Net stack erorr: {}", e);
                        return;
                    }
                }
            }
        }));

        // Reads packet from TUN and sends to stack.
        futs.push(Box::pin(async move {
            while let Some(pkt) = tun_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = stack_sink.send(pkt).await {
                            error!("Sending packet to NetStack failed: {}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        error!("TUN error: {}", e);
                        return;
                    }
                }
            }
        }));

        // Extracts TCP connections from stack and sends them to the dispatcher.
        let inbound_tag_cloned = inbound_tag.clone();
        let fakedns_cloned = fakedns.clone();
        futs.push(Box::pin(async move {
            while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
                tokio::spawn(handle_inbound_stream_smoltcp(
                    Box::pin(stream),
                    local_addr,
                    remote_addr,
                    inbound_tag_cloned.clone(),
                    dispatcher.clone(),
                    fakedns_cloned.clone(),
                ));
            }
        }));

        // Receive and send UDP packets between netstack and NAT manager. The NAT
        // manager would maintain UDP sessions and send them to the dispatcher.
        futs.push(Box::pin(async move {
            handle_inbound_datagram_smoltcp(udp_socket, inbound_tag, nat_manager, fakedns.clone())
                .await;
        }));

        info!("start tun inbound (smoltcp)");
        futures::future::select_all(futs).await;
    }))
}

/// The options of a TUN inbound.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct TunInboundOptions {
    /// An already open TUN device; everything but the fake DNS options is
    /// ignored when it is set.
    #[serde(default = "no_fd")]
    pub fd: i32,
    /// Routes all traffic into the device.
    #[serde(default)]
    pub auto: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub netmask: Option<String>,
    /// With `auto`, forwards the traffic of other hosts, which use this one
    /// as their gateway.
    #[serde(default)]
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    pub gateway_mode: bool,
    #[serde(default = "default_mtu")]
    pub mtu: i32,
    #[serde(default)]
    pub fake_dns_exclude: Vec<String>,
    #[serde(default)]
    pub fake_dns_include: Vec<String>,
    /// `lwip` (default) or `smoltcp`.
    #[serde(default)]
    pub tun2socks: String,
    /// Windows only.
    #[serde(default)]
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub wintun: Option<String>,
    /// Windows only.
    #[serde(default)]
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub dns_servers: Vec<String>,
}

#[cfg(windows)]
const DEFAULT_ADDRESS: &str = "10.7.7.2";
#[cfg(windows)]
const DEFAULT_GATEWAY: &str = "10.7.7.1";
#[cfg(not(windows))]
const DEFAULT_ADDRESS: &str = "192.168.233.2";
#[cfg(not(windows))]
const DEFAULT_GATEWAY: &str = "192.168.233.1";

impl TunInboundOptions {
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or("utun233")
    }

    pub fn address(&self) -> &str {
        self.address.as_deref().unwrap_or(DEFAULT_ADDRESS)
    }

    pub fn gateway(&self) -> &str {
        self.gateway.as_deref().unwrap_or(DEFAULT_GATEWAY)
    }

    pub fn netmask(&self) -> &str {
        self.netmask.as_deref().unwrap_or("255.255.255.0")
    }
}

fn no_fd() -> i32 {
    -1
}

fn default_mtu() -> i32 {
    1500
}

pub(crate) fn options(inbound: &Inbound) -> Result<TunInboundOptions> {
    let options: TunInboundOptions = parse_options("inbound", &inbound.tag, &inbound.options)?;
    if options.auto && options.fd >= 0 {
        return Err(anyhow!(
            "[{}] inbound: auto sets up a device of its own; it cannot take fd",
            inbound.tag
        ));
    }
    if options.gateway_mode && !options.auto {
        return Err(anyhow!(
            "[{}] inbound: gateway_mode needs auto, which does the routing",
            inbound.tag
        ));
    }
    Ok(options)
}

pub fn new(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> Result<Runner> {
    tracing::debug!("Create TUN inbound");

    let settings = options(&inbound)?;

    let mut cfg = tun::Configuration::default();
    if settings.fd >= 0 {
        cfg.raw_fd(settings.fd);
    } else {
        cfg.tun_name(settings.name())
            .address(settings.address())
            .destination(settings.gateway())
            .mtu(settings.mtu as u16);

        #[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
        {
            cfg.netmask(settings.netmask());
        }

        cfg.up();
    }

    // FIXME it's a bad design to have 2 lists in config while we need only one
    let fake_dns_exclude = settings.fake_dns_exclude;
    let fake_dns_include = settings.fake_dns_include;
    if !fake_dns_exclude.is_empty() && !fake_dns_include.is_empty() {
        return Err(anyhow!(
            "fake DNS run in either include mode or exclude mode"
        ));
    }
    let fakedns = if !fake_dns_include.is_empty() {
        Some(Arc::new(FakeDns::new(
            FakeDnsMode::Include,
            fake_dns_include,
        )))
    } else if !fake_dns_exclude.is_empty() {
        Some(Arc::new(FakeDns::new(
            FakeDnsMode::Exclude,
            fake_dns_exclude,
        )))
    } else {
        None
    };

    #[cfg(target_os = "windows")]
    {
        use rand::Rng;
        use std::net::IpAddr;
        let mut rng = rand::thread_rng();
        let dns_servers: Vec<IpAddr> = settings
            .dns_servers
            .iter()
            .filter_map(|x| x.parse().ok())
            .collect();
        cfg.metric(0);
        cfg.platform_config(|x| {
            x.device_guid(rng.gen());
            if !dns_servers.is_empty() {
                x.dns_servers(&dns_servers);
            }
            if let Some(f) = &settings.wintun {
                x.wintun_file(f.clone());
            }
        });
    }

    let tun = tun::create_as_async(&cfg).map_err(|e| anyhow!("create tun failed: {}", e))?;

    match settings.tun2socks.as_str() {
        "smoltcp" => {
            #[cfg(feature = "netstack-smoltcp")]
            return new_smoltcp(inbound, dispatcher, nat_manager, fakedns, tun);
            #[cfg(not(feature = "netstack-smoltcp"))]
            return Err(anyhow!("netstack-smoltcp feature is not enabled"));
        }
        _ => {
            #[cfg(feature = "netstack-lwip")]
            return new_lwip(inbound, dispatcher, nat_manager, fakedns, tun);
            #[cfg(not(feature = "netstack-lwip"))]
            return Err(anyhow!("netstack-lwip feature is not enabled"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tun(options: serde_json::Value) -> Inbound {
        Inbound {
            protocol: "tun".into(),
            tag: "tun".into(),
            listen: None,
            listen_port: None,
            udp_timeout: None,
            options: options.as_object().unwrap().clone(),
        }
    }

    #[test]
    fn unset_addresses_take_the_defaults() {
        let options = options(&tun(serde_json::json!({ "auto": true }))).unwrap();
        assert_eq!(options.name(), "utun233");
        assert_eq!(options.address(), DEFAULT_ADDRESS);
        assert_eq!(options.netmask(), "255.255.255.0");
    }

    #[test]
    fn conflicting_options_are_errors() {
        let err = options(&tun(serde_json::json!({ "auto": true, "fd": 3 }))).unwrap_err();
        assert!(err.to_string().contains("fd"), "{}", err);
        let err = options(&tun(serde_json::json!({ "gateway_mode": true }))).unwrap_err();
        assert!(err.to_string().contains("gateway_mode"), "{}", err);
    }
}
