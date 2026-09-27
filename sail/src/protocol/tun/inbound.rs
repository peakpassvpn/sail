use std::{net::SocketAddr, num::NonZeroUsize, sync::Arc};

use anyhow::{anyhow, Result};
use lru::LruCache;
use sail_netstack::{BudgetProfile, ResourceLedger, RunnerConfig, UdpFlowToken};
use serde_derive::Deserialize;
use tokio::sync::mpsc::{
    channel as tokio_channel, Receiver as TokioReceiver, Sender as TokioSender,
};
use tracing::{debug, error, info, warn};

use crate::{
    app::dispatcher::Dispatcher,
    app::fake_dns::{FakeDns, FakeDnsMode},
    app::nat_manager::{NatManager, UdpPacket},
    config::model::{parse_options, Inbound},
    runtime::options::{Netstack, NetstackBudget},
    session::{DatagramSource, Network, Session, SocksAddr},
    Runner,
};

use super::packet_io::TunPacketIo;
#[cfg(target_os = "linux")]
use super::packet_io::TunRsPacketIo;
use crate::net::netstack::{
    NativeRuntimeControl, NativeRuntimeGroup, NativeTcpStream, NativeUdpDatagram,
    NativeUdpReplyHandle,
};

/// What runs a TUN inbound, and how the instance controls it.
pub(crate) struct TunRunner {
    pub runner: Runner,
    pub control: NativeRuntimeControl,
}

const fn budget_profile(budget: NetstackBudget) -> BudgetProfile {
    match budget {
        NetstackBudget::Mobile => BudgetProfile::Mobile,
        NetstackBudget::Router => BudgetProfile::Router,
        NetstackBudget::Desktop => BudgetProfile::Desktop,
        NetstackBudget::Server => BudgetProfile::Server,
    }
}

async fn handle_stream(
    stream: NativeTcpStream,
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
            } else if remote_addr.port() != 443 && remote_addr.port() != 80 {
                // Although requests targeting fake IPs are assumed never to
                // happen in real traffic, poisoned DNS cache records cause
                // them; TLS and HTTP may still be sniffed in the dispatcher.
                debug!(
                    "No paired domain found for this fake IP: {}, connection is rejected.",
                    remote_addr.ip()
                );
                return;
            }
        }
    }
    dispatcher.dispatch_stream(sess, stream).await;
}

async fn handle_datagrams(
    mut uplink: TokioReceiver<NativeUdpDatagram>,
    mut reply: NativeUdpReplyHandle,
    inbound_tag: String,
    nat_manager: Arc<NatManager>,
    fakedns: Option<Arc<FakeDns>>,
    flow_capacity: usize,
) {
    let (downlink_tx, mut downlink_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
        tokio_channel(nat_manager.env().options.udp.downlink_channel_size);
    // Replies name a client and a source; the stack wants the flow token.
    let mut flows = LruCache::<(SocketAddr, SocketAddr), UdpFlowToken>::new(
        NonZeroUsize::new(flow_capacity).unwrap_or(NonZeroUsize::MIN),
    );

    loop {
        tokio::select! {
            datagram = uplink.recv() => {
                let Some(datagram) = datagram else {
                    return;
                };
                flows.put((datagram.source, datagram.destination), datagram.token);
                let payload = datagram.payload.to_vec();

                if datagram.destination.port() == 53 {
                    if let Some(fakedns) = &fakedns {
                        match fakedns.generate_fake_response(&payload).await {
                            Ok(response) => {
                                if let Err(e) = reply
                                    .send(datagram.token, datagram.destination, response)
                                    .await
                                {
                                    warn!("A fake DNS response failed to reach the netstack: {}", e);
                                }
                                continue;
                            }
                            Err(e) => debug!("generate fake ip failed: {}", e),
                        }
                    }
                }

                // A fake IP destination becomes its domain. Real UDP only
                // carries addresses, so a direct outbound resolves it again
                // and a proxy outbound needs a server that takes domains.
                let destination = if let Some(fakedns) = &fakedns {
                    if fakedns.is_fake_ip(&datagram.destination.ip()).await {
                        let Some(domain) = fakedns.query_domain(&datagram.destination.ip()).await
                        else {
                            debug!(
                                "No paired domain found for this fake IP: {}, datagram is rejected.",
                                datagram.destination.ip()
                            );
                            continue;
                        };
                        SocksAddr::Domain(domain, datagram.destination.port())
                    } else {
                        SocksAddr::Ip(datagram.destination)
                    }
                } else {
                    SocksAddr::Ip(datagram.destination)
                };

                let source = DatagramSource::new(datagram.source, None);
                let packet = UdpPacket::new(payload, SocksAddr::Ip(datagram.source), destination);
                nat_manager
                    .send(None, &source, &inbound_tag, &downlink_tx, packet)
                    .await;
            }
            packet = downlink_rx.recv() => {
                let Some(packet) = packet else {
                    return;
                };
                let client = match packet.dst_addr {
                    SocksAddr::Ip(address) => address,
                    SocksAddr::Domain(domain, port) => {
                        warn!("Received a datagram for client {}:{}, which is not an address.", domain, port);
                        continue;
                    }
                };
                let source = match packet.src_addr {
                    SocksAddr::Ip(address) => address,
                    SocksAddr::Domain(domain, port) => {
                        let Some(fakedns) = &fakedns else {
                            warn!(
                                "Received datagram with source address {}:{} but fake DNS is disabled.",
                                domain, port
                            );
                            continue;
                        };
                        let Some(ip) = fakedns.query_fake_ip(&domain).await else {
                            warn!(
                                "Received datagram with source address {}:{} without paired fake IP found.",
                                domain, port
                            );
                            continue;
                        };
                        SocketAddr::new(ip, port)
                    }
                };
                let Some(token) = flows.get(&(client, source)).copied() else {
                    debug!("No netstack UDP flow for client {} and source {}.", client, source);
                    continue;
                };
                if let Err(e) = reply.send(token, source, packet.data).await {
                    warn!("A packet failed to send to the netstack: {}", e);
                }
            }
        }
    }
}

fn run<I: sail_netstack::PacketIo + 'static>(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    fakedns: Option<Arc<FakeDns>>,
    queues: Vec<I>,
    mtu: usize,
    netstack: &Netstack,
) -> Result<TunRunner> {
    let profile = budget_profile(netstack.budget);
    let ledger = ResourceLedger::new(profile.budget())?;
    let udp_flow_capacity = profile.budget().max_udp_flows;
    let mut config = RunnerConfig::default();
    config.mtu = mtu;
    config.max_packet_size = config.max_packet_size.max(mtu);
    // Room for the largest IPv6 and TCP headers with options.
    config.tcp.max_segment_payload_bytes = config
        .tcp
        .max_segment_payload_bytes
        .min(mtu.saturating_sub(sail_netstack::TCP_MAX_HEADER_BYTES));
    config.tcp.keepalive_idle_ms = Some(2 * 60 * 60 * 1_000);
    config.tcp.nagle_enabled = true;
    let (runtime, mut accepted, datagrams, udp_reply, mut control) = NativeRuntimeGroup::new(
        queues,
        ledger,
        config,
        netstack.command_channel_size,
        netstack.command_channel_size,
        netstack.udp_uplink_channel_size,
    )?;

    let runtime_control = control.clone();
    let runner = Box::pin(async move {
        let inbound_tag = inbound.tag;
        let datagram_tag = inbound_tag.clone();
        let datagram_fakedns = fakedns.clone();
        let accept_loop = async move {
            while let Some(accepted) = accepted.recv().await {
                tokio::spawn(handle_stream(
                    accepted.stream,
                    accepted.connection.source,
                    accepted.connection.destination,
                    inbound_tag.clone(),
                    dispatcher.clone(),
                    fakedns.clone(),
                ));
            }
        };
        let datagram_loop = handle_datagrams(
            datagrams,
            udp_reply,
            datagram_tag,
            nat_manager,
            datagram_fakedns,
            udp_flow_capacity,
        );
        let mut runtime = Box::pin(runtime.run());
        info!("start tun inbound");
        let runtime_finished = tokio::select! {
            result = &mut runtime => {
                if let Err(e) = result {
                    error!("netstack runner failed: {}", e);
                }
                true
            }
            () = accept_loop => {
                error!("netstack accept loop stopped");
                false
            }
            () = datagram_loop => {
                error!("netstack datagram loop stopped");
                false
            }
        };
        // A bridge ended first: stop every shard and wait for them, rather
        // than dropping live runners.
        if !runtime_finished {
            if let Ok(snapshot) = control.stats_snapshot().await {
                debug!(
                    shards = snapshot.shard_count,
                    tcp_flows = snapshot.stack.tcp_active_flows,
                    udp_flows = snapshot.stack.udp_active_flows,
                    queued_packets = snapshot.router.queued_packets,
                    "netstack final snapshot"
                );
            }
            if let Err(e) = control.shutdown(0).await {
                debug!("netstack shutdown failed: {}", e);
                let _ = control.abort().await;
            }
            if let Err(e) = runtime.await {
                error!("netstack runner failed during shutdown: {}", e);
            }
        }
    });
    Ok(TunRunner {
        runner,
        control: runtime_control,
    })
}

/// One multi-queue device, a queue per shard, each with its own runner.
#[cfg(target_os = "linux")]
fn linux_queues(settings: &TunInboundOptions, netstack: &Netstack) -> Result<Vec<TunRsPacketIo>> {
    let mtu = usize::try_from(settings.mtu).map_err(|_| anyhow!("invalid TUN mtu"))?;
    let available = std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(1);
    let queue_count = available.min(netstack.max_queues).max(1);
    let first = tun_rs::DeviceBuilder::new()
        .name(settings.name())
        .ipv4(
            settings.address(),
            settings.netmask(),
            Some(settings.gateway()),
        )
        .mtu(u16::try_from(settings.mtu).map_err(|_| anyhow!("invalid TUN mtu"))?)
        .enable(true)
        .multi_queue(queue_count > 1)
        .offload(netstack.offload)
        .build_async()
        .map_err(|e| anyhow!("create tun failed: {}", e))?;
    let mut devices = Vec::with_capacity(queue_count);
    for _ in 1..queue_count {
        devices.push(
            first
                .try_clone()
                .map_err(|e| anyhow!("attach tun queue failed: {}", e))?,
        );
    }
    devices.push(first);
    devices
        .into_iter()
        .map(|device| {
            TunRsPacketIo::new(
                device,
                mtu,
                netstack.batch_size,
                queue_count,
                netstack.offload,
            )
        })
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(Into::into)
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
    // IPv4 hosts must take 576-byte datagrams; an IP packet is at most 64 KiB.
    if !(576..=65_535).contains(&options.mtu) {
        return Err(anyhow!(
            "[{}] inbound: mtu {} is outside 576 to 65535",
            inbound.tag,
            options.mtu
        ));
    }
    Ok(options)
}

pub(crate) fn new(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> Result<TunRunner> {
    tracing::debug!("Create TUN inbound");

    let mut settings = options(&inbound)?;

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
    let fake_dns_exclude = std::mem::take(&mut settings.fake_dns_exclude);
    let fake_dns_include = std::mem::take(&mut settings.fake_dns_include);
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

    let netstack = &dispatcher.env().options.netstack;
    let mtu = usize::try_from(settings.mtu).map_err(|_| anyhow!("invalid TUN mtu"))?;

    #[cfg(target_os = "linux")]
    if settings.fd < 0 {
        let queues = linux_queues(&settings, netstack)?;
        return run(
            inbound,
            dispatcher.clone(),
            nat_manager,
            fakedns,
            queues,
            mtu,
            netstack,
        );
    }

    let tun = tun::create_as_async(&cfg).map_err(|e| anyhow!("create tun failed: {}", e))?;
    let io = TunPacketIo::new(tun, mtu, netstack.batch_size)?;
    run(
        inbound,
        dispatcher.clone(),
        nat_manager,
        fakedns,
        vec![io],
        mtu,
        netstack,
    )
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
