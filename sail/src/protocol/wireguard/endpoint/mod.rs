//! The WireGuard endpoint: a [`WireGuard`](super::WireGuard) device whose
//! tunnel carries the userspace TCP/IP stack, as an outbound and an
//! inbound under one tag, configured as sing-box's WireGuard endpoint.
//!
//! ```text
//!             outbound: connect / send_udp          inbound: accepted / datagrams
//!                        \                             /
//!                         NativeRuntimeGroup (one shard)
//!                                 |  ChannelPacketIo
//!                    stack_in (bounded) ^   v stack_out (bounded)
//!                         pump_in task  |   |  pump_out task
//!                                       |   v
//!                         WireGuard shell: device (one mutex), recv and
//!                         timer tasks, over a Transport: a UDP socket or
//!                         a detour outbound's datagrams
//! ```
//!
//! Datagrams the stack delivers are replies to the outbound's UDP flows
//! when their destination is one of the local addresses the outbound
//! handed out, and datagrams from peers to route otherwise.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use lru::LruCache;
use sail_netstack::{BudgetProfile, ResourceLedger, RunnerConfig, UdpFlowToken};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    BuiltEndpoint, EndpointFactory, EndpointRegistry, EndpointServer, OutboundContext,
};
use crate::adapter::AnyOutboundHandler;
use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::{NatManager, UdpPacket};
use crate::app::SyncDnsClient;
use crate::net::netstack::{
    ChannelPacketIo, NativeRuntimeControl, NativeRuntimeGroup, NativeUdpDatagram,
    NativeUdpReplyHandle,
};
use crate::net::DialOptions;
use crate::runtime::options::{Netstack, NetstackBudget};
use crate::session::{DatagramSource, Network, Session, SocksAddr};
use crate::transport::layers::Blocks;

use super::allowed_ips::AllowedIps;
use super::{Device, DeviceConfig, Transport, WireGuard};

mod options;
mod outbound;
mod transport;

pub use options::{Reserved, Settings, WireGuardOptions};
pub use transport::{DetourTransport, SocketTransport};

/// Packets queued between the tunnel and the stack, each way.
const PACKET_QUEUE: usize = 1024;
/// Packets the stack takes or gives at a time.
const PACKET_BATCH: usize = 64;
/// How long the stack keeps a UDP flow without traffic. The NAT sessions
/// the flows carry end sooner, by `udp_timeout`.
const STACK_UDP_IDLE: Duration = Duration::from_secs(10 * 60);
/// How long the outbound waits for the endpoint to be up.
const START_WAIT: Duration = Duration::from_secs(10);

pub(crate) fn register(registry: &mut EndpointRegistry) {
    registry.register(
        "wireguard",
        EndpointFactory::new(crate::adapter::registry::no_dependencies, build)
            .with_blocks(Blocks::DIALER),
    );
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<BuiltEndpoint> {
    let options: WireGuardOptions = ctx.options()?;
    let settings = Settings::parse(&options, ctx.detour.is_some())
        .map_err(|e| anyhow!("[{}] endpoint: {}", ctx.tag, e))?;
    let (running_tx, running_rx) = watch::channel(None);
    let shared = Arc::new(Shared {
        tag: ctx.tag.to_string(),
        settings,
        dial: ctx.dial.clone(),
        detour: ctx.detour.clone(),
        dns_client: ctx.dns_client.clone(),
        netstack: ctx.env.options.netstack.clone(),
        started: AtomicBool::new(false),
        running_tx,
        running_rx,
    });
    let outbound: AnyOutboundHandler = HandlerBuilder::default()
        .tag(ctx.tag.to_string())
        .stream_handler(Arc::new(outbound::StreamHandler(shared.clone())))
        .datagram_handler(Arc::new(outbound::DatagramHandler(shared.clone())))
        .build();
    Ok(BuiltEndpoint {
        outbound,
        server: Arc::new(Server(shared)),
    })
}

/// What the outbound and inbound halves share.
struct Shared {
    tag: String,
    settings: Settings,
    dial: Arc<DialOptions>,
    detour: Option<AnyOutboundHandler>,
    dns_client: SyncDnsClient,
    netstack: Netstack,
    started: AtomicBool,
    running_tx: watch::Sender<Option<Arc<Running>>>,
    running_rx: watch::Receiver<Option<Arc<Running>>>,
}

/// A started endpoint, as the outbound uses it.
struct Running {
    control: NativeRuntimeControl,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    /// The outbound's UDP flows, by the local address the outbound handed
    /// each: replies to it go to the flow.
    flows: parking_lot::Mutex<HashMap<SocketAddr, FlowSender>>,
}

/// Where an outbound UDP flow's replies go: their source and payload.
type FlowSender = mpsc::Sender<(SocketAddr, Vec<u8>)>;

/// Outbound UDP flows use ports from the IANA dynamic range (RFC 6335).
const FIRST_PORT: u16 = 49_152;

impl Running {
    /// A local address on `ip` no outbound flow uses, whose replies go to
    /// `tx` until `release`d.
    fn bind(&self, ip: IpAddr, tx: FlowSender) -> io::Result<SocketAddr> {
        let mut flows = self.flows.lock();
        let span = u32::from(u16::MAX - FIRST_PORT) + 1;
        let start = rand::random::<u32>() % span;
        for offset in 0..span {
            let port = FIRST_PORT + ((start + offset) % span) as u16;
            let addr = SocketAddr::new(ip, port);
            if let std::collections::hash_map::Entry::Vacant(e) = flows.entry(addr) {
                e.insert(tx);
                return Ok(addr);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "every UDP port of the endpoint is in use",
        ))
    }

    fn release(&self, addr: &SocketAddr) {
        self.flows.lock().remove(addr);
    }

    /// The endpoint's address for talking to `remote`.
    fn local_for(&self, remote: IpAddr) -> Option<IpAddr> {
        match remote {
            IpAddr::V4(_) => self.v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.v6.map(IpAddr::V6),
        }
    }
}

impl Shared {
    /// The running endpoint, once it is up.
    async fn running(&self) -> io::Result<Arc<Running>> {
        let mut rx = self.running_rx.clone();
        let running = tokio::time::timeout(START_WAIT, rx.wait_for(Option::is_some))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    format!("endpoint [{}] is not running", self.tag),
                )
            })?
            .map_err(|_| io::Error::other(format!("endpoint [{}] stopped", self.tag)))?;
        Ok(running.clone().expect("waited for it"))
    }

    fn address(&self, v4: bool) -> Option<IpAddr> {
        self.settings
            .address
            .iter()
            .map(|(ip, _)| *ip)
            .find(|ip| ip.is_ipv4() == v4)
    }

    /// Resolves the peers' hosts, again and again until they resolve: a
    /// peer without an address is not sent to.
    async fn resolve_peers(&self) -> Vec<Option<SocketAddr>> {
        let mut resolved = Vec::with_capacity(self.settings.peers.len());
        for peer in &self.settings.peers {
            let Some((host, port)) = &peer.server else {
                resolved.push(None);
                continue;
            };
            let mut delay = Duration::from_secs(1);
            let addr = loop {
                match self.dns_client.load_full().direct_lookup(host).await {
                    Ok(ips) if !ips.is_empty() => {
                        // IPv4 first, unless IPv6 is all there is.
                        let ip = ips
                            .iter()
                            .find(|ip| ip.is_ipv4())
                            .or_else(|| ips.first())
                            .copied()
                            .expect("not empty");
                        break SocketAddr::new(ip, *port);
                    }
                    Ok(_) => warn!("wireguard [{}]: {} has no address", self.tag, host),
                    Err(e) => warn!("wireguard [{}]: resolving {}: {}", self.tag, host, e),
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            };
            resolved.push(Some(addr));
        }
        resolved
    }

    async fn transport(&self, peers: &[Option<SocketAddr>]) -> io::Result<Arc<dyn Transport>> {
        if let Some(detour) = &self.detour {
            let first = self
                .settings
                .peers
                .iter()
                .find_map(|p| p.server.clone())
                .map(|(host, port)| match host.parse::<IpAddr>() {
                    Ok(ip) => SocksAddr::Ip(SocketAddr::new(ip, port)),
                    Err(_) => SocksAddr::Domain(host, port),
                })
                .expect("checked: a detour has a peer to send to");
            return Ok(Arc::new(DetourTransport::new(
                &self.tag,
                detour.clone(),
                self.dns_client.clone(),
                first,
            )));
        }
        let v6 = self.dial.ipv6 || peers.iter().flatten().any(|p| p.is_ipv6());
        let socket =
            SocketTransport::bind(self.settings.listen_port.unwrap_or(0), v6, &self.dial).await?;
        info!(
            "wireguard [{}]: listening on udp {}",
            self.tag,
            socket.local_addr()?
        );
        Ok(Arc::new(socket))
    }

    fn runner_config(&self) -> RunnerConfig {
        let mtu = self.settings.mtu;
        let mut config = RunnerConfig::default();
        config.mtu = mtu;
        config.max_packet_size = config.max_packet_size.max(mtu);
        // Segments that fit the endpoint's MTU with the largest IP and TCP
        // headers and options, as the TUN inbound does.
        config.tcp.max_segment_payload_bytes = config
            .tcp
            .max_segment_payload_bytes
            .min(mtu.saturating_sub(sail_netstack::TCP_MAX_HEADER_BYTES));
        config.tcp.keepalive_idle_ms = Some(2 * 60 * 60 * 1_000);
        config.udp_idle_timeout_ms = STACK_UDP_IDLE.as_millis() as u64;
        config
    }

    async fn run(
        self: Arc<Self>,
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
    ) -> Result<()> {
        let peers = self.resolve_peers().await;
        let transport = self.transport(&peers).await?;

        let now = tokio::time::Instant::now().into_std();
        let mut device_config = DeviceConfig::new(self.settings.private_key);
        device_config.mtu = self.settings.mtu;
        let mut device = Device::new(device_config, now);
        let mut users = AllowedIps::new();
        for (peer, endpoint) in self.settings.peers.iter().zip(&peers) {
            let mut config = peer.config.clone();
            config.endpoint = *endpoint;
            for &(ip, len) in &config.allowed_ips {
                users.insert(ip, len, peer.name.clone());
            }
            device
                .add_peer(config)
                .map_err(|e| anyhow!("peer {}: {}", peer.name, e))?;
        }
        let (wg, mut from_tunnel) = WireGuard::spawn(device, transport);

        let (stack_in_tx, stack_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
        let (stack_out_tx, mut stack_out_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
        let io = ChannelPacketIo::new(stack_in_rx, stack_out_tx, PACKET_BATCH);
        let profile = budget_profile(self.netstack.budget);
        let ledger = ResourceLedger::new(profile.budget())?;
        let flow_capacity = profile.budget().max_udp_flows;
        let (runtime, mut accepted, datagrams, udp_reply, mut control) = NativeRuntimeGroup::new(
            vec![io],
            ledger,
            self.runner_config(),
            self.netstack.command_channel_size,
            self.netstack.command_channel_size,
            self.netstack.udp_uplink_channel_size,
        )?;

        let running = Arc::new(Running {
            control: control.clone(),
            v4: self.address(true).and_then(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            }),
            v6: self.address(false).and_then(|ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                IpAddr::V4(_) => None,
            }),
            flows: parking_lot::Mutex::new(HashMap::new()),
        });
        self.running_tx.send_replace(Some(running.clone()));
        info!("wireguard [{}]: started", self.tag);

        // Out of the tunnel, into the stack. The stack takes packets up to
        // its max_packet_size, so a peer with a larger MTU (a kernel peer at
        // 1420, to an endpoint at 1408) is fine.
        let pump_in = async move {
            while let Some(packet) = from_tunnel.recv().await {
                if stack_in_tx.send(packet.packet).await.is_err() {
                    return;
                }
            }
        };
        // Out of the stack, into the tunnel.
        let tag = self.tag.clone();
        let pump_out = async move {
            while let Some(packet) = stack_out_rx.recv().await {
                if let Err(e) = wg.send(&packet).await {
                    debug!("wireguard [{}]: a packet is dropped: {}", tag, e);
                }
            }
        };
        let users = Arc::new(users);
        let accept_loop = {
            let tag = self.tag.clone();
            let users = users.clone();
            let dispatcher = dispatcher.clone();
            async move {
                while let Some(conn) = accepted.recv().await {
                    let sess = Session {
                        network: Network::Tcp,
                        source: conn.connection.source,
                        local_addr: conn.connection.destination,
                        destination: SocksAddr::Ip(conn.connection.destination),
                        inbound_tag: tag.clone(),
                        user: users.lookup(conn.connection.source.ip()).cloned(),
                        ..Default::default()
                    };
                    let dispatcher = dispatcher.clone();
                    tokio::spawn(async move {
                        dispatcher.dispatch_stream(sess, conn.stream).await;
                    });
                }
            }
        };
        let datagram_loop = handle_datagrams(
            datagrams,
            udp_reply,
            self.tag.clone(),
            running,
            users,
            nat_manager,
            flow_capacity,
        );
        // Each on a task of its own, so that they run in parallel; the set
        // aborts them all when the endpoint stops, or is dropped.
        let mut tasks = tokio::task::JoinSet::new();
        let stack_tag = self.tag.clone();
        tasks.spawn(async move {
            if let Err(e) = runtime.run().await {
                error!("wireguard [{}]: the stack failed: {}", stack_tag, e);
            }
            "stack"
        });
        tasks.spawn(async move {
            pump_in.await;
            "tunnel to stack"
        });
        tasks.spawn(async move {
            pump_out.await;
            "stack to tunnel"
        });
        tasks.spawn(async move {
            accept_loop.await;
            "accept"
        });
        tasks.spawn(async move {
            datagram_loop.await;
            "datagrams"
        });
        if tracing::enabled!(tracing::Level::DEBUG) {
            let mut control = control.clone();
            let tag = self.tag.clone();
            tasks.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if let Ok(s) = control.stats_snapshot().await {
                        debug!("wireguard [{}]: stack {:?}", tag, s.stack);
                    }
                }
            });
        }
        let stopped = tasks.join_next().await;
        self.running_tx.send_replace(None);
        if let Some(Ok(what)) = stopped {
            warn!("wireguard [{}]: {} stopped", self.tag, what);
            if what != "stack" {
                if let Err(e) = control.shutdown(0).await {
                    debug!("wireguard [{}]: stack shutdown failed: {}", self.tag, e);
                    let _ = control.abort().await;
                }
            }
        }
        tasks.shutdown().await;
        Ok(())
    }
}

const fn budget_profile(budget: NetstackBudget) -> BudgetProfile {
    match budget {
        NetstackBudget::Mobile => BudgetProfile::Mobile,
        NetstackBudget::Router => BudgetProfile::Router,
        NetstackBudget::Desktop => BudgetProfile::Desktop,
        NetstackBudget::Server => BudgetProfile::Server,
    }
}

/// The stack's datagrams: replies to the outbound's flows go to them, the
/// rest came from peers and is routed, as a TUN inbound's.
async fn handle_datagrams(
    mut uplink: mpsc::Receiver<NativeUdpDatagram>,
    mut reply: NativeUdpReplyHandle,
    inbound_tag: String,
    running: Arc<Running>,
    users: Arc<AllowedIps<Arc<str>>>,
    nat_manager: Arc<NatManager>,
    flow_capacity: usize,
) {
    let (downlink_tx, mut downlink_rx) =
        mpsc::channel::<UdpPacket>(nat_manager.env().options.udp.downlink_channel_size);
    // Replies name a client and a source; the stack wants the flow token.
    let mut flows = LruCache::<(SocketAddr, SocketAddr), UdpFlowToken>::new(
        NonZeroUsize::new(flow_capacity).unwrap_or(NonZeroUsize::MIN),
    );
    loop {
        tokio::select! {
            datagram = uplink.recv() => {
                let Some(datagram) = datagram else { return };
                let outbound = running.flows.lock().get(&datagram.destination).cloned();
                if let Some(flow) = outbound {
                    // A full flow drops, as a socket's buffer would.
                    let _ = flow.try_send((datagram.source, datagram.payload.to_vec()));
                    continue;
                }
                flows.put((datagram.source, datagram.destination), datagram.token);
                let mut source = DatagramSource::new(datagram.source, None);
                source.user = users.lookup(datagram.source.ip()).cloned();
                let packet = UdpPacket::new(
                    datagram.payload.to_vec(),
                    SocksAddr::Ip(datagram.source),
                    SocksAddr::Ip(datagram.destination),
                );
                nat_manager
                    .send(None, &source, &inbound_tag, &downlink_tx, packet)
                    .await;
            }
            packet = downlink_rx.recv() => {
                let Some(packet) = packet else { return };
                let (SocksAddr::Ip(client), SocksAddr::Ip(source)) = (&packet.dst_addr, &packet.src_addr) else {
                    debug!("wireguard [{}]: a reply without addresses is dropped: {}", inbound_tag, packet);
                    continue;
                };
                let result = match flows.get(&(*client, *source)).copied() {
                    Some(token) => reply.send(token, *source, packet.data).await,
                    // From an address the client did not send to: a flow of
                    // its own, as a full-cone NAT would let through.
                    None => running
                        .control
                        .clone()
                        .send_udp(*source, *client, packet.data)
                        .await
                        .map(|(token, _)| {
                            flows.put((*client, *source), token);
                        }),
                };
                if let Err(e) = result {
                    debug!(
                        "wireguard [{}]: a reply to {} from {} failed to reach the stack: {}",
                        inbound_tag, client, source, e
                    );
                }
            }
        }
    }
}

/// The endpoint's running side, started with the instance.
struct Server(Arc<Shared>);

impl EndpointServer for Server {
    fn start(
        &self,
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
    ) -> Result<crate::Runner> {
        if self.0.started.swap(true, Ordering::SeqCst) {
            return Err(anyhow!("started already"));
        }
        let shared = self.0.clone();
        Ok(Box::pin(async move {
            let tag = shared.tag.clone();
            // On a task of its own, which is aborted when the runner is
            // dropped.
            let mut task = tokio::task::JoinSet::new();
            task.spawn(shared.run(dispatcher, nat_manager));
            if let Some(Ok(Err(e))) = task.join_next().await {
                error!("wireguard [{}]: {:#}", tag, e);
            }
        }))
    }
}
