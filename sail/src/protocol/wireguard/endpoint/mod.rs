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

use portable_atomic::AtomicU64;
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
use crate::net::network::NetworkChange;
use crate::net::Dialer;
use crate::runtime::options::{Netstack, NetstackBudget};
use crate::runtime::scope::{spawn_child_of, TaskClass};
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
/// How long the outbound waits for the endpoint to be up, once it is
/// starting; one stopped fails it at once.
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
    let settings = Settings::parse(&options, ctx.dialer.detour().is_some())
        .map_err(|e| anyhow!("[{}] endpoint: {}", ctx.tag, e))?;
    let shared = Arc::new(Shared::new(
        ctx.tag,
        settings,
        ctx.dialer.clone(),
        ctx.dns_client.clone(),
        ctx.env.options.netstack.clone(),
        ctx.task_class,
    ));
    Ok(BuiltEndpoint {
        outbound: shared.outbound(),
        server: Arc::new(Server(shared)),
    })
}

/// What the outbound and inbound halves share.
struct Shared {
    tag: String,
    settings: Settings,
    /// Its sockets, or its detour's datagrams.
    dialer: Dialer,
    dns_client: SyncDnsClient,
    netstack: Netstack,
    /// The class of its tasks: a provider's member's are contained.
    class: TaskClass,
    started: AtomicBool,
    state: watch::Sender<State>,
    /// What the tunnel sends on, while it runs. Its lock orders a stop
    /// against the start binding it.
    bind: parking_lot::Mutex<Option<Arc<dyn Transport>>>,
    /// The last network change it was bound anew for.
    rebound: AtomicU64,
    /// What a test has it send on instead of a socket of its own.
    #[cfg(test)]
    test_transport: parking_lot::Mutex<Option<Arc<dyn Transport>>>,
}

/// Where an endpoint is, as its outbound sees it.
#[derive(Clone)]
enum State {
    /// Not up yet: a dial waits for it, up to `START_WAIT`.
    Starting,
    Running(Arc<Running>),
    /// Ended, however: a task of it ended or panicked, or it was stopped.
    /// It does not start again, and a dial fails at once.
    Stopped,
}

/// Stops the endpoint when its run ends, however it ends: returned,
/// failed, panicked or aborted.
struct StopOnDrop(Arc<Shared>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.stop();
    }
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
    fn new(
        tag: &str,
        settings: Settings,
        dialer: Dialer,
        dns_client: SyncDnsClient,
        netstack: Netstack,
        class: TaskClass,
    ) -> Self {
        Shared {
            tag: tag.to_string(),
            settings,
            dialer,
            dns_client,
            netstack,
            class,
            started: AtomicBool::new(false),
            state: watch::Sender::new(State::Starting),
            bind: parking_lot::Mutex::new(None),
            rebound: AtomicU64::new(0),
            #[cfg(test)]
            test_transport: parking_lot::Mutex::new(None),
        }
    }

    /// The endpoint as an outbound.
    fn outbound(self: &Arc<Self>) -> AnyOutboundHandler {
        HandlerBuilder::default()
            .tag(self.tag.clone())
            .stream_handler(Arc::new(outbound::StreamHandler(self.clone())))
            .datagram_handler(Arc::new(outbound::DatagramHandler(self.clone())))
            .build()
    }

    /// Binds what the tunnel sends on anew, as sing-box's InterfaceUpdated
    /// does with updateBind; the peers' sessions go on over it. Both
    /// halves of the outbound hear of a change, which is acted on once.
    fn network_changed(&self, change: &NetworkChange) {
        if self.rebound.fetch_max(change.generation, Ordering::SeqCst) >= change.generation {
            return;
        }
        let Some(bind) = self.bind.lock().clone() else {
            return;
        };
        let tag = self.tag.clone();
        crate::runtime::scope::spawn("wireguard rebind", async move {
            match bind.rebind().await {
                Ok(()) => debug!("wireguard [{}]: bound anew", tag),
                Err(e) => error!("wireguard [{}]: update bind: {}", tag, e),
            }
        });
    }

    /// The running endpoint, once it is up; an error at once if it has
    /// stopped.
    async fn running(&self) -> io::Result<Arc<Running>> {
        let stopped = || {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!("endpoint [{}] stopped", self.tag),
            )
        };
        let mut rx = self.state.subscribe();
        let state =
            tokio::time::timeout(START_WAIT, rx.wait_for(|s| !matches!(s, State::Starting)))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        format!("endpoint [{}] is not running", self.tag),
                    )
                })?
                .map_err(|_| stopped())?;
        match &*state {
            State::Running(running) => Ok(running.clone()),
            _ => Err(stopped()),
        }
    }

    /// Stops it for good: what the tunnel sends on is closed and let go
    /// of, and the stack with the running state, whoever still holds the
    /// outbound; every dial fails from then on. Its tasks end as they are
    /// aborted, or as the stack and the tunnel they work on are gone.
    fn stop(&self) {
        let bind = {
            let mut bind = self.bind.lock();
            self.state.send_replace(State::Stopped);
            bind.take()
        };
        if let Some(bind) = bind {
            bind.close();
        }
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
                match self
                    .dns_client
                    .load_full()
                    .lookup_dial(host, self.dialer.resolve_spec())
                    .await
                {
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
        #[cfg(test)]
        if let Some(transport) = self.test_transport.lock().take() {
            return Ok(transport);
        }
        if self.dialer.detour().is_some() {
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
                self.dialer.clone(),
                self.dns_client.clone(),
                first,
            )));
        }
        let v6 = self.dialer.spec().ipv6 || peers.iter().flatten().any(|p| p.is_ipv6());
        let socket =
            SocketTransport::bind(self.settings.listen_port.unwrap_or(0), v6, &self.dialer).await?;
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
        let _stop = StopOnDrop(self.clone());
        let peers = self.resolve_peers().await;
        let transport = self.transport(&peers).await?;
        {
            let mut bind = self.bind.lock();
            if matches!(*self.state.borrow(), State::Stopped) {
                transport.close();
                return Ok(());
            }
            *bind = Some(transport.clone());
        }

        let now = tokio::time::Instant::now().into_std();
        let mut device_config = DeviceConfig::new(*self.settings.private_key);
        device_config.mtu = self.settings.mtu;
        let mut device = Device::new(device_config, now);
        let mut users = AllowedIps::new();
        for (peer, endpoint) in self.settings.peers.iter().zip(&peers) {
            let mut config = peer.config.clone();
            config.endpoint = *endpoint;
            for &(ip, len) in &config.allowed_ips {
                users.insert(ip, len, dispatcher.env().users.bind(&peer.name));
            }
            device
                .add_peer(config)
                .map_err(|e| anyhow!("peer {}: {}", peer.name, e))?;
        }
        let (wg, mut from_tunnel) = WireGuard::spawn(device, transport, self.class);
        let tunnel_ended = wg.ended();

        let (stack_in_tx, stack_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
        let (stack_out_tx, mut stack_out_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
        let io = ChannelPacketIo::new(stack_in_rx, stack_out_tx, PACKET_BATCH);
        let profile = budget_profile(self.netstack.budget);
        let ledger = ResourceLedger::new(profile.budget())?;
        let flow_capacity = profile.budget().max_udp_flows;
        let (mut runtime, mut accepted, datagrams, udp_reply, mut control) =
            NativeRuntimeGroup::new(
                vec![io],
                ledger,
                self.runner_config(),
                self.netstack.command_channel_size,
                self.netstack.command_channel_size,
                self.netstack.udp_uplink_channel_size,
            )?;
        runtime.set_read_ahead(self.netstack.read_ahead << 10);

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
        // Not when a stop came meanwhile.
        let up = self.state.send_if_modified(|state| match state {
            State::Starting => {
                *state = State::Running(running.clone());
                true
            }
            _ => false,
        });
        if !up {
            return Ok(());
        }
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
                    crate::runtime::scope::spawn("wireguard stream", async move {
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
        // aborts them all when the endpoint stops, or is dropped. The end
        // of any, a panic caught among them, ends the endpoint.
        let class = self.class;
        let mut tasks = tokio::task::JoinSet::new();
        let stack_tag = self.tag.clone();
        spawn_child_of(class, &mut tasks, "wireguard stack", async move {
            if let Err(e) = runtime.run().await {
                error!("wireguard [{}]: the stack failed: {}", stack_tag, e);
            }
            "stack"
        });
        spawn_child_of(class, &mut tasks, "wireguard endpoint task", async move {
            pump_in.await;
            "tunnel to stack"
        });
        spawn_child_of(class, &mut tasks, "wireguard endpoint task", async move {
            pump_out.await;
            "stack to tunnel"
        });
        // The tunnel's receive and timer tasks are not the set's.
        spawn_child_of(class, &mut tasks, "wireguard endpoint task", async move {
            tunnel_ended.await;
            "tunnel"
        });
        spawn_child_of(class, &mut tasks, "wireguard endpoint task", async move {
            accept_loop.await;
            "accept"
        });
        spawn_child_of(class, &mut tasks, "wireguard endpoint task", async move {
            datagram_loop.await;
            "datagrams"
        });
        if tracing::enabled!(tracing::Level::DEBUG) {
            let mut control = control.clone();
            let tag = self.tag.clone();
            spawn_child_of(class, &mut tasks, "wireguard endpoint task", async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if let Ok(s) = control.stats_snapshot().await {
                        debug!("wireguard [{}]: stack {:?}", tag, s.stack);
                    }
                }
            });
        }
        let stopped = tasks.join_next().await;
        self.stop();
        match &stopped {
            Some(Ok(what)) => warn!("wireguard [{}]: {} stopped", self.tag, what),
            Some(Err(e)) if e.is_panic() => warn!("wireguard [{}]: a task panicked", self.tag),
            _ => {}
        }
        if let Some(Ok(what)) = stopped {
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
    users: Arc<AllowedIps<crate::user::UserRef>>,
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
            spawn_child_of(
                shared.class,
                &mut task,
                "wireguard endpoint",
                shared.run(dispatcher, nat_manager),
            );
            if let Some(Ok(Err(e))) = task.join_next().await {
                error!("wireguard [{}]: {:#}", tag, e);
            }
        }))
    }

    fn stop(&self) {
        self.0.stop();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use async_trait::async_trait;

    use super::*;
    use crate::adapter::registry::{
        build_outbounds_as, start_member, AnyEndpointServer, OutboundBuildState,
    };
    use crate::net::network::ChangeReason;
    use crate::runtime::scope::TaskScope;

    /// Counts its rebinds.
    #[derive(Default)]
    struct Counting(AtomicUsize);

    #[async_trait]
    impl Transport for Counting {
        async fn send_to(&self, _datagram: &[u8], _dst: SocketAddr) -> io::Result<()> {
            Ok(())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }

        async fn rebind(&self) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Panics on a send, as a bug would; receives nothing.
    struct PanicsOnSend;

    #[async_trait]
    impl Transport for PanicsOnSend {
        async fn send_to(&self, _datagram: &[u8], _dst: SocketAddr) -> io::Result<()> {
            panic!("a bug in the transport")
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    /// An endpoint's options, its peer's with `peer` added.
    fn options(peer: serde_json::Value) -> serde_json::Value {
        let mut options = serde_json::json!({
            "address": ["10.0.0.2/32"],
            "private_key": "YFf6vyGG0nAu8ZlKIYO7nZbcfdd2dbmodt1XRkcCdU4=",
            "peers": [{
                "address": "127.0.0.1",
                "port": 51820,
                "public_key": "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=",
                "allowed_ips": ["0.0.0.0/0"],
            }],
        });
        for (key, value) in peer.as_object().unwrap() {
            options["peers"][0][key] = value.clone();
        }
        options
    }

    fn dns() -> SyncDnsClient {
        crate::app::dns::DnsClient::new(
            &crate::config::Dns::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared()
    }

    /// An endpoint of tasks of `class`, sending on `transport`.
    fn shared_on(
        class: TaskClass,
        peer: serde_json::Value,
        transport: Arc<dyn Transport>,
    ) -> Arc<Shared> {
        let options: WireGuardOptions = serde_json::from_value(options(peer)).unwrap();
        let shared = Arc::new(Shared::new(
            "wg",
            Settings::parse(&options, false).unwrap(),
            Dialer::system(),
            dns(),
            Netstack::default(),
            class,
        ));
        *shared.test_transport.lock() = Some(transport);
        shared
    }

    fn shared() -> Arc<Shared> {
        shared_on(
            TaskClass::Essential,
            serde_json::json!({}),
            Arc::new(Counting::default()),
        )
    }

    /// What an instance routes with, and the instance, to keep.
    fn routing() -> (
        crate::app::instance::Instance,
        Arc<Dispatcher>,
        Arc<NatManager>,
    ) {
        let config = crate::config::Config::from_json("{}").unwrap();
        let instance = crate::app::instance::Instance::build(
            &config,
            Vec::new(),
            Arc::default(),
            Arc::default(),
        )
        .unwrap();
        let dispatcher = instance.dispatcher.clone();
        let nat = Arc::new(NatManager::new(dispatcher.clone(), &[]));
        (instance, dispatcher, nat)
    }

    /// Waits up to 5 s for the endpoint's state to be as `is` says.
    async fn until(shared: &Shared, is: impl FnMut(&State) -> bool) {
        let mut state = shared.state.subscribe();
        tokio::time::timeout(Duration::from_secs(5), state.wait_for(is))
            .await
            .expect("in time")
            .unwrap();
    }

    /// The error a TCP dial through `outbound` fails with, and how long it
    /// took.
    async fn dial(outbound: &AnyOutboundHandler) -> (io::Error, Duration) {
        let sess = Session {
            destination: SocksAddr::Ip("10.0.0.9:80".parse().unwrap()),
            ..Default::default()
        };
        let started = tokio::time::Instant::now();
        match outbound.stream().unwrap().handle(&sess, None, None).await {
            Ok(_) => panic!("dialed"),
            Err(e) => (e, started.elapsed()),
        }
    }

    fn change(generation: u64) -> NetworkChange {
        NetworkChange {
            generation,
            reason: ChangeReason::DefaultInterface,
            old: Arc::default(),
            new: Arc::default(),
        }
    }

    /// The rebinds once `n` are done, and after a moment more.
    async fn rebinds(bind: &Counting, n: usize) -> usize {
        for _ in 0..100 {
            if bind.0.load(Ordering::SeqCst) >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        bind.0.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn a_network_change_rebinds_the_tunnel_once() {
        let shared = shared();
        let outbound = shared.outbound();
        // Not running: nothing to rebind.
        outbound.network_changed(&change(1));

        let bind = Arc::new(Counting::default());
        *shared.bind.lock() = Some(bind.clone());
        // Both halves of the outbound hear of it.
        outbound.network_changed(&change(2));
        assert_eq!(rebinds(&bind, 1).await, 1);
        outbound.network_changed(&change(2));
        assert_eq!(rebinds(&bind, 1).await, 1);
        outbound.network_changed(&change(3));
        assert_eq!(rebinds(&bind, 2).await, 2);
    }

    /// A provider's member whose timer task panics (a contained one, not
    /// in the endpoint's own set of tasks) stops, and fails a dial at once;
    /// the scope counts the panic and goes on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_member_s_panic_stops_it_alone() {
        let scope = TaskScope::default();
        // The timer sends the first keepalive's handshake at once.
        let shared = shared_on(
            TaskClass::Contained,
            serde_json::json!({ "persistent_keepalive_interval": 25 }),
            Arc::new(PanicsOnSend),
        );
        let server: AnyEndpointServer = Arc::new(Server(shared.clone()));
        let (_instance, dispatcher, nat) = routing();
        let run = start_member(&server, dispatcher, nat, &scope).unwrap();
        until(&shared, |s| matches!(s, State::Stopped)).await;
        assert_eq!(scope.faults(), 1);
        assert!(scope.failure().is_none(), "{:?}", scope.failure());
        let (e, took) = dial(&shared.outbound()).await;
        assert!(e.to_string().contains("endpoint [wg] stopped"), "{}", e);
        assert!(took < Duration::from_millis(100), "{:?}", took);
        run.stop();
    }

    /// The configuration's endpoints are essential: the same panic fails
    /// the instance.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_configured_endpoint_s_panic_fails_the_instance() {
        let scope = TaskScope::default();
        let shared = shared_on(
            TaskClass::Essential,
            serde_json::json!({ "persistent_keepalive_interval": 25 }),
            Arc::new(PanicsOnSend),
        );
        let (_instance, dispatcher, nat) = routing();
        let runner = Server(shared.clone()).start(dispatcher, nat).unwrap();
        scope.spawn_essential("endpoint", runner);
        tokio::time::timeout(Duration::from_secs(5), scope.failed())
            .await
            .expect("failed in time");
        let why = scope.failure().unwrap();
        assert!(why.contains("[wireguard timer] panicked"), "{}", why);
        assert_eq!(scope.faults(), 0);
        scope.stop(Duration::from_secs(2)).await;
    }

    /// A stopped member lets its port go at once, though its outbound is
    /// still held, as a connection or a group holds it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stopped_member_frees_its_port() {
        let port = std::net::UdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut endpoint = options(serde_json::json!({}));
        endpoint["type"] = "wireguard".into();
        endpoint["tag"] = "p/wg".into();
        endpoint["listen_port"] = port.into();
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "endpoints": [endpoint] }).to_string(),
        )
        .unwrap();
        let env = crate::runtime::RuntimeEnv::default();
        let mut handlers = HashMap::new();
        #[cfg(feature = "plugin")]
        let mut external_handlers = crate::app::outbound::plugin::ExternalHandlers::new();
        let built = build_outbounds_as(
            TaskClass::Contained,
            &crate::include::OUTBOUNDS,
            &crate::include::ENDPOINTS,
            &[],
            &config.endpoints,
            OutboundBuildState {
                dns_client: &dns(),
                dial_defaults: &Default::default(),
                env: &env,
                handlers: &mut handlers,
                abort_handles: &mut HashMap::new(),
                dependencies: &mut HashMap::new(),
                endpoints: &mut HashMap::new(),
                #[cfg(feature = "outbound-select")]
                selectors: &mut Default::default(),
                #[cfg(feature = "plugin")]
                external_handlers: &mut external_handlers,
                #[cfg(feature = "outbound-provider")]
                providers: &mut Default::default(),
                #[cfg(any(
                    feature = "outbound-urltest",
                    feature = "outbound-load-balance",
                    feature = "outbound-fallback"
                ))]
                checkers: &mut HashMap::new(),
            },
        )
        .unwrap();
        assert_eq!(built.servers.len(), 1);
        let (tag, server) = &built.servers[0];
        assert_eq!(tag, "p/wg");
        let outbound = handlers.remove("p/wg").unwrap();

        let (_instance, dispatcher, nat) = routing();
        let scope = TaskScope::default();
        let run = start_member(server, dispatcher, nat, &scope).unwrap();
        // Taken in either family: the member's dual-stack [::] socket does
        // not keep a bind of 0.0.0.0 out on Windows.
        let taken = move || {
            [IpAddr::from([0u8; 4]), IpAddr::from([0u16; 8])]
                .into_iter()
                .any(|ip| match std::net::UdpSocket::bind((ip, port)) {
                    Ok(_) => false,
                    // A host without IPv6 has no [::] to bind.
                    Err(e) => e.kind() != io::ErrorKind::AddrNotAvailable,
                })
        };
        let free = |within: Duration| async move {
            let deadline = tokio::time::Instant::now() + within;
            loop {
                if !taken() {
                    return true;
                }
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        // Up, on its port.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !taken() {
            assert!(tokio::time::Instant::now() < deadline, "never bound");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        run.stop();
        let started = tokio::time::Instant::now();
        assert!(
            free(Duration::from_secs(1)).await,
            "the port is still taken"
        );
        eprintln!("the port was free in {:?}", started.elapsed());
        let (e, _) = dial(&outbound).await;
        assert!(e.to_string().contains("endpoint [p/wg] stopped"), "{}", e);
        drop(outbound);
    }

    /// A member not started yet has a dial wait for it; one stopped fails
    /// a dial at once, not after `START_WAIT`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stopped_member_fails_a_dial_at_once() {
        let shared = shared_on(
            TaskClass::Contained,
            serde_json::json!({}),
            Arc::new(Counting::default()),
        );
        let outbound = shared.outbound();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), dial(&outbound))
                .await
                .is_err(),
            "not started: the dial waits"
        );
        let server: AnyEndpointServer = Arc::new(Server(shared.clone()));
        let (_instance, dispatcher, nat) = routing();
        let scope = TaskScope::default();
        let run = start_member(&server, dispatcher.clone(), nat.clone(), &scope).unwrap();
        until(&shared, |s| matches!(s, State::Running(_))).await;
        run.stop();
        let (e, took) = dial(&outbound).await;
        assert!(e.to_string().contains("endpoint [wg] stopped"), "{}", e);
        assert!(took < Duration::from_millis(100), "{:?}", took);
        assert!(server.start(dispatcher, nat).is_err(), "started once");
    }

    /// A UDP session through the endpoint is recorded as going out through
    /// its stack, which a change of network leaves be; a TCP dial that
    /// fails records nothing. (`test_wireguard_endpoint` has a TCP
    /// connection through it survive a move.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_through_it_is_recorded_as_through_its_stack() {
        use crate::net::dial::{BoundInterface, Egress};

        let shared = shared_on(
            TaskClass::Contained,
            serde_json::json!({}),
            Arc::new(Counting::default()),
        );
        let outbound = shared.outbound();
        let server: AnyEndpointServer = Arc::new(Server(shared.clone()));
        let (_instance, dispatcher, nat) = routing();
        let scope = TaskScope::default();
        let run = start_member(&server, dispatcher, nat, &scope).unwrap();
        until(&shared, |s| matches!(s, State::Running(_))).await;

        let sess = Session {
            destination: SocksAddr::Ip("10.0.0.9:53".parse().unwrap()),
            ..Default::default()
        };
        let _datagram = outbound
            .datagram()
            .unwrap()
            .handle(&sess, None)
            .await
            .unwrap();
        assert_eq!(
            sess.state.get::<BoundInterface>().get(),
            Some(Egress::Tunnel {
                endpoint: "wg".into()
            })
        );
        // No peer answers: the dial fails, and is not recorded as one.
        let failed = Session {
            destination: SocksAddr::Ip("10.0.0.9:80".parse().unwrap()),
            ..Default::default()
        };
        assert!(outbound
            .stream()
            .unwrap()
            .handle(&failed, None, None)
            .await
            .is_err());
        assert_eq!(failed.state.get::<BoundInterface>().get(), None);
        run.stop();
    }

    /// A member started from a task outside every scope, as a host's
    /// reload is, runs in the scope it is given: the scope's stop ends it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_member_runs_in_the_scope_it_is_given() {
        assert!(TaskScope::current().is_none());
        let shared = shared_on(
            TaskClass::Contained,
            serde_json::json!({}),
            Arc::new(Counting::default()),
        );
        let server: AnyEndpointServer = Arc::new(Server(shared.clone()));
        let (_instance, dispatcher, nat) = routing();
        let scope = TaskScope::default();
        let run = start_member(&server, dispatcher, nat, &scope).unwrap();
        until(&shared, |s| matches!(s, State::Running(_))).await;
        let tasks = scope.tasks();
        for name in ["endpoint member", "wireguard recv", "wireguard timer"] {
            assert!(tasks.iter().any(|(n, _)| *n == name), "{:?}", tasks);
        }
        let report = scope.stop(Duration::from_secs(2)).await;
        assert!(report.clean(), "{:?}", report);
        until(&shared, |s| matches!(s, State::Stopped)).await;
        drop(run);
    }
}
