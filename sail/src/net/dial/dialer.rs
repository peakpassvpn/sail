//! The one way sail opens a socket to go out: a [`Dialer`], built once for
//! an outbound, a DNS server or an HTTP client from its [`DialSpec`] and
//! [`ResolveSpec`], and the handles of the running instance it applies them
//! with, [`DialEnv`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use socket2::{Domain, SockRef, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;
#[cfg(unix)]
use tracing::trace;
use tracing::{debug, warn};

#[cfg(unix)]
use {
    std::os::unix::io::{AsRawFd, RawFd},
    tokio::io::{AsyncReadExt, AsyncWriteExt},
    tokio::net::UnixStream,
};

use super::detour::{DetourDialer, Outbounds, Target};
use super::happy::Order;
use super::networks::{
    self, BoundInterface, Egress, FallbackState, NetworkStrategy, Networks, Via,
};
use super::{DialFields, DialSpec, ResolveSpec, RouteDefaults, SocketProtect};
use crate::adapter::{AnyOutboundDatagram, AnyOutboundHandler, AnyStream};
use crate::app::SyncDnsClient;
use crate::net::interface::AutoInterface;
use crate::net::resolver::Resolver;
use crate::session::{Session, SocksAddr};

/// What of the running instance and its host a dialer applies: the
/// interface `auto_detect_interface` finds, and the host's protection of
/// sockets from its VPN. Handles, not configuration: they are shared, not
/// compared.
#[derive(Debug, Clone, Default)]
pub struct DialEnv {
    /// Follows the system's interfaces, where `auto_detect_interface` is
    /// on.
    pub auto_interface: Option<Arc<AutoInterface>>,
    /// From the host, never from a configuration.
    pub protect: Option<SocketProtect>,
    /// The outbounds the detour of a DNS server or an HTTP client goes
    /// through.
    pub outbounds: Outbounds,
    /// The network the host is on: the interfaces `network_strategy`
    /// chooses among, as it is when a connection is dialled.
    pub network: Option<crate::net::network::Network>,
    /// sail's own interfaces, its TUNs', which it never goes out of.
    pub own_interfaces: Vec<String>,
}

/// What an instance builds its dialers from: its defaults, and the
/// handles its dialers apply.
#[derive(Debug, Clone, Default)]
pub struct DialDefaults {
    pub route: RouteDefaults,
    pub env: DialEnv,
}

impl DialDefaults {
    /// The defaults `route` sets, with no host and nothing detected: what
    /// a configuration is checked with.
    pub fn new(route: &crate::config::Route) -> Result<DialDefaults> {
        Ok(DialDefaults {
            route: RouteDefaults::new(route)?,
            env: DialEnv::default(),
        })
    }

    /// A dialer for `fields` over these defaults, for the outbound
    /// `outbound` if it is one. An error names the field. A `detour` is
    /// looked up among the instance's outbounds when it dials: for what is
    /// built before them.
    pub fn dialer(&self, fields: &DialFields, outbound: Option<&str>) -> Result<Dialer> {
        match &fields.detour {
            Some(tag) => Ok(self.detour(
                fields,
                outbound,
                tag,
                Target::Lookup(self.env.outbounds.clone()),
            )),
            None => Ok(Dialer::new(
                DialSpec::resolve(fields, &self.route)?,
                ResolveSpec::resolve(fields, &self.route, outbound),
                self.env.clone(),
            )),
        }
    }

    /// The dialer of the outbound `outbound`, whose `detour`, if it has
    /// one, is built already as `detour`.
    pub fn outbound_dialer(
        &self,
        fields: &DialFields,
        outbound: &str,
        detour: Option<AnyOutboundHandler>,
    ) -> Result<Dialer> {
        match (&fields.detour, detour) {
            (Some(tag), Some(handler)) => {
                Ok(self.detour(fields, Some(outbound), tag, Target::Handler(handler)))
            }
            _ => self.dialer(fields, Some(outbound)),
        }
    }

    fn detour(
        &self,
        fields: &DialFields,
        outbound: Option<&str>,
        tag: &str,
        target: Target,
    ) -> Dialer {
        Dialer(Arc::new(Kind::Detour(DetourDialer {
            tag: tag.to_owned(),
            target,
            resolve: ResolveSpec::resolve(fields, &self.route, outbound),
            resolves_here: fields.domain_resolver.is_some(),
            owner: outbound.unwrap_or_default().to_owned(),
        })))
    }
}

/// The instance's dial defaults as they are now: a reload replaces them.
pub type SharedDialDefaults = Arc<ArcSwap<DialDefaults>>;

/// What the inbounds dial with when they connect somewhere themselves, a
/// fallback, a REALITY handshake server or a masquerade site: the
/// instance's defaults, as a reload leaves them, and its DNS client.
#[derive(Clone)]
pub struct InstanceDial {
    pub defaults: SharedDialDefaults,
    pub dns: SyncDnsClient,
}

impl InstanceDial {
    /// A dialer for `fields` over the instance's defaults, its fields
    /// checked against this platform now. An error names the field.
    pub fn dialer(&self, fields: &DialFields) -> Result<InboundDialer> {
        DialSpec::resolve(fields, &self.defaults.load().route)?;
        Ok(self.follow(fields.clone()))
    }

    /// A dialer of no fields of its own: the instance's defaults alone.
    pub fn default_dialer(&self) -> InboundDialer {
        self.follow(DialFields::default())
    }

    fn follow(&self, fields: DialFields) -> InboundDialer {
        let defaults = self.defaults.load_full();
        let built = Built::new(&fields, defaults);
        InboundDialer(Arc::new(Following {
            fields,
            instance: self.clone(),
            built: ArcSwap::from_pointee(built),
        }))
    }
}

#[cfg(test)]
impl Default for InstanceDial {
    /// No defaults, and a DNS client of no servers.
    fn default() -> Self {
        InstanceDial {
            defaults: Default::default(),
            dns: crate::app::dns::DnsClient::new(
                &Default::default(),
                Default::default(),
                &Default::default(),
            )
            .expect("a DNS client of no servers")
            .into_shared(),
        }
    }
}

/// An inbound's dialer: its dial fields over the instance's defaults as
/// they are when it dials, so that it follows a reload, which builds the
/// outbounds anew but keeps the inbounds. Clones are the same dialer.
#[derive(Clone)]
pub struct InboundDialer(Arc<Following>);

struct Following {
    /// Checked against the platform when it was built.
    fields: DialFields,
    instance: InstanceDial,
    /// The dialer over the defaults it last saw.
    built: ArcSwap<Built>,
}

struct Built {
    defaults: Arc<DialDefaults>,
    dialer: Dialer,
}

impl Built {
    fn new(fields: &DialFields, defaults: Arc<DialDefaults>) -> Built {
        let dialer = Dialer::new(
            DialSpec::merge(fields, &defaults.route),
            ResolveSpec::resolve(fields, &defaults.route, None),
            defaults.env.clone(),
        );
        Built { defaults, dialer }
    }
}

impl InboundDialer {
    /// The dialer over the instance's defaults as they are now.
    pub fn dialer(&self) -> Dialer {
        let Following {
            fields,
            instance,
            built,
        } = &*self.0;
        let defaults = instance.defaults.load_full();
        let last = built.load();
        if Arc::ptr_eq(&last.defaults, &defaults) {
            return last.dialer.clone();
        }
        let now = Arc::new(Built::new(fields, defaults));
        built.store(now.clone());
        now.dialer.clone()
    }

    /// A TCP connection to `host` and `port`, a name resolved by the
    /// instance's DNS client.
    pub async fn tcp(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        self.dialer().tcp(&self.0.instance.dns, host, port).await
    }
}

impl std::fmt::Debug for InboundDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("InboundDialer")
            .field(&self.0.built.load().dialer)
            .finish()
    }
}

/// Opens the sockets of one outbound, DNS server or HTTP client, as its
/// dial fields and the instance's defaults say, or has another outbound
/// carry its connections, as its `detour` says. Built once and shared:
/// clones are the same dialer.
#[derive(Debug, Clone)]
pub struct Dialer(Arc<Kind>);

/// One per dialer, behind its `Arc`: the size of a variant costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Kind {
    /// Opens sockets of its own.
    Socket(SocketDialer),
    /// Opens none: its TCP and UDP are those of the outbound its `detour`
    /// names.
    Detour(DetourDialer),
}

#[derive(Debug)]
struct SocketDialer {
    spec: DialSpec,
    resolve: ResolveSpec,
    env: DialEnv,
    /// Its `network_strategy`, if it has one.
    racing: Option<Racing>,
}

/// What a dialer with a `network_strategy` keeps between its connections.
#[derive(Debug)]
struct Racing {
    networks: Networks,
    /// What the socket for one interface is opened with: no interface or
    /// address of the defaults', the strategy choosing; nor Fast Open,
    /// which sing-box's racers go without (default.go:311).
    spec: DialSpec,
    fallback: FallbackState,
    /// Turned off for good by `EPERM`, the strategy being implicit
    /// (default.go:328-335).
    off: Arc<AtomicBool>,
    /// Whether it was told that the host lists no interfaces.
    told: Arc<AtomicBool>,
}

impl Racing {
    fn new(networks: Networks, spec: &DialSpec) -> Racing {
        Racing {
            networks,
            spec: DialSpec {
                bind_interface: None,
                auto_detect_interface: false,
                inet4_bind_address: None,
                inet6_bind_address: None,
                tcp_fast_open: false,
                ..spec.clone()
            },
            fallback: FallbackState::default(),
            off: Default::default(),
            told: Default::default(),
        }
    }
}

impl Dialer {
    pub fn new(spec: DialSpec, resolve: ResolveSpec, env: DialEnv) -> Dialer {
        let racing = spec
            .networks
            .clone()
            .map(|networks| Racing::new(networks, &spec));
        Dialer(Arc::new(Kind::Socket(SocketDialer {
            spec,
            resolve,
            env,
            racing,
        })))
    }

    /// What it dials one connection with whose rules set a
    /// `network_strategy` or a `fallback_delay` (`route`, `route-options`),
    /// as sing-box's direct outbound dials with what its router set
    /// (route/route.go:637-648, route/conn.go:102,
    /// protocol/direct/outbound.go:232-247): the rules' strategy over its
    /// own, with its own types (common/dialer/default.go:295-310); their
    /// delay over its own, for the families as for the interfaces
    /// (default_parallel_network.go:56-58). A strategy does not apply where
    /// its sockets are bound already, as sing-box's documentation has it
    /// (route/rule_action.md, `network_strategy`). What it learns, the fast
    /// fallback and that the host lists no interfaces, it shares with
    /// itself; an `EPERM` that turned its implicit strategy off holds only
    /// where the rules set none. Itself where they set neither, or with a
    /// detour.
    pub fn routed(&self, strategy: Option<NetworkStrategy>, delay: Option<Duration>) -> Dialer {
        // Zero is unset, as in sing-box (route/route.go:646).
        let delay = delay.filter(|d| !d.is_zero());
        let Kind::Socket(socket) = &*self.0 else {
            return self.clone();
        };
        if strategy.is_none() && delay.is_none() {
            return self.clone();
        }
        let mut spec = socket.spec.clone();
        if let Some(delay) = delay {
            spec.fallback_delay = delay;
        }
        if let Some(own) = spec.network_fallback_delay {
            let delay = delay.unwrap_or(own);
            spec.network_fallback_delay = Some(delay);
            spec.networks = match (strategy, spec.networks.take()) {
                (Some(strategy), own) => {
                    let (network_type, fallback_network_type) = own
                        .map(|own| (own.network_type, own.fallback_network_type))
                        .unwrap_or_default();
                    Some(Networks {
                        strategy,
                        implicit: false,
                        network_type,
                        fallback_network_type,
                        fallback_delay: delay,
                    })
                }
                (None, own) => own.map(|own| Networks {
                    fallback_delay: delay,
                    ..own
                }),
            };
        }
        let racing = spec.networks.clone().map(|networks| {
            let mut racing = Racing::new(networks, &spec);
            if let Some(own) = &socket.racing {
                racing.fallback = own.fallback.clone();
                racing.told = own.told.clone();
                if strategy.is_none() {
                    racing.off = own.off.clone();
                }
            }
            racing
        });
        Dialer(Arc::new(Kind::Socket(SocketDialer {
            spec,
            resolve: socket.resolve.clone(),
            env: socket.env.clone(),
            racing,
        })))
    }

    /// A dialer of no configuration and no instance: nothing bound, nothing
    /// protected, its names resolved by the DNS rules of whichever client
    /// it is given. For what dials outside an instance, and for tests.
    pub fn system() -> Dialer {
        Dialer::new(
            DialSpec::default(),
            ResolveSpec::default(),
            DialEnv::default(),
        )
    }

    fn socket(&self) -> io::Result<&SocketDialer> {
        match &*self.0 {
            Kind::Socket(socket) => Ok(socket),
            Kind::Detour(detour) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("dials through [{}], with no socket of its own", detour.tag),
            )),
        }
    }

    /// The outbound it dials through, if it has a `detour`.
    pub fn detour(&self) -> Option<&str> {
        match &*self.0 {
            Kind::Socket(_) => None,
            Kind::Detour(detour) => Some(&detour.tag),
        }
    }

    /// How its sockets are opened; a detour's, which opens none, are the
    /// defaults.
    pub fn spec(&self) -> &DialSpec {
        static NONE: std::sync::OnceLock<DialSpec> = std::sync::OnceLock::new();
        match &*self.0 {
            Kind::Socket(socket) => &socket.spec,
            Kind::Detour(_) => NONE.get_or_init(DialSpec::default),
        }
    }

    /// How the names it dials resolve.
    pub fn resolve_spec(&self) -> &ResolveSpec {
        match &*self.0 {
            Kind::Socket(socket) => &socket.resolve,
            Kind::Detour(detour) => &detour.resolve,
        }
    }

    /// The handles it applies.
    #[cfg(test)]
    pub fn env(&self) -> &DialEnv {
        &self.socket().expect("a dialer of sockets").env
    }

    /// How long a connect to one address may take.
    pub fn connect_timeout(&self) -> Duration {
        self.spec().connect_timeout
    }

    /// The local address for a UDP socket that is not bound to anything in
    /// particular.
    pub fn unspecified(&self) -> SocketAddr {
        self.spec().unspecified()
    }

    /// The addresses of `host`, as its resolver says, from `dns`.
    pub async fn lookup(&self, dns: &SyncDnsClient, host: &str) -> io::Result<Vec<IpAddr>> {
        dns.load_full()
            .lookup_dial(host, self.resolve_spec())
            .await
            .map_err(|e| io::Error::other(format!("lookup {} failed: {}", host, e)))
    }

    /// Where a connection to `host` and `port` goes, to be tried in turn:
    /// the addresses a name resolves to here, or, through a detour that
    /// leaves names to the far end, the name itself.
    pub async fn targets(
        &self,
        dns: &SyncDnsClient,
        host: &str,
        port: u16,
    ) -> io::Result<Vec<SocksAddr>> {
        let to = SocksAddr::try_from((host, port))?;
        match &*self.0 {
            Kind::Detour(detour) => detour.targets(dns, &to).await,
            Kind::Socket(_) => match to {
                SocksAddr::Ip(_) => Ok(vec![to]),
                SocksAddr::Domain(..) => {
                    let ips = self.lookup(dns, host).await?;
                    if ips.is_empty() {
                        return Err(io::Error::other(format!("{} resolves to nothing", host)));
                    }
                    Ok(ips
                        .into_iter()
                        .map(|ip| SocksAddr::from(SocketAddr::new(ip, port)))
                        .collect())
                }
            },
        }
    }

    /// A stream to `to`: a TCP connection of its own, or one through its
    /// detour, which carries it in `sess` going to `to` (in a session of
    /// its own without one).
    pub async fn stream(
        &self,
        dns: &SyncDnsClient,
        sess: Option<&Session>,
        to: &SocksAddr,
    ) -> io::Result<AnyStream> {
        match &*self.0 {
            Kind::Socket(_) => {
                let (stream, egress) = self.tcp_out(dns, &to.host(), to.port()).await?;
                record(sess, egress);
                record_peer(sess, &stream);
                Ok(Box::new(stream))
            }
            Kind::Detour(detour) => detour.stream(dns, sess, to).await,
        }
    }

    /// A stream to one of `ips` at `port`, the addresses a `resolve` rule
    /// resolved the destination's domain to, which it does not resolve
    /// again: their families raced as `tcp` races a name's, the first
    /// address's family first, as sing-box's direct outbound dials them
    /// (protocol/direct/outbound.go:232-246). A dialer with a detour has
    /// none.
    pub async fn stream_to_resolved(
        &self,
        sess: Option<&Session>,
        ips: &[IpAddr],
        port: u16,
    ) -> io::Result<AnyStream> {
        let SocketDialer { spec, .. } = self.socket()?;
        let Some(first) = ips.first() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no address to dial",
            ));
        };
        let addrs: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
        let order = Order {
            race: !spec.tcp_fast_open,
            prefer_ipv6: first.to_canonical().is_ipv6(),
            fallback_delay: spec.fallback_delay,
        };
        let (stream, egress) =
            super::happy::connect(&addrs, order, |addr| self.tcp_to_out(addr)).await?;
        record(sess, egress);
        record_peer(sess, &stream);
        Ok(Box::new(stream))
    }

    /// Datagrams to `to`: a UDP socket of its own, a name resolved as each
    /// datagram is sent, or the datagrams of its detour, as `stream`.
    pub async fn datagram(
        &self,
        dns: &SyncDnsClient,
        sess: Option<&Session>,
        to: &SocksAddr,
    ) -> io::Result<AnyOutboundDatagram> {
        match &*self.0 {
            Kind::Socket(_) => {
                let indicator = match to.ip() {
                    Some(ip) if ip.is_loopback() => SocketAddr::new(ip, 0),
                    _ => self.unspecified(),
                };
                let (socket, egress) = self.udp_out(&indicator).await?;
                record(sess, egress);
                Ok(Box::new(crate::net::DomainResolveOutboundDatagram::new(
                    socket,
                    dns.clone(),
                    self.clone(),
                )))
            }
            Kind::Detour(detour) => detour.datagram(dns, sess, to).await,
        }
    }

    /// What quinn sends and receives through to reach `to`, an address of
    /// `targets`, and the address quinn is to connect to: a UDP socket of
    /// its own, or its detour's datagrams, a name standing for itself.
    #[cfg(feature = "quic")]
    pub async fn quic_socket(
        &self,
        dns: &SyncDnsClient,
        sess: Option<&Session>,
        to: &SocksAddr,
    ) -> io::Result<(Arc<dyn quinn::AsyncUdpSocket>, SocketAddr)> {
        match (&*self.0, to) {
            (Kind::Socket(_), SocksAddr::Ip(addr)) => {
                let socket = crate::transport::quic::bind(addr.ip(), self).await?;
                Ok((crate::transport::quic::wrap_socket(socket)?, *addr))
            }
            (Kind::Socket(_), SocksAddr::Domain(..)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: not an address", to),
            )),
            (Kind::Detour(detour), _) => {
                let datagram = detour.datagram(dns, sess, to).await?;
                let socket = crate::transport::quic::DetourSocket::new(datagram, to.clone());
                let peer = socket.peer();
                Ok((Arc::new(socket), peer))
            }
        }
    }

    /// A TCP connection to `host` and `port`, a name resolved with `dns`:
    /// its two families raced (Happy Eyeballs), or, with TCP Fast Open,
    /// its addresses tried one by one. A dialer with a detour has none.
    pub async fn tcp(&self, dns: &SyncDnsClient, host: &str, port: u16) -> io::Result<TcpStream> {
        self.tcp_out(dns, host, port)
            .await
            .map(|(stream, _)| stream)
    }

    /// `tcp`, and where the connection went out.
    async fn tcp_out(
        &self,
        dns: &SyncDnsClient,
        host: &str,
        port: u16,
    ) -> io::Result<(TcpStream, Egress)> {
        let SocketDialer { spec, resolve, .. } = self.socket()?;
        let addrs: Vec<SocketAddr> = Resolver::new(dns.clone(), host, port, resolve)
            .await
            .map_err(|e| io::Error::other(format!("resolve address failed: {}", e)))?
            .collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            ));
        }
        let order = Order {
            // A Fast Open connect completes before the server answers, so
            // there is nothing to race: as in sing-box.
            race: !spec.tcp_fast_open,
            prefer_ipv6: resolve.prefers_ipv6(),
            fallback_delay: spec.fallback_delay,
        };
        // The families race outside, the interfaces of each address
        // inside, as sing-box's resolving dialer has it (resolve.go:108).
        super::happy::connect(&addrs, order, |addr| self.tcp_to_out(addr)).await
    }

    /// A TCP connection to `addr`.
    pub async fn tcp_to(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        self.tcp_to_out(addr).await.map(|(stream, _)| stream)
    }

    /// `tcp_to`, and where the connection went out: out of the interfaces
    /// its `network_strategy` races, if it has one.
    async fn tcp_to_out(&self, addr: SocketAddr) -> io::Result<(TcpStream, Egress)> {
        let socket = self.socket()?;
        // On an IPv6-only network, IPv4 is reached through NAT64.
        let addr = crate::net::nat64::map(addr);
        let Some((racing, primaries, fallbacks)) = socket.candidates(addr.ip()) else {
            return self.tcp_via(addr, None).await;
        };
        let this = self.clone();
        let raced = networks::race(
            primaries,
            fallbacks,
            racing.networks.fallback_delay,
            &racing.fallback,
            move |via| {
                let this = this.clone();
                async move { this.tcp_via(addr, Some(via)).await }
            },
        )
        .await;
        match raced {
            Ok((connected, _)) => Ok(connected),
            Err(failed) => {
                racing.permission_refused(failed)?;
                self.tcp_via(addr, None).await
            }
        }
    }

    /// A TCP connection to `addr`, out of `via` if one is given.
    async fn tcp_via(&self, addr: SocketAddr, via: Option<Via>) -> io::Result<(TcpStream, Egress)> {
        let SocketDialer {
            spec, env, racing, ..
        } = self.socket()?;
        let socket = match addr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        let (spec, egress) = match (&via, racing) {
            (Some(via), Some(racing)) => {
                super::bind_via(&SockRef::from(&socket), &addr, &racing.spec, via)?;
                (&racing.spec, Egress::of(via))
            }
            _ => {
                let (_, egress) = super::bind_egress(
                    &SockRef::from(&socket),
                    &addr,
                    spec,
                    env.auto_interface.as_deref(),
                )?;
                (spec, egress)
            }
        };

        #[cfg(unix)]
        protect_socket(socket.as_raw_fd(), env.protect.as_ref()).await?;

        debug!("tcp dialing {}", &addr);
        let start = tokio::time::Instant::now();
        let connect = super::sockopt::connect(socket, addr, spec.tcp_fast_open);
        let stream = timeout(spec.connect_timeout, connect).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connect {} timed out", addr),
            )
        })??;
        let elapsed = tokio::time::Instant::now().duration_since(start);

        crate::net::apply_socket_opts(SockRef::from(&stream), spec.tcp_keep_alive)?;

        debug!(
            "tcp {} <-> {} connected in {}ms",
            stream.local_addr()?,
            &addr,
            elapsed.as_millis()
        );
        Ok((stream, egress))
    }

    /// A UDP socket for talking to `indicator`'s address family; bound to
    /// `indicator` itself where that is unspecified and nothing else binds
    /// it. A dialer with a detour has none.
    pub async fn udp_socket(&self, indicator: &SocketAddr) -> io::Result<UdpSocket> {
        self.udp_out(indicator).await.map(|(socket, _)| socket)
    }

    /// `udp_socket`, its interface recorded on `sess` as the connection's.
    pub async fn udp_socket_for(
        &self,
        sess: &Session,
        indicator: &SocketAddr,
    ) -> io::Result<UdpSocket> {
        let (socket, egress) = self.udp_out(indicator).await?;
        record(Some(sess), egress);
        Ok(socket)
    }

    /// `udp_socket`, and where it goes out: the first of the interfaces its
    /// `network_strategy` chooses that takes it, if it has one
    /// (default.go:377-408).
    async fn udp_out(&self, indicator: &SocketAddr) -> io::Result<(UdpSocket, Egress)> {
        let dialer = self.socket()?;
        // On an IPv6-only network, IPv4 is reached through NAT64, over IPv6.
        let indicator = &crate::net::nat64::map(*indicator);
        let Some((racing, primaries, fallbacks)) = dialer.candidates(indicator.ip()) else {
            return self.udp_via(indicator, None).await;
        };
        let opened = networks::serial(primaries, fallbacks, |via| {
            self.udp_via(indicator, Some(via))
        })
        .await;
        match opened {
            Ok((opened, _)) => Ok(opened),
            Err(failed) => {
                racing.permission_refused(failed)?;
                self.udp_via(indicator, None).await
            }
        }
    }

    /// A UDP socket for `indicator`, bound to `via` if one is given.
    async fn udp_via(
        &self,
        indicator: &SocketAddr,
        via: Option<Via>,
    ) -> io::Result<(UdpSocket, Egress)> {
        let SocketDialer {
            spec, env, racing, ..
        } = self.socket()?;
        let socket = Socket::new(Domain::for_address(*indicator), Type::DGRAM, None)?;
        crate::net::no_udp_connreset(SockRef::from(&socket));
        crate::net::dual_stack(SockRef::from(&socket), indicator)?;
        socket.set_nonblocking(true)?;
        crate::net::fit_largest_datagram(SockRef::from(&socket))?;
        if spec.reuse_addr {
            super::sockopt::reuse_addr(SockRef::from(&socket))?;
        }
        if !spec.udp_fragment {
            super::sockopt::dont_fragment(SockRef::from(&socket), indicator.is_ipv6())?;
        }
        let (bound, egress) = match (&via, racing) {
            (Some(via), Some(racing)) => {
                super::bind_via(&socket, indicator, &racing.spec, via)?;
                (false, Egress::of(via))
            }
            _ => super::bind_egress(&socket, indicator, spec, env.auto_interface.as_deref())?,
        };
        if !bound && indicator.ip().is_unspecified() {
            socket.bind(&(*indicator).into())?;
        }

        #[cfg(unix)]
        protect_socket(socket.as_raw_fd(), env.protect.as_ref()).await?;

        Ok((UdpSocket::from_std(socket.into())?, egress))
    }
}

impl SocketDialer {
    /// The interfaces its `network_strategy` chooses for `target`, first
    /// and fallback, from the host's as they are now; none where it has
    /// no strategy, or it does not apply. It does not to loopback, which
    /// is never bound, nor while the host lists no interfaces: its
    /// connections then go out the default route, as without one, and it
    /// says so once.
    fn candidates(&self, target: IpAddr) -> Option<(&Racing, Vec<Via>, Vec<Via>)> {
        let racing = self.racing.as_ref()?;
        if racing.off.load(Ordering::Relaxed) || target.is_loopback() {
            return None;
        }
        let state = self.env.network.as_ref().map(|network| network.snapshot());
        let Some(state) = state.filter(|state| !state.interfaces.is_empty()) else {
            if !racing.told.swap(true, Ordering::Relaxed) {
                warn!(
                    "network_strategy: the host lists no interfaces; connections go out the \
                     default route until it does"
                );
            }
            return None;
        };
        let (primaries, fallbacks) =
            networks::select(&state, &self.env.own_interfaces, &racing.networks);
        Some((racing, primaries, fallbacks))
    }
}

impl Racing {
    /// Every interface failed: the error, unless one was refused for want
    /// of permission and the strategy is implicit, which turns it off for
    /// good, for the caller to dial as without one (default.go:328-335).
    fn permission_refused(&self, failed: networks::Failed) -> io::Result<()> {
        if !(failed.permission && self.networks.implicit) {
            return Err(failed.error);
        }
        warn!(
            "network_strategy: binding to an interface is not permitted; connections go out \
             the default route from now on: {}",
            failed.error
        );
        self.off.store(true, Ordering::Relaxed);
        Ok(())
    }
}

/// Records on `sess`, if there is one, where its connection went out.
fn record(sess: Option<&Session>, egress: Egress) {
    if let Some(sess) = sess {
        sess.state.get::<BoundInterface>().set(egress);
    }
}

/// Records on `sess`, if there is one, the address its TCP connection out
/// was made to.
fn record_peer(sess: Option<&Session>, stream: &TcpStream) {
    if let (Some(sess), Ok(peer)) = (sess, stream.peer_addr()) {
        sess.state.get::<BoundInterface>().set_peer(peer);
    }
}

/// Keeps an outbound socket out of the host's VPN, as `protect` says.
#[cfg(unix)]
async fn protect_socket(fd: RawFd, protect: Option<&SocketProtect>) -> io::Result<()> {
    let answer = match protect {
        None => return Ok(()),
        Some(SocketProtect::Platform(platform)) => {
            let start = std::time::Instant::now();
            platform.protect_socket(fd).map_err(|e| {
                io::Error::other(format!("failed to protect outbound socket {}: {}", fd, e))
            })?;
            trace!(
                "protected socket {} in {} µs",
                fd,
                start.elapsed().as_micros()
            );
            return Ok(());
        }
        Some(SocketProtect::Tcp(addr)) => {
            let mut stream = TcpStream::connect(addr).await?;
            stream.write_i32(fd).await?;
            stream.read_i32().await?
        }
        Some(SocketProtect::Unix(path)) => {
            let mut stream = UnixStream::connect(path).await?;
            stream.write_i32(fd).await?;
            stream.read_i32().await?
        }
    };
    if answer != 0 {
        return Err(io::Error::other(format!(
            "failed to protect outbound socket {}",
            fd
        )));
    }
    Ok(())
}

/// A dialer whose host protects sockets by counting them: which dialer a
/// socket was opened with, for tests.
#[cfg(all(test, unix))]
pub(crate) mod recording {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::runtime::{Platform, PlatformRef};

    #[derive(Default)]
    pub(crate) struct Protected(AtomicUsize);

    impl Platform for Protected {
        fn log(&self, _line: &str) {}

        fn protects_sockets(&self) -> bool {
            true
        }

        fn protect_socket(&self, _fd: i32) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl Protected {
        /// How many sockets were protected.
        pub(crate) fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Defaults whose dialers are counted by the returned counter.
    pub(crate) fn defaults() -> (DialDefaults, Arc<Protected>) {
        let protected = Arc::new(Protected::default());
        let defaults = DialDefaults {
            route: RouteDefaults::default(),
            env: DialEnv {
                auto_interface: None,
                protect: Some(SocketProtect::Platform(PlatformRef(protected.clone()))),
                ..Default::default()
            },
        };
        (defaults, protected)
    }

    /// What inbounds dial with, over defaults whose dialers are counted by
    /// the returned counter.
    // Its tests run on Unix, and REALITY's only with its client too.
    #[cfg_attr(
        not(all(
            unix,
            any(
                feature = "inbound-anytls",
                feature = "inbound-trojan",
                feature = "inbound-vless",
                feature = "inbound-shadowtls",
                all(feature = "inbound-reality", feature = "outbound-reality"),
                feature = "inbound-hysteria2"
            )
        )),
        allow(dead_code)
    )]
    pub(crate) fn instance() -> (InstanceDial, Arc<Protected>) {
        let (defaults, protected) = defaults();
        let dial = InstanceDial {
            defaults: Arc::new(ArcSwap::from_pointee(defaults)),
            ..InstanceDial::default()
        };
        (dial, protected)
    }

    /// A dialer counted by the returned counter.
    pub(crate) fn dialer() -> (Dialer, Arc<Protected>) {
        let (defaults, protected) = defaults();
        (
            defaults.dialer(&DialFields::default(), None).unwrap(),
            protected,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_from_the_defaults_it_takes_their_handles() {
        let auto = AutoInterface::new(Vec::new(), || Ok("lo".into()));
        let defaults = DialDefaults {
            route: RouteDefaults {
                auto_detect_interface: true,
                ..Default::default()
            },
            env: DialEnv {
                auto_interface: Some(auto.clone()),
                protect: None,
                ..Default::default()
            },
        };
        let dialer = defaults
            .dialer(
                &serde_json::from_value(serde_json::json!({ "connect_timeout": "3s" })).unwrap(),
                Some("proxy"),
            )
            .unwrap();
        assert!(dialer.spec().auto_detect_interface);
        assert!(Arc::ptr_eq(
            dialer.env().auto_interface.as_ref().unwrap(),
            &auto
        ));
        assert_eq!(dialer.connect_timeout(), Duration::from_secs(3));
        assert_eq!(dialer.resolve_spec().outbound.as_deref(), Some("proxy"));
        // Clones are the same dialer.
        let clone = dialer.clone();
        assert!(Arc::ptr_eq(&clone.0, &dialer.0));
    }

    #[test]
    fn a_field_the_platform_cannot_apply_fails_the_build() {
        let fields = serde_json::from_value(serde_json::json!({ "routing_mark": 1 })).unwrap();
        let built = DialDefaults::default().dialer(&fields, None);
        assert_eq!(built.is_ok(), super::super::supports_routing_mark());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn its_sockets_are_protected_by_its_host() {
        let (dialer, protected) = recording::dialer();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (dialled, accepted) = tokio::join!(dialer.tcp_to(addr), listener.accept());
        dialled.unwrap();
        accepted.unwrap();
        assert_eq!(protected.count(), 1);
        dialer
            .udp_socket(&"127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(protected.count(), 2);
        // Another dialer, another host.
        Dialer::system().tcp_to(addr).await.unwrap();
        assert_eq!(protected.count(), 2);
    }

    #[test]
    fn an_inbound_dialer_follows_the_defaults_a_reload_brings() {
        let dial = InstanceDial::default();
        let fields =
            serde_json::from_value(serde_json::json!({ "connect_timeout": "2s" })).unwrap();
        let inbound = dial.dialer(&fields).unwrap();
        assert_eq!(inbound.dialer().spec().routing_mark, None);
        // The same defaults, the same dialer.
        assert!(Arc::ptr_eq(&inbound.dialer().0, &inbound.dialer().0));
        dial.defaults.store(Arc::new(DialDefaults {
            route: RouteDefaults {
                routing_mark: Some(7),
                bind_interface: Some("eth9".into()),
                ..Default::default()
            },
            env: DialEnv::default(),
        }));
        let now = inbound.dialer();
        assert_eq!(now.spec().routing_mark, Some(7));
        assert_eq!(now.spec().bind_interface.as_deref(), Some("eth9"));
        // Its own fields stay.
        assert_eq!(now.connect_timeout(), Duration::from_secs(2));
        // Of no fields, the defaults alone.
        assert_eq!(
            dial.default_dialer().dialer().connect_timeout(),
            super::super::DEFAULT_CONNECT_TIMEOUT
        );
    }

    #[test]
    fn an_inbound_dialer_is_checked_against_the_platform() {
        let fields = serde_json::from_value(serde_json::json!({ "routing_mark": 1 })).unwrap();
        let built = InstanceDial::default().dialer(&fields);
        assert_eq!(built.is_ok(), super::super::supports_routing_mark());
        if let Err(e) = built {
            assert_eq!(e.to_string(), "routing_mark: only supported on Linux");
        }
    }

    /// A dialer of `strategy` over `state`, the host's network.
    fn racing(json: serde_json::Value, state: crate::net::network::NetworkState) -> Dialer {
        let network = crate::net::network::Network::default();
        network.push(state);
        let defaults = DialDefaults {
            env: DialEnv {
                network: Some(network),
                own_interfaces: vec!["utun99".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        defaults
            .dialer(&serde_json::from_value(json).unwrap(), None)
            .unwrap()
    }

    #[cfg(target_os = "macos")]
    fn listed(default: &str, names: &[&str]) -> crate::net::network::NetworkState {
        use crate::net::network::{NetworkInterface, NetworkType};
        crate::net::network::NetworkState {
            interface: Some(default.into()),
            interfaces: names
                .iter()
                .map(|name| NetworkInterface {
                    name: name.to_string(),
                    index: None,
                    kind: NetworkType::Ethernet,
                    addresses: Vec::new(),
                    expensive: false,
                    constrained: false,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[cfg(target_os = "macos")]
    const LOOPBACK: &str = "lo0";

    /// UDP goes out the first interface the strategy chooses that takes
    /// it: the default one unbound, another bound to it.
    // Binding to an interface takes no privilege on macOS.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn udp_goes_out_the_interfaces_in_turn() {
        let any: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let hybrid = || serde_json::json!({ "network_strategy": "hybrid" });
        let dialer = racing(hybrid(), listed(LOOPBACK, &[LOOPBACK]));
        let (_, egress) = dialer.udp_out(&any).await.unwrap();
        assert_eq!(egress, Egress::DefaultRoute);
        // One that cannot be bound, then one that can.
        let dialer = racing(hybrid(), listed("en9", &["no-such-if0", LOOPBACK]));
        let (_, egress) = dialer.udp_out(&any).await.unwrap();
        assert_eq!(
            egress,
            Egress::Interface {
                name: LOOPBACK.into(),
                index: None
            }
        );
        // None of the host's to choose: an error.
        let fallback = serde_json::json!({ "network_strategy": "default" });
        let dialer = racing(fallback, listed("utun99", &["utun99", LOOPBACK]));
        let e = dialer.udp_out(&any).await.unwrap_err();
        assert_eq!(e.to_string(), "no available network interface");
        // Loopback is never raced.
        let (_, egress) = dialer
            .udp_out(&"127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(egress, Egress::DefaultRoute);
    }

    /// Without the host's interfaces listed, it goes out the default route,
    /// as without a strategy.
    #[tokio::test]
    async fn with_no_interfaces_listed_it_goes_out_the_default_route() {
        let dialer = racing(
            serde_json::json!({ "network_strategy": "default" }),
            Default::default(),
        );
        let (_, egress) = dialer.udp_out(&"0.0.0.0:0".parse().unwrap()).await.unwrap();
        assert_eq!(egress, Egress::DefaultRoute);
    }

    /// The interface a connection went out on is on its session.
    // Binding to an interface takes no privilege on macOS.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn the_interface_is_recorded_on_the_session() {
        let dialer = racing(
            serde_json::json!({ "network_strategy": "hybrid" }),
            listed("en9", &[LOOPBACK]),
        );
        let sess = Session::default();
        dialer
            .udp_socket_for(&sess, &"0.0.0.0:0".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            sess.state.get::<BoundInterface>().get(),
            Some(Egress::Interface {
                name: LOOPBACK.into(),
                index: None
            })
        );
        // Its copies share it.
        let sess = Session::default();
        let copy = sess.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let to = SocksAddr::from(listener.local_addr().unwrap());
        let dns = InstanceDial::default().dns;
        dialer.stream(&dns, Some(&sess), &to).await.unwrap();
        assert_eq!(
            copy.state.get::<BoundInterface>().get(),
            Some(Egress::DefaultRoute)
        );
    }

    /// `EPERM` binding turns an implicit strategy off for good; an explicit
    /// one fails (default.go:328-335).
    #[cfg(unix)]
    #[test]
    fn a_refused_bind_turns_off_an_implicit_strategy_only() {
        let refused = || networks::Failed {
            error: io::Error::from_raw_os_error(libc::EPERM),
            permission: true,
        };
        let implicit = racing(
            serde_json::json!({ "network_type": "wifi" }),
            Default::default(),
        );
        let Kind::Socket(socket) = &*implicit.0 else {
            unreachable!()
        };
        let racing_ = socket.racing.as_ref().unwrap();
        racing_.permission_refused(refused()).unwrap();
        assert!(racing_.off.load(Ordering::Relaxed));
        assert!(socket.candidates("192.0.2.1".parse().unwrap()).is_none());
        let explicit = racing(
            serde_json::json!({ "network_strategy": "default" }),
            Default::default(),
        );
        let Kind::Socket(socket) = &*explicit.0 else {
            unreachable!()
        };
        let racing_ = socket.racing.as_ref().unwrap();
        assert!(racing_.permission_refused(refused()).is_err());
        assert!(!racing_.off.load(Ordering::Relaxed));
        // Nor does another refusal.
        let other = networks::Failed {
            error: io::Error::from(io::ErrorKind::ConnectionRefused),
            permission: false,
        };
        let Kind::Socket(socket) = &*implicit.0 else {
            unreachable!()
        };
        assert!(socket
            .racing
            .as_ref()
            .unwrap()
            .permission_refused(other)
            .is_err());
    }

    /// The rules' `network_strategy` goes before its own, its own types
    /// kept; their `fallback_delay` before its own, for the families as
    /// for the interfaces; a strategy applies only where nothing binds its
    /// sockets (default.go:295-310).
    #[test]
    fn the_rules_network_goes_before_its_own() {
        use crate::net::network::NetworkType;
        let dialer = |json| {
            DialDefaults::default()
                .dialer(&serde_json::from_value(json).unwrap(), None)
                .unwrap()
        };
        let delay = Duration::from_millis(40);
        let own = dialer(serde_json::json!({
            "network_strategy": "default", "network_type": "wifi", "fallback_delay": "1s",
        }));
        let routed = own.routed(Some(NetworkStrategy::Fallback), None);
        let networks = routed.spec().networks.clone().unwrap();
        assert_eq!(networks.strategy, NetworkStrategy::Fallback);
        assert!(!networks.implicit);
        assert_eq!(networks.network_type, vec![NetworkType::Wifi]);
        assert_eq!(networks.fallback_delay, Duration::from_secs(1));
        assert_eq!(routed.spec().fallback_delay, Duration::from_secs(1));
        let routed = own.routed(None, Some(delay));
        let networks = routed.spec().networks.clone().unwrap();
        assert_eq!(networks.strategy, NetworkStrategy::Default);
        assert_eq!(networks.fallback_delay, delay);
        assert_eq!(routed.spec().fallback_delay, delay);

        // One of no strategy takes the rules'.
        let plain = dialer(serde_json::json!({}));
        let routed = plain.routed(Some(NetworkStrategy::Hybrid), None);
        let networks = routed.spec().networks.clone().unwrap();
        assert_eq!(networks.strategy, NetworkStrategy::Hybrid);
        assert!(networks.network_type.is_empty());
        assert_eq!(
            networks.fallback_delay,
            super::super::DEFAULT_FALLBACK_DELAY
        );

        // One bound already takes the delay only.
        let bound = dialer(serde_json::json!({ "inet4_bind_address": "127.0.0.1" }));
        let routed = bound.routed(Some(NetworkStrategy::Hybrid), Some(delay));
        assert_eq!(routed.spec().networks, None);
        assert_eq!(routed.spec().fallback_delay, delay);

        // Neither set, or zero, it is itself.
        assert!(Arc::ptr_eq(&own.routed(None, None).0, &own.0));
        assert!(Arc::ptr_eq(
            &own.routed(None, Some(Duration::ZERO)).0,
            &own.0
        ));
    }

    /// A dialer the rules derive keeps what its own learnt: the fast
    /// fallback, and an implicit strategy turned off, unless they set
    /// another.
    #[test]
    fn a_routed_dialer_shares_what_its_own_learnt() {
        let own = racing(
            serde_json::json!({ "network_type": "wifi" }),
            Default::default(),
        );
        let racing_of = |dialer: &Dialer| {
            let Kind::Socket(socket) = &*dialer.0 else {
                unreachable!()
            };
            let racing = socket.racing.as_ref().unwrap();
            (racing.off.clone(), racing.told.clone())
        };
        let (off, told) = racing_of(&own);
        off.store(true, Ordering::Relaxed);
        let delayed = own.routed(None, Some(Duration::from_millis(40)));
        assert!(Arc::ptr_eq(&racing_of(&delayed).0, &off));
        assert!(Arc::ptr_eq(&racing_of(&delayed).1, &told));
        let other = own.routed(Some(NetworkStrategy::Hybrid), None);
        assert!(!racing_of(&other).0.load(Ordering::Relaxed));
        assert!(Arc::ptr_eq(&racing_of(&other).1, &told));
    }

    /// A connect to one address that is never answered gives up after 5s,
    /// sing-box's time.
    #[tokio::test(start_paused = true)]
    async fn a_connect_gives_up_after_five_seconds() {
        assert_eq!(Dialer::system().connect_timeout(), Duration::from_secs(5));
        // TEST-NET-1, which no one answers: the clock, paused, runs on to
        // the timeout while the connect waits. Where the system refuses it
        // at once, as without a route, there is nothing to wait for.
        let addr = SocketAddr::from(([192, 0, 2, 1], 443));
        let start = tokio::time::Instant::now();
        let e = match Dialer::system().tcp_to(addr).await {
            // Something on the path answered for it, as a VPN or a proxy
            // with fake addresses on the machine running the tests does.
            Ok(_) => {
                eprintln!("{} answered: something on the path intercepts it", addr);
                return;
            }
            Err(e) => e,
        };
        if e.kind() != io::ErrorKind::TimedOut {
            eprintln!("{} refused at once: {}", addr, e);
            assert!(start.elapsed() < Duration::from_secs(5));
            return;
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(5) && elapsed < Duration::from_secs(6),
            "{:?}",
            elapsed
        );
    }
}
