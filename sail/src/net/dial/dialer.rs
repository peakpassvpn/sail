//! The one way sail opens a socket to go out: a [`Dialer`], built once for
//! an outbound, a DNS server or an HTTP client from its [`DialSpec`] and
//! [`ResolveSpec`], and the handles of the running instance it applies them
//! with, [`DialEnv`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use socket2::{Domain, SockRef, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;
#[cfg(unix)]
use tracing::trace;

#[cfg(unix)]
use {
    std::os::unix::io::{AsRawFd, RawFd},
    tokio::io::{AsyncReadExt, AsyncWriteExt},
    tokio::net::UnixStream,
};

use super::detour::{DetourDialer, Outbounds, Target};
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
}

impl Dialer {
    pub fn new(spec: DialSpec, resolve: ResolveSpec, env: DialEnv) -> Dialer {
        Dialer(Arc::new(Kind::Socket(SocketDialer { spec, resolve, env })))
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
            Kind::Socket(_) => Ok(Box::new(self.tcp(dns, &to.host(), to.port()).await?)),
            Kind::Detour(detour) => detour.stream(dns, sess, to).await,
        }
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
                let socket = match to.ip() {
                    Some(ip) if ip.is_loopback() => {
                        self.udp_socket(&SocketAddr::new(ip, 0)).await?
                    }
                    _ => self.udp_socket(&self.unspecified()).await?,
                };
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

    /// A TCP connection to `host` and `port`, a name resolved with `dns`,
    /// trying its addresses one by one. A dialer with a detour has none.
    pub async fn tcp(&self, dns: &SyncDnsClient, host: &str, port: u16) -> io::Result<TcpStream> {
        self.socket()?;
        let resolver = Resolver::new(dns.clone(), host, port, self.resolve_spec())
            .await
            .map_err(|e| io::Error::other(format!("resolve address failed: {}", e)))?;

        let mut last_err = None;
        for addr in resolver {
            match self.tcp_to(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }

        Err(match last_err {
            Some(e) => io::Error::other(format!("all attempts failed, last error: {}", e)),
            None => io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            ),
        })
    }

    /// A TCP connection to `addr`.
    pub async fn tcp_to(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let SocketDialer { spec, env, .. } = self.socket()?;
        let socket = match addr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        super::bind(
            &SockRef::from(&socket),
            &addr,
            spec,
            env.auto_interface.as_deref(),
        )?;

        #[cfg(unix)]
        protect_socket(socket.as_raw_fd(), env.protect.as_ref()).await?;

        debug!("tcp dialing {}", &addr);
        let start = tokio::time::Instant::now();
        let stream = timeout(spec.connect_timeout, socket.connect(addr))
            .await
            .map_err(|_| {
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
        Ok(stream)
    }

    /// A UDP socket for talking to `indicator`'s address family; bound to
    /// `indicator` itself where that is unspecified and nothing else binds
    /// it. A dialer with a detour has none.
    pub async fn udp_socket(&self, indicator: &SocketAddr) -> io::Result<UdpSocket> {
        let SocketDialer { spec, env, .. } = self.socket()?;
        let socket = Socket::new(Domain::for_address(*indicator), Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        crate::net::fit_largest_datagram(SockRef::from(&socket))?;
        let bound = super::bind(&socket, indicator, spec, env.auto_interface.as_deref())?;
        if !bound && indicator.ip().is_unspecified() {
            socket.bind(&(*indicator).into())?;
        }

        #[cfg(unix)]
        protect_socket(socket.as_raw_fd(), env.protect.as_ref()).await?;

        UdpSocket::from_std(socket.into())
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
