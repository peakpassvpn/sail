//! The one way sail opens a socket to go out: a [`Dialer`], built once for
//! an outbound, a DNS server or an HTTP client from its [`DialSpec`] and
//! [`ResolveSpec`], and the handles of the running instance it applies them
//! with, [`DialEnv`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use socket2::{Domain, SockRef, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, trace};

#[cfg(unix)]
use {
    std::os::unix::io::{AsRawFd, RawFd},
    tokio::io::{AsyncReadExt, AsyncWriteExt},
    tokio::net::UnixStream,
};

use super::{DialFields, DialSpec, ResolveSpec, RouteDefaults, SocketProtect};
use crate::app::SyncDnsClient;
use crate::net::interface::AutoInterface;
use crate::net::resolver::Resolver;

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
    /// `outbound` if it is one. An error names the field.
    pub fn dialer(&self, fields: &DialFields, outbound: Option<&str>) -> Result<Dialer> {
        Ok(Dialer::new(
            DialSpec::resolve(fields, &self.route)?,
            ResolveSpec::resolve(fields, &self.route, outbound),
            self.env.clone(),
        ))
    }
}

/// Opens the sockets of one outbound, DNS server or HTTP client, as its
/// dial fields and the instance's defaults say. Built once and shared:
/// clones are the same dialer.
#[derive(Debug, Clone)]
pub struct Dialer(Arc<Kind>);

#[derive(Debug)]
enum Kind {
    /// Opens sockets of its own.
    Socket(SocketDialer),
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

    fn socket(&self) -> &SocketDialer {
        let Kind::Socket(socket) = &*self.0;
        socket
    }

    /// How its sockets are opened.
    pub fn spec(&self) -> &DialSpec {
        &self.socket().spec
    }

    /// How the names it dials resolve.
    pub fn resolve_spec(&self) -> &ResolveSpec {
        &self.socket().resolve
    }

    /// The handles it applies.
    pub fn env(&self) -> &DialEnv {
        &self.socket().env
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

    /// A TCP connection to `host` and `port`, a name resolved with `dns`,
    /// trying its addresses one by one.
    pub async fn tcp(&self, dns: &SyncDnsClient, host: &str, port: u16) -> io::Result<TcpStream> {
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
        let SocketDialer { spec, env, .. } = self.socket();
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
    /// it.
    pub async fn udp_socket(&self, indicator: &SocketAddr) -> io::Result<UdpSocket> {
        let SocketDialer { spec, env, .. } = self.socket();
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
            },
        };
        (defaults, protected)
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
}
