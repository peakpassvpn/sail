//! Fallback for the inbounds that authenticate in their first bytes, Trojan
//! and VLESS, as sing-box's trojan inbound has it: a connection that fails
//! to authenticate is relayed to a web server, starting with the bytes read
//! of it so far, so that an active prober meets that server rather than a
//! connection that closes on it. ShadowTLS relays to its handshake server
//! the same way. The relay is sail's, as a routed connection's: its
//! buffers, and its write stall and idle timeouts (`relay`).

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::Instrument;

use crate::{adapter::AnyStream, net::InboundDialer, runtime::options::Relay, session::Session};

/// How long a peer that has sent less than a header is waited for before it
/// is handed to the fallback, as Xray does: a prober that sends a few bytes
/// and waits must get the web server's answer, not a silence that only a
/// proxy would keep. Only applies with a fallback; without one the
/// inbound's handshake deadline bounds the wait as before.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(2);

/// Says, for a server, that the inbound `tag` of `protocol` has no
/// fallback: a fact of how it answers a prober, not a mistake.
pub fn note_without(tag: &str, protocol: &str, env: &crate::runtime::RuntimeEnv) {
    if env.options.profile == crate::runtime::options::Profile::Server {
        tracing::info!(
            "[{}] inbound: {} without a fallback: a wrong first byte closes the connection, as in sing-box",
            tag,
            protocol
        );
    }
}

/// Where a fallback goes, as sing-box writes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackServer {
    server: String,
    server_port: u16,
}

#[derive(Debug)]
struct Target {
    server: String,
    port: u16,
}

impl Target {
    fn parse(field: &str, options: FallbackServer) -> Result<Self> {
        if options.server.is_empty() {
            return Err(anyhow!("{}.server: cannot be empty", field));
        }
        if options.server_port == 0 {
            return Err(anyhow!("{}.server_port: cannot be 0", field));
        }
        Ok(Target {
            server: options.server,
            port: options.server_port,
        })
    }
}

/// The fallback servers of one inbound.
#[derive(Debug)]
pub struct Fallback {
    default: Option<Target>,
    by_alpn: HashMap<String, Target>,
    dialer: InboundDialer,
    relay: Relay,
}

impl Fallback {
    /// `fallback` and `fallback_for_alpn` as the inbound's options have
    /// them, dialled with `dialer` and relayed as `relay` says; `None` if
    /// neither is set, which leaves the inbound closing what fails to
    /// authenticate.
    pub fn new(
        tag: &str,
        fallback: Option<FallbackServer>,
        fallback_for_alpn: HashMap<String, FallbackServer>,
        dialer: InboundDialer,
        relay: Relay,
    ) -> Result<Option<Self>> {
        let default = fallback
            .map(|f| Target::parse("fallback", f))
            .transpose()
            .map_err(|e| anyhow!("[{}] inbound: {}", tag, e))?;
        let mut by_alpn = HashMap::new();
        for (alpn, server) in fallback_for_alpn {
            if alpn.is_empty() {
                return Err(anyhow!(
                    "[{}] inbound: fallback_for_alpn: an ALPN cannot be empty",
                    tag
                ));
            }
            let target = Target::parse(&format!("fallback_for_alpn.{}", alpn), server)
                .map_err(|e| anyhow!("[{}] inbound: {}", tag, e))?;
            by_alpn.insert(alpn, target);
        }
        if default.is_none() && by_alpn.is_empty() {
            return Ok(None);
        }
        Ok(Some(Fallback {
            default,
            by_alpn,
            dialer,
            relay,
        }))
    }

    /// The server for a connection that negotiated `alpn`: the one for that
    /// ALPN, else the default.
    fn target(&self, alpn: Option<&str>) -> Option<&Target> {
        alpn.and_then(|alpn| self.by_alpn.get(alpn))
            .or(self.default.as_ref())
    }

    /// Hands `stream`, of which `consumed` has been read, to the fallback
    /// server for the session's ALPN, and returns the error the inbound
    /// fails with: the connection is no longer its to carry. `why` is why
    /// authentication failed.
    ///
    /// The relay runs on a task of its own, outside the inbound's handshake
    /// deadline: the web server may be talked to for as long as the peer
    /// likes.
    pub fn relay(
        &self,
        sess: &Session,
        stream: AnyStream,
        consumed: Vec<u8>,
        why: &str,
    ) -> io::Error {
        let alpn = sess.tls_alpn.as_deref();
        let Some(target) = self.target(alpn) else {
            return io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{}; no fallback for ALPN {:?}", why, alpn),
            );
        };
        let server = target.server.clone();
        let port = target.port;
        let message = format!("{}; relayed to the fallback {}:{}", why, server, port);
        crate::runtime::scope::spawn(
            "fallback relay",
            relay(
                self.dialer.clone(),
                stream,
                consumed,
                server,
                port,
                self.relay.clone(),
            )
            .instrument(sess.span()),
        );
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    }
}

/// Relays `stream` to `server`:`port`, dialled with `dialer`: `consumed`
/// first, then both ways, as `relay` says, until both sides are done.
///
/// The server is dialled as sail's own sockets are, with the instance's
/// dial defaults: it is a neighbour of the server, not a destination to be
/// routed.
pub(crate) async fn relay(
    dialer: InboundDialer,
    mut stream: AnyStream,
    consumed: Vec<u8>,
    server: String,
    port: u16,
    relay: Relay,
) {
    let result = async {
        let mut remote = dialer.tcp(&server, port).await?;
        relay_to(&mut stream, &mut remote, &consumed, &relay).await
    }
    .await;
    if let Err(e) = result {
        tracing::debug!("fallback to {}:{}: {}", server, port, e);
    }
}

/// Writes `consumed` to `remote`, then relays `stream` and `remote` both
/// ways as `relay` says.
async fn relay_to<S>(
    stream: &mut AnyStream,
    remote: &mut S,
    consumed: &[u8],
    relay: &Relay,
) -> io::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    remote.write_all(consumed).await?;
    crate::net::relay::copy_with_options(stream, remote, relay).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dialer() -> InboundDialer {
        crate::net::InstanceDial::default().default_dialer()
    }

    fn server(port: u16) -> FallbackServer {
        FallbackServer {
            server: "127.0.0.1".to_string(),
            server_port: port,
        }
    }

    #[test]
    fn test_target_by_alpn() {
        let fallback = Fallback::new(
            "t",
            Some(server(1)),
            HashMap::from([("h2".to_string(), server(2))]),
            dialer(),
            Relay::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(fallback.target(Some("h2")).unwrap().port, 2);
        assert_eq!(fallback.target(Some("http/1.1")).unwrap().port, 1);
        assert_eq!(fallback.target(None).unwrap().port, 1);

        let only_alpn = Fallback::new(
            "t",
            None,
            HashMap::from([("h2".to_string(), server(2))]),
            dialer(),
            Relay::default(),
        )
        .unwrap()
        .unwrap();
        assert!(only_alpn.target(None).is_none());
        assert!(
            Fallback::new("t", None, HashMap::new(), dialer(), Relay::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_config_mistakes() {
        assert!(Fallback::new(
            "t",
            None,
            HashMap::from([(String::new(), server(2))]),
            dialer(),
            Relay::default()
        )
        .is_err());
        assert!(Fallback::new(
            "t",
            Some(server(0)),
            HashMap::new(),
            dialer(),
            Relay::default()
        )
        .is_err());
        let empty = FallbackServer {
            server: String::new(),
            server_port: 80,
        };
        assert!(
            Fallback::new("t", Some(empty), HashMap::new(), dialer(), Relay::default()).is_err()
        );
    }

    /// The fallback is dialled with the instance's dial defaults, whose
    /// host protects the socket, and gets what was read first.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_fallback_is_dialled_with_the_instance_defaults() {
        use tokio::io::AsyncReadExt;
        let (dial, protected) = crate::net::dial::recording::instance();
        let web = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback = Fallback::new(
            "t",
            Some(server(web.local_addr().unwrap().port())),
            HashMap::new(),
            dial.default_dialer(),
            Relay::default(),
        )
        .unwrap()
        .unwrap();
        let (peer, _ours) = tokio::io::duplex(64);
        let e = fallback.relay(&Session::default(), Box::new(peer), b"GET".to_vec(), "no");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        let (mut accepted, _) = web.accept().await.unwrap();
        let mut first = [0u8; 3];
        accepted.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"GET");
        assert_eq!(protected.count(), 1);
    }

    /// A site that stops taking what is written to it ends the relay after
    /// the write stall timeout, rather than holding the connection for
    /// good.
    #[tokio::test(start_paused = true)]
    async fn a_site_that_takes_nothing_ends_the_relay_after_the_write_stall_timeout() {
        let relay = Relay::default();
        let (mut client, ours) = tokio::io::duplex(64 << 10);
        let mut stream: AnyStream = Box::new(ours);
        // Room for what was read first and a little more, never read.
        let (mut site, _never_read) = tokio::io::duplex(16);
        client.write_all(&[7u8; 1024]).await.unwrap();
        let relayed = relay_to(&mut stream, &mut site, b"GET", &relay);
        tokio::pin!(relayed);
        let before = relay.write_stall_timeout - Duration::from_secs(1);
        assert!(
            tokio::time::timeout(before, &mut relayed).await.is_err(),
            "ended before the write stall timeout"
        );
        let e = tokio::time::timeout(Duration::from_secs(2), relayed)
            .await
            .expect("still relaying past the write stall timeout")
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }
}
