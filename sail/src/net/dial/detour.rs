//! A dialer with a `detour`: no socket of its own, but the TCP and UDP of
//! another outbound, as sing-box's `DetourDialer` has them. What it is
//! asked to reach is handed to that outbound as a destination, never
//! routed.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, Weak};

use arc_swap::ArcSwap;

use super::ResolveSpec;
use crate::adapter::{AnyOutboundDatagram, AnyOutboundHandler, AnyStream};
use crate::app::outbound::manager::OutboundManager;
use crate::app::SyncDnsClient;
use crate::session::{Network, Session, SocksAddr};

/// The outbounds of the running instance, found by tag: what the detour
/// of a DNS server or an HTTP client reaches, for those are built before
/// the outbounds are. Set once the outbounds are built; a reload keeps
/// the instance's, which it swaps.
#[derive(Clone, Default)]
pub struct Outbounds(Arc<OnceLock<Weak<ArcSwap<OutboundManager>>>>);

impl Outbounds {
    /// Finds them in `manager` from now on.
    pub fn set(&self, manager: &Arc<ArcSwap<OutboundManager>>) {
        let _ = self.0.set(Arc::downgrade(manager));
    }

    fn get(&self, tag: &str) -> io::Result<AnyOutboundHandler> {
        let manager = self
            .0
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| io::Error::other(format!("detour [{}]: no outbounds run", tag)))?;
        let handler = manager.load().get(tag);
        handler.ok_or_else(|| io::Error::other(format!("detour [{}]: no such outbound", tag)))
    }
}

impl std::fmt::Debug for Outbounds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Outbounds")
    }
}

/// Which outbound a detour goes through.
#[derive(Clone)]
pub(super) enum Target {
    /// Built already: an outbound's detour, which it is built after.
    Handler(AnyOutboundHandler),
    /// Looked up when it dials.
    Lookup(Outbounds),
}

pub(super) struct DetourDialer {
    /// The outbound it goes through, by tag.
    pub tag: String,
    pub target: Target,
    /// How a name resolves when it resolves here: set only when its own
    /// fields name a `domain_resolver`, as in sing-box; else a name goes
    /// to the detour as it is, and resolves at the far end.
    pub resolve: ResolveSpec,
    pub resolves_here: bool,
    /// What the sessions it makes up come in as, when the caller has none
    /// to give: the outbound that dials, or the DNS client.
    pub owner: String,
}

impl std::fmt::Debug for DetourDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetourDialer")
            .field("tag", &self.tag)
            .field("resolve", &self.resolve)
            .field("resolves_here", &self.resolves_here)
            .finish()
    }
}

type Boxed<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

impl DetourDialer {
    fn handler(&self) -> io::Result<AnyOutboundHandler> {
        match &self.target {
            Target::Handler(handler) => Ok(handler.clone()),
            Target::Lookup(outbounds) => outbounds.get(&self.tag),
        }
    }

    /// The session the detour carries a connection to `to` in: the
    /// caller's, going somewhere else, or one of its own.
    fn session(&self, sess: Option<&Session>, network: Network, to: SocksAddr) -> Session {
        let mut sess = match sess {
            Some(sess) => sess.clone(),
            None => Session {
                inbound_tag: self.owner.clone(),
                outbound_tag: self.tag.clone(),
                ..Default::default()
            },
        };
        sess.network = network;
        sess.destination = to;
        // What was sniffed is of the destination just replaced.
        sess.forget_sniffed();
        sess
    }

    /// Where `to` is reached: the addresses its name resolves to here,
    /// when it resolves here, else `to` itself.
    pub async fn targets(&self, dns: &SyncDnsClient, to: &SocksAddr) -> io::Result<Vec<SocksAddr>> {
        let SocksAddr::Domain(host, port) = to else {
            return Ok(vec![to.clone()]);
        };
        if !self.resolves_here {
            return Ok(vec![to.clone()]);
        }
        let ips = dns
            .load_full()
            .lookup_dial(host, &self.resolve)
            .await
            .map_err(|e| io::Error::other(format!("lookup {} failed: {}", host, e)))?;
        if ips.is_empty() {
            return Err(io::Error::other(format!("{} resolves to nothing", host)));
        }
        Ok(ips
            .into_iter()
            .map(|ip| SocksAddr::from(SocketAddr::new(ip, *port)))
            .collect())
    }

    /// A stream to `to` through the detour, trying the addresses of a name
    /// resolved here one by one.
    pub fn stream<'a>(
        &'a self,
        dns: &'a SyncDnsClient,
        sess: Option<&'a Session>,
        to: &'a SocksAddr,
    ) -> Boxed<'a, AnyStream> {
        Box::pin(async move {
            let handler = self.handler()?;
            let mut last = None;
            for to in self.targets(dns, to).await? {
                let sess = self.session(sess, Network::Tcp, to);
                let dialled = async {
                    let stream =
                        crate::net::connect_stream_outbound(&sess, dns.clone(), &handler).await?;
                    handler.stream()?.handle(&sess, None, stream).await
                };
                match dialled.await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last = Some(e),
                }
            }
            Err(through(&self.tag, last.unwrap_or_else(nothing)))
        })
    }

    /// Datagrams to `to` through the detour; a name resolved here goes as
    /// its first address.
    pub fn datagram<'a>(
        &'a self,
        dns: &'a SyncDnsClient,
        sess: Option<&'a Session>,
        to: &'a SocksAddr,
    ) -> Boxed<'a, AnyOutboundDatagram> {
        Box::pin(async move {
            let handler = self.handler()?;
            let to = self
                .targets(dns, to)
                .await?
                .into_iter()
                .next()
                .ok_or_else(nothing)?;
            let sess = self.session(sess, Network::Udp, to);
            let dialled = async {
                let transport =
                    crate::net::connect_datagram_outbound(&sess, dns.clone(), &handler).await?;
                handler.datagram()?.handle(&sess, transport).await
            };
            dialled.await.map_err(|e| through(&self.tag, e))
        })
    }
}

fn nothing() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "nowhere to dial")
}

fn through(tag: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("through [{}]: {}", tag, e))
}

#[cfg(test)]
mod tests {
    fn config(json: serde_json::Value) -> anyhow::Result<crate::config::Config> {
        crate::config::from_string(&json.to_string())
    }

    // Its tests need a socks outbound.
    #[cfg_attr(not(feature = "outbound-socks"), allow(dead_code))]
    fn built(json: serde_json::Value) -> Result<(), String> {
        config(json)
            .and_then(|c| crate::check_config(&c, &Default::default()))
            .map_err(|e| format!("{:#}", e))
    }

    // Its tests need a socks outbound.
    #[cfg_attr(not(feature = "outbound-socks"), allow(dead_code))]
    fn fails(json: serde_json::Value, wanted: &str) {
        let err = built(json).expect_err(wanted);
        assert!(err.contains(wanted), "{}", err);
    }

    #[cfg(feature = "outbound-socks")]
    #[test]
    fn detours_that_go_round_are_refused_with_the_way_round() {
        fails(
            serde_json::json!({ "outbounds": [
                { "type": "socks", "tag": "a", "server": "127.0.0.1", "server_port": 1,
                  "detour": "b" },
                { "type": "socks", "tag": "b", "server": "127.0.0.1", "server_port": 2,
                  "detour": "a" },
            ] }),
            "outbound [a] -> outbound [b] -> outbound [a]",
        );
        fails(
            serde_json::json!({ "outbounds": [
                { "type": "socks", "tag": "a", "server": "127.0.0.1", "server_port": 1,
                  "detour": "a" },
            ] }),
            "outbound [a] -> outbound [a]",
        );
    }

    #[cfg(all(feature = "outbound-socks", feature = "outbound-direct"))]
    #[test]
    fn a_detour_to_a_direct_of_nothing_is_refused() {
        let direct = serde_json::json!({ "type": "direct", "tag": "d" });
        let proxy = serde_json::json!({ "type": "socks", "tag": "p", "server": "127.0.0.1",
            "server_port": 1, "detour": "d" });
        fails(
            serde_json::json!({ "outbounds": [proxy, direct] }),
            "[p] outbound: detour: [d] is a direct outbound of no fields of its own",
        );
        fails(
            serde_json::json!({ "outbounds": [direct],
                "dns": { "servers": [{ "type": "udp", "tag": "u", "server": "127.0.0.1",
                    "detour": "d" }] } }),
            "dns.servers[u]: detour: [d] is a direct outbound",
        );
        fails(
            serde_json::json!({ "outbounds": [direct],
                "http_clients": [{ "tag": "h", "detour": "d" }] }),
            "http_clients[0]: detour: [d] is a direct outbound",
        );
        // A direct of fields of its own dials otherwise, and may be one.
        built(serde_json::json!({ "outbounds": [
            proxy,
            { "type": "direct", "tag": "d", "connect_timeout": "3s" },
        ] }))
        .unwrap();
    }

    #[cfg(feature = "outbound-socks")]
    #[test]
    fn a_detour_takes_no_fields_of_the_socket_it_replaces() {
        fails(
            serde_json::json!({ "outbounds": [
                { "type": "socks", "tag": "p", "server": "127.0.0.1", "server_port": 1,
                  "detour": "q", "connect_timeout": "3s" },
                { "type": "socks", "tag": "q", "server": "127.0.0.1", "server_port": 2 },
            ] }),
            "[p] outbound: connect_timeout: has no effect with a detour; set it on [q]",
        );
        // domain_resolver is not of the socket: it resolves here first.
        built(serde_json::json!({ "outbounds": [
            { "type": "socks", "tag": "p", "server": "example.com", "server_port": 1,
              "detour": "q", "domain_resolver": "local" },
            { "type": "socks", "tag": "q", "server": "127.0.0.1", "server_port": 2 },
        ] }))
        .unwrap();
    }

    #[cfg(all(feature = "outbound-hysteria2", feature = "outbound-socks"))]
    #[test]
    fn hysteria2_takes_a_detour() {
        built(serde_json::json!({ "outbounds": [
            { "type": "hysteria2", "tag": "p", "server": "example.com", "server_port": 1,
              "password": "pw", "detour": "q", "tls": { "enabled": true } },
            { "type": "socks", "tag": "q", "server": "127.0.0.1", "server_port": 2 },
        ] }))
        .unwrap();
    }

    #[cfg(all(feature = "inbound-vless", feature = "inbound-reality"))]
    #[test]
    fn a_handshake_resolves_with_a_dns_server_that_exists() {
        let err = config(serde_json::json!({ "inbounds": [{
            "type": "vless", "tag": "r", "listen_port": 1,
            "users": [{ "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b" }],
            "tls": { "enabled": true, "server_name": "example.com", "reality": {
                "enabled": true, "short_id": "0123",
                "private_key": "11".repeat(32),
                "handshake": { "server": "example.com", "server_port": 443,
                    "domain_resolver": "nowhere" } } },
        }] }))
        .map(|_| ())
        .expect_err("no such server");
        assert!(
            format!("{:#}", err).contains(
                "[r] inbound: tls.reality.handshake.domain_resolver: \
                 dns server [nowhere] does not exist"
            ),
            "{:#}",
            err
        );
        let err = config(serde_json::json!({ "inbounds": [{
            "type": "shadowtls", "tag": "s", "listen_port": 1,
            "handshake_for_server_name": { "a.example": { "server": "a.example",
                "server_port": 443, "domain_resolver": { "server": "nowhere" } } },
        }] }))
        .map(|_| ())
        .expect_err("no such server");
        assert!(
            format!("{:#}", err).contains(
                "[s] inbound: handshake_for_server_name.a.example.domain_resolver: \
                 dns server [nowhere] does not exist"
            ),
            "{:#}",
            err
        );
    }

    #[tokio::test]
    async fn a_detour_looked_up_before_the_outbounds_run_fails_to_dial() {
        let fields: super::super::DialFields =
            serde_json::from_value(serde_json::json!({ "detour": "later" })).unwrap();
        let dialer = crate::net::DialDefaults::default()
            .dialer(&fields, None)
            .unwrap();
        assert_eq!(dialer.detour(), Some("later"));
        let dns = crate::net::InstanceDial::default().dns;
        let to = crate::session::SocksAddr::Domain("example.com".into(), 80);
        let err = match dialer.stream(&dns, None, &to).await {
            Ok(_) => panic!("dialled"),
            Err(e) => e.to_string(),
        };
        assert_eq!(err, "detour [later]: no outbounds run");
        // It has no socket of its own either.
        assert!(dialer.tcp_to("127.0.0.1:1".parse().unwrap()).await.is_err());
    }
}
