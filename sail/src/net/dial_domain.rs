//! `override_destination`: a connection to an address is dialled by the
//! name known for it, where its last hop dials a proxy's server (and a
//! direct dial too, with `proxy_and_direct`), so that the proxy resolves
//! the name itself. The rules have matched the address by then.
//!
//! The name is the sniffed domain, a real one the client sent, else the one
//! sail's DNS answered with for the address (`dns.reverse_mapping`), within
//! its TTL. Each dial takes it as its outbound is: a group hands the
//! connection to a member, which takes it then.

use std::borrow::Cow;
use std::io;

use tracing::debug;

use crate::adapter::{AnyOutboundDatagram, AnyOutboundHandler, AnyStream, OutboundConnect};
use crate::app::SyncDnsClient;
use crate::config::model::OverrideDestination;
use crate::session::{DialDomain, DialDomainSource, Dialled, Session, SniffedFrom, SocksAddr};

/// Whether a sniffed `domain` is a name to dial: neither empty nor an
/// address, as an HTTP Host may be.
pub(crate) fn usable(domain: &str) -> bool {
    let bare = domain.trim_start_matches('[').trim_end_matches(']');
    !bare.is_empty()
        && bare.parse::<std::net::IpAddr>().is_err()
        && SocksAddr::try_from((bare, 0)).is_ok_and(|a| a.is_domain())
}

/// The name `sess`, routed, is dialled as, where its `override_destination`
/// asks for one and its destination is an address: the sniffed domain, if
/// a usable one, else the one `reverse_map` keeps for the address, unmapped
/// from IPv4-mapped IPv6, if its TTL has not run out.
pub(crate) async fn find(
    sess: &Session,
    reverse_map: Option<&crate::sniff::dns::DnsSniffer>,
) -> Option<DialDomain> {
    let how = sess.route.override_destination?;
    let ip = sess.destination.ip()?;
    let sniffed = [SniffedFrom::Tls, SniffedFrom::Http]
        .into_iter()
        .filter_map(|from| sess.sniffed_domain_from(from))
        .find(|domain| usable(domain));
    let (domain, source) = match sniffed {
        Some(domain) => (domain.to_string(), DialDomainSource::Sniff),
        None => {
            let domain = reverse_map?.get(&ip.to_canonical()).await?;
            (domain, DialDomainSource::ReverseMapping)
        }
    };
    Some(DialDomain {
        address: sess.destination.clone(),
        domain,
        source,
        direct: how == OverrideDestination::ProxyAndDirect,
    })
}

/// How a source is told in the logs.
fn told(source: DialDomainSource) -> &'static str {
    match source {
        DialDomainSource::Sniff => "sniff",
        DialDomainSource::ReverseMapping => "reverse mapping",
    }
}

/// `sess` as `handler`, asking for `connect`, is to be handed it: to the
/// name its route found where the handler is the last hop and dials a
/// proxy's server, or dials directly with `proxy_and_direct`; to the
/// address where it dials directly otherwise, a group having handed it the
/// name. A group, which hands the connection to a member, takes it as it
/// is; so does a session to anywhere else, a chain's earlier hop or an
/// address a resolve rule handed on.
pub(crate) fn session<'a>(
    sess: &'a Session,
    handler: &AnyOutboundHandler,
    connect: &OutboundConnect,
) -> Cow<'a, Session> {
    let Some(dial) = &sess.route.dial_domain else {
        return Cow::Borrowed(sess);
    };
    if handler.is_group() {
        return Cow::Borrowed(sess);
    }
    let port = dial.address.port();
    let named = SocksAddr::Domain(dial.domain.clone(), port);
    if sess.destination != dial.address && sess.destination != named {
        return Cow::Borrowed(sess);
    }
    let direct = matches!(connect, OutboundConnect::Direct(dialer) if dialer.detour().is_none());
    let to = if direct && !dial.direct {
        dial.address.clone()
    } else {
        named
    };
    if to == sess.destination {
        return Cow::Borrowed(sess);
    }
    if to.is_domain() {
        debug!(
            "dial {} as {} ({})",
            dial.address,
            dial.domain,
            told(dial.source)
        );
    }
    Cow::Owned(Session {
        destination: to,
        ..sess.clone()
    })
}

/// Notes a dial of `at`, as [`session`] gave it, that connected: the
/// connections list shows the name it was dialled as.
pub(crate) fn connected(at: &Session) {
    if let Some(dial) = &at.route.dial_domain {
        if at.destination.domain() == Some(&dial.domain) {
            at.state.get::<Dialled>().set(&dial.domain, dial.source);
        }
    }
}

/// Logs a dial of `at`, as [`session`] gave it, that failed by a name the
/// reverse mapping gave, which may be stale; it is not tried again by the
/// address, as sing-box dials a connection one way.
pub(crate) fn failed(at: &Session, e: &io::Error) {
    if let Some(dial) = &at.route.dial_domain {
        if dial.source == DialDomainSource::ReverseMapping
            && at.destination.domain() == Some(&dial.domain)
        {
            debug!(
                "dial {} for {} ({}) failed: {}",
                dial.domain,
                dial.address,
                told(dial.source),
                e
            );
        }
    }
}

/// The datagrams `handler` opened for `at`, as [`session`] gave it from
/// `given`: those the client sends to the destination it was given go
/// where `at` goes, and the answers from there come back from it, unless
/// `udp_disable_domain_unmapping` keeps them from the name dialled.
pub(crate) fn datagram(
    d: AnyOutboundDatagram,
    given: &Session,
    at: &Session,
) -> AnyOutboundDatagram {
    if at.destination == given.destination {
        return d;
    }
    let keep = at.destination.is_domain() && at.route.udp_disable_domain_unmapping;
    Box::new(
        crate::sniff::OverriddenDatagram::new(d, given.destination.clone(), at.destination.clone())
            .without_unmapping(keep),
    )
}

/// What a dial of `at`, as [`session`] gave it, came to, noted.
pub(crate) fn stream_done(at: &Session, result: io::Result<AnyStream>) -> io::Result<AnyStream> {
    match &result {
        Ok(_) => connected(at),
        Err(e) => failed(at, e),
    }
    result
}

/// What datagrams opened for `at`, as [`session`] gave it from `given`,
/// came to, noted, and mapped as [`datagram`] says.
pub(crate) fn datagram_done(
    given: &Session,
    at: &Session,
    result: io::Result<AnyOutboundDatagram>,
) -> io::Result<AnyOutboundDatagram> {
    match result {
        Ok(d) => {
            connected(at);
            Ok(datagram(d, given, at))
        }
        Err(e) => {
            failed(at, &e);
            Err(e)
        }
    }
}

/// A stream through `handler`, a group's member, to `sess`'s destination,
/// or the name it is dialled as.
pub async fn stream(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<AnyStream> {
    let th = handler.stream()?;
    let at = session(sess, handler, &th.connect_addr());
    let result = async {
        let stream = super::connect_stream_outbound(&at, dns_client, handler).await?;
        th.handle(&at, None, stream).await
    }
    .await;
    stream_done(&at, result)
}

/// Datagrams through `handler`, a group's member, to `sess`'s
/// destination, or the name it is dialled as.
pub async fn datagram_through(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<AnyOutboundDatagram> {
    let dh = handler.datagram()?;
    let at = session(sess, handler, &dh.connect_addr());
    let result = async {
        let transport = super::connect_datagram_outbound(&at, dns_client, handler).await?;
        dh.handle(&at, transport).await
    }
    .await;
    datagram_done(sess, &at, result)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::adapter::outbound::HandlerBuilder;
    use crate::net::DialDefaults;
    use crate::session::{Network, RouteOptions};
    use crate::sniff::dns::DnsSniffer;

    const V6: &str = "[2001:db8::50]:443";

    fn addr(s: &str) -> SocksAddr {
        s.parse::<std::net::SocketAddr>()
            .map(SocksAddr::from)
            .unwrap_or_else(|_| {
                let (host, port) = s.rsplit_once(':').unwrap();
                SocksAddr::try_from((host, port.parse().unwrap())).unwrap()
            })
    }

    fn to(destination: &str, how: Option<OverrideDestination>) -> Session {
        Session {
            destination: addr(destination),
            route: RouteOptions {
                override_destination: how,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn name(dial: Option<DialDomain>) -> Option<(String, DialDomainSource)> {
        dial.map(|d| (d.domain, d.source))
    }

    async fn map(entries: &[(&str, &str)]) -> DnsSniffer {
        let map = DnsSniffer::new();
        for (ip, domain) in entries {
            map.add_for(
                ip.parse().unwrap(),
                domain.to_string(),
                Duration::from_secs(60),
            )
            .await;
        }
        map
    }

    #[test]
    fn an_address_is_no_name() {
        assert!(usable("a.test"));
        for no in ["", "1.2.3.4", "2001:db8::1", "[2001:db8::1]"] {
            assert!(!usable(no), "{}", no);
        }
    }

    /// The sniffed name first; else the reverse mapping, also where the
    /// sniff found only an address; nothing without the option.
    #[tokio::test]
    async fn the_name_is_the_sniffed_one_else_the_mapped_one() {
        let map = map(&[("2001:db8::50", "dual.test")]).await;
        let how = Some(OverrideDestination::Proxy);
        let mut sess = to(V6, how);
        assert_eq!(
            name(find(&sess, Some(&map)).await),
            Some(("dual.test".into(), DialDomainSource::ReverseMapping))
        );
        // Without the reverse mapping on, there is none.
        assert_eq!(name(find(&sess, None).await), None);
        sess.set_sniffed_domain(SniffedFrom::Http, "2001:db8::50".into());
        assert_eq!(
            name(find(&sess, Some(&map)).await),
            Some(("dual.test".into(), DialDomainSource::ReverseMapping))
        );
        sess.set_sniffed_domain(SniffedFrom::Tls, "sni.test".into());
        assert_eq!(
            name(find(&sess, Some(&map)).await),
            Some(("sni.test".into(), DialDomainSource::Sniff))
        );
        // Nothing asked for, or a destination that is a name already.
        assert_eq!(name(find(&to(V6, None), Some(&map)).await), None);
        assert_eq!(name(find(&to("a.test:443", how), Some(&map)).await), None);
        let dial = find(
            &to(V6, Some(OverrideDestination::ProxyAndDirect)),
            Some(&map),
        )
        .await
        .unwrap();
        assert!(dial.direct);
        assert_eq!(dial.address, to(V6, None).destination);
    }

    /// An IPv4-mapped IPv6 destination is looked up as the IPv4 address.
    #[tokio::test]
    async fn a_mapped_address_is_looked_up_unmapped() {
        let map = map(&[("192.0.2.7", "v4.test")]).await;
        let sess = to("[::ffff:192.0.2.7]:80", Some(OverrideDestination::Proxy));
        assert_eq!(
            name(find(&sess, Some(&map)).await),
            Some(("v4.test".into(), DialDomainSource::ReverseMapping))
        );
    }

    /// A mapping is not used once the TTL of its answer has run out.
    #[tokio::test(start_paused = true)]
    async fn a_mapping_past_its_ttl_is_not_used() {
        let map = DnsSniffer::new();
        map.add_for(
            "2001:db8::50".parse().unwrap(),
            "dual.test".into(),
            Duration::from_secs(10),
        )
        .await;
        let sess = to(V6, Some(OverrideDestination::Proxy));
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(find(&sess, Some(&map)).await.is_some());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(find(&sess, Some(&map)).await.is_none());
    }

    fn dialled(how: OverrideDestination) -> Session {
        let mut sess = to(V6, Some(how));
        sess.route.dial_domain = Some(DialDomain {
            address: sess.destination.clone(),
            domain: "dual.test".into(),
            source: DialDomainSource::Sniff,
            direct: how == OverrideDestination::ProxyAndDirect,
        });
        sess
    }

    /// A proxy's server is told the name; a direct dial keeps the address,
    /// unless `proxy_and_direct`; a group takes the session as it is, and
    /// a direct member it hands the name to dials the address again.
    #[test]
    fn each_hop_is_handed_the_name_as_it_dials() {
        let dialer = DialDefaults::default()
            .dialer(&Default::default(), None)
            .unwrap();
        let proxy = OutboundConnect::Proxy(Network::Tcp, "192.0.2.1".into(), 1080, dialer.clone());
        let direct = OutboundConnect::Direct(dialer);
        let leaf = HandlerBuilder::default().build();
        let group = HandlerBuilder::default().is_group(true).build();
        let named = SocksAddr::Domain("dual.test".into(), 443);
        let address = to(V6, None).destination;

        let sess = dialled(OverrideDestination::Proxy);
        assert_eq!(session(&sess, &leaf, &proxy).destination, named);
        assert_eq!(session(&sess, &leaf, &direct).destination, address);
        assert_eq!(
            session(&sess, &group, &OutboundConnect::Unknown).destination,
            address
        );
        // Self-dialing proxies ask for nothing.
        assert_eq!(
            session(&sess, &leaf, &OutboundConnect::Unknown).destination,
            named
        );
        let handed = session(&sess, &leaf, &proxy).into_owned();
        assert_eq!(session(&handed, &leaf, &direct).destination, address);
        // Anywhere else, as a chain's earlier hop, is left alone.
        let elsewhere = Session {
            destination: addr("192.0.2.9:443"),
            ..sess.clone()
        };
        assert!(matches!(
            session(&elsewhere, &leaf, &proxy),
            Cow::Borrowed(_)
        ));

        let sess = dialled(OverrideDestination::ProxyAndDirect);
        assert_eq!(session(&sess, &leaf, &direct).destination, named);
        assert_eq!(session(&sess, &leaf, &proxy).destination, named);
    }

    /// Datagrams sent to whatever answers from `from`, recording where
    /// each was sent.
    struct Echo {
        sent: std::sync::Arc<std::sync::Mutex<Vec<SocksAddr>>>,
        from: SocksAddr,
    }

    struct EchoRecv(SocksAddr);
    struct EchoSend(std::sync::Arc<std::sync::Mutex<Vec<SocksAddr>>>);

    #[async_trait::async_trait]
    impl crate::adapter::OutboundDatagramRecvHalf for EchoRecv {
        async fn recv_from(&mut self, _buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
            Ok((1, self.0.clone()))
        }
    }

    #[async_trait::async_trait]
    impl crate::adapter::OutboundDatagramSendHalf for EchoSend {
        async fn send_to(&mut self, buf: &[u8], to: &SocksAddr) -> io::Result<usize> {
            self.0.lock().unwrap().push(to.clone());
            Ok(buf.len())
        }

        async fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl crate::adapter::OutboundDatagram for Echo {
        fn split(
            self: Box<Self>,
        ) -> (
            Box<dyn crate::adapter::OutboundDatagramRecvHalf>,
            Box<dyn crate::adapter::OutboundDatagramSendHalf>,
        ) {
            (Box::new(EchoRecv(self.from)), Box::new(EchoSend(self.sent)))
        }
    }

    /// Where datagrams through what [`datagram`] makes of `given` and `at`
    /// go, and where the answer from `from` seems to come from.
    async fn through(given: &Session, at: &Session, from: &SocksAddr) -> (SocksAddr, SocksAddr) {
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let echo = Box::new(Echo {
            sent: sent.clone(),
            from: from.clone(),
        });
        let (mut recv, mut send) = datagram(echo, given, at).split();
        send.send_to(b"x", &given.destination).await.unwrap();
        let (_, answered) = recv.recv_from(&mut [0u8; 4]).await.unwrap();
        let to = sent.lock().unwrap()[0].clone();
        (to, answered)
    }

    /// A group's member dialled by the name: datagrams to the address go
    /// to the name, and its answers come from the address, or, with
    /// `udp_disable_domain_unmapping`, from the name; a direct member a
    /// group handed the name to sends to the address, answering as the
    /// name, for the group's caller to map.
    #[tokio::test]
    async fn datagrams_to_the_name_answer_as_the_option_says() {
        let named = SocksAddr::Domain("dual.test".into(), 443);
        let address = to(V6, None).destination;
        for disabled in [false, true] {
            let mut given = dialled(OverrideDestination::Proxy);
            given.route.udp_disable_domain_unmapping = disabled;
            let at = Session {
                destination: named.clone(),
                ..given.clone()
            };
            let expected = if disabled { &named } else { &address };
            assert_eq!(
                through(&given, &at, &named).await,
                (named.clone(), expected.clone()),
                "disabled {}",
                disabled
            );
            let (given, at) = (at, given);
            assert_eq!(
                through(&given, &at, &address).await,
                (address.clone(), named.clone()),
                "disabled {}",
                disabled
            );
        }
    }
}
