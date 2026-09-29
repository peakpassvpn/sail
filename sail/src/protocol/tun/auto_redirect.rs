//! `auto_redirect` (Linux): the kernel sends the system's TCP to a local
//! listener with nftables' `redirect`, and its UDP and ICMP into the TUN by
//! a mark and the policy routing; a connection's first packet can be
//! judged by the router first, through NFQUEUE, so that a bypassed one never
//! reaches sail at all.
//!
//! Set up after the TUN device exists, and undone, in the reverse order,
//! when the instance stops: see [`AutoRedirect`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use anyhow::{anyhow, Result};
use tracing::{debug, info, warn};

use super::inbound::{AutoRedirectSettings, TunSettings};
use super::prematch::{self, Marks};
use crate::app::dispatcher::Dispatcher;
use crate::app::router::rule_set::RuleSets;
use crate::platform::addr_monitor::AddressMonitor;
use crate::platform::auto_redirect::{self as ruleset, AddressSet, RulesetOptions};
use crate::platform::ip_ranges::range_prefixes;
use crate::platform::nfqueue::Queue;
use crate::platform::openwrt;
use crate::platform::original_dst::{original_destination, unmapped};
use crate::platform::policy_route::PolicyRoutes;
use crate::session::{Network, Session, SocksAddr};
use crate::Runner;

/// What auto_redirect set up; dropping it undoes it.
pub(crate) struct AutoRedirect {
    routes: PolicyRoutes,
    /// Whether the ruleset may be there, to be deleted.
    ruleset: bool,
    /// Whether fw4's drop-in was written (OpenWrt).
    fw4: bool,
    feed: RuleSetFeed,
}

/// The nftables table of the ruleset.
const TABLE: &str = "sail";

impl Drop for AutoRedirect {
    fn drop(&mut self) {
        if self.ruleset {
            if let Err(e) = ruleset::cleanup(TABLE).commit() {
                warn!("auto_redirect: removing the ruleset: {}", e);
            }
        }
        if self.fw4 {
            openwrt::cleanup();
        }
        self.routes.cleanup();
        info!("auto_redirect removed");
    }
}

/// How long an idle redirected connection goes before the kernel probes
/// it, as sing-tun's listener has it.
const KEEPALIVE: Duration = Duration::from_secs(10 * 60);

/// How long address notices are gathered before the local sets are
/// rebuilt from them.
const SETTLE: Duration = Duration::from_millis(200);

impl AutoRedirect {
    /// What a reload hands its rule-sets to.
    pub(crate) fn rule_set_feed(&self) -> RuleSetFeed {
        self.feed.clone()
    }

    /// Sets it up for the TUN inbound `tag`, and returns what serves it.
    /// What fails is undone.
    pub(crate) fn start(
        tag: &str,
        settings: &TunSettings,
        options: &AutoRedirectSettings,
        dispatcher: Arc<Dispatcher>,
        rule_sets: &RuleSets,
    ) -> Result<(AutoRedirect, Runner)> {
        let listener = listen(settings.ipv6.is_some())?;
        let port = listener.local_addr()?.port();
        // Without the queue, nothing is judged before it is redirected: the
        // ruleset leaves the pre-match out, and bypass rules are skipped.
        let queue = match Queue::open(options.nfqueue) {
            Ok(queue) => Some(queue),
            Err(e) => {
                warn!(
                    "auto_redirect: no pre-match, bypass rules will not apply: {}",
                    e
                );
                None
            }
        };
        let monitor = AddressMonitor::open()
            .map_err(|e| anyhow!("auto_redirect: watching addresses: {}", e))?;
        let address_sets = AddressSets {
            tun: tag.to_owned(),
            include: settings.route.route_address_set.clone(),
            exclude: settings.route.route_exclude_address_set.clone(),
        };
        let (include, exclude) = address_sets.load(rule_sets)?;
        let (sender, feed) = watch::channel(rule_sets.clone());
        let ruleset_options = Arc::new(ruleset_options(
            settings,
            options,
            port,
            queue.as_ref().map(Queue::num),
            include,
            exclude,
        ));
        let batch = ruleset::setup(&ruleset_options)?;

        let routes = policy_routes(settings, options);
        routes.setup()?;
        let follow_sets = AddressSets {
            tun: address_sets.tun.clone(),
            include: address_sets.include.clone(),
            exclude: address_sets.exclude.clone(),
        };
        let mut this = AutoRedirect {
            routes,
            ruleset: true,
            fw4: false,
            feed: RuleSetFeed {
                sets: Arc::new(address_sets),
                sender: Arc::new(sender),
            },
        };
        batch
            .commit()
            .map_err(|e| anyhow!("auto_redirect: nftables: {}", e))?;
        this.fw4 = openwrt::setup(&settings.name)?;
        info!("auto_redirect: TCP redirected to port {}", port);

        let tag = tag.to_owned();
        let marks = Marks {
            input: options.input_mark,
            output: options.output_mark,
            reset: options.reset_mark,
        };
        let runner = Box::pin(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(e) => {
                    warn!("auto_redirect: listener: {}", e);
                    return;
                }
            };
            let prematch = async {
                match queue {
                    Some(queue) => {
                        prematch::serve(queue, tag.clone(), dispatcher.clone(), marks).await
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::join!(
                serve(listener, tag.clone(), dispatcher.clone()),
                prematch,
                follow_addresses(monitor, ruleset_options.clone()),
                follow_sets.follow(feed, ruleset_options.clone()),
            );
        });
        Ok((this, runner))
    }
}

/// Keeps the local address sets as the interfaces' addresses change.
async fn follow_addresses(monitor: AddressMonitor, options: Arc<RulesetOptions>) {
    let mut current = options.local_prefixes.clone();
    loop {
        if let Err(e) = monitor.changed().await {
            warn!("auto_redirect: watching addresses stopped: {}", e);
            return;
        }
        // A change comes as several notices: take them all first.
        tokio::time::sleep(SETTLE).await;
        let _ = tokio::time::timeout(Duration::ZERO, monitor.changed()).await;
        let prefixes = local_prefixes();
        if prefixes == current {
            continue;
        }
        debug!("auto_redirect: local addresses now {:?}", prefixes);
        match ruleset::update_local_prefixes(&options, &prefixes).commit() {
            Ok(()) => current = prefixes,
            Err(e) => warn!("auto_redirect: updating local addresses: {}", e),
        }
    }
}

/// The rule-sets of `route_address_set` and `route_exclude_address_set`.
struct AddressSets {
    tun: String,
    include: Vec<String>,
    exclude: Vec<String>,
}

impl AddressSets {
    /// Their destinations in `rule_sets`; `None` for a list with no
    /// rule-set.
    fn load(&self, rule_sets: &RuleSets) -> Result<(Option<AddressSet>, Option<AddressSet>)> {
        let set = |field: &str, tags: &[String]| -> Result<Option<AddressSet>> {
            if tags.is_empty() {
                return Ok(None);
            }
            let mut prefixes = Vec::new();
            for tag in tags {
                let ranges = rule_sets
                    .ip_ranges(tag)
                    .map_err(|e| anyhow!("[{}] inbound: {}: {:#}", self.tun, field, e))?;
                for (first, last) in ranges {
                    prefixes.extend(range_prefixes(first, last));
                }
            }
            Ok(Some(AddressSet { prefixes }))
        };
        Ok((
            set("route_address_set", &self.include)?,
            set("route_exclude_address_set", &self.exclude)?,
        ))
    }

    fn refill(&self, rule_sets: &RuleSets, options: &RulesetOptions) {
        let (include, exclude) = match self.load(rule_sets) {
            Ok(sets) => sets,
            Err(e) => {
                warn!("auto_redirect: {:#}", e);
                return;
            }
        };
        let batch = ruleset::update_route_address_sets(options, include.as_ref(), exclude.as_ref());
        if let Err(e) = batch.commit() {
            warn!("auto_redirect: updating rule-set addresses: {}", e);
        }
    }

    /// Refills the sets whenever one of their rule-sets is replaced, and
    /// when a reload brings other rule-sets, from those.
    async fn follow(self, mut feed: watch::Receiver<RuleSets>, options: Arc<RulesetOptions>) {
        let mut first = true;
        loop {
            let rule_sets = feed.borrow_and_update().clone();
            if !first {
                self.refill(&rule_sets, &options);
            }
            first = false;
            let (changed, mut changes) = tokio::sync::mpsc::channel::<()>(1);
            let mut watchers = Vec::new();
            for tag in self.include.iter().chain(&self.exclude) {
                let Ok(mut version) = rule_sets.subscribe(tag) else {
                    continue;
                };
                let changed = changed.clone();
                watchers.push(AbortOnDrop(tokio::spawn(async move {
                    while version.changed().await.is_ok() {
                        // A refill is due already if the channel is full.
                        let _ = changed.try_send(());
                    }
                })));
            }
            drop(changed);
            loop {
                tokio::select! {
                    Some(()) = changes.recv() => self.refill(&rule_sets, &options),
                    fed = feed.changed() => {
                        if fed.is_err() {
                            // No more reloads: follow these to the end.
                            while changes.recv().await.is_some() {
                                self.refill(&rule_sets, &options);
                            }
                            std::future::pending::<()>().await;
                        }
                        break;
                    }
                }
            }
        }
    }
}

/// Hands the rule-sets of a reload to a running auto_redirect, which
/// refills its sets from them and follows them from then on.
#[derive(Clone)]
pub(crate) struct RuleSetFeed {
    sets: Arc<AddressSets>,
    sender: Arc<watch::Sender<RuleSets>>,
}

impl RuleSetFeed {
    /// Whether `rule_sets` has every rule-set the TUN names: a reload
    /// without one fails, and changes nothing.
    pub(crate) fn check(&self, rule_sets: &RuleSets) -> Result<()> {
        self.sets.load(rule_sets).map(|_| ())
    }

    pub(crate) fn publish(&self, rule_sets: RuleSets) {
        self.sender.send_replace(rule_sets);
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn ruleset_options(
    settings: &TunSettings,
    options: &AutoRedirectSettings,
    redirect_port: u16,
    nfqueue: Option<u16>,
    route_address_set: Option<AddressSet>,
    route_exclude_address_set: Option<AddressSet>,
) -> RulesetOptions {
    let prefix = |inet: &cidr::IpInet| (inet.address(), inet.network_length());
    RulesetOptions {
        table: TABLE.into(),
        tun_name: settings.name.clone(),
        ipv4: settings.ipv4.map(|i| (i.address(), i.network_length())),
        ipv6: settings.ipv6.map(|i| (i.address(), i.network_length())),
        input_mark: options.input_mark,
        output_mark: options.output_mark,
        reset_mark: options.reset_mark,
        nfqueue,
        redirect_port,
        dns_hijack: true,
        exclude_mptcp: options.exclude_mptcp,
        strict_route: settings.route.strict_route,
        loopback_address: options.loopback_address.clone(),
        route_address: settings.route.route_address.iter().map(prefix).collect(),
        route_exclude_address: settings
            .route
            .route_exclude_address
            .iter()
            .map(prefix)
            .collect(),
        route_address_set,
        route_exclude_address_set,
        include_interface: settings.route.include_interface.clone(),
        exclude_interface: settings.route.exclude_interface.clone(),
        include_uid: settings.route.include_uid.clone(),
        exclude_uid: settings.route.exclude_uid.clone(),
        local_prefixes: local_prefixes(),
    }
}

fn policy_routes(settings: &TunSettings, options: &AutoRedirectSettings) -> PolicyRoutes {
    PolicyRoutes {
        tun: settings.name.clone(),
        ipv4: settings.ipv4.is_some(),
        ipv6: settings.ipv6.is_some(),
        table: settings.route.table_index,
        rule_index: settings.route.rule_index,
        fallback_rule_index: options.fallback_rule_index,
        input_mark: options.input_mark,
        output_mark: options.output_mark,
        route_address: settings.route.route_address.clone(),
        route_exclude_address: settings.route.route_exclude_address.clone(),
    }
}

/// A TCP listener on every address and a port of the kernel's choosing:
/// `redirect` rewrites a connection's destination to an address of the
/// interface it came in on, or to loopback for the host's own. Dual stack
/// when the TUN has IPv6.
fn listen(ipv6: bool) -> Result<std::net::TcpListener> {
    let addr: SocketAddr = if ipv6 {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if ipv6 {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket
        .bind(&addr.into())
        .and_then(|()| socket.listen(1024))
        .map_err(|e| anyhow!("auto_redirect: listen on {}: {}", addr, e))?;
    Ok(socket.into())
}

/// Takes the redirected connections, each to be routed as the TUN's.
async fn serve(listener: tokio::net::TcpListener, tag: String, dispatcher: Arc<Dispatcher>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Out of descriptors, say: wait rather than spin.
                warn!("auto_redirect: accept: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let sess = match session(&stream, peer, &tag) {
            Ok(sess) => sess,
            Err(e) => {
                // Reached directly, not redirected: reset it.
                debug!("auto_redirect: {} from {}", e, peer);
                let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                continue;
            }
        };
        let dispatcher = dispatcher.clone();
        tokio::spawn(async move { dispatcher.dispatch_stream(sess, stream).await });
    }
}

fn session(
    stream: &tokio::net::TcpStream,
    peer: SocketAddr,
    tag: &str,
) -> std::io::Result<Session> {
    let socket = socket2::SockRef::from(stream);
    let destination = original_destination(&socket, peer)?;
    let keepalive = socket2::TcpKeepalive::new().with_time(KEEPALIVE);
    if let Err(e) = socket.set_tcp_keepalive(&keepalive) {
        debug!("auto_redirect: keepalive: {}", e);
    }
    Ok(Session {
        network: Network::Tcp,
        source: unmapped(peer),
        local_addr: unmapped(stream.local_addr()?),
        destination: SocksAddr::Ip(destination),
        inbound_tag: tag.to_owned(),
        ..Default::default()
    })
}

/// The prefixes of the host's interfaces the ruleset leaves alone as
/// local: all of `lo`'s, and the others' global unicast ones (private
/// ranges included, as Go's `IsGlobalUnicast` has it), each masked to its
/// subnet.
fn local_prefixes() -> Vec<(IpAddr, u8)> {
    let mut prefixes: Vec<(IpAddr, u8)> = pnet_datalink::interfaces()
        .iter()
        .flat_map(|iface| {
            iface
                .ips
                .iter()
                .filter(move |net| iface.name == "lo" || is_global_unicast(net.ip()))
                .map(|net| (net.network(), net.prefix()))
        })
        .collect();
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unicast_link_local())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_unicast_as_go_has_it() {
        for (ip, global) in [
            ("192.168.1.10", true),
            ("8.8.8.8", true),
            ("127.0.0.1", false),
            ("169.254.1.1", false),
            ("224.0.0.1", false),
            ("fd00::1", true),
            ("fe80::1", false),
            ("::1", false),
        ] {
            assert_eq!(is_global_unicast(ip.parse().unwrap()), global, "{}", ip);
        }
    }
}
