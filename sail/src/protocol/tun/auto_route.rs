//! `auto_route` without auto_redirect, as sing-tun does it, never touching
//! the system's own routes: what the kernel drops with the device is all
//! that points at it.
//!
//! - Linux: the TUN's routes in a table of their own, and ip rules that
//!   send into it what is to go into the TUN; the rules left by a run that
//!   died are removed by the next start. DNS goes to the address after the
//!   TUN's, through systemd-resolved where there is one and sail runs in
//!   the namespace it serves, the host's.
//! - macOS: routes through the utun more specific than the default route
//!   (1/8, 2/7 ... 128/1), which win without replacing it.
//! - Windows: 0/0 and ::/0 through wintun at metric 0, which win over the
//!   default route by metric without replacing it; the adapter's DNS goes
//!   to the address after the TUN's, and strict_route adds firewall rules
//!   that keep DNS off every other interface.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use tokio::sync::watch;
use tracing::{info, warn};

use super::inbound::TunSettings;
use crate::app::router::rule_set::RuleSets;
use crate::platform::auto_route as plan;
use crate::Runner;

/// What auto_route set up; dropping it undoes it.
pub(crate) struct AutoRoute {
    backend: Arc<backend::Backend>,
    /// The routes added, removed on stop.
    routes: Arc<Mutex<Vec<(IpAddr, u8)>>>,
    feed: RouteSetFeed,
}

impl Drop for AutoRoute {
    fn drop(&mut self) {
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        for &prefix in routes.iter() {
            let _ = self.backend.delete(prefix);
        }
        self.backend.stop();
        info!("auto_route removed");
    }
}

impl AutoRoute {
    /// Sets it up for the TUN `settings` describe, once the device exists.
    /// What fails is undone.
    pub(crate) fn start(
        tag: &str,
        settings: &TunSettings,
        rule_sets: &RuleSets,
    ) -> Result<(AutoRoute, Runner)> {
        let selection = &settings.route;
        let prefix = |inet: &cidr::IpInet| (inet.address(), inet.network_length());
        let sets = RouteSets {
            tun: tag.to_owned(),
            include: selection.route_address_set.clone(),
            exclude: selection.route_exclude_address_set.clone(),
            fixed_include: selection.route_address.iter().map(prefix).collect(),
            fixed_exclude: selection.route_exclude_address.iter().map(prefix).collect(),
            own: settings
                .ipv4
                .map(|i| (IpAddr::from(i.address()), i.network_length()))
                .into_iter()
                .chain(
                    settings
                        .ipv6
                        .map(|i| (IpAddr::from(i.address()), i.network_length())),
                )
                .collect(),
        };
        let prefixes = sets.prefixes(rule_sets)?;
        let backend = Arc::new(backend::Backend::start(settings)?);
        let routes = Arc::new(Mutex::new(Vec::new()));
        let (sender, feed) = watch::channel(rule_sets.clone());
        // From here, dropping it undoes what was done.
        let this = AutoRoute {
            backend: backend.clone(),
            routes: routes.clone(),
            feed: RouteSetFeed {
                sets: Arc::new(sets.clone()),
                sender: Arc::new(sender),
            },
        };
        for &prefix in &prefixes {
            backend
                .add(prefix)
                .map_err(|e| anyhow!("auto_route: route {}/{}: {}", prefix.0, prefix.1, e))?;
            routes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(prefix);
        }
        backend.routed()?;
        info!(
            "auto_route: {} routes into {}",
            prefixes.len(),
            settings.name
        );
        let runner = Box::pin(sets.follow(feed, routes, backend));
        Ok((this, runner))
    }

    /// What a reload hands its rule-sets to.
    pub(crate) fn rule_set_feed(&self) -> RouteSetFeed {
        self.feed.clone()
    }
}

/// The prefixes routed into the TUN: `route_address` and the rule-sets
/// of `route_address_set`, less `route_exclude_address` and those of
/// `route_exclude_address_set`.
#[derive(Clone)]
struct RouteSets {
    tun: String,
    include: Vec<String>,
    exclude: Vec<String>,
    fixed_include: Vec<(IpAddr, u8)>,
    fixed_exclude: Vec<(IpAddr, u8)>,
    /// The TUN's own addresses with their prefix lengths.
    own: Vec<(IpAddr, u8)>,
}

impl RouteSets {
    fn prefixes(&self, rule_sets: &RuleSets) -> Result<Vec<(IpAddr, u8)>> {
        let from_sets = |field: &str, tags: &[String]| -> Result<Vec<(IpAddr, u8)>> {
            let mut prefixes = Vec::new();
            for tag in tags {
                let ranges = rule_sets
                    .ip_ranges(tag)
                    .map_err(|e| anyhow!("[{}] inbound: {}: {:#}", self.tun, field, e))?;
                for (first, last) in ranges {
                    prefixes.extend(crate::platform::ip_ranges::range_prefixes(first, last));
                }
            }
            Ok(prefixes)
        };
        let mut include = self.fixed_include.clone();
        include.extend(from_sets("route_address_set", &self.include)?);
        let mut exclude = self.fixed_exclude.clone();
        exclude.extend(from_sets("route_exclude_address_set", &self.exclude)?);
        let mut prefixes = Vec::new();
        for &(address, len) in &self.own {
            let v6 = address.is_ipv6();
            let mut include: Vec<_> = include
                .iter()
                .filter(|p| p.0.is_ipv6() == v6)
                .copied()
                .collect();
            // macOS's utun is point-to-point: its own network needs a route
            // of its own when not all addresses are routed.
            if backend::ROUTES_OWN_NETWORK && !include.is_empty() && len < full(v6) {
                include.push((address, len));
            }
            prefixes.extend(plan::routes(v6, &include, &exclude, &backend::all(v6)));
        }
        Ok(prefixes)
    }

    /// Replaces the routes when a rule-set they come from is replaced, and
    /// when a reload brings other rule-sets. sing-box routes a rule-set as
    /// it was at the start; sail follows it.
    async fn follow(
        self,
        mut feed: watch::Receiver<RuleSets>,
        routes: Arc<Mutex<Vec<(IpAddr, u8)>>>,
        backend: Arc<backend::Backend>,
    ) {
        if self.include.is_empty() && self.exclude.is_empty() {
            return std::future::pending().await;
        }
        let refill = |rule_sets: &RuleSets| {
            let wanted = match self.prefixes(rule_sets) {
                Ok(prefixes) => prefixes,
                Err(e) => {
                    warn!("auto_route: {:#}", e);
                    return;
                }
            };
            let mut routes = routes.lock().unwrap_or_else(|e| e.into_inner());
            // Adding first leaves no moment without a route.
            for &prefix in wanted.iter().filter(|p| !routes.contains(p)) {
                if let Err(e) = backend.add(prefix) {
                    warn!("auto_route: route {}/{}: {}", prefix.0, prefix.1, e);
                }
            }
            for &prefix in routes.iter().filter(|p| !wanted.contains(p)) {
                let _ = backend.delete(prefix);
            }
            *routes = wanted;
        };
        let mut first = true;
        loop {
            let rule_sets = feed.borrow_and_update().clone();
            if !first {
                refill(&rule_sets);
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
                        let _ = changed.try_send(());
                    }
                })));
            }
            drop(changed);
            loop {
                tokio::select! {
                    Some(()) = changes.recv() => refill(&rule_sets),
                    fed = feed.changed() => {
                        if fed.is_err() {
                            while changes.recv().await.is_some() {
                                refill(&rule_sets);
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

fn full(v6: bool) -> u8 {
    if v6 {
        128
    } else {
        32
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Hands the rule-sets of a reload to a running auto_route.
#[derive(Clone)]
pub(crate) struct RouteSetFeed {
    sets: Arc<RouteSets>,
    sender: Arc<watch::Sender<RuleSets>>,
}

impl RouteSetFeed {
    /// Whether `rule_sets` has every rule-set the TUN names: a reload
    /// without one fails, and changes nothing.
    pub(crate) fn check(&self, rule_sets: &RuleSets) -> Result<()> {
        self.sets.prefixes(rule_sets).map(|_| ())
    }

    pub(crate) fn publish(&self, rule_sets: RuleSets) {
        self.sender.send_replace(rule_sets);
    }
}

/// Linux: a table of the TUN's routes, and ip rules into it.
#[cfg(target_os = "linux")]
mod backend {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};

    use anyhow::{anyhow, Result};
    use tracing::debug;

    use super::super::inbound::TunSettings;
    use crate::platform::auto_route::{self as plan, RuleOptions, RULE_SPAN};
    use crate::platform::rtnetlink::{self as rtnl, Netlink};

    /// The routes are all of each family: the rules choose.
    pub(super) const ROUTES_OWN_NETWORK: bool = false;

    pub(super) fn all(v6: bool) -> Vec<(IpAddr, u8)> {
        vec![if v6 {
            (Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            (Ipv4Addr::UNSPECIFIED.into(), 0)
        }]
    }

    pub(super) struct Backend {
        netlink: Netlink,
        tun: String,
        index: u32,
        table: u32,
        rule_index: u32,
        rules: Vec<plan::Rule>,
        /// Whether systemd-resolved was told of the TUN's DNS.
        resolved: AtomicBool,
        server: Option<IpAddr>,
    }

    impl Backend {
        /// Removes the rules a run that died left.
        pub(super) fn start(settings: &TunSettings) -> Result<Backend> {
            let netlink = Netlink::open().map_err(|e| anyhow!("auto_route: netlink: {}", e))?;
            let index = netlink
                .link_index(&settings.name)
                .map_err(|e| anyhow!("auto_route: {}: {}", settings.name, e))?;
            let backend = Backend {
                netlink,
                tun: settings.name.clone(),
                index,
                table: settings.route.table_index,
                rule_index: settings.route.rule_index,
                rules: plan::rules(&rule_options(settings)),
                resolved: AtomicBool::new(false),
                server: settings
                    .ipv4
                    .map(|i| IpAddr::from(super::super::inbound::peer(i)))
                    .or_else(|| {
                        settings
                            .ipv6
                            .map(|i| IpAddr::from(super::super::inbound::peer(i)))
                    }),
            };
            backend.remove_rules();
            Ok(backend)
        }

        pub(super) fn add(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            self.netlink.add_route(&self.route(prefix))
        }

        pub(super) fn delete(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            self.netlink.del_route(&self.route(prefix))
        }

        /// The routes are there: the rules send traffic to them, and DNS.
        pub(super) fn routed(&self) -> Result<()> {
            for rule in &self.rules {
                self.netlink
                    .add_rule(&to_netlink(rule))
                    .map_err(|e| anyhow!("auto_route: rule {}: {}", plan::render(rule), e))?;
            }
            if let Some(server) = self.server.filter(|_| in_the_host_s_namespace()) {
                let name = self.tun.as_str();
                let server = server.to_string();
                let set = resolvectl(&["dns", name, &server])
                    && resolvectl(&["domain", name, "~."])
                    && resolvectl(&["default-route", name, "true"]);
                self.resolved.store(set, Ordering::Relaxed);
            }
            Ok(())
        }

        pub(super) fn stop(&self) {
            self.remove_rules();
            if self.resolved.load(Ordering::Relaxed) {
                resolvectl(&["revert", &self.tun]);
            }
        }

        fn route(&self, (address, len): (IpAddr, u8)) -> rtnl::Route {
            rtnl::Route::new(rtnl::Prefix::new(address, len), self.table).oif(self.index)
        }

        /// Removes every rule of either family at the priorities auto_route
        /// uses, whatever made it, as sing-tun does.
        fn remove_rules(&self) {
            for family in [rtnl::Family::V4, rtnl::Family::V6] {
                for priority in self.rule_index..=self.rule_index + RULE_SPAN {
                    if let Err(e) = self.netlink.del_rules_at(family, priority) {
                        debug!("auto_route: removing rules at {}: {}", priority, e);
                    }
                }
            }
        }
    }

    fn rule_options(settings: &TunSettings) -> RuleOptions {
        let selection = &settings.route;
        RuleOptions {
            tun: settings.name.clone(),
            table: selection.table_index,
            rule_index: selection.rule_index,
            ipv4: settings
                .ipv4
                .iter()
                .map(|i| (i.address(), i.network_length()))
                .collect(),
            ipv6: settings
                .ipv6
                .iter()
                .map(|i| (i.address(), i.network_length()))
                .collect(),
            strict_route: selection.strict_route,
            include_uid: selection.include_uid.clone(),
            exclude_uid: selection.exclude_uid.clone(),
            include_interface: selection.include_interface.clone(),
            exclude_interface: selection.exclude_interface.clone(),
        }
    }

    fn to_netlink(rule: &plan::Rule) -> rtnl::Rule {
        let prefix = |p: Option<(IpAddr, u8)>| p.map(|(addr, len)| rtnl::Prefix { addr, len });
        rtnl::Rule {
            family: if rule.v6 {
                rtnl::Family::V6
            } else {
                rtnl::Family::V4
            },
            priority: rule.priority,
            invert: rule.invert,
            action: match rule.action {
                plan::Action::Lookup(table) => rtnl::RuleAction::Lookup(table),
                plan::Action::Goto(to) => rtnl::RuleAction::Goto(to),
                plan::Action::Nop => rtnl::RuleAction::Nop,
                plan::Action::Unreachable => rtnl::RuleAction::Unreachable,
            },
            src: prefix(rule.src),
            dst: prefix(rule.dst),
            iif: rule.iif.clone(),
            oif: None,
            fwmark: None,
            uid_range: rule.uid_range,
            ip_proto: None,
            sport: None,
            dport: rule.dport,
            suppress_prefixlength: rule.suppress_prefixlength,
        }
    }

    /// Whether sail runs in the network namespace systemd-resolved serves,
    /// the first process's. resolvectl names a link by its index in the
    /// caller's namespace, but resolved, over the system bus that `ip netns
    /// exec` shares, takes it as the host's: a TUN in a namespace of its
    /// own is index 2, as the host's first interface is, and would get the
    /// TUN's DNS. Where the first process's namespace cannot be read (no
    /// root, but the capability to route), it is taken to be.
    fn in_the_host_s_namespace() -> bool {
        use std::os::unix::fs::MetadataExt;
        let ours = std::fs::metadata("/proc/self/ns/net");
        let first = std::fs::metadata("/proc/1/ns/net");
        match (ours, first) {
            (Ok(ours), Ok(first)) => {
                let same = (ours.dev(), ours.ino()) == (first.dev(), first.ino());
                if !same {
                    debug!("auto_route: in a network namespace of its own: the system's DNS is left as it is");
                }
                same
            }
            _ => true,
        }
    }

    fn resolvectl(args: &[&str]) -> bool {
        match Command::new("resolvectl")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) => status.success(),
            // No systemd-resolved: the system's DNS stays as it is.
            Err(_) => false,
        }
    }

    #[cfg(test)]
    mod tests {
        /// A test runs where the host's processes run, unless a namespace
        /// test put it in its own; there, the TUN's DNS is set as on a
        /// desktop. (tests/test_auto_redirect_linux.rs runs sail in a
        /// namespace of its own, and checks that the host's DNS is left.)
        #[test]
        fn the_host_s_namespace_is_told_from_another() {
            let ours = std::fs::read_link("/proc/self/ns/net").unwrap();
            let first = std::fs::read_link("/proc/1/ns/net");
            let expected = first.map_or(true, |first| first == ours);
            assert_eq!(super::in_the_host_s_namespace(), expected);
        }
    }
}

/// macOS: routes through the utun, more specific than the default route.
#[cfg(target_os = "macos")]
mod backend {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use anyhow::{anyhow, Result};

    use super::super::inbound::TunSettings;
    use crate::platform::route_socket::RouteSocket;

    /// The utun is point-to-point: its network needs a route.
    pub(super) const ROUTES_OWN_NETWORK: bool = true;

    /// All addresses of a family but the first /8, as halves ever larger:
    /// 1/8, 2/7, 4/6 ... 128/1 (sing-tun's sub-ranges), which win over the
    /// default route without replacing it.
    pub(super) fn all(v6: bool) -> Vec<(IpAddr, u8)> {
        (0..8u8)
            .map(|i| {
                let first = 1u8 << i;
                let address: IpAddr = if v6 {
                    Ipv6Addr::from(u128::from(first) << 120).into()
                } else {
                    Ipv4Addr::new(first, 0, 0, 0).into()
                };
                (address, 8 - i)
            })
            .collect()
    }

    pub(super) struct Backend {
        socket: RouteSocket,
        ipv4: Option<IpAddr>,
        ipv6: Option<IpAddr>,
    }

    impl Backend {
        pub(super) fn start(settings: &TunSettings) -> Result<Backend> {
            Ok(Backend {
                socket: RouteSocket::open()
                    .map_err(|e| anyhow!("auto_route: routing socket: {}", e))?,
                ipv4: settings.ipv4.map(|i| i.address().into()),
                ipv6: settings.ipv6.map(|i| i.address().into()),
            })
        }

        /// Through the utun's own address of the family, as sing-tun does.
        fn gateway(&self, v6: bool) -> io::Result<IpAddr> {
            if v6 { self.ipv6 } else { self.ipv4 }.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "no address of the family")
            })
        }

        pub(super) fn add(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            self.socket.add(prefix, self.gateway(prefix.0.is_ipv6())?)
        }

        pub(super) fn delete(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            self.socket
                .delete(prefix, self.gateway(prefix.0.is_ipv6())?)
        }

        /// The routes are there: names cached before them resolved to
        /// what they no longer route to.
        pub(super) fn routed(&self) -> Result<()> {
            flush_dns_cache();
            Ok(())
        }

        pub(super) fn stop(&self) {
            flush_dns_cache();
        }
    }

    fn flush_dns_cache() {
        let _ = std::process::Command::new("dscacheutil")
            .arg("-flushcache")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn all_is_sing_tun_s_sub_ranges() {
            let show = |v6| {
                super::all(v6)
                    .into_iter()
                    .map(|(a, l)| format!("{}/{}", a, l))
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                show(false),
                [
                    "1.0.0.0/8",
                    "2.0.0.0/7",
                    "4.0.0.0/6",
                    "8.0.0.0/5",
                    "16.0.0.0/4",
                    "32.0.0.0/3",
                    "64.0.0.0/2",
                    "128.0.0.0/1"
                ]
            );
            assert_eq!(show(true)[0], "100::/8");
            assert_eq!(show(true)[7], "8000::/1");
        }
    }
}

/// Windows: 0/0 and ::/0 through wintun at metric 0, which wins over the
/// default route without replacing it; the adapter's DNS; strict_route by
/// firewall rules (sing-tun, tun_windows.go:169-367).
#[cfg(target_os = "windows")]
mod backend {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    use anyhow::{anyhow, Result};

    use super::super::inbound::{peer, TunSettings};
    use crate::platform::windows::ip_helper::{self, Luid};
    use crate::platform::windows::wfp::StrictRoute;

    /// The routes are all of each family, as on Linux.
    pub(super) const ROUTES_OWN_NETWORK: bool = false;

    pub(super) fn all(v6: bool) -> Vec<(IpAddr, u8)> {
        vec![if v6 {
            (Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            (Ipv4Addr::UNSPECIFIED.into(), 0)
        }]
    }

    pub(super) struct Backend {
        luid: Luid,
        index: u32,
        /// The address after the TUN's, of each family it has: the next
        /// hop of its routes, and its DNS server.
        gateway4: Option<IpAddr>,
        gateway6: Option<IpAddr>,
        strict_route: bool,
        rules: Mutex<Option<StrictRoute>>,
    }

    impl Backend {
        pub(super) fn start(settings: &TunSettings) -> Result<Backend> {
            let luid = Luid::by_alias(&settings.name)
                .map_err(|e| anyhow!("auto_route: {}: {}", settings.name, e))?;
            let index = luid
                .index()
                .map_err(|e| anyhow!("auto_route: {}: {}", settings.name, e))?;
            Ok(Backend {
                luid,
                index,
                gateway4: settings.ipv4.map(|i| IpAddr::from(peer(i))),
                gateway6: settings.ipv6.map(|i| IpAddr::from(peer(i))),
                strict_route: settings.route.strict_route,
                rules: Mutex::new(None),
            })
        }

        fn gateway(&self, v6: bool) -> io::Result<IpAddr> {
            if v6 { self.gateway6 } else { self.gateway4 }.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no address of this family on the tun",
                )
            })
        }

        pub(super) fn add(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            ip_helper::add_route(self.luid, prefix, self.gateway(prefix.0.is_ipv6())?)
        }

        pub(super) fn delete(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            ip_helper::delete_route(self.luid, prefix, self.gateway(prefix.0.is_ipv6())?)
        }

        /// The routes are there: DNS goes to the address after the TUN's,
        /// and, with strict_route, nowhere else.
        pub(super) fn routed(&self) -> Result<()> {
            for (v6, gateway) in [(false, self.gateway4), (true, self.gateway6)] {
                if let Some(gateway) = gateway {
                    self.luid
                        .set_dns(v6, &[gateway])
                        .map_err(|e| anyhow!("auto_route: DNS: {}", e))?;
                }
            }
            if self.strict_route {
                let rules = StrictRoute::start(
                    self.index,
                    self.gateway4.is_some(),
                    self.gateway6.is_some(),
                )
                .map_err(|e| anyhow!("auto_route: strict_route: firewall rules: {}", e))?;
                *self.rules.lock().unwrap_or_else(|e| e.into_inner()) = Some(rules);
            }
            ip_helper::flush_dns_cache();
            Ok(())
        }

        pub(super) fn stop(&self) {
            drop(self.rules.lock().unwrap_or_else(|e| e.into_inner()).take());
            for (v6, gateway) in [(false, self.gateway4), (true, self.gateway6)] {
                if gateway.is_some() {
                    let _ = self.luid.set_dns(v6, &[]);
                }
            }
            ip_helper::flush_dns_cache();
        }
    }
}
