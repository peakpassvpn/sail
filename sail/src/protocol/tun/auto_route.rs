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

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use tokio::sync::watch;
use tracing::{info, warn};

use super::inbound::TunSettings;
use crate::app::router::rule_set::RuleSets;
use crate::control::events::EventHub;
use crate::platform::auto_route as plan;
use crate::platform::sweep::Ledger;
use crate::runtime::teardown::{LeftKind, Step, StepId, Teardown};
use crate::Runner;

/// What auto_route set up; dropping it undoes it.
pub(crate) struct AutoRoute {
    feed: RouteSetFeed,
    /// The undoing of what it made, newest first: DNS, the rules, the
    /// routes. Run by the instance's teardown, or by the drop.
    teardown: Teardown,
    steps: Vec<StepId>,
}

impl Drop for AutoRoute {
    fn drop(&mut self) {
        self.teardown.run_each(&self.steps);
        info!("auto_route removed");
    }
}

/// The routes added, until they are removed: then none are added again,
/// whatever a rule-set says.
#[derive(Default)]
struct Routed {
    prefixes: Vec<(IpAddr, u8)>,
    undone: bool,
}

fn lock(routed: &Mutex<Routed>) -> std::sync::MutexGuard<'_, Routed> {
    routed.lock().unwrap_or_else(|e| e.into_inner())
}

/// The step that removes the routes added into the TUN `tun`, as they are
/// when it runs.
fn routes_step(backend: &Arc<backend::Backend>, routed: &Arc<Mutex<Routed>>, tun: &str) -> Step {
    let (backend, routed) = (backend.clone(), routed.clone());
    let clear = backend.clear_routes();
    let step = Step::new(
        LeftKind::Route,
        format!("auto_route's routes into {}", tun),
        move || {
            let prefixes = {
                let mut routed = lock(&routed);
                routed.undone = true;
                std::mem::take(&mut routed.prefixes)
            };
            let failed: Vec<String> = prefixes
                .into_iter()
                .filter_map(|prefix| {
                    let e = backend.delete(prefix).err()?;
                    Some(format!("{}/{}: {}", prefix.0, prefix.1, e))
                })
                .collect();
            backend.routes_removed();
            if failed.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(failed.join("; ")))
            }
        },
    );
    match clear {
        Some(clear) => step.clear(clear),
        None => step,
    }
}

impl AutoRoute {
    /// Sets it up for the TUN `settings` describe, once the device exists.
    /// What fails is undone.
    pub(crate) fn start(
        tag: &str,
        settings: &TunSettings,
        rule_sets: &RuleSets,
        ledger: &Ledger,
        teardown: &Teardown,
        events: &EventHub,
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
        let backend = Arc::new(backend::Backend::start(settings, ledger)?);
        let routes = Arc::new(Mutex::new(Routed::default()));
        let (sender, feed) = watch::channel(rule_sets.clone());
        // From here, dropping it undoes what was done.
        let mut this = AutoRoute {
            feed: RouteSetFeed {
                sets: Arc::new(sets.clone()),
                sender: Arc::new(sender),
            },
            teardown: teardown.clone(),
            steps: vec![teardown.push(routes_step(&backend, &routes, &settings.name))],
        };
        for &prefix in &prefixes {
            backend
                .add(prefix)
                .map_err(|e| anyhow!("auto_route: route {}/{}: {}", prefix.0, prefix.1, e))?;
            lock(&routes).prefixes.push(prefix);
        }
        backend.routed(teardown, &mut this.steps)?;
        info!(
            "auto_route: {} routes into {}",
            prefixes.len(),
            settings.name
        );
        #[cfg(target_os = "macos")]
        let runner = {
            let watch = backend.clone().watch(routes.clone(), events.clone());
            Box::pin(async move {
                futures::future::join(sets.follow(feed, routes, backend), watch).await;
            })
        };
        #[cfg(not(target_os = "macos"))]
        let runner = {
            let _ = events;
            Box::pin(sets.follow(feed, routes, backend))
        };
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
        routes: Arc<Mutex<Routed>>,
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
            let mut routed = lock(&routes);
            if routed.undone {
                return;
            }
            // Adding first leaves no moment without a route. Only what was
            // added is routed: one that failed is tried again on the next
            // refill, and is not taken for one someone removed.
            let mut added = Vec::with_capacity(wanted.len());
            for &prefix in &wanted {
                if routed.prefixes.contains(&prefix) {
                    added.push(prefix);
                    continue;
                }
                match backend.add(prefix) {
                    Ok(()) => added.push(prefix),
                    Err(e) => warn!("auto_route: route {}/{}: {}", prefix.0, prefix.1, e),
                }
            }
            for &prefix in routed.prefixes.iter().filter(|p| !wanted.contains(p)) {
                let _ = backend.delete(prefix);
            }
            routed.prefixes = added;
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
                watchers.push(AbortOnDrop(crate::runtime::scope::spawn_essential(
                    "auto_route rule-set watch",
                    async move {
                        while version.changed().await.is_ok() {
                            let _ = changed.try_send(());
                        }
                    },
                )));
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
    use std::sync::Arc;

    use anyhow::{anyhow, Result};
    use tracing::{debug, info, warn};

    use super::super::inbound::TunSettings;
    use crate::platform::auto_route::{self as plan, RuleOptions, RULE_SPAN};
    use crate::platform::rtnetlink::{self as rtnl, Netlink};
    use crate::platform::sweep::{Item, Ledger};
    use crate::runtime::teardown::{command_within, LeftKind, Step, StepId, Teardown, WITHIN};

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
        /// The rules are written down here before they are added: they
        /// outlive a killed process, unlike the TUN and its routes.
        ledger: Ledger,
        server: Option<IpAddr>,
    }

    impl Backend {
        /// Removes the rules a run that died left.
        pub(super) fn start(settings: &TunSettings, ledger: &Ledger) -> Result<Backend> {
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
                ledger: ledger.clone(),
                server: settings
                    .ipv4
                    .map(|i| IpAddr::from(super::super::inbound::peer(i)))
                    .or_else(|| {
                        settings
                            .ipv6
                            .map(|i| IpAddr::from(super::super::inbound::peer(i)))
                    }),
            };
            // A sweep has taken what a killed instance wrote down: what is
            // left at these priorities is another's.
            let others = backend.remove_rules();
            if others > 0 {
                warn!(
                    "auto_route: removed {} ip rules at priorities {} to {} that this instance did not \
                     make: another program's, or another sail instance's; give each its own \
                     iproute2_rule_index",
                    others,
                    backend.rule_index,
                    backend.rule_index + RULE_SPAN
                );
            }
            Ok(backend)
        }

        pub(super) fn add(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            self.netlink.add_route(&self.route(prefix))
        }

        /// Removes the route; one gone already, with its device (ENODEV
        /// names the device gone) or by another's hand, is as wanted.
        pub(super) fn delete(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            match self.netlink.del_route(&self.route(prefix)) {
                Err(e) if matches!(rtnl::errno(&e), Some(libc::ESRCH | libc::ENODEV)) => Ok(()),
                other => other,
            }
        }

        /// The command that removes the routes by hand.
        pub(super) fn clear_routes(&self) -> Option<String> {
            Some(format!(
                "ip -4 route flush table {table}; ip -6 route flush table {table}",
                table = self.table
            ))
        }

        pub(super) fn routes_removed(&self) {}

        /// The routes are there: the rules send traffic to them, and DNS.
        /// Each is undone by a step of `teardown`, registered before it is
        /// made, into `steps`.
        pub(super) fn routed(
            self: &Arc<Self>,
            teardown: &Teardown,
            steps: &mut Vec<StepId>,
        ) -> Result<()> {
            self.ledger.record(Item::Tun(self.tun.clone()));
            let last = self.rule_index + RULE_SPAN;
            steps.push(teardown.push({
                let this = self.clone();
                Step::new(
                    LeftKind::Rule,
                    format!(
                        "auto_route's ip rules at priorities {} to {}",
                        self.rule_index, last
                    ),
                    move || {
                        this.undo_rules()?;
                        for rule in &this.rules {
                            this.ledger.forget(&Item::Rule(to_netlink(rule)));
                        }
                        this.ledger.forget(&Item::Tun(this.tun.clone()));
                        Ok(())
                    },
                )
                .clear(crate::platform::policy_route::clear_command(
                    self.rule_index..=last,
                    None,
                ))
            }));
            for rule in &self.rules {
                let rule_ = to_netlink(rule);
                self.ledger.record(Item::Rule(rule_.clone()));
                self.netlink
                    .add_rule(&rule_)
                    .map_err(|e| anyhow!("auto_route: rule {}: {}", plan::render(rule), e))?;
            }
            if let Some(server) = self.server.filter(|_| in_the_host_s_namespace()) {
                let name = self.tun.as_str();
                // Told of the server, resolved has the link's DNS to revert.
                if resolvectl(&["dns", name, &server.to_string()]) {
                    steps.push(teardown.push({
                        let this = self.clone();
                        Step::new(
                            LeftKind::Dns,
                            format!("systemd-resolved's DNS for {}", self.tun),
                            move || {
                                // Its link gone, resolved has forgotten it.
                                if this.netlink.link_index(&this.tun).ok() != Some(this.index) {
                                    return Ok(());
                                }
                                command_within("resolvectl", &["revert", &this.tun], WITHIN)
                            },
                        )
                        .clear(format!("resolvectl revert {}", self.tun))
                    }));
                    let _ = resolvectl(&["domain", name, "~."])
                        && resolvectl(&["default-route", name, "true"]);
                }
            }
            Ok(())
        }

        /// Removes the rules at auto_route's priorities, saying what it
        /// could not.
        fn undo_rules(&self) -> io::Result<()> {
            let mut failed = Vec::new();
            for family in [rtnl::Family::V4, rtnl::Family::V6] {
                for priority in self.rule_index..=self.rule_index + RULE_SPAN {
                    if let Err(e) = self.netlink.del_rules_at(family, priority) {
                        failed.push(format!("at {} ({}): {}", priority, family, e));
                    }
                }
            }
            if failed.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(failed.join("; ")))
            }
        }

        fn route(&self, (address, len): (IpAddr, u8)) -> rtnl::Route {
            rtnl::Route::new(rtnl::Prefix::new(address, len), self.table).oif(self.index)
        }

        /// Removes every rule of either family at the priorities auto_route
        /// uses, whatever made it, as sing-tun does.
        /// Returns how many there were.
        fn remove_rules(&self) -> usize {
            let mut removed = 0;
            for family in [rtnl::Family::V4, rtnl::Family::V6] {
                for priority in self.rule_index..=self.rule_index + RULE_SPAN {
                    match self.netlink.del_rules_at(family, priority) {
                        Ok(n) => removed += n,
                        Err(e) => debug!("auto_route: removing rules at {}: {}", priority, e),
                    }
                }
            }
            removed
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

    /// Whether sail runs in the network namespace systemd-resolved serves.
    /// resolvectl names a link by its index in the caller's namespace, but
    /// resolved, reached over a system bus that `ip netns exec` (or a
    /// container with the host's bus) shares, takes it as its own: a TUN
    /// in a namespace of its own is index 2, as the host's first interface
    /// is, and would give that interface the TUN's DNS. So sail sets DNS
    /// only in resolved's own namespace, as its process shows it, and in
    /// the first process's; where resolved's cannot be told (no such
    /// process to see, or no right to read it), it leaves DNS alone and
    /// says so.
    fn in_the_host_s_namespace() -> bool {
        let resolved = resolved_pid().and_then(|pid| netns_of(&pid.to_string()));
        match why_not(netns_of("self"), resolved, netns_of("1")) {
            None => true,
            Some(why) => {
                info!(
                    "auto_route: the TUN's DNS is not set through systemd-resolved: {}",
                    why
                );
                false
            }
        }
    }

    type Netns = (u64, u64);

    /// Why the TUN's DNS is not set, given the namespaces of sail, of
    /// resolved and of the first process; None when it is.
    fn why_not(
        ours: Option<Netns>,
        resolved: Option<Netns>,
        first: Option<Netns>,
    ) -> Option<&'static str> {
        match (ours, resolved) {
            (Some(ours), Some(resolved)) if ours != resolved => {
                Some("sail is in a network namespace of its own, not systemd-resolved's")
            }
            (Some(ours), Some(_)) if first.is_some_and(|first| first != ours) => {
                Some("sail is in a network namespace of its own, not the first process's")
            }
            (Some(_), Some(_)) => None,
            _ => Some("systemd-resolved's network namespace cannot be told from here"),
        }
    }

    /// The network namespace of process `pid` ("self" for this one), by its
    /// handle's device and inode.
    fn netns_of(pid: &str) -> Option<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(format!("/proc/{}/ns/net", pid)).ok()?;
        Some((meta.dev(), meta.ino()))
    }

    /// systemd-resolved's process, as systemd tells it.
    fn resolved_pid() -> Option<u32> {
        let out = Command::new("systemctl")
            .args(["show", "-p", "MainPID", "--value", "systemd-resolved"])
            .stderr(Stdio::null())
            .output()
            .ok()?;
        let pid: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
        (pid != 0).then_some(pid)
    }

    /// Whether resolvectl did as `args` say; without systemd-resolved the
    /// system's DNS stays as it is.
    fn resolvectl(args: &[&str]) -> bool {
        command_within("resolvectl", args, WITHIN).is_ok()
    }

    #[cfg(test)]
    mod tests {
        /// The decision, by namespaces given as (device, inode).
        /// (tests/test_auto_redirect_linux.rs runs sail in a namespace of
        /// its own with the host's bus, and checks that the host's DNS is
        /// left and that sail says why.)
        #[test]
        fn dns_is_set_only_in_resolved_s_namespace() {
            let host = Some((4, 1));
            let other = Some((4, 2));
            // resolved's and the first process's: set.
            assert_eq!(super::why_not(host, host, host), None);
            // The first process's unreadable (no root): resolved's decides.
            assert_eq!(super::why_not(host, host, None), None);
            // Not resolved's, though the first process's (a container
            // with its own pid namespace and the host's bus): not set.
            assert!(super::why_not(other, host, other)
                .unwrap()
                .contains("systemd-resolved's"));
            // resolved's, not the first process's: not set.
            assert!(super::why_not(host, host, other)
                .unwrap()
                .contains("first process's"));
            // resolved's not to be told: not set.
            assert!(super::why_not(host, None, host)
                .unwrap()
                .contains("cannot be told"));
            assert!(super::why_not(None, host, host).is_some());
        }
    }
}

/// macOS: routes through the utun, more specific than the default route.
#[cfg(target_os = "macos")]
mod backend {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use anyhow::{anyhow, Result};

    use std::sync::{Arc, Mutex};

    use tracing::{info, warn};

    use super::super::inbound::{peer, TunSettings};
    use super::{lock, Routed};
    use crate::control::events::EventHub;
    use crate::platform::integrity::{self, Broken, Told};
    use crate::platform::route_socket::{self, RouteMonitor, RouteSocket};
    use crate::platform::sc_dns::{self, TunDns};
    use crate::platform::sweep::Ledger;
    use crate::runtime::teardown::{LeftKind, Step, StepId, Teardown};

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
        /// The utun's own networks, as its addresses and prefixes give them.
        own: Vec<cidr::IpCidr>,
        tun: String,
        /// The address after the TUN's, of each family it has: its DNS
        /// server, as on Linux and Windows.
        dns_servers: Vec<IpAddr>,
        /// The system DNS while the TUN runs (platform/sc_dns.rs).
        dns: Mutex<Option<TunDns>>,
    }

    impl Backend {
        pub(super) fn start(settings: &TunSettings, _ledger: &Ledger) -> Result<Backend> {
            Ok(Backend {
                socket: RouteSocket::open()
                    .map_err(|e| anyhow!("auto_route: routing socket: {}", e))?,
                tun: settings.name.clone(),
                dns_servers: settings
                    .ipv4
                    .map(|i| IpAddr::from(peer(i)))
                    .into_iter()
                    .chain(settings.ipv6.map(|i| IpAddr::from(peer(i))))
                    .collect(),
                dns: Mutex::new(None),
                ipv4: settings.ipv4.map(|i| i.address().into()),
                ipv6: settings.ipv6.map(|i| i.address().into()),
                own: settings
                    .ipv4
                    .map(|i| cidr::IpCidr::V4(i.network()))
                    .into_iter()
                    .chain(settings.ipv6.map(|i| cidr::IpCidr::V6(i.network())))
                    .collect(),
            })
        }

        /// Through the utun's own address of the family, as sing-tun does.
        fn gateway(&self, v6: bool) -> io::Result<IpAddr> {
            if v6 { self.ipv6 } else { self.ipv4 }.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "no address of the family")
            })
        }

        pub(super) fn add(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            let replaced = self.socket.add(prefix, self.gateway(prefix.0.is_ipv6())?)?;
            // The kernel's route to the utun's own network is replaced on
            // every start; any other was someone's, and stays gone.
            if let Some(was) = replaced.filter(|_| !self.is_own(prefix)) {
                tracing::warn!(
                    "auto_route: replaced the route to {}/{} ({}) with sail's; it is not put back \
                     when sail stops",
                    prefix.0,
                    prefix.1,
                    was
                );
            }
            Ok(())
        }

        pub(super) fn delete(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            match self
                .socket
                .delete(prefix, self.gateway(prefix.0.is_ipv6())?)
            {
                // Gone already, with the utun (the utun's own network goes
                // with its address) or by another's hand, is as wanted.
                Err(e) if crate::platform::route_socket::errno(&e) == Some(libc::ESRCH) => Ok(()),
                other => other,
            }
        }

        /// No one command removes them by hand; they go with the utun.
        pub(super) fn clear_routes(&self) -> Option<String> {
            None
        }

        /// Names cached while the routes were there resolved to what they
        /// no longer route to.
        pub(super) fn routes_removed(&self) {
            flush_dns_cache();
        }

        /// Whether `prefix` is one of the utun's own networks.
        fn is_own(&self, (address, len): (IpAddr, u8)) -> bool {
            self.own
                .iter()
                .any(|net| net.network_length() == len && net.contains(&address))
        }

        /// The routes are there: the system's DNS goes to the TUN, and
        /// names cached before resolved to what they no longer route to.
        /// The DNS is undone by a step of `teardown`, registered before it
        /// is set, into `steps`. A DNS that cannot be set is said, and the
        /// start goes on, as on Linux.
        pub(super) fn routed(
            self: &Arc<Self>,
            teardown: &Teardown,
            steps: &mut Vec<StepId>,
        ) -> Result<()> {
            if !self.dns_servers.is_empty() {
                let this = self.clone();
                steps.push(
                    teardown.push(
                        Step::new(
                            LeftKind::Dns,
                            format!("the system DNS for {}", self.tun),
                            move || {
                                let dns = this.dns.lock().unwrap_or_else(|e| e.into_inner()).take();
                                match dns {
                                    // Closing its session removes it too.
                                    Some(dns) => dns.remove(),
                                    None => Ok(()),
                                }
                            },
                        )
                        .clear(format!(
                            "sudo scutil <<< \"remove {}\"",
                            sc_dns::key(&self.tun)
                        )),
                    ),
                );
                match TunDns::set(&self.tun, &self.dns_servers) {
                    Ok(dns) => {
                        *self.dns.lock().unwrap_or_else(|e| e.into_inner()) = Some(dns);
                    }
                    Err(e) => warn!("auto_route: the system DNS is not set to the TUN: {}", e),
                }
            }
            flush_dns_cache();
            Ok(())
        }

        /// Follows the system on each notice of the routing socket, once
        /// it is quiet: sets the system DNS again when the network took it
        /// (configd restarted; a wake), and tells what someone else changed
        /// of the routes into the TUN and of its address, leaving it as it
        /// is (platform/integrity.rs). Never ends while the TUN runs.
        pub(super) async fn watch(self: Arc<Self>, routes: Arc<Mutex<Routed>>, events: EventHub) {
            let monitor = match RouteMonitor::open() {
                Ok(monitor) => monitor,
                Err(e) => {
                    warn!("auto_route: not following the system: {}", e);
                    return std::future::pending().await;
                }
            };
            let changed = || monitor.changed();
            let mut told = Told::default();
            while changed().await.is_ok() {
                crate::settle(&changed, crate::SETTLE_QUIET, crate::SETTLE_MAX).await;
                self.keep_dns();
                match self.check(&routes) {
                    Some(found) => told.tell(found, &events),
                    // Undone: what changes now is sail's own.
                    None => break,
                }
            }
            std::future::pending().await
        }

        /// Sets the system DNS again if it is gone.
        fn keep_dns(&self) {
            let restored = match &*self.dns.lock().unwrap_or_else(|e| e.into_inner()) {
                Some(dns) => dns.restore(),
                None => Ok(false),
            };
            match restored {
                Ok(true) => info!(
                    "auto_route: the system DNS for {} was gone; set again",
                    self.tun
                ),
                Ok(false) => {}
                Err(e) => warn!("auto_route: the system DNS for {}: {}", self.tun, e),
            }
        }

        /// What is not as sail set it up: its routes, under the lock its
        /// own changes are made under, then the TUN's addresses. None once
        /// the routes are undone.
        fn check(&self, routes: &Mutex<Routed>) -> Option<Vec<Broken>> {
            let routed = lock(routes);
            if routed.undone {
                return None;
            }
            let Some(index) = index_of(&self.tun) else {
                return Some(vec![Broken {
                    kind: LeftKind::Tun,
                    what: self.tun.clone(),
                    how: "gone".into(),
                }]);
            };
            let mut table = Vec::new();
            for (v6, address) in [(false, self.ipv4), (true, self.ipv6)] {
                if address.is_none() {
                    continue;
                }
                match route_socket::table(v6) {
                    Ok(routes) => table.extend(routes),
                    Err(e) => {
                        warn!("auto_route: reading the routing table: {}", e);
                        return Some(Vec::new());
                    }
                }
            }
            let contested: Vec<(IpAddr, u8)> = all(false)
                .into_iter()
                .chain(all(true))
                .filter(|p| routed.prefixes.contains(p))
                .collect();
            let mut found = integrity::routes(
                &self.tun,
                index,
                &routed.prefixes,
                &contested,
                &table,
                |address| integrity::longest_match(&table, address),
                |index| {
                    u16::try_from(index)
                        .ok()
                        .and_then(|i| route_socket::interface_name(i).ok())
                        .unwrap_or_else(|| format!("interface {}", index))
                },
            );
            drop(routed);
            match addresses_up() {
                Ok(up) => found.extend(
                    [self.ipv4, self.ipv6]
                        .into_iter()
                        .flatten()
                        .filter_map(|address| integrity::address(&self.tun, address, &up)),
                ),
                Err(e) => warn!("auto_route: reading the interfaces' addresses: {}", e),
            }
            Some(found)
        }
    }

    /// The IP addresses of the interfaces that are up, with their names.
    fn addresses_up() -> io::Result<Vec<(String, IpAddr)>> {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs fills `list`, freed below.
        if unsafe { libc::getifaddrs(&mut list) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut up = Vec::new();
        let mut entry = list;
        while !entry.is_null() {
            // SAFETY: a node of the list getifaddrs returned, not yet freed.
            let ifa = unsafe { &*entry };
            entry = ifa.ifa_next;
            if ifa.ifa_flags & libc::IFF_UP as u32 == 0 || ifa.ifa_addr.is_null() {
                continue;
            }
            // SAFETY: a sockaddr of the list, of the size its family says.
            let address: Option<IpAddr> = unsafe {
                match i32::from((*ifa.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)).into())
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        Some(Ipv6Addr::from(sin6.sin6_addr.s6_addr).into())
                    }
                    _ => None,
                }
            };
            if let Some(address) = address {
                // SAFETY: the name is a C string owned by the list.
                let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                up.push((name, address));
            }
        }
        // SAFETY: the list getifaddrs returned, freed once.
        unsafe { libc::freeifaddrs(list) };
        Ok(up)
    }

    /// The index of the interface `name`; none once it is gone.
    fn index_of(name: &str) -> Option<u32> {
        let name = std::ffi::CString::new(name).ok()?;
        // SAFETY: a C string that lives through the call.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        (index != 0).then_some(index)
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
    use std::sync::{Arc, Mutex};

    use anyhow::{anyhow, Result};

    use super::super::inbound::{peer, TunSettings};
    use crate::platform::sweep::Ledger;
    use crate::platform::windows::ip_helper::{self, Luid};
    use crate::platform::windows::wfp::StrictRoute;
    use crate::runtime::teardown::{LeftKind, Step, StepId, Teardown};

    /// winerror.h: what IP Helper says of an interface that is gone.
    const ERROR_FILE_NOT_FOUND: i32 = 2;

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
        /// The TUN's name, for what is told of it.
        name: String,
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
        pub(super) fn start(settings: &TunSettings, _ledger: &Ledger) -> Result<Backend> {
            let luid = Luid::by_alias(&settings.name)
                .map_err(|e| anyhow!("auto_route: {}: {}", settings.name, e))?;
            let index = luid
                .index()
                .map_err(|e| anyhow!("auto_route: {}: {}", settings.name, e))?;
            Ok(Backend {
                name: settings.name.clone(),
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

        /// Removes the route; one gone already, or with its adapter, is as
        /// wanted.
        pub(super) fn delete(&self, prefix: (IpAddr, u8)) -> io::Result<()> {
            match ip_helper::delete_route(self.luid, prefix, self.gateway(prefix.0.is_ipv6())?) {
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => Ok(()),
                other => other,
            }
        }

        /// The command that removes them by hand: every route on the
        /// adapter, which holds no other.
        pub(super) fn clear_routes(&self) -> Option<String> {
            Some(format!(
                "powershell -Command \"Get-NetRoute -InterfaceAlias '{}' | Remove-NetRoute -Confirm:$false\"",
                self.name
            ))
        }

        pub(super) fn routes_removed(&self) {}

        /// The routes are there: DNS goes to the address after the TUN's,
        /// and, with strict_route, nowhere else. Each is undone by a step
        /// of `teardown`, into `steps`: the firewall rules, the newest, go
        /// first, so that no moment blocks DNS with the TUN's own gone.
        pub(super) fn routed(
            self: &Arc<Self>,
            teardown: &Teardown,
            steps: &mut Vec<StepId>,
        ) -> Result<()> {
            // Before it is set: emptying a setting not made is harmless.
            steps.push(teardown.push({
                let this = self.clone();
                Step::new(
                    LeftKind::Dns,
                    format!("the DNS servers of {}", self.name),
                    move || this.undo_dns(),
                )
                .clear(format!(
                    "netsh interface ip set dnsservers name=\"{0}\" source=static address=none & \
                     netsh interface ipv6 set dnsservers name=\"{0}\" source=static address=none",
                    self.name
                ))
            }));
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
                // The session is dynamic: its filters go with the handle,
                // or at the latest with the process.
                steps.push(teardown.push({
                    let this = self.clone();
                    Step::new(
                        LeftKind::Wfp,
                        format!(
                            "strict_route's firewall rules for {} (WFP session \"sail\")",
                            self.name
                        ),
                        move || {
                            let rules = this.rules.lock().unwrap_or_else(|e| e.into_inner()).take();
                            rules.map_or(Ok(()), StrictRoute::close)
                        },
                    )
                    .clear("stop the process that runs sail: the filters go with it")
                }));
            }
            ip_helper::flush_dns_cache();
            Ok(())
        }

        /// Empties the adapter's DNS servers, of the families it has; an
        /// adapter gone has none. One can go while this runs (a start that
        /// failed, its host removing it), and a family's settings with it:
        /// ERROR_FILE_NOT_FOUND then, which leaves nothing either.
        fn undo_dns(&self) -> io::Result<()> {
            if !self.luid.exists() {
                return Ok(());
            }
            let mut failed = Vec::new();
            for (v6, gateway) in [(false, self.gateway4), (true, self.gateway6)] {
                if gateway.is_none() {
                    continue;
                }
                match self.luid.set_dns(v6, &[]) {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {}
                    Err(_) if !self.luid.exists() => {}
                    Err(e) => failed.push(format!("{}: {}", if v6 { "IPv6" } else { "IPv4" }, e)),
                }
            }
            ip_helper::flush_dns_cache();
            if failed.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(failed.join("; ")))
            }
        }
    }
}
