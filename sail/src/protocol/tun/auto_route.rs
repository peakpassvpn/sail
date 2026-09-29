//! `auto_route` on Linux without auto_redirect, as sing-tun does it: the
//! TUN's routes in a table of its own, and ip rules that send into it what
//! is to go into the TUN. The main table is never touched: what the kernel
//! drops with the device is all that points at it, and the rules left by a
//! run that died are removed by the next start. DNS goes to the address
//! after the TUN's, through systemd-resolved where there is one.

use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::inbound::TunSettings;
use crate::app::router::rule_set::RuleSets;
use crate::platform::auto_route::{self as plan, RuleOptions, RULE_SPAN};
use crate::platform::rtnetlink::{self as rtnl, Netlink};
use crate::Runner;

/// What auto_route set up; dropping it undoes it.
pub(crate) struct AutoRoute {
    tun: String,
    table: u32,
    rule_index: u32,
    /// The routes added, of each family, removed on stop.
    routes: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
    /// Whether systemd-resolved was told of the TUN's DNS.
    resolved: bool,
    feed: RouteSetFeed,
}

impl Drop for AutoRoute {
    fn drop(&mut self) {
        match Netlink::open() {
            Ok(netlink) => {
                remove_rules(&netlink, self.rule_index);
                let index = netlink.link_index(&self.tun).ok();
                let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
                for &prefix in routes.iter() {
                    let _ = netlink.del_route(&route(prefix, index, self.table));
                }
            }
            Err(e) => warn!("auto_route: removing the routing: {}", e),
        }
        if self.resolved {
            resolvectl(&["revert", &self.tun]);
        }
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
        let netlink = Netlink::open().map_err(|e| anyhow!("auto_route: netlink: {}", e))?;
        let index = netlink
            .link_index(&settings.name)
            .map_err(|e| anyhow!("auto_route: {}: {}", settings.name, e))?;
        let selection = &settings.route;
        let sets = RouteSets {
            tun: tag.to_owned(),
            include: selection.route_address_set.clone(),
            exclude: selection.route_exclude_address_set.clone(),
            fixed_include: selection
                .route_address
                .iter()
                .map(|inet| (inet.address(), inet.network_length()))
                .collect(),
            fixed_exclude: selection
                .route_exclude_address
                .iter()
                .map(|inet| (inet.address(), inet.network_length()))
                .collect(),
            ipv4: settings.ipv4.is_some(),
            ipv6: settings.ipv6.is_some(),
        };
        let prefixes = sets.prefixes(rule_sets)?;
        let (sender, feed) = watch::channel(rule_sets.clone());
        let routes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut this = AutoRoute {
            tun: settings.name.clone(),
            table: selection.table_index,
            rule_index: selection.rule_index,
            routes: routes.clone(),
            resolved: false,
            feed: RouteSetFeed {
                sets: Arc::new(sets.clone()),
                sender: Arc::new(sender),
            },
        };

        // A run that died left its rules: they go first.
        remove_rules(&netlink, selection.rule_index);
        for &prefix in &prefixes {
            netlink
                .add_route(&route(prefix, Some(index), selection.table_index))
                .map_err(|e| anyhow!("auto_route: route {}/{}: {}", prefix.0, prefix.1, e))?;
            routes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(prefix);
        }
        for rule in plan::rules(&rule_options(settings)) {
            netlink
                .add_rule(&to_netlink(&rule))
                .map_err(|e| anyhow!("auto_route: rule {}: {}", plan::render(&rule), e))?;
        }
        this.resolved = set_dns(settings);
        info!(
            "auto_route: {} routes into {} (table {}), rules from {}",
            prefixes.len(),
            settings.name,
            selection.table_index,
            selection.rule_index
        );

        let table = selection.table_index;
        let runner = Box::pin(sets.follow(feed, routes, table, settings.name.clone()));
        Ok((this, runner))
    }

    /// What a reload hands its rule-sets to.
    pub(crate) fn rule_set_feed(&self) -> RouteSetFeed {
        self.feed.clone()
    }
}

/// Removes every rule of either family at the priorities auto_route uses,
/// whatever made it, as sing-tun does.
fn remove_rules(netlink: &Netlink, rule_index: u32) {
    for family in [rtnl::Family::V4, rtnl::Family::V6] {
        for priority in rule_index..=rule_index + RULE_SPAN {
            if let Err(e) = netlink.del_rules_at(family, priority) {
                debug!("auto_route: removing rules at {}: {}", priority, e);
            }
        }
    }
}

fn route((address, len): (IpAddr, u8), oif: Option<u32>, table: u32) -> rtnl::Route {
    rtnl::Route {
        dst: rtnl::Prefix { addr: address, len },
        gateway: None,
        oif,
        table,
        kind: rtnl::RouteKind::Unicast,
        metric: None,
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

/// Points systemd-resolved at the address after the TUN's for every
/// domain, as sing-tun does, where `resolvectl` is there; says whether it
/// did.
fn set_dns(settings: &TunSettings) -> bool {
    let server = settings
        .ipv4
        .map(|i| IpAddr::from(super::inbound::peer(i)))
        .or_else(|| settings.ipv6.map(|i| IpAddr::from(super::inbound::peer(i))));
    let Some(server) = server else {
        return false;
    };
    let name = settings.name.as_str();
    let server = server.to_string();
    resolvectl(&["dns", name, &server])
        && resolvectl(&["domain", name, "~."])
        && resolvectl(&["default-route", name, "true"])
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
    ipv4: bool,
    ipv6: bool,
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
        for (v6, on) in [(false, self.ipv4), (true, self.ipv6)] {
            if on {
                prefixes.extend(plan::routes(v6, &include, &exclude));
            }
        }
        Ok(prefixes)
    }

    /// Replaces the routes when a rule-set they come from is replaced, and
    /// when a reload brings other rule-sets. sing-box routes a rule-set as
    /// it was at the start; sail follows it.
    async fn follow(
        self,
        mut feed: watch::Receiver<RuleSets>,
        routes: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
        table: u32,
        tun: String,
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
            let netlink = match Netlink::open() {
                Ok(netlink) => netlink,
                Err(e) => {
                    warn!("auto_route: netlink: {}", e);
                    return;
                }
            };
            let index = netlink.link_index(&tun).ok();
            let mut routes = routes.lock().unwrap_or_else(|e| e.into_inner());
            // Adding first leaves no moment without a route.
            for &prefix in wanted.iter().filter(|p| !routes.contains(p)) {
                if let Err(e) = netlink.add_route(&route(prefix, index, table)) {
                    warn!("auto_route: route {}/{}: {}", prefix.0, prefix.1, e);
                }
            }
            for &prefix in routes.iter().filter(|p| !wanted.contains(p)) {
                let _ = netlink.del_route(&route(prefix, index, table));
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
