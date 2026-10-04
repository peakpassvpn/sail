//! What a dialer is, as data: the dial fields of the place it dials for,
//! over the instance's defaults, merged and checked once, when the
//! configuration is built. Nothing here is a handle on the running system,
//! so two can be compared.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Result};

use super::networks::{NetworkStrategy, Networks};
use super::{
    interface_exists, supports_bind_interface, supports_routing_mark, tcp_keep_alive, DialFields,
    TcpKeepAlive, DEFAULT_CONNECT_TIMEOUT, DEFAULT_FALLBACK_DELAY,
};
use crate::config::model::{DnsStrategy, DomainResolver};
use crate::net::network::NetworkType;

/// What an instance gives every dialer that its own fields leave unset:
/// `route.default_*`, and what the instance adds to them, auto_redirect's
/// mark and the families `dns.strategy` uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteDefaults {
    /// `route.default_interface`.
    pub bind_interface: Option<String>,
    /// The default interface's addresses, where `auto_detect_interface`
    /// finds them once at start rather than following the interface
    /// (Windows).
    pub inet4_bind_address: Option<Ipv4Addr>,
    pub inet6_bind_address: Option<Ipv6Addr>,
    /// `route.default_mark`, or the TUN's auto_redirect output mark.
    pub routing_mark: Option<u32>,
    /// `route.default_domain_resolver`.
    pub domain_resolver: Option<DomainResolver>,
    /// Whether `auto_detect_interface` picks the interface for each
    /// destination, as the system changes it.
    pub auto_detect_interface: bool,
    /// Whether IPv6 is used at all (`dns.strategy`), which makes the UDP
    /// sockets that are not bound to anything in particular dual-stack.
    pub ipv6: bool,
    /// `route.default_network_strategy`, `default_network_type`,
    /// `default_fallback_network_type` and `default_fallback_delay`.
    pub network_strategy: Option<NetworkStrategy>,
    pub network_type: Vec<NetworkType>,
    pub fallback_network_type: Vec<NetworkType>,
    pub fallback_delay: Option<Duration>,
}

impl RouteDefaults {
    /// The options, as the configuration names them, in which `other`
    /// differs from these: what a reload changed of the defaults, for
    /// telling what goes on with those it was built with.
    pub fn differs_in(&self, other: &RouteDefaults) -> Vec<&'static str> {
        let mut options = Vec::new();
        if self.bind_interface != other.bind_interface {
            options.push("route.default_interface");
        }
        if self.auto_detect_interface != other.auto_detect_interface
            || (self.inet4_bind_address, self.inet6_bind_address)
                != (other.inet4_bind_address, other.inet6_bind_address)
        {
            options.push("route.auto_detect_interface");
        }
        if self.routing_mark != other.routing_mark {
            options.push("route.default_mark");
        }
        if self.domain_resolver != other.domain_resolver {
            options.push("route.default_domain_resolver");
        }
        if self.network_strategy != other.network_strategy {
            options.push("route.default_network_strategy");
        }
        if self.network_type != other.network_type {
            options.push("route.default_network_type");
        }
        if self.fallback_network_type != other.fallback_network_type {
            options.push("route.default_fallback_network_type");
        }
        if self.fallback_delay != other.fallback_delay {
            options.push("route.default_fallback_delay");
        }
        if self.ipv6 != other.ipv6 {
            options.push("dns.strategy");
        }
        options
    }

    /// The defaults `route` sets, checked against this platform. What
    /// `auto_detect_interface` finds is added at start, where the system
    /// is asked.
    pub fn new(route: &crate::config::Route) -> Result<RouteDefaults> {
        let defaults = RouteDefaults {
            bind_interface: route.default_interface.clone(),
            routing_mark: route.default_mark,
            domain_resolver: route.default_domain_resolver.clone(),
            network_strategy: route.default_network_strategy,
            network_type: route.default_network_type.clone(),
            fallback_network_type: route.default_fallback_network_type.clone(),
            fallback_delay: route.default_fallback_delay,
            ..Default::default()
        };
        // As sing-box's network manager has it (route/network.go:111-118).
        if defaults.network_strategy.is_some() {
            if defaults.bind_interface.is_some() {
                return Err(anyhow!(
                    "route.default_network_strategy: not with default_interface, \
                     which binds every socket itself"
                ));
            }
            if !route.auto_detect_interface {
                return Err(anyhow!(
                    "route.default_network_strategy: needs auto_detect_interface"
                ));
            }
        }
        if defaults.routing_mark.is_some() && !supports_routing_mark() {
            return Err(anyhow!("route.default_mark: only supported on Linux"));
        }
        if let Some(name) = &defaults.bind_interface {
            if !supports_bind_interface() {
                return Err(anyhow!(
                    "route.default_interface: not supported on this platform"
                ));
            }
            if interface_exists(name) == Some(false) {
                return Err(anyhow!(
                    "route.default_interface: there is no interface \"{}\"",
                    name
                ));
            }
        }
        Ok(defaults)
    }
}

/// How a dialer's sockets are opened: the interface or address they are
/// bound to, their mark, how long a connect may take and the keepalive of
/// its connections. The dial fields of one place over the instance's
/// defaults, see [`DialSpec::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialSpec {
    /// The interface to send through, by name.
    pub bind_interface: Option<String>,
    /// Without `bind_interface`: the interface `auto_detect_interface`
    /// finds for each destination.
    pub auto_detect_interface: bool,
    /// The local address for IPv4 destinations.
    pub inet4_bind_address: Option<Ipv4Addr>,
    /// The local address for IPv6 destinations.
    pub inet6_bind_address: Option<Ipv6Addr>,
    /// `SO_MARK`, Linux only.
    pub routing_mark: Option<u32>,
    /// How long a TCP connect to one address may take.
    pub connect_timeout: Duration,
    /// The keepalive of TCP connections, none for none.
    pub tcp_keep_alive: Option<TcpKeepAlive>,
    /// Whether the UDP sockets not bound to anything in particular are
    /// dual-stack.
    pub ipv6: bool,
    /// `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address.
    pub bind_address_no_port: bool,
    /// `SO_REUSEADDR` (and `SO_REUSEPORT`) on UDP sockets.
    pub reuse_addr: bool,
    /// Whether UDP datagrams may be fragmented; if not, DF is set.
    pub udp_fragment: bool,
    /// TCP Fast Open, which tries addresses one by one.
    pub tcp_fast_open: bool,
    /// How long one family's addresses are tried before the other's race
    /// them.
    pub fallback_delay: Duration,
    /// Which of the host's interfaces its connections go out of, where it
    /// chooses: with no bind of its own or of `route.default_interface`.
    pub networks: Option<Networks>,
    /// Where it may choose among the host's interfaces, binding nothing
    /// itself: how long the first interfaces go before the fallback ones,
    /// its `fallback_delay`, else the route's, else 300ms. What a rule's
    /// `network_strategy` takes, see `Dialer::routed`.
    pub network_fallback_delay: Option<Duration>,
}

impl Default for DialSpec {
    /// No fields, and no instance: nothing bound, the default timeout and
    /// keepalive.
    fn default() -> Self {
        DialSpec::merge(&DialFields::default(), &RouteDefaults::default())
    }
}

impl DialSpec {
    /// `fields` over `defaults`, checked against this platform. An error
    /// names the field; the place puts where it is before it.
    pub fn resolve(fields: &DialFields, defaults: &RouteDefaults) -> Result<DialSpec> {
        DialSpec::check(fields)?;
        // sing-box drops the place's strategy then (default.go:101).
        if defaults.bind_interface.is_some() {
            if let Some(name) = fields
                .set()
                .find(|n| ["network_strategy", "network_type", "fallback_network_type"].contains(n))
            {
                return Err(anyhow!(
                    "{}: not with route.default_interface, which binds every socket itself",
                    name
                ));
            }
        }
        Ok(DialSpec::merge(fields, defaults))
    }

    /// Fails for fields this platform cannot apply.
    fn check(fields: &DialFields) -> Result<()> {
        if fields.routing_mark.is_some() && !supports_routing_mark() {
            return Err(anyhow!("routing_mark: only supported on Linux"));
        }
        if fields.bind_address_no_port && !super::sockopt::SUPPORTS_BIND_ADDRESS_NO_PORT {
            return Err(anyhow!("bind_address_no_port: only supported on Linux"));
        }
        if fields.tcp_fast_open {
            super::sockopt::supports_tcp_fast_open()
                .map_err(|e| anyhow!("tcp_fast_open: {}", e))?;
        }
        if let Some(name) = &fields.bind_interface {
            if !supports_bind_interface() {
                return Err(anyhow!("bind_interface: not supported on this platform"));
            }
            if interface_exists(name) == Some(false) {
                return Err(anyhow!(
                    "bind_interface: there is no interface \"{}\"",
                    name
                ));
            }
        }
        Ok(())
    }

    /// `fields` over `defaults`, without checking them against the
    /// platform: for fields checked already, over defaults a reload
    /// replaced.
    pub(crate) fn merge(fields: &DialFields, defaults: &RouteDefaults) -> DialSpec {
        // A place bound to an interface or address of its own is not also
        // bound to the default interface, which could contradict it.
        let binds_itself = fields.bind_interface.is_some()
            || fields.inet4_bind_address.is_some()
            || fields.inet6_bind_address.is_some();
        fn unless<T>(binds_itself: bool, value: Option<T>) -> Option<T> {
            if binds_itself {
                None
            } else {
                value
            }
        }
        // Zero is unset, as in sing-box.
        let set = |d: Option<Duration>| d.filter(|d| !d.is_zero());
        let network_fallback_delay =
            (!binds_itself && defaults.bind_interface.is_none()).then(|| {
                set(fields.fallback_delay)
                    .or(set(defaults.fallback_delay))
                    .unwrap_or(DEFAULT_FALLBACK_DELAY)
            });
        DialSpec {
            bind_interface: fields
                .bind_interface
                .clone()
                .or_else(|| unless(binds_itself, defaults.bind_interface.clone())),
            auto_detect_interface: !binds_itself && defaults.auto_detect_interface,
            inet4_bind_address: fields
                .inet4_bind_address
                .or(unless(binds_itself, defaults.inet4_bind_address)),
            inet6_bind_address: fields
                .inet6_bind_address
                .or(unless(binds_itself, defaults.inet6_bind_address)),
            routing_mark: fields.routing_mark.or(defaults.routing_mark),
            connect_timeout: fields.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT),
            tcp_keep_alive: tcp_keep_alive(
                fields.disable_tcp_keep_alive,
                fields.tcp_keep_alive,
                fields.tcp_keep_alive_interval,
            ),
            ipv6: defaults.ipv6,
            bind_address_no_port: fields.bind_address_no_port,
            reuse_addr: fields.reuse_addr,
            udp_fragment: fields.udp_fragment.unwrap_or(fields.udp_fragment_default),
            tcp_fast_open: fields.tcp_fast_open,
            fallback_delay: set(fields.fallback_delay).unwrap_or(DEFAULT_FALLBACK_DELAY),
            networks: network_fallback_delay.and_then(|delay| networks(fields, defaults, delay)),
            network_fallback_delay,
        }
    }

    /// Whether anything is applied to a socket besides what
    /// `auto_detect_interface` finds.
    pub(crate) fn binds(&self) -> bool {
        self.bind_interface.is_some()
            || self.inet4_bind_address.is_some()
            || self.inet6_bind_address.is_some()
            || self.routing_mark.is_some()
    }

    /// The local address for a UDP socket that is not bound to anything in
    /// particular.
    pub fn unspecified(&self) -> SocketAddr {
        if self.ipv6 {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        }
    }

    /// The local address for `target`, if one is set for its family.
    pub(crate) fn bind_address(&self, target: IpAddr) -> Option<IpAddr> {
        match target {
            IpAddr::V4(_) => self.inet4_bind_address.map(IpAddr::V4),
            IpAddr::V6(_) => self.inet6_bind_address.map(IpAddr::V6),
        }
    }
}

/// The interfaces `fields` choose among, over `defaults`, as sing-box
/// merges them (common/dialer/default.go:107-122): the place's strategy and
/// types where it sets any, else the route's; the strategy `default` where
/// only types are given; the place's delay, else the route's, else 300ms,
/// which `delay` is.
fn networks(fields: &DialFields, defaults: &RouteDefaults, delay: Duration) -> Option<Networks> {
    let own = fields.network_strategy.is_some()
        || !fields.network_type.is_empty()
        || !fields.fallback_network_type.is_empty();
    let from = if own {
        (
            fields.network_strategy,
            &fields.network_type,
            &fields.fallback_network_type,
        )
    } else {
        (
            defaults.network_strategy,
            &defaults.network_type,
            &defaults.fallback_network_type,
        )
    };
    let (strategy, network_type, fallback_network_type) = from;
    if strategy.is_none() && network_type.is_empty() && fallback_network_type.is_empty() {
        return None;
    }
    Some(Networks {
        strategy: strategy.unwrap_or(NetworkStrategy::Default),
        implicit: strategy.is_none(),
        network_type: network_type.clone(),
        fallback_network_type: fallback_network_type.clone(),
        fallback_delay: delay,
    })
}

/// How the names a dialer dials resolve: the DNS server and families to
/// resolve them with, and what the DNS rules see of it. The DNS client
/// resolves with it, see `DnsClient::lookup_dial`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolveSpec {
    /// The DNS server that resolves the names dialled: the place's
    /// `domain_resolver`, or `route.default_domain_resolver`. Unset, the
    /// DNS rules decide.
    pub domain_resolver: Option<DomainResolver>,
    /// The families the names dialled resolve to: sing-box's deprecated
    /// `domain_strategy`, which a `domain_resolver`'s own `strategy` goes
    /// before, where there is one.
    pub strategy: Option<DnsStrategy>,
    /// The outbound that dials, which DNS rules can match.
    pub outbound: Option<String>,
}

impl ResolveSpec {
    /// How the names `fields` dial resolve, over `defaults`, for the
    /// outbound `outbound` if it is one.
    pub fn resolve(
        fields: &DialFields,
        defaults: &RouteDefaults,
        outbound: Option<&str>,
    ) -> ResolveSpec {
        ResolveSpec {
            // Its strategy goes before that of the default resolver, as in
            // sing-box, but not before its own resolver's.
            domain_resolver: fields.domain_resolver().or_else(|| {
                if fields.skip_default_domain_resolver {
                    return None;
                }
                defaults
                    .domain_resolver
                    .clone()
                    .map(|resolver| DomainResolver {
                        strategy: fields.domain_strategy.or(resolver.strategy),
                        ..resolver
                    })
            }),
            strategy: fields.domain_strategy,
            outbound: outbound.map(str::to_owned),
        }
    }
    /// Whether the IPv6 addresses of a name are raced first: with
    /// `prefer_ipv6` only, as in sing-box; otherwise IPv4's are.
    pub(crate) fn prefers_ipv6(&self) -> bool {
        let strategy = self
            .domain_resolver
            .as_ref()
            .and_then(|r| r.strategy)
            .or(self.strategy);
        strategy == Some(DnsStrategy::PreferIpv6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(json: serde_json::Value) -> DialFields {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn a_place_bound_to_an_address_does_not_take_the_default_interface() {
        let defaults = RouteDefaults {
            bind_interface: Some("en0".into()),
            routing_mark: Some(1),
            auto_detect_interface: true,
            ..Default::default()
        };
        let spec = DialSpec::merge(
            &fields(serde_json::json!({ "inet4_bind_address": "10.0.0.2" })),
            &defaults,
        );
        assert_eq!(spec.bind_interface, None);
        assert!(!spec.auto_detect_interface);
        assert_eq!(spec.inet4_bind_address, Some(Ipv4Addr::new(10, 0, 0, 2)));
        // A mark is not an address and still applies.
        assert_eq!(spec.routing_mark, Some(1));
    }

    #[test]
    fn an_unbound_place_takes_the_defaults() {
        let defaults = RouteDefaults {
            bind_interface: Some("en0".into()),
            inet6_bind_address: Some("2001:db8::2".parse().unwrap()),
            routing_mark: Some(7),
            auto_detect_interface: true,
            ipv6: true,
            ..Default::default()
        };
        let spec = DialSpec::merge(&DialFields::default(), &defaults);
        assert_eq!(spec.bind_interface.as_deref(), Some("en0"));
        assert!(spec.auto_detect_interface);
        assert_eq!(spec.inet6_bind_address, defaults.inet6_bind_address);
        assert_eq!(spec.routing_mark, Some(7));
        assert!(spec.ipv6);
    }

    #[test]
    fn its_own_fields_go_before_the_defaults() {
        let defaults = RouteDefaults {
            routing_mark: Some(1),
            ..Default::default()
        };
        let spec = DialSpec::merge(
            &fields(serde_json::json!({
                "bind_interface": "wg0", "routing_mark": 2, "connect_timeout": "2s",
                "tcp_keep_alive": "40s", "tcp_keep_alive_interval": "7s",
            })),
            &defaults,
        );
        assert_eq!(spec.bind_interface.as_deref(), Some("wg0"));
        assert_eq!(spec.routing_mark, Some(2));
        assert_eq!(spec.connect_timeout, Duration::from_secs(2));
        assert_eq!(
            spec.tcp_keep_alive,
            Some(TcpKeepAlive {
                idle: Duration::from_secs(40),
                interval: Duration::from_secs(7),
            })
        );
    }

    #[test]
    fn unset_it_takes_the_runtime_defaults() {
        let spec = DialSpec::default();
        assert_eq!(spec.connect_timeout, Duration::from_secs(5));
        assert_eq!(spec.tcp_keep_alive, Some(TcpKeepAlive::DEFAULT));
        assert!(!spec.binds());
        assert!(!spec.auto_detect_interface);
        let spec = DialSpec::merge(
            &fields(serde_json::json!({ "disable_tcp_keep_alive": true })),
            &RouteDefaults::default(),
        );
        assert_eq!(spec.tcp_keep_alive, None);
    }

    #[test]
    fn socket_options_are_sing_box_s_defaults_unless_set() {
        let spec = DialSpec::default();
        assert!(!spec.udp_fragment);
        assert!(!spec.tcp_fast_open && !spec.reuse_addr && !spec.bind_address_no_port);
        assert_eq!(spec.fallback_delay, Duration::from_millis(300));
        // Zero is unset.
        let merge = |json| DialSpec::merge(&fields(json), &RouteDefaults::default());
        assert_eq!(
            merge(serde_json::json!({ "fallback_delay": "0s" })).fallback_delay,
            Duration::from_millis(300)
        );
        let spec = merge(serde_json::json!({
            "fallback_delay": "50ms", "tcp_fast_open": true, "reuse_addr": true,
            "udp_fragment": true, "bind_address_no_port": true,
        }));
        assert_eq!(spec.fallback_delay, Duration::from_millis(50));
        assert!(spec.tcp_fast_open && spec.reuse_addr && spec.udp_fragment);
        assert!(spec.bind_address_no_port);
        // The protocol's default where the field is unset, the field
        // where set.
        let protocol = |json| DialFields {
            udp_fragment_default: true,
            ..fields(json)
        };
        let merged = |f: DialFields| DialSpec::merge(&f, &RouteDefaults::default()).udp_fragment;
        assert!(merged(protocol(serde_json::json!({}))));
        assert!(!merged(protocol(
            serde_json::json!({ "udp_fragment": false })
        )));
    }

    #[test]
    fn ipv6_goes_first_with_prefer_ipv6_only() {
        let resolve = |json| ResolveSpec::resolve(&fields(json), &RouteDefaults::default(), None);
        assert!(!resolve(serde_json::json!({})).prefers_ipv6());
        assert!(!resolve(serde_json::json!({ "domain_strategy": "prefer_ipv4" })).prefers_ipv6());
        assert!(resolve(serde_json::json!({ "domain_strategy": "prefer_ipv6" })).prefers_ipv6());
        assert!(resolve(serde_json::json!({
            "domain_resolver": { "server": "a", "strategy": "prefer_ipv6" },
            "domain_strategy": "prefer_ipv4",
        }))
        .prefers_ipv6());
        // The default resolver's strategy counts too.
        let defaults = RouteDefaults {
            domain_resolver: Some(DomainResolver {
                server: "a".into(),
                strategy: Some(DnsStrategy::PreferIpv6),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(ResolveSpec::resolve(&DialFields::default(), &defaults, None).prefers_ipv6());
    }

    #[test]
    fn unbound_udp_sockets_are_dual_stack_only_with_ipv6() {
        assert_eq!(
            DialSpec::default().unspecified(),
            "0.0.0.0:0".parse().unwrap()
        );
        let defaults = RouteDefaults {
            ipv6: true,
            ..Default::default()
        };
        assert_eq!(
            DialSpec::merge(&DialFields::default(), &defaults).unspecified(),
            "[::]:0".parse().unwrap()
        );
    }

    #[test]
    fn the_platform_is_checked_when_built() {
        let check = |json| {
            DialSpec::resolve(&fields(json), &RouteDefaults::default())
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        let mark = check(serde_json::json!({ "routing_mark": 1 }));
        if supports_routing_mark() {
            mark.unwrap();
        } else {
            assert_eq!(mark, Err("routing_mark: only supported on Linux".into()));
        }
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert_eq!(
                check(serde_json::json!({ "bind_interface": "no-such-if0" })),
                Err("bind_interface: there is no interface \"no-such-if0\"".into())
            );
        }
        let no_port = check(serde_json::json!({ "bind_address_no_port": true }));
        if cfg!(any(target_os = "linux", target_os = "android")) {
            no_port.unwrap();
        } else {
            assert_eq!(
                no_port,
                Err("bind_address_no_port: only supported on Linux".into())
            );
        }
        let fast_open = check(serde_json::json!({ "tcp_fast_open": true }));
        if cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        )) {
            fast_open.unwrap();
        } else if cfg!(windows) {
            assert_eq!(
                fast_open,
                Err("tcp_fast_open: not supported on Windows yet".into())
            );
        } else {
            assert_eq!(
                fast_open,
                Err("tcp_fast_open: not supported on this platform".into())
            );
        }
        // The defaults are theirs to check, as route's.
        let defaults = RouteDefaults {
            bind_interface: Some("no-such-if0".into()),
            ..Default::default()
        };
        DialSpec::resolve(&DialFields::default(), &defaults).unwrap();
    }

    #[test]
    fn route_s_defaults_are_checked_when_built() {
        let route = |json| -> crate::config::Route { serde_json::from_value(json).unwrap() };
        let mark = RouteDefaults::new(&route(serde_json::json!({ "default_mark": 1 })));
        if supports_routing_mark() {
            assert_eq!(mark.unwrap().routing_mark, Some(1));
        } else {
            assert_eq!(
                mark.unwrap_err().to_string(),
                "route.default_mark: only supported on Linux"
            );
        }
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert_eq!(
                RouteDefaults::new(&route(
                    serde_json::json!({ "default_interface": "no-such-if0" })
                ))
                .unwrap_err()
                .to_string(),
                "route.default_interface: there is no interface \"no-such-if0\""
            );
        }
    }

    #[test]
    fn the_strategy_is_the_place_s_else_the_route_s() {
        use NetworkType::*;
        let route = RouteDefaults {
            network_strategy: Some(NetworkStrategy::Hybrid),
            network_type: vec![Wifi],
            fallback_network_type: vec![Cellular],
            fallback_delay: Some(Duration::from_millis(500)),
            ..Default::default()
        };
        let networks =
            |json, defaults: &RouteDefaults| DialSpec::merge(&fields(json), defaults).networks;
        // None set anywhere, none.
        assert_eq!(
            networks(serde_json::json!({}), &RouteDefaults::default()),
            None
        );
        // The route's, the three together, and its delay.
        assert_eq!(
            networks(serde_json::json!({}), &route),
            Some(Networks {
                strategy: NetworkStrategy::Hybrid,
                implicit: false,
                network_type: vec![Wifi],
                fallback_network_type: vec![Cellular],
                fallback_delay: Duration::from_millis(500),
            })
        );
        // Any one of the place's three, and the route's are left whole;
        // types alone are the default strategy, implicitly.
        assert_eq!(
            networks(serde_json::json!({ "network_type": "ethernet" }), &route),
            Some(Networks {
                strategy: NetworkStrategy::Default,
                implicit: true,
                network_type: vec![Ethernet],
                fallback_network_type: vec![],
                fallback_delay: Duration::from_millis(500),
            })
        );
        // The place's delay goes first; zero is unset; 300ms otherwise.
        let delay = |json| networks(json, &route).unwrap().fallback_delay;
        assert_eq!(
            delay(serde_json::json!({ "fallback_delay": "50ms" })),
            Duration::from_millis(50)
        );
        assert_eq!(
            delay(serde_json::json!({ "fallback_delay": "0s" })),
            Duration::from_millis(500)
        );
        let fallback = serde_json::json!({ "network_strategy": "fallback" });
        let alone = networks(fallback.clone(), &RouteDefaults::default()).unwrap();
        assert_eq!(alone.fallback_delay, Duration::from_millis(300));
        assert!(!alone.implicit);
        // A bind of its own, or the route's interface, and none.
        assert_eq!(
            networks(
                serde_json::json!({ "inet4_bind_address": "10.0.0.2" }),
                &route
            ),
            None
        );
        let bound = RouteDefaults {
            bind_interface: Some("en0".into()),
            ..route.clone()
        };
        assert_eq!(networks(serde_json::json!({}), &bound), None);
        // Which, for the place's own, is an error.
        assert_eq!(
            DialSpec::resolve(&fields(fallback), &bound)
                .unwrap_err()
                .to_string(),
            "network_strategy: not with route.default_interface, which binds every socket itself"
        );
    }

    #[test]
    fn the_route_s_strategy_needs_auto_detection_and_no_interface() {
        let route = |json| -> crate::config::Route { serde_json::from_value(json).unwrap() };
        let err = |json| RouteDefaults::new(&route(json)).unwrap_err().to_string();
        assert_eq!(
            err(serde_json::json!({ "default_network_strategy": "hybrid" })),
            "route.default_network_strategy: needs auto_detect_interface"
        );
        assert_eq!(
            err(serde_json::json!({ "default_network_strategy": "hybrid",
                "default_interface": "lo" })),
            "route.default_network_strategy: not with default_interface, \
             which binds every socket itself"
        );
        let defaults = RouteDefaults::new(&route(serde_json::json!({
            "default_network_strategy": "fallback", "auto_detect_interface": true,
            "default_network_type": "wifi", "default_fallback_network_type": ["cellular"],
            "default_fallback_delay": "1s",
        })))
        .unwrap();
        assert_eq!(defaults.network_strategy, Some(NetworkStrategy::Fallback));
        assert_eq!(defaults.network_type, [NetworkType::Wifi]);
        assert_eq!(defaults.fallback_network_type, [NetworkType::Cellular]);
        assert_eq!(defaults.fallback_delay, Some(Duration::from_secs(1)));
        // Types alone need nothing (route/network.go:111).
        RouteDefaults::new(&route(
            serde_json::json!({ "default_network_type": "wifi" }),
        ))
        .unwrap();
    }

    #[test]
    fn skipping_the_default_resolver_leaves_the_dns_rules() {
        let defaults = RouteDefaults {
            domain_resolver: Some(DomainResolver {
                server: "proxy-dns".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let skipping = fields(serde_json::json!({ "skip_default_domain_resolver": true }));
        assert_eq!(
            ResolveSpec::resolve(&skipping, &defaults, None).domain_resolver,
            None
        );
        assert_eq!(
            ResolveSpec::resolve(&DialFields::default(), &defaults, Some("proxy")),
            ResolveSpec {
                domain_resolver: defaults.domain_resolver.clone(),
                strategy: None,
                outbound: Some("proxy".into()),
            }
        );
    }

    #[test]
    fn domain_strategy_goes_before_the_default_resolver_s_not_its_own() {
        let defaults = RouteDefaults {
            domain_resolver: Some(DomainResolver {
                server: "world".into(),
                strategy: Some(DnsStrategy::Ipv4Only),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolve = |json| ResolveSpec::resolve(&fields(json), &defaults, None);
        let over_default = resolve(serde_json::json!({ "domain_strategy": "ipv6_only" }));
        assert_eq!(
            over_default.domain_resolver.unwrap().strategy,
            Some(DnsStrategy::Ipv6Only)
        );
        assert_eq!(over_default.strategy, Some(DnsStrategy::Ipv6Only));
        let own = resolve(serde_json::json!({
            "domain_resolver": { "server": "home", "strategy": "ipv4_only" },
            "domain_strategy": "ipv6_only",
        }));
        let own = own.domain_resolver.unwrap();
        assert_eq!(own.server, "home");
        assert_eq!(own.strategy, Some(DnsStrategy::Ipv4Only));
    }
}
