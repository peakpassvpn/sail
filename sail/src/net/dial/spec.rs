//! What a dialer is, as data: the dial fields of the place it dials for,
//! over the instance's defaults, merged and checked once, when the
//! configuration is built. Nothing here is a handle on the running system,
//! so two can be compared.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Result};

use super::{
    interface_exists, supports_bind_interface, supports_routing_mark, tcp_keep_alive, DialFields,
    TcpKeepAlive, DEFAULT_CONNECT_TIMEOUT,
};
use crate::config::model::{DnsStrategy, DomainResolver};

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
}

impl RouteDefaults {
    /// The defaults `route` sets, checked against this platform. What
    /// `auto_detect_interface` finds is added at start, where the system
    /// is asked.
    pub fn new(route: &crate::config::Route) -> Result<RouteDefaults> {
        let defaults = RouteDefaults {
            bind_interface: route.default_interface.clone(),
            routing_mark: route.default_mark,
            domain_resolver: route.default_domain_resolver.clone(),
            ..Default::default()
        };
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
        Ok(DialSpec::merge(fields, defaults))
    }

    /// Fails for fields this platform cannot apply.
    fn check(fields: &DialFields) -> Result<()> {
        if fields.routing_mark.is_some() && !supports_routing_mark() {
            return Err(anyhow!("routing_mark: only supported on Linux"));
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
    /// platform: for `http_clients`, which have never been checked, and
    /// fail when they dial instead.
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
        assert_eq!(spec.connect_timeout, Duration::from_secs(8));
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
