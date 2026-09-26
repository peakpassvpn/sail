use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};

/// The IPv6 address the TUN takes when IPv6 is routed into it.
const TUN_IPV6_ADDRESS: Ipv6Addr = Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 2);
const TUN_IPV6_GATEWAY: Ipv6Addr = Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 1);
const TUN_IPV6_PREFIX_LEN: i32 = 64;

/// How a TUN with `auto` is addressed and routed.
#[derive(Debug, Clone)]
pub struct TunRoute {
    pub name: String,
    pub address: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
    /// Routes IPv6 into the TUN as well (`dns.strategy` uses IPv6).
    pub ipv6: bool,
    /// Forwards the traffic of other hosts: the host is their gateway.
    pub gateway_mode: bool,
}

impl TunRoute {
    /// The route of the TUN inbound in `config`, if it has one with `auto`.
    pub fn from_config(config: &crate::config::Config) -> Result<Option<TunRoute>> {
        let Some(inbound) = config.inbounds.iter().find(|i| i.protocol == "tun") else {
            return Ok(None);
        };
        let options = crate::protocol::tun::inbound::options(inbound)?;
        if !options.auto {
            return Ok(None);
        }
        let ip = |field: &str, value: &str| {
            value.parse::<Ipv4Addr>().map_err(|_| {
                anyhow!(
                    "[{}] inbound: {}: \"{}\" is not an IPv4 address",
                    inbound.tag,
                    field,
                    value
                )
            })
        };
        Ok(Some(TunRoute {
            name: options.name().to_string(),
            address: ip("address", options.address())?,
            gateway: ip("gateway", options.gateway())?,
            netmask: ip("netmask", options.netmask())?,
            ipv6: config.dns.strategy.ipv6(),
            gateway_mode: options.gateway_mode,
        }))
    }
}

#[derive(Default)]
pub struct NetInfo {
    pub default_ipv4_gateway: Option<Ipv4Addr>,
    pub default_ipv6_gateway: Option<Ipv6Addr>,
    pub default_ipv4_address: Option<Ipv4Addr>,
    pub default_ipv6_address: Option<Ipv6Addr>,
    pub ipv4_forwarding: bool,
    pub ipv6_forwarding: bool,
    pub default_interface: Option<String>,
    /// The route set up, which is undone by the same description.
    pub route: Option<TunRoute>,
    /// The default routes the TUN replaces, as they were (Linux).
    pub saved_routes: Vec<String>,
    pub saved_routes6: Vec<String>,
}

/// Reads the default route and forwarding the TUN's routes replace. Fails
/// without an IPv4 default gateway, which the TUN's route needs; a missing
/// IPv6 one only leaves IPv6 routing alone.
pub fn get_net_info(route: TunRoute) -> Result<NetInfo> {
    let iface = super::cmd::get_default_interface()?;

    let ipv4_gw = super::cmd::get_default_ipv4_gateway()?;
    let ipv4_gw = ipv4_gw.parse::<Ipv4Addr>().map_err(|_| {
        anyhow!(
            "default IPv4 gateway: \"{}\" is not an IPv4 address",
            ipv4_gw
        )
    })?;
    let ipv6_gw = if route.ipv6 {
        match super::cmd::get_default_ipv6_gateway() {
            Ok(gw) => match gw.parse::<Ipv6Addr>() {
                Ok(gw) => Some(gw),
                Err(_) => {
                    tracing::warn!("default IPv6 gateway: \"{}\" is not an IPv6 address", gw);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("no default IPv6 gateway: {}", e);
                None
            }
        }
    } else {
        None
    };

    let all_interfaces = pnet_datalink::interfaces();
    let default_ifa = all_interfaces.iter().find(|ifa| ifa.name == iface);
    let ipv4_addr = default_ifa.and_then(|ifa| {
        ifa.ips.iter().find_map(|ipn| match ipn.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(_) => None,
        })
    });
    let ipv6_addr = if route.ipv6 {
        default_ifa.and_then(|ifa| {
            ifa.ips.iter().find_map(|ipn| match ipn.ip() {
                std::net::IpAddr::V6(ip) => Some(ip),
                std::net::IpAddr::V4(_) => None,
            })
        })
    } else {
        None
    };
    let ipv4_forwarding = super::cmd::get_ipv4_forwarding()?;
    let ipv6_forwarding = if route.ipv6 {
        super::cmd::get_ipv6_forwarding()?
    } else {
        false
    };

    #[cfg(target_os = "linux")]
    let (saved_routes, saved_routes6) = (
        super::cmd::get_default_routes(false).unwrap_or_default(),
        if route.ipv6 {
            super::cmd::get_default_routes(true).unwrap_or_default()
        } else {
            Vec::new()
        },
    );
    #[cfg(not(target_os = "linux"))]
    let (saved_routes, saved_routes6) = (Vec::new(), Vec::new());

    Ok(NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        ipv4_forwarding,
        ipv6_forwarding,
        default_interface: Some(iface),
        route: Some(route),
        saved_routes,
        saved_routes6,
    })
}

/// Routes the system into the TUN. If a step fails, what was done is
/// undone, as far as it can be, before the error is returned.
pub fn post_tun_creation_setup(net_info: &NetInfo) -> Result<()> {
    let result = route_into_tun(net_info);
    if let Err(e) = &result {
        tracing::warn!("routing into the tun failed, restoring the routes: {}", e);
        post_tun_completion_setup(net_info);
    }
    result
}

fn route_into_tun(net_info: &NetInfo) -> Result<()> {
    #[allow(unused_variables)]
    let NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        ipv4_forwarding,
        ipv6_forwarding,
        default_interface: Some(iface),
        route: Some(route),
        ..
    } = net_info
    else {
        return Ok(());
    };
    super::cmd::add_interface_ipv4_address(
        &route.name,
        route.address,
        route.gateway,
        route.netmask,
    )?;
    super::cmd::delete_default_ipv4_route(None)?;

    super::cmd::add_default_ipv4_route(route.gateway, iface.clone(), true)?;
    super::cmd::add_default_ipv4_route(*ipv4_gw, iface.clone(), false)?;

    #[cfg(target_os = "linux")]
    if let Some(a) = ipv4_addr {
        super::cmd::add_default_ipv4_rule(*a)?;
    }

    if route.gateway_mode && !ipv4_forwarding {
        super::cmd::set_ipv4_forwarding(true)?;
    }

    if route.ipv6 {
        super::cmd::add_interface_ipv6_address(&route.name, TUN_IPV6_ADDRESS, TUN_IPV6_PREFIX_LEN)?;

        if let Some(ipv6_gw) = ipv6_gw {
            super::cmd::delete_default_ipv6_route(None)?;
            super::cmd::add_default_ipv6_route(TUN_IPV6_GATEWAY, iface.clone(), true)?;
            super::cmd::add_default_ipv6_route(*ipv6_gw, iface.clone(), false)?;
        }

        #[cfg(target_os = "linux")]
        if let Some(a) = ipv6_addr {
            super::cmd::add_default_ipv6_rule(*a)?;
        }

        if route.gateway_mode && !ipv6_forwarding {
            super::cmd::set_ipv6_forwarding(true)?;
        }
    }

    #[cfg(target_os = "linux")]
    if route.gateway_mode {
        super::cmd::add_iptable_forward(&route.name)?;
    }
    Ok(())
}

/// Logs a step of undoing the routes that failed; the rest still runs.
fn best_effort(what: &str, result: Result<()>) {
    if let Err(e) = result {
        tracing::warn!("{}: {}", what, e);
    }
}

/// Undoes `post_tun_creation_setup`, step by step: a step that fails is
/// logged, and the others still run.
pub fn post_tun_completion_setup(net_info: &NetInfo) {
    #[allow(unused_variables)]
    let NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        ipv4_forwarding,
        ipv6_forwarding,
        default_interface: Some(iface),
        route: Some(route),
        saved_routes,
        saved_routes6,
    } = net_info
    else {
        return;
    };
    best_effort(
        "delete the default route",
        super::cmd::delete_default_ipv4_route(None),
    );
    best_effort(
        "delete the scoped default route",
        super::cmd::delete_default_ipv4_route(Some(iface.clone())),
    );
    restore_default_route(false, saved_routes, || {
        super::cmd::add_default_ipv4_route(*ipv4_gw, iface.clone(), true)
    });

    #[cfg(target_os = "linux")]
    if let Some(a) = ipv4_addr {
        best_effort("delete the rule", super::cmd::delete_default_ipv4_rule(*a));
    }

    if route.gateway_mode && !ipv4_forwarding {
        best_effort(
            "turn IPv4 forwarding off",
            super::cmd::set_ipv4_forwarding(false),
        );
    }

    if route.ipv6 {
        if let Some(ipv6_gw) = ipv6_gw {
            best_effort(
                "delete the IPv6 default route",
                super::cmd::delete_default_ipv6_route(None),
            );
            best_effort(
                "delete the scoped IPv6 default route",
                super::cmd::delete_default_ipv6_route(Some(iface.clone())),
            );
            restore_default_route(true, saved_routes6, || {
                super::cmd::add_default_ipv6_route(*ipv6_gw, iface.clone(), true)
            });
        }

        #[cfg(target_os = "linux")]
        if let Some(a) = ipv6_addr {
            best_effort(
                "delete the IPv6 rule",
                super::cmd::delete_default_ipv6_rule(*a),
            );
        }

        if route.gateway_mode && !ipv6_forwarding {
            best_effort(
                "turn IPv6 forwarding off",
                super::cmd::set_ipv6_forwarding(false),
            );
        }
    }

    #[cfg(target_os = "linux")]
    if route.gateway_mode {
        best_effort(
            "delete the forward rule",
            super::cmd::delete_iptable_forward(&route.name),
        );
    }
}

/// Puts back the default route the TUN took: exactly as it was where it
/// was saved (Linux), otherwise through `fallback`, from its gateway.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn restore_default_route(v6: bool, saved: &[String], fallback: impl FnOnce() -> Result<()>) {
    #[cfg(target_os = "linux")]
    if !saved.is_empty() {
        match super::cmd::restore_default_routes(v6, saved) {
            Ok(()) => return,
            Err(e) => tracing::warn!("{}; adding a plain default route instead", e),
        }
    }
    if let Err(e) = fallback() {
        tracing::warn!("could not restore the default route: {}", e);
    }
}
