use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};

/// How a TUN with `auto_route` is addressed and routed.
#[derive(Debug, Clone)]
pub struct TunRoute {
    pub name: String,
    pub address: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
    /// With an IPv6 address on the device, IPv6 is routed into it as well:
    /// the address, the other end of the link, and the prefix length.
    pub ipv6: Option<(Ipv6Addr, Ipv6Addr, u8)>,
}

impl TunRoute {
    /// The route of the TUN inbound in `config`, if it has one with
    /// `auto_route` and the device is the instance's to route: a host that
    /// opens it routes it too.
    pub fn from_config(
        config: &crate::config::Config,
        host: &crate::runtime::Host,
    ) -> Result<Option<TunRoute>> {
        let Some(inbound) = config.inbounds.iter().find(|i| i.protocol == "tun") else {
            return Ok(None);
        };
        let settings = crate::protocol::tun::inbound::options(inbound)?;
        let host_opens = host
            .platform
            .as_ref()
            .is_some_and(|platform| platform.opens_tun());
        if !settings.auto_route || host_opens {
            return Ok(None);
        }
        let Some(ipv4) = settings.ipv4 else {
            return Err(anyhow!(
                "[{}] inbound: auto_route needs an IPv4 address on the tun",
                inbound.tag
            ));
        };
        use crate::protocol::tun::inbound::peer;
        Ok(Some(TunRoute {
            name: settings.name,
            address: ipv4.address(),
            gateway: peer(ipv4),
            netmask: ipv4.mask(),
            ipv6: settings
                .ipv6
                .map(|ipv6| (ipv6.address(), peer(ipv6), ipv6.network_length())),
        }))
    }
}

#[derive(Default)]
pub struct NetInfo {
    pub default_ipv4_gateway: Option<Ipv4Addr>,
    pub default_ipv6_gateway: Option<Ipv6Addr>,
    pub default_ipv4_address: Option<Ipv4Addr>,
    pub default_ipv6_address: Option<Ipv6Addr>,
    pub default_interface: Option<String>,
    /// The route set up, which is undone by the same description.
    pub route: Option<TunRoute>,
    /// The default routes the TUN replaces, as they were (Linux).
    pub saved_routes: Vec<String>,
    pub saved_routes6: Vec<String>,
}

/// Reads the default routes the TUN's routes replace. Fails without an IPv4
/// default gateway, which the TUN's route needs; a missing IPv6 one only
/// leaves IPv6 routing alone.
pub fn get_net_info(route: TunRoute) -> Result<NetInfo> {
    let iface = super::cmd::get_default_interface()?;

    let ipv4_gw = super::cmd::get_default_ipv4_gateway()?;
    let ipv4_gw = ipv4_gw.parse::<Ipv4Addr>().map_err(|_| {
        anyhow!(
            "default IPv4 gateway: \"{}\" is not an IPv4 address",
            ipv4_gw
        )
    })?;
    let ipv6 = route.ipv6.is_some();
    let ipv6_gw = if ipv6 {
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
    let ipv6_addr = if ipv6 {
        default_ifa.and_then(|ifa| {
            ifa.ips.iter().find_map(|ipn| match ipn.ip() {
                std::net::IpAddr::V6(ip) => Some(ip),
                std::net::IpAddr::V4(_) => None,
            })
        })
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let (saved_routes, saved_routes6) = (
        super::cmd::get_default_routes(false).unwrap_or_default(),
        if ipv6 {
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

    if let Some((address, gateway, prefix)) = route.ipv6 {
        super::cmd::add_interface_ipv6_address(&route.name, address, i32::from(prefix))?;

        if let Some(ipv6_gw) = ipv6_gw {
            super::cmd::delete_default_ipv6_route(None)?;
            super::cmd::add_default_ipv6_route(gateway, iface.clone(), true)?;
            super::cmd::add_default_ipv6_route(*ipv6_gw, iface.clone(), false)?;
        }

        #[cfg(target_os = "linux")]
        if let Some(a) = ipv6_addr {
            super::cmd::add_default_ipv6_rule(*a)?;
        }
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

    if route.ipv6.is_some() {
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
