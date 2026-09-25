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
    pub default_ipv4_gateway: Option<String>,
    pub default_ipv6_gateway: Option<String>,
    pub default_ipv4_address: Option<String>,
    pub default_ipv6_address: Option<String>,
    pub ipv4_forwarding: bool,
    pub ipv6_forwarding: bool,
    pub default_interface: Option<String>,
    /// The route set up, which is undone by the same description.
    pub route: Option<TunRoute>,
    /// The default routes the TUN replaces, as they were (Linux).
    pub saved_routes: Vec<String>,
    pub saved_routes6: Vec<String>,
}

pub fn get_net_info(route: TunRoute) -> NetInfo {
    let iface = super::cmd::get_default_interface().unwrap();

    let ipv4_gw = super::cmd::get_default_ipv4_gateway().unwrap();
    let ipv6_gw = if route.ipv6 {
        Some(super::cmd::get_default_ipv6_gateway().unwrap())
    } else {
        None
    };

    let all_interfaces = pnet_datalink::interfaces();
    let ipv4_addr = if let Some(ifa) = all_interfaces
        .iter()
        .find(|ifa| ifa.name == iface && !ifa.ips.is_empty())
    {
        ifa.ips
            .iter()
            .find(|ipn| ipn.is_ipv4())
            .map(|ipn| ipn.ip().to_string())
    } else {
        None
    };
    let ipv6_addr = if route.ipv6 {
        if let Some(ifa) = all_interfaces
            .iter()
            .find(|ifa| ifa.name == iface && !ifa.ips.is_empty())
        {
            ifa.ips
                .iter()
                .find(|ipn| ipn.is_ipv6())
                .map(|ipn| ipn.ip().to_string())
        } else {
            None
        }
    } else {
        None
    };
    let ipv4_forwarding = super::cmd::get_ipv4_forwarding().unwrap();
    let ipv6_forwarding = if route.ipv6 {
        super::cmd::get_ipv6_forwarding().unwrap()
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

    NetInfo {
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
    }
}

pub fn post_tun_creation_setup(net_info: &NetInfo) {
    #[allow(unused_variables)]
    if let NetInfo {
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
    {
        super::cmd::add_interface_ipv4_address(
            &route.name,
            route.address,
            route.gateway,
            route.netmask,
        )
        .unwrap();
        super::cmd::delete_default_ipv4_route(None).unwrap();

        super::cmd::add_default_ipv4_route(route.gateway, iface.clone(), true).unwrap();
        super::cmd::add_default_ipv4_route(
            ipv4_gw.parse::<Ipv4Addr>().unwrap(),
            iface.clone(),
            false,
        )
        .unwrap();

        #[cfg(target_os = "linux")]
        {
            if let Some(a) = ipv4_addr {
                super::cmd::add_default_ipv4_rule(a.parse::<Ipv4Addr>().unwrap()).unwrap();
            }
        }

        if route.gateway_mode && !ipv4_forwarding {
            super::cmd::set_ipv4_forwarding(true).unwrap();
        }

        if route.ipv6 {
            super::cmd::add_interface_ipv6_address(
                &route.name,
                TUN_IPV6_ADDRESS,
                TUN_IPV6_PREFIX_LEN,
            )
            .unwrap();

            if let Some(ipv6_gw) = ipv6_gw {
                super::cmd::delete_default_ipv6_route(None).unwrap();
                super::cmd::add_default_ipv6_route(TUN_IPV6_GATEWAY, iface.clone(), true).unwrap();
                super::cmd::add_default_ipv6_route(
                    ipv6_gw.parse::<Ipv6Addr>().unwrap(),
                    iface.clone(),
                    false,
                )
                .unwrap();
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(a) = ipv6_addr {
                    super::cmd::add_default_ipv6_rule(a.parse::<Ipv6Addr>().unwrap()).unwrap();
                }
            }

            if route.gateway_mode && !ipv6_forwarding {
                super::cmd::set_ipv6_forwarding(true).unwrap();
            }
        }

        #[cfg(target_os = "linux")]
        {
            if route.gateway_mode {
                super::cmd::add_iptable_forward(&route.name).unwrap();
            }
        }
    }
}

pub fn post_tun_completion_setup(net_info: &NetInfo) {
    #[allow(unused_variables)]
    if let NetInfo {
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
    } = &net_info
    {
        super::cmd::delete_default_ipv4_route(None).unwrap();
        super::cmd::delete_default_ipv4_route(Some(iface.clone())).unwrap();

        restore_default_route(false, saved_routes, || {
            super::cmd::add_default_ipv4_route(
                ipv4_gw.parse::<Ipv4Addr>().unwrap(),
                iface.clone(),
                true,
            )
        });

        #[cfg(target_os = "linux")]
        {
            if let Some(a) = ipv4_addr {
                super::cmd::delete_default_ipv4_rule(a.parse::<Ipv4Addr>().unwrap()).unwrap();
            }
        }

        if route.gateway_mode && !ipv4_forwarding {
            super::cmd::set_ipv4_forwarding(false).unwrap();
        }

        if route.ipv6 {
            if let Some(ipv6_gw) = ipv6_gw {
                super::cmd::delete_default_ipv6_route(None).unwrap();
                super::cmd::delete_default_ipv6_route(Some(iface.clone())).unwrap();
                restore_default_route(true, saved_routes6, || {
                    super::cmd::add_default_ipv6_route(
                        ipv6_gw.parse::<Ipv6Addr>().unwrap(),
                        iface.clone(),
                        true,
                    )
                });
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(a) = ipv6_addr {
                    super::cmd::delete_default_ipv6_rule(a.parse::<Ipv6Addr>().unwrap()).unwrap();
                }
            }

            if route.gateway_mode && !ipv6_forwarding {
                super::cmd::set_ipv6_forwarding(false).unwrap();
            }
        }

        #[cfg(target_os = "linux")]
        {
            if route.gateway_mode {
                super::cmd::delete_iptable_forward(&route.name).unwrap();
            }
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
