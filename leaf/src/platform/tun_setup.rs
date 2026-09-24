use crate::option;

#[derive(Default)]
pub struct NetInfo {
    pub default_ipv4_gateway: Option<String>,
    pub default_ipv6_gateway: Option<String>,
    pub default_ipv4_address: Option<String>,
    pub default_ipv6_address: Option<String>,
    pub ipv4_forwarding: bool,
    pub ipv6_forwarding: bool,
    pub default_interface: Option<String>,
}

pub fn get_net_info() -> NetInfo {
    let iface = super::cmd::get_default_interface().unwrap();

    let ipv4_gw = super::cmd::get_default_ipv4_gateway().unwrap();
    let ipv6_gw = if *option::ENABLE_IPV6 {
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
    let ipv6_addr = if *option::ENABLE_IPV6 {
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
    let ipv6_forwarding = if *option::ENABLE_IPV6 {
        super::cmd::get_ipv6_forwarding().unwrap()
    } else {
        false
    };

    NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        ipv4_forwarding,
        ipv6_forwarding,
        default_interface: Some(iface),
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
    } = net_info
    {
        use std::net::{Ipv4Addr, Ipv6Addr};
        super::cmd::add_interface_ipv4_address(
            &option::DEFAULT_TUN_NAME,
            (*option::DEFAULT_TUN_IPV4_ADDR)
                .parse::<Ipv4Addr>()
                .unwrap(),
            (*option::DEFAULT_TUN_IPV4_GW).parse::<Ipv4Addr>().unwrap(),
            (*option::DEFAULT_TUN_IPV4_MASK)
                .parse::<Ipv4Addr>()
                .unwrap(),
        )
        .unwrap();
        super::cmd::delete_default_ipv4_route(None).unwrap();

        super::cmd::add_default_ipv4_route(
            option::DEFAULT_TUN_IPV4_GW.parse::<Ipv4Addr>().unwrap(),
            iface.clone(),
            true,
        )
        .unwrap();
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

        if *option::GATEWAY_MODE && !ipv4_forwarding {
            super::cmd::set_ipv4_forwarding(true).unwrap();
        }

        if *option::ENABLE_IPV6 {
            super::cmd::add_interface_ipv6_address(
                &option::DEFAULT_TUN_NAME,
                option::DEFAULT_TUN_IPV6_ADDR.parse::<Ipv6Addr>().unwrap(),
                *option::DEFAULT_TUN_IPV6_PREFIXLEN,
            )
            .unwrap();

            if let Some(ipv6_gw) = ipv6_gw {
                super::cmd::delete_default_ipv6_route(None).unwrap();
                super::cmd::add_default_ipv6_route(
                    option::DEFAULT_TUN_IPV6_GW.parse::<Ipv6Addr>().unwrap(),
                    iface.clone(),
                    true,
                )
                .unwrap();
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

            if *option::GATEWAY_MODE && !ipv6_forwarding {
                super::cmd::set_ipv6_forwarding(true).unwrap();
            }
        }

        #[cfg(target_os = "linux")]
        {
            if *option::GATEWAY_MODE {
                super::cmd::add_iptable_forward(&option::DEFAULT_TUN_NAME).unwrap();
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
    } = &net_info
    {
        use std::net::{Ipv4Addr, Ipv6Addr};
        super::cmd::delete_default_ipv4_route(None).unwrap();
        super::cmd::delete_default_ipv4_route(Some(iface.clone())).unwrap();

        super::cmd::add_default_ipv4_route(
            ipv4_gw.parse::<Ipv4Addr>().unwrap(),
            iface.clone(),
            true,
        )
        .unwrap();

        #[cfg(target_os = "linux")]
        {
            if let Some(a) = ipv4_addr {
                super::cmd::delete_default_ipv4_rule(a.parse::<Ipv4Addr>().unwrap()).unwrap();
            }
        }

        if *option::GATEWAY_MODE && !ipv4_forwarding {
            super::cmd::set_ipv4_forwarding(false).unwrap();
        }

        if *option::ENABLE_IPV6 {
            if let Some(ipv6_gw) = ipv6_gw {
                super::cmd::delete_default_ipv6_route(None).unwrap();
                super::cmd::delete_default_ipv6_route(Some(iface.clone())).unwrap();
                super::cmd::add_default_ipv6_route(
                    ipv6_gw.parse::<Ipv6Addr>().unwrap(),
                    iface.clone(),
                    true,
                )
                .unwrap();
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(a) = ipv6_addr {
                    super::cmd::delete_default_ipv6_rule(a.parse::<Ipv6Addr>().unwrap()).unwrap();
                }
            }

            if *option::GATEWAY_MODE && !ipv6_forwarding {
                super::cmd::set_ipv6_forwarding(false).unwrap();
            }
        }

        #[cfg(target_os = "linux")]
        {
            if *option::GATEWAY_MODE {
                super::cmd::delete_iptable_forward(&option::DEFAULT_TUN_NAME).unwrap();
            }
        }
    }
}
