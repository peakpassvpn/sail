//! The policy routing of a TUN with `auto_redirect`, as sing-tun's mark
//! mode has it (v0.9.6): the main table carries everything unmarked; a
//! packet marked for input, or one main and default have no route for, is
//! looked up in a table of the TUN's own; one marked as sail's own output
//! skips that table.
//!
//! ```text
//! 9000:  from all fwmark OUTPUT goto 9002
//! 9001:  from all fwmark INPUT lookup TABLE
//! 9002:  from all nop
//! 32768: not from all fwmark OUTPUT lookup TABLE
//! ```
//!
//! for each family the TUN has an address of, and in the table a route of
//! each `route_address` (all addresses without) through the TUN, with a
//! `throw` route of each `route_exclude_address`, so that those fall
//! through to the rules after it.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "linux")]
use anyhow::{anyhow, Result};
use cidr::IpInet;

use super::rtnetlink::{Family, Prefix, Route, RouteKind, Rule, RuleAction};

/// What the rules and routes are made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRoutes {
    pub tun: String,
    pub ipv4: bool,
    pub ipv6: bool,
    pub table: u32,
    pub rule_index: u32,
    pub fallback_rule_index: u32,
    pub input_mark: u32,
    pub output_mark: u32,
    pub route_address: Vec<IpInet>,
    pub route_exclude_address: Vec<IpInet>,
}

/// How many rule priorities from `rule_index` are sail's to remove.
const RULE_SPAN: u32 = 10;

impl PolicyRoutes {
    fn families(&self) -> impl Iterator<Item = Family> + '_ {
        [(Family::V4, self.ipv4), (Family::V6, self.ipv6)]
            .into_iter()
            .filter_map(|(family, on)| on.then_some(family))
    }

    /// The rules, in the order they are added.
    pub(crate) fn rules(&self) -> Vec<Rule> {
        let mut rules = Vec::new();
        for family in self.families() {
            let start = self.rule_index;
            rules.push(Rule {
                fwmark: Some((self.output_mark, u32::MAX)),
                ..Rule::new(family, start, RuleAction::Goto(start + 2))
            });
            rules.push(Rule {
                fwmark: Some((self.input_mark, u32::MAX)),
                ..Rule::new(family, start + 1, RuleAction::Lookup(self.table))
            });
            rules.push(Rule::new(family, start + 2, RuleAction::Nop));
            // After main (32766) and default (32767): only what they have
            // no route for, and never sail's own.
            rules.push(Rule {
                invert: true,
                fwmark: Some((self.output_mark, u32::MAX)),
                ..Rule::new(
                    family,
                    self.fallback_rule_index,
                    RuleAction::Lookup(self.table),
                )
            });
        }
        rules
    }

    /// The routes of the table, given the TUN's index.
    pub(crate) fn routes(&self, tun: u32) -> Vec<Route> {
        let mut routes = Vec::new();
        for family in self.families() {
            let v6 = family == Family::V6;
            let of_family = |inet: &&IpInet| inet.is_ipv6() == v6;
            let mut included: Vec<Prefix> = self
                .route_address
                .iter()
                .filter(of_family)
                .map(|inet| Prefix::new(inet.first_address(), inet.network_length()))
                .collect();
            if included.is_empty() {
                let all: IpAddr = if v6 {
                    Ipv6Addr::UNSPECIFIED.into()
                } else {
                    Ipv4Addr::UNSPECIFIED.into()
                };
                included.push(Prefix::new(all, 0));
            }
            for prefix in included {
                routes.push(Route::new(prefix, self.table).oif(tun));
            }
            for inet in self.route_exclude_address.iter().filter(of_family) {
                routes.push(
                    Route::new(
                        Prefix::new(inet.first_address(), inet.network_length()),
                        self.table,
                    )
                    .kind(RouteKind::Throw),
                );
            }
        }
        routes
    }

    /// Sets it up, after removing what an earlier run left. What fails
    /// fails the setup, and what was done is removed again.
    #[cfg(target_os = "linux")]
    pub(crate) fn setup(&self) -> Result<()> {
        let netlink = super::rtnetlink::Netlink::open()
            .map_err(|e| anyhow!("auto_redirect: routing: {}", e))?;
        self.cleanup_with(&netlink);
        let result = (|| -> std::io::Result<()> {
            let tun = netlink.link_index(&self.tun)?;
            for route in self.routes(tun) {
                netlink.add_route(&route)?;
            }
            for rule in self.rules() {
                netlink.add_rule(&rule)?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            self.cleanup_with(&netlink);
            return Err(anyhow!("auto_redirect: routing: {}", e));
        }
        Ok(())
    }

    /// Removes every rule of either family at the priorities sail uses,
    /// whatever made it, as sing-tun does, and the table's routes.
    #[cfg(target_os = "linux")]
    pub(crate) fn cleanup(&self) {
        match super::rtnetlink::Netlink::open() {
            Ok(netlink) => self.cleanup_with(&netlink),
            Err(e) => tracing::warn!("auto_redirect: removing the routing: {}", e),
        }
    }

    #[cfg(target_os = "linux")]
    fn cleanup_with(&self, netlink: &super::rtnetlink::Netlink) {
        for family in [Family::V4, Family::V6] {
            let priorities =
                (self.rule_index..=self.rule_index + RULE_SPAN).chain([self.fallback_rule_index]);
            for priority in priorities {
                let _ = netlink.del_rules_at(family, priority);
            }
            for route in netlink.routes_in(family, self.table).unwrap_or_default() {
                let _ = netlink.del_route(&route);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes() -> PolicyRoutes {
        PolicyRoutes {
            tun: "tun0".into(),
            ipv4: true,
            ipv6: true,
            table: 2022,
            rule_index: 9000,
            fallback_rule_index: 32768,
            input_mark: 0x2023,
            output_mark: 0x2024,
            route_address: Vec::new(),
            route_exclude_address: Vec::new(),
        }
    }

    #[test]
    fn sing_tun_s_mark_mode_rules_for_each_family() {
        let rules = routes().rules();
        assert_eq!(rules.len(), 8);
        for (family, rules) in [(Family::V4, &rules[..4]), (Family::V6, &rules[4..])] {
            let summary: Vec<_> = rules
                .iter()
                .map(|r| (r.family, r.priority, r.invert, r.fwmark, r.action))
                .collect();
            assert_eq!(
                summary,
                [
                    (
                        family,
                        9000,
                        false,
                        Some((0x2024, u32::MAX)),
                        RuleAction::Goto(9002)
                    ),
                    (
                        family,
                        9001,
                        false,
                        Some((0x2023, u32::MAX)),
                        RuleAction::Lookup(2022)
                    ),
                    (family, 9002, false, None, RuleAction::Nop),
                    (
                        family,
                        32768,
                        true,
                        Some((0x2024, u32::MAX)),
                        RuleAction::Lookup(2022)
                    ),
                ]
            );
        }
        let routes = routes().routes(7);
        assert_eq!(routes.len(), 2);
        assert!(routes
            .iter()
            .all(|r| r.dst.len == 0 && r.oif == Some(7) && r.table == 2022));
    }

    #[test]
    fn route_addresses_replace_the_default_and_excluded_ones_are_thrown() {
        let routes = PolicyRoutes {
            ipv6: false,
            route_address: vec![
                "10.1.2.3/8".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            route_exclude_address: vec!["10.9.0.0/16".parse().unwrap()],
            ..routes()
        }
        .routes(7);
        let summary: Vec<_> = routes
            .iter()
            .map(|r| (r.dst.addr.to_string(), r.dst.len, r.kind))
            .collect();
        assert_eq!(
            summary,
            [
                ("10.0.0.0".to_string(), 8, RouteKind::Unicast),
                ("10.9.0.0".to_string(), 16, RouteKind::Throw),
            ]
        );
    }
}
