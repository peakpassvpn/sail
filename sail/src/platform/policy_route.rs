//! The policy routing of a TUN with `auto_redirect`, as sing-tun's mark
//! mode has it: the main table carries everything unmarked; a packet
//! marked for input, or one main has no route for, is looked up in a table
//! of the TUN's own; one marked as sail's own output skips that table.
//!
//! ```text
//! 9000:  from all fwmark OUTPUT goto 9002
//! 9001:  from all fwmark INPUT lookup TABLE
//! 9002:  from all nop
//! 32768: from all lookup TABLE
//! ```
//!
//! for each family the TUN has an address of, and in the table a route of
//! each `route_address` (all addresses without) through the TUN, with a
//! `throw` route of each `route_exclude_address`, so that those fall
//! through to the rules after it.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::process::Command;

use anyhow::{anyhow, Result};
use cidr::IpInet;

use super::output;

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
    fn families(&self) -> impl Iterator<Item = bool> + '_ {
        [(false, self.ipv4), (true, self.ipv6)]
            .into_iter()
            .filter_map(|(v6, on)| on.then_some(v6))
    }

    /// The `ip` commands that set it up, in order.
    pub(crate) fn setup_commands(&self) -> Vec<Vec<String>> {
        let mut commands = Vec::new();
        for v6 in self.families() {
            let family = if v6 { "-6" } else { "-4" };
            let rule = |priority: u32, what: &[String]| {
                let mut args = vec![
                    family.to_string(),
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    priority.to_string(),
                ];
                args.extend_from_slice(what);
                args
            };
            let start = self.rule_index;
            commands.push(rule(
                start,
                &[
                    "fwmark".into(),
                    format!("{:#x}", self.output_mark),
                    "goto".into(),
                    (start + 2).to_string(),
                ],
            ));
            commands.push(rule(
                start + 1,
                &[
                    "fwmark".into(),
                    format!("{:#x}", self.input_mark),
                    "lookup".into(),
                    self.table.to_string(),
                ],
            ));
            commands.push(rule(start + 2, &["nop".into()]));
            commands.push(rule(
                self.fallback_rule_index,
                &["lookup".into(), self.table.to_string()],
            ));

            let of_family = |inet: &&IpInet| inet.is_ipv6() == v6;
            let mut included: Vec<String> = self
                .route_address
                .iter()
                .filter(of_family)
                .map(|inet| inet.network().to_string())
                .collect();
            if included.is_empty() {
                included.push(if v6 { "::/0" } else { "0.0.0.0/0" }.into());
            }
            for prefix in included {
                commands.push(vec![
                    family.into(),
                    "route".into(),
                    "add".into(),
                    prefix,
                    "dev".into(),
                    self.tun.clone(),
                    "table".into(),
                    self.table.to_string(),
                ]);
            }
            for inet in self.route_exclude_address.iter().filter(of_family) {
                commands.push(vec![
                    family.into(),
                    "route".into(),
                    "add".into(),
                    "throw".into(),
                    inet.network().to_string(),
                    "table".into(),
                    self.table.to_string(),
                ]);
            }
        }
        commands
    }

    /// Sets it up, after removing what an earlier run left. A command that
    /// fails fails the setup, and what was done is removed again.
    pub(crate) fn setup(&self) -> Result<()> {
        self.cleanup();
        for args in self.setup_commands() {
            if let Err(e) = output(Command::new("ip").args(&args)) {
                self.cleanup();
                return Err(anyhow!("auto_redirect: routing: {:#}", e));
            }
        }
        Ok(())
    }

    /// Removes every rule of either family at the priorities sail uses,
    /// whatever made it, as sing-tun does, and the table's routes.
    pub(crate) fn cleanup(&self) {
        for family in ["-4", "-6"] {
            let priorities =
                (self.rule_index..=self.rule_index + RULE_SPAN).chain([self.fallback_rule_index]);
            for priority in priorities {
                // Several rules may share a priority: remove until none is left.
                for _ in 0..16 {
                    let removed = Command::new("ip")
                        .args([family, "rule", "del", "priority", &priority.to_string()])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .is_ok_and(|s| s.success());
                    if !removed {
                        break;
                    }
                }
            }
            let _ = Command::new("ip")
                .args([family, "route", "flush", "table", &self.table.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
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

    fn lines(routes: &PolicyRoutes) -> Vec<String> {
        routes
            .setup_commands()
            .iter()
            .map(|args| args.join(" "))
            .collect()
    }

    #[test]
    fn sing_tun_s_mark_mode_rules_for_each_family() {
        assert_eq!(
            lines(&routes()),
            [
                "-4 rule add priority 9000 fwmark 0x2024 goto 9002",
                "-4 rule add priority 9001 fwmark 0x2023 lookup 2022",
                "-4 rule add priority 9002 nop",
                "-4 rule add priority 32768 lookup 2022",
                "-4 route add 0.0.0.0/0 dev tun0 table 2022",
                "-6 rule add priority 9000 fwmark 0x2024 goto 9002",
                "-6 rule add priority 9001 fwmark 0x2023 lookup 2022",
                "-6 rule add priority 9002 nop",
                "-6 rule add priority 32768 lookup 2022",
                "-6 route add ::/0 dev tun0 table 2022",
            ]
        );
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
        };
        let lines = lines(&routes);
        assert_eq!(
            &lines[4..],
            [
                "-4 route add 10.0.0.0/8 dev tun0 table 2022",
                "-4 route add throw 10.9.0.0/16 table 2022",
            ]
        );
    }
}
