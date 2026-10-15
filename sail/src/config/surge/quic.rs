//! Surge's `block-quic`: the policies whose QUIC is refused, so that the
//! app goes on over TCP, as `route.block_quic`, which the dispatcher
//! checks once the rules have chosen an outbound.
//!
//! A proxy's own `block-quic` is `on` or `off`; unset, or `auto` or
//! `adaptive`, Surge decides: DIRECT never, a proxy that relays no UDP or
//! relays it over its TCP connection always, and, in its newest versions,
//! one that relays UDP over UDP adaptively, refusing QUIC until the app
//! has shown it does not fall back. sail cannot tell that, and refuses
//! none of those (Shadowsocks, SOCKS5, Hysteria2, TUIC, WireGuard), where
//! QUIC goes as well as UDP does. The `[General]` `block-quic` overrides
//! the proxies' own: `all-proxy` refuses every proxy's, `always-allow`
//! none, `all` everyone's, DIRECT's too, by a rule of its own.
//!
//! A group is refused QUIC when every member it may take is: the member it
//! takes is chosen as a connection is made, and the rules know only the
//! group. One that may take DIRECT, an unrefused proxy, or a provider's,
//! whose members are not known here, is not refused.

use std::collections::{HashMap, HashSet};

use super::general::BlockQuic;
use super::group::Policies;
use super::proxy::{Kind, Proxies};

/// The policies whose QUIC is refused, by tag, in the proxies' order and
/// then the groups' as named.
pub fn blocked(mode: BlockQuic, proxies: &Proxies, policies: &Policies) -> Vec<String> {
    if matches!(mode, BlockQuic::All | BlockQuic::AlwaysAllow) {
        return Vec::new();
    }
    let mut known = HashMap::new();
    for name in &proxies.names {
        let refused = match proxies.kinds.get(name) {
            Some(Kind::Proxy { .. }) => match mode {
                BlockQuic::AllProxy => true,
                _ => proxies
                    .block_quic
                    .get(name)
                    .copied()
                    .unwrap_or(!proxies.native_udp.contains(name)),
            },
            _ => false,
        };
        known.insert(name.clone(), refused);
    }
    let mut out: Vec<String> = proxies
        .names
        .iter()
        .filter(|n| known[*n])
        .cloned()
        .collect();
    let mut groups: Vec<&String> = policies.group_names().collect();
    groups.sort();
    for group in groups {
        if refused(group, policies, &mut known, &mut HashSet::new()) {
            out.push(group.clone());
        }
    }
    out
}

/// Whether every member the policy `name` may take is refused QUIC; what
/// is neither a proxy nor a group (DIRECT, Surge's own) is not.
fn refused(
    name: &str,
    policies: &Policies,
    known: &mut HashMap<String, bool>,
    seen: &mut HashSet<String>,
) -> bool {
    if let Some(r) = known.get(name) {
        return *r;
    }
    let Some((members, providers)) = policies.group(name) else {
        return false;
    };
    // A group naming itself, through others, is no group of refused ones.
    if !seen.insert(name.to_string()) {
        return false;
    }
    let r = !providers
        && !members.is_empty()
        && members.iter().all(|m| refused(m, policies, known, seen));
    known.insert(name.to_string(), r);
    r
}
