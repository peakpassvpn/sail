//! Linux: systemd-resolved's split DNS, where resolv.conf is its stub: a
//! link's servers answer the names under its domains, its routing-only
//! ones ("~corp.example") and its search ones alike, as resolved routes
//! them; "~." (every name) makes none. As `resolvectl dns` and
//! `resolvectl domain` list them, link by link. A link of another network
//! namespace's resolved (sail in a namespace of its own reads the host's)
//! that is not here is left out.

/// Each link's name and items, of `resolvectl dns` or `resolvectl domain`:
/// "Link 5 (tun0): 10.0.0.53 fe80::1%5". The global line has no link.
pub(super) fn links(text: &str) -> Vec<(String, Vec<String>)> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("Link ")?;
            let (_, rest) = rest.split_once(" (")?;
            let (name, items) = rest.split_once("):")?;
            Some((
                name.to_owned(),
                items.split_whitespace().map(str::to_owned).collect(),
            ))
        })
        .collect()
}

/// The split resolvers of `dns` and `domain`, the outputs of `resolvectl
/// dns` and `resolvectl domain`: each link with servers and a domain.
pub(super) fn split(dns: &str, domain: &str) -> Vec<super::Split> {
    let domains = links(domain);
    links(dns)
        .into_iter()
        .filter_map(|(link, servers)| {
            let (_, names) = domains.iter().find(|(l, _)| *l == link)?;
            let domains: Vec<String> = names
                .iter()
                .filter_map(|d| super::domain(d.trim_start_matches('~')))
                .collect();
            let servers: Vec<super::Listed> = servers
                .iter()
                .filter_map(|s| super::Listed::parse(s))
                .collect();
            (!domains.is_empty() && !servers.is_empty()).then_some(super::Split {
                domains,
                servers,
                interface: Some(link),
            })
        })
        .collect()
}

/// resolved's split resolvers on the links of this namespace; none where
/// resolvectl does not answer.
#[cfg(target_os = "linux")]
pub(super) fn read() -> Vec<super::Split> {
    let run = |what: &str| {
        let out = std::process::Command::new("resolvectl")
            .args(["--no-pager", what])
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let (Some(dns), Some(domain)) = (run("dns"), run("domain")) else {
        return Vec::new();
    };
    split(&dns, &domain)
        .into_iter()
        .filter(|s| s.interface.as_deref().and_then(super::index_of).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNS: &str = "Global:\nLink 2 (eth0): 192.168.1.1 fe80::1%2\nLink 5 (tun0): 10.0.0.53\n\
                       Link 7 (wg0):\nLink 9 (sail): 172.19.0.2\n";
    const DOMAIN: &str = "Global:\nLink 2 (eth0): lan\nLink 5 (tun0): ~Corp.Example vpn.example\n\
                          Link 7 (wg0): ~wg.example\nLink 9 (sail): ~.\n";

    #[test]
    fn resolvectl_s_links_are_read() {
        let links = links(DNS);
        assert_eq!(
            links[0],
            (
                "eth0".into(),
                vec!["192.168.1.1".into(), "fe80::1%2".into()]
            )
        );
        assert_eq!(links[2], ("wg0".into(), Vec::<String>::new()));
        assert_eq!(links.len(), 4);
    }

    /// A link's routing and search domains route to its servers; a link
    /// with no servers, or only "~.", makes no split resolver.
    #[test]
    fn a_link_s_domains_route_to_its_servers() {
        let split = split(DNS, DOMAIN);
        let names: Vec<(&str, Vec<&str>)> = split
            .iter()
            .map(|s| {
                (
                    s.interface.as_deref().unwrap(),
                    s.domains.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            names,
            [
                ("eth0", vec!["lan"]),
                ("tun0", vec!["corp.example", "vpn.example"])
            ]
        );
        assert_eq!(split[1].servers[0].ip.to_string(), "10.0.0.53");
    }
}
