//! The `NETLINK_ROUTE` socket: one request at a time, each waited for.

use std::io;
use std::net::IpAddr;
use std::sync::Mutex;

use super::super::nft::netlink::{messages, put_message};
use super::super::nft::socket::{first_seq, parse_error, Socket};
use super::super::nft::sys::*;
use super::encode::{self, Request};
use super::{DefaultRoute, Error, Family, Prefix, Route, Rule};

/// How many times a dump the kernel interrupted (`NLM_F_DUMP_INTR`: the
/// routes changed while it was being read) is started over before giving
/// up. A judgment call: a change is rare, and one while starting over
/// rarer still.
const DUMP_ATTEMPTS: usize = 5;

/// How many rules `del_rules_at` deletes at most; only so a kernel that
/// keeps answering yes cannot loop it forever.
const MAX_RULES_AT: usize = 4096;

/// A `NETLINK_ROUTE` socket. Its calls block until the kernel answers,
/// which it does within the call for everything here. They may be made
/// from several threads: one request is on the socket at a time.
pub struct Netlink {
    inner: Mutex<Inner>,
}

struct Inner {
    socket: Socket,
    seq: u32,
}

impl Netlink {
    pub fn open() -> io::Result<Netlink> {
        let socket = Socket::open_protocol(libc::NETLINK_ROUTE)?;
        Ok(Netlink {
            inner: Mutex::new(Inner {
                socket,
                seq: first_seq(),
            }),
        })
    }

    pub fn add_route(&self, r: &Route) -> io::Result<()> {
        self.ack(encode::route(r, true)?)
    }

    pub fn del_route(&self, r: &Route) -> io::Result<()> {
        self.ack(encode::route(r, false)?)
    }

    pub fn add_rule(&self, r: &Rule) -> io::Result<()> {
        self.ack(encode::rule(r, true)?)
    }

    pub fn del_rule(&self, r: &Rule) -> io::Result<()> {
        self.ack(encode::rule(r, false)?)
    }

    /// Deletes every rule of `family` at `priority`, whatever it is;
    /// returns how many.
    pub fn del_rules_at(&self, family: Family, priority: u32) -> io::Result<usize> {
        for deleted in 0..MAX_RULES_AT {
            match self.ack(encode::del_rule_at(family, priority)) {
                Ok(()) => {}
                Err(e) if super::errno(&e) == Some(libc::ENOENT) => return Ok(deleted),
                Err(e) => return Err(e),
            }
        }
        Err(Error {
            what: format!("deleting the rules at {} ({})", priority, family),
            errno: libc::ELOOP,
            message: Some(format!("still more after {}", MAX_RULES_AT)),
        }
        .into_io())
    }

    /// The index of the link called `name`; `ENODEV` if there is none.
    pub fn link_index(&self, name: &str) -> io::Result<u32> {
        let req = encode::get_link(Ok(name));
        let what = req.what.clone();
        self.transact(req)?
            .iter()
            .find_map(|body| encode::parse_link(body))
            .map(|(index, _)| index)
            .ok_or_else(|| no_answer(what))
    }

    /// The name of link `index`; `ENODEV` if there is none.
    pub fn link_name(&self, index: u32) -> io::Result<String> {
        let req = encode::get_link(Err(index));
        let what = req.what.clone();
        self.transact(req)?
            .into_iter()
            .find_map(|body| encode::parse_link(&body))
            .map(|(_, name)| name)
            .ok_or_else(|| no_answer(what))
    }

    /// Adds `addr` to link `index`, with `peer` at the other end of a
    /// point-to-point link. Having it already is not an error.
    pub fn add_address(&self, index: u32, addr: Prefix, peer: Option<IpAddr>) -> io::Result<()> {
        match self.ack(encode::add_address(index, addr, peer)?) {
            Err(e) if super::errno(&e) == Some(libc::EEXIST) => Ok(()),
            other => other,
        }
    }

    /// Brings link `index` up, and sets its MTU if given.
    pub fn set_link_up(&self, index: u32, mtu: Option<u32>) -> io::Result<()> {
        self.ack(encode::set_link_up(index, mtu))
    }

    /// The default routes (dst len 0) of the main table, by metric.
    pub fn default_routes(&self, family: Family) -> io::Result<Vec<DefaultRoute>> {
        let what = format!("listing the default routes ({})", family);
        Ok(encode::default_routes(self.dump_routes(family, what)?))
    }

    /// The routes of `table` (a dump), so they can be deleted.
    pub fn routes_in(&self, family: Family, table: u32) -> io::Result<Vec<Route>> {
        let what = format!("listing the routes of table {} ({})", table, family);
        Ok(encode::routes_in(self.dump_routes(family, what)?, table))
    }

    fn dump_routes(&self, family: Family, what: String) -> io::Result<Vec<encode::DumpedRoute>> {
        Ok(self
            .transact(encode::dump_routes(family, what))?
            .iter()
            .filter_map(|body| encode::parse_route(body))
            .filter(|r| r.family == family)
            .collect())
    }

    /// Sends a request whose answer is only an acknowledgement.
    fn ack(&self, req: Request) -> io::Result<()> {
        self.transact(req).map(drop)
    }

    /// Sends `req` and reads the answer to it: the bodies of the messages
    /// before the acknowledgement or, for a dump, before its end. A dump
    /// the kernel interrupted is started over.
    fn transact(&self, req: Request) -> io::Result<Vec<Vec<u8>>> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..DUMP_ATTEMPTS {
            inner.seq = inner.seq.wrapping_add(1);
            let seq = inner.seq;
            let mut wire = Vec::new();
            put_message(&mut wire, req.ty, NLM_F_REQUEST | req.flags, seq, &req.body);
            inner
                .socket
                .send(&wire)
                .map_err(|e| socket_error(e, &req.what))?;
            match read_answer(&inner.socket, seq, &req.what)? {
                Some(bodies) => return Ok(bodies),
                None => continue,
            }
        }
        Err(Error {
            what: req.what,
            errno: libc::EINTR,
            message: Some(format!(
                "the dump was interrupted {} times by changes",
                DUMP_ATTEMPTS
            )),
        }
        .into_io())
    }
}

/// Reads the answer to request `seq`: None if it was a dump the kernel
/// interrupted.
pub(in crate::platform) fn read_answer(
    socket: &Socket,
    seq: u32,
    what: &str,
) -> io::Result<Option<Vec<Vec<u8>>>> {
    let mut bodies = Vec::new();
    let mut interrupted = false;
    loop {
        let dgram = socket.recv().map_err(|e| socket_error(e, what))?;
        for msg in messages(&dgram) {
            let msg = msg.map_err(|e| protocol(what, e))?;
            // Answers to an earlier request, given up on, are skipped.
            if msg.seq != seq {
                continue;
            }
            interrupted |= msg.flags & NLM_F_DUMP_INTR != 0;
            match msg.ty {
                NLMSG_ERROR => {
                    let (errno, message) = parse_error(msg.flags, msg.body)
                        .map_err(|e| protocol(what, &e.to_string()))?;
                    if errno != 0 {
                        return Err(Error {
                            what: what.to_owned(),
                            errno,
                            message,
                        }
                        .into_io());
                    }
                    return Ok(Some(bodies));
                }
                NLMSG_DONE => {
                    // A dump that failed part way says so here.
                    let status = msg
                        .body
                        .get(..4)
                        .map_or(0, |b| -i32::from_ne_bytes(b.try_into().unwrap()));
                    if status > 0 {
                        return Err(Error {
                            what: what.to_owned(),
                            errno: status,
                            message: None,
                        }
                        .into_io());
                    }
                    return Ok(if interrupted { None } else { Some(bodies) });
                }
                _ => bodies.push(msg.body.to_vec()),
            }
        }
    }
}

/// A failed send or receive, with what was being done. A receive that
/// timed out means the kernel never answered.
fn socket_error(e: io::Error, what: &str) -> io::Error {
    match e.raw_os_error() {
        Some(errno) => Error {
            what: what.to_owned(),
            errno,
            message: (errno == libc::EAGAIN).then(|| "no answer from the kernel".to_owned()),
        }
        .into_io(),
        None => io::Error::new(e.kind(), format!("{}: {}", what, e)),
    }
}

fn protocol(what: &str, e: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{}: {}", what, e))
}

/// The kernel acknowledged a lookup without answering it.
fn no_answer(what: String) -> io::Error {
    protocol(&what, "acknowledged without an answer")
}

#[cfg(test)]
mod tests {
    //! Against the kernel: root, and only inside a network namespace made
    //! for them, which they refuse to run outside of --
    //!
    //! ```text
    //! ip netns add sail-rtnl-test
    //! ip netns exec sail-rtnl-test <test binary> --ignored rtnetlink --test-threads 1
    //! ip netns del sail-rtnl-test
    //! ```
    //!
    //! They read back what they did with ip(8), `$SAIL_IP` or `ip`.

    use std::net::IpAddr;
    use std::process::Command;

    use super::super::*;

    fn ip(args: &[&str]) -> String {
        let bin = std::env::var("SAIL_IP").unwrap_or_else(|_| "ip".into());
        let out = Command::new(&bin)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("cannot run {}: {}", bin, e));
        assert!(
            out.status.success(),
            "ip {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// Panics unless this runs in a named network namespace (`ip netns
    /// exec`), so the host's own routing is never touched.
    fn in_test_netns() {
        let name = ip(&["netns", "identify"]);
        assert!(
            !name.trim().is_empty(),
            "run these only under `ip netns exec <a throwaway namespace>`"
        );
    }

    /// A fresh dummy link, down, called `name`.
    fn dummy(name: &str) {
        let _ = Command::new("ip")
            .args(["link", "del", name])
            .stderr(std::process::Stdio::null())
            .status();
        ip(&["link", "add", name, "type", "dummy"]);
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn prefix(s: &str) -> Prefix {
        let (a, len) = s.split_once('/').unwrap();
        Prefix::new(addr(a), len.parse().unwrap())
    }

    /// `out` with each line's trailing blanks trimmed, as ip(8) leaves a
    /// space at the end of some.
    fn lines(out: &str) -> String {
        out.lines()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The rules sing-tun's auto_route adds, and more: every selector and
    /// action this encodes, read back by ip(8).
    fn rules() -> Vec<Rule> {
        let lookup = |family, priority| Rule::new(family, priority, RuleAction::Lookup(2022));
        let mut v = vec![
            lookup(Family::V4, 9000),
            Rule::new(Family::V4, 9001, RuleAction::Goto(9010)),
            Rule::new(Family::V4, 9002, RuleAction::Nop),
            Rule::new(Family::V4, 9003, RuleAction::Unreachable),
        ];
        let mut r = Rule::new(Family::V4, 9004, RuleAction::Lookup(254));
        r.invert = true;
        r.dport = Some((53, 53));
        r.suppress_prefixlength = Some(0);
        v.push(r);
        let mut r = lookup(Family::V4, 9005);
        r.src = Some(prefix("0.0.0.0/32"));
        r.iif = Some("lo".into());
        v.push(r);
        let mut r = lookup(Family::V4, 9006);
        r.uid_range = Some((1000, 2000));
        v.push(r);
        let mut r = lookup(Family::V4, 9007);
        r.fwmark = Some((0x2023, 0xffff));
        v.push(r);
        let mut r = Rule::new(Family::V4, 9008, RuleAction::Lookup(100));
        r.dst = Some(prefix("10.0.0.0/8"));
        r.oif = Some("sailrtnl0".into());
        r.ip_proto = Some(6);
        r.sport = Some((1000, 2000));
        v.push(r);
        let mut r = lookup(Family::V6, 9000);
        r.src = Some(prefix("::/1"));
        v.push(r);
        let mut r = Rule::new(Family::V6, 9001, RuleAction::Lookup(254));
        r.invert = true;
        r.ip_proto = Some(17);
        r.dport = Some((53, 53));
        r.suppress_prefixlength = Some(0);
        v.push(r);
        v.push(Rule::new(Family::V6, 9002, RuleAction::Unreachable));
        v
    }

    #[test]
    #[ignore = "root, in a throwaway network namespace"]
    fn rtnetlink_rules() {
        in_test_netns();
        dummy("sailrtnl0");
        let nl = Netlink::open().unwrap();
        for r in rules() {
            nl.add_rule(&r).unwrap();
        }
        let v4 = lines(&ip(&["rule", "show"]));
        let v6 = lines(&ip(&["-6", "rule", "show"]));
        println!("ip rule show:\n{}\nip -6 rule show:\n{}", v4, v6);
        assert_eq!(
            v4,
            "0:\tfrom all lookup local\n\
             9000:\tfrom all lookup 2022\n\
             9001:\tfrom all goto 9010 [unresolved]\n\
             9002:\tfrom all nop\n\
             9003:\tfrom all unreachable\n\
             9004:\tnot from all dport 53 lookup main suppress_prefixlength 0\n\
             9005:\tfrom 0.0.0.0 iif lo lookup 2022\n\
             9006:\tfrom all uidrange 1000-2000 lookup 2022\n\
             9007:\tfrom all fwmark 0x2023/0xffff lookup 2022\n\
             9008:\tfrom all to 10.0.0.0/8 oif sailrtnl0 ipproto tcp sport 1000-2000 lookup 100\n\
             32766:\tfrom all lookup main\n\
             32767:\tfrom all lookup default"
        );
        assert_eq!(
            v6,
            "0:\tfrom all lookup local\n\
             9000:\tfrom ::/1 lookup 2022\n\
             9001:\tnot from all ipproto udp dport 53 lookup main suppress_prefixlength 0\n\
             9002:\tfrom all unreachable\n\
             32766:\tfrom all lookup main"
        );

        // Adding one again: EEXIST, with what was being done.
        let e = nl.add_rule(&rules()[1]).unwrap_err();
        assert_eq!(errno(&e), Some(libc::EEXIST));
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert!(
            e.to_string().starts_with("adding rule 9001 (v4): EEXIST"),
            "{}",
            e
        );

        // Deleting one by what it is.
        for r in rules()
            .iter()
            .filter(|r| r.priority == 9005 || r.priority == 9008)
        {
            nl.del_rule(r).unwrap();
        }
        let e = nl.del_rule(&rules()[5]).unwrap_err();
        assert_eq!(errno(&e), Some(libc::ENOENT), "{}", e);

        // Deleting whatever is at a priority: two different rules at 9003,
        // v4, and v6's rule at 9002 left alone.
        let mut r = Rule::new(Family::V4, 9003, RuleAction::Lookup(2022));
        r.fwmark = Some((1, 1));
        nl.add_rule(&r).unwrap();
        assert_eq!(nl.del_rules_at(Family::V4, 9003).unwrap(), 2);
        assert_eq!(nl.del_rules_at(Family::V4, 9003).unwrap(), 0);
        assert_eq!(nl.del_rules_at(Family::V4, 9002).unwrap(), 1);
        for p in [9000, 9001, 9004, 9006, 9007] {
            assert_eq!(nl.del_rules_at(Family::V4, p).unwrap(), 1, "{}", p);
        }
        assert_eq!(
            lines(&ip(&["rule", "show"])),
            "0:\tfrom all lookup local\n\
             32766:\tfrom all lookup main\n\
             32767:\tfrom all lookup default"
        );
        assert!(lines(&ip(&["-6", "rule", "show"])).contains("9002:\tfrom all unreachable"));
        for p in [9000, 9001, 9002] {
            assert_eq!(nl.del_rules_at(Family::V6, p).unwrap(), 1, "{}", p);
        }
        let _ = Command::new("ip")
            .args(["link", "del", "sailrtnl0"])
            .status();
    }

    #[test]
    #[ignore = "root, in a throwaway network namespace"]
    fn rtnetlink_links_addresses_routes() {
        in_test_netns();
        dummy("sailrtnl1");
        let nl = Netlink::open().unwrap();

        // Links.
        let index = nl.link_index("sailrtnl1").unwrap();
        assert_eq!(nl.link_name(index).unwrap(), "sailrtnl1");
        assert_eq!(nl.link_index("lo").unwrap(), 1);
        assert_eq!(nl.link_name(1).unwrap(), "lo");
        let e = nl.link_index("sail-none").unwrap_err();
        assert_eq!(errno(&e), Some(libc::ENODEV), "{}", e);
        assert!(e
            .to_string()
            .starts_with("looking up link sail-none: ENODEV"));
        assert_eq!(errno(&nl.link_name(99999).unwrap_err()), Some(libc::ENODEV));

        nl.set_link_up(1, None).unwrap();
        nl.set_link_up(index, Some(1400)).unwrap();
        let link = ip(&["link", "show", "sailrtnl1"]);
        assert!(
            link.contains("<BROADCAST,NOARP,UP,LOWER_UP> mtu 1400"),
            "{}",
            link
        );

        // Addresses: again is fine.
        for _ in 0..2 {
            nl.add_address(index, prefix("172.19.0.1/30"), None)
                .unwrap();
            nl.add_address(index, prefix("10.2.0.1/32"), Some(addr("10.2.0.2")))
                .unwrap();
            nl.add_address(index, prefix("fdfe:dcba:9876::1/126"), None)
                .unwrap();
        }
        let addrs = ip(&["-o", "addr", "show", "dev", "sailrtnl1"]);
        let addrs: Vec<_> = addrs
            .lines()
            .map(|l| {
                l.split_whitespace()
                    .skip(2)
                    .take(4)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .filter(|l| !l.contains("fe80"))
            .collect();
        assert_eq!(
            addrs,
            [
                "inet 172.19.0.1/30 scope global",
                "inet 10.2.0.1 peer 10.2.0.2/32",
                "inet6 fdfe:dcba:9876::1/126 scope global",
            ],
        );

        // Routes in table 2022.
        let v4 = |p| prefix(p);
        let routes = [
            Route::new(v4("0.0.0.0/0"), 2022).oif(index),
            Route::new(v4("10.0.0.0/8"), 2022)
                .gateway(addr("172.19.0.2"))
                .metric(5),
            Route::new(v4("192.168.0.0/16"), 2022).kind(RouteKind::Throw),
            Route::new(v4("1.2.3.0/24"), 2022).kind(RouteKind::Unreachable),
            Route::new(v4("198.18.0.0/15"), 2022).oif(index).metric(100),
            Route::new(prefix("::/0"), 2022).oif(index),
            Route::new(prefix("2001:db8::/32"), 2022)
                .kind(RouteKind::Unreachable)
                .metric(7),
            Route::new(prefix("64:ff9b::/96"), 2022)
                .gateway(addr("fdfe:dcba:9876::2"))
                .oif(index),
        ];
        for r in &routes {
            nl.add_route(r).unwrap();
        }
        let e = nl.add_route(&routes[0]).unwrap_err();
        assert_eq!(errno(&e), Some(libc::EEXIST));
        assert!(e
            .to_string()
            .starts_with("adding route 0.0.0.0/0 in table 2022: EEXIST"));
        let shown4 = lines(&ip(&["route", "show", "table", "2022"]));
        let shown6 = lines(&ip(&["-6", "route", "show", "table", "2022"]));
        println!(
            "ip route show table 2022:\n{}\nip -6 route show table 2022:\n{}",
            shown4, shown6
        );
        assert_eq!(
            shown4,
            "default dev sailrtnl1 scope link\n\
             unreachable 1.2.3.0/24\n\
             10.0.0.0/8 via 172.19.0.2 dev sailrtnl1 metric 5\n\
             throw 192.168.0.0/16\n\
             198.18.0.0/15 dev sailrtnl1 scope link metric 100"
        );
        assert_eq!(
            shown6,
            "64:ff9b::/96 via fdfe:dcba:9876::2 dev sailrtnl1 metric 1024 pref medium\n\
             unreachable 2001:db8::/32 dev lo metric 7 pref medium\n\
             default dev sailrtnl1 metric 1024 pref medium"
        );

        // Read back, and deleted by what was read.
        let got4 = nl.routes_in(Family::V4, 2022).unwrap();
        assert_eq!(got4.len(), 5, "{:?}", got4);
        for r in &routes[..5] {
            let mut want = r.clone();
            if want.kind == RouteKind::Unicast && want.gateway.is_some() {
                // The kernel names the interface the gateway is on.
                want.oif = Some(index);
            }
            assert!(got4.contains(&want), "{:?} not in {:?}", want, got4);
        }
        let got6 = nl.routes_in(Family::V6, 2022).unwrap();
        assert_eq!(got6.len(), 3, "{:?}", got6);
        for r in got4.iter().chain(&got6) {
            nl.del_route(r).unwrap();
        }
        assert_eq!(nl.routes_in(Family::V4, 2022).unwrap(), []);
        assert_eq!(nl.routes_in(Family::V6, 2022).unwrap(), []);
        let e = nl.del_route(&routes[2]).unwrap_err();
        assert_eq!(errno(&e), Some(libc::ESRCH), "{}", e);

        // The main table's default routes, by metric; other tables' and
        // unreachable ones are not.
        nl.add_route(
            &Route::new(v4("0.0.0.0/0"), 254)
                .gateway(addr("172.19.0.2"))
                .metric(600),
        )
        .unwrap();
        nl.add_route(&Route::new(v4("0.0.0.0/0"), 254).oif(index).metric(50))
            .unwrap();
        nl.add_route(&Route::new(v4("0.0.0.0/0"), 100).oif(index))
            .unwrap();
        nl.add_route(
            &Route::new(v4("0.0.0.0/0"), 254)
                .kind(RouteKind::Unreachable)
                .metric(1),
        )
        .unwrap();
        nl.add_route(
            &Route::new(prefix("::/0"), 254)
                .gateway(addr("fdfe:dcba:9876::2"))
                .oif(index),
        )
        .unwrap();
        let defaults = nl.default_routes(Family::V4).unwrap();
        assert_eq!(
            defaults,
            [
                DefaultRoute {
                    family: Family::V4,
                    oif: index,
                    gateway: None,
                    metric: 50,
                    table: 254,
                },
                DefaultRoute {
                    family: Family::V4,
                    oif: index,
                    gateway: Some(addr("172.19.0.2")),
                    metric: 600,
                    table: 254,
                },
            ]
        );
        assert_eq!(
            nl.default_routes(Family::V6).unwrap(),
            [DefaultRoute {
                family: Family::V6,
                oif: index,
                gateway: Some(addr("fdfe:dcba:9876::2")),
                metric: 1024,
                table: 254,
            }]
        );
        let _ = Command::new("ip")
            .args(["link", "del", "sailrtnl1"])
            .status();
    }
}
