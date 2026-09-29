//! rtnetlink (`NETLINK_ROUTE`) spoken without ip(8): routes, policy
//! routing rules, and the few link and address operations a TUN device
//! needs -- enough for `auto_route` as sing-tun does it, routes in a table
//! of their own and ip rules that send traffic there.
//!
//! ```ignore
//! let nl = Netlink::open()?;
//! let tun = nl.link_index("tun0")?;
//! nl.add_address(tun, Prefix::new("172.19.0.1".parse()?, 30), None)?;
//! nl.set_link_up(tun, Some(9000))?;
//! nl.add_route(&Route::new(Prefix::new("0.0.0.0".parse()?, 0), 2022).oif(tun))?;
//! nl.add_rule(&Rule::new(Family::V4, 9001, RuleAction::Lookup(2022)))?;
//! ```
//!
//! This is only encoding and a blocking socket: it knows nothing of sail's
//! configuration. The messages are the ones iproute2 (6.15) sends for the
//! matching `ip rule`/`ip route`/`ip addr`/`ip link` commands, byte for
//! byte; the tests hold the bytes, captured from iproute2 with an `nlmon`
//! device, and the few places this differs say why. The encoder is plain
//! bytes and builds everywhere, so its tests run on any host; talking to
//! the kernel is Linux only.
//!
//! The netlink framing -- message header, attributes, the socket, reading
//! the kernel's errors -- is nf_tables' (`platform::nft`), shared.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod encode;
#[cfg(target_os = "linux")]
mod socket;
mod sys;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "linux")]
pub use socket::Netlink;

/// An address family: which of the kernel's two routing worlds -- its
/// tables and rules are per family -- something belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The family of `addr`.
    pub fn of(addr: &IpAddr) -> Family {
        match addr {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }

    /// Linux's `AF_*` number.
    fn af(self) -> u8 {
        match self {
            Family::V4 => sys::AF_INET,
            Family::V6 => sys::AF_INET6,
        }
    }

    fn from_af(af: u8) -> Option<Family> {
        match af {
            sys::AF_INET => Some(Family::V4),
            sys::AF_INET6 => Some(Family::V6),
            _ => None,
        }
    }

    /// The longest prefix there is: 32 or 128.
    fn max_len(self) -> u8 {
        match self {
            Family::V4 => 32,
            Family::V6 => 128,
        }
    }

    /// 0.0.0.0 or ::, the address of a default route.
    fn unspecified(self) -> IpAddr {
        match self {
            Family::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Family::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Family::V4 => "v4",
            Family::V6 => "v6",
        })
    }
}

/// An address and a prefix length: `10.0.0.0/8`, or `0.0.0.0/0` for
/// everything. The address is sent as it is; the kernel refuses host bits
/// past the length in a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    pub fn new(addr: IpAddr, len: u8) -> Prefix {
        Prefix { addr, len }
    }

    pub fn family(&self) -> Family {
        Family::of(&self.addr)
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// What a route does with what it matches (`rtm_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteKind {
    /// Sends it on, through `oif` or to `gateway`.
    Unicast,
    /// Ends the lookup in this table, as if it had no route: the rule
    /// lookup goes on with the next rule.
    Throw,
    /// Refuses it, "network unreachable".
    Unreachable,
    /// Drops it silently. Listed so a table's routes can all be read back
    /// and deleted; sail does not make these.
    Blackhole,
    /// Refuses it, "prohibited". Listed for the same reason.
    Prohibit,
}

impl RouteKind {
    fn rtn(self) -> u8 {
        match self {
            RouteKind::Unicast => sys::RTN_UNICAST,
            RouteKind::Throw => sys::RTN_THROW,
            RouteKind::Unreachable => sys::RTN_UNREACHABLE,
            RouteKind::Blackhole => sys::RTN_BLACKHOLE,
            RouteKind::Prohibit => sys::RTN_PROHIBIT,
        }
    }

    fn from_rtn(rtn: u8) -> Option<RouteKind> {
        Some(match rtn {
            sys::RTN_UNICAST => RouteKind::Unicast,
            sys::RTN_THROW => RouteKind::Throw,
            sys::RTN_UNREACHABLE => RouteKind::Unreachable,
            sys::RTN_BLACKHOLE => RouteKind::Blackhole,
            sys::RTN_PROHIBIT => RouteKind::Prohibit,
            _ => return None,
        })
    }
}

/// A route: `ip route add [kind] <dst> [via <gateway>] [dev <oif>]
/// table <table> [metric <metric>]`. Its family is `dst`'s; a gateway must
/// be of the same.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Route {
    pub dst: Prefix,
    pub gateway: Option<IpAddr>,
    /// The output interface's index.
    pub oif: Option<u32>,
    pub table: u32,
    pub kind: RouteKind,
    /// `RTA_PRIORITY`. None leaves it to the kernel: 0 for IPv4, 1024 for
    /// IPv6 -- and, when deleting, matches any.
    pub metric: Option<u32>,
}

impl Route {
    /// A unicast route to `dst` in `table`, with nowhere to go yet.
    pub fn new(dst: Prefix, table: u32) -> Route {
        Route {
            dst,
            gateway: None,
            oif: None,
            table,
            kind: RouteKind::Unicast,
            metric: None,
        }
    }

    pub fn oif(mut self, index: u32) -> Route {
        self.oif = Some(index);
        self
    }

    pub fn gateway(mut self, gateway: IpAddr) -> Route {
        self.gateway = Some(gateway);
        self
    }

    pub fn kind(mut self, kind: RouteKind) -> Route {
        self.kind = kind;
        self
    }

    pub fn metric(mut self, metric: u32) -> Route {
        self.metric = Some(metric);
        self
    }

    pub fn family(&self) -> Family {
        self.dst.family()
    }
}

/// What a rule does with a packet it matches (the rule's action).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleAction {
    /// `lookup <table>`: look the route up in that table; if it has none
    /// (or throws), go on with the next rule.
    Lookup(u32),
    /// `goto <priority>`: go on with the rule at that priority, which must
    /// come later.
    Goto(u32),
    /// `nop`: nothing; a rule to jump to.
    Nop,
    /// `unreachable`: refuse, "network unreachable".
    Unreachable,
}

/// A policy routing rule: `ip [-6] rule add [not] priority <priority>
/// [from <src>] [to <dst>] [iif <iif>] [oif <oif>] [fwmark <mark>/<mask>]
/// [uidrange <a>-<b>] [ipproto <proto>] [sport <a>-<b>] [dport <a>-<b>]
/// <action> [suppress_prefixlength <n>]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rule {
    pub family: Family,
    pub priority: u32,
    /// `not`: the rule applies to what its selectors do not match.
    pub invert: bool,
    pub action: RuleAction,
    pub src: Option<Prefix>,
    pub dst: Option<Prefix>,
    /// The input interface's name; `lo` for what the host itself sends.
    pub iif: Option<String>,
    pub oif: Option<String>,
    /// The mark and the mask it is compared under.
    pub fwmark: Option<(u32, u32)>,
    /// The first and last uid, both included.
    pub uid_range: Option<(u32, u32)>,
    /// The IP protocol number: 6 for TCP, 17 for UDP.
    pub ip_proto: Option<u8>,
    /// The first and last port, both included.
    pub sport: Option<(u16, u16)>,
    pub dport: Option<(u16, u16)>,
    /// With `Lookup`: ignore what the table answers with a prefix this
    /// long or shorter -- 0 ignores its default route.
    pub suppress_prefixlength: Option<u32>,
}

impl Rule {
    /// A rule matching everything of `family`.
    pub fn new(family: Family, priority: u32, action: RuleAction) -> Rule {
        Rule {
            family,
            priority,
            invert: false,
            action,
            src: None,
            dst: None,
            iif: None,
            oif: None,
            fwmark: None,
            uid_range: None,
            ip_proto: None,
            sport: None,
            dport: None,
            suppress_prefixlength: None,
        }
    }
}

/// A default route of the main table, as the system has it: where
/// traffic goes when nothing else routes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DefaultRoute {
    pub family: Family,
    pub oif: u32,
    pub gateway: Option<IpAddr>,
    /// 0 when the route has none.
    pub metric: u32,
    pub table: u32,
}

/// The kernel refused a request: what was being done ("adding rule 9001
/// (v4)"), the errno, and what the kernel said about it, if anything.
/// Carried inside the `io::Error` the calls return; [`errno`] reads it
/// back.
#[derive(Debug)]
pub struct Error {
    pub what: String,
    pub errno: i32,
    pub message: Option<String>,
}

impl Error {
    fn into_io(self) -> io::Error {
        io::Error::new(io::Error::from_raw_os_error(self.errno).kind(), self)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // strerror's words, without io::Error's " (os error N)".
        let os = io::Error::from_raw_os_error(self.errno).to_string();
        let os = os.split(" (os error").next().unwrap_or_default();
        match errno_name(self.errno) {
            Some(name) => write!(f, "{}: {} ({})", self.what, name, os)?,
            None => write!(f, "{}: errno {} ({})", self.what, self.errno, os)?,
        }
        if let Some(message) = &self.message {
            write!(f, ": {}", message)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

/// The errno an error of this module carries: the kernel's, or the
/// socket's.
pub fn errno(e: &io::Error) -> Option<i32> {
    e.raw_os_error().or_else(|| {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<Error>())
            .map(|e| e.errno)
    })
}

/// The symbol of an errno rtnetlink is known to answer with.
fn errno_name(errno: i32) -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        match errno {
            libc::ESRCH => return Some("ESRCH"),
            libc::ENETUNREACH => return Some("ENETUNREACH"),
            libc::EADDRNOTAVAIL => return Some("EADDRNOTAVAIL"),
            _ => {}
        }
    }
    super::nft::errno_name(errno)
}

/// A request that cannot be encoded: a prefix too long, families mixed.
fn invalid(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what)
}
