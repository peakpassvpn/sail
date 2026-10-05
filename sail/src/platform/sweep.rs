//! Sweeping what a killed instance left (docs/tun-leftover-sweep.md).
//!
//! Before an instance changes the system in a way the kernel does not undo
//! when the process dies, it writes the change down in a ledger, one file
//! for each instance in the run directory. A clean stop undoes the changes
//! and removes the ledger. The sweep, which runs before every start or on
//! its own, undoes what the ledgers of instances no longer running list,
//! exactly as they list it, and removes them.
//!
//! An instance is no longer running when its process is gone (its pid is
//! dead, or belongs to a process started at another time), or, when its
//! process is this one, when its id is not among those running here: an
//! embedder runs several instances in one process, and may start another
//! after one panicked.
//!
//! Linux leaves ip rules, routes that name no device, the nftables table
//! and fw4's drop-in for the sweep; macOS a route auto_route replaced,
//! which the sweep puts back. Windows leaves nothing.

// Only the TUN on Linux and macOS writes to a ledger.
#![cfg_attr(
    not(all(any(target_os = "linux", target_os = "macos"), feature = "inbound-tun")),
    allow(dead_code)
)]

use portable_atomic::{AtomicU64, Ordering};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_derive::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Where the ledgers are kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RunDir {
    /// The system's: `/run/sail` on Linux, `/var/run/sail` on macOS when
    /// sail runs as root, both emptied at a reboot. None on Windows (a
    /// Wintun adapter goes with its process, with its routes and DNS),
    /// nor for macOS's unprivileged or sandboxed hosts: they give theirs.
    #[default]
    Default,
    /// The host's.
    Dir(PathBuf),
    /// No ledger and no sweep.
    Off,
}

impl RunDir {
    /// The directory, where there is one: by default on Linux only,
    /// the one system a kill leaves anything on.
    fn path(&self) -> Option<PathBuf> {
        match self {
            RunDir::Default if cfg!(target_os = "linux") => Some(PathBuf::from("/run/sail")),
            // SAFETY: geteuid has no failure and touches nothing.
            #[cfg(target_os = "macos")]
            RunDir::Default if unsafe { libc::geteuid() } == 0 => {
                Some(PathBuf::from("/var/run/sail"))
            }
            RunDir::Default => None,
            RunDir::Dir(dir) => Some(dir.clone()),
            RunDir::Off => None,
        }
    }
}

/// A change to the system a ledger lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Item {
    /// The TUN the rest belongs to, which goes with the process. While a
    /// device of its name is up, a live instance holds that name and, by
    /// its own setup, what is named after it: the ledger waits.
    Tun(String),
    /// An ip rule, deleted as it was added: every attribute given, so
    /// that only that rule matches.
    #[cfg(any(target_os = "linux", test))]
    Rule(#[serde(with = "written::rule")] crate::platform::rtnetlink::Rule),
    /// A route that names no device (a throw or unreachable one), which
    /// does not go when the TUN does.
    #[cfg(any(target_os = "linux", test))]
    Route(#[serde(with = "written::route")] crate::platform::rtnetlink::Route),
    /// An `inet` nftables table.
    NftTable(String),
    /// A file sail wrote.
    File(PathBuf),
    /// Someone else's route auto_route replaced with its own (macOS): put
    /// back, as `Replaced` says when.
    #[cfg(any(target_os = "macos", test))]
    ReplacedRoute(Replaced),
}

/// A route auto_route replaced with its own, as the table had it: enough to
/// add it again, and to tell whether it should be.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Replaced {
    pub(crate) dst: (std::net::IpAddr, u8),
    /// Its next hop; none for a route to an interface.
    pub(crate) gateway: Option<std::net::IpAddr>,
    /// Its interface, by name and index: a name alone may be another's by
    /// then, an index alone reused.
    pub(crate) interface: String,
    pub(crate) index: u32,
    /// Its flags (RTF_*), as the table had them.
    pub(crate) flags: i32,
    /// The utun whose route replaced it.
    pub(crate) by: String,
    /// The boot it was replaced in (kern.boottime): after a reboot it is
    /// not put back.
    pub(crate) boot: String,
}

/// Whether a replaced route goes back.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PutBack {
    /// Put it back.
    Put,
    /// Another route to its destination is there: someone's, which wins.
    Taken,
    /// The system booted since: it is no longer anyone's.
    Rebooted,
    /// Its interface is not the one it was: why.
    Gone(String),
}

#[cfg(any(target_os = "macos", test))]
impl Replaced {
    /// "route 128.0.0.0/1 via 10.8.0.1 on utun4".
    pub(crate) fn describe(&self) -> String {
        match self.gateway {
            Some(gateway) => format!(
                "route {}/{} via {} on {}",
                self.dst.0, self.dst.1, gateway, self.interface
            ),
            None => format!("route {}/{} on {}", self.dst.0, self.dst.1, self.interface),
        }
    }

    /// The command that adds it again by hand.
    pub(crate) fn clear(&self) -> String {
        let family = if self.dst.0.is_ipv6() { " -inet6" } else { "" };
        let to = match self.gateway {
            Some(gateway) => gateway.to_string(),
            None => format!("-interface {}", self.interface),
        };
        format!(
            "sudo route -n add{} -net {}/{} {}",
            family, self.dst.0, self.dst.1, to
        )
    }

    /// Whether it goes back, now that sail's own route to its destination
    /// is gone: in the boot `boot`; `taken` if a route to its destination
    /// is there; `interface`, the index and whether it is up of the
    /// interface of its name now, if there is one.
    pub(crate) fn put_back(
        &self,
        boot: &str,
        taken: bool,
        interface: Option<(u32, bool)>,
    ) -> PutBack {
        if boot != self.boot {
            return PutBack::Rebooted;
        }
        if taken {
            return PutBack::Taken;
        }
        match interface {
            Some((index, true)) if index == self.index => PutBack::Put,
            Some((index, false)) if index == self.index => {
                PutBack::Gone(format!("{} is down", self.interface))
            }
            Some(_) => PutBack::Gone(format!("{} is another interface now", self.interface)),
            None => PutBack::Gone(format!("{} is gone", self.interface)),
        }
    }
}

/// Rules and routes as a ledger writes them: the netlink types stay free
/// of serde, as the configuration reference reads every type that is
/// deserialized as configuration.
#[cfg(any(target_os = "linux", test))]
mod written {
    use std::net::IpAddr;

    use serde_derive::{Deserialize, Serialize};

    use crate::platform::rtnetlink::{Family, Prefix, Route, RouteKind, Rule, RuleAction};

    fn prefix(p: Option<Prefix>) -> Option<(IpAddr, u8)> {
        p.map(|p| (p.addr, p.len))
    }

    fn from_prefix(p: Option<(IpAddr, u8)>) -> Option<Prefix> {
        p.map(|(addr, len)| Prefix::new(addr, len))
    }

    #[derive(Serialize, Deserialize)]
    struct LedgerRule {
        v6: bool,
        priority: u32,
        invert: bool,
        /// lookup TABLE, goto PRIORITY, nop, unreachable.
        action: (String, u32),
        src: Option<(IpAddr, u8)>,
        dst: Option<(IpAddr, u8)>,
        iif: Option<String>,
        oif: Option<String>,
        fwmark: Option<(u32, u32)>,
        uid_range: Option<(u32, u32)>,
        ip_proto: Option<u8>,
        sport: Option<(u16, u16)>,
        dport: Option<(u16, u16)>,
        suppress_prefixlength: Option<u32>,
    }

    #[derive(Serialize, Deserialize)]
    struct LedgerRoute {
        dst: (IpAddr, u8),
        gateway: Option<IpAddr>,
        oif: Option<u32>,
        table: u32,
        /// unicast, throw, unreachable, blackhole, prohibit.
        kind: String,
        metric: Option<u32>,
    }

    pub(super) mod rule {
        use super::*;

        pub(in super::super) fn serialize<S: serde::Serializer>(
            r: &Rule,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            let action = match r.action {
                RuleAction::Lookup(t) => ("lookup".into(), t),
                RuleAction::Goto(p) => ("goto".into(), p),
                RuleAction::Nop => ("nop".into(), 0),
                RuleAction::Unreachable => ("unreachable".into(), 0),
            };
            serde::Serialize::serialize(
                &LedgerRule {
                    v6: r.family == Family::V6,
                    priority: r.priority,
                    invert: r.invert,
                    action,
                    src: prefix(r.src),
                    dst: prefix(r.dst),
                    iif: r.iif.clone(),
                    oif: r.oif.clone(),
                    fwmark: r.fwmark,
                    uid_range: r.uid_range,
                    ip_proto: r.ip_proto,
                    sport: r.sport,
                    dport: r.dport,
                    suppress_prefixlength: r.suppress_prefixlength,
                },
                s,
            )
        }

        pub(in super::super) fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> Result<Rule, D::Error> {
            let r: LedgerRule = serde::Deserialize::deserialize(d)?;
            let action = match (r.action.0.as_str(), r.action.1) {
                ("lookup", t) => RuleAction::Lookup(t),
                ("goto", p) => RuleAction::Goto(p),
                ("nop", _) => RuleAction::Nop,
                ("unreachable", _) => RuleAction::Unreachable,
                (other, _) => return Err(serde::de::Error::custom(format!("rule action {other}"))),
            };
            let family = if r.v6 { Family::V6 } else { Family::V4 };
            Ok(Rule {
                invert: r.invert,
                src: from_prefix(r.src),
                dst: from_prefix(r.dst),
                iif: r.iif,
                oif: r.oif,
                fwmark: r.fwmark,
                uid_range: r.uid_range,
                ip_proto: r.ip_proto,
                sport: r.sport,
                dport: r.dport,
                suppress_prefixlength: r.suppress_prefixlength,
                ..Rule::new(family, r.priority, action)
            })
        }
    }

    pub(super) mod route {
        use super::*;

        pub(in super::super) fn serialize<S: serde::Serializer>(
            r: &Route,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            let kind = match r.kind {
                RouteKind::Unicast => "unicast",
                RouteKind::Throw => "throw",
                RouteKind::Unreachable => "unreachable",
                RouteKind::Blackhole => "blackhole",
                RouteKind::Prohibit => "prohibit",
            };
            serde::Serialize::serialize(
                &LedgerRoute {
                    dst: (r.dst.addr, r.dst.len),
                    gateway: r.gateway,
                    oif: r.oif,
                    table: r.table,
                    kind: kind.into(),
                    metric: r.metric,
                },
                s,
            )
        }

        pub(in super::super) fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> Result<Route, D::Error> {
            let r: LedgerRoute = serde::Deserialize::deserialize(d)?;
            let kind = match r.kind.as_str() {
                "unicast" => RouteKind::Unicast,
                "throw" => RouteKind::Throw,
                "unreachable" => RouteKind::Unreachable,
                "blackhole" => RouteKind::Blackhole,
                "prohibit" => RouteKind::Prohibit,
                other => return Err(serde::de::Error::custom(format!("route kind {other}"))),
            };
            Ok(Route {
                dst: Prefix::new(r.dst.0, r.dst.1),
                gateway: r.gateway,
                oif: r.oif,
                table: r.table,
                kind,
                metric: r.metric,
            })
        }
    }
}

/// A ledger file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    pid: u32,
    /// The process's start time, as /proc has it, so that a reused pid
    /// is told apart.
    start: u64,
    instance: u64,
    /// The network namespace the changes were made in: a sweep from
    /// another (a test's) cannot undo them, and leaves the ledger.
    #[serde(default)]
    netns: u64,
    items: Vec<Item>,
}

/// The ids of the instances running in this process.
static RUNNING: Mutex<Option<HashSet<u64>>> = Mutex::new(None);
static NEXT: AtomicU64 = AtomicU64::new(1);

fn running() -> std::sync::MutexGuard<'static, Option<HashSet<u64>>> {
    RUNNING.lock().unwrap_or_else(|e| e.into_inner())
}

/// An instance's ledger: what it changed and has not undone. One with no
/// directory records nothing.
#[derive(Debug, Clone, Default)]
pub struct Ledger(Option<Arc<Book>>);

#[derive(Debug)]
struct Book {
    dir: PathBuf,
    path: PathBuf,
    entry: Mutex<Entry>,
    /// Whether a failed write was warned of: once is enough.
    warned: std::sync::atomic::AtomicBool,
}

impl Ledger {
    /// Writes `item` down before it is made. A ledger that cannot be
    /// written is warned of, and the change made all the same.
    pub(crate) fn record(&self, item: Item) {
        let Some(book) = &self.0 else { return };
        let mut entry = book.entry.lock().unwrap_or_else(|e| e.into_inner());
        if entry.items.contains(&item) {
            return;
        }
        entry.items.push(item);
        // Made with the first entry: an instance that changes nothing (an
        // unprivileged one, say) needs no directory it could not make.
        if let Err(e) = create_dir(&book.dir).and_then(|()| write(&book.path, &entry)) {
            if book.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            warn!(
                "ledger {}: {}; what a kill leaves will not be swept",
                book.path.display(),
                e
            );
        }
    }

    /// Takes `item` off once it is undone.
    pub(crate) fn forget(&self, item: &Item) {
        let Some(book) = &self.0 else { return };
        let mut entry = book.entry.lock().unwrap_or_else(|e| e.into_inner());
        let before = entry.items.len();
        entry.items.retain(|i| i != item);
        if entry.items.len() == before {
            return;
        }
        let result = if entry.items.is_empty() {
            std::fs::remove_file(&book.path).or_else(not_found)
        } else {
            write(&book.path, &entry)
        };
        if let Err(e) = result {
            warn!("ledger {}: {}", book.path.display(), e);
        }
    }
}

fn not_found(e: std::io::Error) -> std::io::Result<()> {
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(e)
    }
}

/// Writes `entry` to `path` whole, or leaves the old one.
fn write(path: &Path, entry: &Entry) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(&serde_json::to_vec(entry)?)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// An instance's place among those running: dropped when its run ends,
/// returns or unwinds, after which a sweep may undo what its ledger
/// still lists.
#[derive(Debug)]
pub struct Running {
    instance: u64,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(set) = running().as_mut() {
            set.remove(&self.instance);
        }
    }
}

/// Sweeps `dir`, then gives the instance about to start its ledger there,
/// and its place among those running.
pub fn begin(dir: &RunDir) -> (Ledger, Running) {
    let instance = NEXT.fetch_add(1, Ordering::Relaxed);
    sweep(dir);
    running().get_or_insert_with(HashSet::new).insert(instance);
    let running = Running { instance };
    let Some(path) = dir.path() else {
        return (Ledger::default(), running);
    };
    let pid = std::process::id();
    let book = Book {
        path: path.join(format!("{}-{}.json", pid, instance)),
        dir: path,
        entry: Mutex::new(Entry {
            pid,
            start: start_time(pid).unwrap_or(0),
            instance,
            netns: netns(),
            items: Vec::new(),
        }),
        warned: Default::default(),
    };
    (Ledger(Some(Arc::new(book))), running)
}

fn create_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)
}

/// Undoes what the ledgers in `dir` of instances no longer running list,
/// and removes them; returns what it undid, a line each. What cannot be
/// undone is warned of and kept for the next sweep.
pub fn sweep(dir: &RunDir) -> Vec<String> {
    let Some(path) = dir.path() else {
        return Vec::new();
    };
    let files = match std::fs::read_dir(&path) {
        Ok(files) => files,
        // None made, or not this process's to read: nothing to sweep.
        Err(e) => {
            debug!("sweep: {}: {}", path.display(), e);
            return Vec::new();
        }
    };
    let mut undone = Vec::new();
    for file in files.flatten() {
        let file = file.path();
        if file.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let entry: Entry = match std::fs::read(&file)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| Ok(serde_json::from_slice(&bytes)?))
        {
            Ok(entry) => entry,
            Err(e) => {
                warn!("ledger {}: {}; left as it is", file.display(), e);
                continue;
            }
        };
        if entry.netns != netns() || !stale(&entry) {
            continue;
        }
        let held = entry.items.iter().find_map(|item| match item {
            Item::Tun(name) if device_exists(name) => Some(name),
            _ => None,
        });
        if let Some(name) = held {
            debug!(
                "sweep: {} left for later: {} is up, held by a running instance",
                file.display(),
                name
            );
            continue;
        }
        let mut left = Vec::new();
        for item in entry.items.iter().rev() {
            match undo(item) {
                Ok(true) => undone.push(describe(item)),
                Ok(false) => {}
                Err(e) => {
                    warn!("sweep: {}: {}", describe(item), e);
                    left.push(item.clone());
                }
            }
        }
        let result = if left.is_empty() {
            std::fs::remove_file(&file).or_else(not_found)
        } else {
            left.reverse();
            write(
                &file,
                &Entry {
                    items: left,
                    ..entry
                },
            )
        };
        if let Err(e) = result {
            warn!("ledger {}: {}", file.display(), e);
        }
    }
    for line in &undone {
        info!(
            "sweep: removed {}, left by an instance that did not stop",
            line
        );
    }
    undone
}

/// Whether the instance `entry` belongs to is no longer running.
fn stale(entry: &Entry) -> bool {
    if entry.pid == std::process::id() {
        return !running()
            .as_ref()
            .is_some_and(|set| set.contains(&entry.instance));
    }
    start_time(entry.pid) != Some(entry.start)
}

/// This process's network namespace, by the inode of its handle; 0 where
/// there is none to tell.
fn netns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata("/proc/self/ns/net") {
            return meta.ino();
        }
    }
    0
}

/// When process `pid` started, in clock ticks after boot (/proc's
/// `starttime`); None if there is no such process.
#[cfg(target_os = "linux")]
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // The name, in parentheses, may hold spaces: count from after it.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// 0 if process `pid` exists, which is all that is told without /proc.
#[cfg(all(unix, not(target_os = "linux")))]
fn start_time(pid: u32) -> Option<u64> {
    let pid = libc::pid_t::try_from(pid).ok()?;
    // SAFETY: signal 0 only checks that the process exists.
    let alive = unsafe { libc::kill(pid, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    alive.then_some(0)
}

#[cfg(not(unix))]
fn start_time(_pid: u32) -> Option<u64> {
    Some(0)
}

/// Whether a network device of this name is up in this namespace.
/// Every system takes the TUN down with its process; only Linux keeps a
/// ledger.
fn device_exists(name: &str) -> bool {
    #[cfg(unix)]
    {
        let Ok(name) = std::ffi::CString::new(name) else {
            return false;
        };
        // SAFETY: a NUL-terminated name, read only.
        unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = name;
        false
    }
}

fn describe(item: &Item) -> String {
    match item {
        Item::Tun(name) => format!("the TUN {}", name),
        #[cfg(any(target_os = "linux", test))]
        Item::Rule(rule) => format!("the ip rule at {} ({})", rule.priority, rule.family),
        #[cfg(any(target_os = "linux", test))]
        Item::Route(route) => format!("the route to {} in table {}", route.dst, route.table),
        Item::NftTable(name) => format!("the nftables table inet {}", name),
        Item::File(path) => path.display().to_string(),
        #[cfg(any(target_os = "macos", test))]
        Item::ReplacedRoute(replaced) => {
            format!("{}, which sail had replaced", replaced.describe())
        }
    }
}

/// Undoes `item`; false if it was already gone.
#[cfg(target_os = "linux")]
fn undo(item: &Item) -> anyhow::Result<bool> {
    use crate::platform::rtnetlink::Netlink;
    let gone = |e: &std::io::Error| {
        matches!(
            crate::platform::rtnetlink::errno(e),
            Some(libc::ENOENT | libc::ESRCH)
        )
    };
    match item {
        // It went with the process.
        Item::Tun(_) => Ok(false),
        Item::Rule(rule) => match Netlink::open()?.del_rule(rule) {
            Ok(()) => Ok(true),
            Err(e) if gone(&e) => Ok(false),
            Err(e) => Err(e.into()),
        },
        Item::Route(route) => match Netlink::open()?.del_route(route) {
            Ok(()) => Ok(true),
            Err(e) if gone(&e) => Ok(false),
            Err(e) => Err(e.into()),
        },
        Item::NftTable(name) => {
            crate::platform::auto_redirect::cleanup(name).commit()?;
            Ok(true)
        }
        Item::File(path) => match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        },
        #[cfg(test)]
        Item::ReplacedRoute(_) => Ok(false),
    }
}

#[cfg(not(target_os = "linux"))]
fn undo(item: &Item) -> anyhow::Result<bool> {
    match item {
        Item::File(path) => match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        },
        // Put back if it should be; else it is no one's to put back, and
        // the ledger lets it go.
        #[cfg(target_os = "macos")]
        Item::ReplacedRoute(replaced) => match crate::platform::route_socket::put_back(replaced)? {
            PutBack::Put => Ok(true),
            PutBack::Taken | PutBack::Rebooted => Ok(false),
            PutBack::Gone(why) => {
                warn!("sweep: {} not put back: {}", replaced.describe(), why);
                Ok(false)
            }
        },
        _ => Ok(false),
    }
}

// The tests start processes, read their pids and look up devices as Unix
// does; nothing on Windows writes a ledger.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A directory of its own for each test.
    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sail-sweep-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A pid no process has: one that has exited and been reaped.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    fn ledger_of(dir: &Path, pid: u32, start: u64, instance: u64, items: Vec<Item>) -> PathBuf {
        let path = dir.join(format!("{}-{}.json", pid, instance));
        let entry = Entry {
            pid,
            start,
            instance,
            netns: netns(),
            items,
        };
        write(&path, &entry).unwrap();
        path
    }

    #[test]
    fn a_dead_process_s_leftovers_are_swept_once() {
        let dir = dir("dead");
        let left = dir.join("drop-in.nft");
        std::fs::write(&left, "x").unwrap();
        let ledger = ledger_of(&dir, dead_pid(), 0, 1, vec![Item::File(left.clone())]);

        let undone = sweep(&RunDir::Dir(dir.clone()));
        assert_eq!(undone, [left.display().to_string()]);
        assert!(!left.exists() && !ledger.exists());
        // Again: nothing left, nothing done.
        assert!(sweep(&RunDir::Dir(dir.clone())).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_running_instance_s_ledger_is_left_and_swept_once_it_ends() {
        let dir = dir("own");
        let run_dir = RunDir::Dir(dir.clone());
        let (ledger, running) = begin(&run_dir);
        let left = dir.join("made.nft");
        ledger.record(Item::File(left.clone()));
        std::fs::write(&left, "x").unwrap();

        // Another instance in this process starts: this one runs on.
        let (_other, _other_running) = begin(&run_dir);
        assert!(left.exists(), "a running instance's changes are not swept");

        // It ends without undoing anything, as after a panic.
        drop(running);
        drop(ledger);
        let undone = sweep(&run_dir);
        assert_eq!(undone, [left.display().to_string()]);
        assert!(!left.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn what_is_undone_is_forgotten_and_an_empty_ledger_goes() {
        let dir = dir("forget");
        let (ledger, _running) = begin(&RunDir::Dir(dir.clone()));
        let item = Item::NftTable("sail".into());
        ledger.record(item.clone());
        ledger.record(item.clone());
        let files = || std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(files(), 1, "written before the change is made");
        ledger.forget(&item);
        assert_eq!(files(), 0, "gone once nothing is left in it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_ledger_of_a_live_process_is_left() {
        let dir = dir("live");
        // The parent of the tests: alive, and as it started.
        let parent = std::os::unix::process::parent_id();
        let left = dir.join("theirs.nft");
        std::fs::write(&left, "x").unwrap();
        let ledger = ledger_of(
            &dir,
            parent,
            start_time(parent).unwrap(),
            1,
            vec![Item::File(left.clone())],
        );
        assert!(sweep(&RunDir::Dir(dir.clone())).is_empty());
        assert!(left.exists() && ledger.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reused_pid_is_told_apart_by_its_start() {
        let dir = dir("reused");
        let parent = std::os::unix::process::parent_id();
        let left = dir.join("old.nft");
        std::fs::write(&left, "x").unwrap();
        let start = start_time(parent).unwrap();
        ledger_of(&dir, parent, start + 1, 1, vec![Item::File(left.clone())]);
        assert_eq!(sweep(&RunDir::Dir(dir.clone())).len(), 1);
        assert!(!left.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_instance_that_changes_nothing_makes_no_directory() {
        let dir = std::env::temp_dir().join(format!("sail-sweep-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_ledger, _running) = begin(&RunDir::Dir(dir.clone()));
        assert!(!dir.exists());
    }

    #[test]
    fn another_namespace_s_ledger_is_left() {
        let dir = dir("netns");
        let left = dir.join("theirs.nft");
        std::fs::write(&left, "x").unwrap();
        let path = dir.join("1-1.json");
        let entry = Entry {
            pid: dead_pid(),
            start: 0,
            instance: 1,
            netns: netns() + 1,
            items: vec![Item::File(left.clone())],
        };
        write(&path, &entry).unwrap();
        assert!(sweep(&RunDir::Dir(dir.clone())).is_empty());
        assert!(left.exists() && path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_ledger_whose_tun_is_up_waits() {
        let dir = dir("held");
        let left = dir.join("named-after-it.nft");
        std::fs::write(&left, "x").unwrap();
        // The loopback device, up everywhere: as a live instance's TUN.
        let lo = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let ledger = ledger_of(
            &dir,
            dead_pid(),
            0,
            1,
            vec![Item::Tun(lo.into()), Item::File(left.clone())],
        );
        assert!(sweep(&RunDir::Dir(dir.clone())).is_empty());
        assert!(left.exists() && ledger.exists(), "left for later");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn off_keeps_no_ledger() {
        let (ledger, _running) = begin(&RunDir::Off);
        ledger.record(Item::NftTable("sail".into()));
        assert!(ledger.0.is_none());
        assert!(sweep(&RunDir::Off).is_empty());
    }

    #[test]
    fn rules_and_routes_read_back_as_written() {
        use crate::platform::rtnetlink::{Family, Prefix, Route, RouteKind, Rule, RuleAction};
        let items = vec![
            Item::Rule(Rule {
                fwmark: Some((0x2024, u32::MAX)),
                invert: true,
                ..Rule::new(Family::V6, 32768, RuleAction::Lookup(2022))
            }),
            Item::Route(
                Route::new(Prefix::new("10.0.0.0".parse().unwrap(), 8), 2022)
                    .kind(RouteKind::Throw),
            ),
        ];
        let json = serde_json::to_string(&items).unwrap();
        assert_eq!(serde_json::from_str::<Vec<Item>>(&json).unwrap(), items);
    }

    fn replaced(gateway: Option<&str>) -> Replaced {
        Replaced {
            dst: ("128.0.0.0".parse().unwrap(), 1),
            gateway: gateway.map(|g| g.parse().unwrap()),
            interface: "utun4".into(),
            index: 17,
            flags: 0x803,
            by: "utun9".into(),
            boot: "1791100000.123".into(),
        }
    }

    /// Put back only in the boot it was replaced in, with its destination
    /// free and its interface the same one, up.
    #[test]
    fn a_replaced_route_goes_back_only_where_it_was() {
        let r = replaced(Some("10.8.0.1"));
        let boot = "1791100000.123";
        assert_eq!(r.put_back(boot, false, Some((17, true))), PutBack::Put);
        assert_eq!(
            r.put_back("1791200000.5", false, Some((17, true))),
            PutBack::Rebooted
        );
        assert_eq!(r.put_back(boot, true, Some((17, true))), PutBack::Taken);
        assert_eq!(
            r.put_back(boot, false, None),
            PutBack::Gone("utun4 is gone".into())
        );
        assert_eq!(
            r.put_back(boot, false, Some((18, true))),
            PutBack::Gone("utun4 is another interface now".into())
        );
        assert_eq!(
            r.put_back(boot, false, Some((17, false))),
            PutBack::Gone("utun4 is down".into())
        );
    }

    #[test]
    fn a_replaced_route_says_how_to_add_it_again() {
        let r = replaced(Some("10.8.0.1"));
        assert_eq!(r.describe(), "route 128.0.0.0/1 via 10.8.0.1 on utun4");
        assert_eq!(r.clear(), "sudo route -n add -net 128.0.0.0/1 10.8.0.1");
        let mut link = replaced(None);
        link.dst = ("8000::".parse().unwrap(), 1);
        assert_eq!(link.describe(), "route 8000::/1 on utun4");
        assert_eq!(
            link.clear(),
            "sudo route -n add -inet6 -net 8000::/1 -interface utun4"
        );
    }

    /// A ledger keeps a replaced route as it was written.
    #[test]
    fn a_replaced_route_is_read_back_from_a_ledger() {
        let item = Item::ReplacedRoute(replaced(Some("10.8.0.1")));
        let json = serde_json::to_string(&item).unwrap();
        assert_eq!(serde_json::from_str::<Item>(&json).unwrap(), item);
    }
}
