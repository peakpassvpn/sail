//! What an instance tells as it happens, beyond its log: a group switching
//! members, a connection failing. One bounded channel per kind, so that a
//! flood of one never pushes another out; the instance's, for a run.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use crate::session::{Network, SocksAddr};

/// Events a subscriber may fall behind by, per kind, before it is told it
/// lagged.
const CAPACITY: usize = 64;

/// Routed connections a subscriber may fall behind by. A judgment value,
/// not a measured one: there is one event a connection, so the 64 of the
/// other kinds would be overrun by any busy instance; 1024 is a second of
/// a thousand connections a second, and costs 1024 pointers while someone
/// subscribes. A subscriber that falls further behind is told
/// `Lagged { kind: ROUTE, missed }` once, with how many it missed, and
/// then goes on from the oldest event still kept; the connections open
/// then are in the instance's connections, those that ended are not told
/// again.
const ROUTE_CAPACITY: usize = 1024;

/// DNS exchanges a subscriber may fall behind by. A judgment value, not a
/// measured one: there is one event a query, and queries come in bursts,
/// most at the start, when every app on a device asks at once, each name
/// twice (A and AAAA); 1024 holds such a burst for a host that reads them
/// a little late. One that falls further behind is told
/// `Lagged { kind: DNS, missed }` once and goes on from the oldest event
/// still kept; what it missed is not told again.
const DNS_CAPACITY: usize = 1024;

/// What the rules did with a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteAction {
    /// It went to an outbound, and was dialled.
    Outbound,
    /// A rule rejected it: closed at once.
    Reject,
    /// A rule dropped it: never answered.
    Drop,
    /// A rule had sail's DNS answer the queries it carries.
    HijackDns,
}

/// Where the domain told of a connection came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainSource {
    /// The destination's own name: as the client asked for it, or as a
    /// sniff rule's `override_destination` made it.
    Request,
    /// The destination was a fake IP, which stands for this name. Told of
    /// TCP connections; a UDP session's is `Request`.
    FakeIp,
    /// A TLS server name or an HTTP Host read from its first bytes, the
    /// destination being an address.
    Sniffed,
    /// The DNS answers sail gave for the address (`dns.reverse_mapping`).
    ReverseMapping,
}

/// A connection, once the rules decided of it and, where they sent it to
/// an outbound, once its dial ended, well or not: one a TCP connection, a
/// UDP session, or a stream of a multiplexed connection.
///
/// Its addresses and its domain are told whole: `log.redact` governs what
/// sail writes to its log, not what it tells the host that embeds it,
/// which redacts what it passes on as it sees fit. (`DialFailure`'s
/// destination, made for a log line, is redacted.)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RoutedConnection {
    /// As the instance's connections list it; none where it never opened
    /// (a dial that failed before a byte, a reject, a drop, hijacked DNS).
    pub id: Option<u64>,
    pub network: Network,
    /// The inbound's tag.
    pub inbound: String,
    pub source: SocketAddr,
    /// Where it was to go, as the rules saw it: a fake IP is its domain.
    pub destination: SocksAddr,
    /// What the outbound was asked to reach: the destination after the
    /// rules' `override_address` and `override_port`, an address a
    /// `resolve` rule handed on, or the name `override_destination` has it
    /// dialled as. None where no outbound was asked.
    pub request_destination: Option<SocksAddr>,
    /// The domain known for it, and where from.
    pub domain: Option<String>,
    pub domain_source: Option<DomainSource>,
    /// The protocol sniffing recognized, as a rule's `protocol` names it.
    pub sniffed_protocol: Option<&'static str>,
    /// The rule that decided: its index in the configuration's
    /// `route.rules`, counting every entry of that list as written, a
    /// logical rule and a rule naming rule-sets one each, from 0. None for
    /// `route.final`, and for a connection the rules never saw (the
    /// host's own dial). A Clash or Surge configuration's rules are
    /// numbered as sail lowered them, which need not be their lines.
    pub rule: Option<u32>,
    /// The rule as the log and the connections list tell it.
    pub rule_text: Option<String>,
    pub action: RouteAction,
    /// The outbounds it went through, outermost first: the outbound the
    /// rules named, then the member each group on the way took, down to
    /// the outbound that carried it, which is the last. For a rule that
    /// names the group `F`, which took the group `G`, which took the
    /// member `m`: `["F", "G", "m"]`, as `DialFailure::chain` joins them
    /// (`F>G>m`) and the log's `out=` names them. For a dial that failed,
    /// the last is the member tried last. Empty where no outbound was
    /// asked. The connections list's `chains` (`ConnectionInfo`), which is
    /// the Clash API's, is the other way round: `["m", "G", "F"]`.
    pub chain: Vec<String>,
    /// The address its TCP connection out was made to: the destination's
    /// for a direct outbound, the server's for a proxy. None where none
    /// was made, or it goes out over UDP.
    pub target: Option<SocketAddr>,
    /// How long the dial and the outbound's handshake took, or how they
    /// failed. None where no outbound was asked.
    pub connect: Option<Result<Duration, std::io::ErrorKind>>,
}

/// Where the answer told of a DNS query came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsSource {
    /// A server was asked.
    Exchanged,
    /// The cache had it, still fresh.
    Cached,
    /// The cache had it, expired, and gave it while the server is asked
    /// again (`dns.optimistic`).
    Optimistic,
    /// A DNS rule answered it: `reject`, or `predefined`.
    Rule,
}

/// How a DNS query ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsOutcome {
    /// An answer, with its response code as DNS names it (`NOERROR`,
    /// `NXDOMAIN`, `SERVFAIL`, ...) and as its number.
    Answered { rcode: String, rcode_code: u16 },
    /// No answer: the server could not be reached, timed out, or what it
    /// sent was not DNS.
    Failed { error: String },
}

/// One DNS query answered or failed: one asked by a client of sail's DNS
/// (a TUN's, a DNS inbound's, hijacked DNS) or by the instance itself, to
/// reach a domain; a sequential server's members each once asked.
///
/// The name and the records are whole: `log.redact` governs sail's log,
/// not what it tells its host, which redacts what it passes on itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsExchange {
    /// The name asked, without its final dot.
    pub name: String,
    /// The type asked, as DNS names it (`A`, `AAAA`, `HTTPS`, ...).
    pub qtype: String,
    pub qtype_code: u16,
    /// The tag of the server that answered or failed; none where a rule
    /// answered.
    pub server: Option<String>,
    pub source: DnsSource,
    pub outcome: DnsOutcome,
    /// The records of the answer section, as DNS writes their data (an
    /// address, a name, ...): the first 16.
    pub answers: Vec<String>,
    /// How many records the answer section had.
    pub answers_total: u32,
    /// The least TTL of the answer's records, as the client is given it.
    pub ttl: Option<u32>,
    /// How long the server took; none from the cache or a rule.
    pub duration: Option<Duration>,
    /// Which attempt of a sequential server it was, from 1: its failed
    /// members each are told, and the one that answered.
    pub attempt: Option<u32>,
    /// Asked by the instance itself (to dial a domain, or a server's own
    /// name), rather than by a client.
    pub for_instance: bool,
}

/// The records of an answer an event carries, at most.
pub const DNS_ANSWERS_TOLD: usize = 16;

/// Why a group took another member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwitchReason {
    /// A connection through the member failed unambiguously, and it was
    /// marked down at once.
    MemberDown,
    /// Its checks found the member down (after `fail_after` rounds).
    TestFailed,
    /// An earlier member passed its checks again and was taken back.
    Recovered,
    /// No member is up: the group falls to its first.
    AllDown,
    /// A member was pinned (Clash API, `select`).
    Pinned,
    /// A pin was released (Clash API DELETE, `unfix`).
    Unpinned,
    /// A selector's member chosen by hand.
    Selected,
    /// A url-test moved to a faster member.
    Faster,
    /// The group's members changed (a provider updated).
    MembersChanged,
}

/// A group took another member.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupSwitch {
    /// The group's tag, after the tags of the groups it is in, outermost
    /// first, joined by `>`.
    pub group: String,
    /// None at the start.
    pub from: Option<String>,
    pub to: String,
    pub reason: SwitchReason,
}

impl GroupSwitch {
    pub fn new(group: String, from: Option<String>, to: String, reason: SwitchReason) -> Self {
        Self {
            group,
            from,
            to,
            reason,
        }
    }
}

/// Where a connection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DialStage {
    /// Connecting to the server or the destination.
    Dial,
    /// The outbound's handshake.
    Handshake,
    /// Relaying, after it was up.
    Transfer,
}

impl DialStage {
    /// The stage a failure of `kind` most likely is at, where nothing
    /// tells how far the attempt got: `Dial` for "connect, or timed out"
    /// (a handshake that times out is `TimedOut` too), else `Handshake`.
    pub(crate) fn guessed(kind: std::io::ErrorKind) -> Self {
        use std::io::ErrorKind as K;
        match kind {
            K::ConnectionRefused
            | K::TimedOut
            | K::HostUnreachable
            | K::NetworkUnreachable
            | K::NotFound
            | K::AddrNotAvailable => DialStage::Dial,
            _ => DialStage::Handshake,
        }
    }
}

/// An attempt to connect that failed: a group's member, or the
/// connection.
///
/// A group that tries members in turn (fallback, smart, tryall) tells
/// each member that fails, with `more_to_try` set while it, or a group
/// around it, goes on to another member; the dispatcher tells a failed
/// connection no group told of. So a connection's last failure, and only
/// it, has `more_to_try` false, and its chain names the member that
/// failed last.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DialFailure {
    /// The outbounds the attempt went through, outermost first, joined by
    /// `>` as the log's `out=` names them: the outbound the rules routed
    /// it to, then the member each group on the way took, down to the
    /// member tried (`sel>hk-ss`; `F>G>m` for a group G in a group F).
    pub chain: String,
    /// Where it went, as `log.redact` lets the log say it.
    pub destination: String,
    pub kind: std::io::ErrorKind,
    pub stage: DialStage,
    /// Whether the group goes on to try another member: false for the
    /// failure that ends the connection.
    pub more_to_try: bool,
}

impl DialFailure {
    /// A failure that ends its connection; see `with_more_to_try`.
    pub fn new(
        chain: String,
        destination: String,
        kind: std::io::ErrorKind,
        stage: DialStage,
    ) -> Self {
        Self {
            chain,
            destination,
            kind,
            stage,
            more_to_try: false,
        }
    }

    pub fn with_more_to_try(mut self, more_to_try: bool) -> Self {
        self.more_to_try = more_to_try;
        self
    }
}

/// A task's panic the instance went on after: its class, what it said,
/// and how many such panics the instance has had.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Fault {
    pub task: &'static str,
    pub class: crate::runtime::scope::TaskClass,
    pub message: String,
    pub count: u64,
}

impl Fault {
    pub fn new(
        task: &'static str,
        class: crate::runtime::scope::TaskClass,
        message: String,
        count: u64,
    ) -> Self {
        Self {
            task,
            class,
            message,
            count,
        }
    }
}

/// The channels, one a kind; cheap to clone, every clone the same.
#[derive(Clone)]
pub struct EventHub {
    group: broadcast::Sender<GroupSwitch>,
    dial: broadcast::Sender<DialFailure>,
    fault: broadcast::Sender<Fault>,
    route: Channel<Arc<RoutedConnection>>,
    dns: Channel<Arc<DnsExchange>>,
}

/// The channel of a kind told once a connection, or once a query: too
/// often to build what no one reads. It counts who listens itself, since
/// the broadcast channel's own count is behind its lock, and what it tells
/// is built only while someone does: `emit` is one load otherwise.
pub struct Channel<T> {
    tx: broadcast::Sender<T>,
    listeners: Arc<Listeners>,
}

#[derive(Default)]
struct Listeners {
    subscribers: AtomicUsize,
    /// The events built, for the tests: none while no one listens.
    built: AtomicUsize,
}

impl<T> Clone for Channel<T> {
    fn clone(&self) -> Self {
        Channel {
            tx: self.tx.clone(),
            listeners: self.listeners.clone(),
        }
    }
}

impl<T: Clone> Channel<T> {
    /// A channel a subscriber may fall `capacity` events behind on.
    pub fn new(capacity: usize) -> Self {
        Channel {
            tx: broadcast::channel(capacity).0,
            listeners: Arc::default(),
        }
    }

    /// Whether anyone listens.
    pub fn wanted(&self) -> bool {
        self.listeners.subscribers.load(Ordering::Relaxed) != 0
    }

    /// Tells what `build` makes, which it makes only when someone listens.
    pub fn emit(&self, build: impl FnOnce() -> T) {
        if !self.wanted() {
            return;
        }
        self.listeners.built.fetch_add(1, Ordering::Relaxed);
        let _ = self.tx.send(build());
    }

    pub fn subscribe(&self) -> Subscription<T> {
        // Subscribed before it is counted: an event built is one it gets.
        let rx = self.tx.subscribe();
        self.listeners.subscribers.fetch_add(1, Ordering::Relaxed);
        Subscription {
            rx,
            listeners: self.listeners.clone(),
        }
    }

    /// How many events were built to be told, since the start.
    pub fn built(&self) -> usize {
        self.listeners.built.load(Ordering::Relaxed)
    }
}

/// A `Channel`'s events, from when it was made until it is dropped.
pub struct Subscription<T> {
    rx: broadcast::Receiver<T>,
    listeners: Arc<Listeners>,
}

impl<T: Clone> Subscription<T> {
    pub async fn recv(&mut self) -> Result<T, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}

impl<T> Drop for Subscription<T> {
    fn drop(&mut self) {
        self.listeners.subscribers.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Default for EventHub {
    fn default() -> Self {
        Self {
            group: broadcast::channel(CAPACITY).0,
            dial: broadcast::channel(CAPACITY).0,
            fault: broadcast::channel(CAPACITY).0,
            route: Channel::new(ROUTE_CAPACITY),
            dns: Channel::new(DNS_CAPACITY),
        }
    }
}

impl std::fmt::Debug for EventHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EventHub")
    }
}

impl EventHub {
    /// Tells of a group's switch; nothing when no one listens.
    pub fn group_switched(&self, switch: GroupSwitch) {
        let _ = self.group.send(switch);
    }

    /// Tells of a failed connection; nothing when no one listens.
    pub fn dial_failed(&self, failure: DialFailure) {
        let _ = self.dial.send(failure);
    }

    /// Tells of a contained panic.
    pub fn fault(&self, fault: Fault) {
        let _ = self.fault.send(fault);
    }

    pub fn faults(&self) -> broadcast::Receiver<Fault> {
        self.fault.subscribe()
    }

    /// Tells of a routed connection, which `build` makes only when
    /// someone listens: one load, and nothing built, when no one does.
    pub fn routed(&self, build: impl FnOnce() -> RoutedConnection) {
        self.route.emit(|| Arc::new(build()));
    }

    /// Whether anyone listens for routed connections.
    pub fn routes_wanted(&self) -> bool {
        self.route.wanted()
    }

    pub fn routes(&self) -> Subscription<Arc<RoutedConnection>> {
        self.route.subscribe()
    }

    /// How many routed connections were built to be told, since the start.
    #[doc(hidden)]
    pub fn routes_built(&self) -> usize {
        self.route.built()
    }

    /// Tells of a DNS query answered or failed, which `build` makes only
    /// when someone listens.
    pub fn dns_exchanged(&self, build: impl FnOnce() -> DnsExchange) {
        self.dns.emit(|| Arc::new(build()));
    }

    pub fn dns_exchanges(&self) -> Subscription<Arc<DnsExchange>> {
        self.dns.subscribe()
    }

    /// How many DNS exchanges were built to be told, since the start.
    #[doc(hidden)]
    pub fn dns_built(&self) -> usize {
        self.dns.built()
    }

    pub fn group_switches(&self) -> broadcast::Receiver<GroupSwitch> {
        self.group.subscribe()
    }

    pub fn dial_failures(&self) -> broadcast::Receiver<DialFailure> {
        self.dial.subscribe()
    }
}
