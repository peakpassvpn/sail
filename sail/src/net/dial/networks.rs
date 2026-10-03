//! `network_strategy`: which of the host's interfaces a connection goes
//! out of, and how they race, as sing-box chooses them
//! (`common/dialer/default_parallel_interface.go`). The interfaces are
//! those `NetworkState` lists, as the host pushes them or sail detects
//! them.

use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::net::network::{NetworkInterface, NetworkState, NetworkType};

/// How a connection chooses among the host's interfaces: sing-box's
/// `network_strategy`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkStrategy {
    /// The default interface, or every interface of `network_type`.
    Default,
    /// Every interface, or every one of `network_type`, at once.
    Hybrid,
    /// As `default`; then, after `fallback_delay` or when one of those
    /// fails, the interfaces of `fallback_network_type`, or all others.
    Fallback,
}

/// A dialer's choice of interfaces: its strategy and the types it names,
/// merged over `route.default_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Networks {
    pub strategy: NetworkStrategy,
    /// Whether the strategy is `default` for want of one set, only types
    /// being given (sing-box's `defaultNetworkStrategy`): an interface that
    /// cannot be bound for want of permission then turns it off for good.
    pub implicit: bool,
    pub network_type: Vec<NetworkType>,
    pub fallback_network_type: Vec<NetworkType>,
    /// How long the first interfaces have before the fallback ones race
    /// them.
    pub fallback_delay: Duration,
}

/// How long, after a connection went out a fallback interface, both kinds
/// race from the start: sing-box's `C.TCPTimeout` (constant/timeout.go:9),
/// which `DialParallelInterface` measures `networkLastFallback` against
/// (common/dialer/default.go:317).
pub const FAST_FALLBACK: Duration = Duration::from_secs(15);

/// One interface to go out of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    pub name: String,
    pub index: Option<u32>,
    /// The default interface, which a socket goes out of unbound: it
    /// follows the default route (default_parallel_interface.go:34).
    pub default: bool,
}

impl Via {
    fn of(interface: &NetworkInterface, state: &NetworkState) -> Via {
        Via {
            name: interface.name.clone(),
            index: interface.index,
            default: state.interface.as_deref() == Some(interface.name.as_str()),
        }
    }
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.index {
            Some(index) => write!(f, "{} ({})", self.name, index),
            None => f.write_str(&self.name),
        }
    }
}

/// Where a connection went out: the interface it was bound to, or none,
/// following the default route. What the connections table shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Egress {
    DefaultRoute,
    Interface { name: String, index: Option<u32> },
}

impl Egress {
    pub(crate) fn of(via: &Via) -> Egress {
        if via.default {
            Egress::DefaultRoute
        } else {
            Egress::Interface {
                name: via.name.clone(),
                index: via.index,
            }
        }
    }
}

/// On a connection's shared state (`Session::state`): where the socket
/// its dialer opened went out, once it is open.
/// And, of a TCP connection, the address it was made to.
#[derive(Debug, Default)]
pub struct BoundInterface(Mutex<(Option<Egress>, Option<std::net::SocketAddr>)>);

impl BoundInterface {
    pub fn get(&self) -> Option<Egress> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).0.clone()
    }

    /// The address the connection's TCP connection out was made to.
    pub fn peer(&self) -> Option<std::net::SocketAddr> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).1
    }

    pub(crate) fn set(&self, egress: Egress) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).0 = Some(egress);
    }

    pub(crate) fn set_peer(&self, peer: std::net::SocketAddr) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).1 = Some(peer);
    }
}

/// The interfaces to go out of first, and those to fall back to, of
/// `state`, sail's own (`own`, its TUNs) left out: sing-box's
/// `selectInterfaces` (default_parallel_interface.go:225-290).
///
/// One deliberate deviation: interfaces of type `other` are candidates only
/// where `network_type` or `fallback_network_type` names `other`, whatever
/// the strategy. sing-box only ever has the lists Android's and Apple's
/// hosts push, of physical networks; the lists sail detects on a desktop
/// hold other VPNs' tunnels, bridges and containers' interfaces as `other`,
/// which "every interface" must not race. The default interface is kept
/// whatever its kind: it is the system's way out.
pub fn select(state: &NetworkState, own: &[String], networks: &Networks) -> (Vec<Via>, Vec<Via>) {
    let named_other = networks
        .network_type
        .iter()
        .chain(&networks.fallback_network_type)
        .any(|t| *t == NetworkType::Other);
    let interfaces: Vec<&NetworkInterface> = state
        .interfaces
        .iter()
        .filter(|i| !own.contains(&i.name))
        // The default interface is the system's way out, whatever its kind.
        .filter(|i| {
            named_other
                || i.kind != NetworkType::Other
                || state.interface.as_deref() == Some(i.name.as_str())
        })
        .collect();
    let of_types = |types: &[NetworkType]| -> Vec<&NetworkInterface> {
        interfaces
            .iter()
            .copied()
            .filter(|i| types.contains(&i.kind))
            .collect()
    };
    // The default interface, by name: the state names it so. Without one
    // known, all of them (default_parallel_interface.go:235-245).
    let default_or_all = || -> Vec<&NetworkInterface> {
        match &state.interface {
            Some(name) => interfaces
                .iter()
                .copied()
                .filter(|i| i.name == *name)
                .collect(),
            None => interfaces.clone(),
        }
    };
    let (primaries, fallbacks) = match networks.strategy {
        NetworkStrategy::Default => {
            let primaries = if networks.network_type.is_empty() {
                default_or_all()
            } else {
                of_types(&networks.network_type)
            };
            (primaries, Vec::new())
        }
        NetworkStrategy::Hybrid => {
            let primaries = if networks.network_type.is_empty() {
                interfaces.clone()
            } else {
                of_types(&networks.network_type)
            };
            (primaries, Vec::new())
        }
        NetworkStrategy::Fallback => {
            let primaries = if networks.network_type.is_empty() {
                default_or_all()
            } else {
                of_types(&networks.network_type)
            };
            // The fallback types as given may name a primary's type too:
            // that one is then in both (default_parallel_interface.go:283).
            let fallbacks = if networks.fallback_network_type.is_empty() {
                interfaces
                    .iter()
                    .copied()
                    .filter(|i| !primaries.iter().any(|p| p.name == i.name))
                    .collect()
            } else {
                of_types(&networks.fallback_network_type)
            };
            (primaries, fallbacks)
        }
    };
    let via = |list: Vec<&NetworkInterface>| list.into_iter().map(|i| Via::of(i, state)).collect();
    (via(primaries), via(fallbacks))
}

/// When a dialer last went out a fallback interface, from which, for
/// [`FAST_FALLBACK`], it races both kinds at once: sing-box's
/// `networkLastFallback`, one per dialer.
#[derive(Debug, Clone, Default)]
pub struct FallbackState(Arc<Mutex<Option<Instant>>>);

impl FallbackState {
    fn fast(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|at| at.elapsed() < FAST_FALLBACK)
    }

    fn fell_back(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }

    fn reset(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Every interface failed: why, each named, and whether one was refused
/// for want of permission (`EPERM`), as binding is on old Xiaomi systems.
#[derive(Debug)]
pub struct Failed {
    pub error: io::Error,
    pub permission: bool,
}

impl Failed {
    fn of(mut errors: Vec<(Via, io::Error)>, what: &str) -> Failed {
        let permission = errors.iter().any(|(_, e)| is_eperm(e));
        let error = match errors.len() {
            0 => io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "no available network interface",
            ),
            1 => {
                let (via, e) = errors.pop().expect("one error");
                io::Error::new(e.kind(), format!("{} {}: {}", what, via, e))
            }
            _ => {
                let kind = errors.last().map(|(_, e)| e.kind()).expect("errors");
                let each = errors
                    .iter()
                    .map(|(via, e)| format!("{} {}: {}", what, via, e))
                    .collect::<Vec<_>>()
                    .join("; ");
                io::Error::new(kind, each)
            }
        };
        Failed { error, permission }
    }
}

/// An error and what was being done when it happened, the system's error
/// kept beneath it, so that `EPERM` is still told.
#[derive(Debug)]
pub(crate) struct Context {
    pub what: String,
    pub source: io::Error,
}

impl Context {
    pub(crate) fn wrap(what: String, source: io::Error) -> io::Error {
        io::Error::new(source.kind(), Context { what, source })
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.what, self.source)
    }
}

impl std::error::Error for Context {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Whether `e`, or the error it wraps, is `EPERM`: sing-box's
/// `errors.Is(err, syscall.EPERM)` (default.go:328).
fn is_eperm(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        if e.raw_os_error() == Some(libc::EPERM) {
            return true;
        }
        e.get_ref().is_some_and(|inner| {
            inner
                .downcast_ref::<io::Error>()
                .or_else(|| inner.downcast_ref::<Context>().map(|c| &c.source))
                .is_some_and(is_eperm)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

/// Connects with `connect` out of one of `primaries` or `fallbacks`, as
/// sing-box's `dialParallelInterface` and
/// `dialParallelInterfaceFastFallback` race them
/// (default_parallel_interface.go:16-191, default.go:317-345); the
/// interface it went out of.
///
/// The primaries start at once. The fallbacks start after `delay`, or as
/// soon as any primary fails, not only once all have. The first connection
/// made wins, and the other attempts are dropped, closing what they made.
/// A win by a fallback puts `state` in fast fallback for 15s, in which all
/// start at once; the primaries then go on after the race is lost, and one
/// that connects within `delay` of the start ends it.
pub async fn race<T, F, Fut>(
    primaries: Vec<Via>,
    fallbacks: Vec<Via>,
    delay: Duration,
    state: &FallbackState,
    connect: F,
) -> Result<(T, Via), Failed>
where
    F: Fn(Via) -> Fut,
    Fut: Future<Output = io::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let fast = state.fast();
    let won = |primary: bool| {
        if !fast && !primary {
            state.fell_back();
        }
    };
    let total = primaries.len() + fallbacks.len();
    if total == 0 {
        return Err(Failed::of(Vec::new(), "dial"));
    }
    if total == 1 {
        let primary = !primaries.is_empty();
        let via = primaries.into_iter().chain(fallbacks).next().expect("one");
        return match connect(via.clone()).await {
            Ok(c) => {
                won(primary);
                Ok((c, via))
            }
            Err(e) => Err(Failed::of(vec![(via, e)], "dial")),
        };
    }
    type Report<T> = (bool, Via, io::Result<T>);
    let (tx, mut rx) = mpsc::unbounded_channel::<Report<T>>();
    let start = Instant::now();
    // Dropped when the race returns, aborting what is still connecting.
    let mut racers = tokio::task::JoinSet::new();
    let start_racer = |racers: &mut tokio::task::JoinSet<()>, primary: bool, via: Via| {
        let attempt = connect(via.clone());
        let tx = tx.clone();
        let state = state.clone();
        let racer = async move {
            let result = attempt.await;
            // The race is over: a primary that connects within `delay` of
            // its start ends fast fallback (default_parallel_interface.go:165).
            if let Err(mpsc::error::SendError((true, _, Ok(_)))) = tx.send((primary, via, result)) {
                if start.elapsed() <= delay {
                    state.reset();
                }
            }
        };
        if fast && primary {
            // On after the race, as with the dial's own context in sing-box.
            tokio::spawn(racer);
        } else {
            racers.spawn(racer);
        }
    };
    for via in primaries {
        start_racer(&mut racers, true, via);
    }
    let mut fallbacks = Some(fallbacks).filter(|f| !f.is_empty());
    if fast {
        for via in fallbacks.take().into_iter().flatten() {
            start_racer(&mut racers, false, via);
        }
    }
    let timer = tokio::time::sleep(delay);
    tokio::pin!(timer);
    let mut errors = Vec::new();
    loop {
        let report = tokio::select! {
            () = &mut timer, if fallbacks.is_some() => {
                for via in fallbacks.take().into_iter().flatten() {
                    start_racer(&mut racers, false, via);
                }
                continue;
            }
            report = rx.recv() => report.expect("a sender is held"),
        };
        match report {
            (primary, via, Ok(c)) => {
                // What others made meanwhile is dropped, closed; a primary's,
                // in fast fallback, ends it as above.
                rx.close();
                while let Ok(other) = rx.try_recv() {
                    if let (true, _, Ok(_)) = other {
                        if fast && start.elapsed() <= delay {
                            state.reset();
                        }
                    }
                }
                won(primary);
                return Ok((c, via));
            }
            (primary, via, Err(e)) => {
                errors.push((via, e));
                if errors.len() == total {
                    return Err(Failed::of(errors, "dial"));
                }
                // Any primary failing starts the fallbacks at once
                // (default_parallel_interface.go:104).
                if primary {
                    for via in fallbacks.take().into_iter().flatten() {
                        start_racer(&mut racers, false, via);
                    }
                }
            }
        }
    }
}

/// Opens with `open` on the first of `primaries`, then of `fallbacks`, that
/// takes it, one after the other: sing-box's `listenSerialInterfacePacket`
/// (default_parallel_interface.go:193-223), for UDP.
pub async fn serial<T, F, Fut>(
    primaries: Vec<Via>,
    fallbacks: Vec<Via>,
    open: F,
) -> Result<(T, Via), Failed>
where
    F: Fn(Via) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut errors = Vec::new();
    for via in primaries.into_iter().chain(fallbacks) {
        match open(via.clone()).await {
            Ok(t) => return Ok((t, via)),
            Err(e) => errors.push((via, e)),
        }
    }
    Err(Failed::of(errors, "listen"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::sleep;

    fn interface(name: &str, kind: NetworkType) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            index: None,
            kind,
            addresses: Vec::new(),
            expensive: false,
            constrained: false,
        }
    }

    /// Wi-Fi the default, cellular, a second Wi-Fi, a wired and a VPN's.
    fn state() -> NetworkState {
        NetworkState {
            interface: Some("wlan0".into()),
            interfaces: vec![
                interface("wlan0", NetworkType::Wifi),
                interface("rmnet0", NetworkType::Cellular),
                interface("wlan1", NetworkType::Wifi),
                interface("eth0", NetworkType::Ethernet),
                interface("utun9", NetworkType::Other),
                interface("tun0", NetworkType::Other),
            ],
            ..Default::default()
        }
    }

    fn networks(
        strategy: NetworkStrategy,
        types: &[NetworkType],
        fallback: &[NetworkType],
    ) -> Networks {
        Networks {
            strategy,
            implicit: false,
            network_type: types.to_vec(),
            fallback_network_type: fallback.to_vec(),
            fallback_delay: Duration::from_millis(300),
        }
    }

    fn names(vias: &[Via]) -> Vec<&str> {
        vias.iter().map(|v| v.name.as_str()).collect()
    }

    fn selected(state: &NetworkState, n: Networks) -> (Vec<String>, Vec<String>) {
        let (p, f) = select(state, &["tun0".into()], &n);
        (
            names(&p).into_iter().map(String::from).collect(),
            names(&f).into_iter().map(String::from).collect(),
        )
    }

    use NetworkStrategy::{Fallback, Hybrid};
    use NetworkType::*;

    #[test]
    fn default_takes_the_default_interface_or_the_types() {
        assert_eq!(
            selected(&state(), networks(NetworkStrategy::Default, &[], &[])),
            (vec!["wlan0".into()], vec![])
        );
        assert_eq!(
            selected(&state(), networks(NetworkStrategy::Default, &[Wifi], &[])),
            (vec!["wlan0".into(), "wlan1".into()], vec![])
        );
        // Without a default interface known, every one.
        let unknown = NetworkState {
            interface: None,
            ..state()
        };
        assert_eq!(
            selected(&unknown, networks(NetworkStrategy::Default, &[], &[])).0,
            ["wlan0", "rmnet0", "wlan1", "eth0"]
        );
        // A default interface not listed (sail's own): none.
        let own = NetworkState {
            interface: Some("tun0".into()),
            ..state()
        };
        assert_eq!(
            selected(&own, networks(NetworkStrategy::Default, &[], &[])),
            (vec![], vec![])
        );
    }

    #[test]
    fn the_default_one_is_marked_so_and_matched_by_name() {
        let mut state = state();
        state.interfaces[0].index = Some(4);
        let (primaries, _) = select(&state, &[], &networks(Hybrid, &[Wifi], &[]));
        assert_eq!(
            primaries,
            [
                Via {
                    name: "wlan0".into(),
                    index: Some(4),
                    default: true
                },
                Via {
                    name: "wlan1".into(),
                    index: None,
                    default: false
                },
            ]
        );
    }

    #[test]
    fn hybrid_takes_every_interface_or_the_types() {
        assert_eq!(
            selected(&state(), networks(Hybrid, &[], &[])).0,
            ["wlan0", "rmnet0", "wlan1", "eth0"]
        );
        assert_eq!(
            selected(&state(), networks(Hybrid, &[Cellular, Ethernet], &[])),
            (vec!["rmnet0".into(), "eth0".into()], vec![])
        );
    }

    #[test]
    fn fallback_falls_back_to_the_others_or_the_fallback_types() {
        assert_eq!(
            selected(&state(), networks(Fallback, &[], &[])),
            (
                vec!["wlan0".into()],
                vec!["rmnet0".into(), "wlan1".into(), "eth0".into()]
            )
        );
        assert_eq!(
            selected(&state(), networks(Fallback, &[Wifi], &[Cellular])),
            (vec!["wlan0".into(), "wlan1".into()], vec!["rmnet0".into()])
        );
        // The fallback types are taken as given, a primary's among them.
        assert_eq!(
            selected(&state(), networks(Fallback, &[], &[Wifi])),
            (vec!["wlan0".into()], vec!["wlan0".into(), "wlan1".into()])
        );
        // Without a default interface known, every one first and none
        // after.
        let unknown = NetworkState {
            interface: None,
            ..state()
        };
        assert_eq!(
            selected(&unknown, networks(Fallback, &[], &[])),
            (
                vec![
                    "wlan0".into(),
                    "rmnet0".into(),
                    "wlan1".into(),
                    "eth0".into()
                ],
                vec![]
            )
        );
    }

    /// sail's own TUN is never raced, even named by type.
    #[test]
    fn sail_s_own_interfaces_are_left_out() {
        assert_eq!(
            selected(&state(), networks(Hybrid, &[Other], &[])).0,
            ["utun9"]
        );
    }

    /// `other` interfaces, which on a desktop are other VPNs' and bridges,
    /// are raced only where a type list names `other`.
    #[test]
    fn other_interfaces_only_where_named() {
        assert!(!selected(&state(), networks(Hybrid, &[], &[]))
            .0
            .contains(&"utun9".into()));
        assert_eq!(
            selected(&state(), networks(Hybrid, &[Other], &[])).0,
            ["utun9"]
        );
        // Named among the fallback types, it may be a primary too.
        assert!(selected(&state(), networks(Hybrid, &[], &[Other]))
            .0
            .contains(&"utun9".into()));
        assert!(!selected(&state(), networks(Fallback, &[], &[]))
            .1
            .contains(&"utun9".into()));
        // Not the default interface: whatever its kind, it is the
        // system's way out.
        let mut state = state();
        state.interface = Some("utun9".into());
        assert_eq!(
            selected(&state, networks(NetworkStrategy::Default, &[], &[])).0,
            ["utun9"]
        );
    }

    fn via(name: &str) -> Via {
        Via {
            name: name.into(),
            index: Some(1),
            default: false,
        }
    }

    /// Answers for an interface after `ms`, or fails after it.
    fn after(
        plan: &'static [(&'static str, u64, bool)],
    ) -> impl Fn(Via) -> std::pin::Pin<Box<dyn Future<Output = io::Result<String>> + Send>> {
        move |via: Via| {
            let (_, ms, ok) = *plan
                .iter()
                .find(|(n, _, _)| *n == via.name)
                .expect("planned");
            Box::pin(async move {
                sleep(Duration::from_millis(ms)).await;
                if ok {
                    Ok(via.name)
                } else {
                    Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
                }
            })
        }
    }

    const DELAY: Duration = Duration::from_millis(300);

    async fn run(
        primaries: &[&str],
        fallbacks: &[&str],
        state: &FallbackState,
        plan: &'static [(&'static str, u64, bool)],
    ) -> (Result<String, String>, Duration) {
        let start = Instant::now();
        let r = race(
            primaries.iter().map(|n| via(n)).collect(),
            fallbacks.iter().map(|n| via(n)).collect(),
            DELAY,
            state,
            after(plan),
        )
        .await;
        (
            r.map(|(c, _)| c).map_err(|f| f.error.to_string()),
            start.elapsed(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn the_fallbacks_start_after_the_delay() {
        let state = FallbackState::default();
        // The primary hangs; the fallback answers 100ms after it starts.
        let (won, took) = run(
            &["wlan0"],
            &["rmnet0"],
            &state,
            &[("wlan0", 5000, false), ("rmnet0", 100, true)],
        )
        .await;
        assert_eq!(won.unwrap(), "rmnet0");
        assert_eq!(took, Duration::from_millis(400));
        // Won by a fallback: fast fallback now.
        assert!(state.fast());
    }

    #[tokio::test(start_paused = true)]
    async fn a_primary_failing_starts_the_fallbacks_at_once() {
        let state = FallbackState::default();
        // One primary of two fails at 50ms: the fallback starts then, not
        // once both have failed.
        let (won, took) = run(
            &["wlan0", "wlan1"],
            &["rmnet0"],
            &state,
            &[
                ("wlan0", 50, false),
                ("wlan1", 5000, false),
                ("rmnet0", 100, true),
            ],
        )
        .await;
        assert_eq!(won.unwrap(), "rmnet0");
        assert_eq!(took, Duration::from_millis(150));
    }

    #[tokio::test(start_paused = true)]
    async fn a_primary_winning_leaves_the_state_alone() {
        let state = FallbackState::default();
        let (won, took) = run(
            &["wlan0"],
            &["rmnet0"],
            &state,
            &[("wlan0", 100, true), ("rmnet0", 10, true)],
        )
        .await;
        assert_eq!(won.unwrap(), "wlan0");
        assert_eq!(took, Duration::from_millis(100));
        assert!(!state.fast());
    }

    #[tokio::test(start_paused = true)]
    async fn in_fast_fallback_all_start_at_once_for_15s() {
        let state = FallbackState::default();
        state.fell_back();
        // The fallback answers first, at once.
        let (won, took) = run(
            &["wlan0"],
            &["rmnet0"],
            &state,
            &[("wlan0", 5000, false), ("rmnet0", 100, true)],
        )
        .await;
        assert_eq!(won.unwrap(), "rmnet0");
        assert_eq!(took, Duration::from_millis(100));
        // Not renewed by winning in fast fallback: over 15s after it began.
        sleep(FAST_FALLBACK - took).await;
        assert!(!state.fast());
        let (won, took) = run(
            &["wlan0"],
            &["rmnet0"],
            &state,
            &[("wlan0", 5000, false), ("rmnet0", 100, true)],
        )
        .await;
        assert_eq!(won.unwrap(), "rmnet0");
        assert_eq!(took, Duration::from_millis(400));
    }

    /// In fast fallback, a primary that connects within the delay, though
    /// it lost, ends it; later, it does not.
    #[tokio::test(start_paused = true)]
    async fn a_primary_back_within_the_delay_ends_fast_fallback() {
        let state = FallbackState::default();
        state.fell_back();
        let (won, _) = run(
            &["wlan0"],
            &["rmnet0"],
            &state,
            &[("wlan0", 200, true), ("rmnet0", 100, true)],
        )
        .await;
        assert_eq!(won.unwrap(), "rmnet0");
        assert!(state.fast());
        sleep(Duration::from_millis(150)).await;
        assert!(!state.fast());

        state.fell_back();
        let (won, _) = run(
            &["wlan0"],
            &["rmnet0"],
            &state,
            &[("wlan0", 400, true), ("rmnet0", 100, true)],
        )
        .await;
        assert_eq!(won.unwrap(), "rmnet0");
        sleep(Duration::from_millis(500)).await;
        assert!(state.fast());
    }

    #[tokio::test(start_paused = true)]
    async fn all_failing_names_each() {
        let state = FallbackState::default();
        let (won, took) = run(
            &["wlan0"],
            &["rmnet0"],
            &state,
            &[("wlan0", 50, false), ("rmnet0", 100, false)],
        )
        .await;
        assert_eq!(
            won.unwrap_err(),
            "dial wlan0 (1): refused; dial rmnet0 (1): refused"
        );
        assert_eq!(took, Duration::from_millis(150));
        assert!(!state.fast());
    }

    #[tokio::test(start_paused = true)]
    async fn one_interface_is_dialled_alone() {
        let state = FallbackState::default();
        // A fallback alone starts at once, and counts as falling back.
        let (won, took) = run(&[], &["rmnet0"], &state, &[("rmnet0", 100, true)]).await;
        assert_eq!(won.unwrap(), "rmnet0");
        assert_eq!(took, Duration::from_millis(100));
        assert!(state.fast());
        let (won, _) = run(
            &["wlan0"],
            &[],
            &FallbackState::default(),
            &[("wlan0", 10, false)],
        )
        .await;
        assert_eq!(won.unwrap_err(), "dial wlan0 (1): refused");
    }

    #[tokio::test(start_paused = true)]
    async fn no_interface_at_all() {
        let (won, _) = run(&[], &[], &FallbackState::default(), &[]).await;
        assert_eq!(won.unwrap_err(), "no available network interface");
    }

    /// The losers are dropped once the race is won: none of them finishes.
    #[tokio::test(start_paused = true)]
    async fn the_losers_are_dropped() {
        static FINISHED: AtomicUsize = AtomicUsize::new(0);
        let connect = |via: Via| async move {
            let ms = if via.name == "wlan0" { 100 } else { 1000 };
            sleep(Duration::from_millis(ms)).await;
            FINISHED.fetch_add(1, Ordering::SeqCst);
            Ok::<_, io::Error>(via.name)
        };
        let vias = vec![via("wlan0"), via("wlan1"), via("eth0")];
        let (won, _) = race(vias, Vec::new(), DELAY, &FallbackState::default(), connect)
            .await
            .unwrap();
        assert_eq!(won, "wlan0");
        sleep(Duration::from_secs(2)).await;
        assert_eq!(FINISHED.load(Ordering::SeqCst), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_refusal_for_want_of_permission_is_told() {
        // Refused binding one interface, as an old Xiaomi system does.
        let eperm = |via: Via| async move {
            if via.name == "wlan1" {
                let e = io::Error::from_raw_os_error(libc::EPERM);
                return Err(Context::wrap(format!("bind to {}", via.name), e));
            }
            Err::<(), _>(io::Error::from(io::ErrorKind::ConnectionRefused))
        };
        let both = || vec![via("wlan0"), via("wlan1")];
        let failed = race(both(), Vec::new(), DELAY, &FallbackState::default(), eperm)
            .await
            .unwrap_err();
        assert!(failed.permission);
        assert_eq!(
            failed.error.to_string(),
            "dial wlan0 (1): connection refused; \
             dial wlan1 (1): bind to wlan1: Operation not permitted (os error 1)"
        );
        let failed = race(
            vec![via("wlan0")],
            Vec::new(),
            DELAY,
            &FallbackState::default(),
            eperm,
        )
        .await
        .unwrap_err();
        assert!(!failed.permission);
    }

    #[tokio::test]
    async fn udp_tries_the_interfaces_in_turn() {
        let tried = Mutex::new(Vec::new());
        let open = |via: Via| {
            tried.lock().unwrap().push(via.name.clone());
            let ok = via.name == "rmnet0";
            async move {
                if ok {
                    Ok(via.name)
                } else {
                    Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
                }
            }
        };
        let (opened, via) = serial(
            vec![via("wlan0"), via("wlan1")],
            vec![via("rmnet0"), via("eth0")],
            open,
        )
        .await
        .unwrap();
        assert_eq!((opened.as_str(), via.name.as_str()), ("rmnet0", "rmnet0"));
        assert_eq!(*tried.lock().unwrap(), ["wlan0", "wlan1", "rmnet0"]);
        let failed = serial(Vec::new(), Vec::new(), open).await.unwrap_err();
        assert_eq!(failed.error.to_string(), "no available network interface");
    }
}
