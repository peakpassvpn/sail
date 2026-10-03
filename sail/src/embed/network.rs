//! The network the host is on, as an instance sees it: a snapshot, and the
//! changes connections do not survive, as events.

use std::net::IpAddr;

use futures::Stream;
use tokio::sync::broadcast::error::RecvError;

use super::{Error, Instance};
use crate::net::network as net;

/// The interface of the default route.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Interface {
    pub name: String,
    /// Its index, as `if_nametoindex` gives it; none where the host pushes
    /// the state and sail has not found it.
    pub index: Option<u32>,
}

/// What kind of network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkKind {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

/// The network now: what sail detected, or what the host pushed
/// (`set_network_state`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkState {
    /// The last change's, 0 before any; the same count as the events',
    /// from 1 in each run.
    pub generation: u64,
    /// None: offline, no default route.
    pub interface: Option<Interface>,
    pub kind: Option<NetworkKind>,
    pub gateway: Option<IpAddr>,
    /// The default interface's addresses, with their prefix lengths.
    pub addresses: Vec<(IpAddr, u8)>,
    /// Metered, as the system says.
    pub expensive: bool,
    /// In a low data mode, as the system says.
    pub constrained: bool,
    /// Behind a captive portal, as the host says.
    pub captive: bool,
}

impl NetworkState {
    /// No default interface.
    pub fn offline(&self) -> bool {
        self.interface.is_none()
    }

    fn of(state: &net::NetworkState, generation: u64) -> Self {
        NetworkState {
            generation,
            interface: state.interface.clone().map(|name| Interface {
                name,
                index: state.index,
            }),
            kind: state.kind.map(|kind| match kind {
                net::NetworkType::Wifi => NetworkKind::Wifi,
                net::NetworkType::Cellular => NetworkKind::Cellular,
                net::NetworkType::Ethernet => NetworkKind::Ethernet,
                net::NetworkType::Other => NetworkKind::Other,
            }),
            gateway: state.gateway,
            addresses: state
                .addresses
                .iter()
                .map(|inet| (inet.address(), inet.network_length()))
                .collect(),
            expensive: state.expensive,
            constrained: state.constrained,
            captive: state.captive,
        }
    }
}

/// How the network changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkChangeKind {
    /// Another default interface: a name or index differs.
    InterfaceChanged,
    /// The same interface on another network: its gateway, type or
    /// addresses (IPv6 by /64) differ; or the host or a wake says the
    /// network changed. A roam to another access point with the same
    /// addresses is no change.
    Moved,
    /// The default interface is gone.
    Offline,
    /// A default interface is back after none.
    Restored,
}

/// What made sail look at the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkChangeReason {
    /// The interface sail sends through changed.
    DefaultInterface,
    /// What sail detects changed.
    Detected,
    /// The host told it (`set_network_state`, `network_changed`).
    Host,
    /// The system woke from sleep.
    Wake,
}

/// A change of network that the connections made before do not survive.
/// Each is settled: sail's detection waits for 100 ms without a notice
/// from the system (1 s at most) before it looks; a state the host pushes
/// is taken as given.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkEvent {
    pub generation: u64,
    pub change: NetworkChangeKind,
    pub reason: NetworkChangeReason,
    pub old: NetworkState,
    pub new: NetworkState,
}

impl NetworkEvent {
    fn of(change: &net::NetworkChange) -> Self {
        let old = NetworkState::of(&change.old, change.generation.saturating_sub(1));
        let new = NetworkState::of(&change.new, change.generation);
        let kind = match (&old.interface, &new.interface) {
            (Some(_), None) => NetworkChangeKind::Offline,
            (None, Some(_)) => NetworkChangeKind::Restored,
            (Some(a), Some(b)) if a != b => NetworkChangeKind::InterfaceChanged,
            _ => NetworkChangeKind::Moved,
        };
        NetworkEvent {
            generation: change.generation,
            change: kind,
            reason: match change.reason {
                net::ChangeReason::DefaultInterface => NetworkChangeReason::DefaultInterface,
                net::ChangeReason::State => NetworkChangeReason::Detected,
                net::ChangeReason::HostPush => NetworkChangeReason::Host,
                net::ChangeReason::Wake => NetworkChangeReason::Wake,
            },
            old,
            new,
        }
    }
}

/// Kinds of event a subscription takes; `Kinds::NETWORK | …`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Kinds(u32);

impl Kinds {
    /// The instance's state: each change of it.
    pub const STATE: Kinds = Kinds(1 << 0);
    pub const NETWORK: Kinds = Kinds(1 << 1);
    /// Every kind there is, and those added later.
    pub const ALL: Kinds = Kinds(u32::MAX);

    pub fn contains(self, other: Kinds) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Kinds {
    type Output = Kinds;
    fn bitor(self, other: Kinds) -> Kinds {
        Kinds(self.0 | other.0)
    }
}

/// What happens to an instance, by kind. More kinds come; a host matches
/// with `_ => {}`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The instance's state changed to this.
    State(super::State),
    Network(NetworkEvent),
    /// This subscriber fell behind on `kind`, and `missed` events of it
    /// are gone: read the snapshot again.
    Lagged {
        kind: Kinds,
        missed: u64,
    },
}

impl Instance {
    /// The network now. Read it after subscribing to `events`, and skip
    /// the events whose generation is this one's or lower: none is then
    /// missed nor taken twice.
    pub fn network(&self) -> Result<NetworkState, Error> {
        let manager = self.manager()?;
        let now = manager.network().snapshot_with_generation();
        Ok(NetworkState::of(&now.state, now.generation))
    }

    /// The events of `kinds`, from now on, through stops and starts,
    /// until dropped. Subscribed at once: a change after this call is not
    /// missed. A run's generations count from 1; after a start, read the
    /// snapshot again.
    pub fn events(&self, kinds: Kinds) -> impl Stream<Item = Event> + Send + 'static {
        let mut streams: Vec<futures::stream::BoxStream<'static, Event>> = Vec::new();
        if kinds.contains(Kinds::STATE) {
            streams.push(Box::pin(self.state_events()));
        }
        if kinds.contains(Kinds::NETWORK) {
            streams.push(Box::pin(self.network_events()));
        }
        futures::stream::select_all(streams)
    }

    /// Each change of state, from now on.
    fn state_events(&self) -> impl Stream<Item = Event> + Send + 'static {
        futures::stream::unfold(self.inner().states(), |mut states| async move {
            states.changed().await.ok()?;
            let state = states.borrow_and_update().clone();
            Some((Event::State(state), states))
        })
    }

    fn network_events(&self) -> impl Stream<Item = Event> + Send + 'static {
        let inner = self.inner().clone();
        let network = Some(inner.manager().ok().map(|m| m.network().change_events()));
        let states = inner.states();
        futures::stream::unfold(
            (inner, network, states),
            |(inner, mut network, mut states)| async move {
                let mut subscribed = network.take()?;
                loop {
                    let Some(mut rx) = subscribed.take() else {
                        // Not running: the next run's, once it runs.
                        if states.changed().await.is_err() {
                            return None;
                        }
                        subscribed = inner.manager().ok().map(|m| m.network().change_events());
                        continue;
                    };
                    match rx.recv().await {
                        Ok(change) => {
                            let event = Event::Network(NetworkEvent::of(&change));
                            return Some((event, (inner, Some(Some(rx)), states)));
                        }
                        Err(RecvError::Lagged(missed)) => {
                            let event = Event::Lagged {
                                kind: Kinds::NETWORK,
                                missed,
                            };
                            return Some((event, (inner, Some(Some(rx)), states)));
                        }
                        // The run ended.
                        Err(RecvError::Closed) => subscribed = None,
                    }
                }
            },
        )
    }

    /// The names of the TUN devices, by inbound tag: as configured, or as
    /// sail chose them at start when none was (`chosen`). None for a TUN
    /// the host opens itself (Android, iOS).
    pub fn tun_names(&self) -> Result<std::collections::BTreeMap<String, TunName>, Error> {
        Ok(self.manager()?.tun_names())
    }
}

pub use crate::runtime::TunName;
