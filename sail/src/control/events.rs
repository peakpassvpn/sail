//! What an instance tells as it happens, beyond its log: a group switching
//! members, a connection failing. One bounded channel per kind, so that a
//! flood of one never pushes another out; the instance's, for a run.

use tokio::sync::broadcast;

/// Events a subscriber may fall behind by, per kind, before it is told it
/// lagged.
const CAPACITY: usize = 64;

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

/// A connection that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DialFailure {
    /// The outbounds it went through, the groups' members first, as the
    /// log's `out=` names them (`sel>hk-ss`).
    pub chain: String,
    /// Where it went, as `log.redact` lets the log say it.
    pub destination: String,
    pub kind: std::io::ErrorKind,
    pub stage: DialStage,
}

impl DialFailure {
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
        }
    }
}

/// The channels, one a kind; cheap to clone, every clone the same.
#[derive(Clone)]
pub struct EventHub {
    group: broadcast::Sender<GroupSwitch>,
    dial: broadcast::Sender<DialFailure>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self {
            group: broadcast::channel(CAPACITY).0,
            dial: broadcast::channel(CAPACITY).0,
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

    pub fn group_switches(&self) -> broadcast::Receiver<GroupSwitch> {
        self.group.subscribe()
    }

    pub fn dial_failures(&self) -> broadcast::Receiver<DialFailure> {
        self.dial.subscribe()
    }
}
