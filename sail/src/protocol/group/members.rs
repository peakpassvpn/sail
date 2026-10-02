//! The members of a group, by key rather than by position: the group's
//! state (its selection, its members' health) names members, so that it
//! outlives a change of the members around them.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use tokio::sync::watch;

use crate::adapter::AnyOutboundHandler;

/// A member of a group, by where it comes from and its name there.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemberKey {
    /// The provider that gives the member; `None` for an outbound of the
    /// configuration, named by its tag.
    pub source: Option<Arc<str>>,
    pub name: Arc<str>,
}

impl MemberKey {
    /// The outbound of the configuration tagged `tag`.
    pub fn outbound(tag: &str) -> Self {
        Self {
            source: None,
            name: tag.into(),
        }
    }
}

#[derive(Clone)]
pub struct Member {
    pub key: MemberKey,
    pub handler: AnyOutboundHandler,
    /// Its type, in Mihomo's name for it, which `exclude_type` goes by;
    /// empty where no group asks.
    pub kind: &'static str,
}

/// The members of a group at one time, in order.
pub struct Snapshot {
    /// Counts the snapshots of the group, from 0.
    pub version: u64,
    pub members: Vec<Member>,
}

impl Snapshot {
    pub fn position(&self, key: &MemberKey) -> Option<usize> {
        self.members.iter().position(|m| m.key == *key)
    }

    /// The first member named `name`, whatever gives it: selections are
    /// kept, and asked for, by bare name.
    pub fn find(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| &*m.key.name == name)
    }

    /// The member a group that tests its members takes until the first
    /// tests are done: the first not a `pass` outbound, which is never
    /// tested and counts as down; the first when all are.
    #[cfg(any(feature = "outbound-urltest", feature = "outbound-fallback"))]
    pub fn first_up(&self) -> Option<&Member> {
        self.members
            .iter()
            .find(|m| !m.handler.is_pass())
            .or(self.members.first())
    }
}

/// A member's last check: its latency, `None` when it failed, and when
/// it ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tested {
    pub latency: Option<Duration>,
    pub at: SystemTime,
}

/// The members' last checks, by member, as a group measures them; a
/// member missing was not checked yet. Those who show them watch it
/// change, see `subscribe`.
pub struct Health {
    tested: RwLock<HashMap<MemberKey, Tested>>,
    /// Counts the changes.
    changed: watch::Sender<u64>,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            tested: Default::default(),
            changed: watch::Sender::new(0),
        }
    }
}

impl Health {
    /// Reads the checks.
    pub fn read<R>(&self, f: impl FnOnce(&HashMap<MemberKey, Tested>) -> R) -> R {
        f(&self.tested.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// `member`'s last check, if it was checked.
    pub fn get(&self, member: &MemberKey) -> Option<Tested> {
        self.read(|tested| tested.get(member).copied())
    }

    /// Changes the checks with `f`, which says whether it changed them;
    /// those who watch hear of it if it did.
    pub fn update(&self, f: impl FnOnce(&mut HashMap<MemberKey, Tested>) -> bool) -> bool {
        let changed = f(&mut self.tested.write().unwrap_or_else(|e| e.into_inner()));
        if changed {
            self.changed.send_modify(|n| *n = n.wrapping_add(1));
        }
        changed
    }

    /// Replaces the checks with `tested`.
    pub fn replace(&self, tested: HashMap<MemberKey, Tested>) {
        self.update(|current| {
            let changed = *current != tested;
            *current = tested;
            changed
        });
    }

    /// Each change of the checks.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }
}

/// A group's `Health`, shared by the group and its selector.
pub type MemberLatencies = Arc<Health>;

/// The members of a group, which may change while it runs: its handlers
/// take the current snapshot per connection.
pub struct Members {
    current: ArcSwap<Snapshot>,
    version: watch::Sender<u64>,
}

impl Members {
    /// The outbounds of the configuration tagged `tags`, `handlers` in
    /// the same order: members that never change.
    pub fn outbounds(tags: &[String], handlers: Vec<AnyOutboundHandler>) -> Arc<Self> {
        let members = tags
            .iter()
            .zip(handlers)
            .map(|(tag, handler)| Member {
                key: MemberKey::outbound(tag),
                handler,
                kind: "",
            })
            .collect();
        Self::of(members)
    }

    /// `members`, to begin with.
    pub fn of(members: Vec<Member>) -> Arc<Self> {
        Arc::new(Self {
            current: ArcSwap::from_pointee(Snapshot {
                version: 0,
                members,
            }),
            version: watch::Sender::new(0),
        })
    }

    pub fn load(&self) -> Arc<Snapshot> {
        self.current.load_full()
    }

    /// Replaces the members.
    #[allow(dead_code)]
    pub fn publish(&self, members: Vec<Member>) {
        let version = self.current.load().version + 1;
        self.current.store(Arc::new(Snapshot { version, members }));
        self.version.send_replace(version);
    }

    /// The version of the snapshot, as the members change.
    #[allow(dead_code)]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.version.subscribe()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::adapter::outbound::HandlerBuilder;

    pub fn handler(tag: &str) -> AnyOutboundHandler {
        HandlerBuilder::default().tag(tag.to_owned()).build()
    }

    pub fn member(source: Option<&str>, name: &str) -> Member {
        Member {
            key: MemberKey {
                source: source.map(Into::into),
                name: name.into(),
            },
            handler: handler(name),
            kind: "",
        }
    }

    pub fn outbounds(tags: &[&str]) -> Arc<Members> {
        let tags: Vec<String> = tags.iter().map(|t| t.to_string()).collect();
        let handlers = tags.iter().map(|t| handler(t)).collect();
        Members::outbounds(&tags, handlers)
    }

    #[test]
    fn a_name_is_the_first_member_so_named() {
        let members = outbounds(&["a"]);
        members.publish(vec![
            member(None, "a"),
            member(Some("p1"), "HK 01"),
            member(Some("p2"), "HK 01"),
        ]);
        let snapshot = members.load();
        let hk = snapshot.find("HK 01").unwrap();
        assert_eq!(hk.key.source.as_deref(), Some("p1"));
        assert_eq!(snapshot.position(&hk.key), Some(1));
        assert!(snapshot.find("HK 02").is_none());
    }

    #[test]
    fn subscribers_see_each_snapshot() {
        let members = outbounds(&["a", "b"]);
        let mut version = members.subscribe();
        assert_eq!(members.load().version, 0);
        members.publish(vec![member(None, "b")]);
        assert!(version.has_changed().unwrap());
        assert_eq!(*version.borrow_and_update(), 1);
        assert_eq!(members.load().version, 1);
        assert_eq!(members.load().members.len(), 1);
    }
}
