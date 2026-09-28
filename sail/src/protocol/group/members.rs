//! The members of a group, by key rather than by position: the group's
//! state (its selection, its members' health) names members, so that it
//! outlives a change of the members around them.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

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

pub struct Member {
    pub key: MemberKey,
    pub handler: AnyOutboundHandler,
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
}

/// The latency of each member, as the last check measured it; `None`
/// for a member that failed it. A member missing was not checked yet.
pub type MemberLatencies = Arc<RwLock<HashMap<MemberKey, Option<Duration>>>>;

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
            })
            .collect();
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
