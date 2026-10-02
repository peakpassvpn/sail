use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::{ArcSwap, Guard};
use tokio::sync::watch;
use tracing::warn;

use anyhow::{anyhow, Result};

use crate::protocol::group::members::{
    Member, MemberKey, MemberLatencies, Members, Snapshot, Tested,
};
use crate::runtime::cache_file::CacheFile;

/// Which member a group sends its connections to, shared by the group's
/// handlers and its selector. It names the member: one selected that is
/// not a member for a while stays selected, and the group's default takes
/// the connections meanwhile. Connections that should not outlive a
/// change of member watch it, see `subscribe`.
pub struct Selection {
    /// The default, by name: the first member so named, whatever gives
    /// it.
    default: Arc<str>,
    selected: ArcSwap<MemberKey>,
    /// A member selected, by name, before any member had that name: one
    /// kept across a restart, of a provider not loaded yet. The first
    /// member to have it is selected, see `settle`.
    wanted: Mutex<Option<Arc<str>>>,
    /// Where the selected member was last found, to look there first.
    hint: AtomicUsize,
    changed: watch::Sender<MemberKey>,
}

impl Selection {
    /// `selected`, or the member named `default` while it is not a member.
    pub fn new(default: &str, selected: MemberKey) -> Self {
        Self {
            default: default.into(),
            selected: ArcSwap::from_pointee(selected.clone()),
            wanted: Mutex::new(None),
            hint: AtomicUsize::new(0),
            changed: watch::Sender::new(selected),
        }
    }

    pub fn get(&self) -> Arc<MemberKey> {
        self.selected.load_full()
    }

    pub fn set(&self, key: MemberKey) {
        *self.wanted.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.selected.store(Arc::new(key.clone()));
        self.changed.send_if_modified(|current| {
            let modified = *current != key;
            *current = key;
            modified
        });
    }

    /// Selects the first member named `name` once there is one, unless
    /// another is selected first.
    pub fn want(&self, name: &str) {
        *self.wanted.lock().unwrap_or_else(|e| e.into_inner()) = Some(name.into());
    }

    /// The name wanted, see `want`.
    fn wanted(&self) -> Option<Arc<str>> {
        self.wanted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Selects the member wanted, if `snapshot`, the members now, has it.
    pub fn settle(&self, snapshot: &Snapshot) {
        let Some(name) = self.wanted() else {
            return;
        };
        if let Some(member) = snapshot.find(&name) {
            self.set(member.key.clone());
        }
    }

    /// The selection as it changes.
    pub fn subscribe(&self) -> watch::Receiver<MemberKey> {
        self.changed.subscribe()
    }

    /// The member of `snapshot` connections go to: the one selected, or,
    /// while it is not a member, the default, or the first; with the
    /// selection it went by. `None` when there is no member.
    pub fn pick(&self, snapshot: &Snapshot) -> Option<(usize, Guard<Arc<MemberKey>>)> {
        let selected = self.selected.load();
        let i = self
            .position(&selected, snapshot)
            .or_else(|| {
                snapshot
                    .members
                    .iter()
                    .position(|m| m.key.name == self.default)
            })
            .or_else(|| (!snapshot.members.is_empty()).then_some(0))?;
        Some((i, selected))
    }

    fn position(&self, key: &MemberKey, snapshot: &Snapshot) -> Option<usize> {
        let hint = self.hint.load(Ordering::Relaxed);
        if snapshot.members.get(hint).is_some_and(|m| m.key == *key) {
            return Some(hint);
        }
        let i = snapshot.position(key)?;
        self.hint.store(i, Ordering::Relaxed);
        Some(i)
    }
}

/// How a group's member comes to be selected.
pub enum SelectedBy {
    /// By hand, through the API; the choice is kept across restarts in
    /// the cache file, if there is one.
    Hand { cache_file: Option<Arc<CacheFile>> },
    /// By the group itself, from its checks; it cannot be selected by
    /// hand.
    Checks,
    /// By the group itself, from what it is told at the time (the
    /// network the host is on): the member it would pick now, asked each
    /// time, by name; it cannot be selected by hand.
    State(Box<dyn Fn() -> String + Send + Sync>),
}

/// The checks of a group that tests its members, which the API runs and
/// feeds, as sing-box's API has its urltest groups check.
#[async_trait::async_trait]
pub trait GroupChecks: Send + Sync {
    /// Tests every member now, as the group does, and returns their
    /// latencies, `None` for those that failed.
    async fn check(&self) -> Vec<(MemberKey, Option<Duration>)>;

    /// A test of `member` made through the API, ended at `at`, counts as
    /// its last check.
    fn record(&self, member: &MemberKey, latency: Option<Duration>, at: SystemTime);
}

/// What changes as a group's state shown does: the member it selects,
/// and its members' checks. A change is a reason to look again.
pub struct GroupChanges {
    selection: watch::Receiver<MemberKey>,
    health: Option<watch::Receiver<u64>>,
}

impl GroupChanges {
    /// Returns at the next change after this was made; at once once the
    /// group is gone.
    pub async fn changed(&mut self) {
        let health = async {
            match &mut self.health {
                Some(health) => {
                    let _ = health.changed().await;
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = self.selection.changed() => {}
            _ = health => {}
        }
    }
}

/// The state of a group that sends its connections to one member at a
/// time, `selector` or `urltest`: its members, the one selected, and
/// their latencies where the group measures them.
pub struct OutboundSelector {
    id: String,
    members: Arc<Members>,
    selected: Arc<Selection>,
    selected_by: SelectedBy,
    latencies: Option<MemberLatencies>,
    checks: Option<Arc<dyn GroupChecks>>,
}

impl OutboundSelector {
    pub fn new(
        id: String,
        members: Arc<Members>,
        selected: Arc<Selection>,
        selected_by: SelectedBy,
        latencies: Option<MemberLatencies>,
    ) -> Self {
        Self {
            id,
            members,
            selected,
            selected_by,
            latencies,
            checks: None,
        }
    }

    /// With the group's own checks, for the API to run and feed.
    pub fn with_checks(mut self, checks: Arc<dyn GroupChecks>) -> Self {
        self.checks = Some(checks);
        self
    }

    /// The group's own checks, for a group that tests its members.
    pub fn checks(&self) -> Option<Arc<dyn GroupChecks>> {
        self.checks.clone()
    }

    /// The changes of what the group shows from now on.
    pub fn changes(&self) -> GroupChanges {
        GroupChanges {
            selection: self.selected.subscribe(),
            health: self.latencies.as_ref().map(|l| l.subscribe()),
        }
    }

    /// The member of the group named `name`, as the group knows it.
    pub fn member(&self, name: &str) -> Option<MemberKey> {
        self.members.load().find(name).map(|m| m.key.clone())
    }

    pub fn get_available_tags(&self) -> Vec<String> {
        let snapshot = self.members.load();
        snapshot
            .members
            .iter()
            .map(|m| m.key.name.to_string())
            .collect()
    }

    /// The member connections go to, see `Selection::pick`.
    pub fn get_selected_tag(&self) -> String {
        if let SelectedBy::State(now) = &self.selected_by {
            return now();
        }
        let snapshot = self.members.load();
        self.selected
            .pick(&snapshot)
            .map(|(i, _)| snapshot.members[i].key.name.to_string())
            .unwrap_or_default()
    }

    /// The member connections go to, as `get_selected_tag` names it.
    pub fn selected_member(&self) -> Option<Member> {
        let snapshot = self.members.load();
        let member = match &self.selected_by {
            SelectedBy::State(now) => snapshot.find(&now()),
            _ => self
                .selected
                .pick(&snapshot)
                .map(|(i, _)| &snapshot.members[i]),
        };
        member.cloned()
    }

    /// Each member with its latency, for a group that measures them.
    pub fn get_latencies(&self) -> Option<Vec<(String, Option<Duration>)>> {
        Some(
            self.get_tested()?
                .into_iter()
                .map(|(name, tested)| (name, tested.and_then(|t| t.latency)))
                .collect(),
        )
    }

    /// Each member with its last check, failed or not, for a group that
    /// checks them; `None` for one not checked yet.
    pub fn get_tested(&self) -> Option<Vec<(String, Option<Tested>)>> {
        let latencies = self.latencies.as_ref()?;
        let snapshot = self.members.load();
        Some(latencies.read(|tested| {
            snapshot
                .members
                .iter()
                .map(|m| (m.key.name.to_string(), tested.get(&m.key).copied()))
                .collect()
        }))
    }

    /// Takes over what `previous`, the selector this one replaces, has
    /// selected by hand: the member itself, which need not be a member
    /// now, and not the one connections go to meanwhile; or the one it
    /// still waits for. It is kept
    /// already, so it is not kept again.
    pub fn restore(&self, previous: &OutboundSelector) {
        if self.is_selectable() && previous.is_selectable() {
            self.selected.set((*previous.selected.get()).clone());
            if let Some(name) = previous.selected.wanted() {
                self.selected.want(&name);
            }
        }
    }

    /// Whether a member can be selected by hand.
    pub fn is_selectable(&self) -> bool {
        matches!(self.selected_by, SelectedBy::Hand { .. })
    }

    /// Selects the member `tag`, the first so named, by hand, and keeps
    /// the choice.
    pub fn set_selected(&mut self, tag: &str) -> Result<()> {
        let SelectedBy::Hand { cache_file } = &self.selected_by else {
            return Err(anyhow!(
                "[{}] selects its outbound by itself, not by hand",
                self.id
            ));
        };
        let Some(member) = self.members.load().find(tag).map(|m| m.key.clone()) else {
            return Err(anyhow!("[{}] has no outbound [{}]", self.id, tag));
        };
        self.selected.set(member);
        if let Some(cache_file) = cache_file {
            if let Err(e) = cache_file.store_selected(&self.id, tag) {
                warn!("[{}] selection will not be kept: {}", self.id, e);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::group::members::tests::{member, outbounds};

    fn key(name: &str) -> MemberKey {
        MemberKey::outbound(name)
    }

    fn picked(selection: &Selection, members: &Members) -> String {
        let snapshot = members.load();
        let (i, _) = selection.pick(&snapshot).unwrap();
        snapshot.members[i].key.name.to_string()
    }

    #[test]
    fn a_selection_absent_is_kept_and_the_default_used_meanwhile() {
        let members = outbounds(&["a", "b", "c"]);
        let selection = Selection::new("b", key("c"));
        assert_eq!(picked(&selection, &members), "c");

        members.publish(vec![member(None, "a"), member(None, "b")]);
        assert_eq!(picked(&selection, &members), "b");
        assert_eq!(*selection.get(), key("c"));

        members.publish(vec![
            member(None, "c"),
            member(None, "a"),
            member(None, "b"),
        ]);
        assert_eq!(picked(&selection, &members), "c");
    }

    #[test]
    fn without_the_default_the_first_member_is_used() {
        let members = outbounds(&["a", "b"]);
        let selection = Selection::new("b", key("b"));
        members.publish(vec![member(None, "x"), member(None, "y")]);
        assert_eq!(picked(&selection, &members), "x");
        members.publish(vec![]);
        assert!(selection.pick(&members.load()).is_none());
    }

    #[test]
    fn a_member_of_the_same_name_from_elsewhere_is_another_member() {
        let members = outbounds(&["a"]);
        members.publish(vec![member(None, "a"), member(Some("p"), "b")]);
        let selection = Selection::new("a", key("b"));
        assert_eq!(picked(&selection, &members), "a");
    }

    #[test]
    fn the_selector_selects_and_reports_by_name() {
        let members = outbounds(&["a", "b"]);
        let selection = Arc::new(Selection::new("a", key("a")));
        let latencies = MemberLatencies::default();
        latencies.update(|tested| {
            tested.insert(
                key("b"),
                Tested {
                    latency: Some(Duration::from_millis(20)),
                    at: SystemTime::now(),
                },
            );
            true
        });
        let mut selector = OutboundSelector::new(
            "g".to_string(),
            members.clone(),
            selection.clone(),
            SelectedBy::Hand { cache_file: None },
            Some(latencies),
        );
        assert_eq!(selector.get_available_tags(), ["a", "b"]);
        assert_eq!(selector.get_selected_tag(), "a");
        selector.set_selected("b").unwrap();
        assert_eq!(selector.get_selected_tag(), "b");
        assert!(selector.set_selected("c").is_err());
        assert_eq!(
            selector.get_latencies().unwrap(),
            [
                ("a".to_string(), None),
                ("b".to_string(), Some(Duration::from_millis(20)))
            ]
        );

        // Its member gone, the selection shows the default, and comes
        // back with it.
        members.publish(vec![member(None, "a")]);
        assert_eq!(selector.get_selected_tag(), "a");
        members.publish(vec![member(None, "a"), member(None, "b")]);
        assert_eq!(selector.get_selected_tag(), "b");
    }

    #[test]
    fn a_reload_keeps_a_selection_absent_and_the_cache() {
        let dir = std::env::temp_dir().join(format!("sail-selector-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let env = crate::runtime::cache_file::tests::env(&dir);
        env.cache_file
            .replace(Some(&crate::runtime::cache_file::tests::enabled()), &env)
            .unwrap()
            .keep();
        let cache_file = env.cache_file.get().unwrap();
        let members = outbounds(&["a", "b"]);
        let mut old = OutboundSelector::new(
            "g".to_string(),
            members.clone(),
            Arc::new(Selection::new("a", key("a"))),
            SelectedBy::Hand {
                cache_file: Some(cache_file.clone()),
            },
            None,
        );
        old.set_selected("b").unwrap();
        members.publish(vec![member(None, "a")]);
        assert_eq!(old.get_selected_tag(), "a");

        let selection = Arc::new(Selection::new("a", key("a")));
        let new = OutboundSelector::new(
            "g".to_string(),
            members.clone(),
            selection.clone(),
            SelectedBy::Hand {
                cache_file: Some(cache_file.clone()),
            },
            None,
        );
        new.restore(&old);
        assert_eq!(*selection.get(), key("b"));
        assert_eq!(cache_file.load_selected("g").unwrap().as_deref(), Some("b"));
        members.publish(vec![member(None, "a"), member(None, "b")]);
        assert_eq!(new.get_selected_tag(), "b");
        drop((old, new, cache_file));
        env.cache_file.replace(None, &env).unwrap().keep();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
