//! The users inbounds authenticate. A user is a name, one namespace for
//! the whole instance, as in sing-box: the same name in two inbounds, or
//! on two credentials of one inbound, is one user.
//!
//! Inbounds bind each named credential to its user when they build their
//! credential tables, and put the user in the session once a connection
//! authenticates: nothing is looked up by name on the data path. A reload
//! binds the names again and gets the same users, as long as the old
//! tables hold them.
//!
//! A user's traffic is counted in its state, so it goes on across reloads;
//! with `experimental.cache_file`, across restarts too. A user no table or
//! session holds any more is dropped with its counts, as sing-box's
//! ssm-api drops a deleted user's.
//!
//! `user_limits`, a sail extension, limits a user across every inbound it
//! is in: its live connections, its bytes up and down together, and until
//! when it may connect. A user over its quota or past its expiry is shut
//! out at once: its connections are closed, and new ones are refused as
//! those of an unknown user.

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;

use crate::app::stat_manager::{Counter, Counts};

mod limits;
pub use limits::{Limits, Status};

/// What sail keeps of a user while it runs.
pub struct UserState {
    name: Arc<str>,
    traffic: UserTraffic,
    limits: Mutex<Limits>,
    /// Up and down together at which the quota runs out: `u64::MAX`
    /// without one. Read on the data path, where `limits` is not.
    quota_at: AtomicU64,
    /// Up and down together when the quota was last reset.
    quota_base: AtomicU64,
    /// What shuts the user out, as `Status` bits; none when it may connect.
    status: AtomicU8,
    /// The live connections, by id.
    live: Mutex<HashMap<u64, Arc<Counter>>>,
    /// The connections that carry others, a QUIC connection or a
    /// multiplexed one, by the inbound they came in through: closed with
    /// the user's, so that its client connects again and is refused.
    carriers: Mutex<HashMap<u64, (Arc<str>, CloseCarrier)>>,
    /// The inbounds it was taken out of. A session a transport keeps may
    /// still let it open streams under the credentials it had; they are
    /// refused.
    removed: Mutex<std::collections::HashSet<Arc<str>>>,
}

/// What closes a carrier.
type CloseCarrier = Box<dyn Fn() + Send + Sync>;

/// Keeps a carrier among its user's while it lives.
pub struct Carrier {
    user: UserRef,
    id: u64,
}

impl Drop for Carrier {
    fn drop(&mut self) {
        self.user
            .carriers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

impl fmt::Debug for UserState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UserState")
            .field("name", &self.name)
            .field("traffic", &self.traffic)
            .field("status", &self.status())
            .finish()
    }
}

impl UserState {
    fn new(name: &str, counts: Counts) -> Self {
        UserState {
            name: name.into(),
            traffic: UserTraffic::new(counts),
            limits: Mutex::default(),
            quota_at: AtomicU64::new(u64::MAX),
            quota_base: AtomicU64::new(0),
            status: AtomicU8::new(0),
            live: Mutex::default(),
            carriers: Mutex::default(),
            removed: Mutex::default(),
        }
    }

    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    pub fn traffic(&self) -> &UserTraffic {
        &self.traffic
    }

    pub fn limits(&self) -> Limits {
        self.limits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn status(&self) -> Status {
        Status::from_bits(self.status.load(Ordering::Acquire))
    }

    /// Whether the user may connect: neither over its quota nor expired.
    pub fn active(&self) -> bool {
        self.status.load(Ordering::Acquire) == 0
    }

    /// Bytes up and down together since the quota was last reset.
    pub fn quota_used(&self) -> u64 {
        let c = self.traffic.counts();
        (c.up + c.down).saturating_sub(self.quota_base.load(Ordering::Relaxed))
    }

    /// How many connections are live.
    pub fn live(&self) -> usize {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Takes `counter` among the live connections, unless the user may not
    /// connect or has as many as it may.
    pub(crate) fn admit(&self, counter: &Arc<Counter>) -> bool {
        if self.removed_from(&counter.sess.inbound_tag) {
            return false;
        }
        let max = self.limits().max_connections;
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        // Checked under the lock `shut` takes: a connection admitted is
        // one it closes.
        if !self.active() || max.is_some_and(|max| live.len() >= max as usize) {
            return false;
        }
        live.insert(counter.id, counter.clone());
        true
    }

    /// Whether a connection through the inbound `tag` would be admitted
    /// now; `admit` decides.
    pub fn admits(&self, tag: &str) -> bool {
        let max = self.limits().max_connections;
        self.active() && !self.removed_from(tag) && max.is_none_or(|max| self.live() < max as usize)
    }

    /// Whether it was taken out of the inbound `tag`.
    pub fn removed_from(&self, tag: &str) -> bool {
        self.removed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(tag)
    }

    pub(crate) fn leave(&self, id: u64) {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    /// Closes the live connections, and what carries them; how many
    /// connections there were.
    pub fn disconnect(&self) -> usize {
        self.disconnect_where(|_| true)
    }

    /// Closes the live connections that came in through the inbound `tag`,
    /// and what carries them there; how many connections there were.
    pub fn disconnect_inbound(&self, tag: &str) -> usize {
        self.disconnect_where(|inbound| inbound == tag)
    }

    fn disconnect_where(&self, inbound: impl Fn(&str) -> bool) -> usize {
        let mut closed = 0;
        for counter in self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|c| inbound(&c.sess.inbound_tag))
        {
            counter.closer.close();
            closed += 1;
        }
        for (_, close) in self
            .carriers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|(tag, _)| inbound(tag))
        {
            close();
        }
        closed
    }

    /// Sets `bits` in the status; shuts the user out if it was active.
    fn shut(&self, bits: u8) {
        let _live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let was = self.status.fetch_or(bits, Ordering::AcqRel);
        drop(_live);
        if was == 0 && bits != 0 {
            let closed = self.disconnect();
            tracing::info!(
                "user [{}]: {}; {} connections closed",
                self.name,
                Status::from_bits(bits),
                closed
            );
        }
    }

    fn clear(&self, bits: u8) {
        self.status.fetch_and(!bits, Ordering::AcqRel);
    }

    /// Checks the quota, on the data path, after bytes were counted.
    pub(crate) fn check_quota(&self) {
        let at = self.quota_at.load(Ordering::Relaxed);
        if at != u64::MAX {
            let c = &self.traffic;
            let total = c.up.load(Ordering::Relaxed) + c.down.load(Ordering::Relaxed);
            if total >= at && self.status.load(Ordering::Relaxed) & Status::EXHAUSTED == 0 {
                self.shut(Status::EXHAUSTED);
            }
        }
    }

    /// Takes `limits`, as `now` is: a user back within them may connect
    /// again, and one no longer is shut out.
    fn apply(&self, limits: Limits, now: SystemTime) {
        let base = self.quota_base.load(Ordering::Relaxed);
        let at = match limits.quota_bytes {
            Some(quota) => base.saturating_add(quota),
            None => u64::MAX,
        };
        let expired = limits.expire_at.is_some_and(|at| at <= now);
        *self.limits.lock().unwrap_or_else(|e| e.into_inner()) = limits;
        self.quota_at.store(at, Ordering::Relaxed);
        let c = self.traffic.counts();
        let mut shut = 0;
        let mut clear = 0;
        match c.up + c.down >= at {
            true => shut |= Status::EXHAUSTED,
            false => clear |= Status::EXHAUSTED,
        }
        match expired {
            true => shut |= Status::EXPIRED,
            false => clear |= Status::EXPIRED,
        }
        self.clear(clear);
        self.shut(shut);
    }

    /// Resets the quota: what was used so far no longer counts.
    pub fn reset_quota(&self) {
        let c = self.traffic.counts();
        self.quota_base.store(c.up + c.down, Ordering::Relaxed);
        let limits = self.limits();
        self.apply(limits, SystemTime::now());
    }

    /// Expires the user if its time has come; when it expires, if later.
    fn expire_if_due(&self, now: SystemTime) -> Option<SystemTime> {
        let at = self.limits().expire_at?;
        if at <= now {
            self.shut(Status::EXPIRED);
            None
        } else {
            Some(at)
        }
    }
}

/// A user's traffic: plain counters, as only the user's own connections
/// add to them.
#[derive(Debug, Default)]
pub struct UserTraffic {
    pub(crate) up: AtomicU64,
    pub(crate) down: AtomicU64,
    tcp: AtomicU64,
    udp: AtomicU64,
}

impl UserTraffic {
    fn new(counts: Counts) -> Self {
        UserTraffic {
            up: counts.up.into(),
            down: counts.down.into(),
            tcp: counts.tcp.into(),
            udp: counts.udp.into(),
        }
    }

    pub(crate) fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn add_down(&self, n: u64) {
        self.down.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn add_session(&self, udp: bool) {
        match udp {
            false => &self.tcp,
            true => &self.udp,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn counts(&self) -> Counts {
        Counts {
            up: self.up.load(Ordering::Relaxed),
            down: self.down.load(Ordering::Relaxed),
            tcp: self.tcp.load(Ordering::Relaxed),
            udp: self.udp.load(Ordering::Relaxed),
        }
    }
}

/// A user, as sessions and credential tables hold it. Two are equal when
/// their names are.
#[derive(Clone)]
pub struct UserRef(Arc<UserState>);

static NEXT_CARRIER: AtomicU64 = AtomicU64::new(0);

impl UserRef {
    /// Keeps `close`, which closes a connection that carries others of
    /// this user through the inbound `tag`, until the guard is dropped:
    /// called when the user is shut out, or taken out of the inbound.
    /// Closed at once if the user is shut out already.
    pub fn carry(&self, tag: &str, close: impl Fn() + Send + Sync + 'static) -> Carrier {
        let id = NEXT_CARRIER.fetch_add(1, Ordering::Relaxed);
        {
            let _live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            if !self.active() {
                close();
            }
            self.carriers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id, (tag.into(), Box::new(close)));
        }
        Carrier {
            user: self.clone(),
            id,
        }
    }

    /// A user of no registry, for tests that need a session with one.
    #[cfg(test)]
    pub fn unbound(name: &str) -> Self {
        UserRef(Arc::new(UserState::new(name, Counts::default())))
    }

    /// Whether `self` and `other` are the same user object, not only the
    /// same name.
    pub fn same(&self, other: &UserRef) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Deref for UserRef {
    type Target = UserState;
    fn deref(&self) -> &UserState {
        &self.0
    }
}

impl PartialEq for UserRef {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for UserRef {}

impl Hash for UserRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state)
    }
}

impl fmt::Display for UserRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl fmt::Debug for UserRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&*self.name, f)
    }
}

/// The name of `user`, if there is one.
pub fn name(user: &Option<UserRef>) -> Option<&str> {
    user.as_ref().map(|user| &*user.name)
}

/// Whether `user` is one `user_limits` shuts out: an inbound refuses its
/// credential as that of no user.
pub fn shut_out(user: &Option<UserRef>) -> bool {
    user.as_ref().is_some_and(|user| !user.active())
}

/// Passwords by username, each with the user it authenticates, for the
/// inbounds whose username is the user's name: HTTP, SOCKS and mixed.
pub type Passwords = HashMap<String, (String, Option<UserRef>)>;

/// `Passwords` of `(username, password)` pairs, for tests.
#[cfg(test)]
pub fn passwords(pairs: &[(&str, &str)]) -> Passwords {
    let users = UserRegistry::default();
    pairs
        .iter()
        .map(|(name, password)| {
            (
                name.to_string(),
                (password.to_string(), users.bind_named(Some(name))),
            )
        })
        .collect()
}

/// The instance's users by name. Copies share them. It holds them weakly:
/// a user lives as long as a credential table or a session holds it.
#[derive(Clone, Default)]
pub struct UserRegistry(Arc<Mutex<Registry>>);

#[derive(Default)]
struct Registry {
    users: HashMap<Arc<str>, Weak<UserState>>,
    /// The counts the cache file kept, for users not made yet.
    kept: HashMap<String, Counts>,
    /// The limits configured, by name.
    limits: HashMap<String, Limits>,
    /// Wakes what expires users when the limits change.
    changed: Arc<tokio::sync::Notify>,
}

impl UserRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The user named `name`, made if there is none. Used when inbounds
    /// build, not on the data path.
    pub fn bind(&self, name: &str) -> UserRef {
        let mut registry = self.lock();
        if let Some(user) = registry.users.get(name).and_then(Weak::upgrade) {
            return UserRef(user);
        }
        registry.users.retain(|_, user| user.strong_count() > 0);
        let counts = registry.kept.remove(name).unwrap_or_default();
        let user = Arc::new(UserState::new(name, counts));
        let limits = registry.limits.get(name).cloned().unwrap_or_default();
        user.apply(limits, SystemTime::now());
        registry
            .users
            .insert(user.name.clone(), Arc::downgrade(&user));
        UserRef(user)
    }

    /// Starts the users made from now on with the counts `kept`, the cache
    /// file's.
    pub(crate) fn keep(&self, kept: HashMap<String, Counts>) {
        self.lock().kept = kept;
    }

    /// The limits `config` sets, by user.
    pub fn configured(config: &crate::config::Config) -> HashMap<String, Limits> {
        config
            .user_limits
            .iter()
            .map(|(name, limits)| (name.clone(), Limits::from_config(limits)))
            .collect()
    }

    /// Limits the users by `limits`, those there are and those made from
    /// now on; the users `limits` does not name are not limited.
    pub fn set_limits(&self, limits: HashMap<String, Limits>) {
        let (users, changed) = {
            let mut registry = self.lock();
            registry.limits = limits.clone();
            (
                registry
                    .users
                    .values()
                    .filter_map(Weak::upgrade)
                    .collect::<Vec<_>>(),
                registry.changed.clone(),
            )
        };
        let now = SystemTime::now();
        for user in users {
            let limits = limits.get(&*user.name).cloned().unwrap_or_default();
            user.apply(limits, now);
        }
        changed.notify_one();
    }

    /// Expires each user at its time: sleeps until the next one is due,
    /// or a minute at most, as the system clock may jump, or until the
    /// limits change.
    pub fn expiry_task(&self) -> crate::Runner {
        let registry = self.clone();
        Box::pin(async move {
            let changed = registry.lock().changed.clone();
            loop {
                let now = SystemTime::now();
                let next = registry
                    .users()
                    .iter()
                    .filter_map(|user| user.expire_if_due(now))
                    .min();
                let wait = next
                    .and_then(|at| at.duration_since(now).ok())
                    .unwrap_or(limits::RECHECK)
                    .min(limits::RECHECK);
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = changed.notified() => {}
                }
            }
        })
    }

    /// The users there are.
    pub fn users(&self) -> Vec<UserRef> {
        self.lock()
            .users
            .values()
            .filter_map(Weak::upgrade)
            .map(UserRef)
            .collect()
    }

    /// Takes the user `name` out of the inbound `tag`: what it has through
    /// it is closed, and what it would open refused; how many connections
    /// there were.
    pub fn remove_from(&self, name: &str, tag: &str) -> usize {
        let user = self.lock().users.get(name).and_then(Weak::upgrade);
        user.map_or(0, |user| {
            user.removed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(tag.into());
            user.disconnect_inbound(tag)
        })
    }

    /// Puts the user `name` in the inbound `tag` again, if it was taken out.
    pub fn restore_to(&self, name: &str, tag: &str) {
        if let Some(user) = self.lock().users.get(name).and_then(Weak::upgrade) {
            user.removed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(tag);
        }
    }

    /// The user named `name` for a credential that may have none: sing-box
    /// gives no identity to a user without a name.
    pub fn bind_named(&self, name: Option<&str>) -> Option<UserRef> {
        name.filter(|name| !name.is_empty())
            .map(|name| self.bind(name))
    }
}

impl fmt::Debug for UserRegistry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let registry = self.lock();
        f.debug_set()
            .entries(
                registry
                    .users
                    .iter()
                    .filter(|(_, u)| u.strong_count() > 0)
                    .map(|(n, _)| n),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_bound_twice_is_one_user() {
        let users = UserRegistry::default();
        let a = users.bind("alice");
        let b = users.clone().bind("alice");
        assert!(a.same(&b));
        assert!(!a.same(&users.bind("bob")));
    }

    #[test]
    fn a_user_no_one_holds_is_made_anew() {
        let users = UserRegistry::default();
        let old = Arc::downgrade(&users.bind("alice").0);
        assert!(old.upgrade().is_none());
        let _new = users.bind("alice");
        assert_eq!(users.lock().users.len(), 1);
    }

    #[test]
    fn an_empty_or_missing_name_is_no_user() {
        let users = UserRegistry::default();
        assert!(users.bind_named(None).is_none());
        assert!(users.bind_named(Some("")).is_none());
        assert_eq!(users.bind_named(Some("a")).unwrap().to_string(), "a");
    }

    #[cfg(all(feature = "inbound-trojan", feature = "inbound-http"))]
    mod inbounds {
        use super::*;
        use crate::adapter::{registry, AnyInboundHandler, InboundTransport};
        use crate::runtime::RuntimeEnv;
        use crate::session::Session;
        use sha2::{Digest, Sha224};
        use tokio::io::AsyncWriteExt;

        fn build(
            env: &RuntimeEnv,
            inbounds: serde_json::Value,
        ) -> HashMap<String, AnyInboundHandler> {
            let inbounds: Vec<crate::config::Inbound> = serde_json::from_value(inbounds).unwrap();
            let mut handlers = HashMap::new();
            registry::build_inbounds(
                &crate::include::INBOUNDS,
                &inbounds,
                crate::include::LISTENER_INBOUNDS,
                env,
                &Default::default(),
                &mut handlers,
                &mut HashMap::new(),
                &mut HashMap::new(),
            )
            .unwrap();
            handlers
        }

        async fn user(handler: &AnyInboundHandler, wire: Vec<u8>) -> Option<UserRef> {
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(&wire).await.unwrap();
            match handler
                .stream()
                .unwrap()
                .handle(Session::default(), Box::new(server))
                .await
                .unwrap()
            {
                InboundTransport::Stream(_, sess) => sess.user,
                _ => panic!("expected a stream"),
            }
        }

        fn trojan(password: &str) -> Vec<u8> {
            let mut wire = hex::encode(Sha224::digest(password.as_bytes())).into_bytes();
            wire.extend_from_slice(b"\r\n\x01\x01\x7f\x00\x00\x01\x00\x50\r\n");
            wire
        }

        fn http(credentials: &str) -> Vec<u8> {
            use base64::Engine;
            let auth = base64::engine::general_purpose::STANDARD.encode(credentials);
            format!("CONNECT 127.0.0.1:80 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")
                .into_bytes()
        }

        fn inbounds(trojan_users: serde_json::Value) -> serde_json::Value {
            serde_json::json!([
                { "type": "trojan", "tag": "t", "users": trojan_users },
                { "type": "http", "tag": "h",
                  "users": [{ "username": "alice", "password": "hp" }] },
            ])
        }

        #[tokio::test]
        async fn one_name_in_two_inbounds_is_one_user_across_reloads() {
            let env = RuntimeEnv::default();
            let handlers = build(
                &env,
                inbounds(serde_json::json!([
                    { "name": "alice", "password": "tp" },
                    { "name": "alice", "password": "tp2" },
                ])),
            );
            let by_trojan = user(&handlers["t"], trojan("tp")).await.unwrap();
            let by_second = user(&handlers["t"], trojan("tp2")).await.unwrap();
            let by_http = user(&handlers["h"], http("alice:hp")).await.unwrap();
            assert_eq!(by_trojan.to_string(), "alice");
            assert!(by_trojan.same(&by_second));
            assert!(by_trojan.same(&by_http));

            // A reload builds the tables again while the old ones hold the
            // users: the new tables get the same users.
            let reloaded = build(
                &env,
                inbounds(serde_json::json!([
                    { "name": "alice", "password": "tp" },
                ])),
            );
            drop(handlers);
            let after = user(&reloaded["t"], trojan("tp")).await.unwrap();
            assert!(after.same(&by_trojan));
        }

        /// A user shut out fails to authenticate, as one unknown does.
        #[tokio::test]
        async fn a_user_shut_out_is_refused_as_unknown() {
            let env = RuntimeEnv::default();
            let handlers = build(
                &env,
                inbounds(serde_json::json!([{ "name": "alice", "password": "tp" }])),
            );
            env.users.set_limits(HashMap::from([(
                "alice".to_string(),
                Limits {
                    expire_at: Some(std::time::UNIX_EPOCH),
                    ..Default::default()
                },
            )]));
            for (tag, wire) in [("t", trojan("tp")), ("h", http("alice:hp"))] {
                let (mut client, server) = tokio::io::duplex(4096);
                client.write_all(&wire).await.unwrap();
                let refused = handlers[tag]
                    .stream()
                    .unwrap()
                    .handle(Session::default(), Box::new(server))
                    .await;
                assert!(refused.is_err(), "{}", tag);
            }
            env.users.set_limits(HashMap::new());
            assert_eq!(
                user(&handlers["t"], trojan("tp"))
                    .await
                    .unwrap()
                    .to_string(),
                "alice"
            );
        }

        #[tokio::test]
        async fn a_credential_without_a_name_gives_no_user() {
            let env = RuntimeEnv::default();
            let handlers = build(
                &env,
                inbounds(serde_json::json!([
                    { "name": "", "password": "empty" },
                    { "password": "missing" },
                ])),
            );
            assert!(user(&handlers["t"], trojan("empty")).await.is_none());
            assert!(user(&handlers["t"], trojan("missing")).await.is_none());
        }
    }

    mod limits {
        use super::*;
        use crate::app::stat_manager::StatManager;
        use crate::session::{Network, Session};
        use std::time::Duration;

        fn limited(users: &UserRegistry, name: &str, limits: Limits) {
            users.set_limits(HashMap::from([(name.to_string(), limits)]));
        }

        fn session(user: &UserRef) -> Session {
            Session {
                user: Some(user.clone()),
                network: Network::Tcp,
                ..Default::default()
            }
        }

        fn stream(sm: &StatManager, user: &UserRef) -> crate::adapter::AnyStream {
            let (a, _b) = tokio::io::duplex(1 << 16);
            std::mem::forget(_b);
            sm.stat_stream(Box::new(a), session(user))
        }

        fn closed(sm: &StatManager) -> Vec<bool> {
            sm.connections()
                .iter()
                .map(|c| c.closer.is_closed())
                .collect()
        }

        #[tokio::test]
        async fn a_user_at_its_most_connections_is_refused_another() {
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            limited(
                &users,
                "alice",
                Limits {
                    max_connections: Some(2),
                    ..Default::default()
                },
            );
            let sm = StatManager::new(0, users.clone());
            let first = stream(&sm, &alice);
            let _second = stream(&sm, &alice);
            assert!(!alice.admits(""));
            let _third = stream(&sm, &alice);
            assert_eq!(closed(&sm), [false, false, true]);
            assert_eq!(alice.live(), 2);
            // One gone, another may come.
            drop(first);
            assert!(alice.admits(""));
            let _fourth = stream(&sm, &alice);
            assert_eq!(alice.live(), 2);
            assert_eq!(closed(&sm), [false, true, false]);
            // Others are not limited by it.
            let bob = users.bind("bob");
            let _bobs = (stream(&sm, &bob), stream(&sm, &bob), stream(&sm, &bob));
            assert_eq!(bob.live(), 3);
        }

        /// Crossing the quota closes every live connection of the user, and
        /// refuses new ones, until the quota is raised.
        #[tokio::test]
        async fn crossing_the_quota_shuts_the_user_out() {
            use tokio::io::AsyncWriteExt;
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            let bob = users.bind("bob");
            limited(
                &users,
                "alice",
                Limits {
                    quota_bytes: Some(10),
                    ..Default::default()
                },
            );
            let sm = StatManager::new(0, users.clone());
            let mut a = stream(&sm, &alice);
            let _idle = stream(&sm, &alice);
            let _bobs = stream(&sm, &bob);
            a.write_all(b"123456789").await.unwrap();
            assert!(alice.active());
            a.write_all(b"0").await.unwrap();
            assert!(alice.status().exhausted());
            assert_eq!(closed(&sm), [true, true, false]);
            assert_eq!(alice.quota_used(), 10);
            assert!(!alice.admits(""));
            assert!(shut_out(&Some(alice.clone())));
            assert!(a.write_all(b"x").await.is_err());

            // A bigger quota lets it in again.
            limited(
                &users,
                "alice",
                Limits {
                    quota_bytes: Some(20),
                    ..Default::default()
                },
            );
            assert!(alice.active());
            // A reset quota counts from what was used.
            limited(
                &users,
                "alice",
                Limits {
                    quota_bytes: Some(10),
                    ..Default::default()
                },
            );
            assert!(!alice.active());
            alice.reset_quota();
            assert!(alice.active());
            assert_eq!(alice.quota_used(), 0);
        }

        #[tokio::test]
        async fn an_expired_user_is_shut_out_at_its_time() {
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            let sm = StatManager::new(0, users.clone());
            let _a = stream(&sm, &alice);
            let expiry = tokio::spawn(users.expiry_task());
            let at = SystemTime::now() + Duration::from_millis(300);
            limited(
                &users,
                "alice",
                Limits {
                    expire_at: Some(at),
                    ..Default::default()
                },
            );
            assert!(alice.active());
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(alice.active());
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert!(alice.status().expired());
            assert_eq!(closed(&sm), [true]);
            // Later expiry, and it may come back.
            limited(
                &users,
                "alice",
                Limits {
                    expire_at: Some(SystemTime::now() + Duration::from_secs(3600)),
                    ..Default::default()
                },
            );
            assert!(alice.active());
            expiry.abort();
        }

        /// A carrier is closed with its user's connections, or those of
        /// its inbound, until it is dropped; at once when the user is shut
        /// out already.
        #[test]
        fn carriers_close_with_their_user() {
            use std::sync::atomic::{AtomicUsize, Ordering};
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            let closes = Arc::new(AtomicUsize::new(0));
            let counting = || {
                let closes = closes.clone();
                move || {
                    closes.fetch_add(1, Ordering::SeqCst);
                }
            };
            let on_a = alice.carry("a", counting());
            let _on_b = alice.carry("b", counting());
            alice.disconnect_inbound("a");
            assert_eq!(closes.load(Ordering::SeqCst), 1);
            alice.disconnect();
            assert_eq!(closes.load(Ordering::SeqCst), 3);
            drop(on_a);
            alice.disconnect();
            assert_eq!(closes.load(Ordering::SeqCst), 4);

            limited(
                &users,
                "alice",
                Limits {
                    expire_at: Some(SystemTime::UNIX_EPOCH),
                    ..Default::default()
                },
            );
            let before = closes.load(Ordering::SeqCst);
            let _late = alice.carry("a", counting());
            assert_eq!(closes.load(Ordering::SeqCst), before + 1);
        }

        #[test]
        fn a_user_made_after_the_limits_is_limited_by_them() {
            let users = UserRegistry::default();
            limited(
                &users,
                "alice",
                Limits {
                    expire_at: Some(SystemTime::UNIX_EPOCH),
                    ..Default::default()
                },
            );
            let alice = users.bind("alice");
            assert!(alice.status().expired());
            assert!(users.bind("bob").active());
            // Limits no longer configured are lifted.
            users.set_limits(HashMap::new());
            assert!(alice.active());
        }

        #[cfg(all(feature = "inbound-trojan", feature = "inbound-http"))]
        fn config(json: &str) -> anyhow::Result<crate::config::Config> {
            crate::config::from_string(json)
        }

        #[cfg(all(feature = "inbound-trojan", feature = "inbound-http"))]
        fn with_limits(limits: &str, cache_file: bool) -> anyhow::Result<crate::config::Config> {
            config(&format!(
                r#"{{"inbounds": [{{"type": "trojan", "tag": "t", "listen_port": 1,
                     "users": [{{"name": "alice", "password": "p"}}]}},
                   {{"type": "http", "tag": "h", "listen_port": 2,
                     "users": [{{"username": "bob", "password": "p"}}]}}],
                   "user_limits": {limits},
                   "experimental": {{"cache_file": {{"enabled": {cache_file}}}}}}}"#
            ))
        }

        #[cfg(all(feature = "inbound-trojan", feature = "inbound-http"))]
        #[test]
        fn user_limits_are_read_and_checked() {
            let c = with_limits(
                r#"{"alice": {"max_connections": 3, "quota_bytes": 100,
                              "expire_at": "2026-12-31T16:00:00+08:00"},
                    "bob": {}}"#,
                true,
            )
            .unwrap();
            let limits = UserRegistry::configured(&c);
            assert_eq!(
                limits["alice"],
                Limits {
                    max_connections: Some(3),
                    quota_bytes: Some(100),
                    expire_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_798_704_000)),
                }
            );
            assert_eq!(limits["bob"], Limits::default());

            for (limits, cache_file, error) in [
                (
                    r#"{"carol": {}}"#,
                    true,
                    "user_limits.carol: no inbound has a user of that name",
                ),
                (
                    r#"{"alice": {"max_connections": 0}}"#,
                    true,
                    "user_limits.alice.max_connections: must be more than 0",
                ),
                (
                    r#"{"alice": {"quota_bytes": 0}}"#,
                    true,
                    "user_limits.alice.quota_bytes: must be more than 0",
                ),
                (
                    r#"{"alice": {"quota_bytes": 1}}"#,
                    false,
                    "user_limits.alice.quota_bytes: needs experimental.cache_file",
                ),
                (
                    r#"{"alice": {"expire_at": "tomorrow"}}"#,
                    true,
                    "user_limits.alice.expire_at: \"tomorrow\" is not an RFC 3339 time",
                ),
                (
                    r#"{"alice": {"max_connection": 1}}"#,
                    true,
                    "unknown field `max_connection`",
                ),
                (r#"{"alice": {"quota_bytes": -1}}"#, true, "user_limits"),
            ] {
                let e = format!("{:#}", with_limits(limits, cache_file).unwrap_err());
                assert!(e.contains(error), "{}: {}", limits, e);
            }
        }
    }
}
