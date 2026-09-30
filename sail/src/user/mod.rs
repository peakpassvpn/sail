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

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::app::stat_manager::Counts;

/// What sail keeps of a user while it runs.
#[derive(Debug)]
pub struct UserState {
    name: Arc<str>,
    traffic: UserTraffic,
}

impl UserState {
    fn new(name: &str, counts: Counts) -> Self {
        UserState {
            name: name.into(),
            traffic: UserTraffic::new(counts),
        }
    }

    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    pub fn traffic(&self) -> &UserTraffic {
        &self.traffic
    }
}

/// A user's traffic: plain counters, as only the user's own connections
/// add to them.
#[derive(Debug, Default)]
pub struct UserTraffic {
    up: AtomicU64,
    down: AtomicU64,
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

impl UserRef {
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

    /// The users there are.
    pub fn users(&self) -> Vec<UserRef> {
        self.lock()
            .users
            .values()
            .filter_map(Weak::upgrade)
            .map(UserRef)
            .collect()
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
}
