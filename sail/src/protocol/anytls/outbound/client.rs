//! The client: sessions to one server, and the pool of idle ones.
//!
//! A session carries one stream at a time here, as in the reference client:
//! a stream takes an idle session, the newest there is, or a new one, and
//! puts it back when it is done. A check every `check_interval` closes the
//! sessions idle for longer than `idle_timeout`, oldest first, keeping the
//! newest `min_idle` of them open whatever their age.

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use futures::future::{abortable, AbortHandle, BoxFuture};
use futures::FutureExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{debug, Instrument};

use crate::session::{Network, Session as ProxySession, SocksAddr};
use crate::transport::layers::Connector;

use super::super::padding::PaddingScheme;
use super::super::session::{auth, PaddingCell, Session, Stream};

/// Idle sessions kept at most. One is kept for each stream that was open at
/// once, so this only bounds a burst.
const MAX_IDLE_SESSIONS: usize = 128;

pub struct ClientOptions {
    pub check_interval: Duration,
    pub idle_timeout: Duration,
    pub min_idle: usize,
}

struct Idle<S> {
    session: S,
    since: Instant,
}

pub struct Client {
    server: String,
    port: u16,
    password_hash: [u8; 32],
    padding: PaddingCell,
    /// Dials the server through the configured layers: TLS, and a detour.
    connector: Connector,
    options: ClientOptions,
    /// Idle sessions by their sequence number, newest last.
    idle: Mutex<BTreeMap<u64, Idle<Arc<Session>>>>,
    next_seq: AtomicU64,
    /// The check, until the first session starts it: building an outbound
    /// happens outside a runtime.
    cleanup: Mutex<Option<BoxFuture<'static, ()>>>,
}

impl Client {
    /// The client, and the handle that stops its idle check.
    pub fn new(
        server: String,
        port: u16,
        password: &str,
        connector: Connector,
        options: ClientOptions,
    ) -> (Arc<Client>, AbortHandle) {
        let client = Arc::new(Client {
            server,
            port,
            password_hash: Sha256::digest(password.as_bytes()).into(),
            padding: Arc::new(RwLock::new(Arc::new(PaddingScheme::default_scheme()))),
            connector,
            options,
            idle: Mutex::new(BTreeMap::new()),
            next_seq: AtomicU64::new(0),
            cleanup: Mutex::new(None),
        });
        let weak = Arc::downgrade(&client);
        let interval = client.options.check_interval;
        let (check, handle) = abortable(async move {
            loop {
                tokio::time::sleep(interval).await;
                let Some(client) = weak.upgrade() else {
                    return;
                };
                client.check_idle();
            }
        });
        if let Ok(mut cleanup) = client.cleanup.lock() {
            *cleanup = Some(check.map(|_| ()).boxed());
        }
        (client, handle)
    }

    /// Opens a stream whose first data is `first`.
    pub async fn open_stream(
        self: &Arc<Self>,
        sess: &ProxySession,
        first: &[u8],
    ) -> io::Result<Stream> {
        if let Some(check) = self.cleanup.lock().ok().and_then(|mut c| c.take()) {
            tokio::spawn(check);
        }
        while let Some((seq, session)) = self.take_idle() {
            match session.open_stream(first).await {
                Ok(stream) => return Ok(self.lease(seq, session, stream)),
                Err(e) => debug!("anytls idle session {} failed: {}", seq, e),
            }
        }
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let session = self
            .new_session(sess)
            .instrument(tracing::Span::current())
            .await?;
        debug!("anytls session {} to {}:{}", seq, self.server, self.port);
        let stream = session.open_stream(first).await?;
        Ok(self.lease(seq, session, stream))
    }

    /// Hands `stream` out, to put its session back when it is dropped.
    fn lease(self: &Arc<Self>, seq: u64, session: Arc<Session>, mut stream: Stream) -> Stream {
        let client: Weak<Client> = Arc::downgrade(self);
        stream.set_on_drop(Box::new(move || {
            if let Some(client) = client.upgrade() {
                client.put_idle(seq, session);
            }
        }));
        stream
    }

    fn take_idle(&self) -> Option<(u64, Arc<Session>)> {
        let mut idle = self.idle.lock().ok()?;
        while let Some((seq, entry)) = idle.pop_last() {
            if !entry.session.is_closed() {
                return Some((seq, entry.session));
            }
        }
        None
    }

    fn put_idle(&self, seq: u64, session: Arc<Session>) {
        if session.is_closed() {
            return;
        }
        let Ok(mut idle) = self.idle.lock() else {
            return;
        };
        if idle.len() >= MAX_IDLE_SESSIONS {
            // Dropped, and so closed.
            return;
        }
        idle.insert(
            seq,
            Idle {
                session,
                since: Instant::now(),
            },
        );
    }

    fn check_idle(&self) {
        let expired = match self.idle.lock() {
            Ok(mut idle) => expire(
                &mut idle,
                Instant::now(),
                self.options.idle_timeout,
                self.options.min_idle,
                |s| s.is_closed(),
            ),
            Err(_) => return,
        };
        // Closed outside the lock.
        for session in expired {
            session.close();
        }
    }

    async fn new_session(&self, sess: &ProxySession) -> io::Result<Arc<Session>> {
        let mut sess = sess.clone();
        sess.network = Network::Tcp;
        sess.destination = SocksAddr::try_from((&self.server, self.port))?;
        sess.sniffed = None;
        let mut conn = self.connector.connect(&sess).await?;
        let padding = self
            .padding
            .read()
            .map(|p| p.auth_padding())
            .unwrap_or_default();
        conn.write_all(&auth(&self.password_hash, padding)).await?;
        conn.flush().await?;
        Ok(Session::client(conn, self.padding.clone()))
    }
}

/// Takes the idle entries a check closes out of `idle`: those idle since
/// before `now - timeout`, but for the newest `min_idle`, which are kept and
/// counted as fresh. Closed sessions go too.
fn expire<S>(
    idle: &mut BTreeMap<u64, Idle<S>>,
    now: Instant,
    timeout: Duration,
    min_idle: usize,
    is_closed: impl Fn(&S) -> bool,
) -> Vec<S> {
    let deadline = now.checked_sub(timeout);
    let mut kept = 0;
    let mut expired_keys = Vec::new();
    for (seq, entry) in idle.iter_mut().rev() {
        if is_closed(&entry.session) {
            expired_keys.push(*seq);
            continue;
        }
        let stale = deadline.is_some_and(|d| entry.since < d);
        if !stale {
            kept += 1;
            continue;
        }
        if kept < min_idle {
            entry.since = now;
            kept += 1;
            continue;
        }
        expired_keys.push(*seq);
    }
    expired_keys
        .into_iter()
        .filter_map(|seq| idle.remove(&seq))
        .map(|entry| entry.session)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(ages: &[(u64, u64)], now: Instant) -> BTreeMap<u64, Idle<u64>> {
        ages.iter()
            .map(|&(seq, age)| {
                (
                    seq,
                    Idle {
                        session: seq,
                        since: now - Duration::from_secs(age),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn expire_closes_the_stale_and_keeps_the_newest() {
        let now = Instant::now() + Duration::from_secs(1000);
        let mut idle = pool(&[(1, 100), (2, 90), (3, 10), (4, 80)], now);
        let mut expired = expire(&mut idle, now, Duration::from_secs(30), 0, |_| false);
        expired.sort();
        assert_eq!(expired, vec![1, 2, 4]);
        assert_eq!(idle.keys().copied().collect::<Vec<_>>(), vec![3]);
    }

    #[test]
    fn expire_keeps_min_idle_counting_fresh_ones() {
        let now = Instant::now() + Duration::from_secs(1000);
        // 4 is fresh and counts; 3 is stale but kept as the second; the rest go.
        let mut idle = pool(&[(1, 100), (2, 90), (3, 80), (4, 10)], now);
        let mut expired = expire(&mut idle, now, Duration::from_secs(30), 2, |_| false);
        expired.sort();
        assert_eq!(expired, vec![1, 2]);
        assert_eq!(idle[&3].since, now);
    }

    #[test]
    fn expire_drops_closed_sessions() {
        let now = Instant::now() + Duration::from_secs(1000);
        let mut idle = pool(&[(1, 1), (2, 1)], now);
        let expired = expire(&mut idle, now, Duration::from_secs(30), 5, |s| *s == 2);
        assert_eq!(expired, vec![2]);
    }
}
