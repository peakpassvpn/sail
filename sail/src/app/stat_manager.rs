//! What connections send and receive: each connection's own counts, which
//! the Clash API lists, and the totals of each user, inbound and outbound,
//! which go on across reloads and, with `experimental.cache_file`, across
//! restarts.
//!
//! Nothing here takes a lock every connection shares. The live connections
//! are kept in shards, each behind a lock held only to add or remove one;
//! a connection is removed when the last of what counts it is dropped.
//! Each read or write adds to the connection's, its user's, its inbound's
//! and its outbound's counts, with atomic additions only. Inbounds and
//! outbounds are shared by every connection, so their counts are striped:
//! a thread adds to a stripe of its own, and a read sums them.

use portable_atomic::AtomicU64;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, pin::Pin};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use futures::{
    ready,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

use crate::user::{UserRef, UserRegistry};
use crate::{adapter::*, session::*};

pub type SyncStatManager = Arc<StatManager>;

/// The stripes of an inbound's or outbound's counts. Measured on 4 cores
/// with 1.2 KiB copied between additions: one counter took 3.5-4 times as
/// long per addition as 8, 16 or 32 stripes, which were alike.
const STRIPES: usize = 16;

/// The shards of the live connections. Measured with 100k connections,
/// 20k opened a second and a listing each second: the time to add one was
/// 15-45 us at the 99.9th percentile with 256 shards, 43-84 us with 64 and
/// 150-340 us with 16; under one lock, 18-45 ms at the 99th.
const SHARDS: usize = 256;

/// How often the counts are written to the cache file, and once more as
/// the instance stops: sing-box's ssm-api writes its every minute.
pub const STORE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Closes a connection from outside, as the Clash API does: its streams
/// and datagrams fail from then on, which ends what relays them, both
/// ways, as any failure does.
#[derive(Default)]
pub struct Closer {
    closed: AtomicBool,
    read: futures::task::AtomicWaker,
    write: futures::task::AtomicWaker,
}

impl Closer {
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.read.wake();
        self.write.wake();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Whether it is closed, with `cx` woken when it is, reading.
    fn poll_read_closed(&self, cx: &Context) -> bool {
        self.read.register(cx.waker());
        self.is_closed()
    }

    /// Whether it is closed, with `cx` woken when it is, writing.
    fn poll_write_closed(&self, cx: &Context) -> bool {
        self.write.register(cx.waker());
        self.is_closed()
    }

    /// Once it is closed.
    async fn closed(&self) {
        futures::future::poll_fn(|cx| {
            if self.poll_read_closed(cx) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

fn closed_by_api() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "closed by API")
}

/// What was sent and received, as payload: up is what the client sent on
/// to where it connects. `tcp` and `udp` count the sessions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub up: u64,
    pub down: u64,
    pub tcp: u64,
    pub udp: u64,
}

#[repr(align(128))]
#[derive(Default)]
struct Stripe(AtomicU64);

/// A count many threads add to.
struct Striped([Stripe; STRIPES]);

static NEXT_STRIPE: AtomicUsize = AtomicUsize::new(0);
thread_local!(static STRIPE: usize = NEXT_STRIPE.fetch_add(1, Ordering::Relaxed) % STRIPES);

impl Striped {
    fn new(start: u64) -> Self {
        let stripes: [Stripe; STRIPES] = Default::default();
        stripes[0].0.store(start, Ordering::Relaxed);
        Striped(stripes)
    }

    fn add(&self, n: u64) {
        let i = STRIPE.with(|i| *i);
        self.0[i].0.fetch_add(n, Ordering::Relaxed);
    }

    fn get(&self) -> u64 {
        self.0.iter().map(|s| s.0.load(Ordering::Relaxed)).sum()
    }
}

/// The counts of an inbound or an outbound.
pub struct Traffic {
    up: Striped,
    down: Striped,
    tcp: AtomicU64,
    udp: AtomicU64,
    /// Up and down as the cache file had them.
    kept: (u64, u64),
}

impl Traffic {
    fn new(counts: Counts) -> Self {
        Traffic {
            up: Striped::new(counts.up),
            down: Striped::new(counts.down),
            tcp: counts.tcp.into(),
            udp: counts.udp.into(),
            kept: (counts.up, counts.down),
        }
    }

    /// Up and down since the instance started.
    fn since_start(&self) -> (u64, u64) {
        (
            self.up.get().saturating_sub(self.kept.0),
            self.down.get().saturating_sub(self.kept.1),
        )
    }

    pub fn counts(&self) -> Counts {
        Counts {
            up: self.up.get(),
            down: self.down.get(),
            tcp: self.tcp.load(Ordering::Relaxed),
            udp: self.udp.load(Ordering::Relaxed),
        }
    }
}

/// Counts by tag. Looked up once per connection, without a lock; a tag not
/// seen before is added under one.
#[derive(Default)]
struct Tags {
    counts: ArcSwap<HashMap<String, Arc<Traffic>>>,
    /// The counts the cache file kept, for tags not seen yet. Its lock is
    /// the one adding and pruning take.
    kept: Mutex<HashMap<String, Counts>>,
    /// What the tags pruned had counted since the start, which the totals
    /// keep.
    pruned: Mutex<(u64, u64)>,
}

impl Tags {
    fn get(&self, tag: &str) -> Arc<Traffic> {
        if let Some(traffic) = self.counts.load().get(tag) {
            return traffic.clone();
        }
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        // Another may have added it while this waited.
        if let Some(traffic) = self.counts.load().get(tag) {
            return traffic.clone();
        }
        let traffic = Arc::new(Traffic::new(kept.remove(tag).unwrap_or_default()));
        let mut counts = HashMap::clone(&self.counts.load());
        counts.insert(tag.to_owned(), traffic.clone());
        self.counts.store(Arc::new(counts));
        traffic
    }

    fn counts(&self) -> Vec<(String, Counts)> {
        let mut counts: Vec<_> = self
            .counts
            .load()
            .iter()
            .map(|(tag, traffic)| (tag.clone(), traffic.counts()))
            .collect();
        counts.sort_by(|a, b| a.0.cmp(&b.0));
        counts
    }

    /// Up and down since the start over every tag, those pruned too.
    fn totals(&self) -> (u64, u64) {
        let pruned = *self.pruned.lock().unwrap_or_else(|e| e.into_inner());
        self.counts.load().values().fold(pruned, |(up, down), t| {
            let (u, d) = t.since_start();
            (up + u, down + d)
        })
    }

    /// Drops the counts of the tags not in `configured` that no connection
    /// counts to any more.
    fn prune(&self, configured: &HashSet<String>) {
        let _adding = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        let mut pruned = self.pruned.lock().unwrap_or_else(|e| e.into_inner());
        let mut counts = HashMap::new();
        // Counted to while something besides this map holds it.
        for (tag, traffic) in self.counts.load().iter() {
            if configured.contains(tag) || Arc::strong_count(traffic) > 1 {
                counts.insert(tag.clone(), traffic.clone());
            } else {
                let (up, down) = traffic.since_start();
                pruned.0 += up;
                pruned.1 += down;
            }
        }
        self.counts.store(Arc::new(counts));
    }
}

/// A connection's counts, as the Clash API lists it.
pub struct Counter {
    pub id: u64,
    pub sess: Session,
    start_time: u32,
    bytes_recvd: AtomicU64,
    bytes_sent: AtomicU64,
    recv_completed: AtomicBool,
    send_completed: AtomicBool,
    last_peer_active: AtomicU32,
    logged: AtomicBool,
    /// Closes the connection, as the Clash API does.
    pub closer: Closer,
}

impl Counter {
    fn new(id: u64, sess: Session) -> Self {
        let now = get_unix_timestamp();
        Counter {
            id,
            sess,
            start_time: now,
            bytes_recvd: Default::default(),
            bytes_sent: Default::default(),
            recv_completed: Default::default(),
            send_completed: Default::default(),
            last_peer_active: now.into(),
            logged: Default::default(),
            closer: Default::default(),
        }
    }

    pub fn bytes_recvd(&self) -> u64 {
        self.bytes_recvd.load(Ordering::Relaxed)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn recv_completed(&self) -> bool {
        self.recv_completed.load(Ordering::Relaxed)
    }

    pub fn send_completed(&self) -> bool {
        self.send_completed.load(Ordering::Relaxed)
    }

    pub fn last_peer_active(&self) -> u32 {
        self.last_peer_active.load(Ordering::Relaxed)
    }

    pub fn start_time(&self) -> u32 {
        self.start_time
    }

    pub fn log_session_end(&self) {
        if !self.logged.swap(true, Ordering::Relaxed) {
            let _g = self.sess.span.enter();
            debug!(
                "session end out={} dst={} tx={} rx={}",
                self.sess.outbound_tag,
                self.sess.destination,
                self.bytes_sent(),
                self.bytes_recvd(),
            );
        }
    }
}

fn get_unix_timestamp() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|x| x.as_secs() as u32)
        .unwrap_or(0)
}

#[derive(Default)]
struct Shard {
    live: HashMap<u64, Arc<Counter>>,
    recent: VecDeque<Arc<Counter>>,
}

/// The live connections, and some of those finished.
struct Table {
    shards: Box<[Mutex<Shard>]>,
    /// How many finished connections each shard keeps.
    recent_per_shard: usize,
}

impl Table {
    fn shard(&self, id: u64) -> std::sync::MutexGuard<'_, Shard> {
        self.shards[id as usize % SHARDS]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn retire(&self, id: u64) {
        let mut shard = self.shard(id);
        if let Some(counter) = shard.live.remove(&id) {
            counter.log_session_end();
            if self.recent_per_shard > 0 {
                if shard.recent.len() == self.recent_per_shard {
                    shard.recent.pop_front();
                }
                shard.recent.push_back(counter);
            }
        }
    }

    /// What `f` takes of each shard, in the order the connections started.
    fn collect(&self, f: impl Fn(&Shard) -> Vec<Arc<Counter>>) -> Vec<Arc<Counter>> {
        let mut counters = Vec::new();
        for shard in self.shards.iter() {
            counters.extend(f(&shard.lock().unwrap_or_else(|e| e.into_inner())));
        }
        counters.sort_by_key(|c| c.id);
        counters
    }
}

/// Where a connection's bytes are counted. The connection is retired when
/// this is dropped.
struct Accounts {
    counter: Arc<Counter>,
    user: Option<UserRef>,
    inbound: Arc<Traffic>,
    outbound: Arc<Traffic>,
    table: Arc<Table>,
}

impl Accounts {
    /// Bytes sent on to where the connection goes: up.
    fn sent(&self, n: u64) {
        self.counter.bytes_sent.fetch_add(n, Ordering::Relaxed);
        if let Some(user) = &self.user {
            user.traffic().add_up(n);
            user.check_quota();
        }
        self.inbound.up.add(n);
        self.outbound.up.add(n);
    }

    /// Bytes received from where the connection goes: down.
    fn recvd(&self, n: u64) {
        self.counter.bytes_recvd.fetch_add(n, Ordering::Relaxed);
        self.counter
            .last_peer_active
            .store(get_unix_timestamp(), Ordering::Relaxed);
        if let Some(user) = &self.user {
            user.traffic().add_down(n);
            user.check_quota();
        }
        self.inbound.down.add(n);
        self.outbound.down.add(n);
    }
}

impl Drop for Accounts {
    fn drop(&mut self) {
        self.counter.recv_completed.store(true, Ordering::Relaxed);
        self.counter.send_completed.store(true, Ordering::Relaxed);
        if let Some(user) = &self.user {
            user.leave(self.counter.id);
        }
        self.table.retire(self.counter.id);
    }
}

/// A stream, counted. `client` when it is the client's side, whose reads
/// are what is sent on. With a rate-limited user, it reads and writes at
/// most a millisecond of its rate at once, and after each waits for what the rate says
/// before the next that way.
pub struct Stream {
    inner: AnyStream,
    accounts: Accounts,
    client: bool,
    read_wait: Option<Pin<Box<tokio::time::Sleep>>>,
    write_wait: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Stream {
    fn new(inner: AnyStream, accounts: Accounts, client: bool) -> Self {
        Stream {
            inner,
            accounts,
            client,
            read_wait: None,
            write_wait: None,
        }
    }

    /// Whether what it reads goes up, to where the connection goes.
    fn reads_up(&self) -> bool {
        self.client
    }

    /// Counts `n` bytes read or written, `up` or down: how long what comes
    /// next that way must wait.
    fn count(&self, up: bool, n: u64) -> Option<std::time::Duration> {
        match up {
            true => self.accounts.sent(n),
            false => self.accounts.recvd(n),
        }
        let user = self.accounts.user.as_ref()?;
        user.shape(up, n)
    }

    /// How much at most to read or write at once, `up` or down.
    fn chunk(&self, up: bool) -> Option<usize> {
        self.accounts.user.as_ref()?.chunk(up)
    }

    /// Marks the direction it reads, or writes, finished.
    fn completed(&self, reading: bool) {
        let counter = &self.accounts.counter;
        match reading != self.client {
            true => &counter.recv_completed,
            false => &counter.send_completed,
        }
        .store(true, Ordering::Relaxed);
    }
}

/// Waits out `wait`, if there is one, clearing it once over.
fn poll_wait(wait: &mut Option<Pin<Box<tokio::time::Sleep>>>, cx: &mut Context) -> Poll<()> {
    if let Some(sleep) = wait {
        ready!(sleep.as_mut().poll(cx));
        *wait = None;
    }
    Poll::Ready(())
}

fn sleep(wait: Option<std::time::Duration>) -> Option<Pin<Box<tokio::time::Sleep>>> {
    wait.map(|wait| Box::pin(tokio::time::sleep(wait)))
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        if self.accounts.counter.closer.poll_read_closed(cx) {
            return Poll::Ready(Err(closed_by_api()));
        }
        ready!(poll_wait(&mut self.read_wait, cx));
        let up = self.reads_up();
        let remaining = buf.remaining();
        let n = match self.chunk(up) {
            None => {
                let len = buf.filled().len();
                ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
                buf.filled().len() - len
            }
            Some(chunk) => {
                let mut part = buf.take(chunk);
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                // What `part` filled is `buf`'s unfilled room.
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                n
            }
        };
        if n > 0 {
            let wait = self.count(up, n as u64);
            self.read_wait = sleep(wait);
        } else if remaining > 0 {
            self.completed(true);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.accounts.counter.closer.poll_write_closed(cx) {
            return Poll::Ready(Err(closed_by_api()));
        }
        ready!(poll_wait(&mut self.write_wait, cx));
        let up = !self.reads_up();
        let buf = match self.chunk(up) {
            Some(chunk) => &buf[..buf.len().min(chunk)],
            None => buf,
        };
        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        let wait = self.count(up, n as u64);
        self.write_wait = sleep(wait);
        Poll::Ready(Ok(n))
    }

    // Forwarded so TLS can hand several records to one writev; a user
    // whose rate is limited writes a chunk of the first at once.
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let up = !self.reads_up();
        if self.chunk(up).is_some() {
            let first = bufs
                .iter()
                .find(|b| !b.is_empty())
                .map_or(&[][..], |b| &**b);
            return self.poll_write(cx, first);
        }
        if self.accounts.counter.closer.poll_write_closed(cx) {
            return Poll::Ready(Err(closed_by_api()));
        }
        let n = ready!(Pin::new(&mut self.inner).poll_write_vectored(cx, bufs))?;
        self.count(up, n as u64);
        Poll::Ready(Ok(n))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        self.completed(false);
        Poll::Ready(Ok(()))
    }
}

/// An outbound's datagrams, counted. Its halves share the accounts: the
/// session is retired when both are dropped.
pub struct Datagram {
    inner: AnyOutboundDatagram,
    accounts: Arc<Accounts>,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, s) = self.inner.split();
        (
            Box::new(DatagramRecvHalf(r, self.accounts.clone())),
            Box::new(DatagramSendHalf(s, self.accounts)),
        )
    }
}

pub struct DatagramRecvHalf(Box<dyn OutboundDatagramRecvHalf>, Arc<Accounts>);

impl Drop for DatagramRecvHalf {
    fn drop(&mut self) {
        self.1.counter.recv_completed.store(true, Ordering::Relaxed);
    }
}

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let accounts = self.1.clone();
        loop {
            let received = tokio::select! {
                received = self.0.recv_from(buf) => received,
                () = accounts.counter.closer.closed() => Err(closed_by_api()),
            }?;
            // Over its user's rate: dropped, and not counted.
            if accounts
                .user
                .as_ref()
                .is_some_and(|user| !user.police(false, received.0 as u64))
            {
                continue;
            }
            accounts.recvd(received.0 as u64);
            return Ok(received);
        }
    }
}

pub struct DatagramSendHalf(Box<dyn OutboundDatagramSendHalf>, Arc<Accounts>);

impl Drop for DatagramSendHalf {
    fn drop(&mut self) {
        self.1.counter.send_completed.store(true, Ordering::Relaxed);
    }
}

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        if self.1.counter.closer.is_closed() {
            return Err(closed_by_api());
        }
        // Over its user's rate: dropped, and not counted.
        if self
            .1
            .user
            .as_ref()
            .is_some_and(|user| !user.police(true, buf.len() as u64))
        {
            return Ok(buf.len());
        }
        self.0
            .send_to(buf, target)
            .await
            .inspect(|&n| self.1.sent(n as u64))
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.close().await
    }
}

/// The counts of every user, inbound and outbound, by name and tag.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrafficReport {
    pub users: Vec<(String, Counts)>,
    pub inbounds: Vec<(String, Counts)>,
    pub outbounds: Vec<(String, Counts)>,
}

pub struct StatManager {
    table: Arc<Table>,
    max_recent_connections: usize,
    next_id: AtomicU64,
    inbounds: Tags,
    outbounds: Tags,
    users: UserRegistry,
    /// Where the next `read_traffic` counts from, by kind and name.
    read: Mutex<HashMap<(u8, String), Counts>>,
    /// One write to the cache file at a time, its counts read under it.
    stores: Mutex<()>,
}

impl Default for StatManager {
    fn default() -> Self {
        Self::new(0, UserRegistry::default())
    }
}

impl StatManager {
    /// Keeps up to about `max_recent_connections` finished connections for
    /// the API to list; counts the traffic of the users of `users`.
    pub fn new(max_recent_connections: usize, users: UserRegistry) -> Self {
        StatManager {
            table: Arc::new(Table {
                shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
                recent_per_shard: max_recent_connections.div_ceil(SHARDS),
            }),
            max_recent_connections,
            next_id: AtomicU64::new(1),
            inbounds: Tags::default(),
            outbounds: Tags::default(),
            users,
            read: Mutex::default(),
            stores: Mutex::default(),
        }
    }

    /// Goes on from the counts `kept`, as the cache file had them. Called
    /// before anything is counted.
    pub fn restore(&self, kept: TrafficReport) {
        *self.inbounds.kept.lock().unwrap_or_else(|e| e.into_inner()) =
            kept.inbounds.into_iter().collect();
        *self
            .outbounds
            .kept
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = kept.outbounds.into_iter().collect();
        self.users.keep(kept.users.into_iter().collect());
    }

    /// Closes the connection `id`, as the Clash API does; false when there
    /// is none so numbered.
    pub fn close(&self, id: u64) -> bool {
        match self.table.shard(id).live.get(&id) {
            Some(counter) => {
                counter.closer.close();
                true
            }
            None => false,
        }
    }

    /// Closes every connection; how many there were.
    pub fn close_all(&self) -> usize {
        let counters = self.connections();
        for counter in &counters {
            counter.closer.close();
        }
        counters.len()
    }

    /// The live connections, in the order they started.
    pub fn connections(&self) -> Vec<Arc<Counter>> {
        self.table
            .collect(|shard| shard.live.values().cloned().collect())
    }

    /// How many live connections `f` holds for.
    fn count(&self, f: impl Fn(&Counter) -> bool) -> usize {
        self.table
            .shards
            .iter()
            .map(|s| {
                let shard = s.lock().unwrap_or_else(|e| e.into_inner());
                shard.live.values().filter(|c| f(c)).count()
            })
            .sum()
    }

    /// How many connections are live.
    pub fn live(&self) -> usize {
        self.count(|_| true)
    }

    /// The finished connections kept, at most `max_recent_connections`,
    /// the latest.
    pub fn recent(&self) -> Vec<Arc<Counter>> {
        let mut recent = self
            .table
            .collect(|shard| shard.recent.iter().cloned().collect());
        let extra = recent.len().saturating_sub(self.max_recent_connections);
        recent.drain(..extra);
        recent
    }

    /// The TCP connections not yet finished both ways: what is still to be
    /// drained.
    pub fn open_streams(&self) -> usize {
        self.count(|c| {
            c.sess.network == Network::Tcp && !(c.recv_completed() && c.send_completed())
        })
    }

    /// What every connection since the start sent and received, those
    /// closed too: the traffic totals. Counts kept from before a restart
    /// are not in them.
    pub fn totals(&self) -> (u64, u64) {
        self.inbounds.totals()
    }

    /// The counts of every user, inbound and outbound since they were
    /// first counted, kept across restarts with the cache file.
    pub fn traffic(&self) -> TrafficReport {
        let mut users: Vec<_> = self
            .users
            .users()
            .into_iter()
            .map(|u| (u.name().to_string(), u.traffic().counts()))
            .collect();
        users.sort_by(|a, b| a.0.cmp(&b.0));
        TrafficReport {
            users,
            inbounds: self.inbounds.counts(),
            outbounds: self.outbounds.counts(),
        }
    }

    /// What was counted since the last read that cleared; `clear` starts
    /// the next from now. A count that went back, as a user dropped and
    /// made again has, is read from nothing.
    pub fn read_traffic(&self, clear: bool) -> TrafficReport {
        let now = self.traffic();
        let mut read = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let mut since = |kind: u8, counts: Vec<(String, Counts)>| -> Vec<(String, Counts)> {
            counts
                .into_iter()
                .map(|(name, c)| {
                    let key = (kind, name);
                    let base = read.get(&key).copied().unwrap_or_default();
                    let base = match c.up >= base.up
                        && c.down >= base.down
                        && c.tcp >= base.tcp
                        && c.udp >= base.udp
                    {
                        true => base,
                        false => Counts::default(),
                    };
                    let delta = Counts {
                        up: c.up - base.up,
                        down: c.down - base.down,
                        tcp: c.tcp - base.tcp,
                        udp: c.udp - base.udp,
                    };
                    if clear {
                        read.insert(key.clone(), c);
                    }
                    (key.1, delta)
                })
                .collect()
        };
        TrafficReport {
            users: since(0, now.users),
            inbounds: since(1, now.inbounds),
            outbounds: since(2, now.outbounds),
        }
    }

    /// Drops the counts of the inbounds and outbounds not among those
    /// configured once no connection counts to them, as a reload leaves
    /// them.
    pub fn configure(&self, inbounds: &HashSet<String>, outbounds: &HashSet<String>) {
        self.inbounds.prune(inbounds);
        self.outbounds.prune(outbounds);
    }

    fn register(&self, sess: Session) -> Accounts {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let udp = sess.network == Network::Udp;
        let user = sess.user.clone();
        let inbound = self.inbounds.get(&sess.inbound_tag);
        let outbound = self.outbounds.get(&sess.outbound_tag);
        for traffic in [&inbound, &outbound] {
            match udp {
                false => &traffic.tcp,
                true => &traffic.udp,
            }
            .fetch_add(1, Ordering::Relaxed);
        }
        if let Some(user) = &user {
            user.traffic().add_session(udp);
        }
        let counter = Arc::new(Counter::new(id, sess));
        self.table.shard(id).live.insert(id, counter.clone());
        if let Some(user) = &user {
            if !user.admit(&counter) {
                // Closed at once: shut out, or at its limit, since it
                // was dispatched.
                debug!(
                    "user [{}]: connection refused: {} live, or shut out",
                    user,
                    user.live()
                );
                counter.closer.close();
            }
        }
        Accounts {
            counter,
            user,
            inbound,
            outbound,
            table: self.table.clone(),
        }
    }

    /// Counts `stream`, the outbound's side of a TCP connection.
    pub fn stat_stream(&self, stream: AnyStream, sess: Session) -> AnyStream {
        self.stat_stream_id(stream, sess).0
    }

    /// `stat_stream`, and the id the connection is listed by.
    pub fn stat_stream_id(&self, stream: AnyStream, sess: Session) -> (AnyStream, u64) {
        let accounts = self.register(sess);
        let id = accounts.counter.id;
        (Box::new(Stream::new(stream, accounts, false)), id)
    }

    /// Counts `stream`, the client's side of a TCP connection, for an
    /// outbound that gives no stream of its own.
    pub fn stat_inbound_stream(&self, stream: AnyStream, sess: Session) -> AnyStream {
        self.stat_inbound_stream_id(stream, sess).0
    }

    /// `stat_inbound_stream`, and the id the connection is listed by.
    pub fn stat_inbound_stream_id(&self, stream: AnyStream, sess: Session) -> (AnyStream, u64) {
        let accounts = self.register(sess);
        let id = accounts.counter.id;
        (Box::new(Stream::new(stream, accounts, true)), id)
    }

    /// Counts `dgram`, the outbound's side of a UDP session.
    pub fn stat_outbound_datagram(
        &self,
        dgram: AnyOutboundDatagram,
        sess: Session,
    ) -> AnyOutboundDatagram {
        self.stat_outbound_datagram_id(dgram, sess).0
    }

    /// `stat_outbound_datagram`, and the id the session is listed by.
    pub fn stat_outbound_datagram_id(
        &self,
        dgram: AnyOutboundDatagram,
        sess: Session,
    ) -> (AnyOutboundDatagram, u64) {
        let accounts = self.register(sess);
        let id = accounts.counter.id;
        (
            Box::new(Datagram {
                inner: dgram,
                accounts: Arc::new(accounts),
            }),
            id,
        )
    }

    pub fn get_last_peer_active(&self, outbound_tag: &str) -> Option<u32> {
        self.connections()
            .iter()
            .filter(|counter| counter.sess.outbound_tag == outbound_tag)
            .map(|counter| counter.last_peer_active())
            .max()
    }

    pub fn since_last_peer_active(&self, outbound_tag: &str) -> Option<u32> {
        self.get_last_peer_active(outbound_tag)
            .map(|ts| get_unix_timestamp().saturating_sub(ts))
    }

    /// Writes the counts to the cache file, if there is one. The counts
    /// are read once the writes before are done, so the last written are
    /// the latest: a periodic write still going when the instance stops
    /// cannot put older counts over those the stop wrote.
    pub fn store(&self, cache_file: &crate::runtime::cache_file::CacheFileSlot) {
        let _one = self.stores.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cache) = cache_file.get() {
            if let Err(e) = cache.store_traffic(&self.traffic()) {
                warn!("cache_file: traffic not written: {:#}", e);
            }
        }
    }

    /// Writes the counts to the cache file every `STORE_INTERVAL`. The
    /// write runs on a blocking thread, which a stopping instance does not
    /// wait for: it holds the file alone, never the instance's environment
    /// and so its host's platform, which is released once the instance
    /// stops.
    pub fn store_task(
        sm: SyncStatManager,
        cache_file: crate::runtime::cache_file::CacheFileSlot,
    ) -> crate::Runner {
        Box::pin(async move {
            let mut interval = tokio::time::interval(STORE_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                let (sm, cache_file) = (sm.clone(), cache_file.clone());
                let _ = tokio::task::spawn_blocking(move || sm.store(&cache_file)).await;
            }
        })
    }
}

#[cfg(test)]
mod tests;
