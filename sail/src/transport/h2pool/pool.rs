//! The HTTP/2 connections an outbound's streams are requests on: gRPC's
//! calls, the HTTP proxy's CONNECTs.
//!
//! A request goes on the least busy connection with room for it; when none
//! has room, one more is dialled, up to `MAX_CONNECTIONS`, by the pool's
//! `Dial` (for gRPC the layers under the transport: dial fields, detour,
//! tls). A connection has room while it carries fewer requests than both
//! `MAX_STREAMS` and what the server allows
//! (`SETTINGS_MAX_CONCURRENT_STREAMS`). With every connection full and no
//! more to dial, the request waits in h2 for a stream on the least busy
//! one to end.
//!
//! Until a new connection has the server's settings, h2 assumes it allows
//! 100 streams. Requests put on it past what the server then says wait in
//! h2, which never exceeds the server's limit.
//!
//! A connection that ends -- closed, cut, or given up by the keepalive -- is
//! dropped from the pool, and the next request dials a new one. So is one
//! that has carried no request for the idle timeout (`transport::idle`),
//! and ended: the keepalive's pings would otherwise hold it up for good.
//!
//! A dial may find the server speaks no HTTP/2 there (`Dialled::Other`, by
//! its ALPN): the connection is handed back, for the caller to speak
//! something else on, and is none of the pool's.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::future::{abortable, AbortHandle};
use h2::client::{ResponseFuture, SendRequest};
use h2::SendStream;
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::adapter::AnyStream;
use crate::session::Session;
use crate::transport::idle::{self, Idle};

use super::{keepalive, Counted, Names};

/// The most connections open to the server at once.
const MAX_CONNECTIONS: usize = 8;

/// The most requests one connection carries, if the server allows as many.
/// Beyond it another connection is dialled rather than more requests
/// sharing one's window.
const MAX_STREAMS: usize = 128;

/// The pool's list, whatever a panic left it: what is done under it,
/// a push, a take, a filter, leaves it whole.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// How the connections are kept alive.
pub struct Keepalive {
    /// Unset, no pings.
    pub idle_timeout: Option<Duration>,
    pub ping_timeout: Duration,
    /// Whether a connection carrying no requests is pinged too.
    pub permit_without_stream: bool,
}

/// A connection dialled for the pool.
pub enum Dialled {
    /// To speak HTTP/2 on.
    H2(AnyStream),
    /// The server speaks no HTTP/2 there: the caller's to speak something
    /// else on.
    Other(AnyStream),
}

/// How a pool's connections are made.
#[async_trait]
pub trait Dial: Send + Sync {
    /// A new connection to the server, for `sess`.
    async fn dial(&self, sess: &Session) -> io::Result<Dialled>;

    /// The layers beneath hear of a change of network.
    fn network_changed(&self, change: &crate::net::network::NetworkChange);

    /// The layers beneath close the carriers they keep with nothing open.
    fn close_idle(&self);
}

/// Every connection the layers make carries HTTP/2.
#[async_trait]
impl Dial for crate::transport::layers::Connector {
    async fn dial(&self, sess: &Session) -> io::Result<Dialled> {
        self.connect(sess).await.map(Dialled::H2)
    }

    fn network_changed(&self, change: &crate::net::network::NetworkChange) {
        crate::transport::layers::Connector::network_changed(self, change);
    }

    fn close_idle(&self) {
        crate::transport::layers::Connector::close_idle(self);
    }
}

/// What a connection's tasks and requests share.
#[derive(Default)]
struct State {
    /// The requests open on it.
    streams: AtomicUsize,
    /// Whether it has ended, or failed a request, and takes no more.
    closed: AtomicBool,
}

struct Connection {
    send: SendRequest<Bytes>,
    state: Arc<State>,
    /// Ends the connection, and the requests on it.
    abort: AbortHandle,
}

impl Connection {
    /// Ends it, and the requests on it; it takes no more.
    fn end(&self) {
        self.state.closed.store(true, Ordering::Release);
        self.abort.abort();
    }

    fn streams(&self) -> usize {
        self.state.streams.load(Ordering::Acquire)
    }

    fn has_room(&self) -> bool {
        self.streams() < MAX_STREAMS.min(self.send.current_max_send_streams())
    }
}

/// A connection of the pool's.
struct Entry {
    connection: Arc<Connection>,
    /// Since when it has carried no request, as last checked.
    idle: Idle,
}

/// A connection to make a request on, counted as carrying it, or one that
/// speaks no HTTP/2.
enum Acquired {
    H2(Arc<Connection>, Slot),
    Other(AnyStream),
}

pub struct Pool {
    dial: Box<dyn Dial>,
    /// How a connection is set up.
    builder: h2::client::Builder,
    keepalive: Keepalive,
    names: Names,
    connections: Arc<Mutex<Vec<Entry>>>,
    /// Held while dialling, so that requests finding no room wait for one
    /// new connection rather than each dialling their own.
    dialling: tokio::sync::Mutex<()>,
    /// How long a connection is kept with no request.
    idle_timeout: Duration,
    /// The idle check, which the first dial starts.
    checking: OnceLock<idle::Check>,
}

impl Pool {
    pub fn new(
        dial: impl Dial + 'static,
        builder: h2::client::Builder,
        keepalive: Keepalive,
        idle_timeout: Duration,
        names: Names,
    ) -> Self {
        Pool {
            dial: Box::new(dial),
            builder,
            keepalive,
            names,
            connections: Arc::default(),
            dialling: tokio::sync::Mutex::new(()),
            idle_timeout,
            checking: OnceLock::new(),
        }
    }

    /// Ends every connection, and the requests on them, as sing-box closes
    /// its transport when the network changes; the layers beneath hear of
    /// it.
    pub fn network_changed(&self, change: &crate::net::network::NetworkChange) {
        let connections = std::mem::take(&mut *lock(&self.connections));
        for entry in connections {
            entry.connection.end();
        }
        self.dial.network_changed(change);
    }

    /// Ends the connections that carry no request; the layers beneath hear
    /// of it.
    pub fn close_idle(&self) {
        check_idle(
            &self.connections,
            Duration::ZERO,
            tokio::time::Instant::now(),
            self.names.log,
        );
        self.dial.close_idle();
    }

    /// Makes the request `request` builds, on a connection with room for
    /// it. A connection that fails it is given up, and the request made
    /// once more, on a new one if need be. A new connection to a server
    /// that speaks no HTTP/2 there is handed back instead.
    pub async fn request(
        &self,
        sess: &Session,
        request: impl Fn() -> io::Result<Request<()>>,
    ) -> io::Result<Requested> {
        let mut retried = false;
        loop {
            let (connection, slot) = match self.acquire(sess).await? {
                Acquired::H2(connection, slot) => (connection, slot),
                Acquired::Other(stream) => return Ok(Requested::Other(stream)),
            };
            let sent = match connection.send.clone().ready().await {
                Ok(mut send) => send.send_request(request()?, false),
                Err(e) => Err(e),
            };
            match sent {
                Ok((response, send)) => {
                    return Ok(Requested::Call(Call {
                        send,
                        response,
                        slot,
                    }))
                }
                Err(e) => {
                    connection.state.closed.store(true, Ordering::Release);
                    if retried {
                        return Err(io::Error::other(format!("{}: {}", self.names.log, e)));
                    }
                    debug!(
                        "{}: connection failed a call, retrying: {}",
                        self.names.log, e
                    );
                    retried = true;
                }
            }
        }
    }

    /// `request`, on a pool whose connections all speak HTTP/2.
    pub async fn call(
        &self,
        sess: &Session,
        request: impl Fn() -> io::Result<Request<()>>,
    ) -> io::Result<Call> {
        match self.request(sess, request).await? {
            Requested::Call(call) => Ok(call),
            Requested::Other(_) => Err(io::Error::other(format!(
                "{}: the server speaks no HTTP/2",
                self.names.log
            ))),
        }
    }

    /// A connection to make a request on, counted as carrying it.
    async fn acquire(&self, sess: &Session) -> io::Result<Acquired> {
        if let Some((connection, slot)) = self.pick(false) {
            return Ok(Acquired::H2(connection, slot));
        }
        let _dialling = self.dialling.lock().await;
        // A connection dialled while this request waited may have room.
        if let Some((connection, slot)) = self.pick(false) {
            return Ok(Acquired::H2(connection, slot));
        }
        if self.live() >= MAX_CONNECTIONS {
            if let Some((connection, slot)) = self.pick(true) {
                return Ok(Acquired::H2(connection, slot));
            }
        }
        let stream = match self.dial.dial(sess).await? {
            Dialled::H2(stream) => stream,
            Dialled::Other(stream) => return Ok(Acquired::Other(stream)),
        };
        let connection = Arc::new(self.handshake(stream, sess).await?);
        let slot = Slot::take(&connection.state);
        lock(&self.connections).push(Entry {
            connection: connection.clone(),
            idle: Idle::default(),
        });
        self.checking.get_or_init(|| {
            let idle_timeout = self.idle_timeout;
            let log = self.names.log;
            idle::spawn_check(
                self.names.idle_check,
                Arc::downgrade(&self.connections),
                idle_timeout,
                move |connections, now| check_idle(connections, idle_timeout, now, log),
            )
        });
        Ok(Acquired::H2(connection, slot))
    }

    /// The least busy live connection, with room for one more request
    /// unless `full` is allowed.
    fn pick(&self, full: bool) -> Option<(Arc<Connection>, Slot)> {
        let mut connections = lock(&self.connections);
        connections.retain(|e| !e.connection.state.closed.load(Ordering::Acquire));
        let connection = connections
            .iter()
            .map(|e| &e.connection)
            .filter(|c| full || c.has_room())
            .min_by_key(|c| c.streams())?
            .clone();
        let slot = Slot::take(&connection.state);
        Some((connection, slot))
    }

    fn live(&self) -> usize {
        let mut connections = lock(&self.connections);
        connections.retain(|e| !e.connection.state.closed.load(Ordering::Acquire));
        connections.len()
    }

    /// HTTP/2 set up over `stream`, run on a task of its own.
    async fn handshake(&self, stream: AnyStream, sess: &Session) -> io::Result<Connection> {
        let log = self.names.log;
        let (stream, received) = Counted::new(stream);
        let (send, mut connection) = self
            .builder
            .handshake::<_, Bytes>(stream)
            .await
            .map_err(|e| io::Error::other(format!("{}: {}", log, e)))?;
        debug!("{}: new connection to {}", log, sess.destination);
        let state = Arc::new(State::default());
        let ping_pong = connection.ping_pong();
        let (connection, abort) = abortable(connection);
        let ends = abort.clone();
        let ended = state.clone();
        crate::runtime::scope::spawn(self.names.connection, async move {
            if let Ok(Err(e)) = connection.await {
                debug!("{}: connection ended: {}", log, e);
            }
            ended.closed.store(true, Ordering::Release);
        });
        if let (Some(interval), Some(ping_pong)) = (self.keepalive.idle_timeout, ping_pong) {
            let watched = state.clone();
            let permit_without_stream = self.keepalive.permit_without_stream;
            keepalive(
                self.names,
                ping_pong,
                received,
                interval,
                self.keepalive.ping_timeout,
                move || permit_without_stream || watched.streams.load(Ordering::Acquire) > 0,
                abort,
            );
        }
        Ok(Connection {
            send,
            state,
            abort: ends,
        })
    }
}

/// Ends the connections that have carried no request for `idle_timeout`,
/// so that the server sees them end; the next request dials anew. Under
/// the lock a request takes its connection under.
fn check_idle(
    connections: &Mutex<Vec<Entry>>,
    idle_timeout: Duration,
    now: tokio::time::Instant,
    log: &str,
) {
    lock(connections).retain_mut(|entry| {
        let connection = &entry.connection;
        if connection.state.closed.load(Ordering::Acquire) {
            return false;
        }
        if !entry.idle.expired(connection.streams(), now, idle_timeout) {
            return true;
        }
        debug!("{}: ending an idle connection", log);
        connection.end();
        false
    });
}

/// A request counted against its connection until dropped.
pub struct Slot(Arc<State>);

impl Slot {
    fn take(state: &Arc<State>) -> Self {
        state.streams.fetch_add(1, Ordering::AcqRel);
        Slot(state.clone())
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A request made, and the room it takes on its connection.
pub struct Call {
    pub send: SendStream<Bytes>,
    pub response: ResponseFuture,
    pub slot: Slot,
}

/// What `Pool::request` made: a request, or a connection to a server that
/// speaks no HTTP/2.
pub enum Requested {
    Call(Call),
    Other(AnyStream),
}

/// A stream that holds its request's `Slot` for as long as it lives.
pub struct Pooled<S> {
    pub inner: S,
    pub _slot: Slot,
}

impl<S: AsyncRead + Unpin> AsyncRead for Pooled<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Pooled<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::net::TcpListener;

    use super::*;
    use crate::adapter::{AnyStream, OutboundConnect, OutboundStreamHandler};
    use crate::app::dns::DnsClient;
    use crate::session::{Network, SocksAddr};
    use crate::transport::layers::Connector;

    const NAMES: Names = Names {
        log: "test",
        connection: "test connection",
        idle_check: "test idle check",
        keepalive: "test keepalive",
    };

    /// Hands over the connection dialled to `port`.
    struct Direct(u16);

    #[async_trait]
    impl OutboundStreamHandler for Direct {
        fn connect_addr(&self) -> OutboundConnect {
            OutboundConnect::Proxy(
                Network::Tcp,
                "127.0.0.1".to_string(),
                self.0,
                crate::net::Dialer::system(),
            )
        }

        async fn handle<'a>(
            &'a self,
            _sess: &'a Session,
            _lhs: Option<&mut AnyStream>,
            stream: Option<AnyStream>,
        ) -> io::Result<AnyStream> {
            stream.ok_or_else(|| io::Error::other("nothing dialled"))
        }
    }

    /// An h2 server allowing `max_streams` streams a connection, which
    /// answers every request and keeps it open; the connections it took,
    /// and a message for each that ended.
    async fn server(
        max_streams: u32,
    ) -> (
        u16,
        Arc<AtomicUsize>,
        tokio::sync::mpsc::UnboundedReceiver<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        let (ended, ends) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let ended = ended.clone();
                tokio::spawn(async move {
                    let mut connection = h2::server::Builder::new()
                        .max_concurrent_streams(max_streams)
                        .handshake::<_, Bytes>(tcp)
                        .await
                        .unwrap();
                    let mut open = Vec::new();
                    while let Some(Ok((request, mut respond))) = connection.accept().await {
                        let send = respond
                            .send_response(http::Response::new(()), false)
                            .unwrap();
                        open.push((request, send));
                    }
                    let _ = ended.send(());
                });
            }
        });
        (port, connections, ends)
    }

    fn pool(port: u16) -> Pool {
        pool_idle(port, Duration::from_secs(60))
    }

    /// A pool keeping a connection with no call for `idle_timeout`.
    fn pool_idle(port: u16, idle_timeout: Duration) -> Pool {
        let dns = DnsClient::new(&Default::default(), Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        let handler = crate::adapter::outbound::HandlerBuilder::default()
            .tag("test".to_owned())
            .stream_handler(Arc::new(Direct(port)))
            .build();
        Pool::new(
            Connector::around(handler, dns),
            h2::client::Builder::new(),
            Keepalive {
                idle_timeout: None,
                ping_timeout: Duration::from_secs(15),
                permit_without_stream: false,
            },
            idle_timeout,
            NAMES,
        )
    }

    fn request() -> io::Result<Request<()>> {
        Request::post("http://localhost/Test/Tun")
            .body(())
            .map_err(io::Error::other)
    }

    /// A call, open once the server has answered it: its connection has the
    /// server's settings by then.
    async fn answered(pool: &Pool, sess: &Session) -> Call {
        let mut call = pool.call(sess, request).await.unwrap();
        let response = (&mut call.response).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        call
    }

    #[tokio::test]
    async fn test_streams_share_a_connection_up_to_the_peers_limit() {
        let (port, connections, _) = server(2).await;
        let pool = pool(port);
        let sess = Session {
            destination: SocksAddr::try_from(("127.0.0.1", port)).unwrap(),
            ..Default::default()
        };

        // One after another: one connection.
        for _ in 0..3 {
            drop(answered(&pool, &sess).await);
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);

        // Five open at once, two a connection as the server allows.
        let mut open = Vec::new();
        for _ in 0..5 {
            open.push(answered(&pool, &sess).await);
        }
        assert_eq!(connections.load(Ordering::SeqCst), 3);
        assert_eq!(pool.live(), 3);

        // Room again once they end, on the connections there are.
        drop(open);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let open: Vec<_> = futures::future::join_all((0..6).map(|_| answered(&pool, &sess))).await;
        assert_eq!(connections.load(Ordering::SeqCst), 3);
        drop(open);
    }

    /// A change of network ends the connections and the calls on them; the
    /// next call dials anew.
    #[tokio::test]
    async fn a_change_of_network_ends_the_connections() {
        let (port, connections, _) = server(10).await;
        let pool = pool(port);
        let sess = Session {
            destination: SocksAddr::try_from(("127.0.0.1", port)).unwrap(),
            ..Default::default()
        };
        let mut open = answered(&pool, &sess).await;
        pool.network_changed(&crate::net::network::NetworkChange {
            generation: 1,
            reason: crate::net::network::ChangeReason::HostPush,
            old: Default::default(),
            new: Default::default(),
        });
        assert_eq!(pool.live(), 0);
        let ended = tokio::time::timeout(
            Duration::from_secs(5),
            futures::future::poll_fn(|cx| open.send.poll_reset(cx)),
        )
        .await;
        assert!(ended.is_ok(), "the open call did not end");
        drop(answered(&pool, &sess).await);
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    fn session(port: u16) -> Session {
        Session {
            destination: SocksAddr::try_from(("127.0.0.1", port)).unwrap(),
            ..Default::default()
        }
    }

    /// A connection whose calls have ended is ended once the idle timeout
    /// has passed, which the server sees; the next call dials anew. Time
    /// paused.
    #[tokio::test(start_paused = true)]
    async fn a_connection_with_no_call_is_ended() {
        let idle = crate::runtime::Profile::Desktop.carrier_idle_timeout();
        let (port, connections, mut ended) = server(10).await;
        let pool = pool_idle(port, idle);
        let sess = session(port);
        drop(answered(&pool, &sess).await);
        tokio::time::sleep(idle * 2).await;
        assert_eq!(pool.live(), 0, "kept with no call");
        let seen = tokio::time::timeout(Duration::from_secs(5), ended.recv()).await;
        assert!(matches!(seen, Ok(Some(()))), "the server saw no end");
        drop(answered(&pool, &sess).await);
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    /// An open call keeps its connection past the idle timeout. Time
    /// paused.
    #[tokio::test(start_paused = true)]
    async fn an_open_call_keeps_the_connection() {
        let idle = crate::runtime::Profile::Desktop.carrier_idle_timeout();
        let (port, connections, mut ended) = server(10).await;
        let pool = pool_idle(port, idle);
        let sess = session(port);
        let open = answered(&pool, &sess).await;
        tokio::time::sleep(idle * 3).await;
        assert_eq!(pool.live(), 1, "ended with a call open");
        assert!(ended.try_recv().is_err(), "the server saw an end");
        drop(answered(&pool, &sess).await);
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        drop(open);
    }

    /// `close_idle` ends a connection that carries no call at once, which
    /// the server sees, and keeps one that carries a call.
    #[tokio::test]
    async fn close_idle_ends_the_connections_without_a_call() {
        let (port, _, mut ended) = server(1).await;
        let pool = pool(port);
        let sess = session(port);
        // One call a connection, as the server allows.
        let busy = answered(&pool, &sess).await;
        drop(answered(&pool, &sess).await);
        assert_eq!(pool.live(), 2);
        pool.close_idle();
        assert_eq!(pool.live(), 1);
        let seen = tokio::time::timeout(Duration::from_secs(5), ended.recv()).await;
        assert!(matches!(seen, Ok(Some(()))), "the server saw no end");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(ended.try_recv().is_err(), "the busy connection ended");
        drop(busy);
    }
}
