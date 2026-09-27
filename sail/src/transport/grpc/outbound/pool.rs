//! The HTTP/2 connections an outbound's calls are made on.
//!
//! A call goes on the least busy connection with room for it; when none has
//! room, one more is dialled, up to `MAX_CONNECTIONS`, through the layers
//! under the transport (dial fields, detour, tls). A connection has room
//! while it carries fewer calls than both `MAX_STREAMS` and what the server
//! allows (`SETTINGS_MAX_CONCURRENT_STREAMS`). With every connection full
//! and no more to dial, the call waits in h2 for a stream on the least busy
//! one to end.
//!
//! Until a new connection has the server's settings, h2 assumes it allows
//! 100 streams. Calls put on it past what the server then says wait in h2,
//! which never exceeds the server's limit.
//!
//! A connection that ends -- closed, cut, or given up by the keepalive -- is
//! dropped from the pool, and the next call dials a new one.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::future::abortable;
use h2::client::{ResponseFuture, SendRequest};
use h2::SendStream;
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::session::Session;
use crate::transport::layers::Connector;

/// The most connections open to the server at once.
const MAX_CONNECTIONS: usize = 8;

/// The most calls one connection carries, if the server allows as many.
/// Beyond it another connection is dialled rather than more calls sharing
/// one's window.
const MAX_STREAMS: usize = 128;

/// How the connections are kept alive.
pub struct Keepalive {
    /// Unset, no pings.
    pub idle_timeout: Option<Duration>,
    pub ping_timeout: Duration,
    /// Whether a connection carrying no calls is pinged too.
    pub permit_without_stream: bool,
}

/// What a connection's tasks and calls share.
#[derive(Default)]
struct State {
    /// The calls open on it.
    streams: AtomicUsize,
    /// Whether it has ended, or failed a call, and takes no more.
    closed: AtomicBool,
}

struct Connection {
    send: SendRequest<Bytes>,
    state: Arc<State>,
}

impl Connection {
    fn streams(&self) -> usize {
        self.state.streams.load(Ordering::Acquire)
    }

    fn has_room(&self) -> bool {
        self.streams() < MAX_STREAMS.min(self.send.current_max_send_streams())
    }
}

pub struct Pool {
    connector: Connector,
    keepalive: Keepalive,
    connections: Mutex<Vec<Arc<Connection>>>,
    /// Held while dialling, so that calls finding no room wait for one new
    /// connection rather than each dialling their own.
    dialling: tokio::sync::Mutex<()>,
}

impl Pool {
    pub fn new(connector: Connector, keepalive: Keepalive) -> Self {
        Pool {
            connector,
            keepalive,
            connections: Mutex::new(Vec::new()),
            dialling: tokio::sync::Mutex::new(()),
        }
    }

    /// Whether the connections are made over TLS.
    pub fn tls(&self) -> bool {
        self.connector.tls()
    }

    /// Makes the call `request` builds, on a connection with room for it.
    /// A connection that fails it is given up, and the call made once more,
    /// on a new one if need be.
    pub async fn call(
        &self,
        sess: &Session,
        request: impl Fn() -> io::Result<Request<()>>,
    ) -> io::Result<Call> {
        let mut retried = false;
        loop {
            let (connection, slot) = self.acquire(sess).await?;
            let sent = match connection.send.clone().ready().await {
                Ok(mut send) => send.send_request(request()?, false),
                Err(e) => Err(e),
            };
            match sent {
                Ok((response, send)) => {
                    return Ok(Call {
                        send,
                        response,
                        slot,
                    })
                }
                Err(e) => {
                    connection.state.closed.store(true, Ordering::Release);
                    if retried {
                        return Err(io::Error::other(format!("gun: {}", e)));
                    }
                    debug!("gun: connection failed a call, retrying: {}", e);
                    retried = true;
                }
            }
        }
    }

    /// A connection to make a call on, counted as carrying it.
    async fn acquire(&self, sess: &Session) -> io::Result<(Arc<Connection>, Slot)> {
        if let Some(taken) = self.pick(false) {
            return Ok(taken);
        }
        let _dialling = self.dialling.lock().await;
        // A connection dialled while this call waited may have room.
        if let Some(taken) = self.pick(false) {
            return Ok(taken);
        }
        if self.live() >= MAX_CONNECTIONS {
            if let Some(taken) = self.pick(true) {
                return Ok(taken);
            }
        }
        let connection = Arc::new(self.dial(sess).await?);
        let slot = Slot::take(&connection.state);
        self.connections.lock().unwrap().push(connection.clone());
        Ok((connection, slot))
    }

    /// The least busy live connection, with room for one more call unless
    /// `full` is allowed.
    fn pick(&self, full: bool) -> Option<(Arc<Connection>, Slot)> {
        let mut connections = self.connections.lock().unwrap();
        connections.retain(|c| !c.state.closed.load(Ordering::Acquire));
        let connection = connections
            .iter()
            .filter(|c| full || c.has_room())
            .min_by_key(|c| c.streams())?
            .clone();
        let slot = Slot::take(&connection.state);
        Some((connection, slot))
    }

    fn live(&self) -> usize {
        let mut connections = self.connections.lock().unwrap();
        connections.retain(|c| !c.state.closed.load(Ordering::Acquire));
        connections.len()
    }

    async fn dial(&self, sess: &Session) -> io::Result<Connection> {
        let stream = self.connector.connect(sess).await?;
        let (send, mut connection) = h2::client::Builder::new()
            .initial_window_size(super::super::STREAM_WINDOW)
            .initial_connection_window_size(super::super::CONNECTION_WINDOW)
            .max_header_list_size(super::super::MAX_HEADER_LIST)
            .enable_push(false)
            .handshake::<_, Bytes>(stream)
            .await
            .map_err(|e| io::Error::other(format!("gun: {}", e)))?;
        debug!("gun: new connection to {}", sess.destination);
        let state = Arc::new(State::default());
        let ping_pong = connection.ping_pong();
        let (connection, abort) = abortable(connection);
        let ended = state.clone();
        tokio::spawn(async move {
            if let Ok(Err(e)) = connection.await {
                debug!("gun: connection ended: {}", e);
            }
            ended.closed.store(true, Ordering::Release);
        });
        if let (Some(interval), Some(ping_pong)) = (self.keepalive.idle_timeout, ping_pong) {
            let watched = state.clone();
            let permit_without_stream = self.keepalive.permit_without_stream;
            super::super::keepalive(
                ping_pong,
                interval,
                self.keepalive.ping_timeout,
                move || permit_without_stream || watched.streams.load(Ordering::Acquire) > 0,
                abort,
            );
        }
        Ok(Connection { send, state })
    }
}

/// A call counted against its connection until dropped.
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

/// A call made, and the room it takes on its connection.
pub struct Call {
    pub send: SendStream<Bytes>,
    pub response: ResponseFuture,
    pub slot: Slot,
}

/// A stream that holds its call's `Slot` for as long as it lives.
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

    /// Hands over the connection dialled to `port`.
    struct Direct(u16);

    #[async_trait]
    impl OutboundStreamHandler for Direct {
        fn connect_addr(&self) -> OutboundConnect {
            OutboundConnect::Proxy(Network::Tcp, "127.0.0.1".to_string(), self.0)
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
    /// answers every request and keeps it open; and the connections it took.
    async fn server(max_streams: u32) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
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
                });
            }
        });
        (port, connections)
    }

    fn pool(port: u16) -> Pool {
        let dns = DnsClient::new(&Default::default(), Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        let handler = crate::adapter::outbound::HandlerBuilder::default()
            .tag("test".to_owned())
            .stream_handler(Arc::new(Direct(port)))
            .build();
        Pool::new(
            Connector::around(handler, dns),
            Keepalive {
                idle_timeout: None,
                ping_timeout: Duration::from_secs(15),
                permit_without_stream: false,
            },
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
        let (port, connections) = server(2).await;
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
}
