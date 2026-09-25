//! The client: mux connections made by an outbound, and the streams handed
//! out over them.
//!
//! A mux connection is a connection of the outbound's whole stack -- its
//! protocol over its transport and TLS, through its detour -- to the magic
//! destination, which is why the outbound hands it over as a `Connector`
//! around the stack instead of being one more layer in it.
//!
//! Streams go to the connection with the fewest, as in sing-mux, and a new
//! connection is made when those are too busy: with `max_connections`,
//! while there are fewer than that many and the least busy carries at
//! least `min_streams`; with `max_streams`, when every connection carries
//! that many. Hard limits stand behind both: `MAX_CONNECTIONS` connections,
//! `session::MAX_STREAMS` streams on one.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex as SyncMutex, Weak};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::future::{abortable, AbortHandle, BoxFuture};
use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, Instrument};

use crate::adapter::*;
use crate::session::{Network, Session, SocksAddr};
use crate::transport::layers::Connector;

use super::h2mux::H2Client;
use super::packet::ClientDatagram;
use super::padding::PaddingStream;
use super::session::{Flavor, FrameSession};
use super::{encode_request, Protocol, StreamRequest, MAGIC_DOMAIN, MAGIC_PORT, STATUS_SUCCESS};

/// Connections one outbound keeps at most.
pub const MAX_CONNECTIONS: usize = 32;
/// How long making a mux connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How often idle connections are looked for.
const CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// How long a connection without streams is kept.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOptions {
    pub protocol: Protocol,
    pub padding: bool,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
}

impl ClientOptions {
    /// Checks the limits as sing-box does: `max_streams` excludes the
    /// other two. With none set, up to 4 connections, a new one while the
    /// least busy carries 4 streams or more.
    pub fn new(
        protocol: Protocol,
        padding: bool,
        max_connections: Option<usize>,
        min_streams: Option<usize>,
        max_streams: Option<usize>,
    ) -> Result<Self, String> {
        let max_streams = max_streams.filter(|n| *n > 0);
        let max_connections = max_connections.filter(|n| *n > 0);
        let min_streams = min_streams.filter(|n| *n > 0);
        if max_streams.is_some() && (max_connections.is_some() || min_streams.is_some()) {
            return Err(
                "max_streams cannot be set with max_connections or min_streams".to_string(),
            );
        }
        if max_connections.is_some_and(|n| n > MAX_CONNECTIONS) {
            return Err(format!("max_connections cannot exceed {}", MAX_CONNECTIONS));
        }
        if max_streams.is_some_and(|n| n > super::session::MAX_STREAMS) {
            return Err(format!(
                "max_streams cannot exceed {}",
                super::session::MAX_STREAMS
            ));
        }
        let (max_connections, min_streams) = match max_streams {
            Some(_) => (0, 0),
            None => (max_connections.unwrap_or(4), min_streams.unwrap_or(4)),
        };
        Ok(ClientOptions {
            protocol,
            padding,
            max_connections,
            min_streams,
            max_streams: max_streams.unwrap_or(0),
        })
    }
}

/// One mux connection.
enum Conn {
    Frames(FrameSession),
    H2(H2Client),
}

impl Conn {
    async fn open(&self) -> io::Result<AnyStream> {
        match self {
            Conn::Frames(session) => Ok(Box::new(session.open()?)),
            Conn::H2(client) => Ok(Box::new(client.open().await?)),
        }
    }

    fn num_streams(&self) -> usize {
        match self {
            Conn::Frames(session) => session.num_streams(),
            Conn::H2(client) => client.num_streams(),
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            Conn::Frames(session) => session.is_closed(),
            Conn::H2(client) => client.is_closed(),
        }
    }

    fn can_take_new_request(&self) -> bool {
        match self {
            Conn::Frames(session) => session.num_streams() < super::session::MAX_STREAMS,
            Conn::H2(client) => client.can_take_new_request(),
        }
    }

    fn close(&self) {
        match self {
            Conn::Frames(session) => session.close(),
            Conn::H2(client) => client.close(),
        }
    }
}

struct Entry {
    conn: Arc<Conn>,
    /// Since when it has carried no streams, as last checked.
    idle_since: Option<Instant>,
}

pub struct Client {
    connector: Connector,
    options: ClientOptions,
    /// Held while a connection is made, so that streams asking at once
    /// share it rather than each making their own, as in sing-mux.
    conns: tokio::sync::Mutex<Vec<Entry>>,
    /// The idle check, until the first connection starts it: outbounds are
    /// built outside a runtime.
    cleanup: SyncMutex<Option<BoxFuture<'static, ()>>>,
}

impl Client {
    /// The client, and the handle that stops its idle check.
    pub fn new(connector: Connector, options: ClientOptions) -> (Arc<Client>, AbortHandle) {
        let client = Arc::new(Client {
            connector,
            options,
            conns: tokio::sync::Mutex::new(Vec::new()),
            cleanup: SyncMutex::new(None),
        });
        let weak: Weak<Client> = Arc::downgrade(&client);
        let (check, handle) = abortable(async move {
            loop {
                tokio::time::sleep(CHECK_INTERVAL).await;
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

    fn check_idle(&self) {
        // Not while a connection is being made; the next check will do.
        let Ok(mut conns) = self.conns.try_lock() else {
            return;
        };
        let now = Instant::now();
        conns.retain_mut(|entry| {
            if entry.conn.is_closed() {
                return false;
            }
            if entry.conn.num_streams() > 0 {
                entry.idle_since = None;
                return true;
            }
            match entry.idle_since {
                None => {
                    entry.idle_since = Some(now);
                    true
                }
                Some(since) if now.duration_since(since) >= IDLE_TIMEOUT => {
                    entry.conn.close();
                    false
                }
                Some(_) => true,
            }
        });
    }

    /// A new stream, before its request.
    async fn open_stream(&self, sess: &Session) -> io::Result<AnyStream> {
        if let Some(check) = self.cleanup.lock().ok().and_then(|mut c| c.take()) {
            tokio::spawn(check);
        }
        let mut last = io::Error::other("mux: no connection");
        for _ in 0..2 {
            let conn = match self.offer(sess).await {
                Ok(conn) => conn,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            match conn.open().await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    debug!("mux open stream: {}", e);
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// The connection a new stream goes on, made if need be.
    async fn offer(&self, sess: &Session) -> io::Result<Arc<Conn>> {
        let mut conns = self.conns.lock().await;
        conns.retain(|entry| {
            if entry.conn.is_closed() {
                entry.conn.close();
                return false;
            }
            true
        });
        let least = conns
            .iter()
            .filter(|e| e.conn.can_take_new_request())
            .min_by_key(|e| e.conn.num_streams())
            .map(|e| e.conn.clone());
        if let Some(conn) = &least {
            if reuse(&self.options, conn.num_streams(), conns.len()) {
                return Ok(conn.clone());
            }
        }
        if conns.len() >= MAX_CONNECTIONS {
            return least.ok_or_else(|| io::Error::other("mux: every connection is full"));
        }
        let conn = Arc::new(
            tokio::time::timeout(CONNECT_TIMEOUT, self.connect(sess))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mux: connect timed out"))??,
        );
        conns.push(Entry {
            conn: conn.clone(),
            idle_since: None,
        });
        Ok(conn)
    }

    async fn connect(&self, sess: &Session) -> io::Result<Conn> {
        let mut sess = sess.clone();
        sess.network = Network::Tcp;
        sess.destination = SocksAddr::Domain(MAGIC_DOMAIN.to_string(), MAGIC_PORT);
        sess.sniffed = None;
        let mut conn = self
            .connector
            .connect(&sess)
            .instrument(tracing::Span::current())
            .await?;
        conn.write_all(&encode_request(self.options.protocol, self.options.padding))
            .await?;
        let conn: AnyStream = if self.options.padding {
            Box::new(PaddingStream::new(conn))
        } else {
            conn
        };
        debug!("mux connection ({:?})", self.options.protocol);
        Ok(match self.options.protocol {
            Protocol::Smux => Conn::Frames(FrameSession::new(conn, Flavor::Smux, false).0),
            Protocol::Yamux => Conn::Frames(FrameSession::new(conn, Flavor::Yamux, false).0),
            Protocol::H2Mux => Conn::H2(H2Client::new(conn).await?),
        })
    }

    /// Opens a stream and sends `request` on it.
    async fn request(&self, sess: &Session, request: StreamRequest) -> io::Result<AnyStream> {
        let mut stream = self.open_stream(sess).await?;
        let mut buf = BytesMut::new();
        request.encode(&mut buf);
        stream.write_all(&buf).await?;
        Ok(stream)
    }
}

/// Whether a stream goes on the least busy connection, which carries
/// `streams`, rather than a new one, with `conns` connections open.
fn reuse(o: &ClientOptions, streams: usize, conns: usize) -> bool {
    if streams == 0 {
        return true;
    }
    if o.max_connections > 0 {
        conns >= o.max_connections || streams < o.min_streams
    } else {
        o.max_streams > 0 && streams < o.max_streams
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Ok(conns) = self.conns.try_lock() {
            for entry in conns.iter() {
                entry.conn.close();
            }
        }
    }
}

/// TCP through the mux.
pub struct StreamHandler {
    pub client: Arc<Client>,
}

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let stream = self
            .client
            .request(sess, StreamRequest::Tcp(sess.destination.clone()))
            .await?;
        Ok(Box::new(ClientStream {
            inner: stream,
            status: [0],
            status_read: false,
        }))
    }
}

/// UDP through the mux, every packet with its address.
pub struct DatagramHandler {
    pub client: Arc<Client>,
}

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Reliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let stream = self
            .client
            .request(sess, StreamRequest::UdpAddr(sess.destination.clone()))
            .await?;
        Ok(Box::new(ClientDatagram { stream }))
    }
}

/// A TCP stream on the client, which reads the server's status before its
/// first data.
struct ClientStream {
    inner: AnyStream,
    status: [u8; 1],
    status_read: bool,
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.status_read {
            let mut status = ReadBuf::new(&mut me.status);
            ready!(Pin::new(&mut me.inner).poll_read(cx, &mut status))?;
            if status.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux: stream closed before its status",
                )));
            }
            if me.status[0] != STATUS_SUCCESS {
                return Poll::Ready(Err(io::Error::other("mux: remote error")));
            }
            me.status_read = true;
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// `layered`, the outbound's whole stack, with its TCP and UDP carried
/// over mux connections it makes.
pub fn outbound(
    tag: &str,
    layered: AnyOutboundHandler,
    dns_client: crate::app::SyncDnsClient,
    options: ClientOptions,
    abort_handles: &mut Vec<AbortHandle>,
) -> AnyOutboundHandler {
    let (client, cleanup) = Client::new(Connector::around(layered, dns_client), options);
    abort_handles.push(cleanup);
    crate::adapter::outbound::HandlerBuilder::default()
        .tag(tag.to_owned())
        .stream_handler(Arc::new(StreamHandler {
            client: client.clone(),
        }))
        .datagram_handler(Arc::new(DatagramHandler { client }))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(
        max_connections: Option<usize>,
        min_streams: Option<usize>,
        max_streams: Option<usize>,
    ) -> Result<ClientOptions, String> {
        ClientOptions::new(
            Protocol::Smux,
            false,
            max_connections,
            min_streams,
            max_streams,
        )
    }

    #[test]
    fn limits_are_checked_as_sing_box_does() {
        let o = options(None, None, None).unwrap();
        assert_eq!((o.max_connections, o.min_streams, o.max_streams), (4, 4, 0));
        let o = options(None, None, Some(8)).unwrap();
        assert_eq!((o.max_connections, o.min_streams, o.max_streams), (0, 0, 8));
        assert!(options(Some(2), None, Some(8)).is_err());
        assert!(options(None, Some(2), Some(8)).is_err());
        assert!(options(Some(MAX_CONNECTIONS + 1), None, None).is_err());
        assert!(options(None, None, Some(100_000)).is_err());
    }

    #[test]
    fn a_new_connection_only_when_the_least_busy_is_busy_enough() {
        let o = options(Some(2), Some(3), None).unwrap();
        assert!(reuse(&o, 0, 1));
        assert!(reuse(&o, 2, 1));
        assert!(!reuse(&o, 3, 1));
        assert!(reuse(&o, 50, 2));
        let o = options(None, None, Some(2)).unwrap();
        assert!(reuse(&o, 1, 10));
        assert!(!reuse(&o, 2, 1));
    }
}
