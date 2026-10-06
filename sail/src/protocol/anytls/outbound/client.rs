//! The client: sessions to one server, and the pool of idle ones.
//!
//! A session carries one stream at a time here, as in the reference client:
//! a stream takes an idle session, the newest there is, or a new one, and
//! puts it back when it is done. A check every `check_interval` closes the
//! sessions idle for longer than `idle_timeout`, oldest first, keeping the
//! newest `min_idle` of them open whatever their age.
//!
//! A session whose stream ended while the server was still sending it is
//! not put back: what it was sent would come ahead of the next stream's
//! `SYNACK`. A reused session that sends no `SYNACK` in time is closed,
//! and the stream waiting for it is opened again on a new session, with
//! what it wrote, as long as it has read nothing and wrote no more than
//! `REPLAY_LIMIT` (`ClientStream`).

use portable_atomic::AtomicU64;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use futures::future::{abortable, AbortHandle, BoxFuture};
use futures::FutureExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, Instrument};

use crate::session::{Network, Session as ProxySession, SocksAddr};
use crate::transport::layers::Connector;
use crate::transport::muxcore::Tuning;

use super::super::padding::PaddingScheme;
use super::super::session::{auth, PaddingCell, Session, Stream};

/// Idle sessions kept at most. One is kept for each stream that was open at
/// once, so this only bounds a burst.
const MAX_IDLE_SESSIONS: usize = 128;
/// What a stream keeps of what it wrote, to write again on a new session
/// if its own sends no `SYNACK`: a request, or a TLS client hello, with
/// room to spare. Past this it is not opened again.
const REPLAY_LIMIT: usize = 64 << 10;

pub struct ClientOptions {
    pub check_interval: Duration,
    pub idle_timeout: Duration,
    pub min_idle: usize,
    pub tuning: Tuning,
    /// Who the sessions serve, in their logs.
    pub label: String,
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
    ) -> io::Result<ClientStream> {
        if let Some(check) = self.cleanup.lock().ok().and_then(|mut c| c.take()) {
            crate::runtime::scope::spawn_essential("anytls idle check", check);
        }
        while let Some((seq, session)) = self.take_idle() {
            match session.open_stream(first).await {
                Ok(stream) => {
                    return Ok(ClientStream {
                        state: State::Open(self.lease(seq, session, stream)),
                        retry: Some(Retry {
                            client: Arc::downgrade(self),
                            sess: sess.clone(),
                            first: Bytes::copy_from_slice(first),
                            written: BytesMut::new(),
                        }),
                    })
                }
                Err(e) => debug!("anytls idle session {} failed: {}", seq, e),
            }
        }
        // A new session sends its first stream no `SYNACK` to wait for.
        Ok(ClientStream {
            state: State::Open(self.open_on_new(sess, first).await?),
            retry: None,
        })
    }

    /// Opens a stream whose first data is `first` on a new session.
    async fn open_on_new(
        self: &Arc<Self>,
        sess: &ProxySession,
        first: &[u8],
    ) -> io::Result<Stream> {
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
            if entry.session.is_reusable() {
                return Some((seq, entry.session));
            }
        }
        None
    }

    fn put_idle(&self, seq: u64, session: Arc<Session>) {
        if !session.is_reusable() {
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
                |s| !s.is_reusable(),
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
        sess.forget_sniffed();
        let mut conn = self.connector.connect(&sess).await?;
        let padding = self
            .padding
            .read()
            .map(|p| p.auth_padding())
            .unwrap_or_default();
        conn.write_all(&auth(&self.password_hash, padding)).await?;
        conn.flush().await?;
        Ok(Session::client(
            conn,
            self.padding.clone(),
            self.options.tuning,
            &self.options.label,
        ))
    }
}

/// A stream as the client hands it out. One on a reused session is opened
/// again on a new session if its own was closed for want of its `SYNACK`,
/// while it has read nothing and kept all it wrote.
pub struct ClientStream {
    state: State,
    /// While the stream may still be opened again: until it reads, shuts
    /// down, writes past `REPLAY_LIMIT`, or is opened again.
    retry: Option<Retry>,
}

/// What opening a stream again takes.
struct Retry {
    client: Weak<Client>,
    sess: ProxySession,
    first: Bytes,
    /// What was written after `first`.
    written: BytesMut,
}

enum State {
    Open(Stream),
    /// On a new session, `first` and what was written going out again.
    Reopening(Mutex<BoxFuture<'static, io::Result<Stream>>>),
    Failed,
}

impl ClientStream {
    /// The stream, once it is open again if it is being opened again.
    fn poll_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut Stream>> {
        if let State::Reopening(reopen) = &mut self.state {
            let reopen = reopen.get_mut().unwrap_or_else(|e| e.into_inner());
            match ready!(reopen.poll_unpin(cx)) {
                Ok(stream) => self.state = State::Open(stream),
                Err(e) => {
                    self.state = State::Failed;
                    return Poll::Ready(Err(e));
                }
            }
        }
        match &mut self.state {
            State::Open(stream) => Poll::Ready(Ok(stream)),
            _ => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "anytls: stream failed to open again",
            ))),
        }
    }

    /// Opens the stream again on a new session if its own was closed for
    /// want of its `SYNACK`, and it may be: says whether it is.
    fn reopen(&mut self) -> bool {
        let State::Open(stream) = &self.state else {
            return false;
        };
        if !stream.synack_missed() {
            return false;
        }
        let Some(retry) = self.retry.take() else {
            return false;
        };
        let Some(client) = retry.client.upgrade() else {
            return false;
        };
        debug!(
            "anytls stream got no SYNACK on a reused session, opening it on a new one with {} bytes",
            retry.written.len()
        );
        self.state = State::Reopening(Mutex::new(
            async move {
                let mut stream = client.open_on_new(&retry.sess, &retry.first).await?;
                stream.write_all(&retry.written).await?;
                Ok(stream)
            }
            .boxed(),
        ));
        true
    }
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            let stream = ready!(me.poll_stream(cx))?;
            match ready!(Pin::new(stream).poll_read(cx, buf)) {
                Ok(()) => {
                    me.retry = None;
                    return Poll::Ready(Ok(()));
                }
                Err(e) if !me.reopen() => return Poll::Ready(Err(e)),
                Err(_) => {}
            }
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        loop {
            let stream = ready!(me.poll_stream(cx))?;
            match ready!(Pin::new(stream).poll_write(cx, buf)) {
                Ok(n) => {
                    if let Some(retry) = &mut me.retry {
                        if retry.written.len() + n > REPLAY_LIMIT {
                            me.retry = None;
                        } else {
                            retry.written.extend_from_slice(&buf[..n]);
                        }
                    }
                    return Poll::Ready(Ok(n));
                }
                Err(e) if !me.reopen() => return Poll::Ready(Err(e)),
                Err(_) => {}
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = ready!(self.get_mut().poll_stream(cx))?;
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.retry = None;
        let stream = ready!(me.poll_stream(cx))?;
        Pin::new(stream).poll_shutdown(cx)
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
    use async_trait::async_trait;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use crate::adapter::{AnyStream, OutboundConnect, OutboundStreamHandler};
    use crate::protocol::anytls::session::{read_auth_padding, AUTH_HASH_LEN};

    /// Hands over a TCP connection to `port`.
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
            _sess: &'a ProxySession,
            _lhs: Option<&mut AnyStream>,
            stream: Option<AnyStream>,
        ) -> io::Result<AnyStream> {
            stream.ok_or_else(|| io::Error::other("nothing dialled"))
        }
    }

    /// An AnyTLS server on a new port: the streams its clients open, each
    /// with the number of the connection it came on, from 1.
    async fn server() -> (u16, mpsc::UnboundedReceiver<(usize, Stream)>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut conns = 0;
            while let Ok((mut tcp, _)) = listener.accept().await {
                conns += 1;
                let conn = conns;
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut hash = [0u8; AUTH_HASH_LEN];
                    tcp.read_exact(&mut hash).await.unwrap();
                    read_auth_padding(&mut tcp).await.unwrap();
                    let (session, mut accept) = Session::server(
                        Box::new(tcp),
                        Arc::new(PaddingScheme::default_scheme()),
                        Tuning::default(),
                        "test",
                    );
                    while let Some(inner) = accept.recv().await {
                        if tx.send((conn, session.stream(inner))).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, rx)
    }

    fn client(port: u16) -> Arc<Client> {
        let dns = crate::app::dns::DnsClient::new(
            &Default::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let direct = crate::adapter::outbound::HandlerBuilder::default()
            .tag("test".to_owned())
            .stream_handler(Arc::new(Direct(port)))
            .build();
        let options = ClientOptions {
            check_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(30),
            min_idle: 0,
            tuning: Tuning::default(),
            label: "test".to_string(),
        };
        Client::new(
            "127.0.0.1".to_string(),
            port,
            "password",
            Connector::around(direct, dns),
            options,
        )
        .0
    }

    /// The next stream a server takes, which has sent `first`: the number
    /// of its connection, and the stream, its `SYNACK` sent.
    async fn accept(
        streams: &mut mpsc::UnboundedReceiver<(usize, Stream)>,
        first: &[u8],
    ) -> (usize, Stream) {
        let (conn, mut stream) = tokio::time::timeout(Duration::from_secs(10), streams.recv())
            .await
            .expect("no stream came")
            .unwrap();
        stream.report(None).await.unwrap();
        let mut got = vec![0u8; first.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, first);
        (conn, stream)
    }

    /// Reads `stream` to its end, which the server ends with `what`.
    async fn read_end<S: AsyncRead + Unpin>(stream: &mut S, what: &[u8]) {
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut got))
            .await
            .expect("the stream did not end")
            .unwrap();
        assert_eq!(got, what);
    }

    /// A stream dropped while the server still sends it does not put its
    /// session back: the next stream goes on a new one. A stream the server
    /// ended does, and the next takes it.
    #[tokio::test]
    async fn a_session_cut_short_is_not_reused() {
        let (port, mut streams) = server().await;
        let client = client(port);
        let sess = ProxySession::default();
        let mut cut = client.open_stream(&sess, b"D").await.unwrap();
        let (conn, mut served) = accept(&mut streams, b"D").await;
        assert_eq!(conn, 1);
        served.write_all(&[7u8; 32 << 10]).await.unwrap();
        cut.read_exact(&mut [0u8; 1]).await.unwrap();
        drop(cut);
        let mut ended = client.open_stream(&sess, b"D").await.unwrap();
        let (conn, mut served) = accept(&mut streams, b"D").await;
        assert_eq!(conn, 2, "the session of a stream cut short was reused");
        served.write_all(b"bye").await.unwrap();
        served.shutdown().await.unwrap();
        read_end(&mut ended, b"bye").await;
        drop(ended);
        let _next = client.open_stream(&sess, b"D").await.unwrap();
        let (conn, _served) = accept(&mut streams, b"D").await;
        assert_eq!(
            conn, 2,
            "the session of a stream the server ended was not reused"
        );
    }

    /// A reused session that sends no `SYNACK` in time is closed, and the
    /// stream waiting for it goes on a new session, with what it wrote:
    /// the caller sees the server's answer, not the closed session.
    #[tokio::test]
    async fn a_stream_without_its_synack_is_opened_again() {
        let (port, mut streams) = server().await;
        let client = client(port);
        let sess = ProxySession::default();
        let mut once = client.open_stream(&sess, b"D").await.unwrap();
        let (_, mut served) = accept(&mut streams, b"D").await;
        served.write_all(b"a").await.unwrap();
        served.shutdown().await.unwrap();
        read_end(&mut once, b"a").await;
        drop(once);
        // Reuses the session, whose server keeps the stream and never
        // answers it.
        let mut stream = client.open_stream(&sess, b"D").await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let (conn, _held) = tokio::time::timeout(Duration::from_secs(10), streams.recv())
            .await
            .expect("no stream came")
            .unwrap();
        assert_eq!(conn, 1);
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            let read = stream.read_to_end(&mut got).await;
            (read, got)
        });
        let (conn, mut served) = accept(&mut streams, b"Dhello").await;
        assert_eq!(conn, 2);
        served.write_all(b"answer").await.unwrap();
        served.shutdown().await.unwrap();
        let (read, got) = tokio::time::timeout(Duration::from_secs(10), reader)
            .await
            .expect("the stream did not end")
            .unwrap();
        read.expect("the caller saw the stuck session");
        assert_eq!(got, b"answer");
    }

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
