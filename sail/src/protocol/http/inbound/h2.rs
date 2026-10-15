//! The HTTP proxy's HTTP/2, as sing-box 1.15's: a connection that starts
//! with the client preface is served HTTP/2, over TLS or not (h2c with
//! prior knowledge), and each CONNECT on it is a tunnel of its own,
//! authenticated by its `Proxy-Authorization` (`407` with
//! `Proxy-Authenticate` if not), answered `200` and handed to the inbound
//! as one session (`InboundTransport::Incoming`).
//!
//! Requests that are not CONNECT get `405`: proxying them over HTTP/2 is
//! not done. Extended CONNECT (RFC 8441, CONNECT-UDP) is not offered: the
//! server sends no `SETTINGS_ENABLE_CONNECT_PROTOCOL`, so h2 resets a
//! request that names a `:protocol` as malformed.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::future::abortable;
use futures::stream::Stream;
use h2::server::SendResponse;
use http::{Method, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;
use tracing::debug;

use super::stream::authenticate;
use crate::adapter::*;
use crate::protocol::http::h2::Settings;
use crate::session::{Session, SocksAddr, StreamId};
use crate::transport::h2connect::H2Inner;
use crate::transport::h2pool::{keepalive, quiet, Counted, Names};
use crate::transport::muxcore::stall::Guarded;
use crate::user::Passwords;

/// What a connection begins with when it speaks HTTP/2 (RFC 9113 3.4).
pub(super) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// How many tunnels opened may wait for the inbound to take them. More are
/// refused, rather than held up: the connection's task must not wait, or
/// the tunnels already open on it would wait too.
const BACKLOG: usize = 64;

/// What its tasks are called, and what it logs under.
const NAMES: Names = Names {
    log: "http",
    connection: "http inbound connection",
    idle_check: "http inbound idle check",
    keepalive: "http inbound keepalive",
};

/// Reads from `stream` onto `data`, what was read already, until `data` is
/// the client preface or differs from it: whether it is. What is read is
/// only what has come, so a request that is not HTTP/2 (`POST` starts as
/// the preface does) is told apart at the first byte that differs, however
/// slowly it comes.
pub(super) async fn read_preface<S>(stream: &mut S, data: &mut Vec<u8>) -> io::Result<bool>
where
    S: AsyncRead + Unpin + ?Sized,
{
    loop {
        let n = data.len().min(PREFACE.len());
        if data[..n] != PREFACE[..n] {
            return Ok(false);
        }
        if n == PREFACE.len() {
            return Ok(true);
        }
        data.reserve(PREFACE.len());
        if stream.read_buf(data).await? == 0 {
            return Ok(false);
        }
    }
}

/// HTTP/2 as the inbound serves it.
pub(super) struct Server {
    pub settings: Settings,
    pub stall_timeout: Duration,
}

/// What a tunnel needs from its connection.
struct Tunnel {
    stream: Guarded<H2Inner>,
    id: u32,
    destination: SocksAddr,
    user: Option<crate::user::UserRef>,
}

impl Server {
    /// Serves HTTP/2 on `stream`, which has the preface still to be read:
    /// the tunnels its CONNECTs open, authenticated against `users` (none:
    /// anyone), come out of what is returned.
    pub(super) async fn serve(
        &self,
        sess: Session,
        stream: AnyStream,
        users: Arc<Passwords>,
        realm: Arc<str>,
    ) -> io::Result<AnyInboundTransport> {
        let (stream, received) = Counted::new(stream);
        let mut connection = self
            .settings
            .server()
            .handshake::<_, Bytes>(stream)
            .await
            .map_err(|e| io::Error::other(format!("http: {}", e)))?;
        let (tx, tunnels) = mpsc::channel(BACKLOG);
        let ping_pong = connection.ping_pong();
        let stall_timeout = self.stall_timeout;
        let idle_close = self.settings.idle_close;
        let label: Arc<str> = format!("inbound={}", sess.inbound_tag).into();
        let active = Arc::new(AtomicUsize::new(0));
        // The connection runs on its own task, taking requests and moving
        // the bytes of the tunnels open. The inbound takes the tunnels as
        // it will.
        let (serving, abort) = abortable(async move {
            let mut taken = true;
            let mut idle = tokio::time::Instant::now();
            loop {
                let accepted = match idle_close {
                    None => connection.accept().await,
                    Some(timeout) => {
                        let open = active.load(Ordering::Acquire) > 0;
                        if open {
                            idle = tokio::time::Instant::now();
                        }
                        tokio::select! {
                            accepted = connection.accept() => accepted,
                            _ = tokio::time::sleep_until(idle + timeout), if !open => {
                                debug!("http: no tunnel for {:?}, closing the connection", timeout);
                                connection.graceful_shutdown();
                                // Drives the shutdown to its end.
                                while connection.accept().await.is_some() {}
                                break;
                            }
                            _ = tokio::time::sleep(timeout / 2), if open => continue,
                        }
                    }
                };
                let Some(accepted) = accepted else {
                    break;
                };
                let (request, respond) = match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        debug!("http: connection ended: {}", e);
                        break;
                    }
                };
                idle = tokio::time::Instant::now();
                let id = u32::from(respond.stream_id());
                let opened = open(request, respond, &users, &realm, &active);
                let Some((stream, destination, user)) = opened else {
                    continue;
                };
                let stream = Guarded::new(stream, NAMES.log, stall_timeout, label.clone());
                let tunnel = Tunnel {
                    stream,
                    id,
                    destination,
                    user,
                };
                match tx.try_send(tunnel) {
                    Ok(()) => {}
                    // Dropping the stream resets it.
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!("http: too many tunnels waiting, refused stream {}", id)
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Nobody takes tunnels any more: no new ones, and
                        // the open ones run to their end.
                        if taken {
                            connection.graceful_shutdown();
                            taken = false;
                        }
                    }
                }
            }
        });
        crate::runtime::scope::spawn(NAMES.connection, serving);
        if let (Some(interval), Some(ping_pong)) = (self.settings.keep_alive, ping_pong) {
            keepalive(
                NAMES,
                ping_pong,
                received.clone(),
                interval,
                self.settings.ping_timeout,
                quiet(received),
                abort,
            );
        }
        Ok(InboundTransport::Incoming(Box::new(Incoming {
            sess,
            tunnels,
        })))
    }
}

/// Answers `request`: a tunnel if it is a CONNECT to an authority, with the
/// credentials of one of `users` where there are any; refused otherwise.
fn open(
    request: http::Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    users: &Passwords,
    realm: &str,
    active: &Arc<AtomicUsize>,
) -> Option<(H2Inner, SocksAddr, Option<crate::user::UserRef>)> {
    let user = if users.is_empty() {
        None
    } else {
        let authorization = request
            .headers()
            .get(http::header::PROXY_AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        match authenticate(users, authorization) {
            Some(user) => user,
            None => {
                debug!(
                    "http: stream {}: authentication failed",
                    u32::from(respond.stream_id())
                );
                let challenge = format!("Basic realm=\"{}\"", realm);
                let response = Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header(http::header::PROXY_AUTHENTICATE, challenge)
                    .body(())
                    .unwrap_or_default();
                let _ = respond.send_response(response, true);
                return None;
            }
        }
    };
    if request.method() != Method::CONNECT {
        refuse(respond, StatusCode::METHOD_NOT_ALLOWED);
        return None;
    }
    let destination = match SocksAddr::try_from(request.uri()) {
        Ok(destination) => destination,
        Err(_) => {
            refuse(respond, StatusCode::BAD_REQUEST);
            return None;
        }
    };
    let send = respond.send_response(Response::new(()), false).ok()?;
    let stream = H2Inner::new(NAMES.log, send, request.into_body()).counted(active);
    Some((stream, destination, user))
}

fn refuse(mut respond: SendResponse<Bytes>, status: StatusCode) {
    let response = Response::builder()
        .status(status)
        .body(())
        .unwrap_or_default();
    let _ = respond.send_response(response, true);
}

/// The tunnels of one connection, as the inbound takes them.
struct Incoming {
    sess: Session,
    tunnels: mpsc::Receiver<Tunnel>,
}

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.tunnels.poll_recv(cx).map(|tunnel| {
            tunnel.map(|tunnel| {
                let mut sess = self.sess.clone();
                sess.destination = tunnel.destination;
                if tunnel.user.is_some() {
                    sess.user = tunnel.user;
                }
                // What tells one tunnel's session from another's.
                sess.stream_id = Some(StreamId::U64(u64::from(tunnel.id)));
                AnyBaseInboundTransport::Stream(Box::new(tunnel.stream), sess)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::super::StreamHandler;
    use super::*;

    const BASIC_U_P: &str = "Basic dTpw";

    fn server() -> Server {
        Server {
            settings: Settings::new("", &Default::default(), crate::runtime::Profile::Desktop)
                .unwrap(),
            stall_timeout: Duration::from_secs(30),
        }
    }

    /// An inbound with the user `u`, password `p`, serving the versions
    /// `http1` and `http2` say.
    fn inbound(http1: bool, http2: bool) -> StreamHandler {
        StreamHandler::new(crate::user::passwords(&[("u", "p")]), "test")
            .with_versions(http1, http2.then(server))
    }

    /// A client connection to `inbound`, and what the inbound made of its
    /// side.
    async fn connect(
        inbound: &StreamHandler,
    ) -> (
        h2::client::SendRequest<Bytes>,
        AnyIncomingTransport,
        tokio::task::JoinHandle<()>,
    ) {
        let (client, server) = tokio::io::duplex(256 << 10);
        let (handshake, served) = tokio::join!(
            h2::client::handshake(client),
            inbound.handle(Session::default(), Box::new(server))
        );
        let (send, connection) = handshake.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let InboundTransport::Incoming(incoming) = served.unwrap() else {
            panic!("not served as HTTP/2");
        };
        (send, incoming, driver)
    }

    fn connect_request(authority: &str, authorization: Option<&str>) -> http::Request<()> {
        let mut request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(authority)
            .body(())
            .unwrap();
        if let Some(authorization) = authorization {
            request.headers_mut().insert(
                http::header::PROXY_AUTHORIZATION,
                authorization.parse().unwrap(),
            );
        }
        request
    }

    /// A CONNECT with the credentials is answered `200` and is a session
    /// to its authority, as the user; what goes either way arrives, and the
    /// client's half-close is read as the end.
    #[tokio::test]
    async fn a_connect_is_a_session() {
        let inbound = inbound(true, true);
        let (send, mut incoming, _driver) = connect(&inbound).await;
        let mut send = send.ready().await.unwrap();
        let (response, mut body) = send
            .send_request(connect_request("example.com:443", Some(BASIC_U_P)), false)
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let Some(BaseInboundTransport::Stream(mut tunnel, sess)) = incoming.next().await else {
            panic!("no session");
        };
        assert_eq!(sess.destination.to_string(), "example.com:443");
        assert_eq!(
            sess.user.as_ref().map(|u| u.to_string()).as_deref(),
            Some("u")
        );
        body.send_data(Bytes::from_static(b"up"), true).unwrap();
        let mut up = Vec::new();
        tunnel.read_to_end(&mut up).await.unwrap();
        assert_eq!(up, b"up");
        tunnel.write_all(b"down").await.unwrap();
        tunnel.shutdown().await.unwrap();
        let mut down = response.into_body();
        // To the end of the stream, which may come in an empty frame of its own.
        let mut got = Vec::new();
        while let Some(data) = down.data().await {
            got.extend_from_slice(&data.unwrap());
        }
        assert_eq!(got, b"down");
    }

    /// Without the credentials, `407` naming the realm, and no session;
    /// what is not a CONNECT, `405`.
    #[tokio::test]
    async fn refused_requests_open_no_session() {
        let inbound = inbound(true, true);
        let (send, mut incoming, _driver) = connect(&inbound).await;
        for (request, status) in [
            (connect_request("example.com:443", None), 407),
            (connect_request("example.com:443", Some("Basic dTp4")), 407),
            (
                http::Request::get("https://example.com/")
                    .header(http::header::PROXY_AUTHORIZATION, BASIC_U_P)
                    .body(())
                    .unwrap(),
                405,
            ),
        ] {
            let mut send = send.clone().ready().await.unwrap();
            let (response, _) = send.send_request(request, true).unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status().as_u16(), status);
            if status == 407 {
                assert_eq!(
                    response.headers()[http::header::PROXY_AUTHENTICATE],
                    "Basic realm=\"test\""
                );
            }
        }
        let next = tokio::time::timeout(Duration::from_millis(100), incoming.next()).await;
        assert!(next.is_err(), "a refused request opened a session");
    }

    /// Many tunnels on one connection, each a session of its own.
    #[tokio::test]
    async fn many_tunnels_on_one_connection() {
        let inbound = inbound(true, true);
        let (send, mut incoming, _driver) = connect(&inbound).await;
        let mut open = Vec::new();
        for i in 0..50 {
            let mut send = send.clone().ready().await.unwrap();
            let authority = format!("host{}.example:443", i);
            let (response, body) = send
                .send_request(connect_request(&authority, Some(BASIC_U_P)), false)
                .unwrap();
            open.push((response, body));
        }
        let mut seen = Vec::new();
        for _ in 0..50 {
            let Some(BaseInboundTransport::Stream(_, sess)) = incoming.next().await else {
                panic!("no session");
            };
            seen.push(sess.destination.to_string());
        }
        seen.sort();
        let mut asked: Vec<_> = (0..50).map(|i| format!("host{}.example:443", i)).collect();
        asked.sort();
        assert_eq!(seen, asked);
    }

    /// What an inbound answers an HTTP/1.1 CONNECT with, `None` for no
    /// answer before the connection ended.
    async fn http1_answer(inbound: &StreamHandler) -> Option<String> {
        let (mut client, server): (DuplexStream, DuplexStream) = tokio::io::duplex(64 << 10);
        client
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
            )
            .await
            .unwrap();
        let (served, answer) = tokio::join!(
            inbound.handle(Session::default(), Box::new(server)),
            async {
                let mut answer = vec![0; 64];
                let n = client.read(&mut answer).await.unwrap();
                String::from_utf8_lossy(&answer[..n]).to_string()
            }
        );
        let _ = served;
        Some(answer)
    }

    /// `version`: HTTP/1.1 alongside HTTP/2, or HTTP/2 alone, which answers
    /// HTTP/1.1 with `505`.
    #[tokio::test]
    async fn http1_is_served_as_the_versions_say() {
        let both = http1_answer(&inbound(true, true)).await.unwrap();
        assert!(both.starts_with("HTTP/1.1 200"), "{}", both);
        let alone = http1_answer(&inbound(false, true)).await.unwrap();
        assert!(alone.starts_with("HTTP/1.1 505"), "{}", alone);
    }

    /// With HTTP/1.1 alone, the preface is an HTTP/1.1 request like any
    /// other, and a bad one.
    #[tokio::test]
    async fn without_http2_the_preface_is_a_bad_request() {
        let (mut client, server) = tokio::io::duplex(64 << 10);
        client.write_all(PREFACE).await.unwrap();
        // With no users, so that what is answered is the request's fault.
        let inbound = StreamHandler::new(Passwords::new(), "test").with_versions(true, None);
        let (served, answer) = tokio::join!(
            inbound.handle(Session::default(), Box::new(server)),
            async {
                let mut answer = vec![0; 64];
                let n = client.read(&mut answer).await.unwrap();
                String::from_utf8_lossy(&answer[..n]).to_string()
            }
        );
        assert!(served.is_err());
        assert!(answer.starts_with("HTTP/1.1 400"), "{}", answer);
    }

    /// The preface is told from a request at the first byte that differs,
    /// without waiting for more: `POST`, `PUT` and `PATCH` start as it
    /// does, and so may a request in HTTP/1 that looks like it.
    #[tokio::test]
    async fn the_preface_is_told_at_the_first_byte_that_differs() {
        for (sent, preface) in [
            (&b"PO"[..], false),
            (&b"PU"[..], false),
            (&b"PA"[..], false),
            (&b"PRI * HTTP/1.1\r\n"[..], false),
            (&b"G"[..], false),
            (PREFACE, true),
        ] {
            let (mut client, mut server) = tokio::io::duplex(1024);
            // One byte at a time, and no more than `sent`.
            let feed = tokio::spawn(async move {
                for byte in sent {
                    client.write_all(&[*byte]).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                client
            });
            let mut data = Vec::new();
            let told =
                tokio::time::timeout(Duration::from_secs(5), read_preface(&mut server, &mut data))
                    .await
                    .expect("waited past the byte that differs")
                    .unwrap();
            assert_eq!(told, preface, "{:?}", String::from_utf8_lossy(sent));
            assert!(sent.starts_with(&data), "read past what was sent");
            drop(feed.await);
        }
    }
}
