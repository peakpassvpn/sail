use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::future::abortable;
use futures::stream::Stream;
use h2::server::SendResponse;
use http::{HeaderValue, Request, Response, StatusCode};
use tokio::sync::mpsc;
use tracing::debug;

use super::super::gun::GunStream;
use crate::session::StreamId;
use crate::{adapter::*, session::Session};

/// How many calls a client may have open on one connection at once.
const MAX_CONCURRENT_STREAMS: u32 = 128;

/// How many accepted calls may wait for the inbound to take them. More are
/// refused, rather than held up: the connection's task must not wait, or
/// the calls already open on it would wait too.
const BACKLOG: usize = 64;

/// The server side of gun: every call a connection carries is a stream of
/// its own.
pub struct Handler {
    /// `/<service_name>/Tun`.
    path: String,
    idle_timeout: Option<Duration>,
    ping_timeout: Duration,
}

impl Handler {
    pub fn new(
        service_name: &str,
        idle_timeout: Option<Duration>,
        ping_timeout: Option<Duration>,
    ) -> anyhow::Result<Self> {
        Ok(Handler {
            path: super::super::service_path(service_name)?,
            idle_timeout: idle_timeout.filter(|d| !d.is_zero()),
            ping_timeout: ping_timeout.unwrap_or(super::super::DEFAULT_PING_TIMEOUT),
        })
    }
}

/// Whether `request` is a gun call to `path`; the status to refuse it with
/// when not.
fn check(path: &str, request: &Request<h2::RecvStream>) -> Result<(), StatusCode> {
    if request.uri().path() != path || request.method() != http::Method::POST {
        return Err(StatusCode::NOT_FOUND);
    }
    let grpc = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/grpc"));
    if !grpc {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    Ok(())
}

/// Answers an acceptable call, and makes a stream of it.
fn open(
    request: Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<GunStream, h2::Error> {
    let mut response = Response::new(());
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    let send = respond.send_response(response, false)?;
    Ok(GunStream::server(send, request.into_body()))
}

fn refuse(mut respond: SendResponse<Bytes>, status: StatusCode) {
    let mut response = Response::new(());
    *response.status_mut() = status;
    let _ = respond.send_response(response, true);
}

/// The calls of one connection, as the inbound takes them.
struct Incoming {
    sess: Session,
    calls: mpsc::Receiver<(GunStream, u32)>,
}

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.calls.poll_recv(cx).map(|call| {
            call.map(|(stream, id)| {
                let mut sess = self.sess.clone();
                // What tells one call's UDP session from another's.
                sess.stream_id = Some(StreamId::U64(u64::from(id)));
                AnyBaseInboundTransport::Stream(Box::new(stream), sess)
            })
        })
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let mut connection = h2::server::Builder::new()
            .initial_window_size(super::super::STREAM_WINDOW)
            .initial_connection_window_size(super::super::CONNECTION_WINDOW)
            .max_header_list_size(super::super::MAX_HEADER_LIST)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .handshake::<_, Bytes>(stream)
            .await
            .map_err(|e| std::io::Error::other(format!("gun: {}", e)))?;

        let (tx, calls) = mpsc::channel(BACKLOG);
        let ping_pong = connection.ping_pong();
        let path = self.path.clone();
        // The connection runs on its own task, accepting calls and moving
        // the bytes of those open. The inbound takes the calls as it will.
        let (serving, abort) = abortable(async move {
            let mut taken = true;
            while let Some(accepted) = connection.accept().await {
                let (request, respond) = match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        debug!("gun: connection ended: {}", e);
                        break;
                    }
                };
                if let Err(status) = check(&path, &request) {
                    debug!("gun: refused {} {}", request.method(), request.uri().path());
                    refuse(respond, status);
                    continue;
                }
                let id = u32::from(respond.stream_id());
                let stream = match open(request, respond) {
                    Ok(stream) => stream,
                    Err(e) => {
                        debug!("gun: call {} failed: {}", id, e);
                        continue;
                    }
                };
                match tx.try_send((stream, id)) {
                    Ok(()) => {}
                    // Dropping the stream resets the call.
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!("gun: too many calls waiting, refused call {}", id)
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Nobody takes calls any more: no new ones, and the
                        // open ones run to their end.
                        if taken {
                            connection.graceful_shutdown();
                            taken = false;
                        }
                    }
                }
            }
        });
        tokio::spawn(serving);
        if let (Some(interval), Some(ping_pong)) = (self.idle_timeout, ping_pong) {
            super::super::keepalive(ping_pong, interval, self.ping_timeout, abort);
        }
        Ok(InboundTransport::Incoming(Box::new(Incoming {
            sess,
            calls,
        })))
    }
}
