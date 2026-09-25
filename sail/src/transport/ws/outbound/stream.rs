use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::{ready, FutureExt};
use http::{HeaderName, HeaderValue};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tungstenite::protocol::{Role, WebSocketConfig};

use super::super::{encode_early_data, target_with_early_data, EarlyData};
use crate::transport::httpupgrade::http1 as upgrade;
use crate::{adapter::*, session::Session};

type Ws = super::ws_stream::WebSocketToStream<WebSocketStream<AnyStream>>;

pub struct Handler {
    request: Arc<Request>,
}

/// What every upgrade request of this handler has in common.
struct Request {
    path: String,
    /// `Host`, when the configuration sets one; the server's address when not.
    host: Option<String>,
    headers: Vec<(HeaderName, HeaderValue)>,
    half_close: bool,
    early_data: EarlyData,
}

impl Handler {
    /// `headers` and the early data settings are checked here, so that a
    /// mistake in them is a configuration error.
    pub fn new(
        path: String,
        headers: &HashMap<String, String>,
        half_close: bool,
        early_data: EarlyData,
    ) -> anyhow::Result<Self> {
        if !path.starts_with('/') {
            return Err(anyhow::anyhow!("path: must start with /"));
        }
        let host = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, host)| host.clone());
        let mut headers = upgrade::config_headers(headers)?;
        // The ones the upgrade sets itself.
        for (name, _) in &headers {
            if [
                http::header::CONNECTION,
                http::header::UPGRADE,
                http::header::SEC_WEBSOCKET_KEY,
                http::header::SEC_WEBSOCKET_VERSION,
            ]
            .contains(name)
                || early_data.header.as_ref() == Some(name)
            {
                return Err(anyhow::anyhow!("headers: {} is set by the transport", name));
            }
        }
        headers.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        Ok(Handler {
            request: Arc::new(Request {
                path,
                host,
                headers,
                half_close,
                early_data,
            }),
        })
    }
}

/// Runs the upgrade over `stream`, with `early_data` in the request.
async fn connect(
    request: Arc<Request>,
    host: String,
    mut stream: AnyStream,
    early_data: Vec<u8>,
) -> io::Result<Ws> {
    let key = tungstenite::handshake::client::generate_key();
    let mut target = request.path.clone();
    let mut headers = vec![
        (
            http::header::SEC_WEBSOCKET_KEY,
            HeaderValue::from_str(&key).map_err(io::Error::other)?,
        ),
        (
            http::header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("13"),
        ),
    ];
    if !early_data.is_empty() {
        let encoded = encode_early_data(&early_data);
        match &request.early_data.header {
            Some(name) => headers.push((
                name.clone(),
                HeaderValue::from_str(&encoded).map_err(io::Error::other)?,
            )),
            None => target = target_with_early_data(&request.path, &encoded),
        }
    }
    headers.extend(request.headers.iter().cloned());
    stream
        .write_all(&upgrade::upgrade_request(&target, &host, &headers))
        .await?;
    stream.flush().await?;

    let (head, rest) = upgrade::read_head(&mut stream).await?;
    let resp = upgrade::parse_response(&head)?;
    let failed = |why: String| io::Error::other(format!("connect ws {} failed: {}", host, why));
    if resp.status != 101 {
        return Err(failed(format!("server answered {}", resp.status)));
    }
    if !upgrade::upgrades_to_websocket(&resp.headers) {
        return Err(failed("not upgraded to websocket".to_string()));
    }
    if resp.header("sec-websocket-accept")
        != Some(tungstenite::handshake::derive_accept_key(key.as_bytes()).as_str())
    {
        return Err(failed("wrong Sec-WebSocket-Accept".to_string()));
    }
    // Whether the server named a subprotocol does not matter. Early data in
    // `Sec-WebSocket-Protocol` is a subprotocol only in name; Xray's server
    // echoes it and sing-box's does not.

    let config = WebSocketConfig {
        write_buffer_size: 0,
        ..Default::default()
    };
    let ws = WebSocketStream::from_partially_read(stream, rest, Role::Client, Some(config)).await;
    Ok(super::ws_stream::WebSocketToStream::new(
        ws,
        request.half_close,
    ))
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        let host = self
            .request
            .host
            .clone()
            .unwrap_or_else(|| sess.destination.host());
        if self.request.early_data.enabled() {
            Ok(Box::new(EarlyStream::new(
                self.request.clone(),
                host,
                stream,
            )))
        } else {
            Ok(Box::new(
                connect(self.request.clone(), host, stream, Vec::new()).await?,
            ))
        }
    }
}

enum State {
    /// Nothing written yet, so no upgrade sent.
    Idle(Arc<Request>, String, AnyStream),
    /// In a mutex only to be `Sync`, as a stream must be; nothing contends
    /// for it.
    Upgrading(std::sync::Mutex<BoxFuture<'static, io::Result<Ws>>>),
    Open(Box<Ws>),
    Failed,
}

/// A WebSocket whose upgrade waits for the first write, to carry its first
/// bytes -- up to the early data limit -- in the request.
///
/// That write takes its bytes at once and reports them written: they are the
/// request's from then on, and a writer that is not polled again with the
/// same buffer, as a cancelled one is not, loses nothing. Whatever comes
/// next -- a write, a flush, a read -- waits for the upgrade, and fails if it
/// did. A read before the first write waits: nothing has been sent, so
/// nothing can have come back.
struct EarlyStream {
    state: State,
    /// Whoever else is waiting for the upgrade. A future remembers only the
    /// last task that polled it, and a read and a write may both be polling.
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl EarlyStream {
    fn new(request: Arc<Request>, host: String, stream: AnyStream) -> Self {
        EarlyStream {
            state: State::Idle(request, host, stream),
            read_waker: None,
            write_waker: None,
        }
    }

    /// Sends the upgrade, with `early_data`, if it has not been sent.
    fn start(&mut self, early_data: &[u8]) {
        if let State::Idle(..) = self.state {
            let State::Idle(request, host, stream) =
                std::mem::replace(&mut self.state, State::Failed)
            else {
                unreachable!()
            };
            let upgrading = connect(request, host, stream, early_data.to_vec()).boxed();
            self.state = State::Upgrading(std::sync::Mutex::new(upgrading));
        }
    }

    /// Drives the upgrade, if one is under way, to the open WebSocket.
    fn poll_open(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.state {
                State::Idle(..) => return Poll::Pending,
                State::Upgrading(upgrading) => {
                    let upgrading = upgrading.get_mut().unwrap_or_else(|e| e.into_inner());
                    let upgraded = ready!(upgrading.poll_unpin(cx));
                    for waker in [self.read_waker.take(), self.write_waker.take()]
                        .into_iter()
                        .flatten()
                    {
                        waker.wake();
                    }
                    match upgraded {
                        Ok(ws) => self.state = State::Open(Box::new(ws)),
                        Err(e) => {
                            self.state = State::Failed;
                            return Poll::Ready(Err(e));
                        }
                    }
                }
                State::Open(_) => return Poll::Ready(Ok(())),
                State::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "websocket upgrade failed",
                    )))
                }
            }
        }
    }
}

impl EarlyStream {
    /// The WebSocket, once `poll_open` has said it is open.
    fn ws(&mut self) -> Pin<&mut Ws> {
        match &mut self.state {
            State::Open(ws) => Pin::new(&mut **ws),
            _ => unreachable!("poll_open said the websocket is open"),
        }
    }
}

impl AsyncRead for EarlyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.poll_open(cx) {
            Poll::Pending => {
                this.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => this.ws().poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for EarlyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let State::Idle(request, ..) = &this.state {
            let n = buf.len().min(request.early_data.max);
            this.start(&buf[..n]);
            // Nobody is waiting on the upgrade yet; a read may be.
            if let Some(waker) = this.read_waker.take() {
                waker.wake();
            }
            return Poll::Ready(Ok(n));
        }
        match this.poll_open(cx) {
            Poll::Pending => {
                this.write_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => this.ws().poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let State::Idle(..) = this.state {
            return Poll::Ready(Ok(()));
        }
        match this.poll_open(cx) {
            Poll::Pending => {
                this.write_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => this.ws().poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Finished before it said anything: the server still has to see the
        // connection, and its end.
        this.start(&[]);
        match this.poll_open(cx) {
            Poll::Pending => {
                this.write_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => this.ws().poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Runs a server over `server` that answers the upgrade and returns the
    /// request head and the first frame after it.
    async fn serve(mut server: tokio::io::DuplexStream) -> (upgrade::RequestHead, Vec<u8>) {
        let (head, _) = upgrade::read_head(&mut server).await.unwrap();
        let req = upgrade::parse_request(&head).unwrap();
        let key = req.header("sec-websocket-key").unwrap().to_string();
        let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
        let extra = [(
            http::header::SEC_WEBSOCKET_ACCEPT,
            HeaderValue::from_str(&accept).unwrap(),
        )];
        server
            .write_all(&upgrade::switching_protocols(&extra))
            .await
            .unwrap();
        // The rest in one frame: a masked binary frame, as a client sends it.
        let mut hdr = [0u8; 2];
        server.read_exact(&mut hdr).await.unwrap();
        let len = (hdr[1] & 0x7f) as usize;
        let mut mask = [0u8; 4];
        server.read_exact(&mut mask).await.unwrap();
        let mut payload = vec![0u8; len];
        server.read_exact(&mut payload).await.unwrap();
        payload
            .iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b ^= mask[i % 4]);
        (req, payload)
    }

    fn early_stream(
        max: usize,
        header: Option<&str>,
        client: tokio::io::DuplexStream,
    ) -> EarlyStream {
        let handler = Handler::new(
            "/ws".to_string(),
            &HashMap::new(),
            false,
            EarlyData::new(max, header).unwrap(),
        )
        .unwrap();
        EarlyStream::new(handler.request, "example.com".to_string(), Box::new(client))
    }

    /// The first bytes, up to the limit, go in the path; the rest in the
    /// first frame.
    #[test]
    fn test_early_data_goes_in_the_path() {
        runtime().block_on(async {
            let (client, server) = tokio::io::duplex(4096);
            let server = tokio::spawn(serve(server));
            let mut stream = early_stream(4, None, client);
            stream.write_all(b"hello world").await.unwrap();
            let (req, frame) = server.await.unwrap();
            assert_eq!(req.target, format!("/ws{}", encode_early_data(b"hell")));
            assert_eq!(req.header("host"), Some("example.com"));
            assert_eq!(frame, b"o world");
        });
    }

    #[test]
    fn test_early_data_goes_in_the_header() {
        runtime().block_on(async {
            let (client, server) = tokio::io::duplex(4096);
            let server = tokio::spawn(serve(server));
            let mut stream = early_stream(64, Some("Sec-WebSocket-Protocol"), client);
            // All of it fits: nothing is left for a frame, so send one more.
            stream.write_all(b"hello").await.unwrap();
            stream.write_all(b"again").await.unwrap();
            let (req, frame) = server.await.unwrap();
            assert_eq!(req.target, "/ws");
            assert_eq!(
                req.header("sec-websocket-protocol"),
                Some(encode_early_data(b"hello").as_str())
            );
            assert_eq!(frame, b"again");
        });
    }

    #[test]
    fn test_headers_the_transport_sets_are_refused() {
        for name in ["Upgrade", "sec-websocket-key", "X-Early"] {
            let headers = HashMap::from([(name.to_string(), "x".to_string())]);
            let early_data = EarlyData::new(16, Some("X-Early")).unwrap();
            assert!(Handler::new("/".to_string(), &headers, false, early_data).is_err());
        }
        assert!(Handler::new(
            "ws".to_string(),
            &HashMap::new(),
            false,
            EarlyData::default()
        )
        .is_err());
    }
}
