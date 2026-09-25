use std::io;
use std::time::Duration;

use async_trait::async_trait;
use futures::future::abortable;
use http::{HeaderValue, Request, Uri};
use tracing::debug;

use super::super::gun::GunStream;
use crate::{adapter::*, session::Session};

/// The client side of gun.
///
/// A stream is a connection of its own: the call is made over whatever the
/// layers under this one dialled for it, and the connection closes with the
/// call. Carrying many calls over one connection, as sing-box's client does,
/// would need this layer to dial for itself, the way the multiplex layer
/// does; a chain hands it one connection per stream.
pub struct Handler {
    /// `/<service_name>/Tun`, escaped.
    path: String,
    /// Whether the connection under it is TLS, for the `:scheme`.
    tls: bool,
    idle_timeout: Option<Duration>,
    ping_timeout: Duration,
}

impl Handler {
    pub fn new(
        service_name: &str,
        tls: bool,
        idle_timeout: Option<Duration>,
        ping_timeout: Option<Duration>,
    ) -> anyhow::Result<Self> {
        let path = super::super::service_path(service_name)?;
        Ok(Handler {
            path,
            tls,
            idle_timeout: idle_timeout.filter(|d| !d.is_zero()),
            ping_timeout: ping_timeout.unwrap_or(super::super::DEFAULT_PING_TIMEOUT),
        })
    }
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
        let failed = |e: h2::Error| io::Error::other(format!("gun: {}", e));

        let (client, mut connection) = h2::client::Builder::new()
            .initial_window_size(super::super::STREAM_WINDOW)
            .initial_connection_window_size(super::super::CONNECTION_WINDOW)
            .max_header_list_size(super::super::MAX_HEADER_LIST)
            .enable_push(false)
            .handshake::<_, bytes::Bytes>(stream)
            .await
            .map_err(failed)?;
        let ping_pong = connection.ping_pong();
        let (connection, abort) = abortable(connection);
        tokio::spawn(async move {
            if let Ok(Err(e)) = connection.await {
                debug!("gun: connection ended: {}", e);
            }
        });
        if let (Some(interval), Some(ping_pong)) = (self.idle_timeout, ping_pong) {
            super::super::keepalive(ping_pong, interval, self.ping_timeout, abort);
        }

        let uri = Uri::builder()
            .scheme(if self.tls { "https" } else { "http" })
            .authority(sess.destination.to_string())
            .path_and_query(self.path.as_str())
            .build()
            .map_err(io::Error::other)?;
        let mut request = Request::post(uri).body(()).map_err(io::Error::other)?;
        let headers = request.headers_mut();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        );
        headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
        headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static("grpc-go/1.48.0"),
        );

        let mut client = client.ready().await.map_err(failed)?;
        let (response, send) = client.send_request(request, false).map_err(failed)?;
        // The response is awaited by the first read: the first bytes need
        // not wait for it.
        Ok(Box::new(GunStream::client(send, response)))
    }
}
