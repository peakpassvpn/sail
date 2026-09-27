use std::io;

use async_trait::async_trait;
use http::{HeaderValue, Request, Uri};

use super::super::gun::GunStream;
use super::pool::{Keepalive, Pool, Pooled};
use crate::transport::layers::Connector;
use crate::{adapter::*, session::Session};

/// The client side of gun.
///
/// Streams are calls on the connections of a `Pool`, which dials them
/// itself through the layers under this one, as a `Connector`. So it asks
/// for nothing to be dialled (`OutboundConnect::Unknown`), and in a chain
/// it comes first: `[grpc, protocol]`, the connector holding
/// `[detour, tls, ...]`. The session it is handed is for the next hop, the
/// server, which is the calls' `:authority`.
pub struct Handler {
    /// `/<service_name>/Tun`, escaped.
    path: String,
    pool: Pool,
}

impl Handler {
    pub fn new(
        service_name: &str,
        connector: Connector,
        keepalive: Keepalive,
    ) -> anyhow::Result<Self> {
        let path = super::super::service_path(service_name)?;
        Ok(Handler {
            path,
            pool: Pool::new(connector, keepalive),
        })
    }

    fn request(&self, sess: &Session) -> io::Result<Request<()>> {
        let uri = Uri::builder()
            .scheme(if self.pool.tls() { "https" } else { "http" })
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
        Ok(request)
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        if stream.is_some() {
            return Err(io::Error::other(
                "gun: handed a connection; it dials its own",
            ));
        }
        let call = self.pool.call(sess, || self.request(sess)).await?;
        // The response is awaited by the first read: the first bytes need
        // not wait for it.
        Ok(Box::new(Pooled {
            inner: GunStream::client(call.send, call.response),
            _slot: call.slot,
        }))
    }
}
