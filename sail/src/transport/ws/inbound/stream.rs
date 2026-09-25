use std::io::{self};
use std::net::IpAddr;

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio_tungstenite::accept_hdr_async;
use tracing::debug;
use tungstenite::handshake::server::{Callback, ErrorResponse, Request, Response};

use crate::{adapter::*, session::Session};

struct SimpleCallback<'a> {
    sess: &'a mut Session,
    path: &'a str,
    forwarded_header: Option<&'a str>,
}

impl<'a> SimpleCallback<'a> {
    pub fn new(sess: &'a mut Session, path: &'a str, forwarded_header: Option<&'a str>) -> Self {
        Self {
            sess,
            path,
            forwarded_header,
        }
    }
}

impl<'a> Callback for SimpleCallback<'a> {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        if request.uri().path() != self.path {
            return Err(::http::response::Response::builder()
                .status(::http::StatusCode::NOT_FOUND)
                .body(None)
                .unwrap());
        }
        if let Some(Ok(forwarded)) = self
            .forwarded_header
            .and_then(|header| request.headers().get(header))
            .map(|x| x.to_str())
        {
            if let Some(f) = forwarded
                .split(',')
                .map(str::trim)
                .map(|x| x.parse::<IpAddr>())
                .take_while(|x| x.is_ok())
                .map(|x| x.unwrap())
                .last()
            {
                self.sess.forwarded_source.replace(f);
            }
        }
        Ok(response)
    }
}

pub struct Handler {
    path: String,
    /// The header a trusted proxy in front puts the client's address in.
    forwarded_header: Option<String>,
    half_close: bool,
}

impl Handler {
    pub fn new(path: String, forwarded_header: Option<String>, half_close: bool) -> Self {
        Handler {
            path,
            forwarded_header,
            half_close,
        }
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let s = accept_hdr_async(
            stream,
            SimpleCallback::new(&mut sess, &self.path, self.forwarded_header.as_deref()),
        )
        .map_err(|e| io::Error::other(format!("accept ws failed: {}", e)))
        .await?;
        debug!("accepted WS stream");
        Ok(InboundTransport::Stream(
            Box::new(super::ws_stream::WebSocketToStream::new(s, self.half_close)),
            sess,
        ))
    }
}
