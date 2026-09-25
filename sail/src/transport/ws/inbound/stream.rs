use std::io;
use std::net::IpAddr;

use async_trait::async_trait;
use http::{HeaderName, HeaderValue, StatusCode};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::WebSocketStream;
use tracing::debug;
use tungstenite::protocol::Role;

use super::super::{decode_early_data, EarlyData};
use crate::transport::httpupgrade::http1::{self as upgrade, RequestHead};
use crate::{adapter::*, session::Session};

pub struct Handler {
    path: String,
    /// The header a trusted proxy in front puts the client's address in.
    forwarded_header: Option<String>,
    half_close: bool,
    early_data: EarlyData,
}

/// What an acceptable upgrade request asks for.
#[derive(Debug)]
struct Accepted {
    /// The `Sec-WebSocket-Accept` the response carries.
    accept_key: String,
    early_data: Vec<u8>,
    /// The subprotocol to answer with: the early data itself, when it came in
    /// `Sec-WebSocket-Protocol`. A browser-grade client, Xray's among them,
    /// fails a handshake whose response names no subprotocol when its request
    /// named one.
    protocol: Option<HeaderValue>,
}

impl Handler {
    pub fn new(
        path: String,
        forwarded_header: Option<String>,
        half_close: bool,
        early_data: EarlyData,
    ) -> Self {
        Handler {
            path,
            forwarded_header,
            half_close,
            early_data,
        }
    }

    /// Checks the request, and says with what status to turn it down when it
    /// will not do.
    fn accept(&self, req: &RequestHead) -> Result<Accepted, (StatusCode, String)> {
        let not_found = |what: String| (StatusCode::NOT_FOUND, what);
        let bad = |what: String| (StatusCode::BAD_REQUEST, what);

        // Early data in the path: the configured path, then the data.
        let in_path = self.early_data.enabled() && self.early_data.header.is_none();
        let early_data = if in_path {
            let encoded = req
                .target
                .strip_prefix(self.path.as_str())
                .ok_or_else(|| not_found(format!("bad path {}", req.target)))?;
            decode_early_data(encoded, self.early_data.max).map_err(bad)?
        } else {
            if req.path() != self.path {
                return Err(not_found(format!("bad path {}", req.path())));
            }
            match &self.early_data.header {
                Some(name) => match req.headers.get(name) {
                    Some(value) => {
                        let encoded = value
                            .to_str()
                            .map_err(|_| bad(format!("invalid {}", name)))?;
                        decode_early_data(encoded, self.early_data.max).map_err(bad)?
                    }
                    None => Vec::new(),
                },
                None => Vec::new(),
            }
        };
        let protocol = match &self.early_data.header {
            Some(name) if *name == http::header::SEC_WEBSOCKET_PROTOCOL => {
                req.headers.get(name).cloned()
            }
            _ => None,
        };

        if req.method != "GET" {
            return Err(bad(format!("method {}", req.method)));
        }
        if !upgrade::upgrades_to_websocket(&req.headers) {
            return Err(bad("not an upgrade to websocket".to_string()));
        }
        if req.header("sec-websocket-version") != Some("13") {
            return Err(bad("unsupported websocket version".to_string()));
        }
        let key = req
            .header("sec-websocket-key")
            .ok_or_else(|| bad("no Sec-WebSocket-Key".to_string()))?;
        Ok(Accepted {
            accept_key: tungstenite::handshake::derive_accept_key(key.as_bytes()),
            early_data,
            protocol,
        })
    }

    /// The client's address as the trusted proxy in front reports it: the
    /// last address in the header that is one.
    fn forwarded_source(&self, req: &RequestHead) -> Option<IpAddr> {
        let forwarded = req.header(self.forwarded_header.as_deref()?)?;
        forwarded
            .split(',')
            .map(str::trim)
            .map_while(|x| x.parse::<IpAddr>().ok())
            .last()
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let (head, rest) = upgrade::read_head(&mut stream).await?;
        let req = upgrade::parse_request(&head)?;
        let accepted = match self.accept(&req) {
            Ok(accepted) => accepted,
            Err((status, why)) => {
                return Err(upgrade::refuse(
                    &mut stream,
                    status,
                    format!("accept ws failed: {}", why),
                )
                .await)
            }
        };
        if let Some(source) = self.forwarded_source(&req) {
            sess.forwarded_source.replace(source);
        }

        let mut extra = vec![(
            http::header::SEC_WEBSOCKET_ACCEPT,
            HeaderValue::from_str(&accepted.accept_key).map_err(io::Error::other)?,
        )];
        if let Some(protocol) = accepted.protocol {
            extra.push((HeaderName::from_static("sec-websocket-protocol"), protocol));
        }
        stream
            .write_all(&upgrade::switching_protocols(&extra))
            .await?;
        stream.flush().await?;

        let ws = WebSocketStream::from_partially_read(stream, rest, Role::Server, None).await;
        debug!(
            "accepted WS stream, {} bytes of early data",
            accepted.early_data.len()
        );
        Ok(InboundTransport::Stream(
            Box::new(super::ws_stream::WebSocketToStream::with_early_data(
                ws,
                self.half_close,
                accepted.early_data,
            )),
            sess,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(target: &str, extra: &str) -> RequestHead {
        let head = format!(
            "GET {} HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{}\r\n",
            target, extra
        );
        upgrade::parse_request(head.as_bytes()).unwrap()
    }

    fn handler(max: usize, header: Option<&str>) -> Handler {
        Handler::new(
            "/ws".to_string(),
            None,
            false,
            EarlyData::new(max, header).unwrap(),
        )
    }

    #[test]
    fn test_accept_key() {
        let accepted = handler(0, None).accept(&request("/ws", "")).unwrap();
        // RFC 6455's own example.
        assert_eq!(accepted.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert!(accepted.early_data.is_empty());
    }

    #[test]
    fn test_early_data_in_path() {
        let h = handler(16, None);
        assert_eq!(h.accept(&request("/wsYWI", "")).unwrap().early_data, b"ab");
        assert!(h.accept(&request("/ws", "")).unwrap().early_data.is_empty());
        assert_eq!(h.accept(&request("/other", "")).unwrap_err().0, 404);
        assert_eq!(h.accept(&request("/ws!!", "")).unwrap_err().0, 400);
        // Without early data configured, the path must be the path.
        assert_eq!(
            handler(0, None)
                .accept(&request("/wsYWI", ""))
                .unwrap_err()
                .0,
            404
        );
    }

    #[test]
    fn test_early_data_in_header() {
        let h = handler(16, Some("Sec-WebSocket-Protocol"));
        let accepted = h
            .accept(&request("/ws", "Sec-WebSocket-Protocol: YWI\r\n"))
            .unwrap();
        assert_eq!(accepted.early_data, b"ab");
        assert_eq!(accepted.protocol.unwrap(), "YWI");
        assert!(h.accept(&request("/ws", "")).unwrap().early_data.is_empty());
        assert_eq!(h.accept(&request("/wsYWI", "")).unwrap_err().0, 404);
        // Over the limit.
        let big = crate::transport::ws::encode_early_data(&[0u8; 17]);
        let extra = format!("Sec-WebSocket-Protocol: {}\r\n", big);
        assert_eq!(h.accept(&request("/ws", &extra)).unwrap_err().0, 400);

        let h = handler(16, Some("X-Early"));
        let accepted = h.accept(&request("/ws", "X-Early: YWI\r\n")).unwrap();
        assert_eq!(accepted.early_data, b"ab");
        assert!(accepted.protocol.is_none());
    }
}
