use std::collections::HashMap;

use async_trait::async_trait;
use http::{HeaderName, HeaderValue, StatusCode};
use tokio::io::AsyncWriteExt;
use tracing::debug;

use super::super::http1::{self as upgrade, Prefixed, RequestHead};
use crate::{adapter::*, session::Session};

pub struct Handler {
    /// The `Host` a request must carry; any, when not set.
    host: Option<String>,
    path: String,
    /// Added to the `101`.
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl Handler {
    pub fn new(
        host: Option<String>,
        path: String,
        headers: &HashMap<String, String>,
    ) -> anyhow::Result<Self> {
        if !path.starts_with('/') {
            return Err(anyhow::anyhow!("path: must start with /"));
        }
        let headers = upgrade::config_headers(headers)?;
        if let Some((name, _)) = headers
            .iter()
            .find(|(name, _)| [http::header::CONNECTION, http::header::UPGRADE].contains(name))
        {
            return Err(anyhow::anyhow!("headers: {} is set by the transport", name));
        }
        Ok(Handler {
            host,
            path,
            headers,
        })
    }

    /// Checks the request, and says with what status to turn it down when it
    /// will not do.
    fn accept(&self, req: &RequestHead) -> Result<(), (StatusCode, String)> {
        if let Some(host) = &self.host {
            let got = req.header("host").unwrap_or_default();
            if !got.eq_ignore_ascii_case(host) {
                return Err((StatusCode::NOT_FOUND, format!("bad host {}", got)));
            }
        }
        if req.path() != self.path {
            return Err((StatusCode::NOT_FOUND, format!("bad path {}", req.path())));
        }
        if req.method != "GET" {
            return Err((StatusCode::BAD_REQUEST, format!("method {}", req.method)));
        }
        if !upgrade::upgrades_to_websocket(&req.headers) {
            return Err((StatusCode::BAD_REQUEST, "not an upgrade".to_string()));
        }
        Ok(())
    }
}

/// The headers of the `101` to `req`: those configured, and, when `req`
/// carries a `Sec-WebSocket-Key`, the `Sec-WebSocket-Accept` it calls for,
/// as Xray's server answers since v26.9.30, so that the exchange is a
/// WebSocket handshake to whatever checks one on the way (a CDN). Without a
/// key, as sing-box's client and Xray's before then ask, there is none.
fn answer_headers(
    req: &RequestHead,
    configured: &[(HeaderName, HeaderValue)],
) -> Vec<(HeaderName, HeaderValue)> {
    let mut headers = configured.to_vec();
    if let Some(key) = req.header("sec-websocket-key").filter(|k| !k.is_empty()) {
        let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
        headers.push((
            http::header::SEC_WEBSOCKET_ACCEPT,
            HeaderValue::from_str(&accept).expect("base64 is a header value"),
        ));
    }
    headers
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let (head, rest) = upgrade::read_head(&mut stream).await?;
        let req = upgrade::parse_request(&head)?;
        if let Err((status, why)) = self.accept(&req) {
            return Err(upgrade::refuse(
                &mut stream,
                status,
                format!("accept httpupgrade failed: {}", why),
            )
            .await);
        }
        stream
            .write_all(&upgrade::switching_protocols(&answer_headers(
                &req,
                &self.headers,
            )))
            .await?;
        stream.flush().await?;
        debug!("accepted httpupgrade stream");
        // A client may send before the `101` is back: what it sent after its
        // head is the stream's already.
        Ok(InboundTransport::Stream(
            Box::new(Prefixed::new(rest, stream)),
            sess,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(target: &str, host: &str, upgrade: &str) -> RequestHead {
        let head = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: {}\r\n\r\n",
            target, host, upgrade
        );
        upgrade::parse_request(head.as_bytes()).unwrap()
    }

    #[test]
    fn test_accept() {
        let h = Handler::new(
            Some("a.example".to_string()),
            "/up".to_string(),
            &HashMap::new(),
        )
        .unwrap();
        assert!(h.accept(&request("/up", "a.example", "websocket")).is_ok());
        assert!(h
            .accept(&request("/up?x=1", "A.example", "websocket"))
            .is_ok());
        assert_eq!(
            h.accept(&request("/up", "b.example", "websocket"))
                .unwrap_err()
                .0,
            404
        );
        assert_eq!(
            h.accept(&request("/down", "a.example", "websocket"))
                .unwrap_err()
                .0,
            404
        );
        assert_eq!(
            h.accept(&request("/up", "a.example", "h2c")).unwrap_err().0,
            400
        );

        let any_host = Handler::new(None, "/up".to_string(), &HashMap::new()).unwrap();
        assert!(any_host
            .accept(&request("/up", "b.example", "websocket"))
            .is_ok());
    }

    /// The head a handler with `configured` headers answers `request` with.
    fn answer(request: &[u8], configured: &HashMap<String, String>) -> upgrade::ResponseHead {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(request).await.unwrap();
            let h = Handler::new(None, "/up".to_string(), configured).unwrap();
            h.handle(Session::default(), Box::new(server))
                .await
                .unwrap();
            let (head, _) = upgrade::read_head(&mut client).await.unwrap();
            upgrade::parse_response(&head).unwrap()
        })
    }

    // With a `Sec-WebSocket-Key`, the `101` carries the accept it calls for,
    // RFC 6455's example here, beside the headers configured; without, none.
    #[test]
    fn test_answer_accepts_a_websocket_key() {
        let configured = HashMap::from([("X-Served-By".to_string(), "sail".to_string())]);
        let resp = answer(
            b"GET /up HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            &configured,
        );
        assert_eq!(resp.status, 101);
        assert_eq!(
            resp.header("sec-websocket-accept"),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );
        assert_eq!(resp.header("x-served-by"), Some("sail"));

        let resp = answer(
            b"GET /up HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            &configured,
        );
        assert_eq!(resp.status, 101);
        assert_eq!(resp.header("sec-websocket-accept"), None);
        assert_eq!(resp.header("x-served-by"), Some("sail"));
    }

    /// Bytes a client sends right behind its request reach the stream.
    #[test]
    fn test_upgrade_keeps_what_follows() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use tokio::io::AsyncReadExt;
            let (mut client, server) = tokio::io::duplex(4096);
            client
                .write_all(
                    b"GET /up HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n\
                      Upgrade: websocket\r\n\r\npayload",
                )
                .await
                .unwrap();
            let h = Handler::new(None, "/up".to_string(), &HashMap::new()).unwrap();
            let transport = h
                .handle(Session::default(), Box::new(server))
                .await
                .unwrap();
            let InboundTransport::Stream(mut stream, _) = transport else {
                panic!("not a stream");
            };
            let mut buf = [0u8; 7];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"payload");

            let (head, _) = upgrade::read_head(&mut client).await.unwrap();
            let resp = upgrade::parse_response(&head).unwrap();
            assert_eq!(resp.status, 101);
        });
    }
}
