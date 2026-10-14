use std::collections::HashMap;
use std::io;

use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use tokio::io::AsyncWriteExt;

use super::super::http1::{self as upgrade, Prefixed};
use crate::{adapter::*, session::Session};

pub struct Handler {
    path: String,
    /// `Host`; the server's address when not set.
    host: Option<String>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl Handler {
    /// `headers` are checked here, so that a mistake in them is a
    /// configuration error.
    pub fn new(
        host: Option<String>,
        path: String,
        headers: &HashMap<String, String>,
    ) -> anyhow::Result<Self> {
        if !path.starts_with('/') {
            return Err(anyhow::anyhow!("path: must start with /"));
        }
        // `host` is where sing-box sets it; a `Host` among the headers is
        // one more place, and two that disagree are a mistake.
        let header_host = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, host)| host.clone());
        let host = match (host, header_host) {
            (Some(a), Some(b)) if a != b => {
                return Err(anyhow::anyhow!("host: differs from the Host header"))
            }
            (a, b) => a.or(b),
        };
        if let Some(host) = &host {
            HeaderValue::from_str(host).map_err(|_| anyhow::anyhow!("host: invalid"))?;
        }
        let mut headers = upgrade::config_headers(headers)?;
        if let Some((name, _)) = headers
            .iter()
            .find(|(name, _)| [http::header::CONNECTION, http::header::UPGRADE].contains(name))
        {
            return Err(anyhow::anyhow!("headers: {} is set by the transport", name));
        }
        headers.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        Ok(Handler {
            path,
            host,
            headers,
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
        let mut stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        let host = self.host.clone().unwrap_or_else(|| sess.destination.host());
        stream
            .write_all(&upgrade::upgrade_request(&self.path, &host, &self.headers))
            .await?;
        stream.flush().await?;

        let (head, rest) = upgrade::read_head(&mut stream).await?;
        let resp = upgrade::parse_response(&head)?;
        let failed =
            |why: String| io::Error::other(format!("connect httpupgrade {} failed: {}", host, why));
        if resp.status != 101 {
            return Err(failed(format!("server answered {}", resp.status)));
        }
        if !upgrade::upgrades_to_websocket(&resp.headers) {
            return Err(failed("not upgraded".to_string()));
        }
        // Whatever the server sent after its head is the stream's already.
        Ok(Box::new(Prefixed::new(rest, stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config() {
        let none = HashMap::new();
        assert!(Handler::new(None, "/".to_string(), &none).is_ok());
        assert!(Handler::new(None, "up".to_string(), &none).is_err());
        let headers = HashMap::from([("Host".to_string(), "a.example".to_string())]);
        let handler = Handler::new(None, "/".to_string(), &headers).unwrap();
        assert_eq!(handler.host.as_deref(), Some("a.example"));
        assert!(handler.headers.is_empty());
        assert!(Handler::new(Some("b.example".to_string()), "/".to_string(), &headers).is_err());
        let headers = HashMap::from([("Upgrade".to_string(), "h2c".to_string())]);
        assert!(Handler::new(None, "/".to_string(), &headers).is_err());
        let headers = HashMap::from([("X-Bad".to_string(), "a\r\nb".to_string())]);
        assert!(Handler::new(None, "/".to_string(), &headers).is_err());
    }

    // The request carries no `Sec-WebSocket-Key`, which sing-box's server
    // turns away with a 404 ("real websocket request received"), and a
    // `101` without `Sec-WebSocket-Accept`, sing-box's, is taken.
    #[test]
    fn test_request_without_websocket_key() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use tokio::io::AsyncReadExt;
            let (client, mut server) = tokio::io::duplex(4096);
            let peer = async move {
                let (head, _) = upgrade::read_head(&mut server).await.unwrap();
                let req = upgrade::parse_request(&head).unwrap();
                assert_eq!(req.header("sec-websocket-key"), None);
                assert_eq!(req.header("sec-websocket-version"), None);
                server
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\
                          Upgrade: websocket\r\n\r\nhello",
                    )
                    .await
                    .unwrap();
                server
            };
            let h = Handler::new(None, "/up".to_string(), &HashMap::new()).unwrap();
            let sess = Session::default();
            let (stream, _server) =
                tokio::join!(h.handle(&sess, None, Some(Box::new(client))), peer);
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
        });
    }
}
