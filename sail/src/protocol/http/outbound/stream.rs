use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{adapter::*, session::*};

/// How long the proxy's answer to `CONNECT` may be, up to its blank line.
const MAX_RESPONSE_HEAD_SIZE: usize = 16 * 1024;

/// How much of a refusal's status line goes into the error.
const MAX_STATUS_LINE_IN_ERROR: usize = 256;

pub struct Handler {
    pub address: String,
    pub port: u16,
    /// The whole `Proxy-Authorization` value, if the proxy wants one.
    pub authorization: Option<String>,
    /// The request target in place of the destination.
    pub path: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl Handler {
    fn request(&self, destination: &SocksAddr) -> Vec<u8> {
        let host = destination.to_string();
        let target = self.path.as_deref().unwrap_or(&host);
        let mut head = format!("CONNECT {} HTTP/1.1\r\n", target);
        let has = |name: &str| {
            self.headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(name))
        };
        if !has("Host") {
            head.push_str(&format!("Host: {}\r\n", host));
        }
        if let Some(authorization) = &self.authorization {
            if !has("Proxy-Authorization") {
                head.push_str(&format!("Proxy-Authorization: {}\r\n", authorization));
            }
        }
        for (name, value) in &self.headers {
            head.push_str(&format!("{}: {}\r\n", name, value));
        }
        head.push_str("\r\n");
        head.into_bytes()
    }
}

/// Reads the proxy's answer up to its blank line, returning it and what came
/// after, which belongs to the tunnel.
async fn read_response_head<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::with_capacity(1024);
    let mut searched = 0usize;
    loop {
        // The end may straddle what was searched and what came since.
        let from = searched.saturating_sub(3);
        if let Some(i) = data[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = from + i;
            let rest = data.split_off(end + 4);
            data.truncate(end);
            return Ok((data, rest));
        }
        if data.len() > MAX_RESPONSE_HEAD_SIZE {
            return Err(io::Error::other(format!(
                "http proxy answer longer than {} bytes",
                MAX_RESPONSE_HEAD_SIZE
            )));
        }
        searched = data.len();
        data.reserve(1024);
        if stream.read_buf(&mut data).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http proxy closed the connection before answering",
            ));
        }
    }
}

/// Checks the proxy's answer is `200`, erring with its status line if not.
fn check_status(head: &[u8]) -> io::Result<()> {
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let line = String::from_utf8_lossy(&head[..line_end]);
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if version.starts_with("HTTP/1.") && code == "200" {
        return Ok(());
    }
    let shown: String = line.chars().take(MAX_STATUS_LINE_IN_ERROR).collect();
    Err(io::Error::other(format!(
        "http proxy refused CONNECT: {}",
        shown.escape_debug()
    )))
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let mut stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        // Nothing goes with the request: a proxy may take whatever follows
        // it as a request of its own until it has answered.
        stream.write_all(&self.request(&sess.destination)).await?;
        stream.flush().await?;
        let (head, rest) = read_response_head(&mut stream).await?;
        check_status(&head)?;
        if rest.is_empty() {
            return Ok(stream);
        }
        Ok(Box::new(Prefixed {
            prefix: rest,
            inner: stream,
        }))
    }
}

/// A stream that first yields `prefix`: tunnel bytes that came in the read
/// that ended the proxy's answer.
struct Prefixed {
    prefix: Vec<u8>,
    inner: AnyStream,
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> Handler {
        Handler {
            address: "proxy".into(),
            port: 8080,
            authorization: Some("Basic dTpw".into()),
            path: None,
            headers: vec![("X-Test".into(), "1".into())],
        }
    }

    #[test]
    fn request_names_the_destination() {
        let dest = SocksAddr::Domain("example.com".into(), 443);
        let request = String::from_utf8(handler().request(&dest)).unwrap();
        assert_eq!(
            request,
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
             Proxy-Authorization: Basic dTpw\r\nX-Test: 1\r\n\r\n"
        );
    }

    #[test]
    fn path_takes_the_request_target() {
        let mut handler = handler();
        handler.path = Some("/tunnel".into());
        let dest = SocksAddr::from(("::1".parse::<std::net::IpAddr>().unwrap(), 443));
        let request = String::from_utf8(handler.request(&dest)).unwrap();
        assert!(request.starts_with("CONNECT /tunnel HTTP/1.1\r\nHost: [::1]:443\r\n"));
    }

    #[test]
    fn only_200_succeeds() {
        assert!(check_status(b"HTTP/1.1 200 Connection established").is_ok());
        assert!(check_status(b"HTTP/1.0 200 OK\r\nX: y").is_ok());
        let err = check_status(b"HTTP/1.1 407 Proxy Authentication Required\r\nX: y")
            .unwrap_err()
            .to_string();
        assert!(err.contains("HTTP/1.1 407 Proxy Authentication Required"));
        assert!(!err.contains("X: y"));
        assert!(check_status(b"HTTP/1.1 204 No Content").is_err());
        assert!(check_status(b"garbage").is_err());
    }

    #[tokio::test]
    async fn answer_is_bounded_and_keeps_what_follows() {
        let mut answer = &b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nhello"[..];
        let (head, rest) = read_response_head(&mut answer).await.unwrap();
        assert_eq!(head, b"HTTP/1.1 200 OK\r\nA: b");
        assert_eq!(rest, b"hello");

        let long = vec![b'a'; MAX_RESPONSE_HEAD_SIZE + 4096];
        assert!(read_response_head(&mut &long[..]).await.is_err());
        assert!(read_response_head(&mut &b"HTTP/1.1 200 OK\r\n"[..])
            .await
            .is_err());
    }
}
