//! The HTTP/1.1 upgrade exchange that both WebSocket and HTTPUpgrade open
//! with: one request, one `101 Switching Protocols`, and then the connection
//! belongs to whatever it was upgraded to.
//!
//! Written here rather than left to tungstenite for two reasons. The heads
//! are read with a bound, since whoever connects to an inbound decides how
//! long they are. And the early data of the WebSocket transport rides in
//! `Sec-WebSocket-Protocol`, which sing-box's server does not answer with a
//! subprotocol and tungstenite's client refuses to do without.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderName, HeaderValue};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// The longest head either side reads. A WebSocket request carrying 2 KiB
/// of early data, as Xray and sing-box configure it, is well within it.
pub const MAX_HEAD: usize = 16 * 1024;

/// The most header fields a head may have.
const MAX_HEADERS: usize = 64;

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

/// Reads an HTTP head, up to and including the blank line that ends it.
/// Returns the head and whatever was read after it, which belongs to the
/// connection that follows.
pub async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed in the middle of an HTTP head",
            ));
        }
        // The end may straddle the last read.
        let from = head.len().saturating_sub(3);
        head.extend_from_slice(&chunk[..n]);
        if let Some(at) = head[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = head.split_off(from + at + 4);
            return Ok((head, rest));
        }
        if head.len() > MAX_HEAD {
            return Err(invalid(format!("HTTP head longer than {} bytes", MAX_HEAD)));
        }
    }
}

fn header_map(headers: &[httparse::Header<'_>]) -> io::Result<HeaderMap> {
    let mut map = HeaderMap::with_capacity(headers.len());
    for h in headers {
        let name = HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|_| invalid(format!("invalid header name {:?}", h.name)))?;
        let value = HeaderValue::from_bytes(h.value)
            .map_err(|_| invalid(format!("invalid value of header {}", h.name)))?;
        map.append(name, value);
    }
    Ok(map)
}

/// A request head.
#[derive(Debug)]
pub struct RequestHead {
    pub method: String,
    /// The request target as sent, query included.
    pub target: String,
    pub headers: HeaderMap,
}

impl RequestHead {
    /// The target without its query.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or_default()
    }

    /// The value of `name`, when it is there and is text.
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
}

pub fn parse_request(head: &[u8]) -> io::Result<RequestHead> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(invalid("incomplete HTTP request head")),
        Err(e) => return Err(invalid(format!("invalid HTTP request head: {}", e))),
    }
    if req.version != Some(1) {
        return Err(invalid("not an HTTP/1.1 request"));
    }
    Ok(RequestHead {
        method: req.method.unwrap_or_default().to_string(),
        target: req.path.unwrap_or_default().to_string(),
        headers: header_map(req.headers)?,
    })
}

/// A response head.
#[derive(Debug)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: HeaderMap,
}

impl ResponseHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
}

pub fn parse_response(head: &[u8]) -> io::Result<ResponseHead> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(invalid("incomplete HTTP response head")),
        Err(e) => return Err(invalid(format!("invalid HTTP response head: {}", e))),
    }
    Ok(ResponseHead {
        status: resp.code.unwrap_or_default(),
        headers: header_map(resp.headers)?,
    })
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Whether the `Connection` and `Upgrade` headers ask for, or agree to, an
/// upgrade to WebSocket. `Connection` is a list, as in
/// `keep-alive, Upgrade`.
pub fn upgrades_to_websocket(headers: &HeaderMap) -> bool {
    let connection = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    let upgrade = header(headers, "upgrade").is_some_and(|v| {
        v.split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("websocket"))
    });
    connection && upgrade
}

/// Headers a configuration gives, checked once when it is loaded. `Host`
/// is left out: it is the request's own, set apart.
pub fn config_headers<'a>(
    headers: impl IntoIterator<Item = (&'a String, &'a String)>,
) -> anyhow::Result<Vec<(HeaderName, HeaderValue)>> {
    let mut checked = Vec::new();
    for (name, value) in headers {
        let name = HeaderName::try_from(name.as_str())
            .map_err(|_| anyhow::anyhow!("headers: invalid header name {:?}", name))?;
        if name == http::header::HOST {
            continue;
        }
        let value = HeaderValue::from_str(value)
            .map_err(|_| anyhow::anyhow!("headers: invalid value of header {}", name))?;
        checked.push((name, value));
    }
    Ok(checked)
}

/// A request head asking to upgrade to WebSocket. `extra` comes after the
/// headers the upgrade needs, and may repeat none of them.
pub fn upgrade_request(target: &str, host: &str, extra: &[(HeaderName, HeaderValue)]) -> Vec<u8> {
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        target, host
    )
    .into_bytes();
    for (name, value) in extra {
        req.extend_from_slice(name.as_str().as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(value.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    req
}

/// The `101` a server agrees to the upgrade with.
pub fn switching_protocols(extra: &[(HeaderName, HeaderValue)]) -> Vec<u8> {
    let mut resp =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
            .to_vec();
    for (name, value) in extra {
        resp.extend_from_slice(name.as_str().as_bytes());
        resp.extend_from_slice(b": ");
        resp.extend_from_slice(value.as_bytes());
        resp.extend_from_slice(b"\r\n");
    }
    resp.extend_from_slice(b"\r\n");
    resp
}

/// Turns a request down with `status`, and fails with `why`. The client is
/// told no more than the status.
pub async fn refuse<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: http::StatusCode,
    why: String,
) -> io::Error {
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or_default()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
    io::Error::new(io::ErrorKind::InvalidData, why)
}

/// A stream that first yields bytes already read from it.
pub struct Prefixed<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Prefixed {
            prefix: Bytes::from(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
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

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_read_head_keeps_what_follows() {
        runtime().block_on(async {
            let (mut a, mut b) = tokio::io::duplex(64);
            let writer = tokio::spawn(async move {
                // In pieces, the blank line split across two of them.
                for piece in [&b"GET /p HTTP/1.1\r\nHost: x\r\n\r"[..], b"\npayload"] {
                    a.write_all(piece).await.unwrap();
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            });
            let (head, rest) = read_head(&mut b).await.unwrap();
            writer.await.unwrap();
            assert_eq!(head, b"GET /p HTTP/1.1\r\nHost: x\r\n\r\n");
            assert_eq!(rest, b"payload");
            let req = parse_request(&head).unwrap();
            assert_eq!((req.method.as_str(), req.path()), ("GET", "/p"));
            assert_eq!(req.header("host"), Some("x"));
        });
    }

    #[test]
    fn test_read_head_is_bounded() {
        runtime().block_on(async {
            let (mut a, mut b) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let _ = a.write_all(b"GET / HTTP/1.1\r\n").await;
                loop {
                    if a.write_all(b"X-Filler: aaaaaaaaaaaaaaaa\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let err = read_head(&mut b).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        });
    }

    #[test]
    fn test_upgrade_headers() {
        let head =
            b"GET / HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\n";
        assert!(upgrades_to_websocket(&parse_request(head).unwrap().headers));
        let head = b"GET / HTTP/1.1\r\nConnection: keep-alive\r\nUpgrade: websocket\r\n\r\n";
        assert!(!upgrades_to_websocket(
            &parse_request(head).unwrap().headers
        ));
        let resp = parse_response(&switching_protocols(&[])).unwrap();
        assert_eq!(resp.status, 101);
        assert!(upgrades_to_websocket(&resp.headers));
    }
}
