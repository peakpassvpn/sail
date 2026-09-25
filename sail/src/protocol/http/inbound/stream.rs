use std::cmp;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::str;
use std::sync::Arc;
use std::{net::IpAddr, pin::Pin, task::Context, task::Poll};
use tokio::io::{AsyncRead, AsyncWrite};

use ::http::{Method, Uri};
use anyhow::Result;
use async_trait::async_trait;
use base64::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::{
    adapter::*,
    session::{Session, SocksAddr},
};

const BUFFER_SIZE: usize = 1024;
const EOL: [u8; 2] = [13, 10];
const EOH: [u8; 4] = [13, 10, 13, 10];

/// How long a request head may be. A client that sends more without ending
/// it is not one to hold memory for.
const MAX_HEAD_SIZE: usize = 16 * 1024;

/// The realm `407` answers name, which clients show when asking for
/// credentials.
const REALM: &str = "sail";

const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";

fn bad_request() -> io::Error {
    io::Error::other("bad request")
}

/// The `407` a request without acceptable credentials is answered with.
fn proxy_auth_required() -> Vec<u8> {
    format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: Basic realm=\"{}\"\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
        REALM
    )
    .into_bytes()
}

fn find(s: &[u8], sep: &[u8]) -> Option<usize> {
    s.windows(sep.len()).position(|w| w == sep)
}

/// Parse destination
impl TryFrom<&Uri> for SocksAddr {
    type Error = io::Error;
    fn try_from(uri: &Uri) -> Result<Self, Self::Error> {
        let (host, port) = (
            uri.host().ok_or(bad_request())?,
            uri.port_u16()
                .or_else(|| match uri.scheme_str() {
                    Some("http") => Some(80),
                    Some("https") => Some(443),
                    _ => None,
                })
                .ok_or(bad_request())?,
        );
        // An IPv6 host comes bracketed.
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let addr = if let Ok(ip) = bare.parse::<IpAddr>() {
            SocksAddr::from((ip, port))
        } else {
            SocksAddr::try_from((host, port))?
        };
        Ok(addr)
    }
}

/// https://www.rfc-editor.org/rfc/rfc7230#section-5.3
enum TargetFormat {
    Origin,
    Absolute,
    Authority,
    Asterisk,
}

struct RequestHead {
    method: Method,
    uri: Uri,
    version: String,
    headers: Vec<(String, String)>,
    target_format: TargetFormat,
}

impl RequestHead {
    fn parse_request_line(request_line: &[u8]) -> io::Result<(Method, Uri, String)> {
        let mut tokens = str::from_utf8(request_line).unwrap_or("").splitn(3, ' ');
        let method = match Method::try_from(tokens.next().unwrap_or("")) {
            Ok(v) => v,
            Err(_e) => return Err(bad_request()),
        };
        let uri = match Uri::try_from(tokens.next().unwrap_or("")) {
            Ok(v) => v,
            Err(_e) => return Err(bad_request()),
        };
        let version = tokens.next().unwrap_or("HTTP/1.1");
        Ok((method, uri, version.to_string()))
    }

    fn parse_headers(header_lines: &[u8]) -> io::Result<Vec<(String, String)>> {
        let mut headers = Vec::new();
        let lines = str::from_utf8(header_lines).unwrap_or("").split("\r\n");
        for line in lines {
            let (name, value) = match line.split_once(':') {
                Some((n, v)) => (n.trim(), v.trim()),
                None => continue,
            };
            headers.push((name.to_string(), value.to_string()));
        }
        Ok(headers)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn set_header(&mut self, name: String, value: String) {
        for (i, (n, _v)) in self.headers.iter().enumerate() {
            if n.eq_ignore_ascii_case(&name) {
                self.headers[i] = (n.clone(), value);
                return;
            }
        }
        self.headers.push((name, value));
    }

    fn remove_header(&mut self, name: &str) {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    }
}

impl From<RequestHead> for Vec<u8> {
    fn from(v: RequestHead) -> Self {
        let mut head = Vec::new();
        let request_line = format!("{} {} {}\r\n", v.method, v.uri, v.version);
        head.append(&mut request_line.into_bytes());
        for (name, value) in v.headers {
            let header = format!("{}: {}\r\n", name, value);
            head.append(&mut header.into_bytes());
        }
        head.extend_from_slice("\r\n".as_bytes());
        head
    }
}

impl TryFrom<&[u8]> for RequestHead {
    type Error = io::Error;
    fn try_from(head: &[u8]) -> Result<Self, Self::Error> {
        let (request_line, header) = match find(head, &EOL) {
            Some(i) => (&head[..i], &head[i + EOL.len()..]),
            None => (head, &[][..]),
        };
        let (method, uri, version) = RequestHead::parse_request_line(request_line)?;
        let headers = RequestHead::parse_headers(header)?;
        let target_format = if uri == "*" {
            TargetFormat::Asterisk
        } else if uri.scheme().is_some() {
            TargetFormat::Absolute
        } else if method == Method::CONNECT {
            TargetFormat::Authority
        } else {
            TargetFormat::Origin
        };
        Ok(RequestHead {
            method,
            uri,
            version,
            headers,
            target_format,
        })
    }
}

/// The user `Proxy-Authorization` authenticates as, if it names one of
/// `users` with their password.
fn authenticate(users: &HashMap<String, String>, authorization: Option<&str>) -> Option<String> {
    let (scheme, credentials) = authorization?.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = BASE64_STANDARD.decode(credentials.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    let expected = users.get(username)?;
    if constant_time_eq(expected.as_bytes(), password.as_bytes()) {
        Some(username.to_owned())
    } else {
        None
    }
}

/// Compares without an early exit, so that timing does not tell how much of
/// a guessed password was right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct HttpStream {
    cache: Vec<u8>,
    origin: AnyStream,
}

impl HttpStream {
    /// Reads up to the end of the request head, returning the head without
    /// its closing blank line and whatever came after it. `data` is what was
    /// read from the stream already.
    async fn read_head(&mut self, mut data: Vec<u8>) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut searched: usize = 0;
        loop {
            // The end may straddle what was searched and what came since.
            let from = searched.saturating_sub(EOH.len() - 1);
            if let Some(i) = find(&data[from..], &EOH) {
                let end = from + i;
                let rest = data.split_off(end + EOH.len());
                data.truncate(end);
                return Ok((data, rest));
            }
            if data.len() > MAX_HEAD_SIZE {
                return Err(io::Error::other(format!(
                    "request head longer than {} bytes",
                    MAX_HEAD_SIZE
                )));
            }
            searched = data.len();
            data.reserve(BUFFER_SIZE);
            let n = self.origin.read_buf(&mut data).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// Reads the request, authenticates it against `users` and finds where
    /// it goes, leaving what the client sent past the proxying in `cache`.
    /// Returns the destination and the user authenticated, if any.
    async fn accept(
        &mut self,
        users: &HashMap<String, String>,
        prefix: Vec<u8>,
    ) -> io::Result<(SocksAddr, Option<String>)> {
        let (head, rest) = self.read_head(prefix).await?;
        let mut head = match RequestHead::try_from(&head[..]) {
            Ok(head) => head,
            Err(e) => {
                let _ = self.origin.write_all(BAD_REQUEST).await;
                return Err(e);
            }
        };

        let user = if users.is_empty() {
            None
        } else {
            match authenticate(users, head.header("Proxy-Authorization")) {
                Some(user) => Some(user),
                None => {
                    let _ = self.origin.write_all(&proxy_auth_required()).await;
                    return Err(io::Error::other("http proxy authentication failed"));
                }
            }
        };

        let addr = match head.target_format {
            TargetFormat::Absolute | TargetFormat::Authority => SocksAddr::try_from(&head.uri),
            _ => Err(bad_request()),
        };
        let addr = match addr {
            Ok(addr) => addr,
            Err(e) => {
                let _ = self.origin.write_all(BAD_REQUEST).await;
                return Err(e);
            }
        };

        match head.target_format {
            TargetFormat::Absolute => {
                // Forwarded to the origin as a request of its own, which
                // names its target by path and Host, without what was meant
                // for this proxy.
                let path_and_query = head
                    .uri
                    .path_and_query()
                    .map(|paq| paq.as_str())
                    .unwrap_or("/");
                head.uri = path_and_query.parse().map_err(|_| bad_request())?;
                head.set_header("Host".to_string(), addr.to_string());
                head.remove_header("Proxy-Authorization");
                head.remove_header("Proxy-Connection");
                self.cache = head.into();
                self.cache.extend_from_slice(&rest);
            }
            _ => {
                self.origin
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await?;
                // A client may send what it tunnels without waiting for the
                // answer.
                self.cache = rest;
            }
        }
        Ok((addr, user))
    }
}

impl AsyncRead for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.cache.is_empty() {
            let n = cmp::min(buf.remaining(), self.cache.len());
            let cached_data = self.cache.drain(..n);
            buf.put_slice(cached_data.as_slice());
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.origin).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.origin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.origin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.origin).poll_shutdown(cx)
    }
}

pub struct Handler {
    /// Passwords by username. Empty lets anyone in.
    users: Arc<HashMap<String, String>>,
}

impl Handler {
    pub fn new(users: HashMap<String, String>) -> Self {
        Handler {
            users: Arc::new(users),
        }
    }

    /// Handles a stream whose first bytes, `prefix`, were read already: by
    /// the mixed inbound, telling HTTP from SOCKS.
    pub(crate) async fn handle_with_prefix(
        &self,
        mut sess: Session,
        stream: AnyStream,
        prefix: Vec<u8>,
    ) -> io::Result<AnyInboundTransport> {
        let mut http_stream = HttpStream {
            cache: Vec::new(),
            origin: stream,
        };
        let (destination, user) = http_stream.accept(&self.users, prefix).await?;
        sess.destination = destination;
        if let Some(user) = user {
            sess.user = Some(user.into());
        }
        Ok(InboundTransport::Stream(Box::new(http_stream), sess))
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
        self.handle_with_prefix(sess, stream, Vec::new()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn users() -> HashMap<String, String> {
        HashMap::from([
            ("alice".to_string(), "a:pass".to_string()),
            ("bob".to_string(), "bpass".to_string()),
        ])
    }

    fn basic(credentials: &str) -> String {
        format!("Basic {}", BASE64_STANDARD.encode(credentials))
    }

    #[test]
    fn basic_credentials_name_their_user() {
        let users = users();
        assert_eq!(
            authenticate(&users, Some(&basic("bob:bpass"))).as_deref(),
            Some("bob")
        );
        // A password may hold a colon; the username ends at the first.
        assert_eq!(
            authenticate(&users, Some(&basic("alice:a:pass"))).as_deref(),
            Some("alice")
        );
        let lower = format!("basic {}", BASE64_STANDARD.encode("bob:bpass"));
        assert_eq!(authenticate(&users, Some(&lower)).as_deref(), Some("bob"));
    }

    #[test]
    fn wrong_or_missing_credentials_are_refused() {
        let users = users();
        assert_eq!(authenticate(&users, None), None);
        assert_eq!(authenticate(&users, Some(&basic("bob:wrong"))), None);
        assert_eq!(authenticate(&users, Some(&basic("carol:bpass"))), None);
        assert_eq!(authenticate(&users, Some(&basic("bob"))), None);
        assert_eq!(authenticate(&users, Some("Basic !!!")), None);
        assert_eq!(authenticate(&users, Some("Bearer abc")), None);
    }

    async fn accept(
        users: HashMap<String, String>,
        request: &[u8],
    ) -> (io::Result<(SocksAddr, Option<String>)>, Vec<u8>, Vec<u8>) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        client_w.write_all(request).await.unwrap();
        let mut stream = HttpStream {
            cache: Vec::new(),
            origin: Box::new(server),
        };
        let result = stream.accept(&users, Vec::new()).await;
        let cache = std::mem::take(&mut stream.cache);
        drop(stream);
        drop(client_w);
        let mut answer = Vec::new();
        client_r.read_to_end(&mut answer).await.unwrap();
        (result, answer, cache)
    }

    #[tokio::test]
    async fn connect_keeps_what_follows_the_head() {
        let (result, answer, cache) = accept(
            HashMap::new(),
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\nhello",
        )
        .await;
        let (addr, user) = result.unwrap();
        assert_eq!(addr.to_string(), "example.com:443");
        assert_eq!(user, None);
        assert!(answer.starts_with(b"HTTP/1.1 200"));
        assert_eq!(cache, b"hello");
    }

    #[tokio::test]
    async fn connect_to_ipv6() {
        let (result, _, _) = accept(HashMap::new(), b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n").await;
        let (addr, _) = result.unwrap();
        assert_eq!(addr.to_string(), "[::1]:443");
    }

    #[tokio::test]
    async fn authenticated_request_is_forwarded_without_proxy_headers() {
        let request = format!(
            "GET http://example.com/a?b HTTP/1.1\r\nHost: example.com\r\n\
             Proxy-Authorization: {}\r\nProxy-Connection: keep-alive\r\n\r\nbody",
            basic("bob:bpass")
        );
        let (result, answer, cache) = accept(users(), request.as_bytes()).await;
        let (addr, user) = result.unwrap();
        assert_eq!(addr.to_string(), "example.com:80");
        assert_eq!(user.as_deref(), Some("bob"));
        assert!(answer.is_empty());
        let forwarded = String::from_utf8(cache).unwrap();
        assert!(forwarded.starts_with("GET /a?b HTTP/1.1\r\n"));
        assert!(!forwarded.to_ascii_lowercase().contains("proxy-"));
        assert!(forwarded.ends_with("\r\n\r\nbody"));
    }

    #[tokio::test]
    async fn missing_credentials_get_407() {
        let (result, answer, _) =
            accept(users(), b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").await;
        assert!(result.is_err());
        let answer = String::from_utf8(answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));
        assert!(answer.contains("Proxy-Authenticate: Basic realm=\"sail\"\r\n"));
    }

    #[tokio::test]
    async fn head_is_bounded() {
        let mut request = b"GET http://example.com/ HTTP/1.1\r\nX: ".to_vec();
        request.resize(MAX_HEAD_SIZE + 2 * BUFFER_SIZE, b'a');
        let (result, _, _) = accept(HashMap::new(), &request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn origin_form_is_a_bad_request() {
        let (result, answer, _) = accept(HashMap::new(), b"GET / HTTP/1.1\r\n\r\n").await;
        assert!(result.is_err());
        assert!(answer.starts_with(b"HTTP/1.1 400"));
    }
}
