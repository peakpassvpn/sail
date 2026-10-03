//! What the server answers HTTP/3 requests that are not a good
//! authentication with, so that it looks like a web server to whoever
//! probes it: 404 by default, a fixed response, or whatever an HTTP or
//! HTTPS site behind it answers.
//!
//! A site behind is asked as sing-box's reverse proxy asks it, Go's
//! `httputil.ReverseProxy` over its default transport: an `https://` site
//! over TLS checked against the trusted roots, named by the URL's host, and
//! over HTTP/2 when it offers it.

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use serde_derive::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use super::super::h3::{self, Field};
use crate::net::InboundDialer;
use crate::transport::tls::roots::TrustRoots;
use crate::transport::tls::TlsClient;

/// Request bodies passed on at most.
const MAX_REQUEST_BODY: usize = 1024 * 1024;
/// Responses passed back at most, headers and body.
const MAX_RESPONSE: usize = 8 * 1024 * 1024;
/// How long the site behind may take.
const PROXY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the TLS handshake with an `https://` site may take: Go's
/// default transport's `TLSHandshakeTimeout`.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// What an `https://` site is offered, as Go's default transport offers it.
const ALPN: [&str; 2] = ["h2", "http/1.1"];

/// Headers that belong to one connection, not to the message: those Go's
/// reverse proxy removes both ways, besides those `connection` names.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Forwarding headers a client sent, which Go's reverse proxy does not pass
/// on.
const FORWARDING: [&str; 4] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
];

/// The `masquerade` field, as sing-box takes it: an `http://` or
/// `https://` URL to proxy to, or an object.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum MasqueradeOptions {
    Url(String),
    Object(MasqueradeObject),
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum MasqueradeObject {
    Proxy {
        url: String,
        /// Sends the site's own host instead of the one asked for.
        #[serde(default)]
        rewrite_host: bool,
    },
    String {
        #[serde(default)]
        status_code: Option<u16>,
        #[serde(default)]
        headers: HashMap<String, String>,
        content: String,
    },
}

pub enum Masquerade {
    NotFound,
    Fixed {
        status: u16,
        headers: Vec<(String, String)>,
        content: String,
    },
    Proxy {
        /// The host dialled, without brackets.
        host: String,
        port: u16,
        /// The URL's host and port, as the `host` header gives them.
        authority: String,
        /// The URL's path, which requested paths are put under.
        base_path: String,
        rewrite_host: bool,
        /// For an `https://` site.
        tls: Option<TlsClient>,
        /// Dials the site: the instance's dial defaults.
        dialer: InboundDialer,
    },
}

impl Masquerade {
    /// What `options` asks for; a site behind is dialled with `dialer`, and
    /// an `https://` one checked against `roots`.
    pub fn new(
        options: MasqueradeOptions,
        dialer: InboundDialer,
        roots: &TrustRoots,
    ) -> Result<Self> {
        match options {
            MasqueradeOptions::Url(url) => Self::proxy(&url, false, dialer, roots),
            MasqueradeOptions::Object(MasqueradeObject::Proxy { url, rewrite_host }) => {
                Self::proxy(&url, rewrite_host, dialer, roots)
            }
            MasqueradeOptions::Object(MasqueradeObject::String {
                status_code,
                headers,
                content,
            }) => {
                let status = status_code.unwrap_or(200);
                if !(200..=599).contains(&status) {
                    return Err(anyhow!("status_code: invalid status {}", status));
                }
                Ok(Masquerade::Fixed {
                    status,
                    headers: headers
                        .into_iter()
                        .map(|(k, v)| (k.to_ascii_lowercase(), v))
                        .collect(),
                    content,
                })
            }
        }
    }

    /// A proxy to `url`, which must be `http://` or `https://`: `file://`
    /// is not supported.
    fn proxy(
        url: &str,
        rewrite_host: bool,
        dialer: InboundDialer,
        roots: &TrustRoots,
    ) -> Result<Self> {
        let url = url::Url::parse(url).map_err(|e| anyhow!("url: {}", e))?;
        let tls = match url.scheme() {
            "http" => None,
            "https" => {
                let alpn: Vec<String> = ALPN.iter().map(|p| p.to_string()).collect();
                Some(
                    TlsClient::new(&alpn, None, false, None, &roots.get()?)
                        .map_err(|e| anyhow!("url: {}", e))?,
                )
            }
            scheme => {
                return Err(anyhow!(
                    "url: only http:// and https:// are supported, not {}://",
                    scheme
                ))
            }
        };
        let bracketed = url
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| anyhow!("url: no host"))?;
        // What Go puts in `host`: the URL's, its port only if written (the
        // url crate leaves out the scheme's own).
        let authority = match url.port() {
            Some(port) => format!("{}:{}", bracketed, port),
            None => bracketed.to_string(),
        };
        Ok(Masquerade::Proxy {
            host: bracketed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port: url
                .port_or_known_default()
                .ok_or_else(|| anyhow!("url: no port"))?,
            authority,
            base_path: url.path().trim_end_matches('/').to_string(),
            rewrite_host,
            tls,
            dialer,
        })
    }

    /// Answers the request `fields` on a stream.
    pub async fn serve(
        &self,
        fields: Vec<Field>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> io::Result<()> {
        let (status, headers, body) = match self {
            Masquerade::NotFound => (404, Vec::new(), Vec::new()),
            Masquerade::Fixed {
                status,
                headers,
                content,
            } => (*status, headers.clone(), content.clone().into_bytes()),
            Masquerade::Proxy { .. } => {
                let body = h3::read_body(&mut recv, MAX_REQUEST_BODY).await?;
                match timeout(PROXY_TIMEOUT, self.forward(&fields, &body)).await {
                    Ok(Ok(response)) => response,
                    _ => (502, Vec::new(), Vec::new()),
                }
            }
        };
        let status = status.to_string();
        let length = body.len().to_string();
        let mut out: Vec<(&str, &str)> = vec![(":status", &status)];
        out.extend(
            headers
                .iter()
                .filter(|(n, _)| n != "content-length")
                .map(|(n, v)| (n.as_str(), v.as_str())),
        );
        out.push(("content-length", &length));
        h3::write_headers(&mut send, &out).await?;
        if !body.is_empty() {
            send.write_all(&h3::data_frame_header(body.len()))
                .await
                .map_err(io::Error::other)?;
            send.write_all(&body).await.map_err(io::Error::other)?;
        }
        let _ = send.finish();
        let _ = recv.stop(0u32.into());
        Ok(())
    }

    /// Asks the site behind: over HTTP/2 when an `https://` site chooses
    /// it, else over HTTP/1.0, so that the answer comes whole, ended by the
    /// close.
    async fn forward(
        &self,
        fields: &[Field],
        body: &[u8],
    ) -> io::Result<(u16, Vec<Field>, Vec<u8>)> {
        let Masquerade::Proxy {
            host,
            port,
            authority,
            base_path,
            rewrite_host,
            tls,
            dialer,
        } = self
        else {
            return Err(io::Error::other("not a proxy"));
        };
        let method = h3::field(fields, ":method").unwrap_or("GET");
        let path = h3::field(fields, ":path").unwrap_or("/");
        let asked = h3::field(fields, ":authority").unwrap_or("");
        // As Go's: the host asked for, unless rewrite_host, which sends the
        // site's.
        let host_header = if *rewrite_host || asked.is_empty() {
            authority.as_str()
        } else {
            asked
        };
        // What goes into the request head must not break out of it.
        if !method.bytes().all(|b| b.is_ascii_alphabetic())
            || [path, host_header].iter().any(|s| {
                s.bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            })
        {
            return Err(io::Error::other("invalid request line"));
        }
        let request = Request {
            method,
            target: format!("{}{}", base_path, path),
            host: host_header,
            headers: request_headers(fields),
            body,
        };

        let upstream = dialer.tcp(host, *port).await?;
        let Some(tls) = tls else {
            return request.http1(upstream).await;
        };
        // Named, and checked, by the URL's host, whatever `host` says.
        let upstream = timeout(
            TLS_HANDSHAKE_TIMEOUT,
            tls.connect(host, upstream, None, None),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out"))??;
        if upstream.conn().ssl().selected_alpn_protocol() == Some(b"h2") {
            request.h2(upstream).await
        } else {
            request.http1(upstream).await
        }
    }
}

/// A request to the site behind.
struct Request<'a> {
    method: &'a str,
    /// The path and query, under the URL's path.
    target: String,
    host: &'a str,
    headers: Vec<Field>,
    body: &'a [u8],
}

impl Request<'_> {
    async fn http1<S>(&self, mut upstream: S) -> io::Result<(u16, Vec<Field>, Vec<u8>)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut head = format!(
            "{} {} HTTP/1.0\r\nhost: {}\r\n",
            self.method, self.target, self.host
        );
        for (name, value) in &self.headers {
            head.push_str(&format!("{}: {}\r\n", name, value));
        }
        head.push_str(&format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            self.body.len()
        ));
        upstream.write_all(head.as_bytes()).await?;
        upstream.write_all(self.body).await?;
        upstream.flush().await?;
        let mut response = Vec::new();
        (&mut upstream)
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut response)
            .await?;
        if response.len() > MAX_RESPONSE {
            return Err(io::Error::other("response too large"));
        }
        parse_response(&response)
    }

    /// The request as one stream of an HTTP/2 connection, which goes with
    /// it.
    async fn h2<S>(&self, upstream: S) -> io::Result<(u16, Vec<Field>, Vec<u8>)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (client, connection) = h2::client::Builder::new()
            .enable_push(false)
            .handshake::<_, Bytes>(upstream)
            .await
            .map_err(io::Error::other)?;
        let _driver = AbortOnDrop(crate::runtime::scope::spawn(
            "hysteria2 masquerade h2",
            async move {
                let _ = connection.await;
            },
        ));
        let mut request = http::Request::builder()
            .method(self.method)
            .uri(format!("https://{}{}", self.host, self.target));
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        let request = request.body(()).map_err(io::Error::other)?;
        let mut client = client.ready().await.map_err(io::Error::other)?;
        let (response, mut send) = client
            .send_request(request, self.body.is_empty())
            .map_err(io::Error::other)?;
        let mut rest = Bytes::copy_from_slice(self.body);
        while !rest.is_empty() {
            send.reserve_capacity(rest.len());
            let n = std::future::poll_fn(|cx| send.poll_capacity(cx))
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
                .map_err(io::Error::other)?;
            let chunk = rest.split_to(n.min(rest.len()));
            send.send_data(chunk, rest.is_empty())
                .map_err(io::Error::other)?;
        }

        let (head, mut recv) = response.await.map_err(io::Error::other)?.into_parts();
        let headers = head
            .headers
            .iter()
            .filter_map(|(name, value)| {
                Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
            })
            .collect();
        let mut data = Vec::new();
        while let Some(chunk) = recv.data().await {
            let chunk = chunk.map_err(io::Error::other)?;
            let _ = recv.flow_control().release_capacity(chunk.len());
            if data.len() + chunk.len() > MAX_RESPONSE {
                return Err(io::Error::other("response too large"));
            }
            data.extend_from_slice(&chunk);
        }
        Ok((head.status.as_u16(), without_hop_by_hop(headers), data))
    }
}

/// Stops the task when dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The client's headers that are passed on: not those of its connection,
/// its forwarding headers, or what the request head says itself.
fn request_headers(fields: &[Field]) -> Vec<Field> {
    let headers = fields
        .iter()
        .filter(|(name, value)| {
            !name.starts_with(':')
                && name != "host"
                && name != "content-length"
                && !FORWARDING.contains(&name.as_str())
                && !name.is_empty()
                && !name
                    .bytes()
                    .any(|b| b == b':' || b.is_ascii_whitespace() || b.is_ascii_control())
                && !value.contains(['\r', '\n'])
        })
        .cloned()
        .collect();
    without_hop_by_hop(headers)
}

/// `headers` without those of one connection: the known ones, and those
/// `connection` names.
fn without_hop_by_hop(headers: Vec<Field>) -> Vec<Field> {
    let named: Vec<String> = headers
        .iter()
        .filter(|(name, _)| name == "connection")
        .flat_map(|(_, value)| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    headers
        .into_iter()
        .filter(|(name, _)| !HOP_BY_HOP.contains(&name.as_str()) && !named.contains(name))
        .collect()
}

/// Reads an HTTP/1 response whose body runs to the end.
fn parse_response(response: &[u8]) -> io::Result<(u16, Vec<Field>, Vec<u8>)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response");
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(invalid)?;
    let head = std::str::from_utf8(&response[..end]).map_err(|_| invalid())?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(invalid)?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(invalid)?;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok((
        status,
        without_hop_by_hop(headers),
        response[end + 4..].to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> Vec<Field> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_response_parses_without_its_connection_headers() {
        let (status, headers, body) = parse_response(
            b"HTTP/1.1 301 Moved\r\nLocation: /x\r\nConnection: close, X-Hop\r\n\
              X-Hop: 1\r\nProxy-Authenticate: Basic\r\nTrailer: X-T\r\n\r\nbody",
        )
        .unwrap();
        assert_eq!(status, 301);
        assert_eq!(headers, fields(&[("location", "/x")]));
        assert_eq!(body, b"body");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(parse_response(b"nonsense\r\n\r\n").is_err());
    }

    /// As Go's reverse proxy: the client's connection headers, those its
    /// `connection` names and its forwarding headers stay behind.
    #[test]
    fn the_clients_connection_and_forwarding_headers_stay_behind() {
        let passed = request_headers(&fields(&[
            (":method", "GET"),
            (":path", "/"),
            ("host", "a"),
            ("content-length", "0"),
            ("accept", "*/*"),
            ("connection", "x-hop"),
            ("x-hop", "1"),
            ("proxy-authorization", "Basic"),
            ("te", "gzip"),
            ("forwarded", "for=1.2.3.4"),
            ("x-forwarded-for", "1.2.3.4"),
            ("x-forwarded-host", "a"),
            ("x-forwarded-proto", "https"),
            ("x-bad", "a\r\nb"),
            ("x-bad:name", "a"),
        ]));
        assert_eq!(passed, fields(&[("accept", "*/*")]));
    }

    fn proxy(url: &str) -> Result<Masquerade> {
        Masquerade::new(MasqueradeOptions::Url(url.into()), dialer(), &roots())
    }

    #[test]
    fn http_and_https_urls_are_proxied() {
        let cases = [
            (
                "http://127.0.0.1:8080/base/",
                "127.0.0.1",
                8080,
                "127.0.0.1:8080",
                "/base",
                false,
            ),
            (
                "http://example.com",
                "example.com",
                80,
                "example.com",
                "",
                false,
            ),
            (
                "https://example.com",
                "example.com",
                443,
                "example.com",
                "",
                true,
            ),
            (
                "https://example.com:443/a",
                "example.com",
                443,
                "example.com",
                "/a",
                true,
            ),
            ("https://[::1]:8443/", "::1", 8443, "[::1]:8443", "", true),
        ];
        for (url, want_host, want_port, want_authority, want_path, https) in cases {
            match proxy(url).unwrap() {
                Masquerade::Proxy {
                    host,
                    port,
                    authority,
                    base_path,
                    rewrite_host,
                    tls,
                    ..
                } => {
                    assert_eq!(
                        (host.as_str(), port, authority.as_str(), base_path.as_str()),
                        (want_host, want_port, want_authority, want_path),
                        "{}",
                        url
                    );
                    assert_eq!(tls.is_some(), https, "{}", url);
                    assert!(!rewrite_host);
                }
                _ => panic!("not a proxy"),
            }
        }
    }

    #[test]
    fn bad_urls_are_refused() {
        for (url, error) in [
            ("https://", "url: empty host"),
            ("https:", "url: empty host"),
            (
                "https://exa mple.com/",
                "url: invalid international domain name",
            ),
            ("https://example.com:65536/", "url: invalid port number"),
            ("https://[::1/", "url: invalid IPv6 address"),
            (
                "file:///var/www",
                "url: only http:// and https:// are supported, not file://",
            ),
            (
                "ftp://example.com",
                "url: only http:// and https:// are supported, not ftp://",
            ),
            ("example.com", "url: relative URL without a base"),
        ] {
            match proxy(url) {
                Ok(_) => panic!("{} is taken", url),
                Err(e) => assert_eq!(e.to_string(), error, "{}", url),
            }
        }
    }

    fn dialer() -> InboundDialer {
        crate::net::InstanceDial::default().default_dialer()
    }

    fn roots() -> TrustRoots {
        let roots = TrustRoots::default();
        roots.set(crate::transport::tls::tests::test_roots());
        roots
    }

    /// The site behind is dialled with the instance's dial defaults, whose
    /// host protects the socket.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_site_behind_is_dialled_with_the_instance_defaults() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (dial, protected) = crate::net::dial::recording::instance();
        let site = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = site.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = site.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.0 204 No Content\r\n\r\n")
                .await
                .unwrap();
        });
        let m = Masquerade::new(
            MasqueradeOptions::Url(format!("http://{}/", addr)),
            dial.default_dialer(),
            &roots(),
        )
        .unwrap();
        let (status, _, _) = m.forward(&[], b"").await.unwrap();
        assert_eq!(status, 204);
        assert_eq!(protected.count(), 1);
    }
}
