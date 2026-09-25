//! What the server answers HTTP/3 requests that are not a good
//! authentication with, so that it looks like a web server to whoever
//! probes it: 404 by default, a fixed response, or whatever an HTTP site
//! behind it answers.

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::super::h3::{self, Field};

/// Request bodies passed on at most.
const MAX_REQUEST_BODY: usize = 1024 * 1024;
/// Responses passed back at most, headers and body.
const MAX_RESPONSE: usize = 8 * 1024 * 1024;
/// How long the site behind may take.
const PROXY_TIMEOUT: Duration = Duration::from_secs(30);

/// Headers that belong to one HTTP/1 connection, not to the message.
const HOP_BY_HOP: [&str; 6] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
];

/// The `masquerade` field, as sing-box takes it: an `http://` URL to proxy
/// to, or an object.
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
        host: String,
        port: u16,
        /// The URL's path, which requested paths are put under.
        base_path: String,
        rewrite_host: bool,
    },
}

impl Masquerade {
    pub fn new(options: MasqueradeOptions) -> Result<Self> {
        match options {
            MasqueradeOptions::Url(url) => Self::proxy(&url, false),
            MasqueradeOptions::Object(MasqueradeObject::Proxy { url, rewrite_host }) => {
                Self::proxy(&url, rewrite_host)
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

    /// A proxy to `url`, which must be `http://`: `https://` and `file://`
    /// are not supported.
    fn proxy(url: &str, rewrite_host: bool) -> Result<Self> {
        let url = url::Url::parse(url).map_err(|e| anyhow!("url: {}", e))?;
        if url.scheme() != "http" {
            return Err(anyhow!(
                "url: only http:// is supported, not {}://",
                url.scheme()
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("url: no host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        Ok(Masquerade::Proxy {
            host,
            port: url.port_or_known_default().unwrap_or(80),
            base_path: url.path().trim_end_matches('/').to_string(),
            rewrite_host,
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

    /// Asks the site behind, over HTTP/1.0 so that the answer comes whole,
    /// ended by the close.
    async fn forward(
        &self,
        fields: &[Field],
        body: &[u8],
    ) -> io::Result<(u16, Vec<Field>, Vec<u8>)> {
        let Masquerade::Proxy {
            host,
            port,
            base_path,
            rewrite_host,
        } = self
        else {
            return Err(io::Error::other("not a proxy"));
        };
        let method = h3::field(fields, ":method").unwrap_or("GET");
        let path = h3::field(fields, ":path").unwrap_or("/");
        let authority = h3::field(fields, ":authority").unwrap_or(host);
        // What goes into the request line must not break out of it.
        if !method.bytes().all(|b| b.is_ascii_alphabetic())
            || path
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(io::Error::other("invalid request line"));
        }
        let host_header = if *rewrite_host || authority.is_empty() {
            if *port == 80 {
                host.clone()
            } else {
                format!("{}:{}", host, port)
            }
        } else {
            authority.to_string()
        };
        let mut request = format!(
            "{} {}{} HTTP/1.0\r\nhost: {}\r\n",
            method, base_path, path, host_header
        );
        for (name, value) in fields {
            if name.starts_with(':')
                || name == "host"
                || name == "content-length"
                || HOP_BY_HOP.contains(&name.as_str())
                || value.contains(['\r', '\n'])
            {
                continue;
            }
            request.push_str(&format!("{}: {}\r\n", name, value));
        }
        request.push_str(&format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        ));

        let mut upstream = tokio::net::TcpStream::connect((host.as_str(), *port)).await?;
        upstream.write_all(request.as_bytes()).await?;
        upstream.write_all(body).await?;
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
        let name = name.trim().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        headers.push((name, value.trim().to_string()));
    }
    Ok((status, headers, response[end + 4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_parses_without_its_connection_headers() {
        let (status, headers, body) =
            parse_response(b"HTTP/1.1 301 Moved\r\nLocation: /x\r\nConnection: close\r\n\r\nbody")
                .unwrap();
        assert_eq!(status, 301);
        assert_eq!(headers, vec![("location".to_string(), "/x".to_string())]);
        assert_eq!(body, b"body");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(parse_response(b"nonsense\r\n\r\n").is_err());
    }

    #[test]
    fn only_http_urls_are_proxied() {
        let m =
            Masquerade::new(MasqueradeOptions::Url("http://127.0.0.1:8080/base/".into())).unwrap();
        match m {
            Masquerade::Proxy {
                host,
                port,
                base_path,
                rewrite_host,
            } => {
                assert_eq!(
                    (host.as_str(), port, base_path.as_str()),
                    ("127.0.0.1", 8080, "/base")
                );
                assert!(!rewrite_host);
            }
            _ => panic!("not a proxy"),
        }
        assert!(Masquerade::new(MasqueradeOptions::Url("https://example.com".into())).is_err());
        assert!(Masquerade::new(MasqueradeOptions::Url("file:///var/www".into())).is_err());
    }
}
