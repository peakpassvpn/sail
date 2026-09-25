use std::time::Duration;

use anyhow::anyhow;
use tokio::time::Instant;

use crate::{
    adapter::AnyOutboundHandler,
    app::SyncDnsClient,
    session::{Session, SocksAddr},
};

pub async fn tcp(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> anyhow::Result<Duration> {
    let sess = Session {
        destination: SocksAddr::Domain("healthcheck.sail".to_string(), 80),
        new_conn_once: true,
        ..Default::default()
    };
    let start = Instant::now();
    let stream = crate::net::connect_stream_outbound(&sess, dns_client, &handler).await?;
    let mut stream = handler.stream()?.handle(&sess, None, stream).await?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"PING").await?;
    let mut buf = Vec::with_capacity(4);
    let n = stream.read_buf(&mut buf).await?;
    if n == 0 {
        Err(anyhow!(
            "EOF during TCP health check for [{}]",
            handler.tag()
        ))
    } else if buf == b"PONG" {
        Ok(Instant::now().duration_since(start))
    } else {
        Err(anyhow!(
            "Unexpected TCP health check response from [{}]: {}",
            handler.tag(),
            String::from_utf8_lossy(&buf)
        ))
    }
}

pub async fn udp(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> anyhow::Result<Duration> {
    let addr = SocksAddr::Domain("healthcheck.sail".to_string(), 80);
    let sess = Session {
        destination: addr.clone(),
        new_conn_once: true,
        ..Default::default()
    };
    let start = Instant::now();
    let dgram = crate::net::connect_datagram_outbound(&sess, dns_client, &handler).await?;
    let dgram = handler.datagram()?.handle(&sess, dgram).await?;
    let (mut recv, mut send) = dgram.split();
    send.send_to(b"PING", &addr).await?;
    let mut buf = [0u8; 2 * 1024];
    let (n, _src_addr) = recv.recv_from(&mut buf).await?;
    if &buf[..n] == b"PONG" {
        Ok(Instant::now().duration_since(start))
    } else {
        Err(anyhow!(
            "Unexpected UDP health check response from [{}]",
            handler.tag()
        ))
    }
}

/// An HTTP request made through an outbound to measure it, as sing-box's
/// URL tests do: the latency is the time to the response's status line,
/// connecting and any TLS handshake included.
pub struct HttpProbe {
    destination: SocksAddr,
    /// The `Host` header: the URL's authority.
    host: String,
    /// The path and query.
    path: String,
    #[cfg(feature = "tls")]
    tls: Option<crate::transport::tls::outbound::StreamHandler>,
}

impl HttpProbe {
    /// A probe of `url`, `http://` or `https://`.
    pub fn new(url: &str, dns_client: SyncDnsClient) -> anyhow::Result<Self> {
        let invalid = |why: &str| anyhow!("invalid URL \"{}\": {}", url, why);
        let (https, rest) = if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else {
            return Err(invalid("expected http:// or https://"));
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) if rest[i..].starts_with('/') => (&rest[..i], rest[i..].to_string()),
            Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
            None => (rest, "/".to_string()),
        };
        if authority.contains('@') {
            return Err(invalid("credentials are not supported"));
        }
        let default_port = if https { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (ip, after) = v6.split_once(']').ok_or_else(|| invalid("unclosed ["))?;
            let port = match after.strip_prefix(':') {
                Some(port) => Some(port),
                None if after.is_empty() => None,
                None => return Err(invalid("bad port")),
            };
            (ip, port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        let port = match port {
            Some(port) => port.parse::<u16>().map_err(|_| invalid("bad port"))?,
            None => default_port,
        };
        if host.is_empty() {
            return Err(invalid("no host"));
        }
        let destination = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => SocksAddr::Ip(std::net::SocketAddr::new(ip, port)),
            Err(_) => SocksAddr::Domain(host.to_string(), port),
        };
        #[cfg(feature = "tls")]
        let tls = if https {
            Some(crate::transport::tls::outbound::StreamHandler::new(
                host.to_string(),
                vec!["http/1.1".to_string()],
                None,
                false,
                None,
                false,
                false,
                None,
                dns_client,
            )?)
        } else {
            None
        };
        #[cfg(not(feature = "tls"))]
        {
            let _ = dns_client;
            if https {
                return Err(invalid("https needs a build with TLS"));
            }
        }
        Ok(Self {
            destination,
            host: authority.to_string(),
            path,
            #[cfg(feature = "tls")]
            tls,
        })
    }

    /// The time the request through `handler` took to be answered.
    pub async fn run(
        &self,
        dns_client: SyncDnsClient,
        handler: &AnyOutboundHandler,
    ) -> anyhow::Result<Duration> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let sess = Session {
            destination: self.destination.clone(),
            new_conn_once: true,
            ..Default::default()
        };
        let start = Instant::now();
        let stream = crate::net::connect_stream_outbound(&sess, dns_client, handler).await?;
        let stream = handler.stream()?.handle(&sess, None, stream).await?;
        #[cfg(feature = "tls")]
        let mut stream = match &self.tls {
            Some(tls) => {
                use crate::adapter::OutboundStreamHandler;
                tls.handle(&sess, None, Some(stream)).await?
            }
            None => stream,
        };
        #[cfg(not(feature = "tls"))]
        let mut stream = stream;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: sail\r\nConnection: close\r\n\r\n",
            self.path, self.host
        );
        stream.write_all(request.as_bytes()).await?;
        // The status line is enough: the rest of the response says nothing
        // more about the path to the server.
        let mut buf = Vec::with_capacity(64);
        let mut chunk = [0u8; 64];
        while !buf.contains(&b'\n') {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(anyhow!(
                    "EOF before an HTTP response through [{}]",
                    handler.tag()
                ));
            }
            if buf.len() > 1024 {
                return Err(anyhow!("no HTTP response through [{}]", handler.tag()));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let elapsed = Instant::now().duration_since(start);
        let _ = stream.shutdown().await;
        let status = buf
            .strip_prefix(b"HTTP/1.")
            .and_then(|rest| rest.get(1..5))
            .filter(|code| code[0] == b' ' && code[1..].iter().all(u8::is_ascii_digit));
        if status.is_none() {
            return Err(anyhow!(
                "not an HTTP response through [{}]: {}",
                handler.tag(),
                String::from_utf8_lossy(&buf[..buf.len().min(32)])
            ));
        }
        Ok(elapsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns() -> SyncDnsClient {
        crate::app::dns_client::DnsClient::new(
            &Default::default(),
            std::sync::Arc::new(crate::net::DialOptions::default()),
            Default::default(),
        )
        .unwrap()
        .into_shared()
    }

    #[test]
    fn a_url_is_split_into_what_the_request_needs() {
        let p = HttpProbe::new("http://example.com/generate_204", dns()).unwrap();
        assert_eq!(p.destination, SocksAddr::Domain("example.com".into(), 80));
        assert_eq!(
            (p.host.as_str(), p.path.as_str()),
            ("example.com", "/generate_204")
        );

        let p = HttpProbe::new("http://127.0.0.1:8080", dns()).unwrap();
        assert_eq!(
            p.destination,
            SocksAddr::Ip("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!((p.host.as_str(), p.path.as_str()), ("127.0.0.1:8080", "/"));

        let p = HttpProbe::new("http://[::1]:81?x=1", dns()).unwrap();
        assert_eq!(p.destination, SocksAddr::Ip("[::1]:81".parse().unwrap()));
        assert_eq!(p.path, "/?x=1");
    }

    #[test]
    fn a_bad_url_is_an_error() {
        for url in [
            "ftp://x/",
            "http://",
            "http://x:port/",
            "http://u@x/",
            "http://[::1/",
        ] {
            assert!(HttpProbe::new(url, dns()).is_err(), "{}", url);
        }
    }
}
