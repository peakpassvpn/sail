use std::io;

use anyhow::Result;
use async_trait::async_trait;
use tracing::trace;

use super::super::client::{Identity, TlsClient};
use super::super::ech::decode_ech_config_list;
use super::super::fingerprint::Fingerprint;
use super::super::options::ClientOptions;
use crate::{adapter::*, app::SyncDnsClient, session::Session, transport::vision::VisionState};

pub struct Handler {
    server_name: String,
    client: TlsClient,
    ech: Option<Ech>,
    dns_client: SyncDnsClient,
}

struct Ech {
    /// The configured ECHConfigList: when set, the only one offered.
    config_list: Option<Vec<u8>>,
    disable_dns_lookup: bool,
}

impl Handler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_name: String,
        alpns: Vec<String>,
        certificate: Option<String>,
        insecure: bool,
        fingerprint: Option<Fingerprint>,
        disable_sni: bool,
        identity: Option<&Identity>,
        ech: bool,
        ech_disable_dns_lookup: bool,
        ech_config_list: Option<String>,
        dns_client: SyncDnsClient,
        roots: &crate::transport::tls::roots::Roots,
        options: &ClientOptions,
    ) -> Result<Self> {
        let ech_config_list = ech_config_list
            .as_deref()
            .map(decode_ech_config_list)
            .transpose()?;
        let mut client = TlsClient::with_options(
            &alpns,
            certificate.as_deref(),
            insecure,
            fingerprint,
            roots,
            identity,
            options,
        )?;
        if disable_sni {
            client = client.without_sni();
        }
        Ok(Handler {
            server_name,
            client,
            ech: ech.then_some(Ech {
                config_list: ech_config_list,
                disable_dns_lookup: ech_disable_dns_lookup,
            }),
            dns_client,
        })
    }

    /// The DNS client's own connections must not look ECH up in DNS.
    fn should_skip_ech_dns_lookup_for_session(sess: &Session) -> bool {
        sess.inbound_tag == "dnsclient"
    }

    /// The ECHConfigList to offer to `name`, if any. As in sing-box, a
    /// configured one is used as it is, and DNS is asked only without one
    /// (its common/tls/ech.go, parseECHClientConfig): no HTTPS record to
    /// override it, nor any query to give the name away. What DNS fails to
    /// give fails the connection, as there.
    async fn select_ech_config_list(
        &self,
        name: &str,
        sess: &Session,
    ) -> io::Result<Option<Vec<u8>>> {
        let Some(ech) = &self.ech else {
            return Ok(None);
        };
        if let Some(list) = &ech.config_list {
            trace!("ech source for {}: the configured one", name);
            return Ok(Some(list.clone()));
        }
        if ech.disable_dns_lookup || Self::should_skip_ech_dns_lookup_for_session(sess) {
            trace!("ech source for {}: none (no dns lookup)", name);
            return Ok(None);
        }
        let dns_client = self.dns_client.load_full();
        let list = dns_client
            .lookup_ech_config_list(name)
            .await
            .map_err(|e| io::Error::other(format!("ech fetch failed for {}: {}", name, e)))?;
        trace!("ech source for {}: https/svcb dns record", name);
        decode_ech_config_list(&list).map(Some)
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
        trace!("handling outbound stream");
        let stream = stream.ok_or_else(|| io::Error::other("invalid tls input"))?;
        let name = if !self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        let ech_config_list = self.select_ech_config_list(&name, sess).await?;
        trace!(
            "handling TLS {}, ech_enabled={}, ech_config_selected={}",
            &name,
            self.ech.is_some(),
            ech_config_list.is_some()
        );
        let tls_stream = self
            .client
            .connect(
                &name,
                stream,
                Some(VisionState::of(sess)),
                ech_config_list.as_deref(),
            )
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("connect tls failed: {}", e),
                )
            })?;
        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use crate::app::{dns::DnsClient, SyncDnsClient};
    use crate::session::Session;

    use super::Handler;

    fn new_test_dns_client() -> SyncDnsClient {
        let dns = crate::config::Dns::default();
        DnsClient::new(&dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared()
    }

    /// A UDP DNS server answering every query NXDOMAIN, and the queries it
    /// has had.
    async fn counting_server() -> (u16, Arc<AtomicUsize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let queries = Arc::new(AtomicUsize::new(0));
        let counted = queries.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                counted.fetch_add(1, Ordering::SeqCst);
                // The query, as a response with NXDOMAIN.
                let mut reply = buf[..n].to_vec();
                reply[2] |= 0x80;
                reply[3] = (reply[3] & 0xf0) | 3;
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        (port, queries)
    }

    fn ech_handler(port: u16, ech_config: Option<&str>, disable_dns_lookup: bool) -> Handler {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": { "timeout": "2s", "servers": [
                { "type": "udp", "tag": "u", "server": "127.0.0.1", "server_port": port },
            ] } })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        Handler::new(
            "example.com".to_string(),
            vec![],
            None,
            false,
            None,
            false,
            None,
            true,
            disable_dns_lookup,
            ech_config.map(str::to_string),
            dns,
            &crate::transport::tls::tests::test_roots(),
            &Default::default(),
        )
        .unwrap()
    }

    /// As in sing-box, a configured ECHConfigList is the one offered, and
    /// DNS is not asked for another.
    #[tokio::test]
    async fn a_configured_ech_config_is_used_without_asking_dns() {
        let (port, queries) = counting_server().await;
        let handler = ech_handler(port, Some("AAT+DQBB"), false);
        let list = handler
            .select_ech_config_list("example.com", &Session::default())
            .await
            .unwrap();
        assert_eq!(list, Some(vec![0x00, 0x04, 0xfe, 0x0d, 0x00, 0x41]));
        assert_eq!(queries.load(Ordering::SeqCst), 0, "DNS was asked");
    }

    /// Without one, DNS is asked, and a failed lookup fails the connection,
    /// as in sing-box, rather than going without ECH.
    #[tokio::test]
    async fn without_a_configured_ech_config_a_failed_lookup_fails() {
        let (port, queries) = counting_server().await;
        let handler = ech_handler(port, None, false);
        let err = handler
            .select_ech_config_list("example.com", &Session::default())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("ech fetch failed for example.com"),
            "{}",
            err
        );
        assert!(queries.load(Ordering::SeqCst) > 0);
    }

    /// `disable_dns_lookup` keeps DNS out of it.
    #[tokio::test]
    async fn with_the_dns_lookup_disabled_dns_is_not_asked() {
        let (port, queries) = counting_server().await;
        let handler = ech_handler(port, None, true);
        let list = handler
            .select_ech_config_list("example.com", &Session::default())
            .await
            .unwrap();
        assert_eq!(list, None);
        assert_eq!(queries.load(Ordering::SeqCst), 0, "DNS was asked");
    }

    #[test]
    fn test_should_skip_ech_dns_lookup_for_dnsclient_session() {
        let sess = |tag: &str| Session {
            inbound_tag: tag.to_string(),
            ..Default::default()
        };
        assert!(Handler::should_skip_ech_dns_lookup_for_session(&sess(
            "dnsclient"
        )));
        assert!(!Handler::should_skip_ech_dns_lookup_for_session(&sess(
            "socks"
        )));
    }

    #[test]
    fn test_new_with_invalid_ech_config_list_fails() {
        let result = Handler::new(
            "localhost".to_string(),
            vec![],
            None,
            false,
            None,
            false,
            None,
            true,
            false,
            Some("$$$".to_string()),
            new_test_dns_client(),
            &crate::transport::tls::tests::test_roots(),
            &Default::default(),
        );
        assert!(result.is_err());
    }
}
