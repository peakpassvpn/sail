use std::io;

use anyhow::Result;
use async_trait::async_trait;
use tracing::trace;

use super::super::client::TlsClient;
use super::super::fingerprint::Fingerprint;
use crate::{adapter::*, app::SyncDnsClient, session::Session, transport::vision::VisionState};

pub struct Handler {
    server_name: String,
    client: TlsClient,
    ech: Option<Ech>,
    dns_client: SyncDnsClient,
}

struct Ech {
    /// The configured ECHConfigList, base64; used when DNS has none.
    fixed_config_list: Option<String>,
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
        ech: bool,
        ech_disable_dns_lookup: bool,
        ech_config_list: Option<String>,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        if let Some(list) = ech_config_list.as_deref() {
            decode_ech_config_list(list)?;
        }
        Ok(Handler {
            server_name,
            client: TlsClient::new(&alpns, certificate.as_deref(), insecure, fingerprint)?,
            ech: ech.then_some(Ech {
                fixed_config_list: ech_config_list,
                disable_dns_lookup: ech_disable_dns_lookup,
            }),
            dns_client,
        })
    }

    fn resolve_selected_ech_config_list(
        name: &str,
        fixed_ech_config_list: Option<&str>,
        auto_result: Option<anyhow::Result<String>>,
    ) -> io::Result<Option<String>> {
        match auto_result {
            Some(Ok(value)) => {
                trace!("ech source for {}: https/svcb dns record", name);
                Ok(Some(value))
            }
            Some(Err(err)) => {
                if let Some(fixed) = fixed_ech_config_list {
                    trace!(
                        "auto ech fetch failed for {}, fallback to fixed ech config: {}",
                        name,
                        err
                    );
                    Ok(Some(fixed.to_string()))
                } else {
                    trace!(
                        "auto ech fetch failed for {}, no fixed ech config available: {}",
                        name,
                        err
                    );
                    Err(io::Error::other(format!(
                        "auto ech fetch failed for {}: {}",
                        name, err
                    )))
                }
            }
            None => {
                if fixed_ech_config_list.is_some() {
                    trace!("ech source for {}: fixed ech config", name);
                } else {
                    trace!("ech source for {}: none", name);
                }
                Ok(fixed_ech_config_list.map(str::to_string))
            }
        }
    }

    /// The DNS client's own connections must not look ECH up in DNS.
    fn should_skip_ech_dns_lookup_for_session(sess: &Session) -> bool {
        sess.inbound_tag == "dnsclient"
    }

    /// The ECHConfigList to offer to `name`, if any.
    async fn select_ech_config_list(
        &self,
        name: &str,
        sess: &Session,
    ) -> io::Result<Option<Vec<u8>>> {
        let Some(ech) = &self.ech else {
            return Ok(None);
        };
        let fixed = ech.fixed_config_list.as_deref();
        let selected = if ech.disable_dns_lookup {
            trace!(
                "ech source for {}: fixed-or-none (dns lookup disabled)",
                name
            );
            fixed.map(str::to_string)
        } else if Self::should_skip_ech_dns_lookup_for_session(sess) {
            trace!(
                "ech source for {}: fixed-or-none (dns lookup skipped)",
                name
            );
            fixed.map(str::to_string)
        } else {
            let dns_client = self.dns_client.load_full();
            let auto_result = dns_client.lookup_ech_config_list(name).await;
            Self::resolve_selected_ech_config_list(name, fixed, Some(auto_result))?
        };
        selected
            .map(|list| decode_ech_config_list(&list))
            .transpose()
    }
}

/// An ECHConfigList from base64 or PEM. A lone ECHConfig gets the list's
/// length prefix.
fn decode_ech_config_list(ech_config_list: &str) -> io::Result<Vec<u8>> {
    let base64: String = ech_config_list
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let (list, _) = ensure_ech_config_list_bytes(decode_base64(&base64)?);
    Ok(list)
}

fn ensure_ech_config_list_bytes(mut decoded: Vec<u8>) -> (Vec<u8>, bool) {
    if decoded.len() >= 2 {
        let declared = u16::from_be_bytes([decoded[0], decoded[1]]) as usize;
        if declared == decoded.len().saturating_sub(2) {
            return (decoded, false);
        }
    }

    if decoded.len() >= 4 && decoded[0] == 0xfe && decoded[1] == 0x0d {
        let len = decoded.len();
        if u16::try_from(len).is_ok() {
            let mut wrapped = Vec::with_capacity(len + 2);
            wrapped.extend_from_slice(&(len as u16).to_be_bytes());
            wrapped.append(&mut decoded);
            return (wrapped, true);
        }
    }

    (decoded, false)
}

fn decode_base64(data: &str) -> io::Result<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }

    fn decode_chunk(chunk: &[u8; 4], output: &mut Vec<u8>) -> io::Result<()> {
        if chunk[0] == 64 || chunk[1] == 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            ));
        }
        output.push((chunk[0] << 2) | (chunk[1] >> 4));
        match (chunk[2], chunk[3]) {
            (64, 64) => Ok(()),
            (64, _) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            )),
            (c2, 64) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                Ok(())
            }
            (c2, c3) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                output.push(((c2 & 0x03) << 6) | c3);
                Ok(())
            }
        }
    }

    let mut output = Vec::with_capacity(data.len() * 3 / 4);
    let mut chunk = [0_u8; 4];
    let mut chunk_len = 0_usize;
    let mut seen_padding = false;

    for byte in data.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            seen_padding = true;
            chunk[chunk_len] = 64;
            chunk_len += 1;
        } else if let Some(decoded) = value(byte) {
            if seen_padding {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid base64 padding",
                ));
            }
            chunk[chunk_len] = decoded;
            chunk_len += 1;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 character",
            ));
        }

        if chunk_len == 4 {
            decode_chunk(&chunk, &mut output)?;
            chunk = [0_u8; 4];
            chunk_len = 0;
        }
    }

    match chunk_len {
        0 => Ok(output),
        2 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            Ok(output)
        }
        3 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push(((chunk[1] & 0x0f) << 4) | (chunk[2] >> 2));
            Ok(output)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid base64 length",
        )),
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
        // FIXME check negotiated alpn
        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use crate::app::{dns::DnsClient, SyncDnsClient};
    use crate::session::Session;

    use super::{decode_base64, decode_ech_config_list, ensure_ech_config_list_bytes, Handler};

    fn new_test_dns_client() -> SyncDnsClient {
        let dns = crate::config::Dns::default();
        DnsClient::new(&dns, Default::default(), Default::default())
            .unwrap()
            .into_shared()
    }

    #[test]
    fn test_decode_base64_standard_and_urlsafe() {
        assert_eq!(decode_base64("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_base64("AQI=").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("AQI").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("-_8=").unwrap(), vec![251, 255]);
    }

    #[test]
    fn test_decode_base64_invalid_input() {
        assert!(decode_base64("A").is_err());
        assert!(decode_base64("AA=A").is_err());
        assert!(decode_base64("AA$A").is_err());
    }

    #[test]
    fn test_ensure_ech_config_list_bytes_wrap_single_config() {
        let input = vec![0xfe, 0x0d, 0x00, 0x41];
        let (out, wrapped) = ensure_ech_config_list_bytes(input);
        assert!(wrapped);
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x04);
        assert_eq!(&out[2..], &[0xfe, 0x0d, 0x00, 0x41]);
    }

    #[test]
    fn test_ensure_ech_config_list_bytes_keep_existing_list() {
        let input = vec![0x00, 0x04, 0xfe, 0x0d, 0x00, 0x41];
        let (out, wrapped) = ensure_ech_config_list_bytes(input.clone());
        assert!(!wrapped);
        assert_eq!(out, input);
    }

    #[test]
    fn test_decode_ech_config_list_pem() {
        let pem = "-----BEGIN ECH CONFIGS-----\nAAT+DQBB\n-----END ECH CONFIGS-----";
        assert_eq!(
            decode_ech_config_list(pem).unwrap(),
            vec![0x00, 0x04, 0xfe, 0x0d, 0x00, 0x41]
        );
    }

    #[test]
    fn test_resolve_selected_ech_config_list_auto_success() {
        let result = Handler::resolve_selected_ech_config_list(
            "example.com",
            Some("AQI="),
            Some(Ok("AQID".to_string())),
        )
        .unwrap();
        assert_eq!(result, Some("AQID".to_string()));
    }

    #[test]
    fn test_resolve_selected_ech_config_list_auto_failed_fallback() {
        let result = Handler::resolve_selected_ech_config_list(
            "example.com",
            Some("AQI="),
            Some(Err(anyhow!("dns failed"))),
        )
        .unwrap();
        assert_eq!(result, Some("AQI=".to_string()));
    }

    #[test]
    fn test_resolve_selected_ech_config_list_auto_failed_without_fallback() {
        let err = Handler::resolve_selected_ech_config_list(
            "example.com",
            None,
            Some(Err(anyhow!("dns failed"))),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("auto ech fetch failed for example.com: dns failed"));
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
            true,
            false,
            Some("$$$".to_string()),
            new_test_dns_client(),
        );
        assert!(result.is_err());
    }
}
