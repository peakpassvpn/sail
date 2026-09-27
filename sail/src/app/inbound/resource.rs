//! Snapshot the complete stream pipeline before TLS and authentication:
//! a connection's certificate and users belong to the same generation.
//! Only stateless TCP pipelines can be rebuilt this way. VMess/SS replay
//! caches, QUIC endpoints and REALITY need state-preserving updates instead.

use crate::adapter::*;
use crate::config::Inbound;
use crate::runtime::resource::HotResource;
use crate::session::{Network, Session};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::sync::Arc;

pub(super) struct StreamGeneration {
    handler: AnyInboundHandler,
}

pub(super) type StreamResource = HotResource<StreamGeneration>;

#[cfg(feature = "auto-reload")]
pub(super) fn files(
    inbound: &Inbound,
    env: &crate::runtime::RuntimeEnv,
) -> Vec<std::path::PathBuf> {
    let Some(tls) = inbound.options.get("tls") else {
        return Vec::new();
    };
    if tls.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
        return Vec::new();
    }
    ["certificate_path", "key_path"]
        .into_iter()
        .filter_map(|field| {
            tls.get(field)
                .and_then(|v| v.as_str())
                .map(|path| env.data_path(path).into())
        })
        .collect()
}

pub(super) fn supported(inbound: &Inbound) -> bool {
    matches!(inbound.protocol.as_str(), "trojan" | "vless" | "anytls")
        && inbound
            .options
            .get("transport")
            .and_then(|v| v.get("type"))
            .and_then(|v| v.as_str())
            != Some("quic")
        && inbound
            .options
            .get("tls")
            .and_then(|v| v.get("reality"))
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            != Some(true)
        && inbound
            .options
            .get("multiplex")
            .and_then(|v| v.get("protocol"))
            .and_then(|v| v.as_str())
            != Some("amux")
}

/// Reject unsupported edits rather than reporting a successful no-op.
pub(super) fn check_change(old: &Inbound, new: &Inbound) -> Result<()> {
    let static_part = |inbound: &Inbound| {
        let mut value = inbound.clone();
        if supported(inbound) {
            value.options.remove("users");
            if let Some(tls) = value.options.get_mut("tls").and_then(|v| v.as_object_mut()) {
                for field in ["certificate", "certificate_path", "key", "key_path"] {
                    tls.remove(field);
                }
            }
        }
        value
    };
    if static_part(old) != static_part(new) {
        return Err(anyhow!(
            "[{}] inbound: reload only replaces supported users and TLS certificates; other changes require removing/adding the inbound or a restart",
            old.tag
        ));
    }
    Ok(())
}

pub(super) fn generation(handler: &AnyInboundHandler) -> Result<Arc<StreamGeneration>> {
    if handler.datagram().is_ok() {
        return Err(anyhow!(
            "[{}] inbound: hot resources require a TCP pipeline",
            handler.tag()
        ));
    }
    handler.stream()?;
    Ok(Arc::new(StreamGeneration {
        handler: handler.clone(),
    }))
}

pub(super) fn wrap(handler: &mut AnyInboundHandler) -> Result<StreamResource> {
    let value = generation(handler)?;
    let resource = HotResource::new(StreamGeneration {
        handler: value.handler.clone(),
    });
    *handler = Arc::new(ReloadableInbound {
        tag: handler.tag().clone(),
        resource: resource.clone(),
        stream: Arc::new(ReloadableStream(resource.clone())),
    });
    Ok(resource)
}

struct ReloadableInbound {
    // Socket policy is static, and must not be lost (e.g. TCP Brutal).
    tag: String,
    resource: StreamResource,
    stream: AnyInboundStreamHandler,
}

impl Tag for ReloadableInbound {
    fn tag(&self) -> &String {
        &self.tag
    }
}
impl BaseHandler for ReloadableInbound {}
impl InboundHandler for ReloadableInbound {
    fn stream(&self) -> std::io::Result<&AnyInboundStreamHandler> {
        Ok(&self.stream)
    }
    fn datagram(&self) -> std::io::Result<&AnyInboundDatagramHandler> {
        Err(std::io::Error::other("no udp handler"))
    }
    fn prepare_listener(
        &self,
        socket: socket2::SockRef<'_>,
        network: Network,
    ) -> std::io::Result<()> {
        self.resource
            .load()
            .handler
            .prepare_listener(socket, network)
    }
    fn accepted(&self, socket: socket2::SockRef<'_>, sess: &mut Session) -> std::io::Result<()> {
        self.resource.load().handler.accepted(socket, sess)
    }
}

struct ReloadableStream(StreamResource);
#[async_trait]
impl InboundStreamHandler for ReloadableStream {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let generation = self.0.load();
        generation.handler.stream()?.handle(sess, stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_resources_of_supported_pipelines_may_change() {
        let old: Inbound = serde_json::from_value(json!({
            "type":"trojan", "tag":"t", "listen_port":1234,
            "users":[{"password":"first"}],
            "tls":{"enabled":true,"certificate":"old", "key":"old"}
        }))
        .unwrap();
        let mut new = old.clone();
        new.options.insert("users".into(), json!([]));
        new.options["tls"]["certificate"] = json!("new");
        assert!(check_change(&old, &new).is_ok());
        new.listen_port = Some(4321);
        assert!(check_change(&old, &new).is_err());
        for protocol in ["vmess", "shadowsocks", "hysteria2", "tuic", "tun", "nf"] {
            let mut old = old.clone();
            old.protocol = protocol.into();
            let mut new = old.clone();
            new.options.insert("users".into(), json!([]));
            assert!(!supported(&old));
            assert!(check_change(&old, &new).is_err());
        }
        let mut reality = old.clone();
        reality.options["tls"]["reality"] = json!({"enabled":true});
        assert!(!supported(&reality));
        let mut quic = old;
        quic.options
            .insert("transport".into(), json!({"type":"quic"}));
        assert!(!supported(&quic));
    }

    #[cfg(feature = "inbound-vless")]
    #[tokio::test]
    async fn vless_inflight_handshake_keeps_its_user_generation() {
        use crate::protocol::vless::{
            inbound::{StreamHandler, User},
            request::{encode_request, Flow, COMMAND_TCP},
        };
        use std::collections::HashMap;
        use tokio::io::AsyncWriteExt;
        let handler = |uuid: [u8; 16], name: &str| -> AnyInboundHandler {
            Arc::new(crate::adapter::inbound::Handler::new(
                "v".into(),
                Some(Arc::new(StreamHandler::new(
                    HashMap::from([(
                        uuid,
                        User {
                            name: Some(Arc::from(name)),
                            flow: Flow::None,
                        },
                    )]),
                    None,
                ))),
                None,
            ))
        };
        let mut live = handler([1; 16], "alice");
        let resource = wrap(&mut live).unwrap();
        let (mut client, server) = tokio::io::duplex(256);
        let mut pending = live
            .stream()
            .unwrap()
            .handle(Session::default(), Box::new(server));
        assert!(futures::poll!(&mut pending).is_pending());
        resource.publish(generation(&handler([2; 16], "bob")).unwrap());
        let destination = crate::session::SocksAddr::from(
            "127.0.0.1:80".parse::<std::net::SocketAddr>().unwrap(),
        );
        client
            .write_all(&encode_request(
                &[1; 16],
                Flow::None,
                COMMAND_TCP,
                Some(&destination),
            ))
            .await
            .unwrap();
        match pending.await.unwrap() {
            InboundTransport::Stream(_, session) => {
                assert_eq!(session.user.as_deref(), Some("alice"))
            }
            _ => panic!("expected stream"),
        }
        for (uuid, allowed) in [([1; 16], false), ([2; 16], true)] {
            let (mut client, server) = tokio::io::duplex(256);
            client
                .write_all(&encode_request(
                    &uuid,
                    Flow::None,
                    COMMAND_TCP,
                    Some(&destination),
                ))
                .await
                .unwrap();
            let result = live
                .stream()
                .unwrap()
                .handle(Session::default(), Box::new(server))
                .await;
            assert_eq!(result.is_ok(), allowed);
            if let Ok(InboundTransport::Stream(_, session)) = result {
                assert_eq!(session.user.as_deref(), Some("bob"));
            }
        }
    }

    #[cfg(feature = "inbound-anytls")]
    #[tokio::test]
    async fn anytls_new_sessions_use_the_replaced_users() {
        use crate::protocol::anytls::inbound::StreamHandler;
        use std::collections::HashMap;
        use tokio::io::AsyncWriteExt;
        let handler = |hash| -> AnyInboundHandler {
            Arc::new(crate::adapter::inbound::Handler::new(
                "a".into(),
                Some(Arc::new(StreamHandler::new(
                    HashMap::from([(hash, Some(Arc::from("user")))]),
                    Arc::default(),
                    std::time::Duration::from_secs(1),
                    None,
                ))),
                None,
            ))
        };
        let mut live = handler([1; 32]);
        let resource = wrap(&mut live).unwrap();
        resource.publish(generation(&handler([2; 32])).unwrap());
        for (hash, allowed) in [([1; 32], false), ([2; 32], true)] {
            let (mut client, server) = tokio::io::duplex(256);
            client.write_all(&hash).await.unwrap();
            client.write_all(&[0, 0]).await.unwrap();
            let result = live
                .stream()
                .unwrap()
                .handle(Session::default(), Box::new(server))
                .await;
            assert_eq!(result.is_ok(), allowed);
        }
    }
}
