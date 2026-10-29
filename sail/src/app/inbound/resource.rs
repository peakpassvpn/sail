//! Snapshot the complete stream pipeline before TLS and authentication:
//! a connection's certificate and users belong to the same generation.
//! Stateful protocols publish their own snapshots while retaining listener
//! lifetime replay caches, UDP sessions and QUIC endpoints.

use crate::adapter::*;
use crate::config::Inbound;
use crate::runtime::resource::HotResource;
use crate::session::{Network, Session};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::sync::Arc;

use crate::embed::kinds::HostKinds;

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
    let mut files: Vec<std::path::PathBuf> = ["certificate_path", "key_path"]
        .into_iter()
        .filter_map(|field| {
            tls.get(field)
                .and_then(|v| v.as_str())
                .map(|path| env.data_path(path).into())
        })
        .collect();
    // The CAs clients' certificates are verified by, one path or a list.
    match tls.get("client_certificate_path") {
        Some(serde_json::Value::String(path)) => files.push(env.data_path(path).into()),
        Some(serde_json::Value::Array(paths)) => files.extend(
            paths
                .iter()
                .filter_map(|v| v.as_str())
                .map(|path| env.data_path(path).into()),
        ),
        _ => {}
    }
    files
}

pub(super) fn supported(inbound: &Inbound, kinds: &HostKinds) -> bool {
    if stateful(inbound) {
        return true;
    }
    // A host's kind: its users replaced, it is built again, its listener
    // and connections kept.
    if kinds.inbound_name(&inbound.protocol).is_some() {
        return true;
    }
    matches!(
        inbound.protocol.as_str(),
        "trojan" | "vless" | "anytls" | "vmess" | "socks" | "http" | "mixed"
    ) && inbound
        .options
        .get("transport")
        .and_then(|v| v.get("type"))
        .and_then(|v| v.as_str())
        != Some("quic")
}

/// These protocols retain their socket/endpoint and publish a protocol
/// snapshot at the boundary of a new connection instead of rebuilding it.
pub(super) fn stateful(inbound: &Inbound) -> bool {
    matches!(
        inbound.protocol.as_str(),
        "hysteria2" | "tuic" | "shadowsocks"
    ) || (matches!(inbound.protocol.as_str(), "trojan" | "vless" | "vmess")
        && inbound
            .options
            .get("transport")
            .and_then(|t| t.get("type"))
            .and_then(|v| v.as_str())
            == Some("quic"))
}

/// Reject unsupported edits rather than reporting a successful no-op.
pub(super) fn check_change(old: &Inbound, new: &Inbound, kinds: &HostKinds) -> Result<()> {
    let static_part = |inbound: &Inbound| {
        let mut value = inbound.clone();
        if supported(inbound, kinds) {
            // None vs Some is the SS2022 wire framing (identity headers).
            // Keep that structural distinction; Some([]) is deny-all.
            if inbound.protocol == "shadowsocks" {
                if !inbound
                    .options
                    .get("method")
                    .and_then(|v| v.as_str())
                    .is_some_and(|m| m.starts_with("2022-"))
                {
                    value.options.remove("password");
                }
                if value.options.get("users").is_some_and(|v| v.is_array()) {
                    value.options.insert("users".into(), serde_json::json!([]));
                }
            } else {
                value.options.remove("users");
            }
            if let Some(tls) = value.options.get_mut("tls").and_then(|v| v.as_object_mut()) {
                // The certificate and its key, or one made (`self_signed`, a
                // sail extension), and how clients' certificates are checked:
                // the resources are built again from them.
                for field in [
                    "certificate",
                    "certificate_path",
                    "key",
                    "key_path",
                    "self_signed",
                    "client_authentication",
                    "client_certificate",
                    "client_certificate_path",
                    "client_certificate_public_key_sha256",
                    "client_certificate_sha256",
                ] {
                    tls.remove(field);
                }
                if let Some(reality) = tls.get_mut("reality").and_then(|v| v.as_object_mut()) {
                    reality.remove("private_key");
                    reality.remove("short_id");
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

    #[cfg(all(
        feature = "inbound-socks",
        feature = "inbound-http",
        feature = "inbound-mixed"
    ))]
    #[tokio::test]
    async fn local_proxy_users_reload_without_resetting_association_limits() {
        use crate::adapter::registry;
        use std::collections::HashMap;
        use tokio::io::AsyncWriteExt;
        async fn authenticate(
            handler: &AnyInboundHandler,
            socks: bool,
            password: &str,
        ) -> std::io::Result<()> {
            use base64::Engine;
            let wire = if socks {
                let mut wire = vec![5, 1, 2, 1, 5];
                wire.extend_from_slice(b"alice");
                wire.push(password.len() as u8);
                wire.extend_from_slice(password.as_bytes());
                wire.extend_from_slice(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]);
                wire
            } else {
                let auth =
                    base64::engine::general_purpose::STANDARD.encode(format!("alice:{password}"));
                format!("CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\nProxy-Authorization: Basic {auth}\r\n\r\n").into_bytes()
            };
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(&wire).await?;
            client.shutdown().await?;
            match handler
                .stream()?
                .handle(Session::default(), Box::new(server))
                .await?
            {
                InboundTransport::Stream(_, sess) => {
                    assert_eq!(crate::user::name(&sess.user), Some("alice"));
                    Ok(())
                }
                _ => panic!("expected stream"),
            }
        }
        for protocol in ["http", "socks", "mixed"] {
            let mut states = HashMap::new();
            let build = |password: &str, states: &mut HashMap<_, _>| {
                let config = serde_json::from_value(json!({"type":protocol,"tag":"local","users":[{"username":"alice","password":password}]})).unwrap();
                let mut handlers = HashMap::new();
                registry::build_inbounds(
                    &crate::include::INBOUNDS,
                    &[config],
                    crate::include::LISTENER_INBOUNDS,
                    &Default::default(),
                    &Default::default(),
                    &mut handlers,
                    &mut HashMap::new(),
                    states,
                )
                .unwrap();
                handlers.remove("local").unwrap()
            };
            let mut live = build("old", &mut states);
            let resource = wrap(&mut live).unwrap();
            let associations = states["local"].socks_associations.get().cloned();
            authenticate(&live, protocol != "http", "old")
                .await
                .unwrap();
            resource.publish(generation(&build("new", &mut states)).unwrap());
            assert!(authenticate(&live, protocol != "http", "old")
                .await
                .is_err());
            authenticate(&live, protocol != "http", "new")
                .await
                .unwrap();
            if protocol == "mixed" {
                authenticate(&live, false, "new").await.unwrap();
            }
            if let Some(old) = associations {
                assert!(Arc::ptr_eq(
                    &old,
                    states["local"].socks_associations.get().unwrap()
                ));
            }
        }
    }

    /// The files followed are the certificate's, its key's, and those of
    /// the CAs clients' certificates are verified by, one or a list.
    #[cfg(feature = "auto-reload")]
    #[test]
    fn the_client_ca_files_are_followed_with_the_certificate() {
        let env = crate::runtime::RuntimeEnv::default();
        for (cas, wanted) in [
            (json!("/c/ca.pem"), vec!["/c/ca.pem"]),
            (
                json!(["/c/a.pem", "/c/b.pem"]),
                vec!["/c/a.pem", "/c/b.pem"],
            ),
        ] {
            let inbound: Inbound = serde_json::from_value(json!({
                "type":"trojan", "tag":"t", "listen_port":1234, "users":[],
                "tls":{"enabled":true,"certificate_path":"/c/cert.pem","key_path":"/c/key.pem",
                    "client_certificate_path":cas}
            }))
            .unwrap();
            let mut paths = vec!["/c/cert.pem", "/c/key.pem"];
            paths.extend(wanted);
            assert_eq!(
                files(&inbound, &env),
                paths
                    .into_iter()
                    .map(std::path::PathBuf::from)
                    .collect::<Vec<_>>()
            );
        }
    }

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
        assert!(check_change(&old, &new, &HostKinds::default()).is_ok());
        for (field, value) in [
            ("client_authentication", json!("require-and-verify")),
            ("client_certificate", json!("a CA")),
            ("client_certificate_path", json!(["ca.pem"])),
            ("client_certificate_public_key_sha256", json!(["a pin"])),
            ("client_certificate_sha256", json!(["a pin"])),
            ("self_signed", json!(true)),
        ] {
            let mut new = new.clone();
            new.options["tls"][field] = value;
            assert!(
                check_change(&old, &new, &HostKinds::default()).is_ok(),
                "{}",
                field
            );
        }
        new.listen_port = Some(4321);
        assert!(check_change(&old, &new, &HostKinds::default()).is_err());
        for protocol in ["tun", "nf"] {
            let mut old = old.clone();
            old.protocol = protocol.into();
            let mut new = old.clone();
            new.options.insert("users".into(), json!([]));
            assert!(!supported(&old, &HostKinds::default()));
            assert!(check_change(&old, &new, &HostKinds::default()).is_err());
        }
        let mut reality = old.clone();
        reality.options["tls"]["reality"] = json!({"enabled":true});
        assert!(supported(&reality, &HostKinds::default()));
        let mut quic = old;
        quic.options
            .insert("transport".into(), json!({"type":"quic"}));
        assert!(supported(&quic, &HostKinds::default()));
    }

    /// A self-signed certificate is the inbound's state: a rebuild with the
    /// same `tls` block, as a reload makes in place (here with other
    /// users), serves the same certificate; one for another `server_name`
    /// makes another. Over TCP and over QUIC.
    #[cfg(any(
        all(feature = "inbound-trojan", feature = "inbound-tls"),
        feature = "inbound-hysteria2"
    ))]
    #[tokio::test]
    async fn a_self_signed_certificate_is_kept_while_the_tls_block_stays() {
        use crate::adapter::registry;
        use std::collections::HashMap;
        let protocols = [
            #[cfg(all(feature = "inbound-trojan", feature = "inbound-tls"))]
            "trojan",
            #[cfg(feature = "inbound-hysteria2")]
            "hysteria2",
        ];
        for protocol in protocols {
            let mut states = HashMap::new();
            let mut build = |server_name: &str, password: &str| {
                let config: Inbound = serde_json::from_value(json!({
                    "type": protocol, "tag": "t", "listen_port": 1234,
                    "users": [{"password": password}],
                    "tls": {"enabled": true, "self_signed": true, "server_name": server_name},
                }))
                .unwrap();
                registry::build_inbounds(
                    &crate::include::INBOUNDS,
                    &[config],
                    crate::include::LISTENER_INBOUNDS,
                    &Default::default(),
                    &Default::default(),
                    &mut HashMap::new(),
                    &mut HashMap::new(),
                    &mut states,
                )
                .unwrap();
                states["t"].self_signed.certificate().unwrap()
            };
            let first = build("a.example", "first");
            assert_eq!(build("a.example", "second"), first, "{}", protocol);
            assert_ne!(build("b.example", "second"), first, "{}", protocol);
        }
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
                            name: Some(crate::user::UserRef::unbound(name)),
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
                assert_eq!(crate::user::name(&session.user), Some("alice"))
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
                assert_eq!(crate::user::name(&session.user), Some("bob"));
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
                    HashMap::from([(hash, Some(crate::user::UserRef::unbound("user")))]),
                    Arc::default(),
                    std::time::Duration::from_secs(1),
                    None,
                    Default::default(),
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

    #[cfg(feature = "inbound-vmess")]
    #[tokio::test]
    async fn vmess_generations_share_replay_history_but_not_credentials() {
        use crate::adapter::registry;
        use crate::protocol::vmess::header::*;
        use std::collections::HashMap;
        use tokio::io::AsyncWriteExt;

        fn build(
            tag: &str,
            users: serde_json::Value,
            states: &mut HashMap<String, Arc<registry::InboundState>>,
        ) -> Result<AnyInboundHandler> {
            let inbound = serde_json::from_value(json!({
                "type":"vmess", "tag":tag, "users":users
            }))?;
            let mut handlers = HashMap::new();
            registry::build_inbounds(
                &crate::include::INBOUNDS,
                &[inbound],
                crate::include::LISTENER_INBOUNDS,
                &Default::default(),
                &Default::default(),
                &mut handlers,
                &mut HashMap::new(),
                states,
            )?;
            Ok(handlers.remove(tag).unwrap())
        }
        fn users(id: u8, name: &str) -> serde_json::Value {
            json!([{"uuid":uuid::Uuid::from_bytes([id;16]).to_string(),"name":name}])
        }
        fn wire(id: u8) -> Vec<u8> {
            RequestHeader::new(
                OPTION_CHUNK_STREAM,
                SECURITY_AES128_GCM,
                COMMAND_TCP,
                Some(crate::session::SocksAddr::try_from(("example.com", 443)).unwrap()),
            )
            .seal(&cmd_key(&[id; 16]))
            .unwrap()
        }
        async fn authenticate(handler: &AnyInboundHandler, wire: &[u8]) -> std::io::Result<String> {
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(wire).await?;
            client.shutdown().await?; // A refusal can drain to EOF without random delay.
            match handler
                .stream()?
                .handle(Session::default(), Box::new(server))
                .await?
            {
                InboundTransport::Stream(_, sess) => Ok(sess.user.unwrap().to_string()),
                _ => panic!("expected TCP"),
            }
        }

        let mut states = HashMap::new();
        let mut live = build("v", users(1, "alice"), &mut states).unwrap();
        let resource = wrap(&mut live).unwrap();
        let first = wire(1);
        assert_eq!(authenticate(&live, &first).await.unwrap(), "alice");
        let renamed = build("v", users(1, "renamed"), &mut states).unwrap();
        resource.publish(generation(&renamed).unwrap());
        assert!(authenticate(&live, &first)
            .await
            .unwrap_err()
            .to_string()
            .contains("Replayed"));
        assert_eq!(authenticate(&live, &wire(1)).await.unwrap(), "renamed");

        let (mut client, server) = tokio::io::duplex(4096);
        let mut pending = live
            .stream()
            .unwrap()
            .handle(Session::default(), Box::new(server));
        assert!(futures::poll!(&mut pending).is_pending());
        let bob = build("v", users(2, "bob"), &mut states).unwrap();
        resource.publish(generation(&bob).unwrap());
        let inflight = wire(1);
        client.write_all(&inflight).await.unwrap();
        match pending.await.unwrap() {
            InboundTransport::Stream(_, sess) => {
                assert_eq!(crate::user::name(&sess.user), Some("renamed"))
            }
            _ => panic!("expected TCP"),
        }
        assert!(authenticate(&live, &wire(1))
            .await
            .unwrap_err()
            .to_string()
            .contains("UnknownUser"));
        assert_eq!(authenticate(&live, &wire(2)).await.unwrap(), "bob");
        assert!(build("v", json!([{"uuid":"invalid"}]), &mut states).is_err());
        assert_eq!(authenticate(&live, &wire(2)).await.unwrap(), "bob");

        let empty = build("v", json!([]), &mut states).unwrap();
        resource.publish(generation(&empty).unwrap());
        assert!(authenticate(&live, &wire(2)).await.is_err());
        let restored = build("v", users(1, "returned"), &mut states).unwrap();
        resource.publish(generation(&restored).unwrap());
        for replay in [&first, &inflight] {
            assert!(authenticate(&live, replay)
                .await
                .unwrap_err()
                .to_string()
                .contains("Replayed"));
        }
        assert_eq!(authenticate(&live, &wire(1)).await.unwrap(), "returned");
        let separate = build("other", users(1, "isolated"), &mut states).unwrap();
        assert_eq!(authenticate(&separate, &first).await.unwrap(), "isolated");
    }
}
