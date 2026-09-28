//! Resource rotation on the same live QUIC endpoint, without external servers.
#![cfg(all(
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
    feature = "inbound-tuic",
    feature = "outbound-tuic",
    feature = "inbound-trojan",
    feature = "outbound-trojan",
    feature = "inbound-quic",
    feature = "outbound-quic",
    feature = "inbound-amux",
    feature = "outbound-amux",
    feature = "outbound-direct"
))]
use crate::common;

use anyhow::{ensure, Result};
use sail::adapter::{AnyOutboundHandler, AnyStream};
use sail::app::instance::Instance;
use sail::session::{Session, SocksAddr};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "90ee4432-671e-4ec8-8512-15d5fd0f8eab";

struct Running(Vec<sail::RuntimeId>);
impl Drop for Running {
    fn drop(&mut self) {
        for id in &self.0 {
            sail::shutdown(*id);
        }
    }
}

fn inbound(protocol: &str, port: u16, password: &str, cert: &str, key: &str) -> Value {
    let mut user = json!({"name":password,"password":password});
    if protocol == "tuic" {
        user["uuid"] = json!(UUID);
    }
    let wire_protocol = if protocol.starts_with("trojan-") {
        "trojan"
    } else {
        protocol
    };
    let mut inbound = json!({"type":wire_protocol,"tag":"server","listen":"127.0.0.1","listen_port":port,
        "users":[user],"tls":{"enabled":true,"alpn":["h3"],"certificate":cert,"key":key}});
    if protocol == "trojan-quic" {
        inbound["transport"] = json!({"type":"quic"});
    }
    if protocol == "trojan-amux" {
        inbound["multiplex"] = json!({"enabled":true,"protocol":"amux"});
    }
    inbound
}

fn client(
    protocol: &str,
    port: u16,
    password: &str,
    cert: &str,
) -> Result<(Instance, AnyOutboundHandler)> {
    let wire_protocol = if protocol.starts_with("trojan-") {
        "trojan"
    } else {
        protocol
    };
    let mut outbound = json!({"type":wire_protocol,"tag":"proxy","server":"127.0.0.1",
        "server_port":port,"password":password,
        "tls":{"enabled":true,"server_name":"localhost","alpn":["h3"],"certificate":cert}});
    if protocol == "tuic" {
        outbound["uuid"] = json!(UUID);
    }
    if protocol == "trojan-quic" {
        outbound["transport"] = json!({"type":"quic"});
    }
    if protocol == "trojan-amux" {
        outbound["multiplex"] =
            json!({"enabled":true,"protocol":"amux","max_accepts":1024,"concurrency":64});
    }
    let config = sail::config::from_string(&json!({"outbounds":[outbound]}).to_string())?;
    let instance = Instance::build(&config, Arc::default(), Arc::default())?;
    let handler = instance.outbound_manager.load().get("proxy").unwrap();
    Ok((instance, handler))
}

async fn open(handler: &AnyOutboundHandler, address: SocketAddr) -> Result<AnyStream> {
    let sess = Session {
        destination: SocksAddr::from(address),
        ..Default::default()
    };
    Ok(tokio::time::timeout(
        Duration::from_secs(5),
        handler.stream()?.handle(&sess, None, None),
    )
    .await??)
}

async fn ping(stream: &mut AnyStream) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        stream.write_all(b"live").await?;
        stream.flush().await?;
        let mut echo = [0; 4];
        stream.read_exact(&mut echo).await?;
        ensure!(&echo == b"live", "echo mismatch");
        anyhow::Ok(())
    })
    .await?
}

async fn udp_ping(
    recv: &mut dyn sail::adapter::OutboundDatagramRecvHalf,
    send: &mut dyn sail::adapter::OutboundDatagramSendHalf,
    address: SocketAddr,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        send.send_to(b"udp-live", &SocksAddr::from(address)).await?;
        let mut buf = [0; 64];
        let (n, _) = recv.recv_from(&mut buf).await?;
        ensure!(&buf[..n] == b"udp-live", "UDP echo mismatch");
        anyhow::Ok(())
    })
    .await?
}

#[test]
fn quic_users_and_certificates_rotate_without_disconnecting_sessions() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    for protocol in ["hysteria2", "tuic", "trojan-quic", "trojan-amux"] {
        let [port] = common::free_ports();
        let first = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let second = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let old = inbound(
            protocol,
            port,
            "alice",
            &first.cert.pem(),
            &first.key_pair.serialize_pem(),
        );
        let new = inbound(
            protocol,
            port,
            "bob",
            &second.cert.pem(),
            &second.key_pair.serialize_pem(),
        );
        let config = json!({"inbounds":[old],"outbounds":[{"type":"direct"}]}).to_string();
        let running = Running(common::run_sail_instances(&rt, vec![config])?);
        let manager = sail::runtime_managers().get(&running.0[0]).unwrap().clone();
        rt.block_on(async {
            let (address, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_task = tokio::spawn(echo);
            let (udp_address, udp_echo) = common::run_udp_echo_server("127.0.0.1:0").await?;
            let udp_echo_task = tokio::spawn(udp_echo);
            let (_old_client, old_handler) = client(protocol, port, "alice", &first.cert.pem())?;
            let mut old_stream = open(&old_handler, address).await?;
            ping(&mut old_stream).await?;
            let sess = Session {
                destination: SocksAddr::from(udp_address),
                ..Default::default()
            };
            let datagram = old_handler.datagram()?.handle(&sess, None).await?;
            let (mut recv, mut send) = datagram.split();
            udp_ping(&mut *recv, &mut *send, udp_address).await?;

            // A bad certificate/key pair must not publish the replacement users.
            let mut invalid = new.clone();
            invalid["tls"]["key"] = json!(first.key_pair.serialize_pem());
            ensure!(manager
                .update_inbound_resources(serde_json::from_value(invalid)?)
                .await
                .is_err());
            let (_fresh_old, fresh_old) = client(protocol, port, "alice", &first.cert.pem())?;
            ping(&mut open(&fresh_old, address).await?).await?;

            manager
                .update_inbound_resources(serde_json::from_value(new.clone())?)
                .await?;
            ping(&mut old_stream).await?;
            udp_ping(&mut *recv, &mut *send, udp_address).await?;
            // More streams on an already authenticated connection retain its generation.
            ping(&mut open(&old_handler, address).await?).await?;
            let (_new_client, new_handler) = client(protocol, port, "bob", &second.cert.pem())?;
            ping(&mut open(&new_handler, address).await?).await?;

            let (_wrong_cert_client, wrong_cert) =
                client(protocol, port, "bob", &first.cert.pem())?;
            ensure!(
                open(&wrong_cert, address).await.is_err(),
                "old certificate still trusted"
            );
            let (_removed_client, removed) = client(protocol, port, "alice", &second.cert.pem())?;
            // TUIC's connect writes before auth completes; an echo, not only open(),
            // is the proof of authentication for both protocols.
            let removed_result = async { ping(&mut open(&removed, address).await?).await }.await;
            ensure!(
                removed_result.is_err(),
                "removed credentials accepted: {protocol}"
            );

            let mut empty = new.clone();
            empty["users"] = json!([]);
            manager
                .update_inbound_resources(serde_json::from_value(empty)?)
                .await?;
            ping(&mut old_stream).await?;
            let (_denied_client, denied) = client(protocol, port, "bob", &second.cert.pem())?;
            ensure!(async { ping(&mut open(&denied, address).await?).await }
                .await
                .is_err());
            manager
                .update_inbound_resources(serde_json::from_value(new.clone())?)
                .await?;
            let (_restored_client, restored) = client(protocol, port, "bob", &second.cert.pem())?;
            ping(&mut open(&restored, address).await?).await?;
            echo_task.abort();
            udp_echo_task.abort();
            anyhow::Ok(())
        })?;
        common::shutdown_instances(&rt, running.0.clone());
    }
    Ok(())
}

#[cfg(all(feature = "inbound-shadowsocks", feature = "outbound-shadowsocks"))]
#[test]
fn ss2022_users_reload_on_live_tcp_and_udp_listeners() -> Result<()> {
    shadowsocks_reload(false)?;
    shadowsocks_reload(true)
}

#[cfg(all(feature = "inbound-shadowsocks", feature = "outbound-shadowsocks"))]
fn shadowsocks_reload(legacy: bool) -> Result<()> {
    use base64::Engine;
    use sail::adapter::OutboundTransport;
    async fn connect(
        handler: &AnyOutboundHandler,
        port: u16,
        address: SocketAddr,
    ) -> Result<AnyStream> {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        let sess = Session {
            destination: SocksAddr::from(address),
            ..Default::default()
        };
        Ok(handler
            .stream()?
            .handle(&sess, None, Some(Box::new(tcp)))
            .await?)
    }
    let psk = |byte| base64::engine::general_purpose::STANDARD.encode([byte; 16]);
    let identity = psk(1);
    let alice = psk(2);
    let bob = psk(3);
    let port = common::free_port();
    let method = if legacy {
        "aes-128-gcm"
    } else {
        "2022-blake3-aes-128-gcm"
    };
    let inbound = |users: Value| {
        if legacy {
            return json!({"type":"shadowsocks","tag":"ss","listen":"127.0.0.1","listen_port":port,
            "method":method,"password":users[0]["password"]});
        }
        json!({"type":"shadowsocks","tag":"ss","listen":"127.0.0.1","listen_port":port,
        "method":"2022-blake3-aes-128-gcm","password":identity,"users":users})
    };
    let old = inbound(json!([{"name":"alice","password":alice}]));
    let new = inbound(json!([{"name":"bob","password":bob}]));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let running = Running(common::run_sail_instances(
        &rt,
        vec![json!({"inbounds":[old],"outbounds":[{"type":"direct"}]}).to_string()],
    )?);
    let result = rt.block_on(async {
        let manager = sail::runtime_managers().get(&running.0[0]).unwrap().clone();
        let client = |password: &str| -> Result<(Instance, AnyOutboundHandler)> {
            let config = sail::config::from_string(
                &json!({"outbounds":[{"type":"shadowsocks","tag":"proxy",
                "server":"127.0.0.1","server_port":port,"method":method,
                "password":if legacy {password.to_owned()} else {format!("{identity}:{password}")}}]})
                .to_string(),
            )?;
            let instance = Instance::build(&config, Arc::default(), Arc::default())?;
            let handler = instance.outbound_manager.load().get("proxy").unwrap();
            Ok((instance, handler))
        };
        let (address, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        let echo = tokio::spawn(echo);
        let (udp_address, udp_echo) = common::run_udp_echo_server("127.0.0.1:0").await?;
        let udp_echo = tokio::spawn(udp_echo);
        let (_old, old) = client(&alice)?;
        let mut stream = connect(&old, port, address).await?;
        ping(&mut stream).await?;
        let sess = Session {
            destination: SocksAddr::from(udp_address),
            ..Default::default()
        };
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let udp = old
            .datagram()?
            .handle(
                &sess,
                Some(OutboundTransport::Datagram(Box::new(
                    sail::net::StdOutboundDatagram::new(socket),
                ))),
            )
            .await?;
        let (mut recv, mut send) = udp.split();
        udp_ping(&mut *recv, &mut *send, udp_address).await?;
        let mut invalid = new.clone();
        if legacy { invalid["password"] = json!(12); }
        else { invalid["users"][0]["password"] = json!("invalid"); }
        ensure!(manager
            .update_inbound_resources(serde_json::from_value(invalid)?)
            .await
            .is_err());
        ping(&mut connect(&old, port, address).await?).await?;
        manager
            .update_inbound_resources(serde_json::from_value(new.clone())?)
            .await?;
        ping(&mut stream).await?;
        udp_ping(&mut *recv, &mut *send, udp_address).await?;
        ensure!(
            async { ping(&mut connect(&old, port, address).await?).await }
                .await
                .is_err()
        );
        let (_new, fresh) = client(&bob)?;
        ping(&mut connect(&fresh, port, address).await?).await?;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let new_udp = fresh.datagram()?.handle(&sess, Some(OutboundTransport::Datagram(Box::new(sail::net::StdOutboundDatagram::new(socket))))).await?;
        let (mut new_recv, mut new_send) = new_udp.split();
        udp_ping(&mut *new_recv, &mut *new_send, udp_address).await?;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let denied_udp = old.datagram()?.handle(&sess, Some(OutboundTransport::Datagram(Box::new(sail::net::StdOutboundDatagram::new(socket))))).await?;
        let (mut denied_recv, mut denied_send) = denied_udp.split();
        ensure!(udp_ping(&mut *denied_recv, &mut *denied_send, udp_address).await.is_err());
        if !legacy {
        manager
            .update_inbound_resources(serde_json::from_value(inbound(json!([])))?)
            .await?;
        ping(&mut stream).await?;
        udp_ping(&mut *recv, &mut *send, udp_address).await?;
        ensure!(
            async { ping(&mut connect(&fresh, port, address).await?).await }
                .await
                .is_err()
        );
        manager
            .update_inbound_resources(serde_json::from_value(new)?)
            .await?;
        ping(&mut connect(&fresh, port, address).await?).await?;
        }
        echo.abort();
        udp_echo.abort();
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, running.0.clone());
    result
}
