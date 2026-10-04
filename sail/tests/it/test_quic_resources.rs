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
#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use anyhow::{ensure, Result};
use sail::adapter::{AnyOutboundHandler, AnyStream};
use sail::app::instance::Instance;
use sail::session::{Session, SocksAddr};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "90ee4432-671e-4ec8-8512-15d5fd0f8eab";
/// The TUIC UUID of the user every configuration keeps.
const KEEPER_UUID: &str = "5b0e7c8a-2f4d-4c1e-9a3b-7d6e8f9a0b1c";

fn uuid(password: &str) -> &'static str {
    match password {
        "keeper" => KEEPER_UUID,
        _ => UUID,
    }
}

struct Running(Vec<sail::RuntimeId>);
impl Drop for Running {
    fn drop(&mut self) {
        for id in &self.0 {
            sail::shutdown(*id);
        }
    }
}

/// The inbound, with a user named for each of `passwords`.
fn inbound(protocol: &str, port: u16, passwords: &[&str], cert: &str, key: &str) -> Value {
    let users: Vec<Value> = passwords
        .iter()
        .map(|password| {
            let mut user = json!({"name":password,"password":password});
            if protocol == "tuic" {
                user["uuid"] = json!(uuid(password));
            }
            user
        })
        .collect();
    let wire_protocol = if protocol.starts_with("trojan-") {
        "trojan"
    } else {
        protocol
    };
    let mut inbound = json!({"type":wire_protocol,"tag":"server","listen":"127.0.0.1","listen_port":port,
        "users":users,"tls":{"enabled":true,"alpn":["h3"],"certificate":cert,"key":key}});
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
        outbound["uuid"] = json!(uuid(password));
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

/// How long an accepted stream or datagram may take to echo.
const ECHOED_WITHIN: Duration = Duration::from_secs(3);
/// How long silence takes, at least, to count as a refusal. A refused
/// stream or datagram gets no echo, and a refusal is often silence (a
/// server that does not tell a prober it failed, a datagram dropped); an
/// accepted one echoes over loopback within milliseconds.
const REFUSED_AFTER: Duration = Duration::from_millis(500);

/// The slowest echo an accepted stream or datagram gave in these tests:
/// what calibrates the refusal window, so that a refusal is told from a
/// slow acceptance on any host.
static SLOWEST_ECHO: std::sync::Mutex<Duration> = std::sync::Mutex::new(Duration::ZERO);

/// How long silence takes to count as a refusal: `REFUSED_AFTER`, or ten
/// times the slowest accepted echo, whichever is longer. A forbidden user
/// answered as slowly as an allowed one is never taken for refused.
fn refusal_window() -> Duration {
    let slowest = *SLOWEST_ECHO.lock().unwrap_or_else(|e| e.into_inner());
    REFUSED_AFTER.max(slowest * 10)
}

/// Keeps `elapsed`, an accepted echo's, for the refusal window.
fn echoed_in(elapsed: Duration) {
    let mut slowest = SLOWEST_ECHO.lock().unwrap_or_else(|e| e.into_inner());
    *slowest = (*slowest).max(elapsed);
}

async fn open(handler: &AnyOutboundHandler, address: SocketAddr) -> Result<AnyStream> {
    open_within(handler, address, Duration::from_secs(5)).await
}

async fn open_within(
    handler: &AnyOutboundHandler,
    address: SocketAddr,
    limit: Duration,
) -> Result<AnyStream> {
    let sess = Session {
        destination: SocksAddr::from(address),
        ..Default::default()
    };
    let opened = common::scoped(tokio::time::timeout(
        limit,
        handler.stream()?.handle(&sess, None, None),
    ));
    Ok(opened.await??)
}

async fn ping(stream: &mut AnyStream) -> Result<()> {
    let start = std::time::Instant::now();
    ping_within(stream, ECHOED_WITHIN).await?;
    echoed_in(start.elapsed());
    Ok(())
}

/// Whether `stream` is refused: it fails, or no echo comes in time.
async fn refused(stream: &mut AnyStream) -> bool {
    ping_within(stream, refusal_window()).await.is_err()
}

/// Whether a stream `handler` opens is refused.
async fn refused_new(handler: &AnyOutboundHandler, address: SocketAddr) -> bool {
    match open_within(handler, address, refusal_window()).await {
        Ok(mut stream) => refused(&mut stream).await,
        Err(_) => true,
    }
}

async fn ping_within(stream: &mut AnyStream, limit: Duration) -> Result<()> {
    tokio::time::timeout(limit, async {
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
    let start = std::time::Instant::now();
    udp_ping_within(recv, send, address, ECHOED_WITHIN).await?;
    echoed_in(start.elapsed());
    Ok(())
}

/// Whether datagrams are refused: none comes back in time.
async fn udp_refused(
    recv: &mut dyn sail::adapter::OutboundDatagramRecvHalf,
    send: &mut dyn sail::adapter::OutboundDatagramSendHalf,
    address: SocketAddr,
) -> bool {
    udp_ping_within(recv, send, address, refusal_window())
        .await
        .is_err()
}

async fn udp_ping_within(
    recv: &mut dyn sail::adapter::OutboundDatagramRecvHalf,
    send: &mut dyn sail::adapter::OutboundDatagramSendHalf,
    address: SocketAddr,
    limit: Duration,
) -> Result<()> {
    tokio::time::timeout(limit, async {
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
            &["alice", "keeper"],
            &first.cert.pem(),
            &first.key_pair.serialize_pem(),
        );
        let new = inbound(
            protocol,
            port,
            &["bob", "keeper"],
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
            let datagram = common::scoped(old_handler.datagram()?.handle(&sess, None)).await?;
            let (mut recv, mut send) = datagram.split();
            udp_ping(&mut *recv, &mut *send, udp_address).await?;
            // A user every configuration keeps keeps its sessions.
            let (_kept_client, kept_handler) = client(protocol, port, "keeper", &first.cert.pem())?;
            let mut kept_stream = open(&kept_handler, address).await?;
            ping(&mut kept_stream).await?;
            let datagram = common::scoped(kept_handler.datagram()?.handle(&sess, None)).await?;
            let (mut kept_recv, mut kept_send) = datagram.split();
            udp_ping(&mut *kept_recv, &mut *kept_send, udp_address).await?;

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
            ping(&mut kept_stream).await?;
            udp_ping(&mut *kept_recv, &mut *kept_send, udp_address).await?;
            // More streams on an already authenticated connection retain its generation.
            ping(&mut open(&kept_handler, address).await?).await?;
            // A user taken out is revoked at once: its sessions are closed,
            // and so are new streams on the connection it authenticated.
            ensure!(
                refused(&mut old_stream).await,
                "a removed user's stream outlived it: {protocol}"
            );
            ensure!(
                udp_refused(&mut *recv, &mut *send, udp_address).await,
                "a removed user's UDP outlived it: {protocol}"
            );
            ensure!(
                refused_new(&old_handler, address).await,
                "a removed user opened a stream on its old connection: {protocol}"
            );
            let (_new_client, new_handler) = client(protocol, port, "bob", &second.cert.pem())?;
            ping(&mut open(&new_handler, address).await?).await?;

            let (_wrong_cert_client, wrong_cert) =
                client(protocol, port, "bob", &first.cert.pem())?;
            ensure!(
                open_within(&wrong_cert, address, refusal_window())
                    .await
                    .is_err(),
                "old certificate still trusted"
            );
            let (_removed_client, removed) = client(protocol, port, "alice", &second.cert.pem())?;
            // TUIC's connect writes before auth completes; an echo, not only open(),
            // is the proof of authentication for both protocols.
            ensure!(
                refused_new(&removed, address).await,
                "removed credentials accepted: {protocol}"
            );

            let mut empty = new.clone();
            empty["users"] = json!([]);
            manager
                .update_inbound_resources(serde_json::from_value(empty)?)
                .await?;
            ensure!(
                refused(&mut kept_stream).await,
                "an emptied inbound's user kept its stream: {protocol}"
            );
            let (_denied_client, denied) = client(protocol, port, "bob", &second.cert.pem())?;
            ensure!(refused_new(&denied, address).await);
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

/// A QUIC inbound replaced by a reload on the port it has: the endpoint
/// before holds the UDP socket until it and its connections are gone, a
/// moment after its listener has ended, and the new one binds once it
/// is. The session open on the one before ends; a new one is served.
#[test]
fn a_quic_inbound_is_replaced_by_a_reload_on_the_port_it_has() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    for protocol in ["hysteria2", "tuic", "trojan-quic"] {
        let [port] = common::free_ports();
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let (cert, key) = (pair.cert.pem(), pair.key_pair.serialize_pem());
        let before = inbound(protocol, port, &["alice"], &cert, &key);
        // Something other than its users and certificate changes.
        let mut after = before.clone();
        after["udp_timeout"] = json!("1m");
        let config = |inbound: &Value| {
            json!({"inbounds":[inbound],"outbounds":[{"type":"direct"}]}).to_string()
        };
        let running = Running(common::run_sail_instances(&rt, vec![config(&before)])?);
        let manager = sail::runtime_managers().get(&running.0[0]).unwrap().clone();
        rt.block_on(async {
            let (address, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_task = tokio::spawn(echo);
            let (_old_client, old_handler) = client(protocol, port, "alice", &cert)?;
            let mut old_stream = open(&old_handler, address).await?;
            ping(&mut old_stream).await?;

            let report = manager
                .reload_with_reporting(sail::config::from_string(&config(&after))?)
                .await
                .map_err(|e| anyhow::anyhow!("{protocol}: the reload: {e}"))?;
            ensure!(
                report.inbounds == [("server".to_string(), sail::control::InboundChange::Replaced)],
                "{protocol}: {:?}",
                report
            );
            ensure!(
                refused(&mut old_stream).await,
                "a session of the inbound before outlived it: {protocol}"
            );
            let (_new_client, new_handler) = client(protocol, port, "alice", &cert)?;
            ping(&mut open(&new_handler, address).await?).await?;
            echo_task.abort();
            anyhow::Ok(())
        })?;
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
    let keeper = psk(4);
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
    let old =
        inbound(json!([{"name":"alice","password":alice},{"name":"keeper","password":keeper}]));
    let new = inbound(json!([{"name":"bob","password":bob},{"name":"keeper","password":keeper}]));
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
        // A user every configuration keeps keeps its sessions; legacy
        // Shadowsocks has one password and no users.
        let (_kept, kept) = client(&keeper)?;
        let mut kept_stream = None;
        if !legacy {
            let mut stream = connect(&kept, port, address).await?;
            ping(&mut stream).await?;
            kept_stream = Some(stream);
        }
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
        if let Some(kept) = &mut kept_stream {
            ping(kept).await?;
            // A user taken out is revoked at once.
            ensure!(refused(&mut stream).await, "a removed user's stream outlived it");
            ensure!(
                udp_refused(&mut *recv, &mut *send, udp_address).await,
                "a removed user's UDP outlived it"
            );
        } else {
            // Without users there is no one to revoke: what the old
            // password opened goes on.
            ping(&mut stream).await?;
            udp_ping(&mut *recv, &mut *send, udp_address).await?;
        }
        // Whether a stream `handler` opens is refused.
        async fn refused_ss(handler: &AnyOutboundHandler, port: u16, address: SocketAddr) -> bool {
            match tokio::time::timeout(refusal_window(), connect(handler, port, address)).await {
                Ok(Ok(mut stream)) => refused(&mut stream).await,
                _ => true,
            }
        }
        ensure!(refused_ss(&old, port, address).await);
        let (_new, fresh) = client(&bob)?;
        ping(&mut connect(&fresh, port, address).await?).await?;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let new_udp = fresh.datagram()?.handle(&sess, Some(OutboundTransport::Datagram(Box::new(sail::net::StdOutboundDatagram::new(socket))))).await?;
        let (mut new_recv, mut new_send) = new_udp.split();
        udp_ping(&mut *new_recv, &mut *new_send, udp_address).await?;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let denied_udp = old.datagram()?.handle(&sess, Some(OutboundTransport::Datagram(Box::new(sail::net::StdOutboundDatagram::new(socket))))).await?;
        let (mut denied_recv, mut denied_send) = denied_udp.split();
        ensure!(udp_refused(&mut *denied_recv, &mut *denied_send, udp_address).await);
        if !legacy {
        manager
            .update_inbound_resources(serde_json::from_value(inbound(json!([])))?)
            .await?;
        if let Some(kept) = &mut kept_stream {
            ensure!(refused(kept).await, "an emptied inbound's user kept its stream");
        }
        ensure!(refused_ss(&fresh, port, address).await);
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

/// A QUIC inbound's certificate files replaced are served to the
/// connections that come next, with no reload, as sing-box's are; a
/// stream open goes on, and a certificate without its key is not taken.
#[cfg(feature = "auto-reload")]
#[test]
fn a_quic_certificate_file_replaced_is_served_with_no_reload() -> Result<()> {
    fn replace(path: &std::path::Path, contents: impl AsRef<[u8]>) -> Result<()> {
        let staged = path.with_extension("new");
        std::fs::write(&staged, contents)?;
        std::fs::rename(&staged, path)?;
        Ok(())
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let [port] = common::free_ports();
    let dir = common::TempDir::new("quic-certificate-follow")?;
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&cert_path, first.cert.pem())?;
    std::fs::write(&key_path, first.key_pair.serialize_pem())?;
    let inbound = json!({"type":"hysteria2","tag":"server","listen":"127.0.0.1","listen_port":port,
        "users":[{"name":"alice","password":"alice"}],
        "tls":{"enabled":true,"alpn":["h3"],"certificate_path":cert_path,"key_path":key_path}});
    let config = json!({"inbounds":[inbound],"outbounds":[{"type":"direct"}]}).to_string();
    let running = Running(common::run_sail_instances(&rt, vec![config])?);
    let manager = sail::runtime_manager(running.0[0]).unwrap();
    ensure!(
        manager.certificates_followed() == 1,
        "the files are not followed"
    );
    let reloads = manager.reloads();
    rt.block_on(async {
        let (address, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        let echo = tokio::spawn(echo);
        let (_old_client, old) = client("hysteria2", port, "alice", &first.cert.pem())?;
        let mut old_stream = open(&old, address).await?;
        ping(&mut old_stream).await?;

        // A certificate without its key is not taken.
        replace(&cert_path, second.cert.pem())?;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let (_early_client, early) = client("hysteria2", port, "alice", &second.cert.pem())?;
        ensure!(
            refused_new(&early, address).await,
            "a certificate was taken without its key"
        );

        replace(&key_path, second.key_pair.serialize_pem())?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let (_new_client, new) = client("hysteria2", port, "alice", &second.cert.pem())?;
            if let Ok(mut stream) = open(&new, address).await {
                if ping(&mut stream).await.is_ok() {
                    break;
                }
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "the replaced certificate was not served"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // The stream open before goes on; a client trusting the old
        // certificate alone gets no new connection.
        ping(&mut old_stream).await?;
        let (_stale_client, stale) = client("hysteria2", port, "alice", &first.cert.pem())?;
        ensure!(
            refused_new(&stale, address).await,
            "the old certificate is still served to new connections"
        );
        echo.abort();
        anyhow::Ok(())
    })?;
    ensure!(
        manager.reloads() == reloads,
        "a certificate file reloaded the whole instance"
    );
    Ok(())
}
