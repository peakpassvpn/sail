//! Reload exercises real handshakes on the same listening socket. No
//! external binaries or network servers are required.
#![cfg(all(
    feature = "inbound-trojan",
    feature = "inbound-vless",
    feature = "inbound-tls",
    feature = "inbound-chain",
    feature = "outbound-direct"
))]
mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use btls::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use serde_json::{json, Value};
use sha2::{Digest, Sha224};

const ID: u16 = 930;
const UUID: &str = "90ee4432-671e-4ec8-8512-15d5fd0f8eab";

struct Running(u16);
impl Drop for Running {
    fn drop(&mut self) {
        sail::shutdown(self.0);
    }
}

fn start_runtime(
    rt: &tokio::runtime::Runtime,
    path: &std::path::Path,
    id: u16,
    _auto: bool,
) -> Result<Running> {
    let path = path.to_string_lossy().to_string();
    let start = rt.spawn_blocking(move || {
        sail::start(
            id,
            sail::StartOptions {
                config: sail::Config::File(path),
                #[cfg(feature = "auto-reload")]
                auto_reload: _auto,
                runtime_opt: sail::RuntimeOption::SingleThread,
                runtime: common::runtime_options(),
                host: Default::default(),
            },
        )
    });
    let running = Running(id);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sail::is_running(id) {
        if start.is_finished() {
            anyhow::bail!("start failed: {:?}", rt.block_on(start)?);
        }
        ensure!(Instant::now() < deadline, "runtime did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(running)
}

fn connect(port: u16) -> Result<SslStream<TcpStream>> {
    let tcp = TcpStream::connect(("127.0.0.1", port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(3)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);
    connector
        .build()
        .connect("localhost", tcp)
        .map_err(|e| anyhow::anyhow!("TLS: {e}"))
}

fn authenticate(
    stream: &mut SslStream<TcpStream>,
    password: &str,
    destination: SocketAddr,
) -> Result<()> {
    let mut request = hex::encode(Sha224::digest(password.as_bytes())).into_bytes();
    request.extend_from_slice(b"\r\n\x01");
    sail::session::SocksAddr::from(destination)
        .write_buf(&mut request, sail::session::SocksAddrWireType::PortLast);
    request.extend_from_slice(b"\r\n");
    stream.write_all(&request)?;
    Ok(())
}

fn ping(stream: &mut SslStream<TcpStream>) -> Result<()> {
    stream.write_all(b"ping")?;
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes)?;
    ensure!(&bytes == b"ping", "echo changed");
    Ok(())
}

fn peer(stream: &SslStream<TcpStream>) -> Result<Vec<u8>> {
    Ok(stream.ssl().peer_certificate().unwrap().to_der()?)
}

#[test]
fn users_and_certificates_reload_without_rebinding() -> Result<()> {
    common::retry_port_clash(|| exercise(common::free_port()))
}

fn exercise(port: u16) -> Result<()> {
    let dir = common::TempDir::new("inbound-resources")?;
    let config_path = dir.join("config.json");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&cert_path, first.cert.pem())?;
    std::fs::write(&key_path, first.key_pair.serialize_pem())?;
    let config = |password: &str| {
        json!({
            "inbounds": [
                {"type":"trojan", "tag":"server", "listen":"127.0.0.1", "listen_port":port,
                 "users":[{"name":password,"password":password}],
                 "tls":{"enabled":true,"certificate_path":cert_path,"key_path":key_path}},
                {"type":"vless", "tag":"guard", "users":[{"name":"guard","uuid":UUID}]}
            ],
        "outbounds":[{"type":"direct"}],
        "experimental":{"clash_api":{"default_mode":"Rule"}},
        "route":{"rules":[
            {"clash_mode":"Rule","action":"route","outbound":"direct"},
            {"inbound":["server"],"action":"reject"}
        ]}
        })
    };
    let save = |value: &Value| -> Result<()> {
        std::fs::write(&config_path, value.to_string())?;
        Ok(())
    };
    save(&config("alice"))?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let _running = start_runtime(&rt, &config_path, ID, false)?;
    let destination = rt.block_on(async {
        let (address, server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(server);
        anyhow::Ok(address)
    })?;

    let mut old = connect(port)?;
    let old_cert = peer(&old)?;
    authenticate(&mut old, "alice", destination)?;
    ping(&mut old)?;
    // Already handshaking, not authenticated yet: retain the old pair.
    let mut pending = connect(port)?;
    save(&config("bob"))?;
    std::fs::write(&cert_path, second.cert.pem())?;
    std::fs::write(&key_path, second.key_pair.serialize_pem())?;
    sail::reload(ID)?;
    let mut current = connect(port)?;
    let new_cert = peer(&current)?;
    ensure!(new_cert != old_cert, "certificate did not rotate");
    authenticate(&mut current, "bob", destination)?;
    ping(&mut current)?;
    ping(&mut old)?;
    authenticate(&mut pending, "alice", destination)?;
    ping(&mut pending)?;
    let mut removed = connect(port)?;
    authenticate(&mut removed, "alice", destination)?;
    ensure!(
        ping(&mut removed).is_err(),
        "removed user still authenticates"
    );

    // An invalid second inbound must not publish the first one's users.
    let mut bad = config("charlie");
    bad["inbounds"][1]["users"][0]["uuid"] = json!("invalid");
    save(&bad)?;
    ensure!(sail::reload(ID).is_err(), "invalid UUID accepted");
    let mut unchanged = connect(port)?;
    authenticate(&mut unchanged, "bob", destination)?;
    ping(&mut unchanged)?;
    // Mismatched certificate/key: no user, certificate or route changes.
    bad = config("charlie");
    bad["route"] = json!({"rules":[{"inbound":["server"],"action":"reject"}]});
    save(&bad)?;
    std::fs::write(&key_path, first.key_pair.serialize_pem())?;
    let error = sail::reload(ID)
        .expect_err("mismatched key accepted")
        .to_string();
    ensure!(
        error.contains("tls"),
        "expected TLS validation failure, got: {error}"
    );
    let mut unchanged = connect(port)?;
    ensure!(
        peer(&unchanged)? == new_cert,
        "failed reload changed certificate"
    );
    authenticate(&mut unchanged, "bob", destination)?;
    ping(&mut unchanged)?;
    ping(&mut old)?;
    std::fs::write(&key_path, second.key_pair.serialize_pem())?;
    // Resources built successfully, but a later outbound build fails.
    // Nothing from the staged inbound generation may leak through.
    bad = config("charlie");
    bad["outbounds"][0]["not_a_field"] = json!(true);
    // Removing the API would also clear the mode; that must wait until
    // validation succeeds, otherwise the live router starts rejecting.
    bad.as_object_mut().unwrap().remove("experimental");
    save(&bad)?;
    let error = sail::reload(ID)
        .expect_err("invalid outbound accepted")
        .to_string();
    ensure!(
        error.contains("not_a_field"),
        "expected outbound validation failure, got: {error}"
    );
    let mut unchanged = connect(port)?;
    authenticate(&mut unchanged, "bob", destination)?;
    ping(&mut unchanged)?;
    bad = config("charlie");
    bad["inbounds"][0]["listen_port"] = json!(port.wrapping_add(1));
    save(&bad)?;
    ensure!(
        sail::reload(ID).is_err(),
        "listener change silently ignored"
    );

    // The host API updates just its selected inbound, with the same checks.
    let manager = sail::runtime_managers().get(&ID).unwrap().clone();
    let inbound = serde_json::from_value(config("charlie")["inbounds"][0].clone())?;
    rt.block_on(manager.update_inbound_resources(inbound))?;
    let mut changed = connect(port)?;
    authenticate(&mut changed, "charlie", destination)?;
    ping(&mut changed)?;
    ping(&mut current)?;

    // Identical configuration paths still re-read replaced PEM contents.
    save(&config("charlie"))?;
    std::fs::write(&cert_path, first.cert.pem())?;
    std::fs::write(&key_path, first.key_pair.serialize_pem())?;
    sail::reload(ID)?;
    ensure!(
        peer(&connect(port)?)? == old_cert,
        "unchanged path was not re-read"
    );
    ping(&mut changed)?;
    let mut empty = config("charlie");
    empty["inbounds"][0]["users"] = json!([]);
    empty["inbounds"][1]["users"] = json!([]);
    save(&empty)?;
    sail::reload(ID)?;
    let mut revoked = connect(port)?;
    authenticate(&mut revoked, "charlie", destination)?;
    ensure!(
        ping(&mut revoked).is_err(),
        "empty table still authenticates users"
    );
    ping(&mut changed)?;
    Ok(())
}

#[cfg(feature = "auto-reload")]
#[test]
fn certificate_files_reload_after_repeated_atomic_replacement() -> Result<()> {
    common::retry_port_clash(|| exercise_watch(common::free_port()))
}

#[cfg(feature = "auto-reload")]
fn exercise_watch(port: u16) -> Result<()> {
    let dir = common::TempDir::new("inbound-watch")?;
    let path = dir.join("config.json");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&cert_path, first.cert.pem())?;
    std::fs::write(&key_path, first.key_pair.serialize_pem())?;
    let mut config = json!({"inbounds":[{
        "type":"trojan", "listen":"127.0.0.1", "listen_port":port,
        "users":[{"password":"alice"}],
        "tls":{"enabled":true,"certificate_path":cert_path,"key_path":key_path}
    }], "outbounds":[{"type":"direct"}]});
    std::fs::write(&path, config.to_string())?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let _running = start_runtime(&rt, &path, ID + 1, true)?;
    let destination = rt.block_on(async {
        let (address, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(echo);
        anyhow::Ok(address)
    })?;
    let mut old = connect(port)?;
    authenticate(&mut old, "alice", destination)?;
    ping(&mut old)?;
    // A half-written pair fails safely; its later partner triggers retry.
    std::fs::write(&key_path, second.key_pair.serialize_pem())?;
    std::thread::sleep(Duration::from_millis(800));
    ensure!(
        peer(&connect(port)?)? == first.cert.der().to_vec(),
        "half pair was published"
    );
    for pair in [&second, &first] {
        let staged = dir.join("staged.pem");
        std::fs::write(&staged, pair.cert.pem())?;
        std::fs::rename(&staged, &cert_path)?;
        std::fs::write(&key_path, pair.key_pair.serialize_pem())?;
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if peer(&connect(port)?)? == pair.cert.der().to_vec() {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "automatic certificate reload timed out"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        ping(&mut old)?;
    }
    // Replacing the config inode must not lose its watcher either.
    config["inbounds"][0]["users"][0]["password"] = json!("bob");
    let staged = dir.join("next.json");
    std::fs::write(&staged, config.to_string())?;
    std::fs::rename(&staged, &path)?;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let mut stream = connect(port)?;
        authenticate(&mut stream, "bob", destination)?;
        if ping(&mut stream).is_ok() {
            break;
        }
        ensure!(Instant::now() < deadline, "automatic user reload timed out");
        std::thread::sleep(Duration::from_millis(50));
    }
    ping(&mut old)?;
    Ok(())
}
