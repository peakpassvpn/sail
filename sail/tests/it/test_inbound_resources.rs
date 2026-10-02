//! Reload exercises real handshakes on the same listening socket. No
//! external binaries or network servers are required.
#![cfg(all(
    feature = "inbound-trojan",
    feature = "inbound-vless",
    feature = "inbound-tls",
    feature = "outbound-direct"
))]
#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use btls::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use serde_json::{json, Value};
use sha2::{Digest, Sha224};

/// Runtime IDs of their own: another test runs at the same time under 930.
const ID: u16 = 950;
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
                 "users":[{"name":password,"password":password},
                          {"name":"keeper","password":"keeper"}],
                 "tls":{"enabled":true,"certificate_path":cert_path,"key_path":key_path}},
                {"type":"vless", "tag":"guard", "listen":"127.0.0.1", "listen_port":0,
                 "users":[{"name":"guard","uuid":UUID}]}
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
    // A user every configuration keeps keeps its connection.
    let mut kept = connect(port)?;
    authenticate(&mut kept, "keeper", destination)?;
    ping(&mut kept)?;
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
    ping(&mut kept)?;
    // A user taken out is revoked at once: its connection is closed, and
    // a handshake it had begun under the old users gets no further.
    ensure!(
        ping(&mut old).is_err(),
        "a removed user's connection outlived it"
    );
    authenticate(&mut pending, "alice", destination)?;
    ensure!(
        ping(&mut pending).is_err(),
        "a removed user's handshake in progress got through"
    );
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
    ping(&mut kept)?;
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
    ping(&mut kept)?;
    ensure!(
        ping(&mut current).is_err(),
        "a user the host API took out kept its connection"
    );

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
    ensure!(
        ping(&mut changed).is_err() && ping(&mut kept).is_err(),
        "an emptied table's users kept their connections"
    );
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

#[cfg(all(feature = "auto-reload", feature = "rule-set"))]
#[test]
fn local_rule_files_reload_and_invalid_replacements_keep_previous_rules() -> Result<()> {
    let dir = common::TempDir::new("rule-resource-watch")?;
    let path = dir.join("config.json");
    let rules = dir.join("rules.json");
    let staged = dir.join("staged.json");
    let port = common::free_port();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&rules, json!({"version":3,"rules":[]}).to_string())?;
    std::fs::write(&path, json!({
        "inbounds":[{"type":"trojan","tag":"server","listen":"127.0.0.1","listen_port":port,
            "users":[{"password":"alice"}],"tls":{"enabled":true,"certificate":cert.cert.pem(),"key":cert.key_pair.serialize_pem()}}],
        "outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"rule_set":[{"type":"local","tag":"blocked","format":"source","path":rules}],
            "rules":[{"rule_set":["blocked"],"action":"reject"}],"final":"direct"}
    }).to_string())?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let _running = start_runtime(&rt, &path, ID + 2, true)?;
    let destination = rt.block_on(async {
        let (address, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(echo);
        anyhow::Ok(address)
    })?;
    let fresh = || -> Result<()> {
        let mut stream = connect(port)?;
        authenticate(&mut stream, "alice", destination)?;
        ping(&mut stream)
    };
    let mut old = connect(port)?;
    authenticate(&mut old, "alice", destination)?;
    ping(&mut old)?;
    for (data, allowed) in [
        (
            json!({"version":3,"rules":[{"ip_cidr":["127.0.0.0/8"]}]}).to_string(),
            false,
        ),
        ("invalid JSON".to_owned(), false),
        (json!({"version":3,"rules":[]}).to_string(), true),
    ] {
        std::fs::write(&staged, data)?;
        std::fs::rename(&staged, &rules)?;
        // Also wait for the invalid candidate to be processed before checking rollback.
        std::thread::sleep(Duration::from_millis(600));
        let deadline = Instant::now() + Duration::from_secs(8);
        while fresh().is_ok() != allowed {
            ensure!(
                Instant::now() < deadline,
                "rule-set file update did not become visible"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        ping(&mut old)?;
    }
    Ok(())
}

/// `path` replaced by `contents` as a deployment replaces it: written
/// beside it, then renamed over it.
#[cfg(feature = "auto-reload")]
fn replace(path: &std::path::Path, contents: impl AsRef<[u8]>) -> Result<()> {
    let staged = path.with_extension("new");
    std::fs::write(&staged, contents)?;
    std::fs::rename(&staged, path)?;
    Ok(())
}

/// A certificate whose files are replaced is served to the handshakes
/// that come next, with no reload and no configuration file, as
/// sing-box's is; those open go on.
#[cfg(feature = "auto-reload")]
#[test]
fn a_certificate_file_replaced_is_served_with_no_reload() -> Result<()> {
    common::retry_port_clash(|| follow_certificate_files(common::free_port()))
}

#[cfg(feature = "auto-reload")]
fn follow_certificate_files(port: u16) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let dir = common::TempDir::new("certificate-follow")?;
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&cert_path, first.cert.pem())?;
    std::fs::write(&key_path, first.key_pair.serialize_pem())?;
    let config = json!({
        "inbounds": [{"type":"trojan", "tag":"server", "listen":"127.0.0.1", "listen_port":port,
            "users":[{"name":"alice","password":"alice"},{"name":"keeper","password":"keeper"}],
            "tls":{"enabled":true,"certificate_path":cert_path,"key_path":key_path}}],
        "outbounds":[{"type":"direct"}],
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
    let _running = Running(ids[0]);
    let manager = sail::runtime_manager(ids[0]).unwrap();
    ensure!(
        manager.certificates_followed() == 1,
        "the files are not followed"
    );
    let reloads = manager.reloads();
    let destination = rt.block_on(async {
        let (address, server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(server);
        anyhow::Ok(address)
    })?;

    let mut kept = connect(port)?;
    let old_cert = peer(&kept)?;
    authenticate(&mut kept, "keeper", destination)?;
    ping(&mut kept)?;

    // A certificate without its key is not taken: the pair in use is kept.
    replace(&cert_path, second.cert.pem())?;
    std::thread::sleep(Duration::from_millis(1000));
    ensure!(
        peer(&connect(port)?)? == old_cert,
        "a certificate was taken without its key"
    );

    // Handshakes go on through the swap, each with one pair or the other.
    let swapping = Arc::new(AtomicBool::new(true));
    let handshakes = std::thread::spawn({
        let swapping = swapping.clone();
        move || {
            let (mut seen, mut failed) = (std::collections::HashSet::new(), 0);
            while swapping.load(Ordering::Relaxed) {
                match connect(port).and_then(|s| peer(&s)) {
                    Ok(cert) => {
                        seen.insert(cert);
                    }
                    Err(_) => failed += 1,
                }
            }
            (seen, failed)
        }
    });
    replace(&key_path, second.key_pair.serialize_pem())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let new_cert = loop {
        let cert = peer(&connect(port)?)?;
        if cert != old_cert {
            break cert;
        }
        ensure!(
            Instant::now() < deadline,
            "the replaced certificate was not served"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    swapping.store(false, Ordering::Relaxed);
    let (seen, failed) = handshakes.join().unwrap();
    ensure!(failed == 0, "{failed} handshakes failed during the swap");
    ensure!(
        seen.iter()
            .all(|cert| *cert == old_cert || *cert == new_cert),
        "a handshake saw a pair that was neither"
    );

    // What was open goes on; who comes next gets in with the new pair.
    ping(&mut kept)?;
    let mut fresh = connect(port)?;
    authenticate(&mut fresh, "alice", destination)?;
    ping(&mut fresh)?;
    ensure!(
        manager.reloads() == reloads,
        "a certificate file reloaded the whole instance"
    );
    Ok(())
}

/// What follows the files is the instance's: nothing of it is left once
/// it stops.
#[cfg(feature = "auto-reload")]
#[test]
fn what_follows_the_files_stops_with_the_instance() -> Result<()> {
    let dir = common::TempDir::new("certificate-follow-stop")?;
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&cert_path, pair.cert.pem())?;
    std::fs::write(&key_path, pair.key_pair.serialize_pem())?;
    let config = json!({
        "inbounds": [{"type":"trojan", "tag":"server", "listen":"127.0.0.1", "listen_port":0,
            "users":[{"name":"alice","password":"alice"}],
            "tls":{"enabled":true,"certificate_path":cert_path,"key_path":key_path}}],
        "outbounds":[{"type":"direct"}],
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let id = common::run_sail_instances(&rt, vec![config.to_string()])?[0];
    let manager = sail::runtime_manager(id).unwrap();
    ensure!(manager.certificates_followed() == 1);
    sail::shutdown(id);
    let deadline = Instant::now() + Duration::from_secs(10);
    while sail::is_running(id) {
        ensure!(Instant::now() < deadline, "the instance did not stop");
        std::thread::sleep(Duration::from_millis(10));
    }
    ensure!(
        manager.certificates_followed() == 0,
        "the files are still followed after the instance stopped"
    );
    Ok(())
}

/// An instance a host embeds (`sail::embed`, which never watches a
/// configuration file) follows its certificate files all the same.
#[cfg(feature = "auto-reload")]
#[test]
fn an_embedded_instance_serves_a_replaced_certificate() -> Result<()> {
    common::retry_port_clash(|| embedded_certificate_follow(common::free_port()))
}

#[cfg(feature = "auto-reload")]
fn embedded_certificate_follow(port: u16) -> Result<()> {
    use sail::embed::{Config, Instance, Options, Threads};

    let dir = common::TempDir::new("embedded-certificate-follow")?;
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    std::fs::write(&cert_path, first.cert.pem())?;
    std::fs::write(&key_path, first.key_pair.serialize_pem())?;
    let config = json!({
        "inbounds": [{"type":"trojan", "tag":"server", "listen":"127.0.0.1", "listen_port":port,
            "users":[{"name":"alice","password":"alice"}],
            "tls":{"enabled":true,"certificate_path":cert_path,"key_path":key_path}}],
        "outbounds":[{"type":"direct"}],
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let instance = Instance::new(Options::new().threads(Threads::One))
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    rt.block_on(instance.start(Config::Json(config.to_string())))
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let result = (|| {
        let old_cert = peer(&connect(port)?)?;
        replace(&cert_path, second.cert.pem())?;
        replace(&key_path, second.key_pair.serialize_pem())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while peer(&connect(port)?)? == old_cert {
            ensure!(
                Instant::now() < deadline,
                "an embedded instance did not serve the replaced certificate"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    })();
    rt.block_on(instance.stop())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    result
}
