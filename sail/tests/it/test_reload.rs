#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Whether a connection through the instance to `sess`'s destination is
/// relayed (true) or closed (false).
async fn relayed(port: u16, sess: &sail::session::Session) -> anyhow::Result<bool> {
    // A rejected connect is answered with a failure.
    let Ok(mut stream) = common::new_socks_stream("127.0.0.1", port, sess, None, None).await else {
        return Ok(false);
    };
    stream.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    match timeout(Duration::from_secs(10), stream.read(&mut buf)).await? {
        Ok(4) => Ok(&buf == b"ping"),
        Ok(_) | Err(_) => Ok(false),
    }
}

// A reload takes effect for new connections, and one that fails to build
// changes nothing.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-fallback"
))]
#[test]
fn a_failed_reload_changes_nothing() -> anyhow::Result<()> {
    common::retry_port_clash(|| a_failed_reload_changes_nothing_on(common::free_port()))
}

/// The test above, with the instance's inbound on `port`, the same across
/// the reloads.
#[allow(dead_code)]
fn a_failed_reload_changes_nothing_on(port: u16) -> anyhow::Result<()> {
    let config_with = |outbounds: &str, rules: &str| {
        format!(
            r#"{{
                "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {port} }}],
                "outbounds": [{{ "type": "direct" }}{}],
                "route": {{ "rules": {} }}
            }}"#,
            outbounds, rules
        )
    };
    let config = |rules: &str| config_with("", rules);
    let dir = common::TempDir::new("reload")?;
    let path = dir.join("config.json");
    std::fs::write(&path, config("[]"))?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let id = common::next_rt_id();
    let opts = sail::StartOptions {
        signals: false,
        config: sail::Config::File(path.to_string_lossy().to_string()),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: common::runtime_options(),
        host: Default::default(),
    };
    // Returns once the instance runs, or with the error it failed with, a
    // port clash among them.
    common::start_instance(id, opts)?;

    // Fails with an error rather than a panic, so that the instance is shut
    // down either way.
    let result = rt.block_on(async {
        let (echo_addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(echo);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(echo_addr),
            ..Default::default()
        };
        anyhow::ensure!(relayed(port, &sess).await?, "relayed before any reload");

        std::fs::write(
            &path,
            config(r#"[{ "ip_cidr": ["127.0.0.0/8"], "action": "reject" }]"#),
        )?;
        let reload = tokio::task::spawn_blocking(move || sail::reload(id)).await?;
        anyhow::ensure!(reload.is_ok(), "the reload failed: {:?}", reload.err());
        anyhow::ensure!(!relayed(port, &sess).await?, "rejected after the reload");

        // Routing that would relay again, with an outbound that reads as a
        // configuration but fails to build.
        std::fs::write(
            &path,
            config_with(
                r#", { "type": "fallback", "tag": "pick", "outbounds": ["missing"] }"#,
                "[]",
            ),
        )?;
        let reload = tokio::task::spawn_blocking(move || sail::reload(id)).await?;
        anyhow::ensure!(reload.is_err(), "a broken configuration should not load");
        anyhow::ensure!(
            !relayed(port, &sess).await?,
            "still rejected: the failed reload changed nothing"
        );
        anyhow::Ok(())
    });
    assert!(sail::shutdown(id));
    result
}

/// A DNS server on a port of its own, answering every A query with
/// 127.0.0.1, and counting the queries it is asked.
#[allow(dead_code)]
async fn counting_dns_server(
) -> anyhow::Result<(u16, std::sync::Arc<std::sync::atomic::AtomicUsize>)> {
    use hickory_proto::op::{Message, MessageType, ResponseCode};
    use hickory_proto::rr::{rdata::A, RData, Record, RecordType};

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let port = socket.local_addr()?.port();
    let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = asked.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, peer) = crate::common::recv_past_errors(&socket, &mut buf).await;
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut resp = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            resp.metadata.recursion_desired = query.metadata.recursion_desired;
            resp.metadata.response_code = ResponseCode::NoError;
            for q in &query.queries {
                resp.add_query(q.clone());
                if q.query_type() == RecordType::A {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
                    ));
                }
            }
            let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    Ok((port, asked))
}

/// Whether `stream` echoes `data` back within 5 s.
#[allow(dead_code)]
async fn echoes<S>(stream: &mut S, data: &[u8]) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(data).await?;
    let mut buf = vec![0u8; data.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await??;
    anyhow::ensure!(buf == data, "echoed {:?}", buf);
    Ok(())
}

// A reload that changes only the DNS servers, as a host does after the
// network changed: a connection made before goes on as it was, and a name
// looked up after is asked of the new server, not the old.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct"
))]
#[test]
fn a_reload_of_the_dns_servers_keeps_connections_and_asks_the_new_ones() -> anyhow::Result<()> {
    common::retry_port_clash(|| dns_servers_reload_on(common::free_port()))
}

/// The test above, with the instance's inbound on `port`.
#[allow(dead_code)]
fn dns_servers_reload_on(port: u16) -> anyhow::Result<()> {
    use std::sync::atomic::Ordering::SeqCst;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (old_port, old) = rt.block_on(counting_dns_server())?;
    let (new_port, new) = rt.block_on(counting_dns_server())?;
    let config = |dns_port: u16| {
        format!(
            r#"{{
                "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {port} }}],
                "outbounds": [{{ "type": "direct" }}],
                "dns": {{ "servers": [{{ "type": "udp", "tag": "resolver",
                                       "server": "127.0.0.1", "server_port": {dns_port} }}] }},
                "route": {{ "default_domain_resolver": "resolver" }}
            }}"#
        )
    };
    let dir = common::TempDir::new("reload-dns")?;
    let path = dir.join("config.json");
    std::fs::write(&path, config(old_port))?;

    let id = common::next_rt_id();
    let opts = sail::StartOptions {
        signals: false,
        config: sail::Config::File(path.to_string_lossy().to_string()),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: common::runtime_options(),
        host: Default::default(),
    };
    // Returns once the instance runs, or with the error it failed with, a
    // port clash among them.
    common::start_instance(id, opts)?;

    let result = rt.block_on(async {
        let (echo_addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(echo);
        let to = |name: &str| sail::session::Session {
            destination: sail::session::SocksAddr::Domain(name.into(), echo_addr.port()),
            ..Default::default()
        };
        let mut held =
            common::new_socks_stream("127.0.0.1", port, &to("held.test"), None, None).await?;
        echoes(&mut held, b"before").await?;
        anyhow::ensure!(
            old.load(SeqCst) > 0,
            "the name was asked of the first server"
        );

        std::fs::write(&path, config(new_port))?;
        let reload = tokio::task::spawn_blocking(move || sail::reload(id)).await?;
        anyhow::ensure!(reload.is_ok(), "the reload failed: {:?}", reload.err());
        let asked_before = old.load(SeqCst);

        echoes(&mut held, b"after the reload").await?;
        let mut fresh =
            common::new_socks_stream("127.0.0.1", port, &to("fresh.test"), None, None).await?;
        echoes(&mut fresh, b"fresh").await?;
        anyhow::ensure!(
            new.load(SeqCst) > 0,
            "a name after the reload is asked of the new server"
        );
        anyhow::ensure!(
            old.load(SeqCst) == asked_before,
            "and not of the old one: {} queries, {} before the reload",
            old.load(SeqCst),
            asked_before
        );
        anyhow::Ok(())
    });
    assert!(sail::shutdown(id));
    result
}
