mod common;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Whether a connection through the instance to `sess`'s destination is
/// relayed (true) or closed (false).
async fn relayed(port: u16, sess: &sail::session::Session) -> anyhow::Result<bool> {
    let mut stream = common::new_socks_stream("127.0.0.1", port, sess, None, None).await?;
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
    let id = 900;
    let opts = sail::StartOptions {
        config: sail::Config::File(path.to_string_lossy().to_string()),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: common::runtime_options(),
        host: Default::default(),
    };
    let start = rt.spawn_blocking(move || sail::start(id, opts));
    // Returns once the instance runs, or with the error it failed with, a
    // port clash among them.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !sail::is_running(id) {
        if start.is_finished() {
            match rt.block_on(start)? {
                Err(e) => anyhow::bail!("start sail failed: {}", e),
                Ok(()) => anyhow::bail!("sail stopped as soon as it started"),
            }
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "sail did not start within 10s"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

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
