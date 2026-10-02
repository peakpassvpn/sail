#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// A selector over the members of a local provider: traffic passes through
// the one selected; one gone from the file leaves the selection to the
// default until it is back; a reload keeps the members and the selection.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-select",
    feature = "outbound-provider"
))]
#[test]
fn a_selector_follows_its_provider() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [port, first, second] = common::free_ports();
        a_selector_follows_its_provider_on(port, first, second)
    })
}

/// The test above, with the instance's inbound on `port`, and the socks
/// servers the provider gives on `first` and `second`.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-select",
    feature = "outbound-provider"
))]
fn a_selector_follows_its_provider_on(port: u16, first: u16, second: u16) -> anyhow::Result<()> {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = common::TempDir::new("provider")?;
    let proxies = dir.join("proxies.yaml");
    let write_proxies = |names: &[&str]| {
        let lines: Vec<String> = names
            .iter()
            .map(|name| {
                let port = if *name == "A" { first } else { second };
                format!(
                    "  - {{ name: {}, type: socks5, server: 127.0.0.1, port: {} }}\n",
                    name, port
                )
            })
            .collect();
        std::fs::write(&proxies, format!("proxies:\n{}", lines.concat()))
    };
    write_proxies(&["A", "B"])?;
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        format!(
            r#"{{
                "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {port} }}],
                "outbounds": [
                    {{ "type": "selector", "tag": "pick", "providers": "subscription",
                       "default": "A" }},
                    {{ "type": "direct" }}
                ],
                "outbound_providers": [{{
                    "type": "local", "tag": "subscription", "path": "{}",
                    "update_interval": "1s"
                }}]
            }}"#,
            crate::common::json_path(&proxies)
        ),
    )?;
    let server = |port: u16| {
        format!(
            r#"{{
                "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {port} }}],
                "outbounds": [{{ "type": "direct" }}]
            }}"#
        )
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let servers = common::run_sail_instances(&rt, vec![server(first), server(second)])?;
    let id = 910;
    let opts = sail::StartOptions {
        config: sail::Config::File(path.to_string_lossy().to_string()),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: common::runtime_options(),
        // The selection is kept here.
        host: sail::runtime::Host {
            data_dir: Some(dir.path().to_path_buf()),
            cache_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        },
    };
    let start = rt.spawn_blocking(move || sail::start(id, opts));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !sail::is_running(id) {
        if start.is_finished() {
            common::shutdown_instances(&rt, servers);
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
    let manager = sail::runtime_managers()
        .get(&id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no runtime manager"))?;

    let result = rt.block_on(async {
        let (echo_addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(echo);
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(echo_addr),
            ..Default::default()
        };
        let relayed = || async {
            let mut stream = common::new_socks_stream("127.0.0.1", port, &sess, None, None).await?;
            stream.write_all(b"ping").await?;
            let mut buf = [0u8; 4];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf)).await??;
            anyhow::ensure!(&buf == b"ping", "echoed {:?}", buf);
            anyhow::Ok(())
        };
        let members = || async {
            manager
                .get_outbound_selects("pick")
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))
        };
        let selected = || async {
            manager
                .get_outbound_selected("pick")
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))
        };
        // The file is read again every second.
        let members_become = |expected: &'static [&'static str]| async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let now = members().await?;
                if now == expected {
                    return anyhow::Ok(());
                }
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "members {:?}, not {:?}",
                    now,
                    expected
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        anyhow::ensure!(members().await? == ["A", "B"]);
        anyhow::ensure!(selected().await? == "A", "the default first");
        relayed().await?;

        manager
            .set_outbound_selected("pick", "B")
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        anyhow::ensure!(selected().await? == "B");
        relayed().await?;

        write_proxies(&["A"])?;
        members_become(&["A"]).await?;
        anyhow::ensure!(selected().await? == "A", "the default while B is gone");
        relayed().await?;

        write_proxies(&["A", "B"])?;
        members_become(&["A", "B"]).await?;
        anyhow::ensure!(selected().await? == "B", "B again once it is back");
        relayed().await?;

        let reload = tokio::task::spawn_blocking(move || sail::reload(id)).await?;
        anyhow::ensure!(reload.is_ok(), "the reload failed: {:?}", reload.err());
        anyhow::ensure!(members().await? == ["A", "B"], "kept across the reload");
        anyhow::ensure!(selected().await? == "B", "selected across the reload");
        relayed().await?;
        anyhow::Ok(())
    });
    assert!(sail::shutdown(id));
    common::shutdown_instances(&rt, servers);
    result
}
