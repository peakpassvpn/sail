#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-select",
    feature = "outbound-redirect",
    feature = "outbound-pass"
))]

use crate::common;

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// A server that answers every connection with its name, and closes it.
async fn named(name: &'static str) -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, name.as_bytes()).await;
            });
        }
    });
    Ok(port)
}

// app(socks) -> sail(x.test -> sel [PASS, a], final b) -> a or b: with the
// selector on PASS, the rule is skipped and final takes the connection.
#[test]
fn a_selector_on_pass_hands_the_connection_to_the_next_rule() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (a, b) = rt.block_on(async { anyhow::Ok((named("a").await?, named("b").await?)) })?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [
                { "type": "selector", "tag": "sel", "outbounds": ["PASS", "a"], "default": "a" },
                { "type": "redirect", "tag": "a", "server": "127.0.0.1", "server_port": a },
                { "type": "redirect", "tag": "b", "server": "127.0.0.1", "server_port": b },
                { "type": "pass", "tag": "PASS" }
            ],
            "route": {
                "rules": [{ "domain": ["x.test"], "outbound": "sel" }],
                "final": "b"
            }
        });
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let manager = sail::runtime_managers()
            .get(&ids[0])
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no runtime manager"))?;
        let result = rt.block_on(async {
            let sess = sail::session::Session {
                destination: sail::session::SocksAddr::Domain("x.test".into(), 80),
                ..Default::default()
            };
            let reached = || async {
                let mut stream =
                    common::new_socks_stream("127.0.0.1", port, &sess, None, None).await?;
                let mut name = String::new();
                tokio::time::timeout(Duration::from_secs(10), stream.read_to_string(&mut name))
                    .await??;
                anyhow::Ok(name)
            };
            let got = reached().await?;
            anyhow::ensure!(got == "a", "reached {:?} through the selector on a", got);

            manager
                .set_outbound_selected("sel", "PASS")
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let got = reached().await?;
            anyhow::ensure!(got == "b", "reached {:?} with the selector on PASS", got);
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}
