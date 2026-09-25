mod common;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

// app(socks) -> leaf(sniff, then route by the sniffed domain) -> echo
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct"
))]
#[test]
fn a_sniffed_domain_is_routed_by_the_rules_after_the_sniff() -> anyhow::Result<()> {
    let config = r#"
    {
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": 1087 }],
        "outbounds": [{ "type": "direct" }],
        "route": {
            "rules": [
                { "action": "sniff", "sniffer": ["http"] },
                { "domain_suffix": ["blocked.test"], "action": "reject" }
            ]
        }
    }
    "#;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let ids = common::run_leaf_instances(&rt, vec![config.to_string()])?;
    // Fails with an error rather than a panic, so that the instance is
    // shut down either way.
    let result = rt.block_on(async {
        let (echo_addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(echo);
        tokio::time::sleep(Duration::from_millis(200)).await;

        // To the echo server's address: the domain is only in the request.
        let sess = leaf::session::Session {
            destination: leaf::session::SocksAddr::from(echo_addr),
            ..Default::default()
        };
        let request = |host: &str| format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);

        let mut allowed = common::new_socks_stream("127.0.0.1", 1087, &sess, None, None).await?;
        allowed
            .write_all(request("allowed.test").as_bytes())
            .await?;
        let mut buf = vec![0u8; 256];
        let n = timeout(Duration::from_secs(2), allowed.read(&mut buf)).await??;
        anyhow::ensure!(
            &buf[..n] == request("allowed.test").as_bytes(),
            "an allowed connection should be relayed"
        );

        let mut blocked = common::new_socks_stream("127.0.0.1", 1087, &sess, None, None).await?;
        blocked
            .write_all(request("www.blocked.test").as_bytes())
            .await?;
        let read = timeout(Duration::from_secs(2), blocked.read(&mut buf)).await?;
        anyhow::ensure!(
            matches!(read, Ok(0) | Err(_)),
            "a rejected connection should be closed, read {:?}",
            read
        );
        anyhow::Ok(())
    });
    for id in ids {
        assert!(leaf::shutdown(id));
    }
    result
}
