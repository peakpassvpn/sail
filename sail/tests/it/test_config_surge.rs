#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// app(socks) -> (socks5-listen)sail, read from a Surge profile -> echo
//
// Its rules decide: through a group to DIRECT, or one of the REJECT
// policies for the echo server's address or port.
#[cfg(all(
    feature = "config-surge",
    feature = "inbound-socks",
    feature = "inbound-http",
    feature = "outbound-direct",
    feature = "outbound-drop",
    feature = "outbound-select"
))]
#[test]
fn a_surge_profile_routes() -> anyhow::Result<()> {
    for (rules, rejected) in [
        ("FINAL,Proxy\n", false),
        ("IP-CIDR,127.0.0.0/8,REJECT,no-resolve\nFINAL,Proxy\n", true),
        ("DEST-PORT,1-65535,REJECT-DROP\nFINAL,Proxy\n", true),
        ("PROTOCOL,UDP,REJECT-NO-DROP\nFINAL,Proxy\n", true),
        ("DOMAIN-SUFFIX,example.com,REJECT\nFINAL,Proxy\n", false),
        ("FINAL,REJECT\n", true),
    ] {
        let result = common::retry_port_clash(|| {
            let [http, socks] = common::free_ports();
            let profile = format!(
                "[General]\nloglevel = warning\n\
                 http-listen = 127.0.0.1:{}\nsocks5-listen = 127.0.0.1:{}\n\
                 [Proxy Group]\nProxy = select, DIRECT, REJECT\n\
                 [Rule]\n{}",
                http, socks, rules
            );
            common::test_configs(vec![profile], "127.0.0.1", socks)
        });
        assert_eq!(result.is_err(), rejected, "{}: {:?}", rules, result);
    }
    Ok(())
}

// app -> (port forwarding)sail -> echo: a forwarded port connects to its
// target.
#[cfg(all(
    feature = "config-surge",
    feature = "inbound-direct",
    feature = "outbound-direct"
))]
#[test]
fn a_forwarded_port_reaches_its_target() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (echo, echo_fut) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    rt.spawn(echo_fut);
    common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let profile = format!(
            "[Port Forwarding]\n127.0.0.1:{} {} policy=DIRECT\n[Rule]\nFINAL,REJECT\n",
            port, echo
        );
        let ids = common::run_sail_instances(&rt, vec![profile])?;
        let result = rt.block_on(async {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
            stream.write_all(b"forwarded").await?;
            let mut buf = [0u8; 9];
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read_exact(&mut buf),
            )
            .await??;
            anyhow::ensure!(&buf == b"forwarded", "echoed {:?}", buf);
            Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}
