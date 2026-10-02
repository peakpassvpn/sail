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
    // Those that pass first: the refusals wait by them.
    let mut cases = [
        ("FINAL,Proxy\n", false),
        ("IP-CIDR,127.0.0.0/8,REJECT,no-resolve\nFINAL,Proxy\n", true),
        ("DEST-PORT,1-65535,REJECT-DROP\nFINAL,Proxy\n", true),
        ("PROTOCOL,UDP,REJECT-NO-DROP\nFINAL,Proxy\n", true),
        ("DOMAIN-SUFFIX,example.com,REJECT\nFINAL,Proxy\n", false),
        ("FINAL,REJECT\n", true),
    ];
    cases.sort_by_key(|(_, rejected)| *rejected);
    let mut passed = Vec::new();
    for (rules, rejected) in cases {
        let result = common::retry_port_clash(|| {
            let [http, socks] = common::free_ports();
            let profile = format!(
                "[General]\nloglevel = warning\n\
                 http-listen = 127.0.0.1:{}\nsocks5-listen = 127.0.0.1:{}\n\
                 [Proxy Group]\nProxy = select, DIRECT, REJECT\n\
                 [Rule]\n{}",
                http, socks, rules
            );
            // A refusal fails by a wait running out where it drops: ten
            // times the slowest of those that pass, which run first.
            if rejected {
                common::test_configs_refused(
                    vec![profile],
                    "127.0.0.1",
                    socks,
                    common::refusal_wait(&passed),
                )
            } else {
                let started = std::time::Instant::now();
                let result = common::test_configs(vec![profile], "127.0.0.1", socks);
                passed.push(started.elapsed());
                result
            }
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

// app(socks) -> (socks5-listen)sail, read from a Surge profile -> echo
//
// Rule-sets decide: a local RULE-SET file, an inline [Ruleset], LAN, and a
// DOMAIN-SET that matches nothing here.
#[cfg(all(
    feature = "config-surge",
    feature = "rule-set",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-drop",
    feature = "outbound-select"
))]
#[test]
fn a_surge_profile_s_rule_sets_route() -> anyhow::Result<()> {
    let dir = common::TempDir::new("surge-sets")?;
    let local = dir.join("local.list");
    std::fs::write(
        &local,
        "# the echo server\nIP-CIDR,127.0.0.0/8,no-resolve // loopback\n",
    )?;
    let domains = dir.join("domains.txt");
    std::fs::write(&domains, ".example.com\nexact.example\n")?;
    for (rules, rejected) in [
        (format!("RULE-SET,{},REJECT\n", local.display()), true),
        (format!("DOMAIN-SET,{},REJECT\n", domains.display()), false),
        ("RULE-SET,Loopback,REJECT\n".to_string(), true),
        ("RULE-SET,LAN,REJECT,no-resolve\n".to_string(), true),
        ("RULE-SET,SYSTEM,REJECT\n".to_string(), false),
    ] {
        let result = common::retry_port_clash(|| {
            let [socks] = common::free_ports();
            let profile = format!(
                "[General]\nloglevel = warning\nsocks5-listen = 127.0.0.1:{}\n\
                 [Ruleset Loopback]\nAND,((IP-CIDR,127.0.0.1/32,no-resolve),(PROTOCOL,TCP))\n\
                 [Rule]\n{}FINAL,DIRECT\n",
                socks, rules
            );
            // Read from text, its files are in the data directory.
            common::test_configs_in(vec![profile], "127.0.0.1", socks, dir.path())
        });
        assert_eq!(result.is_err(), rejected, "{}: {:?}", rules, result);
    }
    Ok(())
}

// app(socks, to a name) -> (socks5-listen)sail -> echo: [Host] gives the
// name the echo server's address, which DIRECT dials; the first line that
// matches decides.
#[cfg(all(
    feature = "config-surge",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-socks"
))]
#[test]
fn a_surge_host_maps_a_name() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (echo, echo_fut) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    rt.spawn(echo_fut);
    common::retry_port_clash(|| {
        let [socks] = common::free_ports();
        let profile = format!(
            "[General]\nloglevel = warning\nsocks5-listen = 127.0.0.1:{}\n\
             [Host]\necho.surge.invalid = 127.0.0.1\n*.surge.invalid = 10.255.255.1\n\
             [Rule]\nFINAL,DIRECT\n",
            socks
        );
        let ids = common::run_sail_instances(&rt, vec![profile])?;
        let result = rt.block_on(async {
            let sess = sail::session::Session {
                destination: sail::session::SocksAddr::Domain(
                    "echo.surge.invalid".into(),
                    echo.port(),
                ),
                ..Default::default()
            };
            let mut stream =
                common::new_socks_stream("127.0.0.1", socks, &sess, None, None).await?;
            stream.write_all(b"mapped").await?;
            let mut buf = [0u8; 6];
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read_exact(&mut buf),
            )
            .await??;
            anyhow::ensure!(&buf == b"mapped", "echoed {:?}", buf);
            Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> (socks5-listen)sail, read from a Surge profile -> (socks)sail
// -> echo
//
// A select group takes its member from a local policy-path, a list of
// Surge's policy lines: through it traffic passes, and fails where the
// policy's server is not there.
#[cfg(all(
    feature = "config-surge",
    feature = "outbound-provider",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-select"
))]
#[test]
fn a_surge_policy_path_routes() -> anyhow::Result<()> {
    let dir = common::TempDir::new("surge-policy-path")?;
    for up in [true, false] {
        let result = common::retry_port_clash(|| {
            let [socks, relay, closed] = common::free_ports();
            let list = dir.join("nodes.list");
            std::fs::write(
                &list,
                format!(
                    "# the relay\nRelay = socks5, 127.0.0.1, {}\n",
                    if up { relay } else { closed }
                ),
            )?;
            let profile = format!(
                "[General]\nloglevel = warning\nsocks5-listen = 127.0.0.1:{}\n\
                 [Proxy Group]\nProxy = select, policy-path={}\n\
                 [Rule]\nFINAL,Proxy\n",
                socks,
                list.display()
            );
            let server = format!(
                r#"{{
                    "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {} }}],
                    "outbounds": [{{ "type": "direct" }}]
                }}"#,
                relay
            );
            // Read from text, its list is in the data directory.
            common::test_configs_in(vec![profile, server], "127.0.0.1", socks, dir.path())
        });
        assert_eq!(result.is_ok(), up, "{:?}", result);
    }
    Ok(())
}
