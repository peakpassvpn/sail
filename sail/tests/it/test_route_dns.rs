//! Routing end to end where the DNS takes part: a `resolve` that names its
//! server, rules combined, and DNS rules on the Clash mode.

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

#[allow(unused_imports)]
use std::time::Duration;

#[allow(unused_imports)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// An echo server on 127.0.0.1, and its port.
#[allow(dead_code)]
fn echo_server(rt: &tokio::runtime::Runtime) -> anyhow::Result<u16> {
    rt.block_on(async {
        let (addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(echo);
        anyhow::Ok(addr.port())
    })
}

/// Whether a connection through the SOCKS server at `socks` to `host` at
/// `port` echoes.
#[allow(dead_code)]
async fn reaches(socks: u16, host: &str, port: u16) -> bool {
    let sess = sail::session::Session {
        destination: sail::session::SocksAddr::Domain(host.to_string(), port),
        ..Default::default()
    };
    let Ok(mut s) = common::new_socks_stream("127.0.0.1", socks, &sess, None, None).await else {
        return false;
    };
    let mut back = [0u8; 4];
    s.write_all(b"ping").await.is_ok()
        && tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut back))
            .await
            .is_ok_and(|r| r.is_ok())
        && &back == b"ping"
}

// app(socks, to a domain) -> sail(resolve with its own server, then
// ip_cidr) -> echo
//
// Locks that a `resolve` naming a server resolves with that server, and
// that the rules after it match the address it gave: the domain it
// resolves lands in a blocked range, while another, resolved as the DNS
// rules say, goes through.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-drop"
))]
#[test]
fn a_resolve_with_its_server_decides_the_rules_on_addresses() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let echo = echo_server(&rt)?;
    let (ids, socks) = common::retry_port_clash(|| {
        let [socks] = common::free_ports();
        let config = serde_json::json!({
            "dns": {
                "servers": [
                    { "type": "hosts", "tag": "usual", "predefined": {
                        "named.example": "127.0.0.1", "other.example": "127.0.0.1" } },
                    { "type": "hosts", "tag": "elsewhere", "predefined": {
                        "named.example": "10.9.9.9" } }
                ],
                "final": "usual"
            },
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks }],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": {
                "rules": [
                    { "domain": "named.example", "action": "resolve", "server": "elsewhere" },
                    { "ip_cidr": "10.0.0.0/8", "outbound": "block" }
                ],
                "final": "direct"
            }
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            socks,
        ))
    })?;
    let checked = rt.block_on(async {
        anyhow::ensure!(
            reaches(socks, "other.example", echo).await,
            "a domain the usual server resolves goes through"
        );
        anyhow::ensure!(
            !reaches(socks, "named.example", echo).await,
            "the resolve's own server gave 10.9.9.9, which a rule blocks"
        );
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}

// app(socks, to domains) -> sail(a logical rule: and, with an inverted
// member) -> echo
//
// Locks a logical rule end to end: `and` of a suffix and an inverted
// domain blocks the suffix's domains but the one inverted.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-drop"
))]
#[test]
fn a_logical_rule_decides_as_its_members_combine() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let echo = echo_server(&rt)?;
    let (ids, socks) = common::retry_port_clash(|| {
        let [socks] = common::free_ports();
        let config = serde_json::json!({
            "dns": { "servers": [{ "type": "hosts", "predefined": {
                "keep.corp.example": "127.0.0.1",
                "drop.corp.example": "127.0.0.1",
                "home.example": "127.0.0.1" } }] },
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks }],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": {
                "rules": [{
                    "type": "logical", "mode": "and",
                    "rules": [
                        { "domain_suffix": "corp.example" },
                        { "domain": "keep.corp.example", "invert": true }
                    ],
                    "outbound": "block"
                }],
                "final": "direct"
            }
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            socks,
        ))
    })?;
    let checked = rt.block_on(async {
        anyhow::ensure!(
            !reaches(socks, "drop.corp.example", echo).await,
            "both members hold"
        );
        anyhow::ensure!(
            reaches(socks, "keep.corp.example", echo).await,
            "the inverted one does not"
        );
        anyhow::ensure!(
            reaches(socks, "home.example", echo).await,
            "the suffix does not"
        );
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}

// app(socks, to a domain) -> sail(DNS rules on the Clash mode) -> echo;
// a dashboard changes the mode through the Clash API.
//
// Locks that DNS rules follow the mode as it changes at run time: in Rule
// mode the usual server answers, in Global the rule's, and the connection
// goes where each answer leads.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "clash-api"
))]
#[test]
fn dns_rules_follow_the_clash_mode_as_it_changes() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let echo = echo_server(&rt)?;
    let secret = sail::generate::secret();
    let (ids, (socks, api)) = common::retry_port_clash(|| {
        let [socks, api] = common::free_ports();
        let config = serde_json::json!({
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", api),
                "secret": secret,
            },
            "dns": {
                "servers": [
                    { "type": "hosts", "tag": "usual", "predefined": { "a.example": "127.0.0.1" } },
                    // Nothing listens there: a connection to it fails.
                    { "type": "hosts", "tag": "global", "predefined": { "a.example": "127.0.0.2" } }
                ],
                "rules": [{ "clash_mode": "Global", "server": "global" }],
                "final": "usual"
            },
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks }],
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            (socks, api),
        ))
    })?;
    let secret = &secret;
    let set_mode = |mode: &'static str| async move {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", api)).await?;
        let body = format!("{{\"mode\":\"{}\"}}", mode);
        s.write_all(
            format!(
                "PATCH /configs HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
                 Authorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                secret,
                body.len(),
                body
            )
            .as_bytes(),
        )
        .await?;
        let mut reply = String::new();
        s.read_to_string(&mut reply).await?;
        anyhow::ensure!(reply.starts_with("HTTP/1.1 204"), "{}", reply);
        anyhow::Ok(())
    };
    let checked = rt.block_on(async {
        anyhow::ensure!(
            reaches(socks, "a.example", echo).await,
            "Rule: the usual server"
        );
        set_mode("Global").await?;
        anyhow::ensure!(
            !reaches(socks, "a.example", echo).await,
            "Global: the rule's server"
        );
        set_mode("Rule").await?;
        anyhow::ensure!(reaches(socks, "a.example", echo).await, "Rule again");
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}

// dns client -> (direct, hijack-dns)sail; app(socks, to an address) ->
// sail(a rule on the domain the address was given for) -> echo
//
// Locks dns.reverse_mapping for the answers sail gives itself, as
// sing-box's DNS router keeps them: once a hijacked query has named an
// address, a connection to the bare address is routed by that name. Before
// the query nothing names it, and the connection goes through.
#[cfg(all(
    feature = "inbound-socks",
    feature = "inbound-direct",
    feature = "outbound-direct",
    feature = "outbound-drop"
))]
#[test]
fn an_address_sail_answered_for_is_routed_by_its_name() -> anyhow::Result<()> {
    use std::net::{IpAddr, SocketAddr};

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let echo = echo_server(&rt)?;
    let (ids, (socks, dns)) = common::retry_port_clash(|| {
        let [socks, dns] = common::free_ports();
        let config = serde_json::json!({
            "dns": {
                "servers": [{ "type": "hosts", "tag": "hosts",
                              "predefined": { "mapped.example": "127.0.0.1" } }],
                "final": "hosts",
                "reverse_mapping": true
            },
            "inbounds": [
                { "type": "socks", "listen": "127.0.0.1", "listen_port": socks },
                { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": dns }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": {
                "rules": [
                    { "inbound": "dns-in", "action": "hijack-dns" },
                    { "domain": "mapped.example", "outbound": "block" }
                ],
                "final": "direct"
            }
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            (socks, dns),
        ))
    })?;
    let reaches_address = |ip: IpAddr| async move {
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(SocketAddr::new(ip, echo)),
            ..Default::default()
        };
        let Ok(mut s) = common::new_socks_stream("127.0.0.1", socks, &sess, None, None).await
        else {
            return false;
        };
        let mut back = [0u8; 4];
        s.write_all(b"ping").await.is_ok()
            && tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut back))
                .await
                .is_ok_and(|r| r.is_ok())
            && &back == b"ping"
    };
    let checked = rt.block_on(async {
        let ip: IpAddr = "127.0.0.1".parse()?;
        anyhow::ensure!(reaches_address(ip).await, "no name for the address yet: direct");

        let mut m = Message::new(5, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii("mapped.example.")?, RecordType::A));
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        udp.send_to(&m.to_vec()?, ("127.0.0.1", dns)).await?;
        let mut buf = vec![0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf)).await??;
        let reply = Message::from_vec(&buf[..n])?;
        anyhow::ensure!(
            matches!(reply.answers.first().map(|r| &r.data), Some(RData::A(a)) if IpAddr::V4(a.0) == ip),
            "the hijacked query is answered with the address: {:?}",
            reply.answers
        );

        anyhow::ensure!(
            !reaches_address(ip).await,
            "the address is now named mapped.example, which a rule blocks"
        );
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}
