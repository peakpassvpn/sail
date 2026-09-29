#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// dig -> (direct)sail, a hijack-dns rule for the inbound -> hosts server
//
// A direct inbound with a hijack-dns rule for it is a DNS server, as in
// sing-box: queries over UDP and TCP to its port are answered by the DNS
// client, as its rules pick a server; a UDP answer too big for the client
// comes back cut down to 512 bytes with TC set, and in full over TCP.
#[cfg(feature = "inbound-direct")]
#[test]
fn a_direct_inbound_hijacked_is_a_dns_server() -> anyhow::Result<()> {
    use std::net::IpAddr;
    use std::str::FromStr;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn query(name: &str, ty: RecordType) -> Vec<u8> {
        let mut m = Message::new(9, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_str(name).unwrap(), ty));
        m.to_vec().unwrap()
    }

    fn addresses(reply: &[u8]) -> (bool, Vec<IpAddr>) {
        let m = Message::from_vec(reply).unwrap();
        assert_eq!(m.metadata.id, 9);
        let ips = m
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                _ => None,
            })
            .collect();
        (m.metadata.truncation, ips)
    }

    let many: Vec<String> = (1..=60).map(|i| format!("2001:db8::{:x}", i)).collect();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, port) = common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let config = serde_json::json!({
            "dns": { "servers": [
                { "type": "hosts", "predefined": {
                    "one.sail": "192.0.2.1",
                    "many.sail": many,
                } }
            ] },
            "inbounds": [{
                "type": "direct", "tag": "dns-in",
                "listen": "127.0.0.1", "listen_port": port,
            }],
            "route": { "rules": [{ "inbound": "dns-in", "action": "hijack-dns" }] },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            port,
        ))
    })?;
    let server = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    rt.block_on(async {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let mut buf = vec![0u8; 65535];
        let mut ask_udp = async |q: Vec<u8>| -> anyhow::Result<Vec<u8>> {
            udp.send_to(&q, server).await?;
            let (n, from) =
                tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_from(&mut buf))
                    .await??;
            assert_eq!(from, server);
            Ok(buf[..n].to_vec())
        };
        let one = ask_udp(query("one.sail.", RecordType::A)).await?;
        assert_eq!(addresses(&one), (false, vec!["192.0.2.1".parse()?]));

        let cut = ask_udp(query("many.sail.", RecordType::AAAA)).await?;
        assert!(cut.len() <= 512, "{}", cut.len());
        let (truncated, ips) = addresses(&cut);
        assert!(truncated && !ips.is_empty() && ips.len() < 60, "{:?}", ips);

        let mut tcp = tokio::net::TcpStream::connect(server).await?;
        let q = query("many.sail.", RecordType::AAAA);
        tcp.write_u16(q.len() as u16).await?;
        tcp.write_all(&q).await?;
        let len = tcp.read_u16().await? as usize;
        let mut reply = vec![0u8; len];
        tcp.read_exact(&mut reply).await?;
        let (truncated, ips) = addresses(&reply);
        assert!(!truncated);
        assert_eq!(ips.len(), 60);
        anyhow::Ok(())
    })?;
    common::shutdown_instances(&rt, ids);
    Ok(())
}
