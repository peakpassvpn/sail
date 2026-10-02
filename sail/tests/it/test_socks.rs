#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// app(socks) -> (socks)client(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
))]
#[test]
fn test_socks() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [server_port, client_port] = common::free_ports();
        let config_server = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": server_port
                }
            ],
            "outbounds": [
                {
                    "type": "direct"
                }
            ]
        });

        let config_client = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": client_port
                }
            ],
            "outbounds": [
                {
                    "type": "socks",
                    "server": "127.0.0.1",
                    "server_port": server_port
                }
            ]
        });

        let configs = vec![config_server.to_string(), config_client.to_string()];
        common::test_configs(configs, "127.0.0.1", client_port)
    })
}

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-direct",
))]
#[test]
fn test_socks_auth() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [server_port, client_port] = common::free_ports();
        let config_server = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
                    "users": [
                        {
                            "username": "user",
                            "password": "password"
                        }
                    ]
                }
            ],
            "outbounds": [
                {
                    "type": "direct"
                }
            ]
        });

        let config_client = serde_json::json!({
            "inbounds": [
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": client_port
                }
            ],
            "outbounds": [
                {
                    "type": "socks",
                    "server": "127.0.0.1",
                    "server_port": server_port,
                    "username": "user",
                    "password": "password"
                }
            ]
        });

        let configs = vec![config_server.to_string(), config_client.to_string()];
        common::test_configs(configs, "127.0.0.1", client_port)
    })
}

/// A SOCKS5 CONNECT through sail(socks -> direct), on a connection of its
/// own: the reply's code (REP), and the connection.
#[cfg(all(feature = "inbound-socks", feature = "outbound-direct"))]
async fn socks5_connect(
    socks_port: u16,
    target: std::net::SocketAddr,
) -> anyhow::Result<(u8, tokio::net::TcpStream)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await?;
    anyhow::ensure!(method == [0x05, 0x00], "method {:?}", method);
    let std::net::SocketAddr::V4(v4) = target else {
        anyhow::bail!("IPv4 only");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&request).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    anyhow::ensure!(reply[0] == 0x05, "reply {:?}", reply);
    Ok((reply[1], s))
}

// app(socks) -> sail(socks -> direct) -> nothing listening, then an echo:
// the reply comes once the outbound connects, as sing-box gives it, with
// the failure's code; not success before the dial.
#[cfg(all(feature = "inbound-socks", feature = "outbound-direct"))]
#[test]
fn test_socks5_replies_once_connected() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    common::retry_port_clash(|| {
        let [socks_port] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
            "outbounds": [{ "type": "direct" }],
        });
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let checked = rt.block_on(async {
            // Refused: connection refused (5). On Linux the port is held,
            // bound but not listening, until the connect, which Linux
            // refuses: a port freed first could be another test's by then.
            // macOS drops a connect to such a socket unanswered, and
            // refuses only a port nothing holds: there it is freed first.
            let held = tokio::net::TcpSocket::new_v4()?;
            held.bind("127.0.0.1:0".parse()?)?;
            let closed = held.local_addr()?;
            if !cfg!(target_os = "linux") {
                drop(held);
            }
            let (rep, _) = socks5_connect(socks_port, closed).await?;
            anyhow::ensure!(rep == 0x05, "a refused connect answered {:#04x}", rep);
            // Reached: success, then the echo.
            let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let serve = tokio::spawn(serve);
            let (rep, mut s) = socks5_connect(socks_port, echo).await?;
            anyhow::ensure!(rep == 0x00, "a connect answered {:#04x}", rep);
            s.write_all(b"ping").await?;
            let mut got = [0u8; 4];
            s.read_exact(&mut got).await?;
            anyhow::ensure!(&got == b"ping");
            serve.abort();
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        checked
    })
}
