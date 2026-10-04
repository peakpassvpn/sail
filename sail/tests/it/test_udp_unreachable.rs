//! A UDP association that sends to a closed port goes on relaying: on
//! Windows an ICMP port unreachable for one datagram fails the outbound
//! socket's next receive, which sail turns off on every socket it makes
//! (`net::no_udp_connreset`); elsewhere it holds as it is.

use std::time::Duration;

use sail::embed::{Config, Instance, Options, Threads};
use sail::session::{Session, SocksAddr};

use crate::common;

/// Through a SOCKS UDP association and the direct outbound, one socket for
/// every destination of the association: many datagrams to a closed port,
/// then one to an echo server, whose answer comes back in time -- not after
/// the receive loop backed off a burst of resets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_association_relays_on_after_sending_to_a_closed_port() {
    let (echo, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let closed = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let [socks] = common::free_ports();
    let config = serde_json::json!({
        "inbounds": [{ "type": "socks", "tag": "socks-in",
                       "listen": "127.0.0.1", "listen_port": socks }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    })
    .to_string();
    let instance = Instance::new(Options::new().threads(Threads::One)).unwrap();
    instance.start(Config::Json(config)).await.unwrap();

    let sess = Session {
        destination: SocksAddr::Ip(echo),
        ..Default::default()
    };
    let datagram = common::new_socks_datagram("127.0.0.1", socks, &sess, None, None)
        .await
        .unwrap();
    let (mut recv, mut send) = datagram.split();
    // Past the 64 resets in a row that accept's backoff takes at once.
    for _ in 0..100 {
        send.send_to(b"nobody", &SocksAddr::Ip(closed))
            .await
            .unwrap();
    }
    send.send_to(b"echo", &SocksAddr::Ip(echo)).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(1), recv.recv_from(&mut buf))
        .await
        .expect("the echo in time")
        .unwrap();
    assert_eq!(&buf[..n], b"echo");
    assert_eq!(from, SocksAddr::Ip(echo));
    // And again: the association lives on.
    send.send_to(b"nobody", &SocksAddr::Ip(closed))
        .await
        .unwrap();
    send.send_to(b"again", &SocksAddr::Ip(echo)).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), recv.recv_from(&mut buf))
        .await
        .expect("the second echo in time")
        .unwrap();
    assert_eq!(&buf[..n], b"again");
    instance.stop().await.unwrap();
}
