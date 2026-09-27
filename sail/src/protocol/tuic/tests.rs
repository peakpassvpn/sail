//! The client against the server, in process.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::adapter::*;
use crate::app::dns::DnsClient;
use crate::session::{Session, SocksAddr};
use crate::transport::quic::{alpn_protocols, client_crypto, server_crypto, ClientTls};

use super::common::{CongestionControl, UdpRelayMode, DEFAULT_ALPN};
use super::inbound::{Server, User};
use super::outbound::{Client, ClientOptions, StreamHandler};

const UUID: [u8; 16] = [7; 16];
const PASSWORD: &[u8] = b"pw";

struct Fixture {
    client: Arc<Client>,
    incoming: AnyIncomingTransport,
    /// The client's session tickets, by server name.
    tickets: Arc<dyn quinn_btls::SessionCache>,
}

/// A server with `zero_rtt` as the server has it, and a client of it with
/// `zero_rtt` as the client has it.
async fn fixture(server_zero_rtt: bool, client_zero_rtt: bool) -> Fixture {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let alpns = alpn_protocols(None, DEFAULT_ALPN);
    let tuning = crate::runtime::options::Quic::default();

    let crypto = server_crypto(&cert.pem(), &key_pair.serialize_pem(), &alpns).unwrap();
    let users = HashMap::from([(
        UUID,
        User {
            password: PASSWORD.to_vec(),
            name: None,
        },
    )]);
    let server = Server::new(
        users,
        crypto,
        CongestionControl::Cubic,
        Duration::from_secs(3),
        server_zero_rtt,
        Duration::from_secs(10),
        &tuning,
    )
    .unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let transport = server
        .handle(Box::new(crate::net::SimpleInboundDatagram(socket)))
        .await
        .unwrap();
    let InboundTransport::Incoming(incoming) = transport else {
        panic!("not incoming");
    };

    let dns = DnsClient::new(
        &crate::config::Dns::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap()
    .into_shared();
    let crypto = client_crypto(Some(&cert.pem()), false, &alpns).unwrap();
    let tickets = crypto.get_session_cache();
    let client = Arc::new(Client::new(ClientOptions {
        server: "127.0.0.1".into(),
        port,
        tls: ClientTls {
            server_name: "localhost".into(),
            crypto,
        },
        uuid: UUID,
        password: PASSWORD.to_vec(),
        congestion: CongestionControl::Cubic,
        udp_relay_mode: UdpRelayMode::Native,
        zero_rtt: client_zero_rtt,
        heartbeat: Duration::from_secs(10),
        dns_client: dns,
        dial: Default::default(),
        tuning: &tuning,
    }));
    Fixture {
        client,
        incoming,
        tickets,
    }
}

impl Fixture {
    /// A `Connect` stream through the client, answered by the server: the
    /// request goes out as soon as the stream is open, before the
    /// handshake is done if the connection is resumed with 0-RTT.
    async fn round_trip(&mut self, n: u8) {
        let destination = SocksAddr::Domain("example.com".into(), 80);
        let sess = Session {
            destination: destination.clone(),
            ..Default::default()
        };
        let mut stream = StreamHandler(self.client.clone())
            .handle(&sess, None, None)
            .await
            .unwrap();
        stream.write_all(&[n; 4]).await.unwrap();

        let accepted = timeout(Duration::from_secs(5), self.incoming.next())
            .await
            .expect("no stream within 5s")
            .expect("server gone");
        let BaseInboundTransport::Stream(mut served, served_sess) = accepted else {
            panic!("not a stream");
        };
        assert_eq!(served_sess.destination, destination);
        let mut got = [0; 4];
        served.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [n; 4]);
        served.write_all(&[n + 1; 4]).await.unwrap();
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [n + 1; 4]);
    }

    /// Closes the client's connection, so that the next stream dials anew.
    async fn reconnect(&self) {
        let conn = self.client.current().await.expect("connected");
        conn.close(quinn::VarInt::from_u32(0), b"");
        conn.closed().await;
    }
}

/// Whether the client's connection was resumed with 0-RTT that the server
/// took: None if it was not resumed with 0-RTT, or the handshake has not
/// said yet.
async fn zero_rtt(client: &Client) -> Option<bool> {
    for _ in 0..50 {
        if let Some(accepted) = client.zero_rtt_accepted().await {
            return Some(accepted);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

impl Fixture {
    /// Whether the client holds a ticket for the server, waiting a while
    /// for one to come: the server sends it after the handshake.
    async fn has_ticket(&self) -> bool {
        let name = bytes::Bytes::from_static(b"localhost");
        for _ in 0..50 {
            if self.tickets.get(name.clone()).is_some() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }
}

// quinn-btls a3efed7 loses the server's NewSessionTicket, so the client
// never has a ticket to resume with. The server's `write_handshake` moves
// on to the Application level while quinn is still in the Handshake
// space (the 1-RTT keys cannot be built before the client's Finished);
// the ticket BoringSSL writes on the client's Finished then goes out with
// the 1-RTT keys in the same call, and quinn files it under the Handshake
// space, whose keys it discards right away. Passes with that fork holding
// Application data back until the 1-RTT keys are handed over.
#[tokio::test]
#[ignore = "quinn-btls a3efed7: the server's session ticket is lost"]
async fn zero_rtt_is_accepted_on_resumption() {
    let mut f = fixture(true, true).await;
    f.round_trip(1).await;
    // A new connection, with no ticket yet: a full handshake.
    assert_eq!(f.client.zero_rtt_accepted().await, None);
    assert!(f.has_ticket().await, "no session ticket from the server");
    f.reconnect().await;

    f.round_trip(3).await;
    assert_eq!(zero_rtt(&f.client).await, Some(true));
    // It stays resumable.
    f.reconnect().await;
    f.round_trip(5).await;
    assert_eq!(zero_rtt(&f.client).await, Some(true));
}

#[tokio::test]
async fn zero_rtt_refused_by_the_server_falls_back() {
    let mut f = fixture(false, true).await;
    f.round_trip(1).await;
    f.reconnect().await;
    // The server issues no early-data tickets, so there is nothing to
    // resume with 0-RTT; the stream gets through all the same.
    assert!(!f.has_ticket().await);
    f.round_trip(3).await;
    assert_eq!(f.client.zero_rtt_accepted().await, None);
}

#[tokio::test]
async fn zero_rtt_is_not_tried_unless_enabled() {
    let mut f = fixture(true, false).await;
    f.round_trip(1).await;
    f.reconnect().await;
    f.round_trip(3).await;
    assert_eq!(f.client.zero_rtt_accepted().await, None);
}

/// With `udp_over_stream`, a UDP session is a `Connect` stream to UoT's
/// magic address, speaking UoT v2, which the server hands on as a stream
/// like any other (dispatch serves it as UDP).
#[tokio::test]
async fn udp_over_stream_is_a_uot_stream() {
    use crate::transport::uot;

    let mut f = fixture(false, false).await;
    let handler = uot::datagram_handler(Arc::new(StreamHandler(f.client.clone())));
    let target = SocksAddr::from((std::net::Ipv4Addr::new(1, 2, 3, 4), 53));
    let sess = Session {
        network: crate::session::Network::Udp,
        destination: target.clone(),
        ..Default::default()
    };
    let datagram = handler.handle(&sess, None).await.unwrap();
    let (mut recv, mut send) = datagram.split();
    send.send_to(b"query", &target).await.unwrap();

    let accepted = timeout(Duration::from_secs(5), f.incoming.next())
        .await
        .expect("no stream within 5s")
        .expect("server gone");
    let BaseInboundTransport::Stream(mut served, served_sess) = accepted else {
        panic!("not a stream");
    };
    assert_eq!(uot::version(&served_sess.destination), Some(2));
    assert_eq!(
        uot::read_request(&mut served).await.unwrap(),
        (false, target.clone())
    );
    assert_eq!(uot::read_addr(&mut served).await.unwrap(), target);
    let mut buf = [0; 64];
    let n = uot::read_payload(&mut served, &mut buf).await.unwrap();
    assert_eq!(&buf[..n.unwrap()], b"query");

    let reply = uot::encode_packet(Some(&target), b"answer").unwrap();
    served.write_all(&reply).await.unwrap();
    let (n, from) = recv.recv_from(&mut buf).await.unwrap();
    assert_eq!((&buf[..n], from), (&b"answer"[..], target));
}
