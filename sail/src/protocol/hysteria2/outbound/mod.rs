//! The Hysteria2 outbound: TCP as QUIC streams and UDP as QUIC datagrams
//! over one authenticated connection to the server.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::sync::mpsc;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::*;
use crate::net::peek_tcp_one_off;
use crate::session::{Session, SocksAddr};
use crate::transport::layers::{Blocks, Listable, OutboundTls};
use crate::transport::{self, quic::ClientTls};

use super::hop;
use super::proto::MBPS_TO_BPS;
use super::quic;
use super::Obfs;

mod client;

use client::{Client, ClientOptions, Packet, UdpSession};

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "hysteria2",
        OutboundFactory::standalone(build).with_blocks(Blocks::DIALER),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hysteria2OutboundOptions {
    server: String,
    /// The one port; with `server_ports`, not needed.
    #[serde(default)]
    server_port: Option<u16>,
    /// Ports or ranges ("20000:30000") to hop between.
    #[serde(default)]
    server_ports: Option<Listable>,
    /// How often to hop, 30s unless set.
    #[serde(default, with = "crate::config::model::duration")]
    hop_interval: Option<Duration>,
    /// What we may send at; set, it selects Brutal.
    #[serde(default)]
    up_mbps: Option<u64>,
    /// What we can receive at, told to the server.
    #[serde(default)]
    down_mbps: Option<u64>,
    #[serde(default)]
    obfs: Option<Obfs>,
    password: String,
    tls: OutboundTls,
    /// "tcp" or "udp", or both, as unset.
    #[serde(default)]
    network: Option<Listable>,
}

const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);
/// sing-box's floor for `hop_interval`.
const MIN_HOP_INTERVAL: Duration = Duration::from_secs(5);

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: Hysteria2OutboundOptions = ctx.options()?;
    let tag = ctx.tag.to_owned();
    let err = |msg: String| anyhow!("[{}] outbound: {}", tag, msg);

    let ports = match (&options.server_ports, options.server_port) {
        (Some(ports), _) => hop::parse_ports(&ports.clone().into_vec())
            .map_err(|e| err(format!("server_ports: {}", e)))?,
        (None, Some(port)) => vec![port],
        (None, None) => return Err(err("server_port: missing".into())),
    };
    let hop_interval = match options.hop_interval {
        Some(interval) if interval < MIN_HOP_INTERVAL => {
            return Err(err(format!(
                "hop_interval: at least {:?}",
                MIN_HOP_INTERVAL
            )))
        }
        Some(interval) => Some(interval),
        None if ports.len() > 1 => Some(DEFAULT_HOP_INTERVAL),
        None => None,
    };

    let tls = options.tls;
    if !tls.enabled {
        return Err(err("tls: hysteria2 needs tls enabled".into()));
    }
    if let Some(field) = transport::quic::unsupported(&tls) {
        return Err(err(format!("tls.{}: not supported over QUIC", field)));
    }
    if tls.certificate.is_some() && tls.certificate_path.is_some() {
        return Err(err(
            "tls: set at most one of certificate and certificate_path".into(),
        ));
    }
    let client_tls = ClientTls::new(&tls, &options.server, quic::DEFAULT_ALPN, ctx.env)
        .map_err(|e| err(format!("tls: {}", e)))?;

    let obfs = options
        .obfs
        .map(|o| o.salamander())
        .transpose()
        .map_err(|e| err(format!("obfs: {}", e)))?;

    let (mut tcp, mut udp) = (true, true);
    if let Some(network) = options.network {
        (tcp, udp) = (false, false);
        for n in network.into_vec() {
            match n.as_str() {
                "tcp" => tcp = true,
                "udp" => udp = true,
                other => return Err(err(format!("network: unknown network \"{}\"", other))),
            }
        }
    }

    let client = Arc::new(Client::new(ClientOptions {
        server_name: client_tls.server_name,
        server: options.server,
        ports,
        hop_interval,
        password: options.password,
        send_bps: options.up_mbps.unwrap_or(0) * MBPS_TO_BPS,
        recv_bps: options.down_mbps.unwrap_or(0) * MBPS_TO_BPS,
        obfs,
        crypto: Arc::new(client_tls.crypto),
        tuning: ctx.env.options.quic.clone(),
        dns_client: ctx.dns_client.clone(),
        dialer: ctx.dialer.clone(),
    }));

    let mut builder = HandlerBuilder::default().tag(ctx.tag.to_owned());
    if tcp {
        builder = builder.stream_handler(Arc::new(StreamHandler(client.clone())));
    }
    if udp {
        builder = builder.datagram_handler(Arc::new(DatagramHandler(client)));
    }
    Ok(builder.build())
}

struct StreamHandler(Arc<Client>);

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let payload = peek_tcp_one_off(lhs).await;
        let stream = self.0.open_stream(sess, &payload).await?;
        Ok(Box::new(stream))
    }

    fn network_changed(&self, _change: &crate::net::network::NetworkChange) {
        self.0.network_changed();
    }
}

struct DatagramHandler(Arc<Client>);

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let conn = self.0.connection().await?;
        let (session, rx) = conn.open_session()?;
        conn.bound.onto(sess);
        Ok(Box::new(Datagram {
            session: Arc::new(session),
            rx,
        }))
    }

    fn network_changed(&self, _change: &crate::net::network::NetworkChange) {
        self.0.network_changed();
    }
}

struct Datagram {
    session: Arc<UdpSession>,
    rx: mpsc::Receiver<Packet>,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf {
                rx: self.rx,
                _session: self.session.clone(),
            }),
            Box::new(DatagramSendHalf(Some(self.session))),
        )
    }
}

struct DatagramRecvHalf {
    rx: mpsc::Receiver<Packet>,
    /// Keeps the session registered while either half lives.
    _session: Arc<UdpSession>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (packet, from) = self
            .rx
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        if packet.len() > buf.len() {
            return Err(io::Error::other(format!(
                "hysteria2: UDP packet of {} bytes, buffer of {}",
                packet.len(),
                buf.len()
            )));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), from))
    }
}

struct DatagramSendHalf(Option<Arc<UdpSession>>);

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let session = self
            .0
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        session.send(buf, target)?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0 = None;
        Ok(())
    }
}

#[cfg(all(test, feature = "inbound-hysteria2"))]
mod tests {
    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    use super::super::h3;
    use super::super::inbound::masquerade::Masquerade;
    use super::super::inbound::server::{DatagramHandler as ServerHandler, Server};
    use super::super::proto;
    use super::*;
    use crate::net::network::{ChangeReason, NetworkChange};
    use crate::transport::quic::{alpn_protocols, client_crypto, server_config, server_crypto};

    /// A client of a server in process, and what the server accepts.
    async fn fixture() -> (Arc<Client>, AnyIncomingTransport) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let alpns = alpn_protocols(None, quic::DEFAULT_ALPN);
        let crypto = server_crypto(&cert.pem(), &key_pair.serialize_pem(), &alpns).unwrap();
        let server = Arc::new(Server {
            tag: "hy2".into(),
            users: [("pw".to_string(), None)].into(),
            send_bps: 0,
            recv_bps: 0,
            ignore_client_bandwidth: false,
            masquerade: Masquerade::NotFound,
            handshake_timeout: Duration::from_secs(5),
            tuning: Default::default(),
        });
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let transport = ServerHandler::new(server_config(crypto).unwrap(), None, server)
            .handle(Box::new(crate::net::SimpleInboundDatagram(socket)))
            .await
            .unwrap();
        let InboundTransport::Incoming(incoming) = transport else {
            panic!("not incoming");
        };
        (client_to(port, &cert.pem()), incoming)
    }

    /// A client of a server on `port` of 127.0.0.1 with the certificate
    /// `cert`.
    fn client_to(port: u16, cert: &str) -> Arc<Client> {
        let alpns = alpn_protocols(None, quic::DEFAULT_ALPN);
        let dns = crate::app::dns::DnsClient::new(
            &crate::config::Dns::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let crypto = client_crypto(
            Some(cert),
            false,
            &alpns,
            &crate::transport::tls::tests::test_roots(),
        )
        .unwrap();
        Arc::new(Client::new(ClientOptions {
            server: "127.0.0.1".into(),
            ports: vec![port],
            hop_interval: None,
            password: "pw".into(),
            send_bps: 0,
            recv_bps: 0,
            obfs: None,
            server_name: "localhost".into(),
            crypto: Arc::new(crypto),
            tuning: Default::default(),
            dns_client: dns,
            dialer: crate::net::Dialer::system(),
        }))
    }

    /// A stand-in for Mihomo's server, whose sing-quic service answers a
    /// stream's TCPRequest only along with the first data it sends back,
    /// as HandshakeSuccess is never called: on 127.0.0.1, with its port
    /// and certificate.
    fn withholding_server() -> (quinn::Endpoint, u16, String) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let alpns = alpn_protocols(None, quic::DEFAULT_ALPN);
        let crypto = server_crypto(&cert.pem(), &key_pair.serialize_pem(), &alpns).unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let endpoint =
            crate::transport::quic::endpoint(socket, Some(server_config(crypto).unwrap())).unwrap();
        (endpoint, port, cert.pem())
    }

    /// Serves one stream on `endpoint`: authenticates the client, reads
    /// its TCPRequest and then `ask`, and only then answers, with
    /// `response` and `reply` together. What it returns keeps the stream.
    async fn withhold(
        endpoint: &quinn::Endpoint,
        ask: &[u8],
        response: bytes::BytesMut,
        reply: &[u8],
    ) -> (quinn::Connection, quinn::SendStream) {
        let conn = endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        h3::read_headers(&mut recv, None).await.unwrap();
        let status = proto::STATUS_AUTH_OK.to_string();
        h3::write_headers(&mut send, &[(":status", &status)])
            .await
            .unwrap();
        send.finish().unwrap();

        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        assert_eq!(
            proto::read_varint(&mut recv).await.unwrap(),
            proto::FRAME_TYPE_TCP_REQUEST
        );
        proto::read_tcp_request(&mut recv).await.unwrap();
        let mut got = vec![0; ask.len()];
        recv.read_exact(&mut got).await.unwrap();
        assert_eq!(got, ask);
        let mut answer = response.to_vec();
        answer.extend_from_slice(reply);
        send.write_all(&answer).await.unwrap();
        (conn, send)
    }

    /// Against a server that answers only along with its first data, the
    /// stream is there at once: what the client sends first goes out
    /// before the answer, and the answer comes ahead of the data.
    #[tokio::test]
    async fn an_upload_first_stream_needs_no_answer_before_its_first_read() {
        let (endpoint, port, cert) = withholding_server();
        let client = client_to(port, &cert);
        let server = withhold(&endpoint, b"ping", proto::tcp_response(true, ""), b"pong");
        let exchange = async {
            let mut stream = StreamHandler(client.clone())
                .handle(&session(), None, None)
                .await
                .expect("a stream before any answer");
            stream.write_all(b"ping").await.unwrap();
            let mut got = [0; 4];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"pong");
        };
        let (_kept, ()) = timeout(Duration::from_secs(10), async {
            tokio::join!(server, exchange)
        })
        .await
        .expect("no exchange within 10s");
    }

    /// A server's refusal fails the stream's first read, with its message.
    #[tokio::test]
    async fn a_refusal_fails_the_first_read() {
        let (endpoint, port, cert) = withholding_server();
        let client = client_to(port, &cert);
        let server = withhold(
            &endpoint,
            b"ping",
            proto::tcp_response(false, "no route"),
            b"",
        );
        let exchange = async {
            let mut stream = StreamHandler(client.clone())
                .handle(&session(), None, None)
                .await
                .expect("a stream before any answer");
            stream.write_all(b"ping").await.unwrap();
            let mut got = [0; 4];
            let err = stream.read(&mut got).await.unwrap_err();
            assert!(err.to_string().contains("no route"), "{}", err);
            // And so does every read after it.
            assert!(stream.read(&mut got).await.is_err());
        };
        let (_kept, ()) = timeout(Duration::from_secs(10), async {
            tokio::join!(server, exchange)
        })
        .await
        .expect("no exchange within 10s");
    }

    fn session() -> Session {
        Session {
            destination: SocksAddr::Domain("example.com".into(), 80),
            ..Default::default()
        }
    }

    /// A stream through the client, and the server's end of it.
    async fn stream(
        client: &Arc<Client>,
        incoming: &mut AnyIncomingTransport,
    ) -> (AnyStream, AnyStream) {
        stream_for(client, incoming, &session()).await
    }

    /// A stream through the client for `sess`, and the server's end of it.
    async fn stream_for(
        client: &Arc<Client>,
        incoming: &mut AnyIncomingTransport,
        sess: &Session,
    ) -> (AnyStream, AnyStream) {
        let stream = StreamHandler(client.clone())
            .handle(sess, None, None)
            .await
            .unwrap();
        let accepted = timeout(Duration::from_secs(5), incoming.next())
            .await
            .expect("no stream within 5s")
            .expect("server gone");
        let BaseInboundTransport::Stream(served, _) = accepted else {
            panic!("not a stream");
        };
        (stream, served)
    }

    fn change(generation: u64) -> NetworkChange {
        NetworkChange {
            generation,
            reason: ChangeReason::DefaultInterface,
            old: Arc::default(),
            new: Arc::default(),
        }
    }

    /// Every stream and UDP session on the connection, which none of them
    /// dialled, goes out where it does.
    #[tokio::test]
    async fn what_the_connection_carries_goes_out_where_it_does() {
        use crate::net::dial::{BoundInterface, Egress};
        let (client, mut incoming) = fixture().await;
        let (first, second) = (session(), session());
        let _first = stream_for(&client, &mut incoming, &first).await;
        let _second = stream_for(&client, &mut incoming, &second).await;
        let udp = Session {
            network: crate::session::Network::Udp,
            ..session()
        };
        let _udp = DatagramHandler(client.clone())
            .handle(&udp, None)
            .await
            .unwrap();
        for sess in [&first, &second, &udp] {
            assert_eq!(
                sess.state.get::<BoundInterface>().get(),
                Some(Egress::DefaultRoute)
            );
        }
    }

    #[tokio::test]
    async fn a_network_change_closes_the_connection() {
        let (client, mut incoming) = fixture().await;
        let (mut open, mut served) = stream(&client, &mut incoming).await;
        open.write_all(b"ping").await.unwrap();
        let mut got = [0; 4];
        served.read_exact(&mut got).await.unwrap();
        let old = client.current().expect("connected");
        let (session, mut rx) = client.connection().await.unwrap().open_session().unwrap();

        // Both handlers hear of it, as an outbound's do.
        StreamHandler(client.clone()).network_changed(&change(1));
        DatagramHandler(client.clone()).network_changed(&change(1));

        assert!(matches!(
            old.close_reason(),
            Some(quinn::ConnectionError::LocallyClosed)
        ));
        assert!(client.current().is_none());
        assert!(open.read(&mut got).await.is_err());
        assert!(session
            .send(b"x", &SocksAddr::Domain("example.com".into(), 53))
            .is_err());
        let ended = timeout(Duration::from_secs(5), rx.recv()).await.unwrap();
        assert!(ended.is_none());

        // The next stream dials anew.
        let (mut open, mut served) = stream(&client, &mut incoming).await;
        assert_ne!(client.current().unwrap().stable_id(), old.stable_id());
        open.write_all(b"pong").await.unwrap();
        served.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");
    }
}
