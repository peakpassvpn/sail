//! `hijack-dns`: the DNS queries a connection carries are answered by
//! sail's DNS client, as its DNS rules pick servers, instead of going where
//! they were sent. Over TCP, each message is prefixed with its length; over
//! UDP, each datagram is one.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

use crate::adapter::{OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
use crate::app::dns::LookupContext;
use crate::app::SyncDnsClient;
use crate::session::{Session, SocksAddr};

/// The answer to the DNS message `query`, which `sess` carried, as the DNS
/// rules pick its server; `None` when it is no DNS message.
pub(crate) async fn answer(dns: &SyncDnsClient, query: &[u8], sess: &Session) -> Option<Vec<u8>> {
    let ctx = LookupContext {
        inbound: Some(sess.inbound_tag.clone()),
        user: sess.user.clone(),
        ..Default::default()
    };
    match dns.load().exchange(query, &ctx).await {
        Ok(reply) => Some(reply),
        Err(e) => {
            debug!("hijack-dns: {}", e);
            None
        }
    }
}

/// Answers the length-prefixed DNS messages of a TCP connection until it
/// ends.
pub(crate) async fn serve_stream<S>(
    dns: &SyncDnsClient,
    mut stream: S,
    sess: &Session,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let len = match stream.read_u16().await {
            Ok(len) => len as usize,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;
        let Some(reply) = answer(dns, &query, sess).await else {
            return Ok(());
        };
        let mut framed = Vec::with_capacity(2 + reply.len());
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).await?;
        stream.flush().await?;
    }
}

/// Datagrams to DNS servers, answered in place: each query sent is
/// answered as from the address it was sent to.
pub(crate) struct Datagram {
    dns: SyncDnsClient,
    sess: Arc<Session>,
}

impl Datagram {
    pub(crate) fn new(dns: SyncDnsClient, sess: Session) -> Self {
        Datagram {
            dns,
            sess: Arc::new(sess),
        }
    }
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (tx, rx) = mpsc::channel(32);
        (
            Box::new(RecvHalf(rx)),
            Box::new(SendHalf {
                dns: self.dns,
                sess: self.sess,
                answers: tx,
            }),
        )
    }
}

struct RecvHalf(mpsc::Receiver<(Vec<u8>, SocksAddr)>);

#[async_trait]
impl OutboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (reply, from) = self
            .0
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "closed"))?;
        let n = reply.len().min(buf.len());
        buf[..n].copy_from_slice(&reply[..n]);
        Ok((n, from))
    }
}

struct SendHalf {
    dns: SyncDnsClient,
    sess: Arc<Session>,
    answers: mpsc::Sender<(Vec<u8>, SocksAddr)>,
}

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let (dns, sess, answers) = (self.dns.clone(), self.sess.clone(), self.answers.clone());
        let (query, target) = (buf.to_vec(), target.clone());
        // Answered apart, so that a slow query holds up none after it.
        tokio::spawn(async move {
            if let Some(reply) = answer(&dns, &query, &sess).await {
                let _ = answers.send((reply, target)).await;
            }
        });
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns_client::DnsClient;
    use crate::util::DnsMessageExt;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType};
    use std::net::IpAddr;
    use std::str::FromStr;

    fn dns(strategy: &str) -> SyncDnsClient {
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": { "strategy": strategy, "servers": [
                    { "type": "hosts", "predefined": {
                        "test.sail": ["127.0.0.1", "::1"],
                    } }
                ] },
            })
            .to_string(),
        )
        .unwrap();
        DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared()
    }

    fn query(name: &str, ty: RecordType) -> Vec<u8> {
        let mut m = Message::new(0, MessageType::Query, OpCode::Query);
        m.set_id(7)
            .set_recursion_desired(true)
            .add_query(Query::query(Name::from_str(name).unwrap(), ty));
        m.to_vec().unwrap()
    }

    fn addresses(reply: &[u8]) -> (ResponseCode, Vec<IpAddr>) {
        let m = Message::from_vec(reply).unwrap();
        assert_eq!(m.id(), 7);
        assert_eq!(m.message_type(), MessageType::Response);
        let ips = m
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                _ => None,
            })
            .collect();
        (m.response_code(), ips)
    }

    #[tokio::test]
    async fn queries_are_answered_as_the_dns_client_resolves() {
        let dns = dns("prefer_ipv4");
        let sess = Session::default();
        let a = answer(&dns, &query("test.sail.", RecordType::A), &sess)
            .await
            .unwrap();
        assert_eq!(
            addresses(&a),
            (ResponseCode::NoError, vec!["127.0.0.1".parse().unwrap()])
        );
        let aaaa = answer(&dns, &query("test.sail.", RecordType::AAAA), &sess)
            .await
            .unwrap();
        assert_eq!(
            addresses(&aaaa),
            (ResponseCode::NoError, vec!["::1".parse().unwrap()])
        );
        let missing = answer(&dns, &query("nowhere.sail.", RecordType::A), &sess)
            .await
            .unwrap();
        // A hosts server has no such name: NXDOMAIN, as in sing-box.
        assert_eq!(addresses(&missing).0, ResponseCode::NXDomain);
        // Any other type is answered too, by the server the rules pick; a
        // hosts server answers only addresses, and NXDOMAIN to the rest.
        let mx = answer(&dns, &query("test.sail.", RecordType::MX), &sess)
            .await
            .unwrap();
        assert_eq!(addresses(&mx), (ResponseCode::NXDomain, vec![]));
        assert!(answer(&dns, b"not dns", &sess).await.is_none());
    }

    #[tokio::test]
    async fn a_family_the_strategy_leaves_out_has_no_answers() {
        let dns = dns("ipv4_only");
        let aaaa = answer(
            &dns,
            &query("test.sail.", RecordType::AAAA),
            &Session::default(),
        )
        .await
        .unwrap();
        assert_eq!(addresses(&aaaa), (ResponseCode::NoError, vec![]));
    }

    #[tokio::test]
    async fn over_tcp_each_message_is_length_prefixed() {
        let dns = dns("prefer_ipv4");
        let (mut client, server) = tokio::io::duplex(4096);
        let task =
            tokio::spawn(async move { serve_stream(&dns, server, &Session::default()).await });
        for _ in 0..2 {
            let q = query("test.sail.", RecordType::A);
            client.write_u16(q.len() as u16).await.unwrap();
            client.write_all(&q).await.unwrap();
            let len = client.read_u16().await.unwrap() as usize;
            let mut reply = vec![0; len];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(
                addresses(&reply).1,
                vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
            );
        }
        drop(client);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn over_udp_answers_come_from_where_queries_went() {
        let datagram: Box<dyn OutboundDatagram> =
            Box::new(Datagram::new(dns("prefer_ipv4"), Session::default()));
        let (mut recv, mut send) = datagram.split();
        let server = SocksAddr::from(("8.8.8.8".parse::<IpAddr>().unwrap(), 53));
        send.send_to(&query("test.sail.", RecordType::A), &server)
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let (n, from) = recv.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, server);
        assert_eq!(
            addresses(&buf[..n]).1,
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }
}
