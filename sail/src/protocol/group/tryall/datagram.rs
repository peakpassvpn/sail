use std::io;

use async_trait::async_trait;
use futures::future::select_ok;
use tracing::debug;

use crate::{adapter::*, app::SyncDnsClient, session::Session};

struct HandleResult {
    idx: usize,
    dgram: AnyOutboundDatagram,
}

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    /// Their tags, as the group names them: members alike share one
    /// handler, and its tag.
    pub tags: Vec<String>,
    pub delay_base: u32,
    pub dns_client: SyncDnsClient,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        let mut tasks = Vec::new();
        for (i, a) in self.actors.iter().enumerate() {
            let t = async move {
                if self.delay_base > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        (self.delay_base * i as u32) as u64,
                    ))
                    .await;
                }
                crate::net::dial_domain::datagram_through(sess, self.dns_client.clone(), a)
                    .await
                    .map(|dgram| HandleResult { idx: i, dgram })
            };
            tasks.push(Box::pin(t));
        }
        match select_ok(tasks).await {
            Ok(v) => {
                debug!(
                    "tryall handles [{}:{}] to [{}]",
                    sess.network,
                    sess.destination,
                    self.actors[v.0.idx].tag()
                );
                sess.chain.push(&self.tags[v.0.idx]);
                Ok(v.0.dgram)
            }
            Err(e) => Err(io::Error::other(format!(
                "all outbound attempts failed, last error: {}",
                e
            ))),
        }
    }
}
