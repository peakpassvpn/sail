use std::io;

use async_trait::async_trait;
use futures::future::select_ok;
use tracing::debug;

use crate::{adapter::*, app::SyncDnsClient, session::Session};

struct HandleResult {
    idx: usize,
    stream: AnyStream,
}

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    /// Their tags, as the group names them: members alike share one
    /// handler, and its tag.
    pub tags: Vec<String>,
    pub delay_base: u32,
    pub dns_client: SyncDnsClient,
    /// Where its members' failures are told.
    pub events: crate::control::events::EventHub,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let attempts = super::Attempts::new(sess, self.actors.len());
        let mut tasks = Vec::new();
        for (i, a) in self.actors.iter().enumerate() {
            let attempts = &attempts;
            let t = async move {
                if self.delay_base > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        (self.delay_base * i as u32) as u64,
                    ))
                    .await;
                }
                let at = attempts.session(sess, i, &self.tags[i]);
                match crate::net::dial_domain::stream(&at, self.dns_client.clone(), a).await {
                    Ok(stream) => Ok(HandleResult { idx: i, stream }),
                    Err(e) => {
                        attempts.failed(&self.events, i, &at, &e);
                        Err(e)
                    }
                }
            };
            tasks.push(Box::pin(t));
        }
        let result = select_ok(tasks).await;
        attempts.done(sess, result.as_ref().ok().map(|v| v.0.idx));
        match result {
            Ok(v) => {
                debug!(
                    "tryall handles [{}:{}] to [{}]",
                    sess.network,
                    sess.destination,
                    self.actors[v.0.idx].tag()
                );
                Ok(v.0.stream)
            }
            Err(e) => Err(io::Error::other(format!(
                "all outbound attempts failed, last error: {}",
                e
            ))),
        }
    }
}
