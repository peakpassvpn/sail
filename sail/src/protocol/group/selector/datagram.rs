use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;

use crate::app::outbound::selector::Selection;
use crate::protocol::group::members::{MemberKey, Members};
use crate::{adapter::*, session::Session};

pub struct Handler {
    pub members: Arc<Members>,
    pub selected: Arc<Selection>,
    /// Set for `interrupt_exist_connections`.
    pub interrupt: Option<watch::Receiver<MemberKey>>,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        let snapshot = self.members.load();
        let Some((i, _)) = self.selected.pick(&snapshot) else {
            return OutboundConnect::Unknown;
        };
        let a = &snapshot.members[i].handler;
        if let Ok(h) = a.datagram() {
            return h.connect_addr();
        }
        if let Ok(h) = a.stream() {
            return h.connect_addr();
        }
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        let snapshot = self.members.load();
        let Some((i, _)) = self.selected.pick(&snapshot) else {
            return DatagramTransportType::Unknown;
        };
        snapshot.members[i]
            .handler
            .datagram()
            .map(|x| x.transport_type())
            .unwrap_or(DatagramTransportType::Unknown)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        let snapshot = self.members.load();
        let (member, by) = super::pick(&snapshot, &self.selected, self.interrupt.is_some())?;
        let a = &member.handler;
        tracing::debug!("selector handles to [{}]", a.tag());
        let datagram = a.datagram()?.handle(sess, transport).await?;
        // By its name: members alike share one handler, and its tag.
        sess.chain.push(&member.key.name);
        Ok(match (&self.interrupt, by) {
            (Some(selection), Some(by)) => {
                super::super::interrupt::datagram(datagram, selection, by)
            }
            _ => datagram,
        })
    }
}
