use std::{io, sync::Arc};

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
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        let snapshot = self.members.load();
        let Some((i, _)) = self.selected.pick(&snapshot) else {
            return OutboundConnect::Unknown;
        };
        let a = &snapshot.members[i].handler;
        if let Ok(h) = a.stream() {
            return h.connect_addr();
        }
        if let Ok(h) = a.datagram() {
            return h.connect_addr();
        }
        OutboundConnect::Unknown
    }

    /// The dial is the member's, as `connect_addr` is: the member goes
    /// into the chain before it, a selector in it adding its own.
    fn dialing(&self, sess: &Session) {
        let snapshot = self.members.load();
        let Some((i, _)) = self.selected.pick(&snapshot) else {
            return;
        };
        let member = &snapshot.members[i];
        // By its name: members alike share one handler, and its tag.
        sess.chain.push(&member.key.name);
        if let Ok(h) = member.handler.stream() {
            h.dialing(sess);
        } else if let Ok(h) = member.handler.datagram() {
            h.dialing(sess);
        }
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let snapshot = self.members.load();
        let (member, by) = super::pick(&snapshot, &self.selected, self.interrupt.is_some())?;
        let a = &member.handler;
        tracing::debug!("selector handles to [{}]", a.tag());
        // In the chain already, from `dialing`.
        let stream = a.stream()?.handle(sess, lhs, stream).await?;
        Ok(match (&self.interrupt, by) {
            (Some(selection), Some(by)) => super::super::interrupt::stream(stream, selection, by),
            _ => stream,
        })
    }
}
