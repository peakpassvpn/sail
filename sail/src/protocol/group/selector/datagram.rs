use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;

use crate::app::outbound::selector::Selection;
use crate::{adapter::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub selected: Arc<Selection>,
    /// Set for `interrupt_exist_connections`.
    pub interrupt: Option<watch::Receiver<usize>>,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        let a = &self.actors[self.selected.get()];
        match a.datagram() {
            Ok(h) => return h.connect_addr(),
            _ => match a.stream() {
                Ok(h) => return h.connect_addr(),
                _ => (),
            },
        }
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        let a = &self.actors[self.selected.get()];
        a.datagram()
            .map(|x| x.transport_type())
            .unwrap_or(DatagramTransportType::Unknown)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        let i = self.selected.get();
        let a = &self.actors[i];
        tracing::debug!("selector handles to [{}]", a.tag());
        let datagram = a.datagram()?.handle(sess, transport).await?;
        Ok(match &self.interrupt {
            Some(selection) => super::super::interrupt::datagram(datagram, selection, i),
            None => datagram,
        })
    }
}
