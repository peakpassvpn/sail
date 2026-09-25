use std::{io, sync::Arc};

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
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        let a = &self.actors[self.selected.get()];
        match a.stream() {
            Ok(h) => return h.connect_addr(),
            _ => match a.datagram() {
                Ok(h) => return h.connect_addr(),
                _ => (),
            },
        }
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let i = self.selected.get();
        let a = &self.actors[i];
        tracing::debug!("selector handles to [{}]", a.tag());
        let stream = a.stream()?.handle(sess, lhs, stream).await?;
        Ok(match &self.interrupt {
            Some(selection) => super::super::interrupt::stream(stream, selection, i),
            None => stream,
        })
    }
}
