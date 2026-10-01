use std::io;

use async_trait::async_trait;
use tracing::Instrument;

use crate::{adapter::*, session::Session};

use super::plan::Plan;

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        Plan::for_stream(&self.actors).dial
    }

    /// Every actor hears of it, for the connections it keeps. The chain's
    /// datagram handler has the same actors, and leaves it to this one.
    fn network_changed(&self, change: &crate::net::network::NetworkChange) {
        for actor in &self.actors {
            actor.network_changed(change);
        }
    }

    /// Runs each actor over what the one before it produced.
    ///
    /// The plan has already decided what each actor is told to reach; all that
    /// is left here is the I/O, in order, with each actor's failure named
    /// after it.
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        mut lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let plan = Plan::for_stream(&self.actors);
        let last = plan.last();
        let mut stream = stream;

        for stage in &plan.stages {
            // Only the actor that talks to the destination is shown the
            // client's side of the connection: it is the one that can read the
            // first payload and put it in its own handshake.
            let lhs = if stage.index == last {
                lhs.take()
            } else {
                None
            };
            let actor = &self.actors[stage.index];
            let handled = actor
                .stream()
                .map_err(|err| stage.error(err))?
                .handle(&stage.session(sess), lhs, stream.take())
                .instrument(sess.span())
                .await
                .map_err(|err| stage.error(err))?;
            stream.replace(handled);
        }

        stream.ok_or_else(|| io::Error::other("a chain with no actors carries nothing"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::net::network::{ChangeReason, NetworkChange};

    /// Counts the changes of network it hears of.
    #[derive(Default)]
    struct Heard(AtomicUsize);

    #[async_trait]
    impl OutboundStreamHandler for Heard {
        fn connect_addr(&self) -> OutboundConnect {
            OutboundConnect::Unknown
        }

        async fn handle<'a>(
            &'a self,
            _sess: &'a Session,
            _lhs: Option<&mut AnyStream>,
            _stream: Option<AnyStream>,
        ) -> io::Result<AnyStream> {
            Err(io::Error::other("not dialled here"))
        }

        fn network_changed(&self, _change: &NetworkChange) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The layers of an outbound, a chain, each hear of a change of
    /// network, once.
    #[test]
    fn each_actor_hears_of_a_change_of_network() {
        let heard: Vec<Arc<Heard>> = (0..2).map(|_| Arc::default()).collect();
        let actors = heard
            .iter()
            .map(|h| {
                crate::adapter::outbound::HandlerBuilder::default()
                    .tag("layer".into())
                    .stream_handler(h.clone())
                    .build()
            })
            .collect();
        let chain = crate::transport::layers::chain_outbound("t", actors).unwrap();
        chain.network_changed(&NetworkChange {
            generation: 1,
            reason: ChangeReason::HostPush,
            old: Default::default(),
            new: Default::default(),
        });
        for h in &heard {
            assert_eq!(h.0.load(Ordering::SeqCst), 1);
        }
    }
}
