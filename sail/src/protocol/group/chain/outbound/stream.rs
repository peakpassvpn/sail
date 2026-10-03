use std::io;

use async_trait::async_trait;
use tracing::Instrument;

use crate::{adapter::*, session::Session};

use super::plan::{dialing, Plan};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        Plan::for_stream(&self.actors).dial
    }

    /// The actors the dial is for hear of it; the others, each before its
    /// part of `handle`.
    fn dialing(&self, sess: &Session) {
        let plan = Plan::for_stream(&self.actors);
        for stage in &plan.stages[..plan.dialled] {
            dialing(&self.actors[stage.index], stage.kind, sess);
        }
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
            let at = stage.session(sess);
            if stage.index >= plan.dialled {
                dialing(actor, stage.kind, &at);
            }
            let handled = actor
                .stream()
                .map_err(|err| stage.error(err))?
                .handle(&at, lhs, stream.take())
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

    /// A hop that adds its name to the chain where a group would, and carries
    /// what it is handed.
    struct Hop(&'static str);

    #[async_trait]
    impl OutboundStreamHandler for Hop {
        fn connect_addr(&self) -> OutboundConnect {
            OutboundConnect::Unknown
        }

        fn dialing(&self, sess: &Session) {
            sess.chain.push(self.0);
        }

        async fn handle<'a>(
            &'a self,
            _sess: &'a Session,
            _lhs: Option<&mut AnyStream>,
            stream: Option<AnyStream>,
        ) -> io::Result<AnyStream> {
            Ok(stream.unwrap_or_else(|| Box::new(tokio::io::duplex(1).0)))
        }
    }

    /// A group in a hop, a selector, adds its member to the chain as it
    /// would on its own: the one the dial is for before the dial, the
    /// others before their part, in order.
    #[tokio::test]
    async fn a_group_in_a_hop_adds_its_member_in_order() {
        let actors = ["a", "b"]
            .into_iter()
            .map(|name| {
                crate::adapter::outbound::HandlerBuilder::default()
                    .tag(name.into())
                    .stream_handler(Arc::new(Hop(name)))
                    .build()
            })
            .collect();
        let chain = crate::transport::layers::chain_outbound("t", actors).unwrap();
        let sess = Session::default();
        let th = chain.stream().unwrap();
        th.dialing(&sess);
        assert_eq!(sess.chain.get(), ["a"]);
        th.handle(&sess, None, None).await.unwrap();
        assert_eq!(sess.chain.get(), ["a", "b"]);
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
