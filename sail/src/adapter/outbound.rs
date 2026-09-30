use std::io;
use std::sync::Arc;

use super::*;

/// An outbound handler groups a TCP outbound handler and a UDP outbound
/// handler.
pub struct Handler {
    tag: String,
    stream_handler: Option<AnyOutboundStreamHandler>,
    datagram_handler: Option<AnyOutboundDatagramHandler>,
    is_direct: bool,
    is_pass: bool,
}

impl Handler {
    pub(self) fn new(
        tag: String,
        stream_handler: Option<AnyOutboundStreamHandler>,
        datagram_handler: Option<AnyOutboundDatagramHandler>,
        is_direct: bool,
        is_pass: bool,
    ) -> Arc<Self> {
        Arc::new(Handler {
            tag,
            stream_handler,
            datagram_handler,
            is_direct,
            is_pass,
        })
    }
}

impl BaseHandler for Handler {}

impl OutboundHandler for Handler {
    fn stream(&self) -> io::Result<&AnyOutboundStreamHandler> {
        self.stream_handler
            .as_ref()
            .ok_or_else(|| io::Error::other("no tcp handler"))
    }

    fn datagram(&self) -> io::Result<&AnyOutboundDatagramHandler> {
        self.datagram_handler
            .as_ref()
            .ok_or_else(|| io::Error::other("no udp handler"))
    }

    fn is_direct(&self) -> bool {
        self.is_direct
    }

    fn is_pass(&self) -> bool {
        self.is_pass
    }

    /// Both its handlers hear of it; one that is both hears twice.
    fn network_changed(&self, change: &crate::net::network::NetworkChange) {
        if let Some(stream) = &self.stream_handler {
            stream.network_changed(change);
        }
        if let Some(datagram) = &self.datagram_handler {
            datagram.network_changed(change);
        }
    }
}

impl Tag for Handler {
    fn tag(&self) -> &String {
        &self.tag
    }
}

pub struct HandlerBuilder {
    tag: String,
    stream_handler: Option<AnyOutboundStreamHandler>,
    datagram_handler: Option<AnyOutboundDatagramHandler>,
    is_direct: bool,
    is_pass: bool,
}

impl HandlerBuilder {
    pub fn new() -> Self {
        Self {
            tag: "".to_string(),
            stream_handler: None,
            datagram_handler: None,
            is_direct: false,
            is_pass: false,
        }
    }

    pub fn tag(mut self, v: String) -> Self {
        self.tag = v;
        self
    }

    pub fn stream_handler(mut self, v: AnyOutboundStreamHandler) -> Self {
        self.stream_handler.replace(v);
        self
    }

    pub fn datagram_handler(mut self, v: AnyOutboundDatagramHandler) -> Self {
        self.datagram_handler.replace(v);
        self
    }

    pub fn is_direct(mut self, v: bool) -> Self {
        self.is_direct = v;
        self
    }

    /// Marks a `pass` outbound, see `OutboundHandler::is_pass`.
    pub fn is_pass(mut self, v: bool) -> Self {
        self.is_pass = v;
        self
    }

    pub fn build(self) -> AnyOutboundHandler {
        Handler::new(
            self.tag,
            self.stream_handler,
            self.datagram_handler,
            self.is_direct,
            self.is_pass,
        )
    }
}

impl Default for HandlerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::net::network::{ChangeReason, NetworkChange};

    /// Counts the changes it hears of.
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

    /// An outbound's handlers hear of a change of network.
    #[test]
    fn a_change_of_network_reaches_the_protocol() {
        let heard = Arc::new(Heard::default());
        let handler = HandlerBuilder::default()
            .tag("t".into())
            .stream_handler(heard.clone())
            .build();
        let change = NetworkChange {
            generation: 1,
            reason: ChangeReason::HostPush,
            old: Default::default(),
            new: Default::default(),
        };
        handler.network_changed(&change);
        assert_eq!(heard.0.load(Ordering::SeqCst), 1);
    }
}
