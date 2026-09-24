use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use super::*;
use crate::net::DialOptions;

/// An outbound handler groups a TCP outbound handler and a UDP outbound
/// handler.
pub struct Handler {
    tag: String,
    stream_handler: Option<AnyOutboundStreamHandler>,
    datagram_handler: Option<AnyOutboundDatagramHandler>,
    is_direct: bool,
}

impl Handler {
    pub(self) fn new(
        tag: String,
        stream_handler: Option<AnyOutboundStreamHandler>,
        datagram_handler: Option<AnyOutboundDatagramHandler>,
        is_direct: bool,
    ) -> Arc<Self> {
        Arc::new(Handler {
            tag,
            stream_handler,
            datagram_handler,
            is_direct,
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
}

impl HandlerBuilder {
    pub fn new() -> Self {
        Self {
            tag: "".to_string(),
            stream_handler: None,
            datagram_handler: None,
            is_direct: false,
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

    pub fn build(self) -> AnyOutboundHandler {
        Handler::new(
            self.tag,
            self.stream_handler,
            self.datagram_handler,
            self.is_direct,
        )
    }
}

impl Default for HandlerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// `handler`, asking to have what it connects to dialled with `dial`.
///
/// Only requests of its own are marked: one it passes on from another
/// outbound, a group's member or a chain's actor, already carries that
/// outbound's options and keeps them.
pub fn with_dial(handler: AnyOutboundHandler, dial: Arc<DialOptions>) -> AnyOutboundHandler {
    let stream_handler = handler.stream().ok().map(|inner| {
        Arc::new(DialingStreamHandler {
            inner: inner.clone(),
            dial: dial.clone(),
        }) as AnyOutboundStreamHandler
    });
    let datagram_handler = handler.datagram().ok().map(|inner| {
        Arc::new(DialingDatagramHandler {
            inner: inner.clone(),
            dial: dial.clone(),
        }) as AnyOutboundDatagramHandler
    });
    Handler::new(
        handler.tag().clone(),
        stream_handler,
        datagram_handler,
        handler.is_direct(),
    )
}

fn attach(connect: OutboundConnect, dial: &Arc<DialOptions>) -> OutboundConnect {
    match connect {
        OutboundConnect::Proxy(..) | OutboundConnect::Direct => {
            OutboundConnect::Dial(Box::new(connect), dial.clone())
        }
        other => other,
    }
}

struct DialingStreamHandler {
    inner: AnyOutboundStreamHandler,
    dial: Arc<DialOptions>,
}

#[async_trait]
impl OutboundStreamHandler for DialingStreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        attach(self.inner.connect_addr(), &self.dial)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        self.inner.handle(sess, lhs, stream).await
    }
}

struct DialingDatagramHandler {
    inner: AnyOutboundDatagramHandler,
    dial: Arc<DialOptions>,
}

#[async_trait]
impl OutboundDatagramHandler for DialingDatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        attach(self.inner.connect_addr(), &self.dial)
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.inner.transport_type()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        self.inner.handle(sess, transport).await
    }
}
