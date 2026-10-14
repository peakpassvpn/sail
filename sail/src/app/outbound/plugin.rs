use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::sync::Arc;

use async_ffi::{BorrowingFfiFuture, FutureExt};
use async_trait::async_trait;
use libloading::Library;

use anyhow::{anyhow, Result};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use serde_derive::Deserialize;

use crate::net::Dialer;
use crate::{
    adapter::*,
    session::{Network, Session},
};

pub struct PluginSpec {
    pub add_handler_fn: unsafe fn(&mut dyn PluginRegistrar, &str, args: &str),
}

pub trait PluginRegistrar {
    fn add_handler(
        &mut self,
        tag: &str,
        stream_handler: AnyExternalOutboundStreamHandler,
        datagram_handler: AnyExternalOutboundDatagramHandler,
    );
}

/// What a plugin's handler asks to have dialled, which the plugin
/// outbound's dialer dials.
#[derive(Debug, Clone)]
pub enum PluginConnect {
    /// Its server.
    Proxy(Network, String, u16),
    /// The session's destination.
    Direct,
}

impl PluginConnect {
    /// The request, to be dialled by `dialer`.
    fn dialled_by(self, dialer: &Dialer) -> OutboundConnect {
        match self {
            PluginConnect::Proxy(network, address, port) => {
                OutboundConnect::Proxy(network, address, port, dialer.clone())
            }
            PluginConnect::Direct => OutboundConnect::Direct(dialer.clone()),
        }
    }
}

pub trait ExternalOutboundStreamHandler: Send + Sync + Unpin {
    fn connect_addr(&self) -> Option<PluginConnect>;

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>>;

    /// `handle`, with `first`, what the client sent before the stream was
    /// asked for (up to 10 ms of it, as the built-in outbounds wait): to go
    /// out with the plugin's own header, as a built-in outbound sends its
    /// own. By default it is written after `handle`, as the next write.
    fn handle_first<'a>(
        &'a self,
        sess: &'a Session,
        first: Vec<u8>,
        stream: Option<AnyStream>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>> {
        async move {
            let mut stream = self.handle(sess, stream).await?;
            if !first.is_empty() {
                tokio::io::AsyncWriteExt::write_all(&mut stream, &first).await?;
            }
            Ok(stream)
        }
        .into_ffi()
    }
}
pub type AnyExternalOutboundStreamHandler = Arc<dyn ExternalOutboundStreamHandler>;

pub trait ExternalOutboundDatagramHandler: Send + Sync + Unpin {
    fn connect_addr(&self) -> Option<PluginConnect>;

    fn transport_type(&self) -> DatagramTransportType;

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyOutboundDatagram>>;
}

struct PluginRegistrarImpl {
    stream_handlers: HashMap<String, OutboundStreamHandlerProxy>,
    datagram_handlers: HashMap<String, OutboundDatagramHandlerProxy>,
    lib: Arc<Library>,
}

impl PluginRegistrarImpl {
    fn new(lib: Arc<Library>) -> Self {
        Self {
            lib,
            stream_handlers: HashMap::new(),
            datagram_handlers: HashMap::new(),
        }
    }
}

impl PluginRegistrar for PluginRegistrarImpl {
    fn add_handler(
        &mut self,
        tag: &str,
        stream_handler: AnyExternalOutboundStreamHandler,
        datagram_handler: AnyExternalOutboundDatagramHandler,
    ) {
        let tcp_proxy = OutboundStreamHandlerProxy {
            handler: stream_handler,
            _lib: Arc::clone(&self.lib),
        };
        let udp_proxy = OutboundDatagramHandlerProxy {
            handler: datagram_handler,
            _lib: Arc::clone(&self.lib),
        };
        self.stream_handlers.insert(tag.to_string(), tcp_proxy);
        self.datagram_handlers.insert(tag.to_string(), udp_proxy);
    }
}

pub struct OutboundStreamHandlerProxy {
    handler: AnyExternalOutboundStreamHandler,
    _lib: Arc<Library>,
}

impl OutboundStreamHandlerProxy {
    fn get_handler(&self) -> AnyExternalOutboundStreamHandler {
        self.handler.clone()
    }
}

impl ExternalOutboundStreamHandler for OutboundStreamHandlerProxy {
    fn connect_addr(&self) -> Option<PluginConnect> {
        self.handler.connect_addr()
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>> {
        self.handler.handle(sess, stream)
    }

    fn handle_first<'a>(
        &'a self,
        sess: &'a Session,
        first: Vec<u8>,
        stream: Option<AnyStream>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>> {
        self.handler.handle_first(sess, first, stream)
    }
}

pub struct OutboundDatagramHandlerProxy {
    handler: AnyExternalOutboundDatagramHandler,
    _lib: Arc<Library>,
}

impl OutboundDatagramHandlerProxy {
    fn get_handler(&self) -> AnyExternalOutboundDatagramHandler {
        self.handler.clone()
    }
}

impl ExternalOutboundDatagramHandler for OutboundDatagramHandlerProxy {
    fn connect_addr(&self) -> Option<PluginConnect> {
        self.handler.connect_addr()
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.handler.transport_type()
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyOutboundDatagram>> {
        self.handler.handle(sess, transport)
    }
}

pub type AnyExternalOutboundDatagramHandler = Arc<dyn ExternalOutboundDatagramHandler>;

#[derive(Default)]
pub struct ExternalHandlers {
    stream_handlers: HashMap<String, OutboundStreamHandlerProxy>,
    datagram_handlers: HashMap<String, OutboundDatagramHandlerProxy>,
    libraries: HashMap<String, Arc<Library>>,
}

impl ExternalHandlers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads the plugin library at `path` and registers its handlers for `tag`.
    ///
    /// # Safety
    ///
    /// `path` must be a sail plugin built against this version of sail: its
    /// `plugin_spec` symbol is read and called as a `PluginSpec`, and nothing
    /// checks that it is one.
    pub unsafe fn new_handler<P>(&mut self, path: P, tag: &str, args: &str) -> io::Result<()>
    where
        P: AsRef<OsStr> + ToString + Clone,
    {
        let lib = if let Some(lib) = self.libraries.get(&path.to_string()) {
            lib.clone()
        } else {
            let lib = Arc::new(Library::new(path.clone()).map_err(|e| {
                io::Error::other(format!("load plugin {}: {}", path.to_string(), e))
            })?);
            self.libraries.insert(path.to_string(), lib.clone());
            lib
        };

        let plugin = lib
            .get::<*mut PluginSpec>(b"plugin_spec\0")
            .map_err(|e| io::Error::other(format!("plugin {}: {}", path.to_string(), e)))?
            .read();
        let mut registrar = PluginRegistrarImpl::new(Arc::clone(&lib));
        (plugin.add_handler_fn)(&mut registrar, tag, args);
        self.stream_handlers.extend(registrar.stream_handlers);
        self.datagram_handlers.extend(registrar.datagram_handlers);
        Ok(())
    }

    pub fn get_stream_handler(&self, name: &str) -> Option<AnyExternalOutboundStreamHandler> {
        self.stream_handlers.get(name).map(|h| h.get_handler())
    }

    pub fn get_datagram_handler(&self, name: &str) -> Option<AnyExternalOutboundDatagramHandler> {
        self.datagram_handlers.get(name).map(|h| h.get_handler())
    }
}

pub struct ExternalOutboundStreamHandlerProxy(pub AnyExternalOutboundStreamHandler, pub Dialer);

#[async_trait]
impl OutboundStreamHandler for ExternalOutboundStreamHandlerProxy {
    fn connect_addr(&self) -> OutboundConnect {
        self.0
            .connect_addr()
            .map_or(OutboundConnect::Unknown, |c| c.dialled_by(&self.1))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        // As a built-in outbound waits for it, to go out with the header.
        let first = crate::net::peek_tcp_one_off(lhs).await;
        self.0.handle_first(sess, first, stream).await
    }
}

pub struct ExternalOutboundDatagramHandlerProxy(pub AnyExternalOutboundDatagramHandler, pub Dialer);

#[async_trait]
impl OutboundDatagramHandler for ExternalOutboundDatagramHandlerProxy {
    fn connect_addr(&self) -> OutboundConnect {
        self.0
            .connect_addr()
            .map_or(OutboundConnect::Unknown, |c| c.dialled_by(&self.1))
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.0.transport_type()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        self.0.handle(sess, transport).await
    }
}

pub(crate) fn register(registry: &mut OutboundRegistry) {
    // Each plugin outbound loads its own handler, so two with the same
    // options are still two handlers.
    registry.register(
        "plugin",
        OutboundFactory {
            shareable: false,
            ..OutboundFactory::standalone(build)
        },
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginOutboundOptions {
    /// The shared library to load.
    path: String,
    #[serde(default)]
    args: String,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: PluginOutboundOptions = ctx.options()?;
    unsafe {
        ctx.external_handlers
            .new_handler(options.path, ctx.tag, &options.args)?
    };
    let missing = || {
        anyhow!(
            "plugin for [{}] registered no handler under its tag",
            ctx.tag
        )
    };
    let stream = Arc::new(ExternalOutboundStreamHandlerProxy(
        ctx.external_handlers
            .get_stream_handler(ctx.tag)
            .ok_or_else(missing)?,
        ctx.dialer.clone(),
    ));
    let datagram = Arc::new(ExternalOutboundDatagramHandlerProxy(
        ctx.external_handlers
            .get_datagram_handler(ctx.tag)
            .ok_or_else(missing)?,
        ctx.dialer.clone(),
    ));
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A plugin that writes `H` as its header, and has no `handle_first`.
    struct Plain;

    impl ExternalOutboundStreamHandler for Plain {
        fn connect_addr(&self) -> Option<PluginConnect> {
            None
        }

        fn handle<'a>(
            &'a self,
            _sess: &'a Session,
            stream: Option<AnyStream>,
        ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>> {
            async move {
                let mut stream = stream.unwrap();
                stream.write_all(b"H").await?;
                Ok(stream)
            }
            .into_ffi()
        }
    }

    /// One that keeps what `handle_first` was given, and writes `H` too.
    #[derive(Default)]
    struct Taking(std::sync::Mutex<Option<Vec<u8>>>);

    impl ExternalOutboundStreamHandler for Taking {
        fn connect_addr(&self) -> Option<PluginConnect> {
            None
        }

        fn handle<'a>(
            &'a self,
            sess: &'a Session,
            stream: Option<AnyStream>,
        ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>> {
            Plain.handle(sess, stream)
        }

        fn handle_first<'a>(
            &'a self,
            sess: &'a Session,
            first: Vec<u8>,
            stream: Option<AnyStream>,
        ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>> {
            *self.0.lock().unwrap() = Some(first);
            self.handle(sess, stream)
        }
    }

    /// Through the adapter, `hello` sent by the client first: what the
    /// server reads.
    async fn through(plugin: AnyExternalOutboundStreamHandler) -> Vec<u8> {
        let proxy = ExternalOutboundStreamHandlerProxy(plugin, Dialer::system());
        let (mut client, lhs) = tokio::io::duplex(64);
        let mut lhs: AnyStream = Box::new(lhs);
        client.write_all(b"hello").await.unwrap();
        let (out, mut server) = tokio::io::duplex(64);
        let sess = Session::default();
        let stream = proxy
            .handle(&sess, Some(&mut lhs), Some(Box::new(out)))
            .await
            .unwrap();
        drop(stream);
        let mut read = Vec::new();
        server.read_to_end(&mut read).await.unwrap();
        read
    }

    #[tokio::test]
    async fn a_plugin_is_given_what_the_client_sent_first() {
        let taking = Arc::new(Taking::default());
        assert_eq!(through(taking.clone()).await, b"H");
        assert_eq!(taking.0.lock().unwrap().as_deref(), Some(&b"hello"[..]));
    }

    #[tokio::test]
    async fn by_default_it_goes_out_after_the_plugin_s_own_handshake() {
        assert_eq!(through(Arc::new(Plain)).await, b"Hhello");
    }
}
