use async_trait::async_trait;

use crate::{
    adapter::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

use super::shadow::ShadowedStream;

pub struct Handler {
    pub cipher: String,
    pub password: String,
}

pub(super) struct ReloadableStream(pub(super) super::HotResource<super::LegacyResources>);

#[async_trait]
impl InboundStreamHandler for ReloadableStream {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let generation = self.0.load();
        Handler {
            cipher: generation.cipher.clone(),
            password: generation.password.clone(),
        }
        .handle(sess, stream)
        .await
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let mut stream = ShadowedStream::new(stream, &self.cipher, &self.password, None)?;
        let destination = match SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await
        {
            Ok(destination) => destination,
            // A request that does not open is read on, not closed at.
            Err(e) => return Err(super::refuse(stream.into_inner(), e).await),
        };
        sess.destination = destination;
        Ok(InboundTransport::Stream(Box::new(stream), sess))
    }
}
