use std::io;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use super::super::body::VmessStream;
use super::super::header::*;
use super::ClientSecurity;
use crate::{adapter::*, session::*};

/// What every request of an outbound shares.
pub struct Client {
    pub cmd_key: [u8; 16],
    pub security: ClientSecurity,
    pub global_padding: bool,
}

impl Client {
    /// Sends a request for `command` and returns the body that follows.
    pub async fn open(
        &self,
        mut stream: AnyStream,
        command: u8,
        address: Option<SocksAddr>,
    ) -> io::Result<VmessStream<AnyStream>> {
        let (security, option) = self.security.request(command, self.global_padding);
        let request = RequestHeader::new(option, security, command, address);
        stream.write_all(&request.seal(&self.cmd_key)?).await?;
        VmessStream::client(stream, &request, command == COMMAND_UDP)
    }
}

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub client: std::sync::Arc<Client>,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        let stream = self
            .client
            .open(stream, COMMAND_TCP, Some(sess.destination.clone()))
            .await?;
        Ok(Box::new(stream))
    }
}
