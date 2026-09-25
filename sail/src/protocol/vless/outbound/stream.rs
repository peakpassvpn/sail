use std::io;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use super::super::request::{encode_request, ClientStream, Flow, COMMAND_TCP};
use super::super::stream::VlessStream;
use crate::{adapter::*, session::*, transport::vision::VisionState};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: [u8; 16],
    pub flow: Flow,
}

/// Sends a request and wraps `stream` for what follows it: Vision frames
/// with Vision, else plain data behind the response header.
pub(super) async fn open(
    sess: &Session,
    mut stream: AnyStream,
    uuid: &[u8; 16],
    flow: Flow,
    command: u8,
    destination: Option<&SocksAddr>,
) -> io::Result<AnyStream> {
    let header = encode_request(uuid, flow, command, destination);
    match flow {
        Flow::Vision => {
            // From the request on, the TLS layer must stop reads at record
            // boundaries until Vision settles.
            VisionState::of(sess).start();
            stream.write_all(&header).await?;
            Ok(Box::new(VlessStream::new(
                stream,
                *uuid,
                Some(VisionState::of(sess)),
            )))
        }
        Flow::None => {
            stream.write_all(&header).await?;
            Ok(Box::new(ClientStream::new(stream)))
        }
    }
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
        open(
            sess,
            stream,
            &self.uuid,
            self.flow,
            COMMAND_TCP,
            Some(&sess.destination),
        )
        .await
    }
}
