use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use futures::TryFutureExt;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tracing::trace;

use crate::protocol::fallback::{Fallback, HEADER_TIMEOUT};

use crate::{
    adapter::*,
    session::{DatagramSource, Network, Session, SocksAddr, SocksAddrWireType},
};

struct Datagram {
    stream: AnyStream,
    source: DatagramSource,
}

impl Datagram {
    pub fn new(stream: AnyStream, source: DatagramSource) -> Self {
        Self { stream, source }
    }
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, s) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf(r, self.source)),
            Box::new(DatagramSendHalf(s)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("stream transport"))
    }
}

struct DatagramRecvHalf<T>(T, DatagramSource);

#[async_trait]
impl<T> InboundDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + Send + Sync + Unpin,
{
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let dst_addr = SocksAddr::read_from(&mut self.0, SocksAddrWireType::PortLast)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        let mut buf2 = [0; 4];
        self.0
            .read_exact(&mut buf2)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        let payload_len = u16::from_be_bytes(buf2[..2].try_into().unwrap()) as usize;
        if buf.len() < payload_len {
            return Err(ProxyError::DatagramFatal(anyhow!("Small buffer")));
        }
        // TODO Check CRLF?
        self.0
            .read_exact(&mut buf[..payload_len])
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        trace!(
            "trojan inbound received UDP {} bytes for {}",
            payload_len,
            &dst_addr
        );
        Ok((payload_len, self.1.clone(), dst_addr))
    }
}

struct DatagramSendHalf<T>(T);

#[async_trait]
impl<T> InboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncWrite + Send + Sync + Unpin,
{
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        trace!(
            "trojan inbound send UDP {} bytes for {}",
            buf.len(),
            &src_addr
        );
        let mut data = BytesMut::new();
        src_addr.write_buf(&mut data, SocksAddrWireType::PortLast);
        data.put_u16(buf.len() as u16);
        data.put_slice(b"\r\n");
        data.put_slice(buf);
        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

/// The first bytes of a Trojan request: the password's SHA-224 in lowercase
/// hex, then CRLF.
const KEY_LEN: usize = 56;
const AUTH_LEN: usize = KEY_LEN + 2;

/// Whether `buf`, the first bytes of a connection, can still be the start of
/// a Trojan request. Checked as bytes arrive, so that a connection that is
/// plainly something else goes to the fallback without waiting for more.
fn could_be_auth(buf: &[u8]) -> bool {
    buf.iter().enumerate().all(|(i, &b)| match i {
        i if i < KEY_LEN => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        KEY_LEN => b == b'\r',
        _ => b == b'\n',
    })
}

pub struct Handler {
    /// The users by the key their password makes, with their names.
    keys: HashMap<Vec<u8>, Option<std::sync::Arc<str>>>,
    /// Where what fails to authenticate goes; closed without one.
    fallback: Option<Fallback>,
}

impl Handler {
    /// Takes the users as their passwords and names.
    pub fn new(users: Vec<(String, Option<String>)>, fallback: Option<Fallback>) -> Self {
        let mut keys = HashMap::new();
        for (pass, name) in users {
            let key = Sha224::digest(pass.as_bytes());
            let key = hex::encode(&key[..]);
            keys.insert(key.as_bytes().to_vec(), name.map(Into::into));
        }
        Handler { keys, fallback }
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        // The key and its CRLF, and no more: what is read here is what the
        // fallback is given if the key is not a user's.
        let mut auth = [0u8; AUTH_LEN];
        let mut read = 0;
        let reading = async {
            while read < AUTH_LEN {
                let n = stream.read(&mut auth[read..]).await?;
                if n == 0 {
                    return Ok(false);
                }
                read += n;
                if !could_be_auth(&auth[..read]) {
                    return Ok(false);
                }
            }
            Ok::<_, io::Error>(true)
        };
        let complete = match self.fallback {
            // A peer that sends part of a key and waits is not a client.
            Some(_) => timeout(HEADER_TIMEOUT, reading)
                .await
                .unwrap_or(Ok(false))?,
            None => reading.await?,
        };
        let user = match complete {
            true => self.keys.get(&auth[..KEY_LEN]).ok_or("unknown password"),
            false => Err("not a Trojan request"),
        };
        let user = match user {
            Ok(user) => user,
            Err(why) => {
                return Err(match &self.fallback {
                    Some(fallback) => fallback.relay(&sess, stream, auth[..read].to_vec(), why),
                    None => io::Error::new(io::ErrorKind::PermissionDenied, why),
                })
            }
        };
        sess.user = user.clone();
        let cmd = stream.read_u8().await?;
        let dst_addr = SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;
        sess.destination = dst_addr;
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(io::Error::other("invalid request"));
        }
        match cmd {
            // tcp
            0x01 => Ok(InboundTransport::Stream(stream, sess)),
            // udp
            0x03 => {
                sess.network = Network::Udp;
                Ok(InboundTransport::Datagram(
                    Box::new(Datagram::new(
                        stream,
                        DatagramSource::new(sess.source, sess.stream_id),
                    )),
                    Some(sess),
                ))
            }
            _ => Err(io::Error::other("invalid command")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_could_be_auth() {
        let key = hex::encode(Sha224::digest(b"password"));
        let mut auth = key.clone().into_bytes();
        auth.extend_from_slice(b"\r\n");
        assert!(could_be_auth(&auth));
        assert!(could_be_auth(&auth[..10]));
        assert!(could_be_auth(b""));
        assert!(!could_be_auth(b"GET / HTTP/1.1\r\n"));
        assert!(!could_be_auth(key.to_uppercase().as_bytes()));
        let mut bad_crlf = key.into_bytes();
        bad_crlf.extend_from_slice(b"\n\r");
        assert!(!could_be_auth(&bad_crlf));
    }
}
