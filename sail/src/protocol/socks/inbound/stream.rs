use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, Instrument};

use crate::{
    adapter::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

/// How long a SOCKS4 USERID or SOCKS4a host may be. Neither has a length of
/// its own, and a client that sends more is not one to hold memory for.
const MAX_SOCKS4_FIELD: usize = 1024;

/// Reads a SOCKS4 field up to its NUL, without the NUL.
async fn read_nul_terminated(stream: &mut AnyStream) -> io::Result<Vec<u8>> {
    let mut field = Vec::new();
    loop {
        let b = stream.read_u8().await?;
        if b == 0 {
            return Ok(field);
        }
        if field.len() >= MAX_SOCKS4_FIELD {
            return Err(io::Error::other(format!(
                "socks4 field longer than {} bytes",
                MAX_SOCKS4_FIELD
            )));
        }
        field.push(b);
    }
}

/// Compares without an early exit, so that timing does not tell how much of
/// a guessed password was right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub struct Handler {
    /// Passwords by username. Empty lets anyone in.
    users: Arc<HashMap<String, String>>,
}

impl Handler {
    pub fn new(users: HashMap<String, String>) -> Self {
        Handler {
            users: Arc::new(users),
        }
    }

    /// Handles a stream whose version byte, `version`, was read already:
    /// by `handle`, or by the mixed inbound telling SOCKS from HTTP.
    pub(crate) async fn handle_version(
        &self,
        sess: Session,
        stream: AnyStream,
        version: u8,
    ) -> io::Result<AnyInboundTransport> {
        let span = sess.span();
        match version {
            0x04 => self.handle_socks4(sess, stream).instrument(span).await,
            0x05 => self.handle_socks5(sess, stream).instrument(span).await,
            v => Err(io::Error::other(format!("unknown socks version {}", v))),
        }
    }

    async fn handle_socks4(
        &self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let mut buf = BytesMut::new();
        // CD, DSTPORT, DSTIP
        buf.resize(1 + 2 + 4, 0);
        stream.read_exact(&mut buf[..]).await?;

        if buf[0] != 0x01 {
            return Err(io::Error::other(format!(
                "unsupported socks4 cmd {}",
                buf[0]
            )));
        }

        let port = u16::from_be_bytes([buf[1], buf[2]]);
        let ip_bytes = [buf[3], buf[4], buf[5], buf[6]];

        // USERID
        let _userid = read_nul_terminated(&mut stream).await?;

        // SOCKS4 has no passwords, so it cannot authenticate anyone.
        if !self.users.is_empty() {
            // Reply: VN=0, CD=91(Rejected)
            stream.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]).await?;
            return Err(io::Error::other(
                "socks4 refused: users are configured, and socks4 cannot authenticate",
            ));
        }

        // SOCKS4a check: 0.0.0.x, x != 0
        let is_socks4a =
            ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0;

        let destination = if is_socks4a {
            let domain = read_nul_terminated(&mut stream).await?;
            let domain_str = String::from_utf8_lossy(&domain).to_string();
            SocksAddr::Domain(domain_str, port)
        } else {
            let ip = std::net::Ipv4Addr::from(ip_bytes);
            SocksAddr::Ip(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                ip, port,
            )))
        };

        // Reply: VN=0, CD=90(Granted), DSTPORT, DSTIP
        let mut reply = BytesMut::new();
        reply.put_u8(0);
        reply.put_u8(90);
        reply.put_u16(port);
        reply.put_slice(&ip_bytes);
        stream.write_all(&reply).await?;

        sess.destination = destination;
        Ok(InboundTransport::Stream(stream, sess))
    }

    async fn handle_socks5(
        &self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let mut buf = BytesMut::new();

        // handle auth
        buf.resize(1, 0);
        // nmethods
        stream.read_exact(&mut buf[..]).await?;
        if buf[0] == 0 {
            return Err(io::Error::other(
                "no socks5 authentication method specified",
            ));
        }
        let nmethods = buf[0] as usize;
        buf.resize(nmethods, 0);
        // methods
        stream.read_exact(&mut buf[..]).await?;
        let mut method_accepted = false;
        let supported_method: u8 = if self.users.is_empty() { 0x00 } else { 0x02 };

        for method in buf[..].iter() {
            if method == &supported_method {
                method_accepted = true;
                break;
            }
        }
        if !method_accepted {
            stream.write_all(&[0x05, 0xff]).await?;
            return Err(io::Error::other(format!(
                "unsupported socks5 authentication methods, client sent: {:?}, server expects: {}",
                &buf[..],
                supported_method
            )));
        }

        stream.write_all(&[0x05, supported_method]).await?;

        if supported_method == 0x02 {
            buf.resize(2, 0);
            // ver, ulen
            stream.read_exact(&mut buf[..]).await?;
            if buf[0] != 0x01 {
                return Err(io::Error::other(format!(
                    "unknown socks5 auth version {}",
                    buf[0]
                )));
            }
            let ulen = buf[1] as usize;
            buf.resize(ulen, 0);
            // uname
            stream.read_exact(&mut buf[..]).await?;
            let username = String::from_utf8_lossy(&buf).to_string();

            buf.resize(1, 0);
            // plen
            stream.read_exact(&mut buf[..]).await?;
            let plen = buf[0] as usize;
            buf.resize(plen, 0);
            // passwd
            stream.read_exact(&mut buf[..]).await?;
            let password = String::from_utf8_lossy(&buf).to_string();

            let accepted = self
                .users
                .get(&username)
                .is_some_and(|expected| constant_time_eq(expected.as_bytes(), password.as_bytes()));
            if accepted {
                stream.write_all(&[0x01, 0x00]).await?;
                sess.user = Some(username.into());
            } else {
                stream.write_all(&[0x01, 0x01]).await?;
                return Err(io::Error::other("socks5 authentication failed"));
            }
        }

        // handle request
        buf.resize(3, 0);
        // ver, cmd, rsv
        stream.read_exact(&mut buf[..]).await?;
        if buf[0] != 0x05 {
            // TODO reply?
            return Err(io::Error::other(format!(
                "unknown socks version {}",
                buf[0]
            )));
        }
        if buf[2] != 0x0 {
            // TODO reply?
            return Err(io::Error::other("non-zero socks5 reserved field"));
        }
        let cmd = buf[1];
        // connect, udp associate
        if cmd != 0x01 && cmd != 0x03 {
            // TODO reply?
            return Err(io::Error::other(format!("unsupported socks5 cmd {}", cmd)));
        }

        let destination = SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;

        match cmd {
            0x01 => {
                // handle response
                buf.clear();
                buf.put_u8(0x05); // version 5
                buf.put_u8(0x0); // succeeded
                buf.put_u8(0x0); // rsv
                let resp_addr = SocksAddr::any();
                resp_addr.write_buf(&mut buf, SocksAddrWireType::PortLast);
                stream.write_all(&buf[..]).await?;
                sess.destination = destination;
                Ok(InboundTransport::Stream(stream, sess))
            }
            0x03 => {
                buf.clear();
                buf.put_u8(0x05); // version 5
                buf.put_u8(0x0); // succeeded
                buf.put_u8(0x0); // rsv
                let relay_addr = SocksAddr::from(sess.local_addr);
                relay_addr.write_buf(&mut buf, SocksAddrWireType::PortLast);
                stream.write_all(&buf[..]).await?;
                tokio::spawn(
                    async move {
                        let mut buf = [0u8; 1];
                        // TODO explicitly drop resources allocated above before waiting?
                        // if stream.read_exact(&mut buf).await.is_err() {
                        //     // perhaps explicitly notifies the NAT manager?
                        //     debug!("udp association end");
                        // }
                        if let Err(e) = stream.read_exact(&mut buf).await {
                            // perhaps explicitly notifies the NAT manager?
                            debug!("udp association end: {}", e);
                        }
                    }
                    .instrument(sess.span()),
                );
                Ok(InboundTransport::Empty)
            }
            _ => Err(io::Error::other("invalid cmd")),
        }
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;
        self.handle_version(sess, stream, buf[0]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> Handler {
        Handler::new(HashMap::from([
            ("alice".to_string(), "apass".to_string()),
            ("bob".to_string(), "bpass".to_string()),
        ]))
    }

    /// Runs `request` through the handler, returning its result and what it
    /// answered.
    async fn run(handler: Handler, request: &[u8]) -> (io::Result<Option<Session>>, Vec<u8>) {
        let (client, server) = tokio::io::duplex(4096);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        client_w.write_all(request).await.unwrap();
        let result = handler
            .handle(Session::default(), Box::new(server))
            .await
            .map(|transport| match transport {
                InboundTransport::Stream(_, sess) => Some(sess),
                _ => None,
            });
        drop(client_w);
        let mut answer = Vec::new();
        client_r.read_to_end(&mut answer).await.unwrap();
        (result, answer)
    }

    fn socks5_connect(username: &str, password: &str) -> Vec<u8> {
        let mut request = vec![0x05, 0x01, 0x02, 0x01, username.len() as u8];
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        // CONNECT 127.0.0.1:80
        request.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        request
    }

    #[tokio::test]
    async fn any_configured_user_authenticates() {
        for (user, pass) in [("alice", "apass"), ("bob", "bpass")] {
            let (result, answer) = run(handler(), &socks5_connect(user, pass)).await;
            let sess = result.unwrap().unwrap();
            assert_eq!(sess.user.as_deref(), Some(user));
            assert_eq!(sess.destination.to_string(), "127.0.0.1:80");
            assert_eq!(&answer[..4], &[0x05, 0x02, 0x01, 0x00]);
        }
    }

    #[tokio::test]
    async fn another_users_password_is_refused() {
        let (result, answer) = run(handler(), &socks5_connect("bob", "apass")).await;
        assert!(result.is_err());
        assert_eq!(answer, [0x05, 0x02, 0x01, 0x01]);
    }

    #[tokio::test]
    async fn socks4_is_refused_when_users_are_set() {
        let request = [0x04, 0x01, 0, 80, 127, 0, 0, 1, b'x', 0];
        let (result, answer) = run(handler(), &request).await;
        assert!(result.is_err());
        assert_eq!(answer[1], 91);

        let (result, answer) = run(Handler::new(HashMap::new()), &request).await;
        assert!(result.unwrap().is_some());
        assert_eq!(answer[1], 90);
    }

    #[tokio::test]
    async fn socks4_fields_are_bounded() {
        let mut request = vec![0x04, 0x01, 0, 80, 127, 0, 0, 1];
        request.resize(request.len() + MAX_SOCKS4_FIELD + 10, b'a');
        let (result, _) = run(Handler::new(HashMap::new()), &request).await;
        assert!(result.is_err());
    }
}
