use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tracing::{debug, Instrument};

use super::association::{Associations, ClientFilter};
use super::datagram;
use crate::{
    adapter::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

/// How long a SOCKS4 USERID or SOCKS4a host may be. Neither has a length of
/// its own, and a client that sends more is not one to hold memory for.
const MAX_SOCKS4_FIELD: usize = 1024;

/// How much the handshake reader reads at once: a judgment value. A SOCKS5
/// greeting with all 255 methods (257 bytes) and a request for a 255-byte
/// domain (262) each fit in one read; only RFC 1929 credentials near their
/// limits, or long SOCKS4 fields, take more.
const HANDSHAKE_READ: usize = 512;

/// The client's stream while its handshake is read: each field is taken from
/// what one read brought, not read from the socket on its own.
type Handshake = BufReader<AnyStream>;

/// The client's stream once its handshake is read, yielding first what the
/// handshake reader read past the handshake: data the client sent ahead of
/// our reply, such as a TLS ClientHello after a CONNECT.
fn read_on(handshake: Handshake) -> AnyStream {
    if handshake.buffer().is_empty() {
        return handshake.into_inner();
    }
    let ahead = Bytes::copy_from_slice(handshake.buffer());
    Box::new(Prefixed {
        prefix: ahead,
        inner: handshake.into_inner(),
    })
}

/// A stream that first yields bytes already read from it.
struct Prefixed {
    prefix: Bytes,
    inner: AnyStream,
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// SOCKS5 reply codes (RFC 1928, section 6).
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// A SOCKS5 reply refusing a request with `code`: no address is bound, so
/// BND.ADDR and BND.PORT are an IPv4 zero.
const fn socks5_reply(code: u8) -> [u8; 10] {
    [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// The SOCKS5 reply to a connect that failed with `e`, as sing-box's
/// `ReplyCodeForError` (sing's protocol/socks/socks5/protocol.go) maps it:
/// network unreachable, host unreachable, refused, not allowed, or a
/// general failure.
fn socks5_failure(e: &io::Error) -> Vec<u8> {
    let code = match e.kind() {
        io::ErrorKind::NetworkUnreachable => 0x03,
        io::ErrorKind::HostUnreachable => 0x04,
        io::ErrorKind::ConnectionRefused => 0x05,
        io::ErrorKind::PermissionDenied => 0x02,
        _ => REP_GENERAL_FAILURE,
    };
    socks5_reply(code).to_vec()
}

/// The SOCKS4 reply to a connect that failed: rejected or failed (91), as
/// sing-box gives it whatever the error.
fn socks4_failure(_: &io::Error) -> Vec<u8> {
    vec![0, 91, 0, 0, 0, 0, 0, 0]
}

/// A connect, answered once the outbound connects or fails, as sing-box
/// answers it, rather than before.
fn answered_once_connected(
    mut sess: Session,
    stream: AnyStream,
    success: Vec<u8>,
    failure: crate::adapter::reply::FailureReply,
) -> AnyInboundTransport {
    let reply = crate::adapter::reply::Reply::new(success, failure);
    sess.reply = Some(reply.clone());
    let stream = crate::adapter::reply::ReplyStream::new(stream, reply);
    InboundTransport::Stream(Box::new(stream), sess)
}

/// Reads a SOCKS4 field up to its NUL, without the NUL.
async fn read_nul_terminated(stream: &mut Handshake) -> io::Result<Vec<u8>> {
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
    users: Arc<crate::user::Passwords>,
    /// The UDP associations clients ask for, each with a relay socket of
    /// its own.
    associations: Arc<Associations>,
    /// The listener's mark, for the relay sockets.
    mark: Option<u32>,
}

impl Handler {
    pub fn new(
        users: crate::user::Passwords,
        associations: Arc<Associations>,
        mark: Option<u32>,
    ) -> Self {
        Handler {
            users: Arc::new(users),
            associations,
            mark,
        }
    }

    /// Handles a stream whose version byte, `version`, the mixed inbound
    /// read already, telling SOCKS from HTTP.
    #[cfg(feature = "inbound-mixed")]
    pub(crate) async fn handle_version(
        &self,
        sess: Session,
        stream: AnyStream,
        version: u8,
    ) -> io::Result<AnyInboundTransport> {
        let stream = BufReader::with_capacity(HANDSHAKE_READ, stream);
        self.handle_handshake(sess, stream, version).await
    }

    /// Handles a handshake whose version byte, `version`, was read already.
    async fn handle_handshake(
        &self,
        sess: Session,
        stream: Handshake,
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
        mut stream: Handshake,
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

        // SOCKS4 has no passwords, so it cannot authenticate anyone. Refused
        // only once the whole request is read: a socket closed with a request
        // left unread is reset, and on Windows the reset discards the reply
        // before the client reads it.
        if !self.users.is_empty() {
            // Reply: VN=0, CD=91(Rejected)
            crate::net::refuse(&mut stream, &[0, 91, 0, 0, 0, 0, 0, 0]).await?;
            return Err(io::Error::other(
                "socks4 refused: users are configured, and socks4 cannot authenticate",
            ));
        }

        // Reply: VN=0, CD=90(Granted), DSTPORT, DSTIP; once connected.
        let mut granted = BytesMut::new();
        granted.put_u8(0);
        granted.put_u8(90);
        granted.put_u16(port);
        granted.put_slice(&ip_bytes);
        sess.destination = destination;
        Ok(answered_once_connected(
            sess,
            read_on(stream),
            granted.to_vec(),
            socks4_failure,
        ))
    }

    async fn handle_socks5(
        &self,
        mut sess: Session,
        mut stream: Handshake,
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
            crate::net::refuse(&mut stream, &[0x05, 0xff]).await?;
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

            let accepted = self.users.get(&username).filter(|(expected, user)| {
                constant_time_eq(expected.as_bytes(), password.as_bytes())
                    && !crate::user::shut_out(user)
            });
            if let Some((_, user)) = accepted {
                stream.write_all(&[0x01, 0x00]).await?;
                sess.user = user.clone();
            } else {
                crate::net::refuse(&mut stream, &[0x01, 0x01]).await?;
                return Err(io::Error::other("socks5 authentication failed"));
            }
        }

        // handle request
        buf.resize(3, 0);
        // ver, cmd, rsv
        stream.read_exact(&mut buf[..]).await?;
        // Not a SOCKS5 request at all: no SOCKS5 reply means anything to
        // its sender, and none is sent, as sing-box sends none.
        if buf[0] != 0x05 {
            return Err(io::Error::other(format!(
                "unknown socks version {}",
                buf[0]
            )));
        }
        // RSV (buf[2]) is read and ignored, as sing-box ignores it.
        let cmd = buf[1];
        // connect, udp associate; BIND, or anything else, is answered as
        // not supported (RFC 1928, as sing-box answers it).
        if cmd != 0x01 && cmd != 0x03 {
            crate::net::refuse(&mut stream, &socks5_reply(REP_COMMAND_NOT_SUPPORTED)).await?;
            return Err(io::Error::other(format!("unsupported socks5 cmd {}", cmd)));
        }

        let destination = SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;

        match cmd {
            0x01 => {
                // Succeeded, once connected; no address is told.
                buf.clear();
                buf.put_u8(0x05);
                buf.put_u8(0x00);
                buf.put_u8(0x00);
                SocksAddr::any().write_buf(&mut buf, SocksAddrWireType::PortLast);
                sess.destination = destination;
                Ok(answered_once_connected(
                    sess,
                    read_on(stream),
                    buf.to_vec(),
                    socks5_failure,
                ))
            }
            0x03 => {
                const FAILURE: [u8; 10] = socks5_reply(REP_GENERAL_FAILURE);
                let Some(slot) = self.associations.acquire() else {
                    stream.write_all(&FAILURE).await?;
                    return Err(io::Error::other(
                        "udp associate refused: too many associations",
                    ));
                };
                // A relay of its own, on the address the client reached
                // the inbound at, so that it can reach the relay too.
                let local_ip = sess.local_addr.ip().to_canonical();
                let socket = match datagram::bind(local_ip, self.mark) {
                    Ok(socket) => socket,
                    Err(e) => {
                        stream.write_all(&FAILURE).await?;
                        return Err(io::Error::other(format!(
                            "udp associate: bind relay on {}: {}",
                            local_ip, e
                        )));
                    }
                };
                let relay_addr = socket.local_addr()?;
                let filter = ClientFilter::new(sess.source, &destination);
                buf.clear();
                buf.put_u8(0x05); // version 5
                buf.put_u8(0x0); // succeeded
                buf.put_u8(0x0); // rsv
                SocksAddr::from(relay_addr).write_buf(&mut buf, SocksAddrWireType::PortLast);
                stream.write_all(&buf[..]).await?;
                debug!(
                    "udp association from {} relayed on {}",
                    sess.source, relay_addr
                );
                // The datagrams' session: their source is the client's UDP
                // address, which the NAT manager fills in from each.
                let mut udp_sess = sess;
                udp_sess.source = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
                udp_sess.local_addr = relay_addr;
                let user = udp_sess.user.clone();
                // The association lasts as long as the connection (RFC
                // 1928): the relay watches it, and ends with it.
                let relay = datagram::Relay::new(socket, slot, read_on(stream), filter, user);
                Ok(InboundTransport::Datagram(Box::new(relay), Some(udp_sess)))
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
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let mut stream = BufReader::with_capacity(HANDSHAKE_READ, stream);
        let version = stream.read_u8().await?;
        self.handle_handshake(sess, stream, version).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> Handler {
        Handler::new(
            crate::user::passwords(&[("alice", "apass"), ("bob", "bpass")]),
            Default::default(),
            None,
        )
    }

    /// Runs `request` through the handler, returning its result and what it
    /// answered.
    async fn run(handler: Handler, request: &[u8]) -> (io::Result<Option<Session>>, Vec<u8>) {
        let (client, server) = tokio::io::duplex(4096);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        client_w.write_all(request).await.unwrap();
        // All sent: a refusal drains to the end without waiting.
        client_w.shutdown().await.unwrap();
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
            assert_eq!(crate::user::name(&sess.user), Some(user));
            assert_eq!(sess.destination.to_string(), "127.0.0.1:80");
            assert_eq!(&answer[..4], &[0x05, 0x02, 0x01, 0x00]);
        }
    }

    fn socks5_no_auth(request: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x05, 0x01, 0x00];
        bytes.extend_from_slice(request);
        bytes
    }

    fn open_handler() -> Handler {
        Handler::new(crate::user::passwords(&[]), Default::default(), None)
    }

    #[tokio::test]
    async fn an_unsupported_command_is_answered_so() {
        // BIND 127.0.0.1:80
        let request = socks5_no_auth(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        let (result, answer) = run(open_handler(), &request).await;
        assert!(result.is_err());
        assert_eq!(
            answer,
            [0x05, 0x00, 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn a_non_zero_reserved_field_is_ignored() {
        let request = socks5_no_auth(&[0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0, 80]);
        let (result, _) = run(open_handler(), &request).await;
        let sess = result.unwrap().expect("a stream session");
        assert_eq!(sess.destination.to_string(), "127.0.0.1:80");
    }

    #[tokio::test]
    async fn a_request_of_another_version_gets_no_reply() {
        let request = socks5_no_auth(&[0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        let (result, answer) = run(open_handler(), &request).await;
        assert!(result.is_err());
        assert_eq!(answer, [0x05, 0x00]);
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

        // Granted, once the outbound connects; nothing before.
        let (client, server) = tokio::io::duplex(4096);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        client_w.write_all(&request).await.unwrap();
        let handler = Handler::new(Default::default(), Default::default(), None);
        let Ok(InboundTransport::Stream(mut stream, sess)) =
            handler.handle(Session::default(), Box::new(server)).await
        else {
            panic!("no stream");
        };
        let mut answer = [0u8; 8];
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(50),
            client_r.read_exact(&mut answer)
        )
        .await
        .is_err());
        sess.reply.expect("answered once connected").succeeded();
        stream.flush().await.unwrap();
        client_r.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[1], 90);
    }

    #[tokio::test]
    async fn a_connect_takes_one_read_for_each_message() {
        let (mut client, server) = tokio::io::duplex(4096);
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = CountReads {
            inner: server,
            reads: reads.clone(),
        };
        let client_side = async {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method = [0u8; 2];
            client.read_exact(&mut method).await.unwrap();
            // CONNECT 127.0.0.1:80
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        };
        let handler = open_handler();
        let (result, ()) = tokio::join!(
            handler.handle(Session::default(), Box::new(counted)),
            client_side
        );
        assert!(matches!(result, Ok(InboundTransport::Stream(..))));
        // The greeting, then the request.
        assert_eq!(reads.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn data_sent_ahead_of_the_reply_is_relayed_first() {
        let (client, server) = tokio::io::duplex(4096);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        // Greeting, CONNECT and early data in one write, as a client that
        // does not wait for the reply sends them.
        let mut request = socks5_no_auth(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        request.extend_from_slice(b"early data");
        client_w.write_all(&request).await.unwrap();
        let Ok(InboundTransport::Stream(mut stream, sess)) = open_handler()
            .handle(Session::default(), Box::new(server))
            .await
        else {
            panic!("no stream");
        };
        sess.reply.expect("answered once connected").succeeded();
        client_w.write_all(b", then more").await.unwrap();
        client_w.shutdown().await.unwrap();
        let mut relayed = Vec::new();
        stream.read_to_end(&mut relayed).await.unwrap();
        assert_eq!(relayed, b"early data, then more");
        let mut answer = [0u8; 4];
        client_r.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [0x05, 0x00, 0x05, 0x00]);
    }

    /// A stream that counts the reads of it that brought data.
    struct CountReads<S> {
        inner: S,
        reads: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for CountReads<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buf.filled().len();
            let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
            if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
                self.reads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            polled
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for CountReads<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn socks4_fields_are_bounded() {
        let mut request = vec![0x04, 0x01, 0, 80, 127, 0, 0, 1];
        request.resize(request.len() + MAX_SOCKS4_FIELD + 10, b'a');
        let (result, _) = run(
            Handler::new(Default::default(), Default::default(), None),
            &request,
        )
        .await;
        assert!(result.is_err());
    }
}
