use async_socks5::Auth;
use std::io;

use async_trait::async_trait;
use futures::future::TryFutureExt;

use crate::{adapter::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub dialer: crate::net::Dialer,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(
            Network::Tcp,
            self.address.clone(),
            self.port,
            self.dialer.clone(),
        )
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        let auth = match (&self.username, &self.password) {
            (auth_username, _) if auth_username.is_empty() => None,
            (auth_username, auth_password) => Some(Auth {
                username: auth_username.to_owned(),
                password: auth_password.to_owned(),
            }),
        };
        // async-socks5 writes a message a field at a time and flushes at its
        // end: buffered, each message goes out in one write, not one a byte.
        // Reads are not buffered, so nothing after the reply is taken.
        let mut buffered = tokio::io::BufWriter::new(stream);
        match &sess.destination {
            SocksAddr::Ip(a) => {
                let _ = async_socks5::connect(&mut buffered, a.to_owned(), auth)
                    .map_err(io::Error::other)
                    .await?;
            }
            SocksAddr::Domain(domain, port) => {
                let _ = async_socks5::connect(&mut buffered, (domain.to_owned(), *port), auth)
                    .map_err(io::Error::other)
                    .await?;
            }
        }
        tokio::io::AsyncWriteExt::flush(&mut buffered).await?;
        Ok(buffered.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_socks5_outbound_handler() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handler = Handler {
            address: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "".to_string(),
            password: "".to_string(),
            dialer: crate::net::Dialer::system(),
        };

        let sess = Session {
            destination: SocksAddr::Domain("google.com".to_string(), 80),
            ..Default::default()
        };

        // Mock a SOCKS5 server in a separate task.
        //
        // It has to consume everything the client sends, not merely enough to
        // know what to reply: a socket dropped with unread bytes still in it is
        // reset rather than closed, and the client loses the reply it was in
        // the middle of being given. This used to read the greeting as two
        // bytes, one short of the shortest there is, and every read after it
        // was off by that byte -- so the request went unread, the close became
        // a reset, and whether the client got the reply out first was a race it
        // won often enough on Unix to look like a passing test.
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Greeting: VER, NMETHODS, and then that many method bytes.
            let mut greeting = [0u8; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();

            // Request: VER, CMD, RSV, ATYP, and then the address and port.
            let mut request = [0u8; 4];
            socket.read_exact(&mut request).await.unwrap();
            let address_len = match request[3] {
                0x01 => 4,
                0x04 => 16,
                0x03 => {
                    let mut len = [0u8; 1];
                    socket.read_exact(&mut len).await.unwrap();
                    len[0] as usize
                }
                other => panic!("the client asked for address type {}", other),
            };
            let mut address_and_port = vec![0u8; address_len + 2];
            socket.read_exact(&mut address_and_port).await.unwrap();

            // Reply
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let counted = CountWrites {
            inner: client_stream,
            writes: writes.clone(),
        };
        let result = handler.handle(&sess, None, Some(Box::new(counted))).await;
        assert!(
            result.is_ok(),
            "the handshake failed: {}",
            result.err().unwrap()
        );
        // The greeting (3 bytes) and the request (4 + 1 + 10 + 2), each in
        // one write.
        assert_eq!(*writes.lock().unwrap(), vec![3, 17]);
    }

    /// A stream that notes the length of every write made to it.
    struct CountWrites<S> {
        inner: S,
        writes: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
    }

    impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CountWrites<S> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CountWrites<S> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            let polled = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
            if let std::task::Poll::Ready(Ok(n)) = polled {
                self.writes.lock().unwrap().push(n);
            }
            polled
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
}
