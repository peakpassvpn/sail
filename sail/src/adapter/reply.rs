//! An inbound's answer to its client, given once the outbound connects, as
//! sing-box answers a SOCKS request (`LazyConn`, sing's
//! protocol/socks/lazy.go): success once connected, or the failure the
//! dial met; success too as soon as anything reads from or writes to the
//! client first, as sniffing does or an outbound reading the client's
//! first bytes.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The answer to a failure, for its error.
pub type FailureReply = fn(&io::Error) -> Vec<u8>;

enum State {
    /// Nothing decided: success, if the client is read from or written to.
    Pending {
        success: Vec<u8>,
        failure: FailureReply,
    },
    /// To be written, from the offset given.
    Due(Vec<u8>, usize),
    /// Never answered: the connection is dropped as it is.
    Silent,
    Done,
}

/// The answer an inbound owes its client, which the dispatcher decides and
/// the client's stream writes.
pub struct Reply(Mutex<State>);

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match &*self.state() {
            State::Pending { .. } => "pending",
            State::Due(..) => "due",
            State::Silent => "withheld",
            State::Done => "done",
        };
        f.debug_tuple("Reply").field(&state).finish()
    }
}

impl Reply {
    pub fn new(success: Vec<u8>, failure: FailureReply) -> Arc<Reply> {
        Arc::new(Reply(Mutex::new(State::Pending { success, failure })))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The outbound connected: success, unless already answered.
    pub fn succeeded(&self) {
        let mut state = self.state();
        if let State::Pending { success, .. } = &mut *state {
            *state = State::Due(std::mem::take(success), 0);
        }
    }

    /// The outbound failed with `e`: its failure, unless already answered.
    pub fn failed(&self, e: &io::Error) {
        let mut state = self.state();
        if let State::Pending { failure, .. } = &*state {
            *state = State::Due(failure(e), 0);
        }
    }

    /// The client is never answered, unless it already was.
    pub fn withheld(&self) {
        let mut state = self.state();
        if let State::Pending { .. } = &*state {
            *state = State::Silent;
        }
    }

    /// Writes what is due to `io` before anything else goes either way;
    /// what is pending is success, unless `on_close`.
    fn poll_write_due<S: AsyncWrite + Unpin>(
        &self,
        io: &mut S,
        cx: &mut Context<'_>,
        on_close: bool,
    ) -> Poll<io::Result<()>> {
        let mut state = self.state();
        loop {
            match &mut *state {
                State::Pending { success, .. } => {
                    if on_close {
                        return Poll::Ready(Ok(()));
                    }
                    *state = State::Due(std::mem::take(success), 0);
                }
                State::Due(bytes, written) => {
                    while *written < bytes.len() {
                        let n = ready!(Pin::new(&mut *io).poll_write(cx, &bytes[*written..]))?;
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        *written += n;
                    }
                    ready!(Pin::new(&mut *io).poll_flush(cx))?;
                    *state = State::Done;
                }
                State::Silent | State::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// The client's stream, which writes the inbound's answer before anything
/// else.
pub struct ReplyStream<S> {
    inner: S,
    reply: Arc<Reply>,
}

impl<S> ReplyStream<S> {
    pub fn new(inner: S, reply: Arc<Reply>) -> Self {
        ReplyStream { inner, reply }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ReplyStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.reply.poll_write_due(&mut me.inner, cx, false))?;
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ReplyStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        ready!(me.reply.poll_write_due(&mut me.inner, cx, false))?;
        Pin::new(&mut me.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.reply.poll_write_due(&mut me.inner, cx, true))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    /// A failure decided is written before the connection ends; nothing
    /// decided, nothing is.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.reply.poll_write_due(&mut me.inner, cx, true))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn reply() -> Arc<Reply> {
        Reply::new(b"ok".to_vec(), |e| {
            format!("failed:{:?}", e.kind()).into_bytes()
        })
    }

    #[tokio::test]
    async fn success_comes_before_the_first_bytes_either_way() {
        let (client, server) = tokio::io::duplex(64);
        let r = reply();
        let mut stream = ReplyStream::new(server, r.clone());
        let mut client = client;
        // Nothing yet: the dial is under way.
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), client.read(&mut buf))
                .await
                .is_err()
        );
        r.succeeded();
        stream.write_all(b"data").await.unwrap();
        let mut got = [0u8; 6];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"okdata");
    }

    #[tokio::test]
    async fn a_failure_is_written_as_the_connection_ends() {
        let (mut client, server) = tokio::io::duplex(64);
        let r = reply();
        let mut stream = ReplyStream::new(server, r.clone());
        r.failed(&io::ErrorKind::ConnectionRefused.into());
        // Too late to change it.
        r.succeeded();
        stream.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"failed:ConnectionRefused");
    }

    #[tokio::test]
    async fn reading_the_client_first_answers_success() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut stream = ReplyStream::new(server, reply());
        client.write_all(b"hi").await.unwrap();
        let mut got = [0u8; 2];
        stream.read_exact(&mut got).await.unwrap();
        let mut answered = [0u8; 2];
        client.read_exact(&mut answered).await.unwrap();
        assert_eq!(&answered, b"ok");
    }

    #[tokio::test]
    async fn withheld_or_undecided_nothing_is_written() {
        for withhold in [true, false] {
            let (mut client, server) = tokio::io::duplex(64);
            let r = reply();
            let mut stream = ReplyStream::new(server, r.clone());
            if withhold {
                r.withheld();
            }
            stream.shutdown().await.unwrap();
            drop(stream);
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.unwrap();
            assert!(got.is_empty());
        }
    }
}
