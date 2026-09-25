//! Connections that end once their group moves off the member they went
//! through, for `interrupt_exist_connections`.
//!
//! A group that switches members sends new connections to the new one,
//! but the connections already open would otherwise stay on the old one
//! for as long as they last: long-lived ones never see the switch. These
//! wrappers fail such a connection's reads and writes, which ends it, as
//! soon as the selection moves off its member.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

use crate::adapter::*;
use crate::session::SocksAddr;

/// Resolves once the selection is not `member`. A group that is gone
/// (replaced by a reload) never ends its connections.
async fn moved_off(mut selection: watch::Receiver<usize>, member: usize) {
    if selection.wait_for(|&i| i != member).await.is_err() {
        std::future::pending::<()>().await
    }
}

fn interrupted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the group switched to another outbound",
    )
}

type Moved = Mutex<Pin<Box<dyn Future<Output = ()> + Send>>>;

fn moved(selection: &watch::Receiver<usize>, member: usize) -> Moved {
    Mutex::new(Box::pin(moved_off(selection.clone(), member)))
}

/// Whether the selection moved off; each direction watches on its own,
/// so that a read and a write pending in different tasks are both woken.
fn poll_moved(moved: &mut Moved, cx: &mut Context<'_>) -> bool {
    match moved.get_mut() {
        Ok(fut) => fut.as_mut().poll(cx).is_ready(),
        Err(_) => true,
    }
}

/// `stream`, which went through `member`, ended when `selection` moves
/// off it.
pub fn stream(stream: AnyStream, selection: &watch::Receiver<usize>, member: usize) -> AnyStream {
    Box::new(InterruptibleStream {
        inner: stream,
        read: moved(selection, member),
        write: moved(selection, member),
        interrupted: false,
    })
}

struct InterruptibleStream {
    inner: AnyStream,
    read: Moved,
    write: Moved,
    interrupted: bool,
}

impl AsyncRead for InterruptibleStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.interrupted || poll_moved(&mut this.read, cx) {
            this.interrupted = true;
            return Poll::Ready(Err(interrupted()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for InterruptibleStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.interrupted || poll_moved(&mut this.write, cx) {
            this.interrupted = true;
            return Poll::Ready(Err(interrupted()));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `datagram`, which went through `member`, ended when `selection` moves
/// off it.
pub fn datagram(
    datagram: AnyOutboundDatagram,
    selection: &watch::Receiver<usize>,
    member: usize,
) -> AnyOutboundDatagram {
    Box::new(InterruptibleDatagram {
        inner: datagram,
        selection: selection.clone(),
        member,
    })
}

struct InterruptibleDatagram {
    inner: AnyOutboundDatagram,
    selection: watch::Receiver<usize>,
    member: usize,
}

impl OutboundDatagram for InterruptibleDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (recv, send) = self.inner.split();
        (
            Box::new(RecvHalf {
                inner: recv,
                selection: self.selection.clone(),
                member: self.member,
            }),
            Box::new(SendHalf {
                inner: send,
                selection: self.selection,
                member: self.member,
            }),
        )
    }
}

struct RecvHalf {
    inner: Box<dyn OutboundDatagramRecvHalf>,
    selection: watch::Receiver<usize>,
    member: usize,
}

#[async_trait]
impl OutboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let moved = moved_off(self.selection.clone(), self.member);
        let recv = self.inner.recv_from(buf);
        futures::pin_mut!(moved, recv);
        match futures::future::select(recv, moved).await {
            futures::future::Either::Left((r, _)) => r,
            futures::future::Either::Right(_) => Err(interrupted()),
        }
    }
}

struct SendHalf {
    inner: Box<dyn OutboundDatagramSendHalf>,
    selection: watch::Receiver<usize>,
    member: usize,
}

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        if *self.selection.borrow() != self.member {
            return Err(interrupted());
        }
        self.inner.send_to(buf, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::outbound::selector::Selection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn a_stream_ends_when_the_group_moves_off_its_member() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let selection = Selection::new(0);
            let (a, mut b) = tokio::io::duplex(64);
            let mut a = stream(Box::new(a), &selection.subscribe(), 0);
            a.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            b.read_exact(&mut buf).await.unwrap();

            // A read pending while the group switches is woken and fails.
            let reader = tokio::spawn(async move {
                let mut buf = [0u8; 4];
                a.read(&mut buf).await
            });
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            selection.set(1);
            let r = tokio::time::timeout(std::time::Duration::from_secs(1), reader)
                .await
                .expect("the pending read must be woken")
                .unwrap();
            assert_eq!(r.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        });
    }

    #[test]
    fn a_stream_on_the_selected_member_stays() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let selection = Selection::new(1);
            let (a, mut b) = tokio::io::duplex(64);
            let mut a = stream(Box::new(a), &selection.subscribe(), 1);
            // Selecting the same member again is no change.
            selection.set(1);
            a.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            b.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        });
    }
}
