//! Connections dialled through a named outbound, handed to the host: the
//! outbound's end stays on the instance's runtime, relayed to the host's
//! end in memory, so the host may use it from any executor, on every
//! platform. Either end closing closes the other; the instance stopping
//! closes both.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

use super::{Address, Error, Instance};
use crate::control::Dialed;
use crate::session::Network;

/// Datagrams waiting either way, at most; more are dropped, as UDP would.
const DATAGRAMS: usize = 256;
/// The largest datagram either way: any UDP payload.
const LARGEST: usize = 65_535;

/// A TCP connection through an outbound: read, write, shut down. Dropping
/// it closes the connection.
pub struct DialStream(tokio::io::DuplexStream);

impl AsyncRead for DialStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for DialStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// UDP through an outbound: datagrams to the address dialled, or another
/// the outbound reaches, and from them. Dropping it closes it.
pub struct DialDatagram {
    to: Address,
    out: mpsc::Sender<(Vec<u8>, Address)>,
    back: Mutex<mpsc::Receiver<(Vec<u8>, Address)>>,
}

impl DialDatagram {
    /// Sends `data` to the address dialled.
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        let to = self.to.clone();
        self.send_to(data, &to).await
    }

    /// Sends `data` to `to`, through the same outbound.
    pub async fn send_to(&self, data: &[u8], to: &Address) -> io::Result<()> {
        if data.len() > LARGEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "larger than a datagram",
            ));
        }
        self.out
            .send((data.to_vec(), to.clone()))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    /// The next datagram, into `buf`, cut to its length: its length, and
    /// where it came from.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let (data, from) = self
            .back
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, from))
    }
}

impl Instance {
    /// Connects to `to` over TCP through the outbound `outbound` alone,
    /// whatever the rules say, within `timeout`: its handshake done, the
    /// name resolved as a routed connection's would be. Listed among the
    /// connections under the inbound `control`.
    pub async fn dial_tcp(
        &self,
        outbound: &str,
        to: Address,
        timeout: Duration,
    ) -> Result<DialStream, Error> {
        let outbound = outbound.to_string();
        self.with_dialer(timeout, move |dialer, timeout| {
            Box::pin(async move {
                let Dialed::Stream(stream) =
                    dialer.dial(&outbound, Network::Tcp, to, timeout).await?
                else {
                    unreachable!("a TCP dial gives a stream");
                };
                let relay = dialer.env().options.relay.clone();
                let (host, ours) = tokio::io::duplex(relay.buffer_size.max(1) * 1024);
                dialer.env().scope.spawn(
                    "dial relay",
                    crate::control::relay_stream(ours, stream, relay),
                );
                Ok(DialStream(host))
            })
        })
        .await?
    }

    /// Opens UDP to `to` through the outbound `outbound` alone, as
    /// `dial_tcp` does.
    pub async fn dial_udp(
        &self,
        outbound: &str,
        to: Address,
        timeout: Duration,
    ) -> Result<DialDatagram, Error> {
        let outbound = outbound.to_string();
        let dialled = to.clone();
        self.with_dialer(timeout, move |dialer, timeout| {
            Box::pin(async move {
                let Dialed::Datagram(datagram) = dialer
                    .dial(&outbound, Network::Udp, dialled, timeout)
                    .await?
                else {
                    unreachable!("a UDP dial gives datagrams");
                };
                let (mut recv, send) = datagram.split();
                let (out_tx, mut out_rx) = mpsc::channel::<(Vec<u8>, Address)>(DATAGRAMS);
                let (back_tx, back_rx) = mpsc::channel(DATAGRAMS);
                let send = Arc::new(Mutex::new(send));
                dialer.env().scope.spawn("dial datagrams out", {
                    let send = send.clone();
                    async move {
                        while let Some((data, to)) = out_rx.recv().await {
                            if send.lock().await.send_to(&data, &to).await.is_err() {
                                break;
                            }
                        }
                        let _ = send.lock().await.close().await;
                    }
                });
                dialer.env().scope.spawn("dial datagrams back", async move {
                    let mut buf = vec![0u8; LARGEST];
                    loop {
                        tokio::select! {
                            got = recv.recv_from(&mut buf) => match got {
                                Ok((n, from)) => {
                                    // Full: dropped, as the network would.
                                    if let Err(mpsc::error::TrySendError::Closed(_)) =
                                        back_tx.try_send((buf[..n].to_vec(), from))
                                    {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            },
                            _ = back_tx.closed() => break,
                        }
                    }
                });
                Ok::<_, Error>(DialDatagram {
                    to,
                    out: out_tx,
                    back: Mutex::new(back_rx),
                })
            })
        })
        .await?
    }
}
