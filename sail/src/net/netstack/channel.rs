use std::io;

use sail_netstack::{
    ChecksumCapabilities, Packet, PacketBatch, PacketCapabilities, PacketIo, PacketToken,
};
use tokio::sync::mpsc::{self, error::TryRecvError, error::TrySendError};

/// A [`PacketIo`] over a pair of channels, for a stack whose IP packets come
/// from and go to something other than a device: the tunnel of a WireGuard
/// endpoint, or a test. Each packet is one whole IP datagram.
///
/// Both directions keep the cancellation contract of [`PacketIo`]: `recv`
/// takes packets off the channel only once it can no longer be dropped
/// before returning them, and `send` awaits only for room for its first
/// packet.
pub(crate) struct ChannelPacketIo {
    inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<Vec<u8>>,
    max_batch: usize,
    next_token: u64,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the WireGuard outbound is its first user outside tests"
    )
)]
impl ChannelPacketIo {
    /// Packets sent on `inbound` enter the stack, and packets the stack emits
    /// arrive on `outbound`, at most `max_batch` at a time.
    pub(crate) fn new(
        inbound: mpsc::Receiver<Vec<u8>>,
        outbound: mpsc::Sender<Vec<u8>>,
        max_batch: usize,
    ) -> Self {
        assert!(max_batch > 0, "channel batch size must be non-zero");
        Self {
            inbound,
            outbound,
            max_batch,
            next_token: 0,
        }
    }

    fn push(&mut self, out: &mut PacketBatch, payload: &[u8]) -> io::Result<()> {
        let token = PacketToken::new(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        out.push(Packet::from_payload(token, 0, payload))
            .map_err(|_| io::Error::other("receive batch is full"))
    }
}

impl PacketIo for ChannelPacketIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        let room = out.limit().saturating_sub(out.len()).min(self.max_batch);
        if room == 0 {
            return Ok(0);
        }
        let first = self
            .inbound
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "packet input closed"))?;
        self.push(out, &first)?;
        let mut received = 1;
        while received < room {
            match self.inbound.try_recv() {
                Ok(packet) => {
                    self.push(out, &packet)?;
                    received += 1;
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        Ok(received)
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        let mut packets = packets.iter();
        let Some(first) = packets.next() else {
            return Ok(0);
        };
        let permit = self
            .outbound
            .reserve()
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "packet output closed"))?;
        permit.send(first.payload().to_vec());
        let mut sent = 1;
        for packet in packets {
            match self.outbound.try_send(packet.payload().to_vec()) {
                Ok(()) => sent += 1,
                Err(TrySendError::Full(_) | TrySendError::Closed(_)) => break,
            }
        }
        Ok(sent)
    }

    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: self.max_batch,
            queue_count: 1,
            headroom: 0,
            vectored: false,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}
