use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool as CleanupActive, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, SinkExt};
#[cfg(target_os = "linux")]
use sail_netstack::{parse_ip_packet, parse_tcp_segment};
use sail_netstack::{
    ChecksumCapabilities, NetworkGeneration, Packet, PacketBatch, PacketCapabilities, PacketIo,
    PacketToken, ResourceLedger, RunnerConfig, RunnerError, ShardRouterStats, ShardedPacketIo,
    ShardedPacketIoControl, SingleShardRunner, SlabChain, StackStats, StepOutcome, TcpError,
    TcpEvent, TcpFlowToken, TcpTableError, UdpFlowToken,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc as tokio_mpsc, watch, Notify};

use super::native_stream::{command_channel, next_command, NativeTcpStream, TcpCommand};

const TIMER_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) struct TunPacketIo {
    writer: tun::DeviceWriter,
    reader: tun::DeviceReader,
    recv_buffer: Vec<u8>,
    max_batch: usize,
    next_token: u64,
    pending_recv_error: Option<io::Error>,
    pending_send_error: Option<io::Error>,
}

impl TunPacketIo {
    pub(super) fn new(device: tun::AsyncDevice, mtu: usize, max_batch: usize) -> io::Result<Self> {
        if max_batch == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo batch size must be non-zero",
            ));
        }
        let (writer, reader) = device.split()?;
        Ok(Self {
            writer,
            reader,
            recv_buffer: vec![0; mtu],
            max_batch,
            next_token: 0,
            pending_recv_error: None,
            pending_send_error: None,
        })
    }

    fn push_received(&mut self, out: &mut PacketBatch, count: usize) -> io::Result<()> {
        let token = PacketToken::new(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        out.push(Packet::from_payload(token, 0, &self.recv_buffer[..count]))
            .map_err(|_| io::Error::other("native PacketIo receive batch is full"))
    }
}

impl PacketIo for TunPacketIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        if let Some(error) = self.pending_recv_error.take() {
            return Err(error);
        }
        let initial_len = out.len();
        let receive_limit = self.max_batch.min(out.limit().saturating_sub(initial_len));
        if receive_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo receive batch has no free slots",
            ));
        }
        let count = self.reader.read(&mut self.recv_buffer).await?;
        if count == 0 {
            return Ok(0);
        }
        self.push_received(out, count)?;
        while out.len().saturating_sub(initial_len) < receive_limit {
            match self.reader.read(&mut self.recv_buffer).now_or_never() {
                None => break,
                Some(Ok(0)) => {
                    self.pending_recv_error = Some(io::Error::from(io::ErrorKind::UnexpectedEof));
                    break;
                }
                Some(Ok(count)) => self.push_received(out, count)?,
                Some(Err(error)) => {
                    self.pending_recv_error = Some(error);
                    break;
                }
            }
        }
        Ok(out.len().saturating_sub(initial_len))
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        if let Some(error) = self.pending_send_error.take() {
            return Err(error);
        }
        let mut sent = 0;
        for packet in packets.iter() {
            // PacketIo cancellation: await only before the first packet is
            // accepted, then report a partial send instead of waiting.
            let result = if sent == 0 {
                self.writer.write(packet.payload()).await
            } else {
                match self.writer.write(packet.payload()).now_or_never() {
                    Some(result) => result,
                    None => break,
                }
            };
            let error = match result {
                Ok(written) if written == packet.payload().len() => {
                    sent += 1;
                    continue;
                }
                Ok(_) => io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TUN device accepted a partial packet",
                ),
                Err(error) => error,
            };
            if sent == 0 {
                return Err(error);
            }
            self.pending_send_error = Some(error);
            break;
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

#[cfg(target_os = "linux")]
fn prepare_coalesced_tcp_batch(
    gro_table: &mut tun_rs::GROTable,
    buffers: &mut [Vec<u8>],
    packets: &PacketBatch,
) -> Option<usize> {
    let count = packets.len();
    if count < 2 || count > buffers.len() {
        return None;
    }
    let mut original_payload_bytes = 0_usize;
    for (buffer, packet) in buffers.iter_mut().zip(packets.iter()).take(count) {
        let segment =
            parse_tcp_segment(parse_ip_packet(packet.payload(), true).ok()?, true).ok()?;
        if segment.payload.is_empty() {
            return None;
        }
        original_payload_bytes = original_payload_bytes.checked_add(segment.payload.len())?;
        buffer.clear();
        buffer.resize(tun_rs::VIRTIO_NET_HDR_LEN, 0);
        buffer.extend_from_slice(packet.payload());
    }
    gro_table
        .apply_gro(&mut buffers[..count], tun_rs::VIRTIO_NET_HDR_LEN, false)
        .ok()?;

    let mut candidate = None;
    for (index, buffer) in buffers[..count].iter().enumerate() {
        let header = tun_rs::VirtioNetHdr::decode(buffer).ok()?;
        let gso_type = header.gso_type & 0x7f;
        if !matches!(
            gso_type,
            tun_rs::VIRTIO_NET_HDR_GSO_TCPV4 | tun_rs::VIRTIO_NET_HDR_GSO_TCPV6
        ) {
            continue;
        }
        if candidate.is_some() || header.gso_size == 0 {
            return None;
        }
        let header_bytes = usize::from(header.hdr_len);
        let payload_bytes = buffer
            .len()
            .checked_sub(tun_rs::VIRTIO_NET_HDR_LEN + header_bytes)?;
        let segment_size = usize::from(header.gso_size);
        if payload_bytes != original_payload_bytes || payload_bytes.div_ceil(segment_size) != count
        {
            return None;
        }
        candidate = Some(index);
    }
    candidate
}

#[cfg(target_os = "linux")]
pub(super) struct TunRsPacketIo {
    device: tun_rs::AsyncDevice,
    recv_buffer: Vec<u8>,
    offload_buffer: Vec<u8>,
    offload_send_packets: Vec<Vec<u8>>,
    offload_packets: Vec<Vec<u8>>,
    offload_sizes: Vec<usize>,
    pending_packet_index: usize,
    pending_packet_count: usize,
    gro_table: tun_rs::GROTable,
    offload: bool,
    max_batch: usize,
    queue_count: usize,
    next_token: u64,
    pending_recv_error: Option<io::Error>,
    pending_send_error: Option<io::Error>,
}

#[cfg(target_os = "linux")]
impl TunRsPacketIo {
    pub(super) fn new(
        device: tun_rs::AsyncDevice,
        mtu: usize,
        max_batch: usize,
        queue_count: usize,
        offload: bool,
    ) -> io::Result<Self> {
        if mtu == 0 || max_batch == 0 || queue_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo MTU, batch size, and queue count must be non-zero",
            ));
        }
        let required_segments = 65_535 / mtu + 1;
        if offload && max_batch < required_segments {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "native PacketIo offload requires at least {required_segments} packet buffers"
                ),
            ));
        }
        Ok(Self {
            device,
            recv_buffer: vec![0; mtu],
            offload_buffer: vec![0; tun_rs::VIRTIO_NET_HDR_LEN + 65_535],
            offload_send_packets: (0..max_batch)
                .map(|index| {
                    let packet_capacity = if index == 0 { 65_535 } else { mtu };
                    Vec::with_capacity(2 * tun_rs::VIRTIO_NET_HDR_LEN + packet_capacity)
                })
                .collect(),
            offload_packets: (0..max_batch).map(|_| vec![0; mtu]).collect(),
            offload_sizes: vec![0; max_batch],
            pending_packet_index: 0,
            pending_packet_count: 0,
            gro_table: tun_rs::GROTable::default(),
            offload,
            max_batch,
            queue_count,
            next_token: 0,
            pending_recv_error: None,
            pending_send_error: None,
        })
    }

    fn push_received(&mut self, out: &mut PacketBatch, count: usize) -> io::Result<()> {
        let token = PacketToken::new(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        out.push(Packet::from_payload(token, 0, &self.recv_buffer[..count]))
            .map_err(|_| io::Error::other("native PacketIo receive batch is full"))
    }

    fn push_offload_packet(&mut self, out: &mut PacketBatch, index: usize) -> io::Result<()> {
        let token = PacketToken::new(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        let size = self.offload_sizes[index];
        let payload = self.offload_packets[index]
            .get(..size)
            .ok_or_else(|| io::Error::other("TUN offload produced an oversized segment"))?;
        out.push(Packet::from_payload(token, 0, payload))
            .map_err(|_| io::Error::other("native PacketIo receive batch is full"))
    }
}

#[cfg(target_os = "linux")]
impl PacketIo for TunRsPacketIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        if let Some(error) = self.pending_recv_error.take() {
            return Err(error);
        }
        let initial_len = out.len();
        let receive_limit = self.max_batch.min(out.limit().saturating_sub(initial_len));
        if receive_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo receive batch has no free slots",
            ));
        }
        while self.pending_packet_index < self.pending_packet_count
            && out.len().saturating_sub(initial_len) < receive_limit
        {
            let index = self.pending_packet_index;
            self.pending_packet_index += 1;
            self.push_offload_packet(out, index)?;
        }
        if self.pending_packet_index == self.pending_packet_count {
            self.pending_packet_index = 0;
            self.pending_packet_count = 0;
        }
        if out.len() > initial_len {
            return Ok(out.len().saturating_sub(initial_len));
        }
        if self.offload {
            let count = self
                .device
                .recv_multiple(
                    &mut self.offload_buffer,
                    &mut self.offload_packets,
                    &mut self.offload_sizes,
                    0,
                )
                .await?;
            if count > self.offload_packets.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TUN offload reported too many segments",
                ));
            }
            self.pending_packet_count = count;
            while self.pending_packet_index < self.pending_packet_count
                && out.len().saturating_sub(initial_len) < receive_limit
            {
                let index = self.pending_packet_index;
                self.pending_packet_index += 1;
                self.push_offload_packet(out, index)?;
            }
            if self.pending_packet_index == self.pending_packet_count {
                self.pending_packet_index = 0;
                self.pending_packet_count = 0;
            }
            return Ok(out.len().saturating_sub(initial_len));
        }
        let count = self.device.recv(&mut self.recv_buffer).await?;
        if count == 0 {
            return Ok(0);
        }
        self.push_received(out, count)?;
        while out.len().saturating_sub(initial_len) < receive_limit {
            match self.device.try_recv(&mut self.recv_buffer) {
                Ok(0) => {
                    self.pending_recv_error = Some(io::Error::from(io::ErrorKind::UnexpectedEof));
                    break;
                }
                Ok(count) => self.push_received(out, count)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    self.pending_recv_error = Some(error);
                    break;
                }
            }
        }
        Ok(out.len().saturating_sub(initial_len))
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        if let Some(error) = self.pending_send_error.take() {
            return Err(error);
        }
        if self.offload {
            if let Some(index) = prepare_coalesced_tcp_batch(
                &mut self.gro_table,
                &mut self.offload_send_packets,
                packets,
            ) {
                let frame = &self.offload_send_packets[index];
                return match self.device.send(frame).await {
                    Ok(written) if written == frame.len() => Ok(packets.len()),
                    Ok(_) => Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TUN device accepted a partial GSO frame",
                    )),
                    Err(error) => Err(error),
                };
            }
        }
        let mut sent = 0;
        for packet in packets.iter() {
            let expected = if self.offload {
                tun_rs::VIRTIO_NET_HDR_LEN + packet.payload().len()
            } else {
                packet.payload().len()
            };
            // PacketIo cancellation: await only before the first packet is
            // accepted; later packets use a non-blocking send.
            let result = if self.offload {
                let buffer = &mut self.offload_send_packets[0];
                buffer.clear();
                buffer.resize(tun_rs::VIRTIO_NET_HDR_LEN, 0);
                buffer.extend_from_slice(packet.payload());
                if sent == 0 {
                    self.device.send(buffer).await
                } else {
                    self.device.try_send(buffer)
                }
            } else if sent == 0 {
                self.device.send(packet.payload()).await
            } else {
                self.device.try_send(packet.payload())
            };
            match result {
                Ok(written) if written == expected => {
                    sent += 1;
                }
                Ok(_) if sent == 0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TUN device accepted a partial packet",
                    ));
                }
                Ok(_) => {
                    self.pending_send_error = Some(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TUN device accepted a partial packet",
                    ));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && sent > 0 => break,
                Err(error) if sent == 0 => return Err(error),
                Err(error) => {
                    self.pending_send_error = Some(error);
                    break;
                }
            }
        }
        Ok(sent)
    }

    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: self.max_batch,
            queue_count: self.queue_count,
            headroom: 0,
            vectored: false,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}

pub(super) struct NativeAccepted {
    pub connection: sail_netstack::TcpConnection,
    pub stream: NativeTcpStream,
}

pub(super) struct NativeUdpDatagram {
    pub token: UdpFlowToken,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: SlabChain,
}

#[derive(Clone)]
pub(super) struct NativeUdpReplyHandle {
    commands: Vec<mpsc::Sender<TcpCommand>>,
}

impl NativeUdpReplyHandle {
    pub(super) async fn send(
        &mut self,
        token: UdpFlowToken,
        source: SocketAddr,
        payload: Vec<u8>,
    ) -> io::Result<()> {
        let (response, receiver) = oneshot::channel();
        let commands = self
            .commands
            .get_mut(usize::from(token.shard().get()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid UDP token shard")
            })?;
        commands
            .send(TcpCommand::UdpReply {
                token,
                source,
                payload,
                response,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner stopped"))?;
        receiver
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner dropped reply"))?
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NativeStatsSnapshot {
    pub stack: StackStats,
    pub router: ShardRouterStats,
    pub shard_count: usize,
}

#[derive(Clone)]
pub(crate) struct NativeRuntimeControl {
    commands: Vec<mpsc::Sender<TcpCommand>>,
    router: ShardedPacketIoControl,
    ledger: Arc<ResourceLedger>,
    completion: watch::Receiver<bool>,
}

impl NativeRuntimeControl {
    async fn send_all<T>(
        &mut self,
        mut command: impl FnMut(oneshot::Sender<T>) -> TcpCommand,
    ) -> io::Result<Vec<oneshot::Receiver<T>>> {
        let mut receivers = Vec::with_capacity(self.commands.len());
        for commands in &mut self.commands {
            let (response, receiver) = oneshot::channel();
            commands
                .send(command(response))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner stopped"))?;
            receivers.push(receiver);
        }
        Ok(receivers)
    }

    async fn wait_all<T>(receivers: Vec<oneshot::Receiver<T>>) -> io::Result<Vec<T>> {
        futures::future::try_join_all(receivers)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native runner dropped reply"))
    }

    pub(crate) async fn shutdown(&mut self, grace_period_ms: u64) -> io::Result<()> {
        let receivers = self
            .send_all(|response| TcpCommand::Shutdown {
                grace_period_ms,
                response,
            })
            .await?;
        Self::wait_all(receivers).await.map(|_| ())
    }

    pub(crate) async fn wait_stopped(&mut self) -> io::Result<()> {
        self.completion
            .wait_for(|stopped| *stopped)
            .await
            .map(|_| ())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "native runtime completion channel closed",
                )
            })
    }

    pub(super) async fn abort(&mut self) -> io::Result<()> {
        let receivers = self
            .send_all(|response| TcpCommand::ControlAbort { response })
            .await?;
        Self::wait_all(receivers).await.map(|_| ())
    }

    pub(crate) async fn reset_network(&mut self, generation: NetworkGeneration) -> io::Result<()> {
        // Change classification first. Packets racing the transition can be
        // dropped, but cannot create fresh ownership under the old generation.
        self.router.reset_network(generation)?;
        let receivers = self
            .send_all(|response| TcpCommand::ResetNetwork {
                generation,
                response,
            })
            .await?;
        Self::wait_all(receivers).await.map(|_| ())
    }

    pub(crate) async fn update_mtu(&mut self, mtu: usize) -> io::Result<()> {
        let receivers = self
            .send_all(|response| TcpCommand::UpdateMtu { mtu, response })
            .await?;
        for result in Self::wait_all(receivers).await? {
            result.map_err(runner_io_error)?;
        }
        Ok(())
    }

    pub(super) async fn stats_snapshot(&mut self) -> io::Result<NativeStatsSnapshot> {
        let receivers = self
            .send_all(|response| TcpCommand::StatsSnapshot { response })
            .await?;
        let shards = Self::wait_all(receivers).await?;
        let shard_count = shards.len();
        let stack = StackStats::aggregate(shards, self.ledger.snapshot()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native shard generations disagree",
            )
        })?;
        Ok(NativeStatsSnapshot {
            stack,
            router: self.router.stats()?,
            shard_count,
        })
    }
}

struct FlowBridge {
    cleanup_active: Arc<CleanupActive>,
    readable_bytes: usize,
    peer_eof: bool,
    pending_read: Option<(usize, oneshot::Sender<io::Result<Vec<u8>>>)>,
    pending_write_reservation: Option<(usize, oneshot::Sender<io::Result<usize>>)>,
    reserved_write_bytes: usize,
    pending_write: Option<(Vec<u8>, oneshot::Sender<io::Result<usize>>)>,
    pending_close: Option<oneshot::Sender<io::Result<()>>>,
}

impl FlowBridge {
    fn new(cleanup_active: Arc<CleanupActive>) -> Self {
        Self {
            cleanup_active,
            readable_bytes: 0,
            peer_eof: false,
            pending_read: None,
            pending_write_reservation: None,
            reserved_write_bytes: 0,
            pending_write: None,
            pending_close: None,
        }
    }

    fn fail(mut self, message: &'static str) {
        self.cleanup_active.store(false, AtomicOrdering::Release);
        if let Some((_, response)) = self.pending_read.take() {
            let _ = response.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)));
        }
        if let Some((_, response)) = self.pending_write_reservation.take() {
            let _ = response.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)));
        }
        if let Some((_, response)) = self.pending_write.take() {
            let _ = response.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)));
        }
        if let Some(response) = self.pending_close.take() {
            let _ = response.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)));
        }
    }
}

pub(super) struct NativeRuntime<I> {
    runner: SingleShardRunner<I>,
    commands_tx: mpsc::Sender<TcpCommand>,
    commands_rx: mpsc::Receiver<TcpCommand>,
    cleanup_tx: tokio_mpsc::Sender<TcpFlowToken>,
    cleanup_rx: tokio_mpsc::Receiver<TcpFlowToken>,
    cleanup_overflow: Arc<Notify>,
    accepted_tx: tokio_mpsc::Sender<NativeAccepted>,
    udp_tx: tokio_mpsc::Sender<NativeUdpDatagram>,
    flows: HashMap<TcpFlowToken, FlowBridge>,
}

impl<I: PacketIo> NativeRuntime<I> {
    #[cfg(test)]
    pub(super) fn new(
        io: I,
        ledger: Arc<ResourceLedger>,
        config: RunnerConfig,
        command_capacity: usize,
        accept_capacity: usize,
        udp_capacity: usize,
    ) -> Result<
        (
            Self,
            tokio_mpsc::Receiver<NativeAccepted>,
            tokio_mpsc::Receiver<NativeUdpDatagram>,
            NativeUdpReplyHandle,
        ),
        RunnerError,
    > {
        assert!(
            command_capacity > 0,
            "native command capacity must be non-zero"
        );
        assert!(
            accept_capacity > 0,
            "native accept capacity must be non-zero"
        );
        assert!(udp_capacity > 0, "native UDP capacity must be non-zero");
        let (accepted_tx, accepted_rx) = tokio_mpsc::channel(accept_capacity);
        let (udp_tx, udp_rx) = tokio_mpsc::channel(udp_capacity);
        let (runtime, commands_tx) =
            Self::new_with_sinks(io, ledger, config, command_capacity, accepted_tx, udp_tx)?;
        let udp_reply = NativeUdpReplyHandle {
            commands: vec![commands_tx],
        };
        Ok((runtime, accepted_rx, udp_rx, udp_reply))
    }

    fn new_with_sinks(
        io: I,
        ledger: Arc<ResourceLedger>,
        config: RunnerConfig,
        command_capacity: usize,
        accepted_tx: tokio_mpsc::Sender<NativeAccepted>,
        udp_tx: tokio_mpsc::Sender<NativeUdpDatagram>,
    ) -> Result<(Self, mpsc::Sender<TcpCommand>), RunnerError> {
        assert!(
            command_capacity > 0,
            "native command capacity must be non-zero"
        );
        let cleanup_capacity = ledger.budget().max_tcp_flows;
        let runner = SingleShardRunner::new(io, ledger, config)?;
        let (commands_tx, commands_rx) = command_channel(command_capacity);
        let (cleanup_tx, cleanup_rx) = tokio_mpsc::channel(cleanup_capacity);
        let cleanup_overflow = Arc::new(Notify::new());
        Ok((
            Self {
                runner,
                commands_tx: commands_tx.clone(),
                commands_rx,
                cleanup_tx,
                cleanup_rx,
                cleanup_overflow,
                accepted_tx,
                udp_tx,
                flows: HashMap::new(),
            },
            commands_tx,
        ))
    }

    pub(super) async fn run(mut self) -> Result<(), RunnerError> {
        let started = Instant::now();
        let cleanup_overflow = Arc::clone(&self.cleanup_overflow);
        let mut interval = tokio::time::interval(TIMER_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            enum Wake {
                Command(Option<TcpCommand>),
                Cleanup(Option<TcpFlowToken>),
                CleanupOverflow,
                Step(Result<StepOutcome, RunnerError>),
                Timer,
            }
            let wake = tokio::select! {
                command = next_command(&mut self.commands_rx) => Wake::Command(command),
                cleanup = self.cleanup_rx.recv() => Wake::Cleanup(cleanup),
                () = cleanup_overflow.notified() => Wake::CleanupOverflow,
                result = self.runner.step(now_ms) => Wake::Step(result),
                _ = interval.tick() => Wake::Timer,
            };
            match wake {
                Wake::Command(Some(command)) => {
                    if self.handle_command(command, now_ms) {
                        return Ok(());
                    }
                }
                Wake::Command(None) => {
                    self.runner.abort();
                    self.fail_all("native TCP command channel closed");
                    return Ok(());
                }
                Wake::Cleanup(Some(token)) => self.abort_flow(token),
                Wake::Cleanup(None) => {}
                Wake::CleanupOverflow => self.cleanup_dropped_streams(),
                Wake::Step(Ok(outcome)) => self.handle_outcome(outcome),
                Wake::Step(Err(RunnerError::Closed)) => {
                    self.fail_all("native network runner stopped");
                    return Ok(());
                }
                Wake::Step(Err(error)) => {
                    self.fail_all("native network runner failed");
                    return Err(error);
                }
                Wake::Timer => self.retry_pending(),
            }
        }
    }

    /// Returns true when the runtime should stop after acknowledging a
    /// terminal control command.
    fn handle_command(&mut self, command: TcpCommand, now_ms: u64) -> bool {
        match command {
            TcpCommand::Read {
                token,
                max_bytes,
                response,
            } => {
                let Some(flow) = self.flows.get_mut(&token) else {
                    let _ = response.send(Ok(Vec::new()));
                    return false;
                };
                if flow.pending_read.is_some() {
                    let _ = response.send(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "concurrent TCP read",
                    )));
                    return false;
                }
                flow.pending_read = Some((max_bytes, response));
                self.service_read(token);
            }
            TcpCommand::ReserveWrite {
                token,
                max_bytes,
                response,
            } => self.try_reserve_write(token, max_bytes, response),
            TcpCommand::CommitWrite {
                token,
                payload,
                response,
            } => self.try_write(token, payload, response),
            TcpCommand::Close { token, response } => self.try_close(token, response),
            TcpCommand::UdpReply {
                token,
                source,
                payload,
                response,
            } => {
                let result = self
                    .runner
                    .queue_udp_reply(token, source, &payload, now_ms)
                    .map_err(runner_io_error);
                let _ = response.send(result);
            }
            TcpCommand::Shutdown {
                grace_period_ms,
                response,
            } => {
                self.runner.shutdown(now_ms.saturating_add(grace_period_ms));
                let _ = response.send(());
            }
            TcpCommand::ControlAbort { response } => {
                self.runner.abort();
                self.fail_all("native network runner aborted");
                let _ = response.send(());
                return true;
            }
            TcpCommand::ResetNetwork {
                generation,
                response,
            } => {
                self.runner.reset_network(generation);
                self.fail_all("native network generation changed");
                let _ = response.send(());
            }
            TcpCommand::UpdateMtu { mtu, response } => {
                let _ = response.send(self.runner.update_mtu(mtu));
            }
            TcpCommand::StatsSnapshot { response } => {
                let _ = response.send(self.runner.stats_snapshot());
            }
        }
        false
    }

    fn handle_outcome(&mut self, outcome: StepOutcome) {
        for datagram in outcome.datagrams {
            let datagram = NativeUdpDatagram {
                token: datagram.token,
                source: datagram.source,
                destination: datagram.destination,
                payload: datagram.payload,
            };
            if self.udp_tx.try_send(datagram).is_err() {
                tracing::warn!("native UDP uplink channel is full; dropping datagram");
            }
        }
        for event in outcome.tcp_events {
            match event {
                TcpEvent::Accepted(connection) => self.accept(connection),
                // The TUN runtime opens no connections; `connect` arrives with
                // the shared runtime.
                TcpEvent::Connected(_) => {}
                TcpEvent::Readable { token, bytes } => {
                    if let Some(flow) = self.flows.get_mut(&token) {
                        flow.readable_bytes = flow.readable_bytes.saturating_add(bytes);
                    }
                    self.service_read(token);
                }
                TcpEvent::Writable(token) => {
                    self.retry_write(token);
                    self.retry_write_reservation(token);
                    self.retry_close(token);
                }
                TcpEvent::PeerHalfClosed(token) => {
                    if let Some(flow) = self.flows.get_mut(&token) {
                        flow.peer_eof = true;
                    }
                    self.service_read(token);
                }
                TcpEvent::Closed(token) => self.finish_flow(token),
            }
        }
    }

    fn accept(&mut self, connection: sail_netstack::TcpConnection) {
        let token = connection.token;
        if self.runner.accept_tcp(token).is_err() {
            return;
        }
        let cleanup_active = Arc::new(CleanupActive::new(true));
        let stream = NativeTcpStream::new(
            token,
            connection.max_segment_payload_bytes,
            self.commands_tx.clone(),
            self.cleanup_tx.clone(),
            Arc::clone(&self.cleanup_overflow),
            Arc::clone(&cleanup_active),
        );
        self.flows.insert(token, FlowBridge::new(cleanup_active));
        if self
            .accepted_tx
            .try_send(NativeAccepted { connection, stream })
            .is_err()
        {
            self.abort_flow(token);
        }
    }

    fn service_read(&mut self, token: TcpFlowToken) {
        let Some(flow) = self.flows.get_mut(&token) else {
            return;
        };
        let should_complete =
            flow.pending_read.is_some() && (flow.readable_bytes > 0 || flow.peer_eof);
        if !should_complete {
            return;
        }
        let (max_bytes, response) = flow.pending_read.take().expect("checked above");
        if flow.readable_bytes == 0 {
            let _ = response.send(Ok(Vec::new()));
            return;
        }
        let amount = max_bytes.min(flow.readable_bytes);
        match self.runner.read_tcp(token, amount) {
            Ok(bytes) => {
                flow.readable_bytes = flow.readable_bytes.saturating_sub(bytes.len());
                if response.send(Ok(bytes)).is_err() {
                    self.abort_flow(token);
                }
            }
            Err(error) => {
                let _ = response.send(Err(runner_io_error(error)));
            }
        }
    }

    fn try_write(
        &mut self,
        token: TcpFlowToken,
        payload: Vec<u8>,
        response: oneshot::Sender<io::Result<usize>>,
    ) {
        let Some(flow) = self.flows.get_mut(&token) else {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP flow is closed",
            )));
            return;
        };
        if flow.pending_write.is_some() {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "concurrent TCP write",
            )));
            return;
        }
        if payload.is_empty() || payload.len() > flow.reserved_write_bytes {
            flow.reserved_write_bytes = 0;
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP write exceeded its reservation",
            )));
            return;
        }
        flow.reserved_write_bytes = 0;
        self.submit_write(token, payload, response);
    }

    fn submit_write(
        &mut self,
        token: TcpFlowToken,
        payload: Vec<u8>,
        response: oneshot::Sender<io::Result<usize>>,
    ) {
        let Some(flow) = self.flows.get_mut(&token) else {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP flow is closed",
            )));
            return;
        };
        if flow.pending_write.is_some() {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "concurrent TCP write",
            )));
            return;
        }
        match self.runner.write_tcp(token, &payload) {
            Ok(_) => {
                if response.send(Ok(payload.len())).is_err() {
                    self.abort_flow(token);
                }
            }
            Err(error) if retryable(&error) => flow.pending_write = Some((payload, response)),
            Err(error) => {
                let _ = response.send(Err(runner_io_error(error)));
            }
        }
    }

    fn try_reserve_write(
        &mut self,
        token: TcpFlowToken,
        max_bytes: usize,
        response: oneshot::Sender<io::Result<usize>>,
    ) {
        let Some(flow) = self.flows.get_mut(&token) else {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP flow is closed",
            )));
            return;
        };
        if max_bytes == 0
            || flow.pending_write_reservation.is_some()
            || flow.reserved_write_bytes != 0
            || flow.pending_write.is_some()
        {
            let _ = response.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "concurrent or empty TCP write reservation",
            )));
            return;
        }
        let limit = match self.runner.tcp_write_capacity(token) {
            Ok(limit) => limit,
            Err(error) => {
                let _ = response.send(Err(runner_io_error(error)));
                return;
            }
        };
        if limit == 0 {
            flow.pending_write_reservation = Some((max_bytes, response));
            return;
        }
        let amount = max_bytes.min(limit);
        flow.reserved_write_bytes = amount;
        if response.send(Ok(amount)).is_err() {
            flow.reserved_write_bytes = 0;
        }
    }

    fn retry_write(&mut self, token: TcpFlowToken) {
        let pending = self
            .flows
            .get_mut(&token)
            .and_then(|flow| flow.pending_write.take());
        if let Some((payload, response)) = pending {
            self.submit_write(token, payload, response);
        }
    }

    fn retry_write_reservation(&mut self, token: TcpFlowToken) {
        let pending = self
            .flows
            .get_mut(&token)
            .and_then(|flow| flow.pending_write_reservation.take());
        if let Some((max_bytes, response)) = pending {
            self.try_reserve_write(token, max_bytes, response);
        }
    }

    fn try_close(&mut self, token: TcpFlowToken, response: oneshot::Sender<io::Result<()>>) {
        let Some(flow) = self.flows.get_mut(&token) else {
            let _ = response.send(Ok(()));
            return;
        };
        flow.pending_write_reservation = None;
        flow.reserved_write_bytes = 0;
        match self.runner.close_tcp(token) {
            Ok(_) => {
                let _ = response.send(Ok(()));
            }
            Err(error) if retryable(&error) => flow.pending_close = Some(response),
            Err(error) => {
                let _ = response.send(Err(runner_io_error(error)));
            }
        }
    }

    fn retry_close(&mut self, token: TcpFlowToken) {
        let pending = self
            .flows
            .get_mut(&token)
            .and_then(|flow| flow.pending_close.take());
        if let Some(response) = pending {
            self.try_close(token, response);
        }
    }

    fn retry_pending(&mut self) {
        let tokens: Vec<_> = self.flows.keys().copied().collect();
        for token in tokens {
            self.retry_write(token);
            self.retry_write_reservation(token);
            self.retry_close(token);
            self.service_read(token);
        }
    }

    fn cleanup_dropped_streams(&mut self) {
        let dropped = self
            .flows
            .iter()
            .filter_map(|(token, flow)| {
                (!flow.cleanup_active.load(AtomicOrdering::Acquire)).then_some(*token)
            })
            .collect::<Vec<_>>();
        for token in dropped {
            self.abort_flow(token);
        }
    }

    fn abort_flow(&mut self, token: TcpFlowToken) {
        if let Some(flow) = self.flows.remove(&token) {
            flow.fail("TCP stream aborted");
        }
        let _ = self.runner.abort_tcp(token);
    }

    fn finish_flow(&mut self, token: TcpFlowToken) {
        if let Some(mut flow) = self.flows.remove(&token) {
            if let Some((_, response)) = flow.pending_read.take() {
                let _ = response.send(Ok(Vec::new()));
            }
            flow.fail("TCP flow closed");
        }
    }

    fn fail_all(&mut self, message: &'static str) {
        for (_, flow) in self.flows.drain() {
            flow.fail(message);
        }
    }
}

pub(super) struct NativeRuntimeGroup<I: PacketIo> {
    runtimes: Vec<NativeRuntime<ShardedPacketIo<I>>>,
    completion: watch::Sender<bool>,
}

type NativeRuntimeGroupParts<I> = (
    NativeRuntimeGroup<I>,
    tokio_mpsc::Receiver<NativeAccepted>,
    tokio_mpsc::Receiver<NativeUdpDatagram>,
    NativeUdpReplyHandle,
    NativeRuntimeControl,
);

impl<I: PacketIo> NativeRuntimeGroup<I> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        queues: Vec<I>,
        ledger: Arc<ResourceLedger>,
        config: RunnerConfig,
        command_capacity: usize,
        accept_capacity: usize,
        udp_capacity: usize,
    ) -> Result<NativeRuntimeGroupParts<I>, RunnerError> {
        assert!(
            accept_capacity > 0,
            "native accept capacity must be non-zero"
        );
        assert!(udp_capacity > 0, "native UDP capacity must be non-zero");
        let (adapters, router) = ShardedPacketIo::group(
            queues,
            Arc::clone(&ledger),
            config.generation,
            config.scheduler,
        )
        .map_err(|error| RunnerError::Io(io::Error::other(error)))?;
        let (accepted_tx, accepted_rx) = tokio_mpsc::channel(accept_capacity);
        let (udp_tx, udp_rx) = tokio_mpsc::channel(udp_capacity);
        let (completion_tx, completion_rx) = watch::channel(false);
        let mut runtimes = Vec::with_capacity(adapters.len());
        let mut commands = Vec::with_capacity(adapters.len());
        for adapter in adapters {
            let mut shard_config = config;
            shard_config.shard = adapter.shard();
            let (runtime, command) = NativeRuntime::new_with_sinks(
                adapter,
                Arc::clone(&ledger),
                shard_config,
                command_capacity,
                accepted_tx.clone(),
                udp_tx.clone(),
            )?;
            runtimes.push(runtime);
            commands.push(command);
        }
        drop(accepted_tx);
        drop(udp_tx);
        Ok((
            Self {
                runtimes,
                completion: completion_tx,
            },
            accepted_rx,
            udp_rx,
            NativeUdpReplyHandle {
                commands: commands.clone(),
            },
            NativeRuntimeControl {
                commands,
                router,
                ledger,
                completion: completion_rx,
            },
        ))
    }

    pub(super) async fn run(self) -> Result<(), RunnerError> {
        let Self {
            runtimes,
            completion,
        } = self;
        let futures = runtimes
            .into_iter()
            .map(|runtime| Box::pin(runtime.run()))
            .collect::<Vec<_>>();
        let result = futures::future::try_join_all(futures).await.map(|_| ());
        let _ = completion.send(true);
        result
    }
}

fn retryable(error: &RunnerError) -> bool {
    matches!(
        error,
        RunnerError::TxQueueFull
            | RunnerError::Budget(_)
            | RunnerError::Tcp(TcpTableError::Budget(_))
            | RunnerError::Tcp(TcpTableError::State(
                TcpError::SendOutstanding | TcpError::SendWindowExceeded
            ))
    )
}

fn runner_io_error(error: RunnerError) -> io::Error {
    let kind = match error {
        RunnerError::Closed | RunnerError::Tcp(TcpTableError::StaleToken) => {
            io::ErrorKind::BrokenPipe
        }
        RunnerError::TxQueueFull
        | RunnerError::Budget(_)
        | RunnerError::Tcp(TcpTableError::Budget(_)) => io::ErrorKind::WouldBlock,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, RecordType},
    };
    use sail_netstack::{
        emit_tcp_segment, emit_udp_packet, parse_ip_packet, parse_tcp_segment, parse_udp_datagram,
        BudgetProfile, NetworkGeneration, ResourceKind, SendControl, SeqNumber, TcpFlags,
    };
    use std::net::Ipv4Addr;
    #[cfg(target_os = "linux")]
    use std::net::Ipv6Addr;
    #[cfg(target_os = "linux")]
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::timeout;

    #[cfg(target_os = "linux")]
    async fn fake_dns_lookup(
        socket: &tokio::net::UdpSocket,
        server: SocketAddr,
        id: u16,
        domain: &str,
    ) -> anyhow::Result<Ipv4Addr> {
        let mut request = Message::new();
        request
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(Query::query(Name::from_ascii(domain)?, RecordType::A));
        socket.send_to(&request.to_vec()?, server).await?;
        let mut buffer = [0_u8; 512];
        let (count, source) =
            timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await??;
        anyhow::ensure!(source == server, "fake DNS response source changed");
        let response = Message::from_vec(&buffer[..count])?;
        anyhow::ensure!(response.id() == id, "fake DNS response ID changed");
        response
            .answers()
            .iter()
            .find_map(|answer| match answer.data() {
                Some(RData::A(address)) => Some(**address),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("fake DNS response has no A record"))
    }

    struct MemoryPacketIo {
        inbound: tokio_mpsc::Receiver<Vec<u8>>,
        outbound: tokio_mpsc::Sender<Vec<u8>>,
        next_token: u64,
    }

    #[cfg(target_os = "linux")]
    struct DropFirstTcpPayload<I> {
        inner: I,
        armed: Arc<AtomicBool>,
        pending_send_error: Option<io::Error>,
    }

    #[cfg(target_os = "linux")]
    struct ReorderDuplicateTcpPayload<I> {
        inner: I,
        armed: Arc<AtomicBool>,
        completed: Arc<AtomicBool>,
        pending: Option<(PacketToken, Vec<u8>)>,
        release_at: Option<std::time::Instant>,
        pending_send_error: Option<io::Error>,
    }

    #[cfg(target_os = "linux")]
    impl<I: PacketIo> ReorderDuplicateTcpPayload<I> {
        fn new(inner: I, armed: Arc<AtomicBool>, completed: Arc<AtomicBool>) -> Self {
            Self {
                inner,
                armed,
                completed,
                pending: None,
                release_at: None,
                pending_send_error: None,
            }
        }

        fn is_tcp_payload(packet: &Packet) -> bool {
            parse_ip_packet(packet.payload(), true)
                .and_then(|ip| parse_tcp_segment(ip, true))
                .is_ok_and(|segment| !segment.payload.is_empty())
        }

        async fn send_one(&mut self, token: PacketToken, payload: &[u8]) -> io::Result<()> {
            let mut single = PacketBatch::with_limit(1);
            single
                .push(Packet::from_payload(token, 0, payload))
                .expect("single-packet batch has capacity");
            match self.inner.send(&single).await {
                Ok(1) => Ok(()),
                Ok(0) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test PacketIo reported more than one sent packet",
                )),
                Err(error) => Err(error),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl<I: PacketIo> PacketIo for ReorderDuplicateTcpPayload<I> {
        async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
            self.inner.recv(out).await
        }

        async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
            if let Some(error) = self.pending_send_error.take() {
                return Err(error);
            }
            let mut sent = 0;
            for packet in packets.iter() {
                let payload = Self::is_tcp_payload(packet);
                if payload && self.pending.is_none() && self.armed.swap(false, Ordering::SeqCst) {
                    // Holding the packet accepts it without an await.
                    self.pending = Some((packet.token(), packet.payload().to_vec()));
                    sent += 1;
                    continue;
                }

                if payload && self.pending.is_some() {
                    // PacketIo cancellation: the reordering delay must precede
                    // every acceptance in this call, so defer the trigger. The
                    // runtime drops a step on every timer tick, so the delay is
                    // a deadline rechecked on retry rather than an await.
                    if sent > 0 {
                        break;
                    }
                    let release_at = *self.release_at.get_or_insert_with(|| {
                        std::time::Instant::now() + Duration::from_millis(25)
                    });
                    if std::time::Instant::now() < release_at {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    self.release_at = None;
                    self.send_one(packet.token(), packet.payload()).await?;
                    sent = 1;
                    let (pending_token, pending_payload) =
                        self.pending.take().expect("checked above");
                    match self
                        .send_one(pending_token, &pending_payload)
                        .now_or_never()
                    {
                        Some(Ok(())) => {
                            let _ = self
                                .send_one(packet.token(), packet.payload())
                                .now_or_never();
                            self.completed.store(true, Ordering::SeqCst);
                        }
                        Some(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                            self.pending = Some((pending_token, pending_payload));
                        }
                        Some(Err(error)) => self.pending_send_error = Some(error),
                        None => self.pending = Some((pending_token, pending_payload)),
                    }
                    break;
                }

                let result = if sent == 0 {
                    self.send_one(packet.token(), packet.payload()).await
                } else {
                    match self
                        .send_one(packet.token(), packet.payload())
                        .now_or_never()
                    {
                        Some(result) => result,
                        None => break,
                    }
                };
                match result {
                    Ok(()) => sent += 1,
                    Err(error) if sent == 0 => return Err(error),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        self.pending_send_error = Some(error);
                        break;
                    }
                }
            }
            Ok(sent)
        }

        fn capabilities(&self) -> PacketCapabilities {
            self.inner.capabilities()
        }
    }

    #[cfg(target_os = "linux")]
    impl<I: PacketIo> DropFirstTcpPayload<I> {
        fn new(inner: I, armed: Arc<AtomicBool>) -> Self {
            Self {
                inner,
                armed,
                pending_send_error: None,
            }
        }

        fn should_drop(&self, packet: &Packet) -> bool {
            let Ok(ip) = parse_ip_packet(packet.payload(), true) else {
                return false;
            };
            let Ok(segment) = parse_tcp_segment(ip, true) else {
                return false;
            };
            !segment.payload.is_empty() && self.armed.swap(false, Ordering::SeqCst)
        }
    }

    #[cfg(target_os = "linux")]
    impl<I: PacketIo> PacketIo for DropFirstTcpPayload<I> {
        async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
            self.inner.recv(out).await
        }

        async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
            if let Some(error) = self.pending_send_error.take() {
                return Err(error);
            }
            let mut sent = 0;
            for packet in packets.iter() {
                if self.should_drop(packet) {
                    sent += 1;
                    continue;
                }
                let mut single = PacketBatch::with_limit(1);
                single
                    .push(Packet::from_payload(packet.token(), 0, packet.payload()))
                    .expect("single-packet batch has capacity");
                // PacketIo cancellation: await only before the first accept.
                let result = if sent == 0 {
                    self.inner.send(&single).await
                } else {
                    match self.inner.send(&single).now_or_never() {
                        Some(result) => result,
                        None => break,
                    }
                };
                match result {
                    Ok(1) => sent += 1,
                    Ok(0) => break,
                    Ok(_) if sent == 0 => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "test PacketIo reported more than one sent packet",
                        ));
                    }
                    Ok(_) => {
                        self.pending_send_error = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "test PacketIo reported more than one sent packet",
                        ));
                        break;
                    }
                    Err(error) if sent == 0 => return Err(error),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        self.pending_send_error = Some(error);
                        break;
                    }
                }
            }
            Ok(sent)
        }

        fn capabilities(&self) -> PacketCapabilities {
            self.inner.capabilities()
        }
    }

    impl PacketIo for MemoryPacketIo {
        async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
            let bytes =
                self.inbound.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "test input closed")
                })?;
            let token = PacketToken::new(self.next_token);
            self.next_token = self.next_token.wrapping_add(1);
            out.push(Packet::from_payload(token, 0, &bytes))
                .map_err(|_| io::Error::other("test receive batch full"))?;
            Ok(1)
        }

        async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
            for packet in packets.iter() {
                self.outbound
                    .send(packet.payload().to_vec())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test output closed"))?;
            }
            Ok(packets.len())
        }

        fn capabilities(&self) -> PacketCapabilities {
            PacketCapabilities {
                max_batch: 1,
                queue_count: 1,
                headroom: 0,
                vectored: false,
                rx_checksum: ChecksumCapabilities::default(),
                tx_checksum: ChecksumCapabilities::default(),
                gso: None,
            }
        }
    }

    fn tcp_packet(
        source: SocketAddr,
        destination: SocketAddr,
        sequence: u32,
        acknowledgment: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> Vec<u8> {
        emit_tcp_segment(
            source,
            destination,
            SendControl {
                sequence: SeqNumber::new(sequence),
                acknowledgment: SeqNumber::new(acknowledgment),
                flags,
                window: 32_000,
            },
            payload,
            64,
            1,
        )
        .unwrap()
    }

    fn tcp_packet_with_window(
        source: SocketAddr,
        destination: SocketAddr,
        sequence: u32,
        acknowledgment: u32,
        flags: TcpFlags,
        window: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        emit_tcp_segment(
            source,
            destination,
            SendControl {
                sequence: SeqNumber::new(sequence),
                acknowledgment: SeqNumber::new(acknowledgment),
                flags,
                window,
            },
            payload,
            64,
            1,
        )
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn gso_test_buffers(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                Vec::with_capacity(
                    2 * tun_rs::VIRTIO_NET_HDR_LEN + if index == 0 { 65_535 } else { 1_500 },
                )
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_offload_coalesces_a_complete_tcp_prefix_into_one_atomic_gso_frame() {
        let source = SocketAddr::from((Ipv4Addr::new(10, 20, 0, 1), 443));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 20, 0, 2), 50_000));
        let payloads = [vec![1; 512], vec![2; 512], vec![3; 128]];
        let mut batch = PacketBatch::with_limit(payloads.len());
        let mut sequence = 10_000_u32;
        for (index, payload) in payloads.iter().enumerate() {
            let wire = tcp_packet(source, destination, sequence, 77, TcpFlags::ACK, payload);
            batch
                .push(Packet::from_payload(
                    PacketToken::new(index as u64),
                    0,
                    &wire,
                ))
                .unwrap();
            sequence = sequence.wrapping_add(u32::try_from(payload.len()).unwrap());
        }
        let mut table = tun_rs::GROTable::default();
        let mut buffers = gso_test_buffers(payloads.len());
        let index = prepare_coalesced_tcp_batch(&mut table, &mut buffers, &batch).unwrap();
        let header = tun_rs::VirtioNetHdr::decode(&buffers[index]).unwrap();
        assert_eq!(header.gso_type & 0x7f, tun_rs::VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(usize::from(header.gso_size), payloads[0].len());

        let mut coalesced = buffers[index][tun_rs::VIRTIO_NET_HDR_LEN..].to_vec();
        let mut split = vec![vec![0_u8; 1_500]; payloads.len()];
        let mut sizes = vec![0; payloads.len()];
        let count =
            tun_rs::gso_split(&mut coalesced, header, &mut split, &mut sizes, 0, false).unwrap();
        assert_eq!(count, payloads.len());
        for (index, expected) in payloads.iter().enumerate() {
            let ip = parse_ip_packet(&split[index][..sizes[index]], true).unwrap();
            assert_eq!(parse_tcp_segment(ip, true).unwrap().payload, expected);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_offload_rejects_noncontiguous_tcp_batch_for_per_packet_fallback() {
        let source = SocketAddr::from((Ipv4Addr::new(10, 21, 0, 1), 443));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 21, 0, 2), 50_000));
        let wires = [
            tcp_packet(source, destination, 1_000, 77, TcpFlags::ACK, &[1; 64]),
            tcp_packet(source, destination, 2_000, 77, TcpFlags::ACK, &[2; 64]),
        ];
        let mut batch = PacketBatch::with_limit(wires.len());
        for (index, wire) in wires.iter().enumerate() {
            batch
                .push(Packet::from_payload(
                    PacketToken::new(index as u64),
                    0,
                    wire,
                ))
                .unwrap();
        }
        let mut table = tun_rs::GROTable::default();
        let mut buffers = gso_test_buffers(wires.len());
        assert!(prepare_coalesced_tcp_batch(&mut table, &mut buffers, &batch).is_none());
    }

    #[tokio::test]
    async fn runtime_reports_a_partial_write_for_a_small_peer_window() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = MemoryPacketIo {
            inbound: inbound_rx,
            outbound: outbound_tx,
            next_token: 0,
        };
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, ledger, RunnerConfig::default(), 4, 4, 4).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 0, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 0, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet_with_window(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                3,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(accepted.stream.write(b"abcdef").await.unwrap(), 3);
        let outgoing = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let outgoing = parse_tcp_segment(parse_ip_packet(&outgoing, true).unwrap(), true).unwrap();
        assert_eq!(outgoing.payload, b"abc");

        runtime_task.abort();
    }

    #[tokio::test]
    async fn runtime_retries_a_committed_write_after_transient_packet_budget_pressure() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = MemoryPacketIo {
            inbound: inbound_rx,
            outbound: outbound_tx,
            next_token: 0,
        };
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, Arc::clone(&ledger), RunnerConfig::default(), 4, 4, 4).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 4, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 4, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();

        let snapshot = ledger.snapshot();
        let packet_credit = ledger
            .try_acquire(
                ResourceKind::PacketBytes,
                ledger
                    .budget()
                    .packet_bytes
                    .saturating_sub(snapshot.used(ResourceKind::PacketBytes)),
            )
            .unwrap();
        let denied_before = ledger.snapshot().denied;

        assert_eq!(accepted.stream.write(b"retry").await.unwrap(), 5);
        timeout(Duration::from_secs(1), async {
            while ledger.snapshot().denied == denied_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("committed write never reached transient packet-budget pressure");

        drop(packet_credit);
        timeout(Duration::from_secs(1), accepted.stream.flush())
            .await
            .expect("write was not retried after packet credit returned")
            .unwrap();
        let outgoing = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let outgoing = parse_tcp_segment(parse_ip_packet(&outgoing, true).unwrap(), true).unwrap();
        assert_eq!(outgoing.payload, b"retry");

        runtime_task.abort();
    }

    #[tokio::test]
    async fn dropped_stream_reclaims_its_flow_when_the_command_channel_is_full() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = MemoryPacketIo {
            inbound: inbound_rx,
            outbound: outbound_tx,
            next_token: 0,
        };
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, Arc::clone(&ledger), RunnerConfig::default(), 1, 1, 1).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 3, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 3, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ledger.snapshot().used(ResourceKind::TcpFlows), 1);

        // Fill the ordinary command queue and drop without yielding. Cleanup
        // must use its dedicated path rather than disappearing behind
        // backpressure.
        accepted.stream.saturate_command_channel_for_test();
        drop(accepted);

        timeout(Duration::from_secs(1), async {
            while ledger.snapshot().used(ResourceKind::TcpFlows) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped stream did not release its TCP flow");

        runtime_task.abort();
    }

    #[tokio::test]
    async fn runtime_retransmits_an_application_write_after_wire_loss() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(4);
        let io = MemoryPacketIo {
            inbound: inbound_rx,
            outbound: outbound_tx,
            next_token: 0,
        };
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply) =
            NativeRuntime::new(io, ledger, RunnerConfig::default(), 4, 4, 4).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 1, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 1, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();

        accepted.stream.write_all(b"lost").await.unwrap();
        let first = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let first = parse_tcp_segment(parse_ip_packet(&first, true).unwrap(), true).unwrap();
        assert_eq!(first.payload, b"lost");

        let retransmit = timeout(Duration::from_secs(3), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let retransmit =
            parse_tcp_segment(parse_ip_packet(&retransmit, true).unwrap(), true).unwrap();
        assert_eq!(retransmit.meta.sequence, first.meta.sequence);
        assert_eq!(retransmit.payload, first.payload);

        runtime_task.abort();
    }

    #[tokio::test]
    async fn runtime_group_forwards_a_flow_and_keeps_application_commands_on_its_owner() {
        let (first_inbound_tx, first_inbound_rx) = tokio_mpsc::channel(8);
        let (first_outbound_tx, mut first_outbound_rx) = tokio_mpsc::channel(8);
        let (second_inbound_tx, second_inbound_rx) = tokio_mpsc::channel(8);
        let (second_outbound_tx, mut second_outbound_rx) = tokio_mpsc::channel(8);
        let queues = vec![
            MemoryPacketIo {
                inbound: first_inbound_rx,
                outbound: first_outbound_tx,
                next_token: 0,
            },
            MemoryPacketIo {
                inbound: second_inbound_rx,
                outbound: second_outbound_tx,
                next_token: 0,
            },
        ];
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply, mut control) =
            NativeRuntimeGroup::new(queues, ledger, RunnerConfig::default(), 8, 8, 8).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 8, 2, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 8, 2, 1), 443));

        first_inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), async {
            tokio::select! {
                packet = first_outbound_rx.recv() => packet,
                packet = second_outbound_rx.recv() => packet,
            }
        })
        .await
        .unwrap()
        .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        first_inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(usize::from(accepted.connection.token.shard().get()) < 2);

        accepted.stream.write_all(b"grouped").await.unwrap();
        let outgoing = timeout(Duration::from_secs(1), async {
            tokio::select! {
                packet = first_outbound_rx.recv() => packet,
                packet = second_outbound_rx.recv() => packet,
            }
        })
        .await
        .unwrap()
        .unwrap();
        let outgoing = parse_tcp_segment(parse_ip_packet(&outgoing, true).unwrap(), true).unwrap();
        assert_eq!(outgoing.payload, b"grouped");

        let before_reset = control.stats_snapshot().await.unwrap();
        assert_eq!(before_reset.shard_count, 2);
        assert_eq!(before_reset.stack.tcp_active_flows, 1);
        assert_eq!(before_reset.router.directory_entries, 1);

        control.update_mtu(1_400).await.unwrap();
        control
            .reset_network(NetworkGeneration::new(7))
            .await
            .unwrap();
        let after_reset = control.stats_snapshot().await.unwrap();
        assert_eq!(after_reset.stack.generation, NetworkGeneration::new(7));
        assert_eq!(after_reset.stack.tcp_active_flows, 0);
        assert_eq!(after_reset.stack.mtu_changes, 2);
        assert_eq!(after_reset.stack.network_resets, 2);
        assert_eq!(after_reset.router.directory_entries, 0);
        assert_eq!(after_reset.router.queued_packets, 0);

        control.shutdown(u64::MAX).await.unwrap();
        let draining = control.stats_snapshot().await.unwrap();
        assert_eq!(draining.stack.shutdowns, 2);

        control.abort().await.unwrap();
        control.wait_stopped().await.unwrap();
        runtime_task.await.unwrap().unwrap();
        drop(second_inbound_tx);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN"]
    async fn linux_kernel_accepts_one_atomic_tcp_gso_frame_for_a_complete_batch() {
        let device = tun_rs::DeviceBuilder::new()
            .name("sailns-gso")
            .ipv4("10.207.0.1", 24, None)
            .mtu(1_500)
            .enable(true)
            .offload(true)
            .build_async()
            .unwrap();
        let mut io = TunRsPacketIo::new(device, 1_500, 64, 1, true).unwrap();
        let source = SocketAddr::from((Ipv4Addr::new(10, 207, 0, 2), 50_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 207, 0, 1), 443));
        let payloads = [vec![1; 512], vec![2; 512], vec![3; 128]];
        let mut packets = PacketBatch::with_limit(payloads.len());
        let mut sequence = 1_000_u32;
        for (index, payload) in payloads.iter().enumerate() {
            let wire = tcp_packet(source, destination, sequence, 9_000, TcpFlags::ACK, payload);
            packets
                .push(Packet::from_payload(
                    PacketToken::new(index as u64),
                    0,
                    &wire,
                ))
                .unwrap();
            sequence = sequence.wrapping_add(u32::try_from(payload.len()).unwrap());
        }

        let sent = timeout(Duration::from_secs(2), io.send(&packets))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sent, packets.len());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN"]
    async fn linux_multiqueue_kernel_tcp_udp_round_trips() {
        let first = tun_rs::DeviceBuilder::new()
            .name("sailns-smoke")
            .ipv4("10.203.0.1", 24, None)
            .ipv6("2001:db8:203::1", 64)
            .mtu(1_500)
            .enable(true)
            .multi_queue(true)
            .offload(true)
            .build_async()
            .unwrap();
        let second = first.try_clone().unwrap();
        let drop_tcp_payload = Arc::new(AtomicBool::new(false));
        let reorder_tcp_payload = Arc::new(AtomicBool::new(false));
        let reorder_completed = Arc::new(AtomicBool::new(false));
        let queues = vec![
            ReorderDuplicateTcpPayload::new(
                DropFirstTcpPayload::new(
                    TunRsPacketIo::new(first, 1_500, 64, 2, true).unwrap(),
                    Arc::clone(&drop_tcp_payload),
                ),
                Arc::clone(&reorder_tcp_payload),
                Arc::clone(&reorder_completed),
            ),
            ReorderDuplicateTcpPayload::new(
                DropFirstTcpPayload::new(
                    TunRsPacketIo::new(second, 1_500, 64, 2, true).unwrap(),
                    Arc::clone(&drop_tcp_payload),
                ),
                Arc::clone(&reorder_tcp_payload),
                Arc::clone(&reorder_completed),
            ),
        ];
        let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
        let (runtime, mut accepted, mut datagrams, mut udp_reply, mut control) =
            NativeRuntimeGroup::new(queues, ledger, RunnerConfig::default(), 8, 8, 8).unwrap();
        assert_eq!(runtime.runtimes.len(), 2);
        let runtime_task = tokio::spawn(runtime.run());
        let socket = tokio::net::UdpSocket::bind("10.203.0.1:0").await.unwrap();
        let client = socket.local_addr().unwrap();
        let remote = SocketAddr::from((Ipv4Addr::new(10, 203, 0, 2), 53_535));
        socket.send_to(b"kernel-uplink", remote).await.unwrap();

        let datagram = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(datagram.source, client);
        assert_eq!(datagram.destination, remote);
        assert_eq!(datagram.payload.to_vec(), b"kernel-uplink");
        udp_reply
            .send(datagram.token, remote, b"kernel-downlink".to_vec())
            .await
            .unwrap();

        let mut received = [0_u8; 32];
        let (count, source) = timeout(Duration::from_secs(1), socket.recv_from(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, remote);
        assert_eq!(&received[..count], b"kernel-downlink");

        let fragmented_payload = (0..4_096)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        socket.send_to(&fragmented_payload, remote).await.unwrap();
        let fragmented_datagram = timeout(Duration::from_secs(2), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fragmented_datagram.source, client);
        assert_eq!(fragmented_datagram.destination, remote);
        assert_eq!(fragmented_datagram.payload.to_vec(), fragmented_payload);
        udp_reply
            .send(
                fragmented_datagram.token,
                remote,
                fragmented_payload.clone(),
            )
            .await
            .unwrap();
        let mut fragmented_reply = vec![0_u8; fragmented_payload.len() + 64];
        let (count, source) = timeout(
            Duration::from_secs(2),
            socket.recv_from(&mut fragmented_reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(source, remote);
        assert_eq!(&fragmented_reply[..count], fragmented_payload);

        let tcp_remote = SocketAddr::from((Ipv4Addr::new(10, 203, 0, 2), 44_443));
        let (kernel_stream, accepted_stream) = timeout(Duration::from_secs(1), async {
            tokio::join!(tokio::net::TcpStream::connect(tcp_remote), accepted.recv())
        })
        .await
        .unwrap();
        let mut kernel_stream = kernel_stream.unwrap();
        let mut accepted_stream = accepted_stream.unwrap().stream;
        kernel_stream.write_all(b"kernel-tcp-uplink").await.unwrap();
        let mut uplink = [0_u8; 17];
        accepted_stream.read_exact(&mut uplink).await.unwrap();
        assert_eq!(&uplink, b"kernel-tcp-uplink");
        drop_tcp_payload.store(true, Ordering::SeqCst);
        accepted_stream
            .write_all(b"kernel-tcp-downlink")
            .await
            .unwrap();
        let mut downlink = [0_u8; 19];
        timeout(
            Duration::from_secs(3),
            kernel_stream.read_exact(&mut downlink),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!drop_tcp_payload.load(Ordering::SeqCst));
        assert_eq!(&downlink, b"kernel-tcp-downlink");

        let reordered_payload = (0..4_096)
            .map(|index| u8::try_from(index % 239).unwrap())
            .collect::<Vec<_>>();
        reorder_tcp_payload.store(true, Ordering::SeqCst);
        accepted_stream.write_all(&reordered_payload).await.unwrap();
        let mut reordered_reply = vec![0_u8; reordered_payload.len()];
        timeout(
            Duration::from_secs(3),
            kernel_stream.read_exact(&mut reordered_reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reordered_reply, reordered_payload);
        assert!(reorder_completed.load(Ordering::SeqCst));

        accepted_stream.shutdown().await.unwrap();
        let mut eof = [0_u8; 1];
        assert_eq!(
            timeout(Duration::from_secs(2), kernel_stream.read(&mut eof))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        kernel_stream.shutdown().await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), accepted_stream.read(&mut eof))
                .await
                .unwrap()
                .unwrap(),
            0
        );

        let socket_v6 = tokio::net::UdpSocket::bind(SocketAddr::from((
            "2001:db8:203::1".parse::<Ipv6Addr>().unwrap(),
            0,
        )))
        .await
        .unwrap();
        let client_v6 = socket_v6.local_addr().unwrap();
        let remote_v6 = SocketAddr::from(("2001:db8:203::2".parse::<Ipv6Addr>().unwrap(), 53_536));
        socket_v6
            .send_to(b"kernel-ipv6-uplink", remote_v6)
            .await
            .unwrap();
        let datagram_v6 = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(datagram_v6.source, client_v6);
        assert_eq!(datagram_v6.destination, remote_v6);
        assert_eq!(datagram_v6.payload.to_vec(), b"kernel-ipv6-uplink");
        udp_reply
            .send(
                datagram_v6.token,
                remote_v6,
                b"kernel-ipv6-downlink".to_vec(),
            )
            .await
            .unwrap();
        let mut received_v6 = [0_u8; 32];
        let (count, source) = timeout(
            Duration::from_secs(1),
            socket_v6.recv_from(&mut received_v6),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(source, remote_v6);
        assert_eq!(&received_v6[..count], b"kernel-ipv6-downlink");
        socket_v6
            .send_to(&fragmented_payload, remote_v6)
            .await
            .unwrap();
        let fragmented_datagram_v6 = timeout(Duration::from_secs(2), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fragmented_datagram_v6.source, client_v6);
        assert_eq!(fragmented_datagram_v6.destination, remote_v6);
        assert_eq!(fragmented_datagram_v6.payload.to_vec(), fragmented_payload);
        udp_reply
            .send(
                fragmented_datagram_v6.token,
                remote_v6,
                fragmented_payload.clone(),
            )
            .await
            .unwrap();
        let mut fragmented_reply_v6 = vec![0_u8; fragmented_payload.len() + 64];
        let (count, source) = timeout(
            Duration::from_secs(2),
            socket_v6.recv_from(&mut fragmented_reply_v6),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(source, remote_v6);
        assert_eq!(&fragmented_reply_v6[..count], fragmented_payload);

        let tcp_remote_v6 =
            SocketAddr::from(("2001:db8:203::2".parse::<Ipv6Addr>().unwrap(), 44_444));
        let (kernel_stream_v6, accepted_stream_v6) = timeout(Duration::from_secs(1), async {
            tokio::join!(
                tokio::net::TcpStream::connect(tcp_remote_v6),
                accepted.recv()
            )
        })
        .await
        .unwrap();
        let mut kernel_stream_v6 = kernel_stream_v6.unwrap();
        let mut accepted_stream_v6 = accepted_stream_v6.unwrap().stream;
        kernel_stream_v6
            .write_all(b"kernel-ipv6-tcp-uplink")
            .await
            .unwrap();
        let mut uplink_v6 = [0_u8; 22];
        accepted_stream_v6.read_exact(&mut uplink_v6).await.unwrap();
        assert_eq!(&uplink_v6, b"kernel-ipv6-tcp-uplink");
        accepted_stream_v6
            .write_all(b"kernel-ipv6-tcp-downlink")
            .await
            .unwrap();
        let mut downlink_v6 = [0_u8; 24];
        kernel_stream_v6.read_exact(&mut downlink_v6).await.unwrap();
        assert_eq!(&downlink_v6, b"kernel-ipv6-tcp-downlink");
        accepted_stream_v6.shutdown().await.unwrap();

        let reset_remote = SocketAddr::from((Ipv4Addr::new(10, 203, 0, 2), 44_445));
        let (kernel_reset, accepted_reset) = timeout(Duration::from_secs(1), async {
            tokio::join!(
                tokio::net::TcpStream::connect(reset_remote),
                accepted.recv()
            )
        })
        .await
        .unwrap();
        let kernel_reset = kernel_reset.unwrap().into_std().unwrap();
        socket2::SockRef::from(&kernel_reset)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(kernel_reset);
        let mut accepted_reset = accepted_reset.unwrap().stream;
        let reset_result = timeout(Duration::from_secs(2), accepted_reset.read(&mut eof))
            .await
            .unwrap();
        match reset_result {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("abrupt kernel reset did not terminate the native stream: {other:?}"),
        }

        control.abort().await.unwrap();
        control.wait_stopped().await.unwrap();
        runtime_task.await.unwrap().unwrap();
    }

    /// Long-running single-process soak over the real kernel path. Each
    /// iteration sends a fragmenting UDP round trip and a bidirectional TCP
    /// bulk transfer with an orderly close. `SAIL_NETSTACK_SOAK_SECONDS` sets
    /// the traffic duration (default 30); progress is printed every minute.
    /// After traffic stops, every flow, payload, and packet lease must return
    /// to zero; router metadata is a bounded cache and is only reported.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN; long-running"]
    async fn linux_native_kernel_soak() {
        fn resident_kib() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| {
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix("VmRSS:"))
                        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
                })
                .unwrap_or(0)
        }

        let seconds = std::env::var("SAIL_NETSTACK_SOAK_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30);
        // `SAIL_NETSTACK_SOAK_NET` (default 206) picks the 10.N.0.0/24 the
        // device takes, so that soaks can run side by side: two devices on
        // one subnet would receive each other's traffic.
        let net = std::env::var("SAIL_NETSTACK_SOAK_NET")
            .ok()
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or(206);
        let local = Ipv4Addr::new(10, net, 0, 1);
        let first = tun_rs::DeviceBuilder::new()
            .name(format!("sailns-soak{net}"))
            .ipv4(local, 24, None)
            .mtu(1_500)
            .enable(true)
            .multi_queue(true)
            .offload(true)
            .build_async()
            .unwrap();
        let second = first.try_clone().unwrap();
        let queues = vec![
            TunRsPacketIo::new(first, 1_500, 64, 2, true).unwrap(),
            TunRsPacketIo::new(second, 1_500, 64, 2, true).unwrap(),
        ];
        let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
        let config = RunnerConfig {
            udp_idle_timeout_ms: 2_000,
            tcp: sail_netstack::TcpTableConfig {
                time_wait_ms: 2_000,
                ..sail_netstack::TcpTableConfig::default()
            },
            ..RunnerConfig::default()
        };
        let (runtime, mut accepted, mut datagrams, mut udp_reply, mut control) =
            NativeRuntimeGroup::new(queues, Arc::clone(&ledger), config, 8, 64, 64).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let udp_remote = SocketAddr::from((Ipv4Addr::new(10, net, 0, 2), 53_000));
        let tcp_remote = SocketAddr::from((Ipv4Addr::new(10, net, 0, 2), 45_000));
        let started = std::time::Instant::now();
        let deadline = started + Duration::from_secs(seconds);
        let mut next_report = started;
        let mut iterations = 0_u64;
        let mut transferred = 0_u64;
        while std::time::Instant::now() < deadline {
            let seed = iterations;
            let socket = tokio::net::UdpSocket::bind(SocketAddr::from((local, 0)))
                .await
                .unwrap();
            let udp_size = 1 + usize::try_from(seed % 4_000).unwrap();
            let udp_payload = (0..udp_size)
                .map(|index| (index as u64 ^ seed) as u8)
                .collect::<Vec<_>>();
            socket.send_to(&udp_payload, udp_remote).await.unwrap();
            let datagram = timeout(Duration::from_secs(5), datagrams.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(datagram.payload.to_vec(), udp_payload);
            udp_reply
                .send(datagram.token, udp_remote, udp_payload.clone())
                .await
                .unwrap();
            let mut reply = vec![0_u8; udp_size + 64];
            let (count, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply[..count], udp_payload);

            let tcp_size = 1 + usize::try_from(seed.wrapping_mul(7_919) % 262_144).unwrap();
            let tcp_payload = (0..tcp_size)
                .map(|index| (index as u64 ^ seed.rotate_left(8)) as u8)
                .collect::<Vec<_>>();
            timeout(Duration::from_secs(30), async {
                let (kernel, accepted_stream) =
                    tokio::join!(tokio::net::TcpStream::connect(tcp_remote), accepted.recv());
                let mut kernel = kernel.unwrap();
                let mut accepted_stream = accepted_stream.unwrap().stream;
                let mut uplink = vec![0_u8; tcp_size];
                let (written, read) = tokio::join!(
                    kernel.write_all(&tcp_payload),
                    accepted_stream.read_exact(&mut uplink)
                );
                written.unwrap();
                read.unwrap();
                assert_eq!(uplink, tcp_payload);
                let mut downlink = vec![0_u8; tcp_size];
                let (written, read) = tokio::join!(
                    accepted_stream.write_all(&tcp_payload),
                    kernel.read_exact(&mut downlink)
                );
                written.unwrap();
                read.unwrap();
                assert_eq!(downlink, tcp_payload);
                let mut eof = [0_u8; 1];
                accepted_stream.shutdown().await.unwrap();
                assert_eq!(kernel.read(&mut eof).await.unwrap(), 0);
                kernel.shutdown().await.unwrap();
                assert_eq!(accepted_stream.read(&mut eof).await.unwrap(), 0);
            })
            .await
            .unwrap_or_else(|_| panic!("TCP soak iteration {iterations} timed out"));

            iterations += 1;
            transferred += 2 * (udp_size as u64 + tcp_size as u64);
            if std::time::Instant::now() >= next_report {
                let stats = control.stats_snapshot().await.unwrap().stack;
                eprintln!(
                    "soak elapsed_s={} iterations={iterations} bytes={transferred} rss_kib={} \
                     ledger_bytes={} tcp_flows={} time_wait={} udp_flows={} drops={} \
                     wire_drops={} resource_drops={} policy_drops={} \
                     udp_invalid_address_drops={} retransmission_timeouts={}",
                    started.elapsed().as_secs(),
                    resident_kib(),
                    stats.resources.total_bytes,
                    stats.tcp_active_flows,
                    stats.tcp_time_wait,
                    stats.udp_active_flows,
                    stats.dropped_packets,
                    stats.dropped_wire_packets,
                    stats.dropped_resource_packets,
                    stats.dropped_policy_packets,
                    stats.udp_invalid_address_drops,
                    stats.tcp_retransmission_timeouts,
                );
                next_report += Duration::from_secs(60);
            }
        }

        // Outlast TIME-WAIT and UDP idle expiry before checking reclamation.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let stats = control.stats_snapshot().await.unwrap().stack;
        let resources = ledger.snapshot();
        eprintln!(
            "soak done elapsed_s={} iterations={iterations} bytes={transferred} rss_kib={} \
             ledger_bytes={} metadata_bytes={} drops={}",
            started.elapsed().as_secs(),
            resident_kib(),
            resources.total_bytes,
            resources.used(ResourceKind::MetadataBytes),
            stats.dropped_packets,
        );
        assert!(iterations > 0);
        assert_eq!(stats.tcp_active_flows, 0);
        assert_eq!(stats.tcp_time_wait, 0);
        assert_eq!(stats.udp_active_flows, 0);
        for kind in [
            ResourceKind::TcpPayloadBytes,
            ResourceKind::PacketBytes,
            ResourceKind::ControlPacketBytes,
            ResourceKind::FragmentBytes,
            ResourceKind::TcpFlows,
            ResourceKind::SynReceived,
            ResourceKind::AcceptQueue,
            ResourceKind::UdpFlows,
            ResourceKind::Fragments,
            ResourceKind::TimeWait,
        ] {
            assert_eq!(resources.used(kind), 0, "{kind:?} leaked after soak");
        }

        control.abort().await.unwrap();
        control.wait_stopped().await.unwrap();
        runtime_task.await.unwrap().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires permission to configure a macOS utun interface and route"]
    async fn macos_kernel_tcp_udp_round_trips() -> anyhow::Result<()> {
        let mut configuration = tun::Configuration::default();
        configuration
            .address("10.204.0.1")
            .destination("10.204.0.2")
            .netmask("255.255.255.252")
            .mtu(1_500)
            .up();
        configuration.platform_config(|platform| {
            platform.enable_routing(true);
        });
        let device = tun::create_as_async(&configuration)?;
        let queue = TunPacketIo::new(device, 1_500, 32)?;
        let ledger = ResourceLedger::new(BudgetProfile::Desktop.budget())?;
        let (runtime, mut accepted, mut datagrams, mut udp_reply, mut control) =
            NativeRuntimeGroup::new(vec![queue], ledger, RunnerConfig::default(), 8, 8, 8)?;
        let runtime_task = tokio::spawn(runtime.run());

        let socket = tokio::net::UdpSocket::bind("10.204.0.1:0").await?;
        let client = socket.local_addr()?;
        let remote = SocketAddr::from((Ipv4Addr::new(10, 204, 0, 2), 53_535));
        socket.send_to(b"macos-kernel-uplink", remote).await?;
        let datagram = timeout(Duration::from_secs(2), datagrams.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("macOS native UDP channel closed"))?;
        anyhow::ensure!(datagram.source == client);
        anyhow::ensure!(datagram.destination == remote);
        anyhow::ensure!(datagram.payload.to_vec() == b"macos-kernel-uplink");
        udp_reply
            .send(datagram.token, remote, b"macos-kernel-downlink".to_vec())
            .await?;
        let mut udp_reply_buffer = [0_u8; 32];
        let (count, source) = timeout(
            Duration::from_secs(2),
            socket.recv_from(&mut udp_reply_buffer),
        )
        .await??;
        anyhow::ensure!(source == remote);
        anyhow::ensure!(&udp_reply_buffer[..count] == b"macos-kernel-downlink");

        let tcp_remote = SocketAddr::from((Ipv4Addr::new(10, 204, 0, 2), 44_443));
        let (kernel_stream, accepted_stream) = timeout(Duration::from_secs(2), async {
            tokio::join!(tokio::net::TcpStream::connect(tcp_remote), accepted.recv())
        })
        .await?;
        let mut kernel_stream = kernel_stream?;
        let mut accepted_stream = accepted_stream
            .ok_or_else(|| anyhow::anyhow!("macOS native TCP accept channel closed"))?
            .stream;
        kernel_stream.write_all(b"macos-kernel-tcp-uplink").await?;
        let mut tcp_uplink = [0_u8; 23];
        timeout(
            Duration::from_secs(2),
            accepted_stream.read_exact(&mut tcp_uplink),
        )
        .await??;
        anyhow::ensure!(&tcp_uplink == b"macos-kernel-tcp-uplink");
        accepted_stream
            .write_all(b"macos-kernel-tcp-downlink")
            .await?;
        let mut tcp_downlink = [0_u8; 25];
        timeout(
            Duration::from_secs(2),
            kernel_stream.read_exact(&mut tcp_downlink),
        )
        .await??;
        anyhow::ensure!(&tcp_downlink == b"macos-kernel-tcp-downlink");

        control.abort().await?;
        control.wait_stopped().await?;
        runtime_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn runtime_bridges_wire_tcp_and_udp_to_sail_channels() {
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(8);
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(8);
        let io = MemoryPacketIo {
            inbound: inbound_rx,
            outbound: outbound_tx,
            next_token: 0,
        };
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let config = RunnerConfig {
            generation: NetworkGeneration::new(7),
            ..RunnerConfig::default()
        };
        let (runtime, mut accepted, mut datagrams, mut udp_reply) =
            NativeRuntime::new(io, ledger, config, 8, 8, 8).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let source = SocketAddr::from((Ipv4Addr::new(10, 9, 0, 2), 40_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 9, 0, 1), 443));

        inbound_tx
            .send(tcp_packet(source, destination, 100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let syn_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_ack = parse_tcp_segment(parse_ip_packet(&syn_ack, true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next,
                TcpFlags::ACK,
                &[],
            ))
            .await
            .unwrap();
        let mut accepted = timeout(Duration::from_secs(1), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.connection.source, source);
        assert_eq!(accepted.connection.destination, destination);

        accepted.stream.write_all(b"ping").await.unwrap();
        let outgoing = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let outgoing = parse_tcp_segment(parse_ip_packet(&outgoing, true).unwrap(), true).unwrap();
        assert_eq!(outgoing.payload, b"ping");

        inbound_tx
            .send(tcp_packet(
                source,
                destination,
                101,
                server_next.wrapping_add(4),
                TcpFlags::ACK,
                b"pong",
            ))
            .await
            .unwrap();
        let mut read = [0_u8; 4];
        timeout(
            Duration::from_secs(1),
            accepted.stream.read_exact(&mut read),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&read, b"pong");
        let read_ack = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            parse_tcp_segment(parse_ip_packet(&read_ack, true).unwrap(), true)
                .unwrap()
                .payload
                .is_empty()
        );

        let udp_source = SocketAddr::from((Ipv4Addr::new(10, 9, 0, 2), 50_000));
        let udp_destination = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
        inbound_tx
            .send(emit_udp_packet(udp_source, udp_destination, b"query", 64, 2).unwrap())
            .await
            .unwrap();
        let datagram = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(datagram.source, udp_source);
        assert_eq!(datagram.destination, udp_destination);
        assert_eq!(datagram.payload.to_vec(), b"query");
        udp_reply
            .send(datagram.token, udp_destination, b"answer".to_vec())
            .await
            .unwrap();
        let reply = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let reply = parse_udp_datagram(parse_ip_packet(&reply, true).unwrap(), true).unwrap();
        assert_eq!(reply.source, udp_destination);
        assert_eq!(reply.destination, udp_source);
        assert_eq!(reply.payload, b"answer");

        let second_destination = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));
        let third_destination = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53));
        inbound_tx
            .send(emit_udp_packet(udp_source, second_destination, b"second", 64, 3).unwrap())
            .await
            .unwrap();
        inbound_tx
            .send(emit_udp_packet(udp_source, third_destination, b"third", 64, 4).unwrap())
            .await
            .unwrap();
        let second = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        let third = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.destination, second_destination);
        assert_eq!(third.destination, third_destination);
        udp_reply
            .send(third.token, third_destination, b"third-reply".to_vec())
            .await
            .unwrap();
        udp_reply
            .send(second.token, second_destination, b"second-reply".to_vec())
            .await
            .unwrap();
        for (expected_source, expected_payload) in [
            (third_destination, b"third-reply".as_slice()),
            (second_destination, b"second-reply".as_slice()),
        ] {
            let reply = timeout(Duration::from_secs(1), outbound_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let reply = parse_udp_datagram(parse_ip_packet(&reply, true).unwrap(), true).unwrap();
            assert_eq!(reply.source, expected_source);
            assert_eq!(reply.destination, udp_source);
            assert_eq!(reply.payload, expected_payload);
        }

        runtime_task.abort();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN"]
    async fn linux_default_native_process_dispatcher_nat_fakedns_round_trips() -> anyhow::Result<()>
    {
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let tcp_port = tcp_listener.local_addr()?.port();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await?;
            let mut payload = [0_u8; 64];
            let count = stream.read(&mut payload).await?;
            stream.write_all(&payload[..count]).await?;
            Ok::<_, io::Error>(())
        });
        let first_udp_echo_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let first_udp_port = first_udp_echo_socket.local_addr()?.port();
        let second_udp_echo_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let second_udp_port = second_udp_echo_socket.local_addr()?.port();
        let (release_first_udp, await_second_udp) = tokio::sync::oneshot::channel();
        let first_udp_echo = tokio::spawn(async move {
            let mut payload = [0_u8; 64];
            let (count, peer) = first_udp_echo_socket.recv_from(&mut payload).await?;
            await_second_udp.await.map_err(io::Error::other)?;
            first_udp_echo_socket
                .send_to(&payload[..count], peer)
                .await?;
            Ok::<_, io::Error>(())
        });
        let second_udp_echo = tokio::spawn(async move {
            let mut payload = [0_u8; 64];
            let (count, peer) = second_udp_echo_socket.recv_from(&mut payload).await?;
            second_udp_echo_socket
                .send_to(&payload[..count], peer)
                .await?;
            let _ = release_first_udp.send(());
            Ok::<_, io::Error>(())
        });

        let runtime_id = 60_001;
        anyhow::ensure!(!crate::is_running(runtime_id), "test runtime ID is in use");
        let config = r#"{
                "inbounds": [{
                    "type": "tun",
                    "tag": "native-process-test",
                    "name": "sailns-e2e",
                    "address": "198.19.255.254",
                    "gateway": "198.19.255.253",
                    "netmask": "255.254.0.0",
                    "mtu": 1500,
                    "fake_dns_include": ["*"]
                }],
                "outbounds": [{ "type": "direct", "tag": "direct" }],
                "dns": {
                    "servers": ["1.1.1.1"],
                    "hosts": { "netstack.test": ["127.0.0.1"] }
                }
            }"#
        .to_string();
        let start_task = tokio::task::spawn_blocking(move || {
            crate::start(
                runtime_id,
                crate::StartOptions {
                    config: crate::Config::Str(config),
                    #[cfg(feature = "auto-reload")]
                    auto_reload: false,
                    runtime_opt: crate::RuntimeOption::MultiThread(4, 2 * 1024 * 1024),
                    runtime: Default::default(),
                    host: Default::default(),
                },
            )
        });

        let result = async {
            timeout(Duration::from_secs(5), async {
                while !crate::is_running(runtime_id) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .map_err(|_| anyhow::anyhow!("native sail process did not start"))?;

            let dns_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            let dns_server = SocketAddr::from((Ipv4Addr::new(198, 19, 255, 252), 53));
            let _reserved_network_address =
                fake_dns_lookup(&dns_socket, dns_server, 0x7001, "prime.invalid.").await?;
            let fake_ip =
                fake_dns_lookup(&dns_socket, dns_server, 0x7002, "netstack.test.").await?;
            anyhow::ensure!(
                fake_ip == Ipv4Addr::new(198, 18, 0, 1),
                "unexpected fake address {fake_ip}"
            );

            let mut tcp = timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(SocketAddr::from((fake_ip, tcp_port))),
            )
            .await??;
            tcp.write_all(b"dispatcher-tcp").await?;
            let mut tcp_reply = [0_u8; 14];
            timeout(Duration::from_secs(3), tcp.read_exact(&mut tcp_reply)).await??;
            anyhow::ensure!(&tcp_reply == b"dispatcher-tcp", "TCP echo changed payload");

            let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            let first_udp_target = SocketAddr::from((fake_ip, first_udp_port));
            let second_udp_target = SocketAddr::from((fake_ip, second_udp_port));
            udp.send_to(b"first-nat-udp", first_udp_target).await?;
            udp.send_to(b"second-nat-udp", second_udp_target).await?;
            let mut udp_reply = [0_u8; 32];
            for (expected_source, expected_payload) in [
                (second_udp_target, b"second-nat-udp".as_slice()),
                (first_udp_target, b"first-nat-udp".as_slice()),
            ] {
                let (count, source) =
                    timeout(Duration::from_secs(3), udp.recv_from(&mut udp_reply)).await??;
                anyhow::ensure!(
                    source == expected_source,
                    "UDP fake source was not restored: expected {expected_source}, got {source}"
                );
                anyhow::ensure!(
                    &udp_reply[..count] == expected_payload,
                    "UDP echo changed or reordered the mapped payload"
                );
            }

            tokio::task::spawn_blocking(move || crate::network_changed(runtime_id, Some(1_400)))
                .await??;
            let remapped =
                fake_dns_lookup(&dns_socket, dns_server, 0x7003, "netstack.test.").await?;
            anyhow::ensure!(
                remapped == fake_ip,
                "network reset changed the stable FakeDNS mapping"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;

        // Release the registry lock before awaiting the shutdown.
        let manager = crate::runtime_managers().get(&runtime_id).cloned();
        if let Some(manager) = manager {
            manager.shutdown().await;
        }
        let process_result = timeout(Duration::from_secs(5), start_task)
            .await
            .map_err(|_| anyhow::anyhow!("native sail process did not stop"))??;
        tcp_echo.abort();
        first_udp_echo.abort();
        second_udp_echo.abort();
        process_result?;
        result
    }
}
