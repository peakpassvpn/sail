use std::collections::VecDeque;

use sail_netstack::{
    parse_ip_packet, parse_tcp_segment, BudgetProfile, NetworkGeneration, ResourceLedger,
    TcpConnection, TcpEvent, TcpTable, TcpTableConfig, TimerEvent,
};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

#[derive(Debug, Default)]
struct IpWire {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
}

impl IpWire {
    fn inject(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    fn take(&mut self) -> Vec<u8> {
        self.outbound
            .pop_front()
            .expect("smoltcp should have emitted an IP packet")
    }
}

struct WireRx(Vec<u8>);

impl smoltcp::phy::RxToken for WireRx {
    fn consume<R, F>(self, operation: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        operation(&self.0)
    }
}

struct WireTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::TxToken for WireTx<'_> {
    fn consume<R, F>(self, length: usize, operation: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; length];
        let result = operation(&mut packet);
        self.0.push_back(packet);
        result
    }
}

impl Device for IpWire {
    type RxToken<'a> = WireRx;
    type TxToken<'a> = WireTx<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inbound
            .pop_front()
            .map(|packet| (WireRx(packet), WireTx(&mut self.outbound)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(WireTx(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1_500;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}

struct InteropHarness {
    wire: IpWire,
    iface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    table: TcpTable,
    now_ms: u64,
}

impl InteropHarness {
    fn new() -> Self {
        let mut wire = IpWire::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x1eed_5eed;
        let mut iface = Interface::new(config, &mut wire, Instant::ZERO);
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                .unwrap();
        });
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4_096]),
            tcp::SocketBuffer::new(vec![0; 4_096]),
        );
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(iface.context(), (IpAddress::v4(10, 0, 0, 1), 8_080), 49_500)
            .unwrap();
        let ledger = ResourceLedger::new(BudgetProfile::Desktop.budget()).unwrap();
        let table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
        Self {
            wire,
            iface,
            sockets,
            handle,
            table,
            now_ms: 0,
        }
    }

    fn poll(&mut self) {
        self.iface.poll(
            Instant::from_millis(i64::try_from(self.now_ms).unwrap()),
            &mut self.wire,
            &mut self.sockets,
        );
    }

    fn handshake(&mut self) -> TcpConnection {
        self.poll();
        let syn_ack = self
            .table
            .ingest_with_policy_at(&self.wire.take(), true, self.now_ms)
            .unwrap();
        assert_eq!(syn_ack.outgoing.len(), 1);
        self.wire
            .inject(syn_ack.outgoing.into_iter().next().unwrap());
        self.now_ms += 1;
        self.poll();
        let established = self
            .table
            .ingest_with_policy_at(&self.wire.take(), true, self.now_ms)
            .unwrap();
        let connection = established
            .events
            .iter()
            .find_map(|event| match event {
                TcpEvent::Accepted(connection) => Some(*connection),
                _ => None,
            })
            .expect("sail-netstack should accept the smoltcp handshake");
        self.table.accept(connection.token).unwrap();
        assert!(self.sockets.get::<tcp::Socket>(self.handle).is_active());
        connection
    }

    fn send_from_client(&mut self, connection: TcpConnection, bytes: &[u8]) {
        assert_eq!(
            self.sockets
                .get_mut::<tcp::Socket>(self.handle)
                .send_slice(bytes)
                .unwrap(),
            bytes.len()
        );
        self.now_ms += 1;
        self.poll();
        let received = self
            .table
            .ingest_with_policy_at(&self.wire.take(), true, self.now_ms)
            .unwrap();
        assert!(received.events.iter().any(|event| matches!(
            event,
            TcpEvent::Readable { token, bytes: count }
                if *token == connection.token && *count == bytes.len()
        )));
        let read = self.table.read(connection.token, bytes.len()).unwrap();
        assert_eq!(read.bytes, bytes);
        for packet in received.outgoing.into_iter().chain(read.outgoing) {
            self.wire.inject(packet);
        }
        self.now_ms += 1;
        self.poll();
    }

    fn send_from_server_after_one_drop(&mut self, connection: TcpConnection, bytes: &[u8]) {
        let first_send = self.table.write(connection.token, bytes).unwrap();
        assert_eq!(first_send.outgoing.len(), 1);
        let timeout = first_send
            .timers
            .iter()
            .find(|timer| timer.event == TimerEvent::Retransmission)
            .map(|timer| timer.after_ms)
            .expect("the unacknowledged server payload should arm RTO");
        let dropped = first_send.outgoing.into_iter().next().unwrap();
        self.now_ms += timeout;
        let retry = self
            .table
            .on_timer_at(connection.token, TimerEvent::Retransmission, self.now_ms)
            .unwrap();
        assert_same_tcp_payload(&dropped, &retry.outgoing[0]);
        self.wire.inject(retry.outgoing.into_iter().next().unwrap());
        self.poll();
        let mut received = vec![0; bytes.len()];
        assert_eq!(
            self.sockets
                .get_mut::<tcp::Socket>(self.handle)
                .recv_slice(&mut received)
                .unwrap(),
            bytes.len()
        );
        assert_eq!(received, bytes);
        self.now_ms += 11;
        self.poll();
        let acked = self
            .table
            .ingest_with_policy_at(&self.wire.take(), true, self.now_ms)
            .unwrap();
        assert!(acked
            .cancelled_timers
            .iter()
            .any(|timer| timer.event == TimerEvent::Retransmission));
    }

    fn recover_reordered_server_segments(&mut self, connection: TcpConnection) {
        let mut packets = Vec::new();
        for byte in b"abcd" {
            let sent = self.table.write(connection.token, &[*byte]).unwrap();
            assert_eq!(sent.outgoing.len(), 1);
            packets.push(sent.outgoing.into_iter().next().unwrap());
        }
        let missing = packets.remove(0);
        let mut recovery = Vec::new();
        let mut saw_sack = false;
        for packet in packets {
            self.wire.inject(packet);
            self.now_ms += 1;
            self.poll();
            let ack_wire = self.wire.take();
            let ack = parse_tcp_segment(parse_ip_packet(&ack_wire, true).unwrap(), true).unwrap();
            saw_sack |= ack.options.sack_blocks.iter().any(Option::is_some);
            let duplicate_ack = self
                .table
                .ingest_with_policy_at(&ack_wire, true, self.now_ms)
                .unwrap();
            recovery.extend(duplicate_ack.outgoing);
        }
        assert!(
            saw_sack,
            "smoltcp should describe the reordered receive hole"
        );
        let retransmission = recovery
            .iter()
            .find(|packet| same_tcp_payload(packet, &missing))
            .expect("three smoltcp duplicate ACKs should trigger fast retransmit")
            .clone();
        self.wire.inject(retransmission);
        self.now_ms += 1;
        self.poll();
        let mut received = [0; 4];
        assert_eq!(
            self.sockets
                .get_mut::<tcp::Socket>(self.handle)
                .recv_slice(&mut received)
                .unwrap(),
            received.len()
        );
        assert_eq!(&received, b"abcd");
        self.now_ms += 11;
        self.poll();
        let final_ack = self
            .table
            .ingest_with_policy_at(&self.wire.take(), true, self.now_ms)
            .unwrap();
        assert!(final_ack.outgoing.is_empty());
    }

    fn graceful_close(&mut self, connection: TcpConnection) {
        self.sockets.get_mut::<tcp::Socket>(self.handle).close();
        self.now_ms += 1;
        self.poll();
        let peer_close = self
            .table
            .ingest_with_policy_at(&self.wire.take(), true, self.now_ms)
            .unwrap();
        assert!(peer_close.events.iter().any(
            |event| matches!(event, TcpEvent::PeerHalfClosed(token) if *token == connection.token)
        ));
        for packet in peer_close.outgoing {
            self.wire.inject(packet);
        }
        let local_close = self.table.close(connection.token).unwrap();
        assert_eq!(local_close.outgoing.len(), 1);
        self.wire
            .inject(local_close.outgoing.into_iter().next().unwrap());
        self.now_ms += 1;
        self.poll();
        let final_ack = self
            .table
            .ingest_with_policy_at(&self.wire.take(), true, self.now_ms)
            .unwrap();
        assert!(final_ack
            .events
            .iter()
            .any(|event| matches!(event, TcpEvent::Closed(token) if *token == connection.token)));
        assert!(!self.sockets.get::<tcp::Socket>(self.handle).may_recv());
    }
}

fn assert_same_tcp_payload(first: &[u8], second: &[u8]) {
    let first = parse_tcp_segment(parse_ip_packet(first, true).unwrap(), true).unwrap();
    let second = parse_tcp_segment(parse_ip_packet(second, true).unwrap(), true).unwrap();
    assert_eq!(second.meta.sequence, first.meta.sequence);
    assert_eq!(second.payload, first.payload);
}

fn same_tcp_payload(first: &[u8], second: &[u8]) -> bool {
    let first = parse_tcp_segment(parse_ip_packet(first, true).unwrap(), true).unwrap();
    let second = parse_tcp_segment(parse_ip_packet(second, true).unwrap(), true).unwrap();
    second.meta.sequence == first.meta.sequence && second.payload == first.payload
}

#[test]
fn independent_smoltcp_client_interoperates_through_loss_and_retransmission() {
    let mut harness = InteropHarness::new();
    let connection = harness.handshake();
    harness.send_from_client(connection, b"hello from smoltcp");
    harness.send_from_server_after_one_drop(connection, b"hello from sail-netstack");
    harness.recover_reordered_server_segments(connection);
    harness.graceful_close(connection);
}
