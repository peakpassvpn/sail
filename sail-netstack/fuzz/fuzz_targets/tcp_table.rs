#![no_main]

//! Drives `TcpTable` through complete wire packets from up to two peers.
//!
//! Every peer byte is a pure function of its sequence number, and every
//! application byte is a pure function of its stream offset. Overlap,
//! reordering, trimming, retransmission, and resegmentation therefore cannot
//! change the expected bytes: whatever the table delivers or emits must match
//! those functions exactly. Tearing down the network generation must return
//! every ledger lease.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use sail_netstack::{
    emit_tcp_segment_with_options, parse_ip_packet, parse_tcp_segment, BudgetProfile,
    NetworkGeneration, ResourceLedger, SendControl, SeqNumber, TcpError, TcpEvent, TcpFlags,
    TcpFlowToken, TcpTable, TcpTableConfig, TcpTableError, TimerEvent,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 8_192;
const HEADER_BYTES: usize = 8;
const OPERATION_BYTES: usize = 12;
const PEERS: usize = 2;
const MAX_TIMERS: usize = 256;

/// Set `TCP_TABLE_TRACE=1` when replaying an artifact to print each operation
/// and emitted segment.
fn tracing() -> bool {
    static TRACE: OnceLock<bool> = OnceLock::new();
    *TRACE.get_or_init(|| std::env::var_os("TCP_TABLE_TRACE").is_some())
}

fn peer_byte(sequence: u32) -> u8 {
    let mixed = sequence.wrapping_mul(0x9e37_79b1);
    (mixed >> 24) as u8 ^ (mixed as u8)
}

fn app_byte(offset: u64) -> u8 {
    let mixed = offset.wrapping_mul(0xa24b_aed4_963e_e407);
    (mixed >> 56) as u8
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

struct Peer {
    address: SocketAddr,
    initial_sequence: u32,
    timestamp: u32,
    timestamps: bool,
    server_initial: Option<u32>,
    server_high: Option<u32>,
    token: Option<TcpFlowToken>,
    receive_base: u32,
    read_offset: u32,
    write_offset: u64,
}

struct Harness {
    table: TcpTable,
    service: SocketAddr,
    peers: Vec<Peer>,
    timers: Vec<(TcpFlowToken, TimerEvent, u64)>,
    now_ms: u64,
}

fn check_result<T>(result: &Result<T, TcpTableError>) {
    match result {
        Err(TcpTableError::Invariant(message)) => panic!("table invariant: {message}"),
        Err(TcpTableError::State(TcpError::ConsumedBeyondBuffered)) => {
            panic!("table consumed beyond the TCB buffered count")
        }
        _ => {}
    }
}

impl Harness {
    fn observe(
        &mut self,
        outgoing: &[Vec<u8>],
        events: &[TcpEvent],
        timers: &[sail_netstack::TcpTimerRequest],
    ) {
        for packet in outgoing {
            let ip = parse_ip_packet(packet, true).expect("emitted IP packet must parse");
            let segment = parse_tcp_segment(ip, true).expect("emitted TCP segment must parse");
            assert_eq!(segment.source, self.service);
            let Some(peer) = self
                .peers
                .iter_mut()
                .find(|peer| peer.address == segment.destination)
            else {
                panic!("segment emitted to an unknown peer");
            };
            let flags = segment.meta.flags;
            let sequence = segment.meta.sequence.get();
            if tracing() {
                eprintln!(
                    "  emit to {} seq={sequence} ack={:?} flags={:#04x} len={} isn={:?} written={}",
                    segment.destination,
                    segment.meta.acknowledgment.map(SeqNumber::get),
                    flags.bits(),
                    segment.payload.len(),
                    peer.server_initial,
                    peer.write_offset,
                );
            }
            if flags.contains(TcpFlags::SYN) {
                assert!(
                    flags.contains(TcpFlags::ACK),
                    "passive side sent a bare SYN"
                );
                // A SYN-ACK acknowledges exactly the peer ISN, which is the
                // base of the peer's byte stream for this flow.
                peer.server_initial = Some(sequence);
                peer.receive_base = segment.meta.acknowledgment.map_or(0, SeqNumber::get);
            }
            if !segment.payload.is_empty() {
                let initial = peer
                    .server_initial
                    .expect("payload emitted before the handshake");
                let offset = sequence.wrapping_sub(initial).wrapping_sub(1);
                for (index, byte) in segment.payload.iter().enumerate() {
                    let stream = u64::from(offset) + index as u64;
                    assert!(
                        stream < peer.write_offset,
                        "emitted payload beyond application writes"
                    );
                    assert_eq!(*byte, app_byte(stream), "emitted payload corrupted");
                }
            }
            let length = segment.payload.len() as u32
                + u32::from(flags.contains(TcpFlags::SYN))
                + u32::from(flags.contains(TcpFlags::FIN));
            let end = sequence.wrapping_add(length);
            peer.server_high = Some(match peer.server_high {
                Some(high) if (end.wrapping_sub(high) as i32) <= 0 => high,
                _ => end,
            });
        }
        for event in events {
            if let TcpEvent::Accepted(connection) = event {
                let peer = self
                    .peers
                    .iter_mut()
                    .find(|peer| peer.address == connection.source)
                    .expect("accepted an unknown peer");
                peer.token = Some(connection.token);
                peer.read_offset = 0;
                peer.write_offset = 0;
            }
        }
        for timer in timers {
            if self.timers.len() == MAX_TIMERS {
                self.timers.remove(0);
            }
            self.timers.push((
                timer.token,
                timer.event,
                self.now_ms.saturating_add(timer.after_ms),
            ));
        }
    }

    fn send_segment(&mut self, index: usize, operation: &[u8]) {
        let peer = &mut self.peers[index];
        let flags = TcpFlags::from_bits(operation[1] & 0x3f);
        let relative = i32::from(i16::from_le_bytes([operation[2], operation[3]]));
        let sequence = peer
            .initial_sequence
            .wrapping_add(1)
            .wrapping_add(relative as u32);
        let sequence = if flags.contains(TcpFlags::SYN) && operation[1] & 0x40 != 0 {
            peer.initial_sequence
        } else {
            sequence
        };
        let ack_delta = i32::from(i8::from_le_bytes([operation[4]]));
        let acknowledgment = match operation[5] % 4 {
            0 => peer.server_high.unwrap_or(0).wrapping_add(ack_delta as u32),
            1 => peer
                .server_initial
                .unwrap_or(0)
                .wrapping_add(1)
                .wrapping_add(ack_delta as u32),
            2 => peer.server_high.unwrap_or(0),
            _ => u32_at(operation, 4),
        };
        let window = u16_at(operation, 6);
        let payload_len = usize::from(operation[8]) * 8 + usize::from(operation[9] % 8);
        // SYN occupies `sequence`; data begins after it.
        let data_start = sequence.wrapping_add(u32::from(flags.contains(TcpFlags::SYN)));
        let payload: Vec<u8> = (0..payload_len)
            .map(|offset| peer_byte(data_start.wrapping_add(offset as u32)))
            .collect();

        let option_bits = operation[10];
        let mut options = Vec::new();
        if flags.contains(TcpFlags::SYN) {
            if option_bits & 1 != 0 {
                let mss = 64 + u16::from(operation[11]) * 8;
                options.extend_from_slice(&[2, 4]);
                options.extend_from_slice(&mss.to_be_bytes());
            }
            if option_bits & 2 != 0 {
                options.extend_from_slice(&[1, 3, 3, operation[11] % 16]);
            }
            if option_bits & 4 != 0 {
                options.extend_from_slice(&[1, 1, 4, 2]);
            }
            peer.timestamps = option_bits & 8 != 0;
        }
        if (peer.timestamps || option_bits & 16 != 0) && option_bits & 32 == 0 {
            peer.timestamp = peer.timestamp.wrapping_add(u32::from(option_bits >> 6));
            options.extend_from_slice(&[1, 1, 8, 10]);
            options.extend_from_slice(&peer.timestamp.to_be_bytes());
            options.extend_from_slice(&peer.server_high.unwrap_or(0).to_be_bytes());
        }
        if !flags.contains(TcpFlags::SYN) && option_bits & 128 != 0 {
            let high = peer.server_high.unwrap_or(0);
            let left = high.wrapping_sub(u32::from(operation[11]) * 16);
            options.extend_from_slice(&[1, 1, 5, 10]);
            options.extend_from_slice(&left.to_be_bytes());
            options.extend_from_slice(&left.wrapping_add(64).to_be_bytes());
        }
        if options.len() > 40 {
            options.truncate(40);
        }
        while options.len() % 4 != 0 {
            options.push(1);
        }

        let Ok(packet) = emit_tcp_segment_with_options(
            peer.address,
            self.service,
            SendControl {
                sequence: SeqNumber::new(sequence),
                acknowledgment: SeqNumber::new(acknowledgment),
                flags,
                window,
            },
            &options,
            &payload,
            64,
            u16::from(operation[0]),
        ) else {
            return;
        };
        let result = self.table.ingest_with_policy_at(&packet, true, self.now_ms);
        check_result(&result);
        if let Ok(output) = result {
            self.observe(&output.outgoing, &output.events, &output.timers);
        }
    }

    fn run(&mut self, operation: &[u8]) {
        let index = usize::from(operation[0] >> 7);
        if tracing() {
            eprintln!(
                "op {} peer={index} now={} {operation:?}",
                operation[0] % 10,
                self.now_ms
            );
        }
        match operation[0] % 10 {
            0..=3 => self.send_segment(index, operation),
            4 => {
                let Some(token) = self.peers[index].token else {
                    return;
                };
                check_result(&self.table.accept(token));
            }
            5 => {
                let Some(token) = self.peers[index].token else {
                    return;
                };
                let result = self.table.read(token, usize::from(u16_at(operation, 1)));
                check_result(&result);
                let Ok(read) = result else {
                    return;
                };
                let peer = &mut self.peers[index];
                for byte in &read.bytes {
                    let sequence = peer.receive_base.wrapping_add(peer.read_offset);
                    assert_eq!(*byte, peer_byte(sequence), "delivered payload corrupted");
                    peer.read_offset = peer.read_offset.wrapping_add(1);
                }
                self.observe(&read.outgoing, &[], &read.timers);
            }
            6 => {
                let Some(token) = self.peers[index].token else {
                    return;
                };
                let limit = self.table.write_limit(token).unwrap_or(0);
                let length = usize::from(u16_at(operation, 1)).min(limit);
                let start = self.peers[index].write_offset;
                let payload: Vec<u8> = (0..length as u64)
                    .map(|offset| app_byte(start + offset))
                    .collect();
                // Admit the bytes before observing, since emitted payload is
                // checked against everything the application has written.
                self.peers[index].write_offset += length as u64;
                let result = self.table.write(token, &payload);
                check_result(&result);
                match result {
                    Ok(output) => self.observe(&output.outgoing, &output.events, &output.timers),
                    Err(_) => self.peers[index].write_offset = start,
                }
            }
            7 => {
                let Some(token) = self.peers[index].token else {
                    return;
                };
                let result = if operation[1] & 1 == 0 {
                    self.table.close(token)
                } else {
                    self.table.abort(token)
                };
                check_result(&result);
                if let Ok(output) = result {
                    self.observe(&output.outgoing, &output.events, &output.timers);
                }
            }
            8 => {
                if self.timers.is_empty() {
                    return;
                }
                let (token, event, due) = self
                    .timers
                    .remove(usize::from(operation[1]) % self.timers.len());
                self.now_ms = self.now_ms.max(due);
                let result = self.table.on_timer_at(token, event, self.now_ms);
                check_result(&result);
                if let Ok(output) = result {
                    self.observe(&output.outgoing, &output.events, &output.timers);
                }
            }
            _ => {
                self.now_ms = self
                    .now_ms
                    .saturating_add(u64::from(u32_at(operation, 1) % 120_000));
            }
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let data = &input[..input.len().min(MAX_INPUT_LEN)];
    if data.len() < HEADER_BYTES {
        return;
    }
    let receive_credit_bytes = [1, 7, 536, 4_096, 16_384, 70_001][usize::from(data[0] % 6)];
    let max_segment_payload_bytes = [1, 17, 536, 1_200][usize::from(data[1] % 4)];
    let config = TcpTableConfig {
        receive_credit_bytes,
        max_segment_payload_bytes,
        nagle_enabled: data[1] & 0x80 != 0,
        keepalive_idle_ms: (data[1] & 0x40 != 0).then_some(1_000),
        time_wait_ms: 1_000,
        ..TcpTableConfig::default()
    };
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let service = SocketAddr::from((Ipv4Addr::new(10, 0, 1, 1), 443));
    let mut harness = Harness {
        table: TcpTable::new(Arc::clone(&ledger), NetworkGeneration::new(1), config),
        service,
        peers: (0..PEERS)
            .map(|index| Peer {
                address: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2 + index as u8), 40_000)),
                initial_sequence: u32_at(data, 2).wrapping_add((index as u32) << 31),
                timestamp: u32::from(u16_at(data, 6)),
                timestamps: false,
                server_initial: None,
                server_high: None,
                token: None,
                receive_base: 0,
                read_offset: 0,
                write_offset: 0,
            })
            .collect(),
        timers: Vec::new(),
        now_ms: 0,
    };

    for operation in data[HEADER_BYTES..].chunks_exact(OPERATION_BYTES) {
        harness.run(operation);
        let stats = harness.table.stats();
        assert!(stats.active_flows <= PEERS);
        assert!(stats.accept_queue <= stats.active_flows);
    }

    drop(harness.timers);
    let mut table = harness.table;
    table.reset_network(NetworkGeneration::new(2));
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(table.stats().time_wait, 0);
    assert_eq!(
        ledger.snapshot().total_bytes,
        0,
        "ledger leaked after reset"
    );
});
