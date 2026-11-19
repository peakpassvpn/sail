//! Focused protocol child only. Real checksum-valid handshakes and output bytes;
//! private state is inspected for ownership, not substituted for ledger/TCB.
use super::*;
use crate::{emit_tcp_segment_with_options, parse_ip_packet, parse_tcp_segment, BudgetProfile};
use std::net::{Ipv4Addr, Ipv6Addr};

struct Fixture {
    table: TcpTable,
    ledger: Arc<ResourceLedger>,
    token: TcpFlowToken,
    key: TcpFlowKey,
    peer: SocketAddr,
    local: SocketAddr,
    peer_next: u32,
    clock: u32,
    timestamps: bool,
    peer_mss: usize,
}
fn timestamp(value: u32, echo: u32) -> Vec<u8> {
    let mut options = vec![8, 10];
    options.extend_from_slice(&value.to_be_bytes());
    options.extend_from_slice(&echo.to_be_bytes());
    options.extend_from_slice(&[1, 1]);
    options
}
fn syn_options(mss: Option<u16>, timestamps: bool, sack: bool, echo: u32) -> Vec<u8> {
    let mut options = Vec::new();
    if let Some(mss) = mss {
        options.extend_from_slice(&[2, 4]);
        options.extend_from_slice(&mss.to_be_bytes());
    }
    if sack {
        options.extend_from_slice(&[4, 2]);
    }
    if timestamps {
        options.extend(timestamp(100, echo));
    }
    options.extend_from_slice(&[3, 3, 7]);
    options.resize(options.len().next_multiple_of(4), 1);
    options
}
fn wire(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    options: &[u8],
    data: &[u8],
) -> Vec<u8> {
    emit_tcp_segment_with_options(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(ack),
            flags,
            window,
        },
        options,
        data,
        64,
        1,
    )
    .unwrap()
}
fn open(ipv6: bool, active: bool, mss: Option<u16>, timestamps: bool, sack: bool) -> Fixture {
    let (peer, local) = if ipv6 {
        (
            SocketAddr::from((Ipv6Addr::LOCALHOST, 40000)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
        )
    } else {
        (
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 40000)),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
        )
    };
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let config = TcpTableConfig {
        max_segment_payload_bytes: 9000,
        link_mtu: Some(9000),
        max_send_buffer_bytes: Some(256 * 1024),
        ..TcpTableConfig::default()
    };
    let mut table = TcpTable::new(ledger.clone(), NetworkGeneration::new(1), config);
    let expected_advertised = if ipv6 { 8940 } else { 8960 };
    let (token, peer_next) = if active {
        let (token, sent) = table.connect(local, peer).unwrap();
        let syn =
            parse_tcp_segment(parse_ip_packet(&sent.outgoing[0], true).unwrap(), true).unwrap();
        assert_eq!(syn.options.maximum_segment_size, Some(expected_advertised));
        let opts = syn_options(mss, timestamps, sack, syn.options.timestamps.unwrap().0);
        let response = wire(
            peer,
            local,
            9000,
            syn.meta.sequence.get().wrapping_add(1),
            TcpFlags::SYN.union(TcpFlags::ACK),
            65535,
            &opts,
            &[],
        );
        let connected = table.ingest(&response).unwrap();
        assert!(matches!(
            connected.events.as_slice(),
            [TcpEvent::Connected(_)]
        ));
        (token, 9001)
    } else {
        let opts = syn_options(mss, timestamps, sack, 0);
        let response = table
            .ingest(&wire(peer, local, 100, 0, TcpFlags::SYN, 65535, &opts, &[]))
            .unwrap();
        let syn_ack =
            parse_tcp_segment(parse_ip_packet(&response.outgoing[0], true).unwrap(), true).unwrap();
        assert_eq!(
            syn_ack.options.maximum_segment_size,
            Some(expected_advertised)
        );
        let ack_opts = if timestamps {
            timestamp(101, syn_ack.options.timestamps.unwrap().0)
        } else {
            Vec::new()
        };
        let ack = wire(
            peer,
            local,
            101,
            syn_ack.meta.sequence.get().wrapping_add(1),
            TcpFlags::ACK,
            65535,
            &ack_opts,
            &[],
        );
        let accepted = table.ingest(&ack).unwrap();
        let token = match accepted.events.as_slice() {
            [TcpEvent::Accepted(connection)] => connection.token,
            other => panic!("{other:?}"),
        };
        table.accept(token).unwrap();
        (token, 101)
    };
    let key = table.key_for(token).unwrap();
    let peer_mss = usize::from(mss.unwrap_or(if ipv6 { 1220 } else { 536 }));
    assert_eq!(table.by_key[&key].peer_send_mss, peer_mss);
    Fixture {
        table,
        ledger,
        token,
        key,
        peer,
        local,
        peer_next,
        clock: 101,
        timestamps,
        peer_mss,
    }
}
impl Fixture {
    fn send_next(&self) -> u32 {
        self.table.by_key[&self.key].tcb.send_next().get()
    }
    fn unacked(&self) -> u32 {
        self.table.by_key[&self.key].tcb.send_unacked().get()
    }
    fn input(
        &mut self,
        sequence: u32,
        acknowledgment: u32,
        data: &[u8],
        window: u16,
    ) -> TcpIngress {
        self.clock += 1;
        let opts = if self.timestamps {
            timestamp(self.clock, 0)
        } else {
            Vec::new()
        };
        self.table
            .ingest(&wire(
                self.peer,
                self.local,
                sequence,
                acknowledgment,
                TcpFlags::ACK,
                window,
                &opts,
                data,
            ))
            .unwrap()
    }
    fn check(&self, bytes: &[u8], path: usize) -> (u32, Vec<u8>) {
        let tcp = parse_tcp_segment(parse_ip_packet(bytes, true).unwrap(), true).unwrap();
        let fixed_ip = if self.peer.is_ipv4() { 20 } else { 40 };
        let tcp_header = bytes.len() - fixed_ip - tcp.payload.len();
        let options = tcp_header - 20;
        assert!(bytes.len() <= path, "wire={} path={path}", bytes.len());
        if !tcp.payload.is_empty() {
            assert!(
                tcp.payload.len() <= self.peer_mss.checked_sub(options).unwrap(),
                "wire={} payload={} options={options} peer={}",
                bytes.len(),
                tcp.payload.len(),
                self.peer_mss
            );
        }
        eprintln!(
            "mss-wire={} ip={} tcp={} options={} payload={} flags={:?} seq={}",
            bytes.len(),
            fixed_ip,
            tcp_header,
            options,
            tcp.payload.len(),
            tcp.meta.flags,
            tcp.meta.sequence.get()
        );
        (tcp.meta.sequence.get(), tcp.payload.to_vec())
    }
    fn close(mut self) {
        self.table.reset_network(NetworkGeneration::new(2));
        assert_eq!(self.ledger.snapshot().used(ResourceKind::TcpFlows), 0);
        assert_eq!(self.ledger.snapshot().total_bytes, 0);
    }
    fn add_three_receive_sack_blocks(&mut self) {
        for (index, offset) in [10, 30, 50].into_iter().enumerate() {
            let window = if self.table.by_key[&self.key].tcb.peer_window() == 0 {
                0
            } else {
                65535
            };
            let out = self.input(self.peer_next + offset, self.unacked(), &[0x77], window);
            for packet in &out.outgoing {
                self.check(packet, 9000);
            }
            assert_eq!(
                SegmentOptionPlan::new(&self.table.by_key[&self.key]).len,
                24 + 8 * index
            );
            assert_eq!(
                self.table.write_limit(self.token).unwrap(),
                self.peer_mss - (24 + 8 * index)
            );
        }
    }
    fn fill_receive_gaps(&mut self, path: usize) {
        for (offset, len) in [(0, 10), (11, 19), (31, 19)] {
            let out = self.input(
                self.peer_next + offset,
                self.unacked(),
                &vec![0x66; len],
                65535,
            );
            for packet in &out.outgoing {
                self.check(packet, path);
            }
        }
        assert!(self.table.by_key[&self.key].out_of_order.is_empty());
    }
}

#[test]
fn peer_mss_passive_families_and_defaults() {
    for ipv6 in [false, true] {
        for timestamps in [false, true] {
            for explicit in [false, true] {
                let mss = explicit.then_some(if ipv6 { 1440 } else { 1460 });
                let mut f = open(ipv6, false, mss, timestamps, true);
                let effective = f.peer_mss - if timestamps { 12 } else { 0 };
                assert_eq!(f.table.write_limit(f.token).unwrap(), effective);
                let data = vec![0x5a; effective];
                let output = f.table.write(f.token, &data).unwrap();
                assert_eq!(
                    f.table.packet_len(f.token, effective).unwrap(),
                    output.outgoing[0].len()
                );
                assert_eq!(f.check(&output.outgoing[0], 1500).1, data);
                // Aggregate credit remains window/sendbuffer based, not one MSS.
                assert!(f.table.write_capacity(f.token).unwrap() > 4 * effective);
                f.close();
            }
        }
    }
    // Natural ACK growth must still allow one full64KiB commit reservation.
    let mut f = open(false, false, Some(1460), true, true);
    for _ in 0..64 {
        if f.table.write_capacity(f.token).unwrap() >= 65536 {
            break;
        }
        let len = f.table.write_limit(f.token).unwrap();
        let out = f.table.write(f.token, &vec![0x44; len]).unwrap();
        f.check(&out.outgoing[0], 1500);
        f.input(f.peer_next, f.send_next(), &[], 65535);
    }
    assert!(f.table.write_capacity(f.token).unwrap() >= 65536);
    f.close();
}

#[test]
fn peer_mss_active_families_and_defaults() {
    for ipv6 in [false, true] {
        for timestamps in [false, true] {
            for explicit in [false, true] {
                let mss = explicit.then_some(if ipv6 { 1440 } else { 1460 });
                let mut f = open(ipv6, true, mss, timestamps, true);
                let limit = f.peer_mss - if timestamps { 12 } else { 0 };
                assert_eq!(f.table.write_limit(f.token).unwrap(), limit);
                let sent = f.table.write(f.token, &vec![0x45; limit]).unwrap();
                assert_eq!(
                    f.table.packet_len(f.token, limit).unwrap(),
                    sent.outgoing[0].len()
                );
                assert_eq!(f.check(&sent.outgoing[0], 1500).1.len(), limit);
                f.close();
            }
        }
    }
}

#[test]
fn peer_mss_dynamic_options_retransmit_suffixes() {
    let mut f = open(false, false, Some(1460), true, true);
    let first_sequence = f.send_next();
    for byte in [0x41, 0x42, 0x43] {
        let out = f.table.write(f.token, &vec![byte; 1448]).unwrap();
        assert_eq!(f.check(&out.outgoing[0], 1500).1, vec![byte; 1448]);
    }
    let original_next = f.send_next();
    f.add_three_receive_sack_blocks();
    let retransmit = f
        .table
        .on_timer(f.token, TimerEvent::Retransmission)
        .unwrap();
    let first = retransmit
        .outgoing
        .iter()
        .find(|packet| {
            !parse_tcp_segment(parse_ip_packet(packet, true).unwrap(), true)
                .unwrap()
                .payload
                .is_empty()
        })
        .unwrap();
    assert_eq!(f.check(first, 1500), (first_sequence, vec![0x41; 1420]));
    let before = f.ledger.snapshot().used(ResourceKind::TcpPayloadBytes);
    let continued = f.input(f.peer_next, first_sequence.wrapping_add(1420), &[], 65535);
    let tail = continued
        .outgoing
        .iter()
        .find(|packet| {
            !parse_tcp_segment(parse_ip_packet(packet, true).unwrap(), true)
                .unwrap()
                .payload
                .is_empty()
        })
        .unwrap();
    assert_eq!(
        f.check(tail, 1500),
        (first_sequence.wrapping_add(1420), vec![0x41; 28])
    );
    assert_eq!(
        f.ledger.snapshot().used(ResourceKind::TcpPayloadBytes),
        before - 1420
    );
    assert_eq!(
        f.send_next(),
        original_next,
        "retransmits must not consume new application sequence"
    );
    // Exercise fast/SACK/rescue render boundaries using the same real send
    // chunks/leases; selection state is set explicitly, not a loss benchmark.
    {
        let flow = f.table.by_key.get_mut(&f.key).unwrap();
        flow.send[0].sacked = true;
        flow.send[1].sacked = false;
        flow.send[1].retransmitted = false;
        flow.send[2].sacked = true;
        flow.sack_recovery = Some(SackRecovery {
            recovery_point: flow.tcb.send_next(),
            rescue_after: SeqNumber::new(flow.tcb.send_unacked().get().wrapping_sub(1)),
        });
    }
    let selected = f.table.render_sack_recovery(f.key, 1).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(f.check(&selected[0], 1500).1, vec![0x42; 1420]);
    assert!(f.table.by_key[&f.key].send[1].resegment);
    let rescue_before = f.table.stats.sack_rescue_segments;
    let rescue = f.table.render_sack_recovery(f.key, 1).unwrap();
    assert_eq!(rescue.len(), 1);
    assert_eq!(f.check(&rescue[0], 1500).1, vec![0x42; 1420]);
    assert_eq!(f.table.stats.sack_rescue_segments, rescue_before + 1);
    f.fill_receive_gaps(1500);
    assert_eq!(f.table.write_limit(f.token).unwrap(), 1448);
    assert_eq!(f.send_next(), original_next);
    f.close();
    // SACK split uses actual current option length while transferring (not
    // duplicating) payload leases; an unsacked1430B piece exceeds1420.
    let mut split = open(false, false, Some(1460), true, true);
    let sequence = split.send_next();
    split.table.write(split.token, &vec![0x46; 1448]).unwrap();
    split.add_three_receive_sack_blocks();
    let before = split.ledger.snapshot().used(ResourceKind::TcpPayloadBytes);
    let blocks = [
        Some(SackBlock {
            left: SeqNumber::new(sequence.wrapping_add(1430)),
            right: SeqNumber::new(sequence.wrapping_add(1448)),
        }),
        None,
        None,
        None,
    ];
    let plan = prepare_sack_split(&split.ledger, &split.table.by_key[&split.key], &blocks)
        .unwrap()
        .unwrap();
    apply_sack_split(split.table.by_key.get_mut(&split.key).unwrap(), plan);
    let flow = &split.table.by_key[&split.key];
    assert_eq!(flow.send.len(), 2);
    assert_eq!(flow.send[0].bytes.len(), 1430);
    assert!(flow.send[0].resegment);
    assert_eq!(flow.send[1].sequence.get(), sequence.wrapping_add(1430));
    assert_eq!(flow.send[1].bytes.len(), 18);
    assert!(flow.send[1].sacked);
    assert_eq!(
        split.ledger.snapshot().used(ResourceKind::TcpPayloadBytes),
        before
    );
    let retransmit = split
        .table
        .on_timer(split.token, TimerEvent::Retransmission)
        .unwrap();
    let data = retransmit
        .outgoing
        .iter()
        .find(|packet| {
            !parse_tcp_segment(parse_ip_packet(packet, true).unwrap(), true)
                .unwrap()
                .payload
                .is_empty()
        })
        .unwrap();
    assert_eq!(split.check(data, 1500), (sequence, vec![0x46; 1420]));
    split.close();
}

#[test]
fn peer_mss_pending_and_path_ceiling() {
    for persist in [false, true] {
        let mut f = open(false, false, Some(1460), true, true);
        let old_next = f.send_next();
        if persist {
            f.input(f.peer_next, old_next, &[], 0);
        } else {
            f.table.config.nagle_enabled = true;
            f.table.write(f.token, &vec![0x41; 1448]).unwrap();
        }
        let pending_start = f.send_next();
        let out = f.table.write(f.token, &vec![0x55; 1440]).unwrap();
        assert!(out.outgoing.is_empty());
        assert_eq!(f.send_next(), pending_start);
        assert_eq!(
            f.table.by_key[&f.key]
                .pending_send
                .as_ref()
                .unwrap()
                .bytes
                .len(),
            1440
        );
        f.add_three_receive_sack_blocks();
        let ack = if persist { old_next } else { pending_start };
        // The peer already sent the byte at peer_next+50; its SND.NXT is
        // peer_next+51 even though our RCV.NXT still waits for the gaps.
        // Reusing peer_next for a window update is stale versus SND.WL1.
        if persist {
            assert_eq!(f.table.by_key[&f.key].tcb.peer_window(), 0);
            let before = f.ledger.snapshot().used(ResourceKind::TcpPayloadBytes);
            let stale = f.input(f.peer_next, ack, &[], 65535);
            assert!(
                stale.outgoing.iter().all(|packet| {
                    parse_tcp_segment(parse_ip_packet(packet, true).unwrap(), true)
                        .unwrap()
                        .payload
                        .is_empty()
                }),
                "stale window update must not flush persist data"
            );
            eprintln!(
                "persist-stale-window seq={} current_window={} pending_bytes={} send_next={}",
                f.peer_next,
                f.table.by_key[&f.key].tcb.peer_window(),
                f.table.by_key[&f.key]
                    .pending_send
                    .as_ref()
                    .unwrap()
                    .bytes
                    .len(),
                f.send_next()
            );
            assert_eq!(f.table.by_key[&f.key].tcb.peer_window(), 0);
            assert_eq!(
                f.table.by_key[&f.key]
                    .pending_send
                    .as_ref()
                    .unwrap()
                    .bytes
                    .len(),
                1440
            );
            assert_eq!(f.send_next(), pending_start);
            assert_eq!(
                f.ledger.snapshot().used(ResourceKind::TcpPayloadBytes),
                before
            );
        }
        let peer_ack_sequence = f.peer_next.wrapping_add(51);
        let sequence = SeqNumber::new(peer_ack_sequence);
        let tcb = &f.table.by_key[&f.key].tcb;
        assert!(!sequence.before(tcb.recv_next()));
        assert!(sequence.before(tcb.advertised_right_edge()));
        let first = f.input(peer_ack_sequence, ack, &[], 65535);
        eprintln!("pending-fresh-window persist={persist} seq={peer_ack_sequence} current_window={} send_next={}",
            f.table.by_key[&f.key].tcb.peer_window(), f.send_next());
        assert!(f.table.by_key[&f.key].tcb.peer_window() > 0);
        let data = first
            .outgoing
            .iter()
            .find(|packet| {
                !parse_tcp_segment(parse_ip_packet(packet, true).unwrap(), true)
                    .unwrap()
                    .payload
                    .is_empty()
            })
            .unwrap();
        assert_eq!(f.check(data, 1500), (pending_start, vec![0x55; 1420]));
        assert_eq!(
            f.table.by_key[&f.key]
                .pending_send
                .as_ref()
                .unwrap()
                .bytes
                .len(),
            20
        );
        let second = f.input(
            peer_ack_sequence,
            pending_start.wrapping_add(1420),
            &[],
            65535,
        );
        let tail = second
            .outgoing
            .iter()
            .find(|packet| {
                !parse_tcp_segment(parse_ip_packet(packet, true).unwrap(), true)
                    .unwrap()
                    .payload
                    .is_empty()
            })
            .unwrap();
        assert_eq!(
            f.check(tail, 1500),
            (pending_start.wrapping_add(1420), vec![0x55; 20])
        );
        f.input(
            peer_ack_sequence,
            pending_start.wrapping_add(1440),
            &[],
            65535,
        );
        assert!(f.table.by_key[&f.key].pending_send.is_none());
        assert_eq!(f.table.lower_platform_mtu(1490), 1);
        assert_eq!(f.table.write_limit(f.token).unwrap(), 1410);
        let cached = f.table.by_key[&f.key].max_send_segment_bytes;
        f.fill_receive_gaps(1490);
        assert_eq!(f.table.by_key[&f.key].max_send_segment_bytes, cached);
        assert_eq!(
            f.table.write_limit(f.token).unwrap(),
            1410,
            "options disappearing must not undo path lowering"
        );
        let sent = f.table.write(f.token, &vec![0x66; 1410]).unwrap();
        f.check(&sent.outgoing[0], 1490);
        f.close();
    }
}

#[test]
fn peer_mss_checked_bounds_and_layout() {
    for (cache, peer, options) in [
        (0, 1460, 12),
        (9000, 0, 0),
        (9000, 12, 12),
        (9000, 1, 12),
        (9000, 1460, 41),
        (9000, 1460, usize::MAX),
    ] {
        assert!(matches!(
            checked_effective_segment_bytes(cache, peer, options),
            Err(TcpTableError::PayloadTooLarge)
        ));
    }
    assert_eq!(
        checked_effective_segment_bytes(1460, 1460, 12).unwrap(),
        1448
    );
    assert_eq!(
        checked_effective_segment_bytes(1400, 1460, 12).unwrap(),
        1400
    );
    let mut f = open(false, false, Some(1460), true, true);
    f.table.by_key.get_mut(&f.key).unwrap().peer_send_mss = 1;
    let next = f.send_next();
    let total = f.ledger.snapshot().total_bytes;
    let pending = f.table.by_key[&f.key].send.len();
    assert!(matches!(
        f.table.write(f.token, &[1]),
        Err(TcpTableError::PayloadTooLarge)
    ));
    assert_eq!(f.send_next(), next);
    assert_eq!(f.ledger.snapshot().total_bytes, total);
    assert_eq!(f.table.by_key[&f.key].send.len(), pending);
    eprintln!("mss-layout TcpFlow size={} align={} raw_peer_size={} raw_peer_offset={} metadata_charge={} (parent layout/delta and allocator still require paired measurement)",
        std::mem::size_of::<TcpFlow>(),std::mem::align_of::<TcpFlow>(),std::mem::size_of::<usize>(),
        std::mem::offset_of!(TcpFlow,peer_send_mss),TCP_FLOW_METADATA_CHARGE);
    f.close();
}
