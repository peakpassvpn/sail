use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use sail_netstack::{
    emit_udp_packet, parse_ip_packet, parse_udp_datagram, BudgetProfile, NetworkGeneration,
    ResourceKind, ResourceLedger, ShardId, UdpError, UdpTable,
};

#[test]
fn repeated_tuple_reuses_flow_and_reply_reverses_path() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger.clone(), NetworkGeneration::new(1), 30_000, 512);
    let client = SocketAddr::from((Ipv4Addr::new(10, 7, 7, 2), 50_000));
    let remote = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
    let packet = emit_udp_packet(client, remote, b"query", 64, 1).unwrap();
    let first = table.ingest(&packet, 100).unwrap();
    let token = first.token;
    assert_eq!(first.payload.to_vec(), b"query");
    drop(first);
    let second = table.ingest(&packet, 200).unwrap();
    assert_eq!(second.token, token);
    drop(second);
    assert_eq!(table.stats().active_flows, 1);

    let reply = table.emit_reply(token, remote, b"answer", 300).unwrap();
    let parsed = parse_udp_datagram(parse_ip_packet(&reply, true).unwrap(), true).unwrap();
    assert_eq!(parsed.source, remote);
    assert_eq!(parsed.destination, client);
    assert_eq!(parsed.payload, b"answer");
}

#[test]
fn non_unicast_endpoints_never_become_flows() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger.clone(), NetworkGeneration::new(1), 30_000, 512);
    let host = SocketAddr::from((Ipv4Addr::new(10, 203, 0, 1), 5_355));
    let host_v6 = SocketAddr::from(("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 5_353));
    let unicast = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
    let pairs = [
        // LLMNR and mDNS queries a host sends on every interface.
        (
            host,
            SocketAddr::from((Ipv4Addr::new(224, 0, 0, 252), 5_355)),
        ),
        (
            host,
            SocketAddr::from((Ipv4Addr::new(224, 0, 0, 251), 5_353)),
        ),
        (
            host_v6,
            SocketAddr::from(("ff02::fb".parse::<Ipv6Addr>().unwrap(), 5_353)),
        ),
        (host, SocketAddr::from((Ipv4Addr::BROADCAST, 67))),
        (host, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 53))),
        (host, SocketAddr::from((Ipv4Addr::new(240, 0, 0, 1), 53))),
        (SocketAddr::from((Ipv4Addr::UNSPECIFIED, 68)), unicast),
        (SocketAddr::from((Ipv4Addr::LOCALHOST, 53)), unicast),
        (SocketAddr::from((Ipv4Addr::new(224, 0, 0, 1), 53)), unicast),
        (
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 546)),
            SocketAddr::from(("2001:db8::53".parse::<Ipv6Addr>().unwrap(), 53)),
        ),
    ];
    for (source, destination) in pairs {
        let packet = emit_udp_packet(source, destination, b"query", 64, 1).unwrap();
        assert!(matches!(
            table.ingest(&packet, 100),
            Err(UdpError::InvalidAddress)
        ));
    }
    assert_eq!(table.stats().invalid_address_drops, 10);
    assert_eq!(table.stats().created_flows, 0);
    assert_eq!(table.stats().malformed_packets, 0);
    assert_eq!(ledger.snapshot().total_bytes, 0);

    let loopback_v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 50_000));
    let packet = emit_udp_packet(
        loopback_v6,
        SocketAddr::from((Ipv6Addr::LOCALHOST, 53)),
        b"q",
        64,
        1,
    )
    .unwrap();
    assert!(table.ingest(&packet, 100).is_ok());
    assert_eq!(table.stats().created_flows, 1);
}

#[test]
fn shard_identity_disambiguates_local_flow_ids_and_rejects_cross_shard_use() {
    let ledger = ResourceLedger::new(BudgetProfile::Desktop.budget()).unwrap();
    let generation = NetworkGeneration::new(4);
    let mut first =
        UdpTable::new_on_shard(ledger.clone(), generation, ShardId::new(1), 30_000, 512);
    let mut second = UdpTable::new_on_shard(ledger, generation, ShardId::new(2), 30_000, 512);
    let client = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40_000));
    let remote = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53));
    let packet = emit_udp_packet(client, remote, b"query", 64, 1).unwrap();

    let first_token = first.ingest(&packet, 1).unwrap().token;
    let second_token = second.ingest(&packet, 1).unwrap().token;
    assert_eq!(first_token.flow(), second_token.flow());
    assert_ne!(first_token, second_token);
    assert_eq!(first_token.shard(), ShardId::new(1));
    assert_eq!(second_token.shard(), ShardId::new(2));
    assert!(matches!(
        second.emit_reply(first_token, remote, b"answer", 2),
        Err(UdpError::StaleToken)
    ));
}

#[test]
fn reset_and_expiry_make_tokens_stale_and_release_resources() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = UdpTable::new(ledger.clone(), NetworkGeneration::new(7), 10, 256);
    let client = SocketAddr::from(("2001:db8::2".parse::<Ipv6Addr>().unwrap(), 111));
    let remote = SocketAddr::from(("2001:db8::53".parse::<Ipv6Addr>().unwrap(), 222));
    let packet = emit_udp_packet(client, remote, b"x", 64, 0).unwrap();
    let ingress = table.ingest(&packet, 1).unwrap();
    let token = ingress.token;
    drop(ingress);
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 1);
    assert_eq!(table.expire_idle(11).unwrap(), 0);
    assert_eq!(table.expire_idle(20).unwrap(), 1);
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 0);
    assert!(matches!(
        table.emit_reply(token, remote, &[], 21),
        Err(UdpError::StaleToken)
    ));

    let fresh = table.ingest(&packet, 22).unwrap().token;
    table.reset_network(NetworkGeneration::new(8));
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(table.stats().peak_active_flows, 1);
    assert!(matches!(
        table.emit_reply(fresh, remote, &[], 23),
        Err(UdpError::StaleToken)
    ));
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 0);
}

#[test]
fn flow_admission_is_a_hard_limit_and_does_not_leak_payload() {
    let mut budget = BudgetProfile::Router.budget();
    budget.max_udp_flows = 1;
    let ledger = ResourceLedger::new(budget).unwrap();
    let mut table = UdpTable::new(ledger.clone(), NetworkGeneration::new(0), 100, 64);
    for port in [10, 11] {
        let packet = emit_udp_packet(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), port)),
            SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)),
            b"payload",
            64,
            port,
        )
        .unwrap();
        let result = table.ingest(&packet, u64::from(port));
        if port == 10 {
            drop(result.unwrap());
        } else {
            assert!(matches!(result, Err(UdpError::Budget(_))));
        }
    }
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.used[ResourceKind::UdpFlows as usize], 1);
    assert_eq!(snapshot.used[ResourceKind::PacketBytes as usize], 0);
}

#[test]
fn reversed_time_is_rejected_without_expiring_flows() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger, NetworkGeneration::new(0), 10, 64);
    assert_eq!(table.expire_idle(100).unwrap(), 0);
    assert!(matches!(
        table.expire_idle(99),
        Err(UdpError::ClockWentBackwards)
    ));
}

#[test]
fn pressure_divisor_shortens_idle_retention() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger, NetworkGeneration::new(0), 100, 64);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 1)),
        SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 2)),
        b"x",
        64,
        1,
    )
    .unwrap();
    drop(table.ingest(&packet, 0).unwrap());
    assert_eq!(table.expire_idle_under_pressure(49, 2).unwrap(), 0);
    assert_eq!(table.expire_idle_under_pressure(50, 2).unwrap(), 1);
}

#[test]
fn activity_replaces_the_old_expiry_without_a_stale_timeout() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger, NetworkGeneration::new(0), 10, 64);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 10)),
        SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 20)),
        b"refresh",
        64,
        1,
    )
    .unwrap();

    drop(table.ingest(&packet, 0).unwrap());
    drop(table.ingest(&packet, 9).unwrap());
    assert_eq!(table.expire_idle(10).unwrap(), 0);
    assert_eq!(table.expire_idle(18).unwrap(), 0);
    assert_eq!(table.expire_idle(19).unwrap(), 0);
    assert_eq!(table.expire_idle(20).unwrap(), 1);
}

#[test]
fn pressure_recovery_extends_live_flow_deadlines_again() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger, NetworkGeneration::new(0), 100, 64);
    let packet = emit_udp_packet(
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 11)),
        SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 21)),
        b"recover",
        64,
        1,
    )
    .unwrap();

    drop(table.ingest(&packet, 0).unwrap());
    assert_eq!(table.expire_idle_under_pressure(10, 4).unwrap(), 0);
    assert_eq!(table.expire_idle_under_pressure(20, 1).unwrap(), 0);
    assert_eq!(table.expire_idle(25).unwrap(), 0);
    assert_eq!(table.expire_idle(100).unwrap(), 1);
}

#[test]
fn timer_expiry_removes_only_flows_whose_deadlines_are_due() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger, NetworkGeneration::new(0), 10, 64);
    let packet = |port| {
        emit_udp_packet(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), port)),
            SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)),
            b"due",
            64,
            port,
        )
        .unwrap()
    };

    drop(table.ingest(&packet(30), 0).unwrap());
    drop(table.ingest(&packet(31), 5).unwrap());
    assert_eq!(table.expire_idle(10).unwrap(), 1);
    assert_eq!(table.stats().active_flows, 1);
    assert_eq!(table.stats().peak_active_flows, 2);
    assert_eq!(table.expire_idle(15).unwrap(), 0);
    assert_eq!(table.expire_idle(20).unwrap(), 1);
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(table.stats().peak_active_flows, 2);
}

#[test]
fn late_reply_expires_and_rejects_a_stale_token_without_an_external_sweep() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger, NetworkGeneration::new(0), 10, 64);
    let client = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40));
    let remote = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53));
    let packet = emit_udp_packet(client, remote, b"late", 64, 1).unwrap();
    let token = table.ingest(&packet, 0).unwrap().token;

    assert!(matches!(
        table.emit_reply(token, remote, b"reply", 10),
        Err(UdpError::StaleToken)
    ));
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(table.stats().expired_flows, 1);
}

#[test]
fn ingress_after_idle_expiry_replaces_the_tuple_capability() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger.clone(), NetworkGeneration::new(0), 10, 64);
    let client = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 41));
    let remote = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53));
    let packet = emit_udp_packet(client, remote, b"new session", 64, 1).unwrap();

    let retired = table.ingest(&packet, 0).unwrap().token;
    let replacement = table.ingest(&packet, 10).unwrap().token;

    assert_ne!(replacement, retired);
    assert!(matches!(
        table.emit_reply(retired, remote, b"stale", 10),
        Err(UdpError::StaleToken)
    ));
    assert!(table.emit_reply(replacement, remote, b"fresh", 10).is_ok());
    assert_eq!(table.stats().created_flows, 2);
    assert_eq!(table.stats().expired_flows, 1);
    assert_eq!(table.stats().active_flows, 1);
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 1);
}

#[test]
fn invalid_reply_does_not_refresh_an_idle_flow() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger.clone(), NetworkGeneration::new(0), 10, 64);
    let client = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 42));
    let remote = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53));
    let packet = emit_udp_packet(client, remote, b"query", 64, 1).unwrap();
    let token = table.ingest(&packet, 0).unwrap().token;

    let invalid_source = SocketAddr::from((Ipv6Addr::LOCALHOST, 53));
    assert!(matches!(
        table.emit_reply(token, invalid_source, b"invalid", 9),
        Err(UdpError::Wire(_))
    ));
    assert!(matches!(
        table.emit_reply(token, remote, b"too late", 10),
        Err(UdpError::StaleToken)
    ));
    assert_eq!(table.stats().expired_flows, 1);
    assert_eq!(table.stats().active_flows, 0);
    assert_eq!(ledger.snapshot().used[ResourceKind::UdpFlows as usize], 0);
}

#[test]
fn ingest_recovers_the_wheel_across_a_large_clock_jump() {
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    let mut table = UdpTable::new(ledger, NetworkGeneration::new(0), 10, 64);
    let packet = |port| {
        emit_udp_packet(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), port)),
            SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)),
            b"jump",
            64,
            port,
        )
        .unwrap()
    };

    drop(table.ingest(&packet(41), 0).unwrap());
    drop(table.ingest(&packet(42), 1_000_000_000_000).unwrap());
    assert_eq!(table.stats().expired_flows, 1);
    assert_eq!(table.stats().active_flows, 1);
}
