#![no_main]

use libfuzzer_sys::fuzz_target;
use sail_netstack::{
    parse_icmp_packet, parse_ip_packet, parse_tcp_segment, parse_udp_datagram, ParsedIpPacket,
};

const MAX_PACKET_LEN: usize = 65_535;

fn exercise_transport_parsers(ip: ParsedIpPacket<'_>) {
    for verify_checksum in [false, true] {
        let _ = parse_tcp_segment(ip, verify_checksum);
        let _ = parse_udp_datagram(ip, verify_checksum);
        let _ = parse_icmp_packet(ip, verify_checksum);
    }
}

fn exercise_packet(packet: &[u8]) {
    for verify_checksum in [false, true] {
        if let Ok(ip) = parse_ip_packet(packet, verify_checksum) {
            exercise_transport_parsers(ip);
        }
    }
}

fn synthesized_ipv4(data: &[u8], selector: u8) -> Vec<u8> {
    let packet_len = data.len().clamp(20, MAX_PACKET_LEN);
    let mut packet = vec![0_u8; packet_len];
    let copied = data.len().min(packet_len);
    packet[..copied].copy_from_slice(&data[..copied]);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
    packet[6] &= 0x7f;
    packet[9] = [1, 6, 17][usize::from(selector % 3)];
    packet
}

fn synthesized_ipv6(data: &[u8], selector: u8) -> Vec<u8> {
    let payload_len = data.len().min(MAX_PACKET_LEN);
    let mut packet = vec![0_u8; 40 + payload_len];
    packet[40..].copy_from_slice(&data[..payload_len]);
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    packet[6] = [58, 6, 17][usize::from(selector % 3)];
    packet
}

fuzz_target!(|data: &[u8]| {
    exercise_packet(data);

    let selector = data.first().copied().unwrap_or_default();
    let ipv4 = synthesized_ipv4(data, selector);
    exercise_packet(&ipv4);
    let ipv6 = synthesized_ipv6(data, selector.rotate_left(4));
    exercise_packet(&ipv6);
});
