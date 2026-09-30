#[cfg(feature = "inbound-trojan")]
pub mod inbound;
#[cfg(feature = "outbound-trojan")]
pub mod outbound;

/// The length of a UDP packet's payload, from the four bytes that follow its
/// address: the length, big-endian, then CRLF. Without the CRLF the packet
/// is malformed, and so is the stream it came in.
fn packet_length(head: [u8; 4]) -> std::io::Result<usize> {
    if head[2..] != *b"\r\n" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "trojan udp packet without CRLF",
        ));
    }
    Ok(u16::from_be_bytes([head[0], head[1]]) as usize)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_packet_length() {
        assert_eq!(
            super::packet_length([0x01, 0x02, b'\r', b'\n']).unwrap(),
            0x102
        );
        assert!(super::packet_length([0x00, 0x04, b'\n', b'\r']).is_err());
        assert!(super::packet_length([0x00, 0x04, 0, 0]).is_err());
    }
}
