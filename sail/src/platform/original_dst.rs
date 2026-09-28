//! A connection's destination before a REDIRECT rule sent it to a local
//! listener: the redirect inbound's and auto_redirect's.

use std::io;
use std::net::SocketAddr;

use socket2::SockRef;

/// Where the connection on `socket`, from `peer`, was going before REDIRECT
/// sent it here. An IPv4 connection accepted on a dual-stack IPv6 listener
/// is tracked, and asked for, as IPv4.
pub(crate) fn original_destination(
    socket: &SockRef<'_>,
    peer: SocketAddr,
) -> io::Result<SocketAddr> {
    let original = match unmapped(peer) {
        SocketAddr::V4(_) => socket.original_dst(),
        SocketAddr::V6(_) => socket.original_dst_ipv6(),
    }
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("no original destination (not redirected?): {}", e),
        )
    })?;
    original
        .as_socket()
        .map(unmapped)
        .ok_or_else(|| io::Error::other("original destination is not an IP address"))
}

/// `addr`, as IPv4 if it is an IPv4-mapped IPv6 address.
pub(crate) fn unmapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mapped_address_is_unmapped() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:80".parse().unwrap();
        assert_eq!(unmapped(mapped), "10.0.0.1:80".parse().unwrap());
        let v6: SocketAddr = "[fd00::1]:80".parse().unwrap();
        assert_eq!(unmapped(v6), v6);
    }
}
