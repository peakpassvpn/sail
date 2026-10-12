pub mod request;
pub mod stream;

pub use stream::VlessStream;

/// Fuzzing (sail::fuzzing): the request and response headers, UDP
/// packets, vision, and XUDP.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz(data: &[u8]) {
    use futures::FutureExt;
    request::fuzz(data);
    stream::fuzz(data);
    // XUDP, which a VLESS mux stream carries: an address, a frame's
    // metadata, and its data into buffers of several sizes.
    use crate::protocol::vmess::xudp;
    let _ = xudp::parse_addr_port(data);
    let _ = xudp::read_addr_port(&mut &data[..]).now_or_never();
    let _ = xudp::read_metadata(&mut &data[..]).now_or_never();
    for room in [0, 7, 2048] {
        let mut buf = vec![0_u8; room];
        if let Some(Ok(read)) = xudp::read_data(&mut &data[..], &mut buf).now_or_never() {
            assert!(read <= room);
        }
    }
}

#[cfg(feature = "inbound-vless")]
pub mod inbound;
#[cfg(feature = "outbound-vless")]
pub mod outbound;
