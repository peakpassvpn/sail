//! Session frames: `command u8 | stream id u32 | length u16 | data`, all
//! big-endian.

use bytes::{BufMut, BytesMut};

/// Padding, read and dropped by either end.
pub const CMD_WASTE: u8 = 0;
/// A client opens a stream.
pub const CMD_SYN: u8 = 1;
/// Data on a stream.
pub const CMD_PSH: u8 = 2;
/// A stream is closed. Its peer closes its end without answering.
pub const CMD_FIN: u8 = 3;
/// The client's settings, the first frame of every session.
pub const CMD_SETTINGS: u8 = 4;
/// A server's reason for closing a session.
pub const CMD_ALERT: u8 = 5;
/// A server's padding scheme, for a client whose own differs.
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
/// Version 2: the server has opened a stream, or failed to, with the error
/// as its data.
pub const CMD_SYNACK: u8 = 7;
/// Version 2: keepalive.
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
/// Version 2: the server's settings, in answer to a client's.
pub const CMD_SERVER_SETTINGS: u8 = 10;

pub const HEADER_LEN: usize = 7;

/// The most data one frame carries.
pub const MAX_DATA: usize = u16::MAX as usize;

/// The protocol version this implementation speaks.
pub const VERSION: u8 = 2;

/// What this implementation reports as its `client` setting.
pub const CLIENT_NAME: &str = concat!("sail/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub cmd: u8,
    pub sid: u32,
    pub len: u16,
}

impl Header {
    pub fn decode(raw: &[u8; HEADER_LEN]) -> Self {
        Header {
            cmd: raw[0],
            sid: u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]),
            len: u16::from_be_bytes([raw[5], raw[6]]),
        }
    }
}

/// Appends a frame to `buf`. `data` longer than a frame carries is split
/// across frames of the same command and stream, which only data frames
/// ever need.
pub fn put(buf: &mut BytesMut, cmd: u8, sid: u32, data: &[u8]) {
    let mut chunks = data.chunks(MAX_DATA);
    let first = chunks.next().unwrap_or(&[]);
    put_one(buf, cmd, sid, first);
    for chunk in chunks {
        put_one(buf, cmd, sid, chunk);
    }
}

fn put_one(buf: &mut BytesMut, cmd: u8, sid: u32, data: &[u8]) {
    debug_assert!(data.len() <= MAX_DATA);
    buf.reserve(HEADER_LEN + data.len());
    buf.put_u8(cmd);
    buf.put_u32(sid);
    buf.put_u16(data.len() as u16);
    buf.put_slice(data);
}

/// One frame, on its own.
pub fn encode(cmd: u8, sid: u32, data: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(HEADER_LEN + data.len());
    put(&mut buf, cmd, sid, data);
    buf
}

/// A waste frame of `len` bytes of zeros.
pub fn waste(len: usize) -> BytesMut {
    let len = len.min(MAX_DATA);
    let mut buf = BytesMut::with_capacity(HEADER_LEN + len);
    buf.put_u8(CMD_WASTE);
    buf.put_u32(0);
    buf.put_u16(len as u16);
    buf.put_bytes(0, len);
    buf
}

/// Settings as `key=value` lines.
pub fn settings(pairs: &[(&str, &str)]) -> Vec<u8> {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let buf = encode(CMD_PSH, 0x0102_0304, b"hello");
        assert_eq!(&buf[..HEADER_LEN], &[2, 1, 2, 3, 4, 0, 5]);
        assert_eq!(&buf[HEADER_LEN..], b"hello");
        let header = Header::decode(buf[..HEADER_LEN].try_into().unwrap());
        assert_eq!(
            header,
            Header {
                cmd: CMD_PSH,
                sid: 0x0102_0304,
                len: 5
            }
        );
    }

    #[test]
    fn control_frames_may_be_empty() {
        let buf = encode(CMD_FIN, 7, &[]);
        assert_eq!(&buf[..], &[3, 0, 0, 0, 7, 0, 0]);
    }

    #[test]
    fn long_data_is_split_across_frames() {
        let data = vec![0xab; MAX_DATA + 10];
        let buf = encode(CMD_PSH, 1, &data);
        assert_eq!(buf.len(), 2 * HEADER_LEN + data.len());
        let first = Header::decode(buf[..HEADER_LEN].try_into().unwrap());
        assert_eq!(first.len as usize, MAX_DATA);
        let at = HEADER_LEN + MAX_DATA;
        let second = Header::decode(buf[at..at + HEADER_LEN].try_into().unwrap());
        assert_eq!((second.cmd, second.sid, second.len), (CMD_PSH, 1, 10));
    }

    #[test]
    fn waste_is_zeros_on_stream_zero() {
        let buf = waste(3);
        assert_eq!(&buf[..], &[0, 0, 0, 0, 0, 0, 3, 0, 0, 0]);
    }

    #[test]
    fn settings_are_lines() {
        assert_eq!(
            settings(&[("v", "2"), ("client", "x/1")]),
            b"v=2\nclient=x/1".to_vec()
        );
    }
}
