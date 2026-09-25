//! yamux, as hashicorp/yamux speaks it: frames of `version u8 | type u8 |
//! flags u16 | stream id u32 | length u32`, big-endian. Data frames carry
//! `length` bytes; a window update's length is the window it grants; a
//! ping's is its opaque value. Every stream starts with a 256 KiB window
//! each way.
//!
//! A server acknowledges a stream as soon as it takes it: the reference
//! client closes the whole session if a stream is not acknowledged within
//! its open timeout.
//!
//! See <https://github.com/hashicorp/yamux/blob/master/spec.md>.

use std::io;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::session::{refuse_frame, Flavor, Shared};

const VERSION: u8 = 0;
const TYPE_DATA: u8 = 0;
const TYPE_WINDOW_UPDATE: u8 = 1;
const TYPE_PING: u8 = 2;
const TYPE_GO_AWAY: u8 = 3;

pub const FLAG_SYN: u16 = 1;
pub const FLAG_ACK: u16 = 2;
pub const FLAG_FIN: u16 = 4;
pub const FLAG_RST: u16 = 8;

/// The initial window of every stream.
pub const WINDOW: u32 = 256 << 10;
/// The largest window a stream may be granted, beyond which a peer is
/// taken to be misbehaving.
const MAX_WINDOW: u32 = 16 << 20;
const HEADER: usize = 12;

fn header(buf: &mut BytesMut, kind: u8, flags: u16, id: u32, len: u32) {
    buf.put_u8(VERSION);
    buf.put_u8(kind);
    buf.put_u16(flags);
    buf.put_u32(id);
    buf.put_u32(len);
}

pub fn data(flags: u16, id: u32, data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER + data.len());
    header(&mut buf, TYPE_DATA, flags, id, data.len() as u32);
    buf.put_slice(data);
    buf.freeze()
}

pub fn window_update(flags: u16, id: u32, delta: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER);
    header(&mut buf, TYPE_WINDOW_UPDATE, flags, id, delta);
    buf.freeze()
}

fn ping(flags: u16, opaque: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER);
    header(&mut buf, TYPE_PING, flags, 0, opaque);
    buf.freeze()
}

fn protocol_error(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("yamux: {}", message))
}

pub async fn read_loop<R: AsyncRead + Unpin>(shared: &Arc<Shared>, mut r: R) -> io::Result<()> {
    let mut hdr = [0u8; HEADER];
    loop {
        shared.wait_for_room().await;
        match r.read_exact(&mut hdr).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        if hdr[0] != VERSION {
            return Err(protocol_error(format!("unsupported version {}", hdr[0])));
        }
        let kind = hdr[1];
        let flags = u16::from_be_bytes([hdr[2], hdr[3]]);
        let id = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let len = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        match kind {
            TYPE_DATA | TYPE_WINDOW_UPDATE => {
                let payload = if kind == TYPE_DATA && len > 0 {
                    if len > MAX_WINDOW {
                        return Err(protocol_error(format!("data frame of {} bytes", len)));
                    }
                    let mut buf = BytesMut::zeroed(len as usize);
                    r.read_exact(&mut buf).await?;
                    Some(buf.freeze())
                } else {
                    None
                };
                let mut state = shared.lock();
                if flags & FLAG_SYN != 0 {
                    if shared.accept(&mut state, id) {
                        state.out.push(window_update(FLAG_ACK, id, 0));
                    } else if !state.streams.contains_key(&id) {
                        state.out.push(refuse_frame(Flavor::Yamux, id));
                    }
                    shared.check_out(&mut state)?;
                    shared.wake_writer();
                }
                let Some(slot) = state.streams.get_mut(&id) else {
                    // A stream already gone: what comes for it is dropped.
                    continue;
                };
                if kind == TYPE_WINDOW_UPDATE && len > 0 {
                    slot.send_window = slot
                        .send_window
                        .checked_add(len)
                        .filter(|w| *w <= MAX_WINDOW)
                        .ok_or_else(|| protocol_error("window overflows".to_string()))?;
                    slot.wake();
                }
                if let Some(payload) = payload {
                    if payload.len() as u32 > slot.recv_window {
                        return Err(protocol_error(format!(
                            "stream {} sent past its window",
                            id
                        )));
                    }
                    slot.recv_window -= payload.len() as u32;
                    shared.deliver(&mut state, id, payload);
                }
                if flags & (FLAG_FIN | FLAG_RST) != 0 {
                    if let Some(slot) = state.streams.get_mut(&id) {
                        if flags & FLAG_FIN != 0 {
                            slot.remote_fin = true;
                        }
                        if flags & FLAG_RST != 0 {
                            slot.reset = true;
                        }
                        slot.wake();
                    }
                }
            }
            TYPE_PING => {
                if flags & FLAG_SYN != 0 {
                    let mut state = shared.lock();
                    state.out.push(ping(FLAG_ACK, len));
                    shared.check_out(&mut state)?;
                    drop(state);
                    shared.wake_writer();
                }
            }
            TYPE_GO_AWAY => {
                shared.lock().going_away = true;
            }
            kind => return Err(protocol_error(format!("unknown frame type {}", kind))),
        }
    }
}
