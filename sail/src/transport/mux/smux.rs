//! smux, version 1, as sing-mux configures it (keepalive off): frames of
//! `version u8 | cmd u8 | length u16 | stream id u32`, little-endian, then
//! `length` bytes of data. There is no flow control per stream, and no
//! half-close: a FIN ends a stream both ways.
//!
//! See <https://github.com/SagerNet/smux>.

use std::io;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::session::{refuse_frame, Flavor, Shared};

const VERSION: u8 = 1;
pub const CMD_SYN: u8 = 0;
pub const CMD_FIN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_NOP: u8 = 3;
const HEADER: usize = 8;

pub fn frame(cmd: u8, id: u32, data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER + data.len());
    buf.put_u8(VERSION);
    buf.put_u8(cmd);
    buf.put_u16_le(data.len() as u16);
    buf.put_u32_le(id);
    buf.put_slice(data);
    buf.freeze()
}

pub async fn read_loop<R: AsyncRead + Unpin>(shared: &Arc<Shared>, mut r: R) -> io::Result<()> {
    let mut header = [0u8; HEADER];
    loop {
        shared.wait_for_room().await;
        match r.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        if header[0] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("smux: unsupported version {}", header[0]),
            ));
        }
        let len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        match header[1] {
            CMD_NOP => {}
            CMD_SYN => {
                let mut state = shared.lock();
                if !state.streams.contains_key(&id) && !shared.accept(&mut state, id) {
                    state.out.push(refuse_frame(Flavor::Smux, id));
                    shared.check_out(&mut state)?;
                    drop(state);
                    shared.wake_writer();
                }
            }
            CMD_FIN => {
                let mut state = shared.lock();
                if let Some(slot) = state.streams.get_mut(&id) {
                    slot.remote_fin = true;
                    slot.wake();
                }
            }
            CMD_PSH => {
                if len == 0 {
                    continue;
                }
                let mut data = BytesMut::zeroed(len);
                r.read_exact(&mut data).await?;
                let mut state = shared.lock();
                shared.deliver(&mut state, id, data.freeze());
            }
            cmd => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("smux: unknown command {}", cmd),
                ))
            }
        }
    }
}
