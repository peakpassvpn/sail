//! smux, version 1, as sing-mux configures it (keepalive off): frames of
//! `version u8 | cmd u8 | length u16 | stream id u32`, little-endian, then
//! `length` bytes of data. There is no flow control per stream, and no
//! half-close: a FIN ends a stream both ways.
//!
//! See <https://github.com/SagerNet/smux>.

use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::transport::muxcore::{Closing, Codec, Decoder, Event, Flow, Framing};

const VERSION: u8 = 1;
const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const HEADER: usize = 8;
/// The largest data frame sent.
const MAX_FRAME_DATA: usize = 32 << 10;

fn frame(cmd: u8, id: u32, data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER + data.len());
    buf.put_u8(VERSION);
    buf.put_u8(cmd);
    buf.put_u16_le(data.len() as u16);
    buf.put_u32_le(id);
    buf.put_slice(data);
    buf.freeze()
}

pub struct Smux;

impl Codec for Smux {
    fn name(&self) -> &'static str {
        "smux"
    }

    fn flow(&self) -> Flow {
        Flow::Pause
    }

    fn closing(&self) -> Closing {
        Closing::OnDrop
    }

    fn max_data(&self) -> usize {
        MAX_FRAME_DATA
    }

    /// smux counts from 1 on a client and from 0 on a server, and opens
    /// with the next.
    fn first_id(&self, server: bool) -> u32 {
        if server {
            2
        } else {
            3
        }
    }

    fn open(&self, id: u32) -> Bytes {
        frame(CMD_SYN, id, &[])
    }

    fn refuse(&self, id: u32) -> Bytes {
        frame(CMD_FIN, id, &[])
    }

    fn data(&self, id: u32, data: &[u8]) -> Bytes {
        frame(CMD_PSH, id, data)
    }

    fn fin(&self, id: u32) -> Bytes {
        frame(CMD_FIN, id, &[])
    }

    fn reset(&self, id: u32) -> Bytes {
        frame(CMD_FIN, id, &[])
    }

    fn decoder(&self, _server: bool) -> Box<dyn Decoder> {
        Box::<SmuxDecoder>::default()
    }
}

#[derive(Default)]
struct SmuxDecoder {
    framing: Framing,
}

impl Decoder for SmuxDecoder {
    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Event>> {
        loop {
            if let Some(next) = self.framing.next(buf) {
                return Ok(next);
            }
            if buf.len() < HEADER {
                return Ok(None);
            }
            if buf[0] != VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("smux: unsupported version {}", buf[0]),
                ));
            }
            let cmd = buf[1];
            let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
            let id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
            buf.advance(HEADER);
            match cmd {
                CMD_NOP => {}
                CMD_SYN => self.framing.frame(&[Event::Open(id)], None, &[]),
                CMD_FIN => self.framing.frame(&[Event::Fin(id)], None, &[]),
                CMD_PSH => self.framing.frame(&[], Some((id, len)), &[]),
                cmd => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("smux: unknown command {}", cmd),
                    ))
                }
            }
        }
    }
}
