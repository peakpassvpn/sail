//! XTLS Vision over VLESS: the padded frames both sides write while the
//! proxied traffic may still be a TLS handshake, and the switch to direct
//! copy.

pub struct VisionParser {
    uuid_bytes: [u8; 16],
    v_remaining_cmd: i32,
    v_remaining_content: i32,
    v_remaining_padding: i32,
    v_current_cmd: u8,
    v_buffer: Vec<u8>,
    vless_response_header_parsed: bool,
    pub v_direct_copy_rx: bool,
    pub v_vision_done: bool,
}

impl VisionParser {
    pub fn new(uuid_bytes: [u8; 16]) -> Self {
        Self {
            uuid_bytes,
            v_remaining_cmd: -1,
            v_remaining_content: -1,
            v_remaining_padding: -1,
            v_current_cmd: 0,
            v_buffer: Vec::new(),
            vless_response_header_parsed: false,
            v_direct_copy_rx: false,
            v_vision_done: false,
        }
    }

    /// A parser for what a client sends: no response header comes first.
    pub fn for_server(uuid_bytes: [u8; 16]) -> Self {
        Self {
            vless_response_header_parsed: true,
            ..Self::new(uuid_bytes)
        }
    }

    pub fn parse(&mut self, data: &[u8]) -> Vec<u8> {
        self.v_buffer.extend_from_slice(data);
        let mut to_client = Vec::new();
        let mut offset = 0;

        if !self.vless_response_header_parsed {
            if self.v_buffer.len() >= 2 {
                self.vless_response_header_parsed = true;
                offset += 2; // Skip 0x00 0x00 VLESS response header
            } else {
                return to_client; // Wait for more data
            }
        }

        while offset < self.v_buffer.len() {
            if self.v_direct_copy_rx {
                to_client.extend_from_slice(&self.v_buffer[offset..]);
                offset = self.v_buffer.len();
                break;
            }

            if self.v_remaining_cmd == -1
                && self.v_remaining_content == -1
                && self.v_remaining_padding == -1
            {
                if self.v_buffer.len() - offset >= 21
                    && &self.v_buffer[offset..offset + 16] == self.uuid_bytes.as_slice()
                {
                    offset += 16;
                    self.v_remaining_cmd = 5;
                } else if self.v_buffer.len() - offset < 21 {
                    // Wait for more data to check UUID
                    break;
                } else {
                    // UUID not found and buffer is large enough: Vision parsing is done.
                    self.v_vision_done = true;
                    to_client.extend_from_slice(&self.v_buffer[offset..]);
                    offset = self.v_buffer.len();
                    break;
                }
            }

            while offset < self.v_buffer.len() && self.v_remaining_cmd > 0 {
                let data = self.v_buffer[offset];
                offset += 1;
                match self.v_remaining_cmd {
                    5 => self.v_current_cmd = data,
                    4 => self.v_remaining_content = (data as i32) << 8,
                    3 => self.v_remaining_content |= data as i32,
                    2 => self.v_remaining_padding = (data as i32) << 8,
                    1 => self.v_remaining_padding |= data as i32,
                    _ => {}
                }
                self.v_remaining_cmd -= 1;
            }

            if self.v_remaining_cmd <= 0 && self.v_remaining_content > 0 {
                let available = (self.v_buffer.len() - offset) as i32;
                let consume = if available < self.v_remaining_content {
                    available
                } else {
                    self.v_remaining_content
                };
                if consume > 0 {
                    let consume_usize = consume as usize;
                    to_client.extend_from_slice(&self.v_buffer[offset..offset + consume_usize]);
                    offset += consume_usize;
                    self.v_remaining_content -= consume;
                }
            } else if self.v_remaining_cmd <= 0 && self.v_remaining_padding > 0 {
                let available = (self.v_buffer.len() - offset) as i32;
                let consume = if available < self.v_remaining_padding {
                    available
                } else {
                    self.v_remaining_padding
                };
                if consume > 0 {
                    offset += consume as usize;
                    self.v_remaining_padding -= consume;
                }
            }

            if self.v_remaining_cmd <= 0
                && self.v_remaining_content <= 0
                && self.v_remaining_padding <= 0
            {
                if self.v_current_cmd == 0 {
                    // CommandPaddingContinue
                    self.v_remaining_cmd = 5;
                } else {
                    // cmd=1 (PaddingEnd) or cmd=2 (PaddingDirect)
                    self.v_remaining_cmd = -1;
                    self.v_remaining_content = -1;
                    self.v_remaining_padding = -1;
                    if self.v_current_cmd == 2 {
                        self.v_direct_copy_rx = true;
                    } else {
                        self.v_vision_done = true;
                    }
                    // Drain remaining bytes to client
                    if offset < self.v_buffer.len() {
                        to_client.extend_from_slice(&self.v_buffer[offset..]);
                        offset = self.v_buffer.len();
                    }
                    break;
                }
            }
        }

        if offset < self.v_buffer.len() {
            // Drain consumed bytes
            let remaining = self.v_buffer.len() - offset;
            let mut new_vec = Vec::with_capacity(remaining);
            new_vec.extend_from_slice(&self.v_buffer[offset..]);
            self.v_buffer = new_vec;
        } else {
            self.v_buffer.clear();
        }

        to_client
    }
}

// Vision writer side (client to server), ported from sing-vmess's VisionConn.

const COMMAND_PADDING_CONTINUE: u8 = 0;
const COMMAND_PADDING_END: u8 = 1;
const COMMAND_PADDING_DIRECT: u8 = 2;
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
/// Largest content per padded frame, so frames fit the 8 KB buffers Xray uses.
const MAX_PADDED_CONTENT: usize = 8192 - 21;

/// Watches the first packets in both directions to tell whether the proxied
/// traffic is TLS, which decides how long Vision pads.
struct TlsFilter {
    packets_left: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    remaining_server_hello: usize,
    cipher: u16,
    // Inner TLS 1.3 with a cipher suite Vision accepts: direct copy allowed.
    enable_xtls: bool,
}

impl Default for TlsFilter {
    fn default() -> Self {
        Self {
            packets_left: 8,
            is_tls: false,
            is_tls12_or_above: false,
            remaining_server_hello: 0,
            cipher: 0,
            enable_xtls: false,
        }
    }
}

impl TlsFilter {
    fn filter(&mut self, data: &[u8]) {
        if self.packets_left <= 0 {
            return;
        }
        self.packets_left -= 1;
        if data.len() > 6 {
            if data[..3] == [0x16, 0x03, 0x03] {
                self.is_tls = true;
                if data[5] == 2 {
                    // ServerHello
                    self.is_tls12_or_above = true;
                    self.remaining_server_hello =
                        (u16::from_be_bytes([data[3], data[4]]) as usize) + 5;
                    if data.len() >= 79 && self.remaining_server_hello >= 79 {
                        let session_id_len = data[43] as usize;
                        let at = 43 + session_id_len + 1;
                        if let Some(suite) = data.get(at..at + 2) {
                            self.cipher = u16::from_be_bytes([suite[0], suite[1]]);
                        }
                    }
                }
            } else if data[..2] == [0x16, 0x03] && data[5] == 1 {
                // ClientHello
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = self.remaining_server_hello.min(data.len());
            self.remaining_server_hello -= end;
            let tls13 = data[..end]
                .windows(TLS13_SUPPORTED_VERSIONS.len())
                .any(|w| w == TLS13_SUPPORTED_VERSIONS);
            if tls13 {
                // TLS 1.3 cipher suites except TLS_AES_128_CCM_8_SHA256.
                self.enable_xtls = matches!(self.cipher, 0x1301..=0x1304);
            }
            if tls13 || self.remaining_server_hello == 0 {
                // TLS 1.3 or 1.2 confirmed, nothing more to learn.
                self.packets_left = 0;
            }
        }
    }
}

/// Appends one Vision padding frame:
/// [UUID, first frame only] command, content length (2), padding length (2),
/// content, padding.
fn write_padding_frame(
    out: &mut Vec<u8>,
    content: &[u8],
    command: u8,
    uuid: Option<&[u8; 16]>,
    long_padding: bool,
) {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let padding_len = if content.len() < 900 && long_padding {
        rng.gen_range(0..500) + 900 - content.len()
    } else {
        rng.gen_range(0..256)
    };
    if let Some(uuid) = uuid {
        out.extend_from_slice(uuid);
    }
    out.push(command);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
}

/// How much of `data` goes into the next padded frame: all of it if small,
/// otherwise up to the last TLS application data record start (so that record
/// begins the next frame and can end the padding), or half a buffer.
fn padded_chunk_len(data: &[u8]) -> usize {
    if data.len() < MAX_PADDED_CONTENT {
        return data.len();
    }
    data[..MAX_PADDED_CONTENT]
        .windows(TLS_APPLICATION_DATA_START.len())
        .rposition(|w| w == TLS_APPLICATION_DATA_START)
        .filter(|&i| i > 0)
        .unwrap_or(8192 / 2)
}

use crate::transport::vision::VisionState;
use futures::ready;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct VlessStream<S> {
    stream: S,
    vision_parser: VisionParser,
    plaintext_buffer: Vec<u8>,
    // Bytes of plaintext_buffer already handed to the caller.
    plaintext_pos: usize,
    is_direct_copy: bool,
    vision_state: Option<VisionState>,
    uuid: [u8; 16],
    tls_filter: TlsFilter,
    // Writes are wrapped in Vision padding frames until the padding ends.
    write_padding: bool,
    write_uuid: bool,
    // A padded frame accepted from the caller but not fully written yet.
    pending: Vec<u8>,
    pending_pos: usize,
    // The pending frame carries PaddingDirect: switch writes to the raw
    // transport once it is written.
    direct_after_pending: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> VlessStream<S> {
    pub fn new(stream: S, uuid_bytes: [u8; 16], vision_state: Option<VisionState>) -> Self {
        Self {
            stream,
            vision_parser: VisionParser::new(uuid_bytes),
            plaintext_buffer: Vec::new(),
            plaintext_pos: 0,
            is_direct_copy: false,
            vision_state,
            uuid: uuid_bytes,
            tls_filter: TlsFilter::default(),
            write_padding: true,
            write_uuid: true,
            pending: Vec::new(),
            pending_pos: 0,
            direct_after_pending: false,
        }
    }

    fn poll_write_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            let n = ready!(
                Pin::new(&mut self.stream).poll_write(cx, &self.pending[self.pending_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "write zero byte into writer",
                )));
            }
            self.pending_pos += n;
        }
        if !self.pending.is_empty() {
            // Only the first few writes are padded; don't keep the buffer.
            self.pending = Vec::new();
            self.pending_pos = 0;
        }
        if std::mem::take(&mut self.direct_after_pending) {
            if let Some(state) = &self.vision_state {
                // The TLS layer writes out everything queued so far as TLS
                // records before it starts writing raw.
                state.set_write_direct();
            }
        }
        Poll::Ready(Ok(()))
    }

    /// The server side: it reads the client's frames, which follow the
    /// request directly. The response header goes out beneath it, see
    /// `request::ServerStream`.
    pub fn server(stream: S, uuid_bytes: [u8; 16], vision_state: Option<VisionState>) -> Self {
        Self {
            vision_parser: VisionParser::for_server(uuid_bytes),
            ..Self::new(stream, uuid_bytes, vision_state)
        }
    }

    pub fn get_stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn is_direct_copy(&self) -> bool {
        self.is_direct_copy
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            if this.plaintext_pos < this.plaintext_buffer.len() {
                let pending = &this.plaintext_buffer[this.plaintext_pos..];
                let len = std::cmp::min(buf.remaining(), pending.len());
                buf.put_slice(&pending[..len]);
                this.plaintext_pos += len;
                if this.plaintext_pos == this.plaintext_buffer.len() {
                    this.plaintext_buffer = Vec::new();
                    this.plaintext_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // Once Vision has finished (or switched to direct copy) the parser
            // passes everything through and holds nothing back, so read
            // straight into the caller's buffer.
            if this.vision_parser.v_vision_done || this.vision_parser.v_direct_copy_rx {
                debug_assert!(this.vision_parser.v_buffer.is_empty());
                return Pin::new(&mut this.stream).poll_read(cx, buf);
            }

            let mut temp_buf = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut temp_buf);
            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf.filled().len();
                    if bytes_read == 0 {
                        return Poll::Ready(Ok(()));
                    }

                    let decrypted = this.vision_parser.parse(&temp_buf[..bytes_read]);

                    if this.vision_parser.v_direct_copy_rx && !this.is_direct_copy {
                        tracing::debug!("vision switched to direct copy");
                        this.is_direct_copy = true;
                        if let Some(state) = &this.vision_state {
                            state.set_direct_copy();
                        }
                    } else if this.vision_parser.v_vision_done {
                        // Tell the TLS layer it may read freely again.
                        if let Some(state) = &this.vision_state {
                            state.set_done();
                        }
                    }

                    if decrypted.is_empty() {
                        // Data consumed but no plaintext yielded. Loop around and poll inner again!
                        continue;
                    }
                    this.tls_filter.filter(&decrypted);

                    let len = std::cmp::min(buf.remaining(), decrypted.len());
                    buf.put_slice(&decrypted[..len]);
                    if decrypted.len() > len {
                        this.plaintext_buffer.extend_from_slice(&decrypted[len..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_write_pending(cx))?;
        if !this.write_padding || buf.is_empty() {
            return Pin::new(&mut this.stream).poll_write(cx, buf);
        }

        let n = padded_chunk_len(buf);
        let chunk = &buf[..n];
        this.tls_filter.filter(chunk);
        let filter = &this.tls_filter;
        let command =
            if filter.is_tls && chunk.len() > 6 && chunk.starts_with(&TLS_APPLICATION_DATA_START) {
                // Inner TLS reached application data: stop padding, and with
                // inner TLS 1.3 over a transport that can go raw, switch the
                // uplink to direct copy.
                this.write_padding = false;
                let raw_capable = this
                    .vision_state
                    .as_ref()
                    .is_some_and(|v| v.is_raw_capable());
                if filter.enable_xtls && raw_capable {
                    this.direct_after_pending = true;
                    COMMAND_PADDING_DIRECT
                } else {
                    COMMAND_PADDING_END
                }
            } else if !filter.is_tls12_or_above && filter.packets_left <= 1 {
                // Not TLS 1.2+: stop padding; the rest stays in the outer TLS.
                this.write_padding = false;
                COMMAND_PADDING_END
            } else {
                COMMAND_PADDING_CONTINUE
            };
        let uuid = std::mem::take(&mut this.write_uuid).then_some(&this.uuid);
        write_padding_frame(&mut this.pending, chunk, command, uuid, filter.is_tls);

        // The chunk is taken; push out as much of the frame as the transport
        // accepts now and finish it on the next write or flush.
        if let Poll::Ready(Err(e)) = this.poll_write_pending(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_write_pending(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_write_pending(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const UUID: [u8; 16] = [7; 16];

    fn tls_record(typ: u8, hs_type: u8, len: usize) -> Vec<u8> {
        let mut r = vec![typ, 0x03, 0x03, (len >> 8) as u8, len as u8, hs_type];
        r.resize(5 + len, 0x42);
        r
    }

    #[test]
    fn test_padding_frame_layout() {
        let mut out = vec![];
        write_padding_frame(
            &mut out,
            b"hello",
            COMMAND_PADDING_CONTINUE,
            Some(&UUID),
            true,
        );
        assert_eq!(&out[..16], &UUID);
        assert_eq!(out[16], COMMAND_PADDING_CONTINUE);
        assert_eq!(u16::from_be_bytes([out[17], out[18]]), 5);
        let padding = u16::from_be_bytes([out[19], out[20]]) as usize;
        // Long padding brings short content up to 900..1400 bytes.
        assert!((895..1395).contains(&padding), "{padding}");
        assert_eq!(&out[21..26], b"hello");
        assert_eq!(out.len(), 26 + padding);

        let mut out = vec![];
        write_padding_frame(&mut out, &[1; 2000], COMMAND_PADDING_END, None, true);
        assert_eq!(out[0], COMMAND_PADDING_END);
        assert!(u16::from_be_bytes([out[3], out[4]]) < 256);
    }

    #[test]
    fn test_padded_chunk_len() {
        assert_eq!(padded_chunk_len(&[0; 100]), 100);
        assert_eq!(padded_chunk_len(&[0; 20000]), 4096);
        let mut data = vec![0; 20000];
        data[3000..3003].copy_from_slice(&TLS_APPLICATION_DATA_START);
        assert_eq!(padded_chunk_len(&data), 3000);
        // A record start beyond the frame limit doesn't count.
        let mut data = vec![0; 20000];
        data[9000..9003].copy_from_slice(&TLS_APPLICATION_DATA_START);
        assert_eq!(padded_chunk_len(&data), 4096);
    }

    #[test]
    fn test_tls_filter() {
        let mut f = TlsFilter::default();
        f.filter(&tls_record(0x16, 1, 300));
        assert!(f.is_tls && !f.is_tls12_or_above);
        let mut hello = tls_record(0x16, 2, 120);
        hello[80..86].copy_from_slice(&TLS13_SUPPORTED_VERSIONS);
        f.filter(&hello);
        assert!(f.is_tls12_or_above);
        assert_eq!(f.packets_left, 0);

        let mut f = TlsFilter::default();
        f.filter(b"GET / HTTP/1.1\r\n");
        assert!(!f.is_tls);
        assert_eq!(f.packets_left, 7);
    }

    // Writes through a VlessStream and decodes the wire bytes with the Vision
    // parser, which reads the same frame format the server does.
    async fn round_trip(writes: &[Vec<u8>]) -> (Vec<u8>, VisionParser) {
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let mut stream = VlessStream::new(client, UUID, None);
        for w in writes {
            stream.write_all(w).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        drop(stream);
        let mut wire = vec![0, 0]; // the parser expects a VLESS response header
        server.read_to_end(&mut wire).await.unwrap();
        let mut parser = VisionParser::new(UUID);
        let out = parser.parse(&wire);
        (out, parser)
    }

    #[tokio::test]
    async fn test_vision_write_tls_round_trip() {
        let writes = vec![
            tls_record(0x16, 1, 500),   // ClientHello
            tls_record(0x14, 1, 1),     // ChangeCipherSpec
            tls_record(0x17, 0, 20000), // application data
            b"after padding ends".to_vec(),
        ];
        let (out, parser) = round_trip(&writes).await;
        assert_eq!(out, writes.concat());
        assert!(parser.v_vision_done);
    }

    fn tls13_server_hello(cipher: u16) -> Vec<u8> {
        let mut hello = tls_record(0x16, 2, 120);
        hello[43] = 0; // empty session id
        hello[44..46].copy_from_slice(&cipher.to_be_bytes());
        hello[80..86].copy_from_slice(&TLS13_SUPPORTED_VERSIONS);
        hello
    }

    #[test]
    fn test_tls_filter_enables_xtls_for_tls13_ciphers() {
        let mut f = TlsFilter::default();
        f.filter(&tls13_server_hello(0x1301));
        assert!(f.enable_xtls);
        let mut f = TlsFilter::default();
        f.filter(&tls13_server_hello(0x1305)); // TLS_AES_128_CCM_8_SHA256
        assert!(!f.enable_xtls);
    }

    #[tokio::test]
    async fn test_vision_write_switches_to_direct() {
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let vision = VisionState::default();
        vision.set_raw_capable();
        let mut stream = VlessStream::new(client, UUID, Some(vision.clone()));
        stream.tls_filter.filter(&tls13_server_hello(0x1301));

        stream.write_all(&tls_record(0x16, 1, 300)).await.unwrap();
        assert!(!vision.is_write_direct());
        let app_data = tls_record(0x17, 0, 500);
        stream.write_all(&app_data).await.unwrap();
        // Set only after the PaddingDirect frame went out.
        assert!(vision.is_write_direct());
        stream.write_all(b"raw").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);

        let mut wire = vec![0, 0];
        server.read_to_end(&mut wire).await.unwrap();
        let mut parser = VisionParser::new(UUID);
        let out = parser.parse(&wire);
        assert!(parser.v_direct_copy_rx);
        assert_eq!(
            out,
            [tls_record(0x16, 1, 300), app_data, b"raw".to_vec()].concat()
        );
    }

    #[tokio::test]
    async fn test_vision_write_plain_round_trip() {
        // Not TLS: padding ends on its own after a few packets.
        let writes: Vec<Vec<u8>> = (0..12).map(|i| vec![i as u8; 3000 + i * 1000]).collect();
        let (out, parser) = round_trip(&writes).await;
        assert_eq!(out, writes.concat());
        assert!(parser.v_vision_done);
    }
}
