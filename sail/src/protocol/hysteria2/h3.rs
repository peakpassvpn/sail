//! The little of HTTP/3 (RFC 9114) and QPACK (RFC 9204) Hysteria2 needs:
//! one request and its response on a bidirectional stream, and the control
//! streams each side must keep open.
//!
//! Not the `h3` crate: a Hysteria2 server tells a proxied TCP stream from
//! an HTTP request by the frame type the stream starts with (0x401), and
//! `h3` owns every bidirectional stream it accepts, with no way to hand one
//! back. Doing it by hand keeps both ends in one place.
//!
//! QPACK runs without its dynamic table: we announce a capacity of zero, the
//! default, so a peer may only use the static table and literals. What we
//! send is the same.

use std::collections::HashMap;
use std::io;
use std::sync::OnceLock;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::h3_tables::{HUFFMAN_CODES, STATIC_TABLE};
use super::proto::{put_varint, read_varint};

pub const FRAME_DATA: u64 = 0x00;
pub const FRAME_HEADERS: u64 = 0x01;
pub const FRAME_SETTINGS: u64 = 0x04;

pub const STREAM_CONTROL: u64 = 0x00;

/// The largest field section we read.
pub const MAX_FIELD_SECTION: u64 = 64 * 1024;
/// The most bytes of frames we skip, unknown or not wanted, on a request
/// stream before its HEADERS.
const MAX_SKIPPED: u64 = 64 * 1024;

/// An HTTP field, its name in lowercase as HTTP/3 wants it.
pub type Field = (String, String);

/// The first bytes of a control stream: its type and an empty SETTINGS,
/// which leaves every setting at its default, the QPACK table at zero among
/// them.
pub fn control_stream_preface() -> BytesMut {
    let mut buf = BytesMut::new();
    put_varint(&mut buf, STREAM_CONTROL);
    put_varint(&mut buf, FRAME_SETTINGS);
    put_varint(&mut buf, 0);
    buf
}

/// A HEADERS frame carrying `fields`.
pub fn headers_frame(fields: &[(&str, &str)]) -> BytesMut {
    let section = encode_field_section(fields);
    let mut buf = BytesMut::with_capacity(section.len() + 16);
    put_varint(&mut buf, FRAME_HEADERS);
    put_varint(&mut buf, section.len() as u64);
    buf.put_slice(&section);
    buf
}

/// Writes a HEADERS frame carrying `fields`.
pub async fn write_headers<W: AsyncWrite + Unpin>(
    w: &mut W,
    fields: &[(&str, &str)],
) -> io::Result<()> {
    w.write_all(&headers_frame(fields)).await
}

/// Reads frames until a HEADERS frame and returns its fields. `first_type`
/// is the type of the first frame when the caller has read it already.
pub async fn read_headers<R: AsyncRead + Unpin>(
    r: &mut R,
    mut first_type: Option<u64>,
) -> io::Result<Vec<Field>> {
    let mut skipped = 0u64;
    loop {
        let ty = match first_type.take() {
            Some(ty) => ty,
            None => read_varint(r).await?,
        };
        let len = read_varint(r).await?;
        match ty {
            FRAME_HEADERS => {
                if len > MAX_FIELD_SECTION {
                    return Err(invalid("field section too large"));
                }
                let mut section = vec![0; len as usize];
                r.read_exact(&mut section).await?;
                return decode_field_section(&section);
            }
            FRAME_DATA => return Err(invalid("DATA before HEADERS")),
            _ => {
                // Unknown and reserved frames are to be ignored.
                skipped = skipped.saturating_add(len);
                if skipped > MAX_SKIPPED {
                    return Err(invalid("too many frames before HEADERS"));
                }
                let copied =
                    tokio::io::copy(&mut (&mut *r).take(len), &mut tokio::io::sink()).await?;
                if copied != len {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
        }
    }
}

/// Reads the DATA frames that follow the HEADERS of a request or response,
/// up to `max` bytes of body, until the stream ends.
pub async fn read_body<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let ty = match read_varint(r).await {
            Ok(ty) => ty,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(body),
            Err(e) => return Err(e),
        };
        let len = read_varint(r).await?;
        if ty == FRAME_DATA {
            if body.len() as u64 + len > max as u64 {
                return Err(invalid("body too large"));
            }
            let start = body.len();
            body.resize(start + len as usize, 0);
            r.read_exact(&mut body[start..]).await?;
        } else {
            // Trailers and unknown frames.
            if len > MAX_FIELD_SECTION {
                return Err(invalid("frame too large"));
            }
            let copied = tokio::io::copy(&mut (&mut *r).take(len), &mut tokio::io::sink()).await?;
            if copied != len {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }
}

/// A DATA frame's header, for a body of `len` bytes.
pub fn data_frame_header(len: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(16);
    put_varint(&mut buf, FRAME_DATA);
    put_varint(&mut buf, len as u64);
    buf
}

/// The value of the field `name`, if there is one.
pub fn field<'a>(fields: &'a [Field], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("http/3: {}", msg))
}

// ---------------------------------------------------------------------------
// QPACK
// ---------------------------------------------------------------------------

/// Encodes `fields` as a field section: a static table reference where one
/// fits, a literal otherwise, never Huffman-coded.
pub fn encode_field_section(fields: &[(&str, &str)]) -> BytesMut {
    let mut buf = BytesMut::new();
    // Required Insert Count and Base: no dynamic table.
    buf.put_u8(0);
    buf.put_u8(0);
    for (name, value) in fields {
        let exact = STATIC_TABLE
            .iter()
            .position(|(n, v)| n == name && v == value);
        let named = STATIC_TABLE.iter().position(|(n, _)| n == name);
        match (exact, named) {
            (Some(index), _) => {
                // Indexed field line, static: 1T + index.
                put_prefixed(&mut buf, 0xc0, 6, index as u64);
            }
            (None, Some(index)) => {
                // Literal with a static name reference: 01NT + index.
                put_prefixed(&mut buf, 0x50, 4, index as u64);
                put_prefixed(&mut buf, 0x00, 7, value.len() as u64);
                buf.put_slice(value.as_bytes());
            }
            (None, None) => {
                // Literal with a literal name: 001NH + name length.
                put_prefixed(&mut buf, 0x20, 3, name.len() as u64);
                buf.put_slice(name.as_bytes());
                put_prefixed(&mut buf, 0x00, 7, value.len() as u64);
                buf.put_slice(value.as_bytes());
            }
        }
    }
    buf
}

/// Decodes a field section that refers to no dynamic table.
pub fn decode_field_section(mut buf: &[u8]) -> io::Result<Vec<Field>> {
    let required_insert_count = get_prefixed(&mut buf, 8)?;
    if required_insert_count != 0 {
        return Err(invalid("field section refers to the dynamic table"));
    }
    // The Base means nothing without a dynamic table.
    get_prefixed(&mut buf, 7)?;
    let mut fields = Vec::new();
    while let Some(&first) = buf.first() {
        if first & 0x80 != 0 {
            // Indexed field line.
            if first & 0x40 == 0 {
                return Err(invalid("dynamic table reference"));
            }
            let (name, value) = static_entry(get_prefixed(&mut buf, 6)?)?;
            fields.push((name.to_string(), value.to_string()));
        } else if first & 0x40 != 0 {
            // Literal with a name reference.
            if first & 0x10 == 0 {
                return Err(invalid("dynamic table reference"));
            }
            let (name, _) = static_entry(get_prefixed(&mut buf, 4)?)?;
            let value = get_string(&mut buf, 7)?;
            fields.push((name.to_string(), value));
        } else if first & 0x20 != 0 {
            // Literal with a literal name.
            let name = get_string(&mut buf, 3)?.to_ascii_lowercase();
            let value = get_string(&mut buf, 7)?;
            fields.push((name, value));
        } else {
            // The post-base forms, both about the dynamic table.
            return Err(invalid("dynamic table reference"));
        }
    }
    Ok(fields)
}

fn static_entry(index: u64) -> io::Result<(&'static str, &'static str)> {
    STATIC_TABLE
        .get(index as usize)
        .copied()
        .ok_or_else(|| invalid("static table index out of range"))
}

/// Writes `v` as an integer with an `n`-bit prefix, the bits above the
/// prefix in the first byte being `flags`.
fn put_prefixed(buf: &mut BytesMut, flags: u8, n: u8, mut v: u64) {
    let max = (1u64 << n) - 1;
    if v < max {
        buf.put_u8(flags | v as u8);
        return;
    }
    buf.put_u8(flags | max as u8);
    v -= max;
    while v >= 0x80 {
        buf.put_u8((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    buf.put_u8(v as u8);
}

/// Reads an integer with an `n`-bit prefix, taking it off the front of
/// `buf`.
fn get_prefixed(buf: &mut &[u8], n: u8) -> io::Result<u64> {
    let short = || invalid("truncated field section");
    let (&first, rest) = buf.split_first().ok_or_else(short)?;
    *buf = rest;
    let max = (1u64 << n) - 1;
    let mut v = first as u64 & max;
    if v < max {
        return Ok(v);
    }
    let mut shift = 0;
    loop {
        let (&b, rest) = buf.split_first().ok_or_else(short)?;
        *buf = rest;
        if shift > 56 {
            return Err(invalid("integer too large"));
        }
        v += ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
}

/// Reads a string literal whose length has an `n`-bit prefix, the Huffman
/// flag being the bit just above it.
fn get_string(buf: &mut &[u8], n: u8) -> io::Result<String> {
    let huffman = buf.first().is_some_and(|b| b & (1 << n) != 0);
    let len = get_prefixed(buf, n)?;
    if len > buf.len() as u64 {
        return Err(invalid("truncated field section"));
    }
    let (raw, rest) = buf.split_at(len as usize);
    *buf = rest;
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    String::from_utf8(bytes).map_err(|_| invalid("field not UTF-8"))
}

/// The Huffman code as a map from (length, code) to symbol.
fn huffman_table() -> &'static HashMap<(u8, u32), u16> {
    static TABLE: OnceLock<HashMap<(u8, u32), u16>> = OnceLock::new();
    TABLE.get_or_init(|| {
        HUFFMAN_CODES
            .iter()
            .enumerate()
            .map(|(sym, (code, len))| ((*len, *code), sym as u16))
            .collect()
    })
}

/// Decodes a Huffman-coded string (RFC 7541, section 5.2).
pub fn huffman_decode(input: &[u8]) -> io::Result<Vec<u8>> {
    let table = huffman_table();
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let mut code = 0u32;
    let mut len = 0u8;
    for byte in input {
        for shift in (0..8).rev() {
            code = (code << 1) | ((byte >> shift) & 1) as u32;
            len += 1;
            if let Some(&sym) = table.get(&(len, code)) {
                if sym == 256 {
                    return Err(invalid("EOS in a Huffman string"));
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            } else if len >= 30 {
                return Err(invalid("invalid Huffman code"));
            }
        }
    }
    // What is left must be padding: fewer than 8 bits, all ones.
    if len >= 8 || code != (1 << len) - 1 {
        return Err(invalid("invalid Huffman padding"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(list: &[(&str, &str)]) -> Vec<Field> {
        list.iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn huffman_decodes_the_rfc_examples() {
        // RFC 7541, appendix C.4.
        let www = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(huffman_decode(&www).unwrap(), b"www.example.com");
        let no_cache = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        assert_eq!(huffman_decode(&no_cache).unwrap(), b"no-cache");
        let custom_key = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
        assert_eq!(huffman_decode(&custom_key).unwrap(), b"custom-key");
    }

    #[test]
    fn huffman_rejects_bad_padding() {
        // 'a' is 00011: padded with ones it decodes, with zeroes it does not.
        assert_eq!(huffman_decode(&[0x1f]).unwrap(), b"a");
        assert!(huffman_decode(&[0x18]).is_err());
        // A whole byte of padding.
        assert!(huffman_decode(&[0x1f, 0xff]).is_err());
    }

    #[test]
    fn a_field_section_round_trips() {
        let list = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "hysteria"),
            (":path", "/auth"),
            ("hysteria-auth", "secret"),
            ("hysteria-cc-rx", "0"),
            ("content-length", "0"),
        ];
        let section = encode_field_section(&list);
        assert_eq!(decode_field_section(&section).unwrap(), fields(&list));
    }

    #[test]
    fn long_values_use_multi_byte_lengths() {
        let long = "x".repeat(3000);
        let list = [("hysteria-padding", long.as_str())];
        let section = encode_field_section(&list);
        assert_eq!(decode_field_section(&section).unwrap(), fields(&list));
    }

    #[test]
    fn a_huffman_coded_field_section_decodes() {
        // :authority (static 0) with "www.example.com" Huffman-coded, then
        // a literal name "custom-key" Huffman-coded, value plain.
        let mut section = vec![0x00, 0x00, 0x50, 0x80 | 12];
        section.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        // 001 N=0 H=1 + 3-bit length 7 (prefix full), then 8 - 7 = 1.
        section.extend_from_slice(&[0x28 | 0x07, 0x01]);
        section.extend_from_slice(&[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f]);
        section.extend_from_slice(&[0x02, b'o', b'k']);
        assert_eq!(
            decode_field_section(&section).unwrap(),
            fields(&[(":authority", "www.example.com"), ("custom-key", "ok")])
        );
    }

    #[test]
    fn dynamic_table_references_are_refused() {
        assert!(decode_field_section(&[0x01, 0x00]).is_err());
        assert!(decode_field_section(&[0x00, 0x00, 0x80]).is_err());
        assert!(decode_field_section(&[0x00, 0x00, 0x10]).is_err());
        assert!(decode_field_section(&[0x00, 0x00, 0xff, 0x7f]).is_err());
    }

    #[tokio::test]
    async fn headers_are_read_past_unknown_frames() {
        let mut wire = BytesMut::new();
        put_varint(&mut wire, 0x21); // reserved
        put_varint(&mut wire, 3);
        wire.put_slice(b"abc");
        wire.put_slice(&headers_frame(&[(":status", "233")]));
        wire.put_slice(&data_frame_header(2));
        wire.put_slice(b"hi");
        let mut r = &wire[..];
        let got = read_headers(&mut r, None).await.unwrap();
        assert_eq!(field(&got, ":status"), Some("233"));
        assert_eq!(read_body(&mut r, 10).await.unwrap(), b"hi");
    }

    #[tokio::test]
    async fn data_before_headers_is_an_error() {
        let wire = data_frame_header(0);
        assert!(read_headers(&mut &wire[..], None).await.is_err());
    }
}
