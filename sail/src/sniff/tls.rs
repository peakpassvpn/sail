//! The server name of a TLS ClientHello, in TLS records over a stream or
//! in QUIC's CRYPTO frames.

use super::{be_u16, be_u24, is_domain_name, Sniff, MAX_SNIFF_LEN};

const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
/// The largest record plaintext TLS allows.
const MAX_RECORD: usize = 1 << 14;
/// The largest ClientHello looked into. Chrome's, with its post-quantum
/// key share, is under 2 KB.
const MAX_HELLO: usize = MAX_SNIFF_LEN;

/// The first bytes of a TLS connection: a ClientHello, which may span
/// several handshake records.
pub fn sniff(buf: &[u8]) -> Sniff {
    let mut rest = buf;
    // The handshake bytes of the records so far. A ClientHello in one
    // record, the usual case, is read in place.
    let mut joined = Vec::new();
    let mut first: &[u8] = &[];
    loop {
        if rest.is_empty() {
            return Sniff::NeedMore;
        }
        if rest[0] != HANDSHAKE {
            return Sniff::NotMatch;
        }
        // The record version is 3.x; the minor is 1 in all but the oldest.
        match rest.get(1..3) {
            Some([3, minor]) if *minor <= 4 => {}
            Some(_) => return Sniff::NotMatch,
            None if rest.get(1).is_some_and(|major| *major != 3) => return Sniff::NotMatch,
            None => return Sniff::NeedMore,
        }
        let Some(len) = rest.get(3..).and_then(be_u16) else {
            return Sniff::NeedMore;
        };
        let len = len as usize;
        if len == 0 || len > MAX_RECORD {
            return Sniff::NotMatch;
        }
        let body = &rest[5.min(rest.len())..];
        let whole = body.len() >= len;
        let body = &body[..len.min(body.len())];
        let handshake = if first.is_empty() && joined.is_empty() {
            first = body;
            first
        } else {
            if joined.is_empty() {
                joined.extend_from_slice(first);
            }
            joined.extend_from_slice(body);
            &joined[..]
        };
        match client_hello(handshake) {
            Sniff::NeedMore if whole => rest = &rest[5 + len..],
            outcome => return outcome,
        }
    }
}

/// The handshake bytes a client sends first, as QUIC's CRYPTO frames carry
/// them: a ClientHello, whole or in part.
pub fn client_hello(handshake: &[u8]) -> Sniff {
    match handshake.first() {
        None => return Sniff::NeedMore,
        Some(&CLIENT_HELLO) => {}
        Some(_) => return Sniff::NotMatch,
    }
    let Some(len) = be_u24(&handshake[1..]) else {
        return Sniff::NeedMore;
    };
    // The smallest ClientHello has a version, a random, a session ID, one
    // cipher suite and one compression method.
    if !(2 + 32 + 1 + 4 + 2..=MAX_HELLO).contains(&len) {
        return Sniff::NotMatch;
    }
    match handshake.get(4..4 + len) {
        None => Sniff::NeedMore,
        Some(body) => match server_name(body) {
            Some(name) => Sniff::Found(name),
            None => Sniff::NotMatch,
        },
    }
}

/// Reads `n` bytes off the front of `buf`.
fn take<'a>(buf: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if buf.len() < n {
        return None;
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Some(head)
}

/// Reads a vector with a `u8` length off the front of `buf`.
fn take_u8_vec<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = *take(buf, 1)?.first()? as usize;
    take(buf, len)
}

/// Reads a vector with a `u16` length off the front of `buf`.
fn take_u16_vec<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = be_u16(take(buf, 2)?)? as usize;
    take(buf, len)
}

/// The server name of a ClientHello body, `None` when the body is not one,
/// and `Some(None)` when it names none, or not a domain.
fn server_name(mut body: &[u8]) -> Option<Option<String>> {
    let version = take(&mut body, 2)?;
    if version[0] != 3 {
        return None;
    }
    take(&mut body, 32)?;
    if take_u8_vec(&mut body)?.len() > 32 {
        return None;
    }
    let suites = take_u16_vec(&mut body)?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return None;
    }
    if take_u8_vec(&mut body)?.is_empty() {
        return None;
    }
    if body.is_empty() {
        return Some(None);
    }
    let mut extensions = take_u16_vec(&mut body)?;
    if !body.is_empty() {
        return None;
    }
    let mut name = None;
    while !extensions.is_empty() {
        let kind = be_u16(take(&mut extensions, 2)?)?;
        let mut data = take_u16_vec(&mut extensions)?;
        // server_name, of which there is one.
        if kind != 0 || name.is_some() {
            continue;
        }
        let mut list = take_u16_vec(&mut data)?;
        if !data.is_empty() {
            return None;
        }
        while !list.is_empty() {
            let kind = *take(&mut list, 1)?.first()?;
            let host = take_u16_vec(&mut list)?;
            // host_name
            if kind == 0 && name.is_none() {
                name = Some(host);
            }
        }
    }
    Some(
        name.and_then(|n| std::str::from_utf8(n).ok())
            .filter(|n| is_domain_name(n))
            .map(String::from),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A ClientHello handshake message naming `host`.
    pub(crate) fn hello(host: &str) -> Vec<u8> {
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        // An extension before it, to be stepped over.
        let mut extensions = vec![0, 0x0b, 0, 2, 1, 0];
        extensions.extend_from_slice(&[0, 0]);
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.push(32);
        body.extend_from_slice(&[9; 32]);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![CLIENT_HELLO, 0];
        handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&body);
        handshake
    }

    /// `handshake` in records of at most `size` bytes.
    fn records(handshake: &[u8], size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in handshake.chunks(size) {
            out.extend_from_slice(&[HANDSHAKE, 3, 1]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    fn found(name: &str) -> Sniff {
        Sniff::Found(Some(name.to_string()))
    }

    #[test]
    fn the_server_name_of_a_client_hello() {
        let records = records(&hello("example.com"), MAX_RECORD);
        assert_eq!(sniff(&records), found("example.com"));
        for len in 0..records.len() {
            assert_eq!(sniff(&records[..len]), Sniff::NeedMore, "{}", len);
        }
    }

    #[test]
    fn a_client_hello_across_records() {
        let hello = hello("www.example.com");
        for size in [1, 2, 3, 4, 5, 17, 100] {
            let records = records(&hello, size);
            assert_eq!(sniff(&records), found("www.example.com"), "{}", size);
            assert_eq!(sniff(&records[..records.len() - 1]), Sniff::NeedMore);
        }
    }

    #[test]
    fn a_client_hello_without_a_domain_is_still_tls() {
        assert_eq!(sniff(&records(&hello("1.2.3.4"), 4096)), Sniff::Found(None));
        let mut no_extensions = hello("example.com");
        let body_len = 2 + 32 + 33 + 4 + 2;
        no_extensions.truncate(4 + body_len);
        no_extensions[1..4].copy_from_slice(&(body_len as u32).to_be_bytes()[1..]);
        assert_eq!(client_hello(&no_extensions), Sniff::Found(None));
    }

    #[test]
    fn what_is_not_a_client_hello() {
        assert_eq!(sniff(b"GET / HTTP/1.1\r\n"), Sniff::NotMatch);
        assert_eq!(sniff(&[HANDSHAKE, 2]), Sniff::NotMatch);
        assert_eq!(sniff(&[HANDSHAKE, 3, 3, 0, 0]), Sniff::NotMatch);
        // A ServerHello.
        let mut server_hello = hello("example.com");
        server_hello[0] = 2;
        assert_eq!(sniff(&records(&server_hello, 4096)), Sniff::NotMatch);
        // A length past the body.
        let mut long = hello("example.com");
        long[3] = long[3].wrapping_add(1);
        assert_eq!(client_hello(&long), Sniff::NeedMore);
        long.push(0);
        assert_eq!(client_hello(&long), Sniff::NotMatch);
    }

    #[test]
    fn captured_client_hellos() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");
        let mut n = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "hello") {
                let hello = std::fs::read(&path).unwrap();
                assert_eq!(client_hello(&hello), found("localhost"), "{:?}", path);
                assert_eq!(sniff(&records(&hello, MAX_RECORD)), found("localhost"));
                assert_eq!(sniff(&records(&hello, 512)), found("localhost"));
                n += 1;
            }
        }
        assert!(n >= 6);
    }

    #[test]
    fn no_input_panics() {
        let hello = records(&hello("example.com"), 40);
        for i in 0..hello.len() {
            for byte in [0x00, 0x01, 0x03, 0x16, 0x7f, 0x80, 0xff] {
                let mut bad = hello.clone();
                bad[i] = byte;
                let _ = sniff(&bad);
                let _ = sniff(&bad[..i]);
                let _ = client_hello(&bad[5..]);
            }
        }
    }
}
