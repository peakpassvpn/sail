//! ClientHello parsing and JA4, for checking browser fingerprints against
//! captures.

use sha2::{Digest, Sha256};

pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_PADDING: u16 = 0x0015;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXT_KEY_SHARE: u16 = 0x0033;
pub const EXT_ECH: u16 = 0xfe0d;

/// A ClientHello handshake message, with its 4-byte header.
#[derive(Debug)]
pub struct ClientHello {
    pub session_id: Vec<u8>,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<(u16, Vec<u8>)>,
}

pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn u16s(b: &[u8]) -> Vec<u16> {
    b.chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
    }
    fn u8(&mut self) -> usize {
        self.take(1)[0] as usize
    }
    fn u16(&mut self) -> usize {
        u16::from_be_bytes(self.take(2).try_into().unwrap()) as usize
    }
}

impl ClientHello {
    /// Panics on a malformed message: it is for tests.
    pub fn parse(msg: &[u8]) -> Self {
        assert_eq!(msg[0], 1, "not a ClientHello");
        let mut r = Reader(&msg[4..]);
        r.take(2 + 32);
        let n = r.u8();
        let session_id = r.take(n).to_vec();
        let n = r.u16();
        let ciphers = u16s(r.take(n));
        let n = r.u8();
        r.take(n);
        let n = r.u16();
        let mut e = Reader(r.take(n));
        let mut extensions = Vec::new();
        while !e.0.is_empty() {
            let t = e.u16() as u16;
            let n = e.u16();
            extensions.push((t, e.take(n).to_vec()));
        }
        Self {
            session_id,
            ciphers,
            extensions,
        }
    }

    /// The ClientHello message in the first TLS records of `wire`.
    pub fn from_records(wire: &[u8]) -> Self {
        let mut body = Vec::new();
        let mut r = Reader(wire);
        loop {
            let header = r.take(5);
            assert_eq!(header[0], 0x16, "not a handshake record");
            let n = u16::from_be_bytes([header[3], header[4]]) as usize;
            body.extend_from_slice(r.take(n));
            if body.len() >= 4 {
                let len = 4 + u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
                if body.len() >= len {
                    return Self::parse(&body[..len]);
                }
            }
        }
    }

    pub fn extension(&self, t: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(x, _)| *x == t)
            .map(|(_, v)| v.as_slice())
    }

    pub fn extension_types(&self) -> Vec<u16> {
        self.extensions.iter().map(|(t, _)| *t).collect()
    }

    /// supported_groups, GREASE included.
    pub fn groups(&self) -> Vec<u16> {
        self.extension(EXT_SUPPORTED_GROUPS)
            .map(|v| u16s(&v[2..]))
            .unwrap_or_default()
    }

    /// signature_algorithms, GREASE included.
    pub fn sigalgs(&self) -> Vec<u16> {
        self.extension(EXT_SIGNATURE_ALGORITHMS)
            .map(|v| u16s(&v[2..]))
            .unwrap_or_default()
    }

    pub fn versions(&self) -> Vec<u16> {
        self.extension(EXT_SUPPORTED_VERSIONS)
            .map(|v| u16s(&v[1..]))
            .unwrap_or_default()
    }

    /// The key shares' groups and key sizes.
    pub fn key_shares(&self) -> Vec<(u16, usize)> {
        let Some(v) = self.extension(EXT_KEY_SHARE) else {
            return vec![];
        };
        let mut r = Reader(&v[2..]);
        let mut out = Vec::new();
        while !r.0.is_empty() {
            let g = r.u16() as u16;
            let n = r.u16();
            r.take(n);
            out.push((g, n));
        }
        out
    }

    /// The JA4 fingerprint (FoxIO), for a ClientHello over TCP.
    pub fn ja4(&self) -> String {
        let hex = |v: &[u16]| {
            v.iter()
                .map(|x| format!("{:04x}", x))
                .collect::<Vec<_>>()
                .join(",")
        };
        let hash = |s: &str| {
            let d = Sha256::digest(s.as_bytes());
            d.iter().map(|b| format!("{:02x}", b)).collect::<String>()[..12].to_string()
        };
        let version = match self.versions().into_iter().filter(|v| !is_grease(*v)).max() {
            Some(0x0304) => "13",
            Some(0x0303) => "12",
            other => panic!("unexpected version {:?}", other),
        };
        let sni = if self.extension(EXT_SERVER_NAME).is_some() {
            "d"
        } else {
            "i"
        };
        let mut ciphers: Vec<u16> = self
            .ciphers
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect();
        let mut exts: Vec<u16> = self
            .extension_types()
            .into_iter()
            .filter(|e| !is_grease(*e))
            .collect();
        let alpn = match self.extension(EXT_ALPN) {
            Some(v) => {
                let first = &v[3..3 + v[2] as usize];
                format!("{}{}", first[0] as char, first[first.len() - 1] as char)
            }
            None => "00".to_string(),
        };
        let a = format!(
            "t{}{}{:02}{:02}{}",
            version,
            sni,
            ciphers.len(),
            exts.len(),
            alpn
        );
        ciphers.sort();
        exts.retain(|e| *e != EXT_SERVER_NAME && *e != EXT_ALPN);
        exts.sort();
        let sigalgs: Vec<u16> = self
            .sigalgs()
            .into_iter()
            .filter(|s| !is_grease(*s))
            .collect();
        let mut c = hex(&exts);
        if !sigalgs.is_empty() {
            c = format!("{}_{}", c, hex(&sigalgs));
        }
        format!("{}_{}_{}", a, hash(&hex(&ciphers)), hash(&c))
    }
}

/// Asserts that `ours` is the same ClientHello as the browser's `capture`,
/// up to what the browser randomizes: GREASE values, the order of
/// extensions, the ECH GREASE payload and, of course, the random values.
pub fn assert_same_hello(ours: &ClientHello, capture: &ClientHello) {
    assert_eq!(ours.ja4(), capture.ja4(), "JA4");
    assert_eq!(
        ours.session_id.len(),
        capture.session_id.len(),
        "session ID length"
    );

    let no_grease = |v: &[u16]| {
        v.iter()
            .copied()
            .filter(|x| !is_grease(*x))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        no_grease(&ours.ciphers),
        no_grease(&capture.ciphers),
        "cipher suites"
    );
    assert_eq!(
        is_grease(ours.ciphers[0]),
        is_grease(capture.ciphers[0]),
        "GREASE cipher first"
    );

    let mut ours_ext = no_grease(&ours.extension_types());
    let mut capture_ext = no_grease(&capture.extension_types());
    ours_ext.sort();
    capture_ext.sort();
    assert_eq!(ours_ext, capture_ext, "extensions");
    let ends = |h: &ClientHello| {
        let types = h.extension_types();
        (is_grease(types[0]), is_grease(*types.last().unwrap()))
    };
    assert_eq!(
        ends(ours),
        ends(capture),
        "GREASE extensions first and last"
    );

    // Values GREASE only in position.
    let shape = |v: Vec<u16>| {
        v.into_iter()
            .map(|x| if is_grease(x) { 0x0a0a } else { x })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        shape(ours.groups()),
        shape(capture.groups()),
        "supported_groups"
    );
    assert_eq!(
        shape(ours.sigalgs()),
        shape(capture.sigalgs()),
        "signature_algorithms"
    );
    assert_eq!(
        shape(ours.versions()),
        shape(capture.versions()),
        "supported_versions"
    );
    let shares = |h: &ClientHello| {
        h.key_shares()
            .into_iter()
            .map(|(g, n)| (if is_grease(g) { 0x0a0a } else { g }, n))
            .collect::<Vec<_>>()
    };
    assert_eq!(shares(ours), shares(capture), "key_share");

    // Every other extension carries the same bytes, except the ones that
    // are per connection.
    for t in capture_ext {
        match t {
            EXT_SERVER_NAME
            | EXT_SUPPORTED_GROUPS
            | EXT_SIGNATURE_ALGORITHMS
            | EXT_SUPPORTED_VERSIONS
            | EXT_KEY_SHARE
            | EXT_ECH
            | EXT_PADDING => {}
            t => assert_eq!(
                ours.extension(t),
                capture.extension(t),
                "extension {:#06x}",
                t
            ),
        }
    }
}

pub fn fixture(name: &str) -> ClientHello {
    let path = format!(
        "{}/tests/fixtures/tls/{}.hello",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    ClientHello::parse(&std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path, e)))
}

#[test]
fn test_ja4_of_chrome_capture() {
    // As computed independently from the same capture.
    assert_eq!(
        fixture("chrome-153").ja4(),
        "t13d1517h2_8daaf6152771_cb7bf5808d99"
    );
}
