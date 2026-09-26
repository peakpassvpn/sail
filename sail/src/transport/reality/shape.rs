//! Giving an authenticated client's server flight the shape of the
//! handshake server's, as Xray's REALITY server does.
//!
//! The handshake server's reply to the same ClientHello is read first:
//! its ServerHello (which must be TLS 1.3), its ChangeCipherSpec and the
//! lengths of the encrypted records that follow. BoringSSL is then told to
//! pick the same cipher suite and key exchange group, and what it writes
//! passes through a [`Shaper`]: the ServerHello and ChangeCipherSpec as
//! they are, and the encrypted flight -- EncryptedExtensions to Finished,
//! sealed under the server handshake traffic key -- opened, then sealed
//! again into records of exactly the handshake server's lengths, padded
//! with zeros as TLS 1.3 allows. The key comes from BoringSSL's key log;
//! nothing BoringSSL writes later uses it, so re-framing that flight leaves
//! every later record, and its sequence number, as BoringSSL made it.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use btls::aead::{AeadCtx, Algorithm};
use btls::hash::MessageDigest;
use btls::hkdf::HkdfSuite;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) const X25519: u16 = 0x001d;
pub(super) const X25519_MLKEM768: u16 = 0x11ec;
const MLKEM768_CIPHERTEXT: usize = 1088;

const HANDSHAKE: u8 = 0x16;
const CHANGE_CIPHER_SPEC: u8 = 0x14;
const APPLICATION_DATA: u8 = 0x17;
const ALERT: u8 = 0x15;
const HEADER: usize = 5;
/// The tag of all three TLS 1.3 AEADs.
const TAG: usize = 16;
/// The largest record body TLS 1.3 allows.
const MAX_RECORD_BODY: usize = 16384 + 256;
/// A first encrypted record longer than this carries the whole flight, not
/// EncryptedExtensions alone: Xray's rule.
const WHOLE_FLIGHT: usize = 512;
/// EncryptedExtensions, Certificate, CertificateVerify, Finished.
const FLIGHT_MESSAGES: usize = 4;
/// The most of the handshake server's reply, or of our own flight, held.
pub(super) const MAX_FLIGHT: usize = 64 * 1024;

/// The random of a HelloRetryRequest.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// What the handshake server's first flight to a ClientHello looked like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TargetFlight {
    pub cipher_suite: u16,
    pub group: u16,
    /// Of each encrypted record, header included.
    pub records: Vec<usize>,
}

/// How far the handshake server's reply has been read.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reply {
    /// Not enough of it yet.
    Incomplete,
    Tls13(TargetFlight),
    /// Its first record is not a TLS 1.3 ServerHello REALITY can imitate:
    /// the client, ours or not, is better off talking to it.
    NotTls13,
    /// A TLS 1.3 ServerHello followed by something no TLS 1.3 server sends.
    Malformed,
}

/// The ServerHello's cipher suite and key share group, if it is a TLS 1.3
/// ServerHello (not a HelloRetryRequest) with a key share REALITY clients
/// offer. `message` is the handshake message, header included.
pub(super) fn parse_server_hello(message: &[u8]) -> Option<(u16, u16)> {
    let mut r = Reader::new(message);
    if r.u8()? != 2 {
        return None;
    }
    let len = r.u24()?;
    if len + 4 != message.len() || r.u16()? != 0x0303 || r.take(32)? == HRR_RANDOM {
        return None;
    }
    r.vec8()?; // session ID
    let cipher_suite = r.u16()?;
    if !(0x1301..=0x1303).contains(&cipher_suite) || r.u8()? != 0 {
        return None;
    }
    let mut e = Reader::new(r.vec16()?);
    if r.pos != message.len() {
        return None;
    }
    let (mut tls13, mut group) = (false, None);
    while e.pos < e.buf.len() {
        let typ = e.u16()?;
        let mut d = Reader::new(e.vec16()?);
        match typ {
            43 => tls13 = d.u16()? == 0x0304 && d.pos == d.buf.len(),
            51 => {
                let g = d.u16()?;
                let share = d.vec16()?;
                let ok = match g {
                    X25519 => share.len() == 32,
                    X25519_MLKEM768 => share.len() == MLKEM768_CIPHERTEXT + 32,
                    _ => false,
                };
                if !ok || d.pos != d.buf.len() {
                    return None;
                }
                group = Some(g);
            }
            _ => {}
        }
    }
    tls13.then_some((cipher_suite, group?))
}

/// Reads the handshake server's reply as far as it has come, as Xray does:
/// a TLS 1.3 ServerHello, a ChangeCipherSpec, then either one encrypted
/// record of more than 512 bytes, the whole flight, or four records, one
/// per message. With `quiet`, the server has gone quiet: fewer than four
/// complete records are taken as the flight, where Xray waits on.
pub(super) fn parse_reply(saved: &[u8], quiet: bool) -> Reply {
    let mut pos = 0;
    let mut records = Vec::new();
    let mut hello = None;
    let mut index = 0;
    while let Some(header) = saved.get(pos..pos + HEADER) {
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let total = HEADER + len;
        let full = saved.get(pos..pos + total);
        match index {
            0 => {
                if header[0] != HANDSHAKE || header[1..3] != [3, 3] || len > MAX_RECORD_BODY {
                    return Reply::NotTls13;
                }
                let Some(full) = full else { break };
                match parse_server_hello(&full[HEADER..]) {
                    Some(parsed) => hello = Some(parsed),
                    None => return Reply::NotTls13,
                }
            }
            1 => {
                if header[0] != CHANGE_CIPHER_SPEC || header[1..3] != [3, 3] || len != 1 {
                    return Reply::Malformed;
                }
                let Some(full) = full else { break };
                if full[HEADER] != 1 {
                    return Reply::Malformed;
                }
            }
            _ => {
                if header[0] != APPLICATION_DATA
                    || header[1..3] != [3, 3]
                    || !(TAG + 2..=MAX_RECORD_BODY).contains(&len)
                {
                    return Reply::Malformed;
                }
                if index == 2 && total > WHOLE_FLIGHT {
                    records.push(total);
                    break;
                }
                if full.is_none() {
                    break;
                }
                records.push(total);
                if records.len() == FLIGHT_MESSAGES {
                    break;
                }
            }
        }
        pos += total;
        index += 1;
    }
    let Some((cipher_suite, group)) = hello else {
        return Reply::Incomplete;
    };
    let whole = records.first().is_some_and(|&l| l > WHOLE_FLIGHT);
    if whole || records.len() == FLIGHT_MESSAGES || (quiet && !records.is_empty()) {
        return Reply::Tls13(TargetFlight {
            cipher_suite,
            group,
            records,
        });
    }
    Reply::Incomplete
}

/// The keys of one direction of a TLS 1.3 record layer.
struct RecordKeys {
    ctx: AeadCtx,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKeys {
    fn new(cipher_suite: u16, secret: &[u8]) -> io::Result<Self> {
        let (algorithm, digest) = match cipher_suite {
            0x1301 => (Algorithm::aes_128_gcm(), MessageDigest::sha256()),
            0x1302 => (Algorithm::aes_256_gcm(), MessageDigest::sha384()),
            0x1303 => (Algorithm::chacha20_poly1305(), MessageDigest::sha256()),
            _ => return Err(io::Error::other("not a TLS 1.3 cipher suite")),
        };
        if secret.len() != digest.size() {
            return Err(io::Error::other("traffic secret of the wrong size"));
        }
        let hkdf = HkdfSuite::new(digest);
        let mut key = vec![0u8; algorithm.key_length()];
        hkdf.expand(secret, &expand_label("key", key.len()), &mut key)
            .map_err(io::Error::other)?;
        let mut iv = [0u8; 12];
        hkdf.expand(secret, &expand_label("iv", iv.len()), &mut iv)
            .map_err(io::Error::other)?;
        Ok(Self {
            ctx: AeadCtx::new_default_tag(&algorithm, &key).map_err(io::Error::other)?,
            iv,
            seq: 0,
        })
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        for (n, s) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *n ^= s;
        }
        self.seq += 1;
        nonce
    }

    /// The inner plaintext of `record`, content type and padding included.
    fn open(&mut self, record: &[u8]) -> io::Result<Vec<u8>> {
        if record.len() < HEADER + TAG + 1 {
            return Err(io::Error::other("record too short"));
        }
        let nonce = self.nonce();
        let (header, body) = record.split_at(HEADER);
        let (ciphertext, tag) = body.split_at(body.len() - TAG);
        let mut plain = ciphertext.to_vec();
        self.ctx
            .open_in_place_mut(&nonce, &mut plain, tag, header)
            .map_err(|_| io::Error::other("cannot open our own handshake record"))?;
        Ok(plain)
    }

    /// A record of `len` bytes, header included, carrying `content` as
    /// handshake data and zeros after it.
    fn seal(&mut self, content: &[u8], len: usize) -> io::Result<Vec<u8>> {
        let inner = len
            .checked_sub(HEADER + TAG)
            .filter(|&n| n > content.len())
            .ok_or_else(|| io::Error::other("record too short for its content"))?;
        let body = (len - HEADER) as u16;
        let mut record = vec![APPLICATION_DATA, 3, 3];
        record.extend_from_slice(&body.to_be_bytes());
        let mut plain = vec![0u8; inner];
        plain[..content.len()].copy_from_slice(content);
        plain[content.len()] = HANDSHAKE;
        let nonce = self.nonce();
        let mut tag = [0u8; TAG];
        let written = self
            .ctx
            .seal_in_place_mut(&nonce, &mut plain, &mut tag, &record)
            .map_err(io::Error::other)?
            .len();
        record.extend_from_slice(&plain);
        record.extend_from_slice(&tag[..written]);
        if record.len() != len {
            return Err(io::Error::other("unexpected tag length"));
        }
        Ok(record)
    }
}

/// TLS 1.3's HkdfLabel with an empty context.
fn expand_label(label: &str, len: usize) -> Vec<u8> {
    let label = format!("tls13 {}", label);
    let mut info = (len as u16).to_be_bytes().to_vec();
    info.push(label.len() as u8);
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    info
}

/// Whether `messages` ends with a whole Finished; an error if a Finished
/// is followed by anything.
fn ends_with_finished(messages: &[u8]) -> io::Result<bool> {
    let mut pos = 0;
    while let Some(header) = messages.get(pos..pos + 4) {
        let end = pos + 4 + u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
        if end > messages.len() {
            return Ok(false);
        }
        if header[0] == 20 {
            return if end == messages.len() {
                Ok(true)
            } else {
                Err(io::Error::other("data after our Finished"))
            };
        }
        pos = end;
    }
    Ok(false)
}

/// Spreads `messages` over records of the `lengths` given, in order, each
/// with at least one byte of them, as TLS 1.3 requires of handshake
/// records.
fn reseal(messages: &[u8], lengths: &[usize], keys: &mut RecordKeys) -> io::Result<Vec<u8>> {
    let room: Vec<usize> = lengths
        .iter()
        .map(|&l| l.saturating_sub(HEADER + TAG + 1))
        .collect();
    if room.contains(&0)
        || room.iter().sum::<usize>() < messages.len()
        || messages.len() < lengths.len()
    {
        return Err(io::Error::other(
            "the handshake server's flight cannot carry ours",
        ));
    }
    let mut out = Vec::with_capacity(lengths.iter().sum());
    let mut pos = 0;
    for (i, (&len, &room)) in lengths.iter().zip(&room).enumerate() {
        let later = lengths.len() - 1 - i;
        let take = room.min(messages.len() - pos - later);
        out.extend_from_slice(&keys.seal(&messages[pos..pos + take], len)?);
        pos += take;
    }
    Ok(out)
}

/// The server handshake traffic secret, as BoringSSL's key log gives it.
pub(super) type SecretSlot = Arc<Mutex<Option<Vec<u8>>>>;

enum Stage {
    ServerHello,
    ChangeCipherSpec,
    Flight {
        keys: Option<(RecordKeys, RecordKeys)>,
        messages: Vec<u8>,
    },
}

struct Plan {
    target: TargetFlight,
    secret: SecretSlot,
    stage: Stage,
}

/// The transport under the TLS server of an authenticated client: re-frames
/// its first encrypted flight after the handshake server's, and passes
/// everything else through.
pub(super) struct Shaper<S> {
    inner: S,
    plan: Option<Plan>,
    /// What BoringSSL wrote that is not yet a whole record.
    pending: Vec<u8>,
    /// What is ready for the transport: out[out_pos..].
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> Shaper<S> {
    pub fn new(inner: S, target: TargetFlight, secret: SecretSlot) -> Self {
        Self {
            inner,
            plan: Some(Plan {
                target,
                secret,
                stage: Stage::ServerHello,
            }),
            pending: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
        }
    }

    fn passing_through(&self) -> bool {
        self.plan.is_none() && self.pending.is_empty() && self.out_pos == self.out.len()
    }

    /// Moves every whole record in `pending` to `out`, re-framing the flight.
    fn process(&mut self) -> io::Result<()> {
        loop {
            let Some(plan) = self.plan.as_mut() else {
                self.out.append(&mut self.pending);
                return Ok(());
            };
            let Some(header) = self.pending.get(..HEADER) else {
                return Ok(());
            };
            let total = HEADER + u16::from_be_bytes([header[3], header[4]]) as usize;
            if self.pending.len() < total {
                return Ok(());
            }
            let record: Vec<u8> = self.pending.drain(..total).collect();
            if record[0] == ALERT {
                // BoringSSL gave up on the handshake: nothing to shape.
                self.out.extend_from_slice(&record);
                self.plan = None;
                continue;
            }
            match &mut plan.stage {
                Stage::ServerHello => {
                    let chosen = (record[0] == HANDSHAKE)
                        .then(|| parse_server_hello(&record[HEADER..]))
                        .flatten();
                    if chosen != Some((plan.target.cipher_suite, plan.target.group)) {
                        return Err(io::Error::other(format!(
                            "could not choose the handshake server's cipher suite {:#06x} \
                             and group {:#06x}",
                            plan.target.cipher_suite, plan.target.group
                        )));
                    }
                    self.out.extend_from_slice(&record);
                    plan.stage = Stage::ChangeCipherSpec;
                }
                Stage::ChangeCipherSpec => {
                    if record[0] != CHANGE_CIPHER_SPEC {
                        return Err(io::Error::other("expected our ChangeCipherSpec"));
                    }
                    self.out.extend_from_slice(&record);
                    plan.stage = Stage::Flight {
                        keys: None,
                        messages: Vec::new(),
                    };
                }
                Stage::Flight { keys, messages } => {
                    if record[0] != APPLICATION_DATA {
                        return Err(io::Error::other("expected an encrypted record"));
                    }
                    if keys.is_none() {
                        let secret = plan
                            .secret
                            .lock()
                            .map_err(|_| io::Error::other("poisoned"))?
                            .take()
                            .ok_or_else(|| io::Error::other("no handshake traffic secret"))?;
                        let suite = plan.target.cipher_suite;
                        *keys = Some((
                            RecordKeys::new(suite, &secret)?,
                            RecordKeys::new(suite, &secret)?,
                        ));
                    }
                    let (opener, sealer) = keys.as_mut().expect("set above");
                    let mut plain = opener.open(&record)?;
                    while plain.last() == Some(&0) {
                        plain.pop();
                    }
                    if plain.pop() != Some(HANDSHAKE) {
                        return Err(io::Error::other("unexpected record in our flight"));
                    }
                    messages.extend_from_slice(&plain);
                    if messages.len() > MAX_FLIGHT {
                        return Err(io::Error::other("our flight is too long"));
                    }
                    if ends_with_finished(messages)? {
                        let resealed = reseal(messages, &plan.target.records, sealer)?;
                        self.out.extend_from_slice(&resealed);
                        self.plan = None;
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> Shaper<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Shaper<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // The TLS stream reads while it waits for the client's Finished;
        // what is still queued for the client goes out meanwhile.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Shaper<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.passing_through() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if this.pending.len() + buf.len() > MAX_FLIGHT {
            return Poll::Ready(Err(io::Error::other("our flight is too long")));
        }
        this.pending.extend_from_slice(buf);
        this.process()?;
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.passing_through() {
            return Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        }
        let buf = bufs
            .iter()
            .find(|b| !b.is_empty())
            .map_or(&[][..], |b| &b[..]);
        Pin::new(this).poll_write(cx, buf)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// A cursor that fails rather than panics.
pub(super) struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.buf.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(out)
    }

    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize)
    }

    pub fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    pub fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Test helpers: a handshake server's reply as bytes.
#[cfg(test)]
pub(super) mod fake {
    use super::*;

    /// A TLS 1.3 ServerHello record echoing `session_id`.
    pub fn server_hello(session_id: &[u8], cipher_suite: u16, group: u16) -> Vec<u8> {
        let share_len = if group == X25519_MLKEM768 {
            MLKEM768_CIPHERTEXT + 32
        } else {
            32
        };
        let mut ext = vec![0, 43, 0, 2, 3, 4, 0, 51];
        ext.extend_from_slice(&((share_len + 4) as u16).to_be_bytes());
        ext.extend_from_slice(&group.to_be_bytes());
        ext.extend_from_slice(&(share_len as u16).to_be_bytes());
        ext.extend(std::iter::repeat_n(7u8, share_len));
        let mut body = vec![3, 3];
        body.extend_from_slice(&[9u8; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut msg = vec![2];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        record(HANDSHAKE, &msg)
    }

    pub fn record(typ: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![typ, 3, 3];
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    /// A ServerHello, a ChangeCipherSpec and encrypted-looking records of
    /// `lengths`, headers included.
    pub fn reply(session_id: &[u8], cipher_suite: u16, group: u16, lengths: &[usize]) -> Vec<u8> {
        let mut out = server_hello(session_id, cipher_suite, group);
        out.extend_from_slice(&record(CHANGE_CIPHER_SPEC, &[1]));
        for &len in lengths {
            out.extend_from_slice(&record(APPLICATION_DATA, &vec![0x5a; len - HEADER]));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;

    #[test]
    fn test_parse_reply_follows_xray() {
        let sid = [1u8; 32];
        // One record for the whole flight: taken once its header is in.
        let whole = reply(&sid, 0x1301, X25519, &[3000]);
        let flight = TargetFlight {
            cipher_suite: 0x1301,
            group: X25519,
            records: vec![3000],
        };
        assert_eq!(parse_reply(&whole, false), Reply::Tls13(flight.clone()));
        let header_only = &whole[..whole.len() - 2990];
        assert_eq!(parse_reply(header_only, false), Reply::Tls13(flight));
        // One record per message: all four, whole.
        let four = reply(&sid, 0x1302, X25519_MLKEM768, &[40, 2500, 300, 74]);
        assert_eq!(
            parse_reply(&four, false),
            Reply::Tls13(TargetFlight {
                cipher_suite: 0x1302,
                group: X25519_MLKEM768,
                records: vec![40, 2500, 300, 74],
            })
        );
        for cut in 0..four.len() - 1 {
            assert_eq!(
                parse_reply(&four[..cut], false),
                Reply::Incomplete,
                "{}",
                cut
            );
        }
        // Gone quiet after two records: those two.
        let two = reply(&sid, 0x1303, X25519, &[40, 400]);
        assert_eq!(parse_reply(&two, false), Reply::Incomplete);
        assert!(matches!(parse_reply(&two, true), Reply::Tls13(f) if f.records == [40, 400]));
        // The second still coming: the first alone.
        assert!(
            matches!(parse_reply(&two[..two.len() - 1], true), Reply::Tls13(f) if f.records == [40])
        );
        let first = two.len() - 400 - 40;
        assert_eq!(parse_reply(&two[..first + 39], true), Reply::Incomplete);
    }

    #[test]
    fn test_parse_reply_refuses() {
        let sid = [1u8; 32];
        // TLS 1.2: no supported_versions.
        let mut tls12 = server_hello(&sid, 0x1301, X25519);
        let at = tls12
            .windows(6)
            .position(|w| w == [0, 43, 0, 2, 3, 4])
            .unwrap();
        tls12[at + 5] = 3;
        assert_eq!(parse_reply(&tls12, false), Reply::NotTls13);
        // A HelloRetryRequest.
        let mut hrr = server_hello(&sid, 0x1301, X25519);
        hrr[HEADER + 6..HEADER + 38].copy_from_slice(&HRR_RANDOM);
        assert_eq!(parse_reply(&hrr, false), Reply::NotTls13);
        // Not TLS at all.
        assert_eq!(parse_reply(b"HTTP/1.1 400", false), Reply::NotTls13);
        // A group REALITY clients do not share with us.
        let p256 = server_hello(&sid, 0x1301, 23);
        assert_eq!(parse_reply(&p256, false), Reply::NotTls13);
        // No ChangeCipherSpec.
        let mut no_ccs = server_hello(&sid, 0x1301, X25519);
        no_ccs.extend_from_slice(&record(APPLICATION_DATA, &[0; 600]));
        assert_eq!(parse_reply(&no_ccs, false), Reply::Malformed);
        // Truncations never panic.
        let four = reply(&sid, 0x1301, X25519, &[40, 2500, 300, 74]);
        for cut in 0..four.len() {
            let _ = parse_reply(&four[..cut], true);
        }
    }

    #[test]
    fn test_reseal_matches_lengths_and_opens() {
        for suite in [0x1301u16, 0x1302, 0x1303] {
            let secret = vec![0x42u8; if suite == 0x1302 { 48 } else { 32 }];
            let mut messages = vec![8, 0, 0, 2, 0, 0]; // EncryptedExtensions
            messages.extend_from_slice(&[11, 0, 0, 200]);
            messages.extend_from_slice(&[1; 200]);
            messages.extend_from_slice(&[20, 0, 0, 32]);
            messages.extend_from_slice(&[2; 32]);
            assert!(ends_with_finished(&messages).unwrap());
            for lengths in [
                vec![3000],
                vec![40, 2500, 300, 74],
                vec![30, 30, 30, 30, 400],
            ] {
                let mut sealer = RecordKeys::new(suite, &secret).unwrap();
                let wire = reseal(&messages, &lengths, &mut sealer).unwrap();
                let mut opener = RecordKeys::new(suite, &secret).unwrap();
                let (mut pos, mut got) = (0, Vec::new());
                for &len in &lengths {
                    let record = &wire[pos..pos + len];
                    assert_eq!(u16::from_be_bytes([record[3], record[4]]) as usize, len - 5);
                    let mut plain = opener.open(record).unwrap();
                    while plain.last() == Some(&0) {
                        plain.pop();
                    }
                    assert_eq!(plain.pop(), Some(HANDSHAKE));
                    assert!(!plain.is_empty());
                    got.extend_from_slice(&plain);
                    pos += len;
                }
                assert_eq!(pos, wire.len());
                assert_eq!(got, messages);
            }
            // Too small a flight to hide ours in.
            let mut sealer = RecordKeys::new(suite, &secret).unwrap();
            assert!(reseal(&messages, &[100], &mut sealer).is_err());
        }
    }
}
