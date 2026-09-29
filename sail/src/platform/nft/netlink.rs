//! Netlink framing: the attribute writer the nf_tables objects are encoded
//! with, the message header, and the reader for what the kernel sends back.
//!
//! Header fields and attribute headers are in the host's byte order, as
//! netlink has them; the nf_tables values inside are big-endian unless a
//! caller says otherwise. rtnetlink (`platform::rtnetlink`) frames its
//! messages with these too, and its values are in the host's order.

use super::sys::*;

/// Rounds `len` up to netlink's 4-byte alignment.
pub fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// Attributes being written into a message body. Each attribute is
/// padded to 4 bytes; a nested one's length covers its padded children.
#[derive(Default)]
pub struct Attrs {
    buf: Vec<u8>,
}

impl Attrs {
    #[cfg(test)]
    pub fn new() -> Attrs {
        Attrs::default()
    }

    /// Starts a body with the `nfgenmsg` every nf_tables message begins
    /// with: the family, the version, and the resource id in network order.
    pub fn nfgen(family: u8, res_id: u16) -> Attrs {
        let mut buf = vec![family, NFNETLINK_V0];
        buf.extend_from_slice(&res_id.to_be_bytes());
        Attrs { buf }
    }

    /// Starts a body with a fixed header, as rtnetlink messages begin with
    /// their family's struct (`rtmsg`, `ifinfomsg`, ...). It is padded to
    /// 4 bytes, as the attributes that follow must be aligned.
    pub fn with_header(header: &[u8]) -> Attrs {
        let mut buf = header.to_vec();
        buf.resize(align(buf.len()), 0);
        Attrs { buf }
    }

    pub fn bytes(&mut self, ty: u16, data: &[u8]) -> &mut Attrs {
        let len = NLA_HDRLEN + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(align(self.buf.len()), 0);
        self
    }

    pub fn u8(&mut self, ty: u16, value: u8) -> &mut Attrs {
        self.bytes(ty, &[value])
    }

    /// A u32 in the host's byte order.
    pub fn ne32(&mut self, ty: u16, value: u32) -> &mut Attrs {
        self.bytes(ty, &value.to_ne_bytes())
    }

    pub fn be16(&mut self, ty: u16, value: u16) -> &mut Attrs {
        self.bytes(ty, &value.to_be_bytes())
    }

    pub fn be32(&mut self, ty: u16, value: u32) -> &mut Attrs {
        self.bytes(ty, &value.to_be_bytes())
    }

    pub fn be64(&mut self, ty: u16, value: u64) -> &mut Attrs {
        self.bytes(ty, &value.to_be_bytes())
    }

    /// A NUL-terminated string, as the kernel's `NLA_STRING` policies take.
    pub fn str(&mut self, ty: u16, value: &str) -> &mut Attrs {
        let mut data = Vec::with_capacity(value.len() + 1);
        data.extend_from_slice(value.as_bytes());
        data.push(0);
        self.bytes(ty, &data)
    }

    /// A nested attribute, `NLA_F_NESTED` set, holding what `f` writes.
    pub fn nested(&mut self, ty: u16, f: impl FnOnce(&mut Attrs)) -> &mut Attrs {
        let start = self.buf.len();
        self.buf.extend_from_slice(&[0; NLA_HDRLEN]);
        f(self);
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        self.buf[start + 2..start + 4].copy_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        self
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// Appends one netlink message, header first, to `out`.
pub fn put_message(out: &mut Vec<u8>, ty: u16, flags: u16, seq: u32, body: &[u8]) {
    let len = NLMSG_HDRLEN + body.len();
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    // The port id: 0, the kernel fills in ours.
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    out.resize(align(out.len()), 0);
}

/// The nf_tables message type for `msg`: the subsystem in the high byte.
pub fn nft_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

/// A message the kernel sent.
#[derive(Debug)]
pub struct Message<'a> {
    pub ty: u16,
    pub flags: u16,
    pub seq: u32,
    pub body: &'a [u8],
}

/// The messages in one datagram. A truncated one ends the walk with an
/// error rather than being read past.
pub fn messages(mut buf: &[u8]) -> impl Iterator<Item = Result<Message<'_>, &'static str>> {
    std::iter::from_fn(move || {
        if buf.is_empty() {
            return None;
        }
        if buf.len() < NLMSG_HDRLEN {
            buf = &[];
            return Some(Err("truncated netlink header"));
        }
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || len > buf.len() {
            buf = &[];
            return Some(Err("bad netlink message length"));
        }
        let msg = Message {
            ty: u16::from_ne_bytes(buf[4..6].try_into().unwrap()),
            flags: u16::from_ne_bytes(buf[6..8].try_into().unwrap()),
            seq: u32::from_ne_bytes(buf[8..12].try_into().unwrap()),
            body: &buf[NLMSG_HDRLEN..len],
        };
        buf = &buf[align(len).min(buf.len())..];
        Some(Ok(msg))
    })
}

/// The attributes in `buf` as (type without flags, payload). Stops at the
/// first one that does not fit.
pub fn attrs(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if buf.len() < NLA_HDRLEN {
            return None;
        }
        let len = u16::from_ne_bytes(buf[0..2].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[2..4].try_into().unwrap());
        if len < NLA_HDRLEN || len > buf.len() {
            return None;
        }
        let payload = &buf[NLA_HDRLEN..len];
        buf = &buf[align(len).min(buf.len())..];
        Some((ty & NLA_TYPE_MASK, payload))
    })
}

/// A NUL-terminated string attribute, without the NUL.
pub fn attr_str(payload: &[u8]) -> String {
    let end = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).into_owned()
}

/// A big-endian u32 attribute.
pub fn attr_be32(payload: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(payload.get(..4)?.try_into().ok()?))
}

/// A u32 attribute in the host's byte order.
pub fn attr_ne32(payload: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(payload.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_is_padded_but_its_length_is_not() {
        let mut a = Attrs::new();
        a.str(1, "nat");
        a.u8(2, 7);
        // "nat\0" fills its 4 bytes; the u8 is padded with three zeros but
        // its length says 5.
        assert_eq!(
            a.into_bytes(),
            b"\x08\x00\x01\x00nat\x00\x05\x00\x02\x00\x07\x00\x00\x00".to_vec()
        );
    }

    #[test]
    fn nested_attribute_sets_the_flag_and_covers_its_children() {
        let mut a = Attrs::new();
        a.nested(4, |a| {
            a.be32(1, 0);
            a.nested(2, |a| {
                a.str(1, "ab");
            });
        });
        let want = b"\x18\x00\x04\x80\
            \x08\x00\x01\x00\x00\x00\x00\x00\
            \x0c\x00\x02\x80\x07\x00\x01\x00ab\x00\x00"
            .to_vec();
        assert_eq!(a.into_bytes(), want);
    }

    #[test]
    fn empty_nested_attribute_is_just_a_header() {
        let mut a = Attrs::new();
        a.nested(2, |_| {});
        assert_eq!(a.into_bytes(), b"\x04\x00\x02\x80".to_vec());
    }

    #[test]
    fn nfgenmsg_has_the_resource_id_in_network_order() {
        assert_eq!(Attrs::nfgen(1, 10).into_bytes(), vec![1, 0, 0, 10]);
    }

    #[test]
    fn message_header_is_host_order() {
        let mut out = Vec::new();
        put_message(
            &mut out,
            nft_type(NFT_MSG_NEWTABLE),
            0x405,
            7,
            &[2, 0, 0, 0],
        );
        let mut want = Vec::new();
        want.extend_from_slice(&20u32.to_ne_bytes());
        want.extend_from_slice(&0x0a00u16.to_ne_bytes());
        want.extend_from_slice(&0x0405u16.to_ne_bytes());
        want.extend_from_slice(&7u32.to_ne_bytes());
        want.extend_from_slice(&0u32.to_ne_bytes());
        want.extend_from_slice(&[2, 0, 0, 0]);
        assert_eq!(out, want);
    }

    #[test]
    fn reads_back_what_it_wrote() {
        let mut body = Attrs::new();
        body.str(NFTA_TABLE_NAME, "sail").be32(NFTA_TABLE_USE, 3);
        let body = body.into_bytes();
        let mut out = Vec::new();
        put_message(&mut out, 1, 2, 3, &body);
        put_message(&mut out, NLMSG_DONE, 0, 4, &[0; 4]);
        let msgs: Vec<_> = messages(&out).collect::<Result<_, _>>().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!((msgs[0].ty, msgs[0].flags, msgs[0].seq), (1, 2, 3));
        let got: Vec<_> = attrs(msgs[0].body).collect();
        assert_eq!(got[0].0, NFTA_TABLE_NAME);
        assert_eq!(attr_str(got[0].1), "sail");
        assert_eq!(attr_be32(got[1].1), Some(3));
        assert_eq!(msgs[1].ty, NLMSG_DONE);
    }

    #[test]
    fn truncated_message_is_an_error() {
        let mut out = Vec::new();
        put_message(&mut out, 1, 0, 1, &[0; 8]);
        out.truncate(20);
        assert!(messages(&out).next().unwrap().is_err());
    }
}
