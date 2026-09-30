//! What Windows answers, read as plain bytes and text, so it is tested on
//! any host: an adapter's GUID as IP Helper names it, which the WLAN
//! service is asked by; a socket address; the SSID the WLAN service holds.

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use std::net::IpAddr;

/// A GUID's fields.
pub(super) type Guid = (u32, u16, u16, [u8; 8]);

/// `{4D36E972-E325-11CE-BFC1-08002BE10318}`, as an adapter's name is.
pub(super) fn parse_guid(s: &str) -> Option<Guid> {
    let s = s.strip_prefix('{')?.strip_suffix('}')?;
    let parts: Vec<&str> = s.split('-').collect();
    let [a, b, c, d, e] = parts[..] else {
        return None;
    };
    if [a.len(), b.len(), c.len(), d.len(), e.len()] != [8, 4, 4, 4, 12]
        || !s.bytes().all(|x| x == b'-' || x.is_ascii_hexdigit())
    {
        return None;
    }
    let tail = format!("{}{}", d, e);
    let mut data4 = [0u8; 8];
    for (i, byte) in data4.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&tail[2 * i..2 * i + 2], 16).ok()?;
    }
    Some((
        u32::from_str_radix(a, 16).ok()?,
        u16::from_str_radix(b, 16).ok()?,
        u16::from_str_radix(c, 16).ok()?,
        data4,
    ))
}

// ws2def.h: Windows' own numbers.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

/// The address of a `SOCKADDR_IN` or `SOCKADDR_IN6`, as its bytes.
pub(super) fn sockaddr(bytes: &[u8]) -> Option<IpAddr> {
    match u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?) {
        AF_INET => Some(IpAddr::from(<[u8; 4]>::try_from(bytes.get(4..8)?).ok()?)),
        AF_INET6 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes.get(8..24)?).ok()?)),
        _ => None,
    }
}

/// The SSID a `DOT11_SSID` holds: its first `len` bytes.
pub(super) fn ssid(len: u32, bytes: &[u8; 32]) -> Option<String> {
    super::ssid(bytes.get(..len as usize)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_adapter_s_guid_is_read() {
        assert_eq!(
            parse_guid("{4D36E972-E325-11CE-BFC1-08002BE10318}"),
            Some((
                0x4d36e972,
                0xe325,
                0x11ce,
                [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18]
            ))
        );
        for bad in [
            "4D36E972-E325-11CE-BFC1-08002BE10318",
            "{4D36E972-E325-11CE-BFC1-08002BE1031}",
            "{4D36E972-E325-11CE-BFC108002BE10318}",
            "{4D36E972-E325-11CE-BFC1-08002BE1031G}",
            "{+D36E972-E325-11CE-BFC1-08002BE10318}",
        ] {
            assert_eq!(parse_guid(bad), None, "{}", bad);
        }
    }

    #[test]
    fn socket_addresses_are_read() {
        let mut v4 = vec![0, 0, 0, 0, 192, 168, 1, 1];
        v4.extend_from_slice(&[0; 8]);
        v4[..2].copy_from_slice(&AF_INET.to_ne_bytes());
        assert_eq!(sockaddr(&v4), Some("192.168.1.1".parse().unwrap()));
        let mut v6 = vec![0u8; 28];
        v6[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        v6[8] = 0xfe;
        v6[9] = 0x80;
        v6[23] = 1;
        assert_eq!(sockaddr(&v6), Some("fe80::1".parse().unwrap()));
        assert_eq!(sockaddr(&v6[..20]), None);
        assert_eq!(sockaddr(&[0; 16]), None);
    }

    #[test]
    fn an_ssid_is_its_length_s_bytes() {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(b"Home");
        assert_eq!(ssid(4, &bytes).as_deref(), Some("Home"));
        assert_eq!(ssid(0, &bytes), None);
        assert_eq!(ssid(33, &bytes), None);
    }
}
