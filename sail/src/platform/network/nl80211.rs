//! nl80211 (generic netlink) spoken without iw(8): the Wi-Fi network an
//! interface is associated with, its SSID and BSSID, as `iw dev <if>
//! link` finds them -- the interface's SSID (`NL80211_CMD_GET_INTERFACE`)
//! and the BSS whose status is associated among the scan results
//! (`NL80211_CMD_GET_SCAN`). Neither needs a privilege.
//!
//! The framing is nf_tables' (`platform::nft`), as rtnetlink's is; the
//! encoder and parsers are plain bytes and build everywhere, so their tests
//! run on any host; talking to the kernel is Linux only.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::platform::nft::netlink::{attr_ne32, attrs, Attrs};

// linux/genetlink.h
const GENL_ID_CTRL: u16 = 0x10;
const GENL_HDRLEN: usize = 4;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

// linux/nl80211.h
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_GET_SCAN: u8 = 32;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_BSS: u16 = 47;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_BSS_BSSID: u16 = 1;
const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
const NL80211_BSS_STATUS: u16 = 9;
const NL80211_BSS_STATUS_ASSOCIATED: u32 = 1;

/// The information element that holds the SSID.
const WLAN_EID_SSID: u8 = 0;

/// A generic netlink body: the command, version 1 as iw sends it, and the
/// attributes `f` writes.
fn body(cmd: u8, f: impl FnOnce(&mut Attrs)) -> Vec<u8> {
    let mut a = Attrs::with_header(&[cmd, 1, 0, 0]);
    f(&mut a);
    a.into_bytes()
}

/// Asks the controller for nl80211's family id.
fn get_family() -> Vec<u8> {
    body(CTRL_CMD_GETFAMILY, |a| {
        a.str(CTRL_ATTR_FAMILY_NAME, "nl80211");
    })
}

/// Asks for interface `index`, or for the scan results seen on it.
fn about(cmd: u8, index: u32) -> Vec<u8> {
    body(cmd, |a| {
        a.ne32(NL80211_ATTR_IFINDEX, index);
    })
}

/// The attributes of a generic netlink body, past its header.
fn genl_attrs(body: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    attrs(body.get(GENL_HDRLEN..).unwrap_or_default())
}

/// The family id in the controller's answer.
fn parse_family(body: &[u8]) -> Option<u16> {
    genl_attrs(body)
        .find(|(ty, _)| *ty == CTRL_ATTR_FAMILY_ID)
        .and_then(|(_, p)| Some(u16::from_ne_bytes(p.get(..2)?.try_into().ok()?)))
}

/// An interface's SSID, when it is a station (a client) on a network.
fn parse_interface(body: &[u8]) -> Option<Vec<u8>> {
    let mut station = false;
    let mut ssid = None;
    for (ty, payload) in genl_attrs(body) {
        match ty {
            NL80211_ATTR_IFTYPE => station = attr_ne32(payload) == Some(NL80211_IFTYPE_STATION),
            NL80211_ATTR_SSID => ssid = Some(payload.to_vec()),
            _ => {}
        }
    }
    ssid.filter(|_| station)
}

/// The BSS a scan result tells of, if the interface is associated with it:
/// its BSSID, and the SSID its information elements carry.
fn parse_associated(body: &[u8]) -> Option<([u8; 6], Option<Vec<u8>>)> {
    let (_, bss) = genl_attrs(body).find(|(ty, _)| *ty == NL80211_ATTR_BSS)?;
    let mut bssid = None;
    let mut associated = false;
    let mut ssid = None;
    for (ty, payload) in attrs(bss) {
        match ty {
            NL80211_BSS_BSSID => bssid = payload.try_into().ok(),
            NL80211_BSS_STATUS => {
                associated = attr_ne32(payload) == Some(NL80211_BSS_STATUS_ASSOCIATED)
            }
            NL80211_BSS_INFORMATION_ELEMENTS => ssid = ssid_element(payload),
            _ => {}
        }
    }
    associated.then_some((bssid?, ssid))
}

/// The SSID among information elements: one byte of id, one of length,
/// the value.
fn ssid_element(mut ies: &[u8]) -> Option<Vec<u8>> {
    while let [id, len, rest @ ..] = ies {
        let value = rest.get(..usize::from(*len))?;
        if *id == WLAN_EID_SSID {
            return Some(value.to_vec());
        }
        ies = &rest[usize::from(*len)..];
    }
    None
}

/// The SSID and BSSID of the Wi-Fi network interface `index` is on; either
/// is none when not associated, or when the kernel has no nl80211.
#[cfg(target_os = "linux")]
pub(super) fn wifi(index: u32) -> std::io::Result<(Option<String>, Option<String>)> {
    use crate::platform::nft::sys::{NLM_F_ACK, NLM_F_DUMP};

    let socket = Genl::open()?;
    let family = socket
        .ask(GENL_ID_CTRL, NLM_F_ACK, get_family(), "looking up nl80211")?
        .iter()
        .find_map(|b| parse_family(b))
        .ok_or_else(|| std::io::Error::other("looking up nl80211: no family id"))?;
    let mut ssid = socket
        .ask(
            family,
            NLM_F_ACK,
            about(NL80211_CMD_GET_INTERFACE, index),
            "reading the wireless interface",
        )?
        .iter()
        .find_map(|b| parse_interface(b));
    let associated = socket
        .ask(
            family,
            NLM_F_DUMP,
            about(NL80211_CMD_GET_SCAN, index),
            "reading the scan results",
        )?
        .iter()
        .find_map(|b| parse_associated(b));
    let bssid = associated.as_ref().and_then(|(mac, _)| super::bssid(mac));
    // Kernels before the SSID was in the interface's answer: the BSS's.
    if ssid.is_none() {
        ssid = associated.and_then(|(_, ssid)| ssid);
    }
    Ok((ssid.as_deref().and_then(super::ssid), bssid))
}

/// A `NETLINK_GENERIC` socket, asked one thing at a time.
#[cfg(target_os = "linux")]
struct Genl {
    socket: crate::platform::nft::socket::Socket,
    seq: std::cell::Cell<u32>,
}

#[cfg(target_os = "linux")]
impl Genl {
    fn open() -> std::io::Result<Genl> {
        Ok(Genl {
            socket: crate::platform::nft::socket::Socket::open_protocol(libc::NETLINK_GENERIC)?,
            seq: std::cell::Cell::new(crate::platform::nft::socket::first_seq()),
        })
    }

    /// Sends `body` as a message of `family` and reads the answer's
    /// bodies. A dump the kernel interrupted is asked again, a few times.
    fn ask(
        &self,
        family: u16,
        flags: u16,
        body: Vec<u8>,
        what: &str,
    ) -> std::io::Result<Vec<Vec<u8>>> {
        use crate::platform::nft::netlink::put_message;
        use crate::platform::nft::sys::NLM_F_REQUEST;

        for _ in 0..3 {
            let seq = self.seq.get().wrapping_add(1);
            self.seq.set(seq);
            let mut wire = Vec::new();
            put_message(&mut wire, family, NLM_F_REQUEST | flags, seq, &body);
            self.socket.send(&wire)?;
            if let Some(bodies) =
                crate::platform::rtnetlink::socket::read_answer(&self.socket, seq, what)?
            {
                return Ok(bodies);
            }
        }
        Err(std::io::Error::other(format!(
            "{}: interrupted by changes",
            what
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generic netlink body as the kernel answers: the header, then the
    /// attributes.
    fn answer(cmd: u8, f: impl FnOnce(&mut Attrs)) -> Vec<u8> {
        body(cmd, f)
    }

    #[test]
    fn requests_are_what_iw_sends() {
        // CTRL_CMD_GETFAMILY v1, CTRL_ATTR_FAMILY_NAME "nl80211\0".
        assert_eq!(
            get_family(),
            [3, 1, 0, 0, 12, 0, 2, 0, b'n', b'l', b'8', b'0', b'2', b'1', b'1', 0]
        );
        // NL80211_CMD_GET_SCAN v1, NL80211_ATTR_IFINDEX 3.
        let mut expected = vec![32, 1, 0, 0, 8, 0, 3, 0];
        expected.extend_from_slice(&3u32.to_ne_bytes());
        assert_eq!(about(NL80211_CMD_GET_SCAN, 3), expected);
    }

    #[test]
    fn the_family_id_is_read() {
        let body = answer(1, |a| {
            a.str(CTRL_ATTR_FAMILY_NAME, "nl80211");
            a.bytes(CTRL_ATTR_FAMILY_ID, &0x1cu16.to_ne_bytes());
        });
        assert_eq!(parse_family(&body), Some(0x1c));
        assert_eq!(parse_family(&[1, 1, 0, 0]), None);
    }

    #[test]
    fn a_station_s_ssid_is_read() {
        let station = answer(7, |a| {
            a.ne32(NL80211_ATTR_IFINDEX, 3);
            a.str(4, "wlan0");
            a.ne32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
            a.bytes(NL80211_ATTR_SSID, b"Home Wi-Fi");
        });
        assert_eq!(
            parse_interface(&station).as_deref(),
            Some(&b"Home Wi-Fi"[..])
        );
        // An access point's own SSID is not a network it is on.
        let ap = answer(7, |a| {
            a.ne32(NL80211_ATTR_IFTYPE, 3);
            a.bytes(NL80211_ATTR_SSID, b"Mine");
        });
        assert_eq!(parse_interface(&ap), None);
        // A station not associated has none.
        let idle = answer(7, |a| {
            a.ne32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
        });
        assert_eq!(parse_interface(&idle), None);
    }

    #[test]
    fn the_associated_bss_is_found_among_the_scan_results() {
        let bss = |status: Option<u32>| {
            answer(34, |a| {
                a.ne32(NL80211_ATTR_IFINDEX, 3);
                a.nested(NL80211_ATTR_BSS, |b| {
                    b.bytes(NL80211_BSS_BSSID, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f]);
                    b.ne32(2, 5180);
                    // The DS parameter set, then the SSID, as beacons carry
                    // them in any order.
                    b.bytes(
                        NL80211_BSS_INFORMATION_ELEMENTS,
                        &[3, 1, 36, 0, 4, b'H', b'o', b'm', b'e', 1, 1, 0x8c],
                    );
                    if let Some(status) = status {
                        b.ne32(NL80211_BSS_STATUS, status);
                    }
                });
            })
        };
        assert_eq!(
            parse_associated(&bss(Some(NL80211_BSS_STATUS_ASSOCIATED))),
            Some(([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f], Some(b"Home".to_vec())))
        );
        // Seen but not joined, or authenticated only.
        assert_eq!(parse_associated(&bss(None)), None);
        assert_eq!(parse_associated(&bss(Some(0))), None);
    }

    #[test]
    fn a_cut_short_element_is_no_ssid() {
        assert_eq!(ssid_element(&[0, 5, b'a']), None);
        assert_eq!(ssid_element(&[1, 1, 2]), None);
        assert_eq!(ssid_element(&[0, 0]), Some(Vec::new()));
    }

    /// This host's Wi-Fi interfaces, if it has any (mac80211_hwsim makes
    /// some), answer; a BSSID comes with an SSID.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_host_s_wifi_is_asked() {
        let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
            return;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.join("phy80211").exists() {
                continue;
            }
            let index: u32 = std::fs::read_to_string(dir.join("ifindex"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let (ssid, bssid) = wifi(index).unwrap();
            assert!(bssid.is_none() || ssid.is_some(), "{:?}", dir);
        }
    }
}
