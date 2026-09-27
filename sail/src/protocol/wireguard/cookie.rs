//! mac1, mac2 and cookies: whitepaper section 5.4.7 and Linux's cookie.c.
//!
//! The [`CookieChecker`] is the device's side as a receiver: it checks mac1
//! against our own public key and, under load, mac2 against the cookie of
//! the sender's address, and makes cookie replies. The [`CookieGenerator`]
//! is a peer's side as a sender: it puts mac1 (keyed by the peer's public
//! key) and, while it holds a fresh cookie from that peer, mac2 on our
//! handshake messages.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::crypto::{self, KEY_LEN, MAC_LEN, XNONCE_LEN};
use super::messages::{mac_offsets, CookieReply, ENCRYPTED_COOKIE_LEN};

pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// How long a responder keeps a cookie secret.
pub const COOKIE_SECRET_MAX_AGE: Duration = Duration::from_secs(120);
/// How long before the secret changes an initiator stops using a cookie.
pub const COOKIE_SECRET_LATENCY: Duration = Duration::from_secs(5);

/// The result of checking a handshake message's MACs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacState {
    InvalidMac,
    ValidMacButNoCookie,
    ValidMacWithCookieButRateLimited,
    ValidMacWithCookie,
}

/// The bytes a cookie is bound to: source address, then port big-endian,
/// as Linux's make_cookie hashes them.
fn address_bytes(src: SocketAddr, out: &mut [u8; 18]) -> usize {
    let n = match src.ip() {
        IpAddr::V4(v4) => {
            out[..4].copy_from_slice(&v4.octets());
            4
        }
        IpAddr::V6(v6) => {
            out[..16].copy_from_slice(&v6.octets());
            16
        }
    };
    out[n..n + 2].copy_from_slice(&src.port().to_be_bytes());
    n + 2
}

pub struct CookieChecker {
    mac1_key: [u8; KEY_LEN],
    cookie_key: [u8; KEY_LEN],
    secret: [u8; KEY_LEN],
    secret_birth: Option<Instant>,
}

impl CookieChecker {
    pub fn new(local_public: &[u8; KEY_LEN]) -> Self {
        CookieChecker {
            mac1_key: crypto::hash(&[LABEL_MAC1, local_public]),
            cookie_key: crypto::hash(&[LABEL_COOKIE, local_public]),
            secret: [0; KEY_LEN],
            secret_birth: None,
        }
    }

    /// The cookie of `src` under the current secret, rotating the secret
    /// every two minutes.
    fn make_cookie(&mut self, src: SocketAddr, now: Instant) -> [u8; MAC_LEN] {
        let stale = self
            .secret_birth
            .is_none_or(|b| now.saturating_duration_since(b) >= COOKIE_SECRET_MAX_AGE);
        if stale {
            crypto::random_bytes(&mut self.secret);
            self.secret_birth = Some(now);
        }
        let mut a = [0u8; 18];
        let n = address_bytes(src, &mut a);
        crypto::mac(&self.secret, &[&a[..n]])
    }

    /// Checks mac1 and, if `check_cookie`, mac2 of a whole handshake
    /// message. `allow` is the rate limiter, consulted only for a message
    /// with a valid cookie.
    pub fn validate(
        &mut self,
        msg: &[u8],
        src: SocketAddr,
        check_cookie: bool,
        now: Instant,
        allow: impl FnOnce() -> bool,
    ) -> MacState {
        let (m1, m2) = mac_offsets(msg.len());
        let mac1 = crypto::mac(&self.mac1_key, &[&msg[..m1]]);
        if !crypto::ct_eq(&mac1, &msg[m1..m2]) {
            return MacState::InvalidMac;
        }
        if !check_cookie {
            return MacState::ValidMacButNoCookie;
        }
        let cookie = self.make_cookie(src, now);
        let mac2 = crypto::mac(&cookie, &[&msg[..m2]]);
        if !crypto::ct_eq(&mac2, &msg[m2..]) {
            return MacState::ValidMacButNoCookie;
        }
        if !allow() {
            return MacState::ValidMacWithCookieButRateLimited;
        }
        MacState::ValidMacWithCookie
    }

    /// A cookie reply to the handshake message `msg` from `src`, whose
    /// sender index was `sender`.
    pub fn create_reply(
        &mut self,
        msg: &[u8],
        sender: u32,
        src: SocketAddr,
        now: Instant,
    ) -> CookieReply {
        let (m1, m2) = mac_offsets(msg.len());
        let cookie = self.make_cookie(src, now);
        let mut nonce = [0u8; XNONCE_LEN];
        crypto::random_bytes(&mut nonce);
        let mut encrypted_cookie = [0u8; ENCRYPTED_COOKIE_LEN];
        crypto::xaead_seal(
            &self.cookie_key,
            &nonce,
            &cookie,
            &msg[m1..m2],
            &mut encrypted_cookie,
        );
        CookieReply {
            reserved: [0; 3],
            receiver: sender,
            nonce,
            encrypted_cookie,
        }
    }
}

impl Drop for CookieChecker {
    fn drop(&mut self) {
        crypto::wipe(&mut self.secret);
    }
}

pub struct CookieGenerator {
    mac1_key: [u8; KEY_LEN],
    cookie_key: [u8; KEY_LEN],
    last_mac1: Option<[u8; MAC_LEN]>,
    cookie: Option<([u8; MAC_LEN], Instant)>,
}

impl CookieGenerator {
    pub fn new(peer_public: &[u8; KEY_LEN]) -> Self {
        CookieGenerator {
            mac1_key: crypto::hash(&[LABEL_MAC1, peer_public]),
            cookie_key: crypto::hash(&[LABEL_COOKIE, peer_public]),
            last_mac1: None,
            cookie: None,
        }
    }

    /// Fills mac1 and mac2 of an outgoing handshake message.
    pub fn add_macs(&mut self, msg: &mut [u8], now: Instant) {
        let (m1, m2) = mac_offsets(msg.len());
        let mac1 = crypto::mac(&self.mac1_key, &[&msg[..m1]]);
        msg[m1..m2].copy_from_slice(&mac1);
        self.last_mac1 = Some(mac1);
        let fresh = self.cookie.filter(|(_, birth)| {
            now.saturating_duration_since(*birth) < COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY
        });
        match fresh {
            Some((cookie, _)) => {
                let mac2 = crypto::mac(&cookie, &[&msg[..m2]]);
                msg[m2..].copy_from_slice(&mac2);
            }
            None => msg[m2..].fill(0),
        }
    }

    /// Takes the cookie of a reply to our last handshake message. False if
    /// we sent none, or the reply does not decrypt.
    pub fn consume_reply(&mut self, reply: &CookieReply, now: Instant) -> bool {
        let Some(mac1) = self.last_mac1 else {
            return false;
        };
        let mut cookie = [0u8; MAC_LEN];
        if !crypto::xaead_open(
            &self.cookie_key,
            &reply.nonce,
            &reply.encrypted_cookie,
            &mac1,
            &mut cookie,
        ) {
            return false;
        }
        self.cookie = Some((cookie, now));
        self.last_mac1 = None;
        true
    }

    #[cfg(test)]
    pub fn has_cookie(&self) -> bool {
        self.cookie.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::wireguard::messages::INITIATION_LEN;

    #[test]
    fn mac1_then_cookie_then_mac2() {
        let responder_pub = crypto::public_key(&crypto::generate_private_key());
        let mut checker = CookieChecker::new(&responder_pub);
        let mut gen = CookieGenerator::new(&responder_pub);
        let src: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let now = Instant::now();

        let mut msg = [0x11u8; INITIATION_LEN];
        msg[0] = 1;
        gen.add_macs(&mut msg, now);
        assert_eq!(&msg[132..], &[0u8; 16]);
        assert_eq!(
            checker.validate(&msg, src, false, now, || true),
            MacState::ValidMacButNoCookie
        );
        // Under load, no cookie yet.
        assert_eq!(
            checker.validate(&msg, src, true, now, || true),
            MacState::ValidMacButNoCookie
        );
        // A corrupted mac1.
        let mut bad = msg;
        bad[120] ^= 1;
        assert_eq!(
            checker.validate(&bad, src, true, now, || true),
            MacState::InvalidMac
        );

        let reply = checker.create_reply(&msg, 7, src, now);
        assert_eq!(reply.receiver, 7);
        // A reply for someone else's key does not decrypt.
        let mut other = CookieGenerator::new(&[9u8; 32]);
        other.add_macs(&mut msg.clone(), now);
        assert!(!other.consume_reply(&reply, now));
        assert!(gen.consume_reply(&reply, now));
        // Only once per mac1 sent.
        assert!(!gen.consume_reply(&reply, now));

        gen.add_macs(&mut msg, now);
        assert_ne!(&msg[132..], &[0u8; 16]);
        assert_eq!(
            checker.validate(&msg, src, true, now, || true),
            MacState::ValidMacWithCookie
        );
        assert_eq!(
            checker.validate(&msg, src, true, now, || false),
            MacState::ValidMacWithCookieButRateLimited
        );
        // The cookie is bound to the address and port.
        let elsewhere: SocketAddr = "192.0.2.1:51821".parse().unwrap();
        assert_eq!(
            checker.validate(&msg, elsewhere, true, now, || true),
            MacState::ValidMacButNoCookie
        );
        // An initiator stops using a cookie after 115 s.
        let later = now + Duration::from_secs(116);
        gen.add_macs(&mut msg, later);
        assert_eq!(&msg[132..], &[0u8; 16]);
        // A responder's secret changes after 120 s.
        let mut msg2 = msg;
        gen.cookie = Some((checker.make_cookie(src, now), now));
        gen.add_macs(&mut msg2, now);
        assert_eq!(
            checker.validate(&msg2, src, true, now + Duration::from_secs(121), || true),
            MacState::ValidMacButNoCookie
        );
    }
}
