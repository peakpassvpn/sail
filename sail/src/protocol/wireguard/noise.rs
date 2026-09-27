//! Noise_IKpsk2 as WireGuard instantiates it: whitepaper section 5.4 and
//! Linux's noise.c. The functions here compute messages and keys; mac1 and
//! mac2, indices and peer lookup are the device's.

use std::time::Instant;

use super::crypto::{self, KEY_LEN};
use super::messages::{
    Initiation, Response, ENCRYPTED_EMPTY_LEN, ENCRYPTED_STATIC_LEN, ENCRYPTED_TIMESTAMP_LEN,
};
use super::tai64n::{self, Tai64n};

pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// HASH(CONSTRUCTION), the first chaining key.
pub fn initial_chaining_key() -> [u8; KEY_LEN] {
    crypto::hash(&[CONSTRUCTION])
}

/// HASH(HASH(CONSTRUCTION) || IDENTIFIER || responder's static public key).
pub fn initial_hash(responder_public: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let h = crypto::hash(&[&initial_chaining_key(), IDENTIFIER]);
    crypto::hash(&[&h, responder_public])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    Zeroed,
    CreatedInitiation,
    ConsumedInitiation,
    CreatedResponse,
    ConsumedResponse,
}

/// A peer's handshake in flight.
pub struct Handshake {
    pub state: HandshakeState,
    /// Our index for this handshake, registered in the device's table.
    pub local_index: Option<u32>,
    pub remote_index: u32,
    ephemeral_private: [u8; KEY_LEN],
    remote_ephemeral: [u8; KEY_LEN],
    hash: [u8; KEY_LEN],
    chaining_key: [u8; KEY_LEN],
    /// The newest initiation timestamp taken from this peer; older or
    /// equal ones are replays. Survives zeroing.
    pub latest_timestamp: Tai64n,
    /// When we last took an initiation from this peer. Survives zeroing.
    pub last_initiation_consumption: Option<Instant>,
}

impl Default for Handshake {
    fn default() -> Self {
        Handshake {
            state: HandshakeState::Zeroed,
            local_index: None,
            remote_index: 0,
            ephemeral_private: [0; KEY_LEN],
            remote_ephemeral: [0; KEY_LEN],
            hash: [0; KEY_LEN],
            chaining_key: [0; KEY_LEN],
            latest_timestamp: Tai64n::default(),
            last_initiation_consumption: None,
        }
    }
}

impl Handshake {
    /// Forgets the handshake's secrets. The caller has already released the
    /// index, or handed it to a keypair.
    pub fn zero(&mut self) {
        crypto::wipe(&mut self.ephemeral_private);
        crypto::wipe(&mut self.remote_ephemeral);
        crypto::wipe(&mut self.hash);
        crypto::wipe(&mut self.chaining_key);
        self.remote_index = 0;
        self.local_index = None;
        self.state = HandshakeState::Zeroed;
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.zero();
    }
}

/// What a peer's static identity contributes to a handshake.
pub struct PeerKeys<'a> {
    pub local_private: &'a [u8; KEY_LEN],
    pub local_public: &'a [u8; KEY_LEN],
    pub remote_public: &'a [u8; KEY_LEN],
    /// DH(local private, remote public), computed once per peer.
    pub static_static: &'a [u8; KEY_LEN],
    pub preshared_key: &'a [u8; KEY_LEN],
}

/// Transport keys out of a finished handshake.
pub struct SessionKeys {
    pub send: [u8; KEY_LEN],
    pub recv: [u8; KEY_LEN],
    pub initiator: bool,
    pub local_index: u32,
    pub remote_index: u32,
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        crypto::wipe(&mut self.send);
        crypto::wipe(&mut self.recv);
    }
}

/// Builds an initiation, mac fields zero. `ephemeral` is the fresh private
/// key; tests pass a fixed one.
pub fn create_initiation(
    hs: &mut Handshake,
    keys: &PeerKeys,
    local_index: u32,
    timestamp: Tai64n,
    ephemeral: [u8; KEY_LEN],
) -> Option<Initiation> {
    if keys.static_static == &[0u8; KEY_LEN] {
        return None;
    }
    let mut ck = initial_chaining_key();
    let mut h = initial_hash(keys.remote_public);

    let e_pub = crypto::public_key(&ephemeral);
    ck = crypto::kdf1(&ck, &e_pub);
    h = crypto::hash(&[&h, &e_pub]);

    let (ck2, mut k) = crypto::kdf2(&ck, &crypto::dh(&ephemeral, keys.remote_public)?);
    ck = ck2;
    let mut encrypted_static = [0u8; ENCRYPTED_STATIC_LEN];
    crypto::aead_seal(&k, 0, keys.local_public, &h, &mut encrypted_static);
    h = crypto::hash(&[&h, &encrypted_static]);

    let (ck3, k2) = crypto::kdf2(&ck, keys.static_static);
    ck = ck3;
    crypto::wipe(&mut k);
    k = k2;
    let mut encrypted_timestamp = [0u8; ENCRYPTED_TIMESTAMP_LEN];
    crypto::aead_seal(&k, 0, &timestamp.0, &h, &mut encrypted_timestamp);
    h = crypto::hash(&[&h, &encrypted_timestamp]);
    crypto::wipe(&mut k);

    hs.zero();
    hs.ephemeral_private = ephemeral;
    hs.chaining_key = ck;
    hs.hash = h;
    hs.local_index = Some(local_index);
    hs.state = HandshakeState::CreatedInitiation;

    Some(Initiation {
        reserved: [0; 3],
        sender: local_index,
        ephemeral: e_pub,
        encrypted_static,
        encrypted_timestamp,
        mac1: [0; 16],
        mac2: [0; 16],
    })
}

/// The first half of consuming an initiation: everything that needs only
/// our own static key. Yields the initiator's static public key, so the
/// device can find the peer.
pub struct InitiationFirstHalf {
    pub remote_static: [u8; KEY_LEN],
    ck: [u8; KEY_LEN],
    h: [u8; KEY_LEN],
    remote_ephemeral: [u8; KEY_LEN],
}

impl Drop for InitiationFirstHalf {
    fn drop(&mut self) {
        crypto::wipe(&mut self.ck);
    }
}

pub fn consume_initiation_static(
    msg: &Initiation,
    local_private: &[u8; KEY_LEN],
    local_public: &[u8; KEY_LEN],
) -> Option<InitiationFirstHalf> {
    let mut ck = initial_chaining_key();
    let mut h = initial_hash(local_public);
    ck = crypto::kdf1(&ck, &msg.ephemeral);
    h = crypto::hash(&[&h, &msg.ephemeral]);
    let (ck2, mut k) = crypto::kdf2(&ck, &crypto::dh(local_private, &msg.ephemeral)?);
    let mut remote_static = [0u8; KEY_LEN];
    let ok = crypto::aead_open(&k, 0, &msg.encrypted_static, &h, &mut remote_static);
    crypto::wipe(&mut k);
    if !ok {
        return None;
    }
    h = crypto::hash(&[&h, &msg.encrypted_static]);
    Some(InitiationFirstHalf {
        remote_static,
        ck: ck2,
        h,
        remote_ephemeral: msg.ephemeral,
    })
}

/// The second half: decrypts the timestamp with the peer's keys and, if it
/// is neither a replay nor a flood, takes the initiation into `hs`.
pub fn consume_initiation_peer(
    first: InitiationFirstHalf,
    msg: &Initiation,
    hs: &mut Handshake,
    static_static: &[u8; KEY_LEN],
    now: Instant,
) -> bool {
    if static_static == &[0u8; KEY_LEN] {
        return false;
    }
    let (ck, mut k) = crypto::kdf2(&first.ck, static_static);
    let mut t = [0u8; tai64n::LEN];
    let ok = crypto::aead_open(&k, 0, &msg.encrypted_timestamp, &first.h, &mut t);
    crypto::wipe(&mut k);
    if !ok {
        return false;
    }
    let h = crypto::hash(&[&first.h, &msg.encrypted_timestamp]);
    let t = Tai64n(t);
    let replay = t <= hs.latest_timestamp;
    let flood = hs.last_initiation_consumption.is_some_and(|last| {
        now.saturating_duration_since(last)
            < std::time::Duration::from_secs(1) / super::timers::INITIATIONS_PER_SECOND
    });
    if replay || flood {
        return false;
    }
    let local_index = hs.local_index;
    hs.zero();
    // The device releases a stale index when it gives this handshake a new
    // one in create_response; keep it until then.
    hs.local_index = local_index;
    hs.remote_ephemeral = first.remote_ephemeral;
    hs.chaining_key = ck;
    hs.hash = h;
    hs.remote_index = msg.sender;
    hs.latest_timestamp = t;
    hs.last_initiation_consumption = Some(now);
    hs.state = HandshakeState::ConsumedInitiation;
    true
}

/// Builds the response to a consumed initiation, mac fields zero.
pub fn create_response(
    hs: &mut Handshake,
    keys: &PeerKeys,
    local_index: u32,
    ephemeral: [u8; KEY_LEN],
) -> Option<Response> {
    if hs.state != HandshakeState::ConsumedInitiation {
        return None;
    }
    let mut ck = hs.chaining_key;
    let mut h = hs.hash;
    let e_pub = crypto::public_key(&ephemeral);
    ck = crypto::kdf1(&ck, &e_pub);
    h = crypto::hash(&[&h, &e_pub]);
    ck = crypto::kdf1(&ck, &crypto::dh(&ephemeral, &hs.remote_ephemeral)?);
    ck = crypto::kdf1(&ck, &crypto::dh(&ephemeral, keys.remote_public)?);
    let (ck2, t, mut k) = crypto::kdf3(&ck, keys.preshared_key);
    ck = ck2;
    h = crypto::hash(&[&h, &t]);
    let mut encrypted_nothing = [0u8; ENCRYPTED_EMPTY_LEN];
    crypto::aead_seal(&k, 0, &[], &h, &mut encrypted_nothing);
    crypto::wipe(&mut k);
    h = crypto::hash(&[&h, &encrypted_nothing]);

    hs.ephemeral_private = ephemeral;
    hs.chaining_key = ck;
    hs.hash = h;
    hs.local_index = Some(local_index);
    hs.state = HandshakeState::CreatedResponse;
    Some(Response {
        reserved: [0; 3],
        sender: local_index,
        receiver: hs.remote_index,
        ephemeral: e_pub,
        encrypted_nothing,
        mac1: [0; 16],
        mac2: [0; 16],
    })
}

/// Takes a response into a handshake we initiated.
pub fn consume_response(hs: &mut Handshake, msg: &Response, keys: &PeerKeys) -> bool {
    if hs.state != HandshakeState::CreatedInitiation {
        return false;
    }
    let mut ck = hs.chaining_key;
    let mut h = hs.hash;
    ck = crypto::kdf1(&ck, &msg.ephemeral);
    h = crypto::hash(&[&h, &msg.ephemeral]);
    let Some(ee) = crypto::dh(&hs.ephemeral_private, &msg.ephemeral) else {
        return false;
    };
    ck = crypto::kdf1(&ck, &ee);
    let Some(se) = crypto::dh(keys.local_private, &msg.ephemeral) else {
        return false;
    };
    ck = crypto::kdf1(&ck, &se);
    let (ck2, t, mut k) = crypto::kdf3(&ck, keys.preshared_key);
    ck = ck2;
    h = crypto::hash(&[&h, &t]);
    let ok = crypto::aead_open(&k, 0, &msg.encrypted_nothing, &h, &mut []);
    crypto::wipe(&mut k);
    if !ok {
        return false;
    }
    h = crypto::hash(&[&h, &msg.encrypted_nothing]);
    hs.chaining_key = ck;
    hs.hash = h;
    hs.remote_index = msg.sender;
    hs.state = HandshakeState::ConsumedResponse;
    true
}

/// Derives the transport keys and zeroes the handshake. The keypair takes
/// over the handshake's index.
pub fn begin_session(hs: &mut Handshake) -> Option<SessionKeys> {
    let initiator = match hs.state {
        HandshakeState::ConsumedResponse => true,
        HandshakeState::CreatedResponse => false,
        _ => return None,
    };
    let (a, b) = crypto::kdf2(&hs.chaining_key, &[]);
    let (send, recv) = if initiator { (a, b) } else { (b, a) };
    let keys = SessionKeys {
        send,
        recv,
        initiator,
        local_index: hs.local_index?,
        remote_index: hs.remote_index,
    };
    hs.zero();
    Some(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Party {
        private: [u8; 32],
        public: [u8; 32],
    }

    fn party(seed: u8) -> Party {
        let mut private = [seed; 32];
        crypto::clamp(&mut private);
        Party {
            public: crypto::public_key(&private),
            private,
        }
    }

    fn keys<'a>(
        me: &'a Party,
        them: &'a Party,
        ss: &'a [u8; 32],
        psk: &'a [u8; 32],
    ) -> PeerKeys<'a> {
        PeerKeys {
            local_private: &me.private,
            local_public: &me.public,
            remote_public: &them.public,
            static_static: ss,
            preshared_key: psk,
        }
    }

    #[test]
    fn handshake_agrees_on_keys() {
        let i = party(1);
        let r = party(2);
        let psk = [3u8; 32];
        let ss_i = crypto::dh(&i.private, &r.public).unwrap();
        let ss_r = crypto::dh(&r.private, &i.public).unwrap();
        assert_eq!(ss_i, ss_r);
        let now = Instant::now();

        let mut hs_i = Handshake::default();
        let init = create_initiation(
            &mut hs_i,
            &keys(&i, &r, &ss_i, &psk),
            11,
            Tai64n::from_unix(1000, 0),
            crypto::generate_private_key(),
        )
        .unwrap();

        let first = consume_initiation_static(&init, &r.private, &r.public).unwrap();
        assert_eq!(first.remote_static, i.public);
        let mut hs_r = Handshake::default();
        assert!(consume_initiation_peer(first, &init, &mut hs_r, &ss_r, now));
        assert_eq!(hs_r.remote_index, 11);

        // The same initiation again is a replay.
        let first = consume_initiation_static(&init, &r.private, &r.public).unwrap();
        assert!(!consume_initiation_peer(
            first,
            &init,
            &mut hs_r,
            &ss_r,
            now + std::time::Duration::from_secs(1)
        ));

        let resp = create_response(
            &mut hs_r,
            &keys(&r, &i, &ss_r, &psk),
            22,
            crypto::generate_private_key(),
        )
        .unwrap();
        assert_eq!(resp.receiver, 11);
        assert!(consume_response(
            &mut hs_i,
            &resp,
            &keys(&i, &r, &ss_i, &psk)
        ));
        let ki = begin_session(&mut hs_i).unwrap();
        let kr = begin_session(&mut hs_r).unwrap();
        assert!(ki.initiator && !kr.initiator);
        assert_eq!(ki.send, kr.recv);
        assert_eq!(ki.recv, kr.send);
        assert_ne!(ki.send, ki.recv);
        assert_eq!((ki.local_index, ki.remote_index), (11, 22));
        assert_eq!((kr.local_index, kr.remote_index), (22, 11));
        assert_eq!(hs_i.state, HandshakeState::Zeroed);
        // The replay guard survives the session.
        assert_eq!(hs_r.latest_timestamp, Tai64n::from_unix(1000, 0));
    }

    #[test]
    fn wrong_psk_fails_the_response() {
        let i = party(1);
        let r = party(2);
        let ss = crypto::dh(&i.private, &r.public).unwrap();
        let now = Instant::now();
        let mut hs_i = Handshake::default();
        let init = create_initiation(
            &mut hs_i,
            &keys(&i, &r, &ss, &[1; 32]),
            1,
            Tai64n::from_unix(1, 0),
            crypto::generate_private_key(),
        )
        .unwrap();
        let first = consume_initiation_static(&init, &r.private, &r.public).unwrap();
        let mut hs_r = Handshake::default();
        assert!(consume_initiation_peer(first, &init, &mut hs_r, &ss, now));
        let resp = create_response(
            &mut hs_r,
            &keys(&r, &i, &ss, &[2; 32]),
            2,
            crypto::generate_private_key(),
        )
        .unwrap();
        assert!(!consume_response(
            &mut hs_i,
            &resp,
            &keys(&i, &r, &ss, &[1; 32])
        ));
    }

    #[test]
    fn initiations_from_a_peer_are_rate_limited() {
        let i = party(1);
        let r = party(2);
        let ss = crypto::dh(&i.private, &r.public).unwrap();
        let now = Instant::now();
        let mut hs_r = Handshake::default();
        let send = |secs: u64, at: Instant, hs_r: &mut Handshake| {
            let mut hs_i = Handshake::default();
            let init = create_initiation(
                &mut hs_i,
                &keys(&i, &r, &ss, &[0; 32]),
                1,
                Tai64n::from_unix(secs, 0),
                crypto::generate_private_key(),
            )
            .unwrap();
            let first = consume_initiation_static(&init, &r.private, &r.public).unwrap();
            consume_initiation_peer(first, &init, hs_r, &ss, at)
        };
        assert!(send(10, now, &mut hs_r));
        // A newer timestamp, but only 10 ms later: a flood.
        assert!(!send(
            11,
            now + std::time::Duration::from_millis(10),
            &mut hs_r
        ));
        assert!(send(
            12,
            now + std::time::Duration::from_millis(20),
            &mut hs_r
        ));
    }
}
