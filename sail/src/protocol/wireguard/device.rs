//! The sans-IO WireGuard device: peers, cryptokey routing, handshakes,
//! sessions and timers, with no sockets and no clock of its own.
//!
//! The caller feeds it:
//! - [`Device::encapsulate`]: an IP packet from the inside, routed to a
//!   peer by its destination, returning datagrams to send;
//! - [`Device::handle_incoming`]: a UDP datagram from the outside, returning
//!   a datagram to write back, an IP packet to deliver, or nothing;
//! - [`Device::tick`]: the passage of time, at [`Device::next_deadline`]
//!   at the latest, returning datagrams the timers send.
//!
//! and drains [`Device::poll_transmit`] after each call: datagrams a
//! handshake released that are not a reply to the datagram at hand (packets
//! staged while waiting for the session, or the keepalive that confirms it).
//!
//! Behaviour follows the whitepaper and Linux's drivers/net/wireguard: the
//! same timers, the same keypair rotation, the same checks.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

use super::allowed_ips::AllowedIps;
use super::cookie::{CookieChecker, CookieGenerator, MacState};
use super::crypto::{self, KEY_LEN};
use super::keypair::{Keypair, Keypairs};
use super::messages::{
    self, CookieReply, DataHeader, Initiation, Response, DATA_HEADER_LEN, INITIATION_LEN,
    RESPONSE_LEN, TYPE_COOKIE_REPLY, TYPE_DATA, TYPE_INITIATION, TYPE_RESPONSE,
};
use super::noise::{self, Handshake, HandshakeState, PeerKeys};
use super::ratelimiter::RateLimiter;
use super::tai64n::Tai64n;
use super::timers::*;

/// The MTU Linux and wg-quick default to.
pub const DEFAULT_MTU: usize = 1420;
/// Handshake messages a second above which the device is under load, as
/// Linux's MAX_QUEUED_INCOMING_HANDSHAKES / 8.
pub const DEFAULT_UNDER_LOAD_THRESHOLD: u32 = 512;
/// A device stays under load this long after the rate drops.
const UNDER_LOAD_STICKY: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct DeviceConfig {
    pub private_key: [u8; KEY_LEN],
    /// The inner MTU: plaintexts are padded to a multiple of 16 up to it.
    pub mtu: usize,
    /// Handshake messages per second from which the device demands
    /// cookies. Zero: always.
    pub under_load_threshold: u32,
}

impl DeviceConfig {
    pub fn new(private_key: [u8; KEY_LEN]) -> Self {
        DeviceConfig {
            private_key,
            mtu: DEFAULT_MTU,
            under_load_threshold: DEFAULT_UNDER_LOAD_THRESHOLD,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub public_key: [u8; KEY_LEN],
    pub preshared_key: Option<[u8; KEY_LEN]>,
    /// Where to send; learnt from the peer's authenticated packets when
    /// absent, and updated by them when present (roaming).
    pub endpoint: Option<SocketAddr>,
    /// Prefixes routed to this peer, and accepted as inner sources from it.
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub persistent_keepalive: Option<Duration>,
    /// The three bytes after the type of every message sent to this peer.
    /// Zero for WireGuard; Cloudflare WARP's client identifier.
    pub reserved: [u8; 3],
}

impl PeerConfig {
    pub fn new(public_key: [u8; KEY_LEN]) -> Self {
        PeerConfig {
            public_key,
            preshared_key: None,
            endpoint: None,
            allowed_ips: Vec::new(),
            persistent_keepalive: None,
            reserved: [0; 3],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(u32);

/// A datagram to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// The peer it is for, when known: a cookie reply goes to an address.
    pub peer: Option<PeerId>,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// What an incoming datagram produced.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    /// A handshake response or cookie reply, to send back.
    WriteBack(Transmit),
    /// An IP packet from `peer`, its source checked against the peer's
    /// allowed IPs and any padding trimmed.
    Deliver { peer: PeerId, packet: Vec<u8> },
    /// Consumed, or dropped.
    Nothing,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("not an IP packet")]
    NotIp,
    #[error("no peer's allowed IPs contain {0}")]
    NoRoute(IpAddr),
    #[error("no such peer")]
    UnknownPeer,
    #[error("a peer with this public key already exists")]
    DuplicatePeer,
    #[error("a peer cannot have the device's own public key")]
    OwnKey,
    #[error("invalid allowed IP prefix {0}/{1}")]
    InvalidPrefix(IpAddr, u8),
}

/// A peer's state, for status output.
#[derive(Clone, Debug)]
pub struct PeerStats {
    pub public_key: [u8; KEY_LEN],
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<Instant>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Whether a current session can send.
    pub has_session: bool,
}

/// Device state peers share: keys, the index table, the clock.
struct Shared {
    private_key: [u8; KEY_LEN],
    public_key: [u8; KEY_LEN],
    mtu: usize,
    /// Our session indices: handshakes and keypairs, to their peer.
    indices: HashMap<u32, PeerId>,
    /// Maps the monotonic `now` the caller passes to wall time, for
    /// TAI64N. Anchored once, so a fake clock moves timestamps too.
    anchor: (Instant, SystemTime),
}

impl Shared {
    fn alloc_index(&mut self, peer: PeerId) -> u32 {
        loop {
            let i = crypto::random_u32();
            if i != 0 && !self.indices.contains_key(&i) {
                self.indices.insert(i, peer);
                return i;
            }
        }
    }

    fn release(&mut self, index: u32) {
        self.indices.remove(&index);
    }

    fn timestamp(&self, now: Instant) -> Tai64n {
        let (i0, w0) = self.anchor;
        let wall = if now >= i0 {
            w0 + (now - i0)
        } else {
            w0 - (i0 - now)
        };
        Tai64n::from_system_time(wall)
    }
}

struct Peer {
    id: PeerId,
    public_key: [u8; KEY_LEN],
    preshared_key: [u8; KEY_LEN],
    static_static: [u8; KEY_LEN],
    endpoint: Option<SocketAddr>,
    reserved: [u8; 3],
    persistent_keepalive: Option<Duration>,
    handshake: Handshake,
    keypairs: Keypairs,
    cookie: CookieGenerator,
    timers: PeerTimers,
    staged: VecDeque<Vec<u8>>,
    last_sent_handshake: Option<Instant>,
    last_handshake: Option<Instant>,
    rx_bytes: u64,
    tx_bytes: u64,
}

impl Drop for Peer {
    fn drop(&mut self) {
        crypto::wipe(&mut self.preshared_key);
        crypto::wipe(&mut self.static_static);
    }
}

fn expired(birth: Option<Instant>, after: Duration, now: Instant) -> bool {
    birth.is_none_or(|b| now.saturating_duration_since(b) >= after)
}

/// A peer's [`PeerKeys`], borrowing fields one by one so that the
/// handshake beside them can be borrowed mutably.
macro_rules! peer_keys {
    ($s:expr, $peer:expr) => {
        PeerKeys {
            local_private: &$s.private_key,
            local_public: &$s.public_key,
            remote_public: &$peer.public_key,
            static_static: &$peer.static_static,
            preshared_key: &$peer.preshared_key,
        }
    };
}

impl Peer {
    // Timer events, named as in Linux's timers.c.

    fn timers_any_authenticated_packet_traversal(&mut self, now: Instant) {
        if let Some(interval) = self.persistent_keepalive {
            self.timers.persistent_keepalive.set(now + interval);
        }
    }

    fn timers_any_authenticated_packet_sent(&mut self) {
        self.timers.send_keepalive.clear();
    }

    fn timers_any_authenticated_packet_received(&mut self) {
        self.timers.new_handshake.clear();
    }

    fn timers_handshake_initiated(&mut self, now: Instant) {
        self.timers
            .retransmit_handshake
            .set(now + REKEY_TIMEOUT + jitter());
    }

    fn timers_handshake_complete(&mut self, now: Instant) {
        self.timers.retransmit_handshake.clear();
        self.timers.handshake_attempts = 0;
        self.timers.sent_lastminute_handshake = false;
        self.last_handshake = Some(now);
    }

    fn timers_session_derived(&mut self, now: Instant) {
        self.timers
            .zero_key_material
            .set(now + REJECT_AFTER_TIME * 3);
    }

    fn timers_data_sent(&mut self, now: Instant) {
        if !self.timers.new_handshake.is_pending() {
            self.timers
                .new_handshake
                .set(now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + jitter());
        }
    }

    fn timers_data_received(&mut self, now: Instant) {
        if !self.timers.send_keepalive.is_pending() {
            self.timers.send_keepalive.set(now + KEEPALIVE_TIMEOUT);
        } else {
            self.timers.need_another_keepalive = true;
        }
    }

    /// Frees the handshake's index, if it has one of its own.
    fn release_handshake_index(&mut self, s: &mut Shared) {
        if let Some(i) = self.handshake.local_index.take() {
            s.release(i);
        }
    }

    /// wg_packet_send_queued_handshake_initiation and
    /// wg_packet_send_handshake_initiation: at most one initiation per
    /// REKEY_TIMEOUT.
    fn send_initiation(
        &mut self,
        s: &mut Shared,
        now: Instant,
        is_retry: bool,
        out: &mut Vec<Transmit>,
    ) {
        if !is_retry {
            self.timers.handshake_attempts = 0;
        }
        if !expired(self.last_sent_handshake, REKEY_TIMEOUT, now) {
            return;
        }
        let Some(dst) = self.endpoint else {
            return;
        };
        self.release_handshake_index(s);
        let index = s.alloc_index(self.id);
        let timestamp = s.timestamp(now);
        let init = noise::create_initiation(
            &mut self.handshake,
            &peer_keys!(s, self),
            index,
            timestamp,
            crypto::generate_private_key(),
        );
        let Some(mut init) = init else {
            s.release(index);
            self.handshake.local_index = None;
            return;
        };
        init.reserved = self.reserved;
        let mut bytes = init.to_bytes();
        self.cookie.add_macs(&mut bytes, now);
        self.timers_any_authenticated_packet_traversal(now);
        self.timers_any_authenticated_packet_sent();
        self.last_sent_handshake = Some(now);
        self.tx_bytes += bytes.len() as u64;
        out.push(Transmit {
            peer: Some(self.id),
            dst,
            payload: bytes.to_vec(),
        });
        self.timers_handshake_initiated(now);
    }

    fn stage(&mut self, packet: Vec<u8>) {
        if self.staged.len() >= MAX_STAGED_PACKETS {
            self.staged.pop_front();
        }
        self.staged.push_back(packet);
    }

    /// wg_packet_send_staged_packets: encrypts what is staged with the
    /// current keypair, or starts a handshake if there is none fit to send.
    fn send_staged(&mut self, s: &mut Shared, now: Instant, out: &mut Vec<Transmit>) {
        if self.staged.is_empty() {
            return;
        }
        let usable = self
            .keypairs
            .current
            .as_mut()
            .is_some_and(|kp| kp.can_send(now));
        if !usable {
            self.send_initiation(s, now, false, out);
            return;
        }
        let Some(dst) = self.endpoint else {
            return;
        };
        let (mut sent_any, mut sent_data) = (false, false);
        while let Some(packet) = self.staged.pop_front() {
            let kp = self.keypairs.current.as_mut().expect("checked usable");
            let Some(counter) = kp.next_counter() else {
                self.staged.push_front(packet);
                self.send_initiation(s, now, false, out);
                break;
            };
            let datagram = encrypt(kp, counter, &packet, self.reserved, s.mtu);
            self.tx_bytes += datagram.len() as u64;
            out.push(Transmit {
                peer: Some(self.id),
                dst,
                payload: datagram,
            });
            sent_any = true;
            sent_data |= !packet.is_empty();
        }
        if sent_any {
            self.timers_any_authenticated_packet_traversal(now);
            self.timers_any_authenticated_packet_sent();
            if sent_data {
                self.timers_data_sent(now);
            }
        }
        self.keep_key_fresh_send(s, now, out);
    }

    fn send_keepalive(&mut self, s: &mut Shared, now: Instant, out: &mut Vec<Transmit>) {
        if self.staged.is_empty() {
            self.staged.push_back(Vec::new());
        }
        self.send_staged(s, now, out);
    }

    /// Rekey after REKEY_AFTER_MESSAGES, or REKEY_AFTER_TIME as initiator.
    fn keep_key_fresh_send(&mut self, s: &mut Shared, now: Instant, out: &mut Vec<Transmit>) {
        let rekey = self.keypairs.current.as_ref().is_some_and(|kp| {
            kp.send_marked_valid()
                && (kp.send_counter() > REKEY_AFTER_MESSAGES
                    || (kp.initiator && expired(Some(kp.birth), REKEY_AFTER_TIME, now)))
        });
        if rekey {
            self.send_initiation(s, now, false, out);
        }
    }

    /// As initiator, rekey once the session nears REJECT_AFTER_TIME, even
    /// if we only receive.
    fn keep_key_fresh_receive(&mut self, s: &mut Shared, now: Instant, out: &mut Vec<Transmit>) {
        if self.timers.sent_lastminute_handshake {
            return;
        }
        let rekey = self.keypairs.current.as_ref().is_some_and(|kp| {
            kp.send_marked_valid()
                && kp.initiator
                && expired(
                    Some(kp.birth),
                    REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT,
                    now,
                )
        });
        if rekey {
            self.timers.sent_lastminute_handshake = true;
            self.send_initiation(s, now, false, out);
        }
    }

    /// Installs a session, releasing the indices of keypairs it evicts.
    fn install(&mut self, s: &mut Shared, kp: Keypair) {
        for i in self.keypairs.add(kp) {
            s.release(i);
        }
    }

    fn zero_key_material(&mut self, s: &mut Shared) {
        for i in self.keypairs.clear() {
            s.release(i);
        }
        self.release_handshake_index(s);
        self.handshake.zero();
    }

    fn tick(&mut self, s: &mut Shared, now: Instant, out: &mut Vec<Transmit>) {
        if self.timers.retransmit_handshake.fire(now) {
            if self.timers.handshake_attempts > MAX_TIMER_HANDSHAKES {
                tracing::debug!(
                    "wireguard: handshake did not complete after {} attempts, giving up",
                    MAX_TIMER_HANDSHAKES + 2
                );
                self.timers.send_keepalive.clear();
                self.staged.clear();
                if !self.timers.zero_key_material.is_pending() {
                    self.timers
                        .zero_key_material
                        .set(now + REJECT_AFTER_TIME * 3);
                }
            } else {
                self.timers.handshake_attempts += 1;
                self.send_initiation(s, now, true, out);
            }
        }
        if self.timers.send_keepalive.fire(now) {
            self.send_keepalive(s, now, out);
            if self.timers.need_another_keepalive {
                self.timers.need_another_keepalive = false;
                self.timers.send_keepalive.set(now + KEEPALIVE_TIMEOUT);
            }
        }
        if self.timers.new_handshake.fire(now) {
            self.send_initiation(s, now, false, out);
        }
        if self.timers.zero_key_material.fire(now) {
            self.zero_key_material(s);
        }
        if self.timers.persistent_keepalive.fire(now) && self.persistent_keepalive.is_some() {
            self.send_keepalive(s, now, out);
        }
    }
}

/// A transport data message carrying `packet`, padded.
fn encrypt(
    kp: &mut Keypair,
    counter: u64,
    packet: &[u8],
    reserved: [u8; 3],
    mtu: usize,
) -> Vec<u8> {
    let padded = packet.len() + messages::padding(packet.len(), mtu);
    let mut buf = vec![0u8; DATA_HEADER_LEN + padded + crypto::TAG_LEN];
    DataHeader {
        receiver: kp.remote_index,
        counter,
    }
    .write(&mut buf, reserved);
    buf[DATA_HEADER_LEN..DATA_HEADER_LEN + packet.len()].copy_from_slice(packet);
    kp.seal(counter, &mut buf[DATA_HEADER_LEN..]);
    buf
}

/// The destination of an IP packet.
fn ip_destination(p: &[u8]) -> Option<IpAddr> {
    match p.first()? >> 4 {
        4 if p.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(&p[16..20]).ok()?,
        ))),
        6 if p.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&p[24..40]).ok()?,
        ))),
        _ => None,
    }
}

/// The source and real length of a decrypted IP packet, whose tail may be
/// padding.
fn ip_source_and_len(p: &[u8]) -> Option<(IpAddr, usize)> {
    match p.first()? >> 4 {
        4 if p.len() >= 20 => {
            let len = u16::from_be_bytes([p[2], p[3]]) as usize;
            if len < 20 || len > p.len() {
                return None;
            }
            let src = <[u8; 4]>::try_from(&p[12..16]).ok()?;
            Some((IpAddr::V4(src.into()), len))
        }
        6 if p.len() >= 40 => {
            let len = 40 + u16::from_be_bytes([p[4], p[5]]) as usize;
            if len > p.len() {
                return None;
            }
            let src = <[u8; 16]>::try_from(&p[8..24]).ok()?;
            Some((IpAddr::V6(src.into()), len))
        }
        _ => None,
    }
}

pub struct Device {
    s: Shared,
    peers: Vec<Option<Peer>>,
    by_key: HashMap<[u8; KEY_LEN], PeerId>,
    routes: AllowedIps<PeerId>,
    cookie_checker: CookieChecker,
    rate_limiter: RateLimiter,
    under_load_threshold: u32,
    handshake_window: (Option<Instant>, u32),
    last_under_load: Option<Instant>,
    pending: VecDeque<Transmit>,
    /// The earliest deadline the caller was last told of.
    deadline_hint: Option<Instant>,
    deadline_moved: bool,
}

impl Device {
    /// A device with no peers. `now` anchors the mapping from the monotonic
    /// times the caller passes to wall time, for handshake timestamps.
    pub fn new(config: DeviceConfig, now: Instant) -> Self {
        let public_key = crypto::public_key(&config.private_key);
        Device {
            s: Shared {
                private_key: config.private_key,
                public_key,
                mtu: config.mtu,
                indices: HashMap::new(),
                anchor: (now, SystemTime::now()),
            },
            peers: Vec::new(),
            by_key: HashMap::new(),
            routes: AllowedIps::new(),
            cookie_checker: CookieChecker::new(&public_key),
            rate_limiter: RateLimiter::default(),
            under_load_threshold: config.under_load_threshold,
            handshake_window: (None, 0),
            last_under_load: None,
            pending: VecDeque::new(),
            deadline_hint: None,
            deadline_moved: false,
        }
    }

    pub fn public_key(&self) -> [u8; KEY_LEN] {
        self.s.public_key
    }

    pub fn add_peer(&mut self, config: PeerConfig) -> Result<PeerId, Error> {
        if config.public_key == self.s.public_key {
            return Err(Error::OwnKey);
        }
        if self.by_key.contains_key(&config.public_key) {
            return Err(Error::DuplicatePeer);
        }
        for &(ip, len) in &config.allowed_ips {
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if len > max {
                return Err(Error::InvalidPrefix(ip, len));
            }
        }
        let slot = match self.peers.iter().position(Option::is_none) {
            Some(i) => i,
            None => {
                self.peers.push(None);
                self.peers.len() - 1
            }
        };
        let id = PeerId(slot as u32);
        // A peer whose DH with us is zero can never handshake; Linux keeps
        // it and fails every handshake, as the zero value does here.
        let static_static =
            crypto::dh(&self.s.private_key, &config.public_key).unwrap_or([0; KEY_LEN]);
        let mut timers = PeerTimers::default();
        if config.persistent_keepalive.is_some() {
            // Linux sends a keepalive as soon as persistent keepalive is
            // configured on a running interface: on the next tick.
            timers.persistent_keepalive.set(self.s.anchor.0);
        }
        for &(ip, len) in &config.allowed_ips {
            self.routes.insert(ip, len, id);
        }
        self.peers[slot] = Some(Peer {
            id,
            public_key: config.public_key,
            preshared_key: config.preshared_key.unwrap_or([0; KEY_LEN]),
            static_static,
            endpoint: config.endpoint,
            reserved: config.reserved,
            persistent_keepalive: config.persistent_keepalive.filter(|d| !d.is_zero()),
            handshake: Handshake::default(),
            keypairs: Keypairs::default(),
            cookie: CookieGenerator::new(&config.public_key),
            timers,
            staged: VecDeque::new(),
            last_sent_handshake: None,
            last_handshake: None,
            rx_bytes: 0,
            tx_bytes: 0,
        });
        self.by_key.insert(config.public_key, id);
        self.note(id);
        Ok(id)
    }

    pub fn remove_peer(&mut self, id: PeerId) -> Result<(), Error> {
        let mut peer = self
            .peers
            .get_mut(id.0 as usize)
            .and_then(Option::take)
            .ok_or(Error::UnknownPeer)?;
        peer.zero_key_material(&mut self.s);
        self.routes.remove(&id);
        self.by_key.remove(&peer.public_key);
        self.pending.retain(|t| t.peer != Some(id));
        Ok(())
    }

    pub fn peer_by_key(&self, public_key: &[u8; KEY_LEN]) -> Option<PeerId> {
        self.by_key.get(public_key).copied()
    }

    pub fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peers.iter().flatten().map(|p| p.id)
    }

    pub fn peer_stats(&self, id: PeerId) -> Option<PeerStats> {
        let p = self.peer(id)?;
        Some(PeerStats {
            public_key: p.public_key,
            endpoint: p.endpoint,
            last_handshake: p.last_handshake,
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
            has_session: p
                .keypairs
                .current
                .as_ref()
                .is_some_and(|k| k.send_marked_valid()),
        })
    }

    /// Sets a peer's endpoint, as `wg set ... endpoint`.
    pub fn set_endpoint(&mut self, id: PeerId, endpoint: SocketAddr) -> Result<(), Error> {
        self.peer_mut(id).ok_or(Error::UnknownPeer)?.endpoint = Some(endpoint);
        Ok(())
    }

    /// The prefixes routed to a peer.
    pub fn allowed_ips(&self, id: PeerId) -> Vec<(IpAddr, u8)> {
        self.routes.prefixes_of(&id)
    }

    fn peer(&self, id: PeerId) -> Option<&Peer> {
        self.peers.get(id.0 as usize)?.as_ref()
    }

    fn peer_mut(&mut self, id: PeerId) -> Option<&mut Peer> {
        self.peers.get_mut(id.0 as usize)?.as_mut()
    }

    /// Records that a peer's timers may have moved earlier than the caller
    /// last learnt from [`Device::next_deadline`].
    fn note(&mut self, id: PeerId) {
        let Some(d) = self.peer(id).and_then(|p| p.timers.earliest()) else {
            return;
        };
        if self.deadline_hint.is_none_or(|h| d < h) {
            self.deadline_hint = Some(d);
            self.deadline_moved = true;
        }
    }

    /// The earliest timer deadline, by which [`Device::tick`] is due.
    pub fn next_deadline(&mut self) -> Option<Instant> {
        let d = self
            .peers
            .iter()
            .flatten()
            .filter_map(|p| p.timers.earliest())
            .min();
        self.deadline_hint = d;
        self.deadline_moved = false;
        d
    }

    /// Whether a call since the last [`Device::next_deadline`] armed a
    /// timer earlier than it returned; clears the flag. An async shell uses
    /// it to wake its timer task only when needed.
    pub fn take_deadline_moved(&mut self) -> bool {
        std::mem::take(&mut self.deadline_moved)
    }

    /// A datagram produced by [`Device::handle_incoming`] besides its
    /// return value.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.pending.pop_front()
    }

    /// Runs expired timers.
    pub fn tick(&mut self, now: Instant) -> Vec<Transmit> {
        let mut out = Vec::new();
        for peer in self.peers.iter_mut().flatten() {
            peer.tick(&mut self.s, now, &mut out);
        }
        out
    }

    /// Routes an IP packet to the peer whose allowed IPs hold its
    /// destination, and encrypts it, or stages it and starts a handshake.
    pub fn encapsulate(&mut self, now: Instant, packet: &[u8]) -> Result<Vec<Transmit>, Error> {
        let dst = ip_destination(packet).ok_or(Error::NotIp)?;
        let id = *self.routes.lookup(dst).ok_or(Error::NoRoute(dst))?;
        self.send_to_peer(now, id, packet)
    }

    /// Encrypts an IP packet for a given peer, bypassing routing.
    pub fn send_to_peer(
        &mut self,
        now: Instant,
        id: PeerId,
        packet: &[u8],
    ) -> Result<Vec<Transmit>, Error> {
        let mut out = Vec::new();
        let peer = self
            .peers
            .get_mut(id.0 as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::UnknownPeer)?;
        peer.stage(packet.to_vec());
        peer.send_staged(&mut self.s, now, &mut out);
        self.note(id);
        Ok(out)
    }

    /// Starts a handshake with a peer now, unless one went out within
    /// REKEY_TIMEOUT.
    pub fn initiate(&mut self, now: Instant, id: PeerId) -> Result<Vec<Transmit>, Error> {
        let mut out = Vec::new();
        let peer = self
            .peers
            .get_mut(id.0 as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::UnknownPeer)?;
        peer.send_initiation(&mut self.s, now, false, &mut out);
        self.note(id);
        Ok(out)
    }

    /// Takes a datagram from `src`.
    pub fn handle_incoming(&mut self, now: Instant, src: SocketAddr, datagram: &[u8]) -> Incoming {
        match datagram.first() {
            Some(&TYPE_INITIATION) if datagram.len() == INITIATION_LEN => {
                self.handle_handshake(now, src, datagram)
            }
            Some(&TYPE_RESPONSE) if datagram.len() == RESPONSE_LEN => {
                self.handle_handshake(now, src, datagram)
            }
            Some(&TYPE_COOKIE_REPLY) => {
                self.handle_cookie_reply(now, datagram);
                Incoming::Nothing
            }
            Some(&TYPE_DATA) => self.handle_data(now, src, datagram),
            _ => Incoming::Nothing,
        }
    }

    fn under_load(&mut self, now: Instant) -> bool {
        let (start, count) = &mut self.handshake_window;
        if expired(*start, Duration::from_secs(1), now) {
            *start = Some(now);
            *count = 0;
        }
        let loaded = *count >= self.under_load_threshold;
        *count = count.saturating_add(1);
        if loaded {
            self.last_under_load = Some(now);
            return true;
        }
        !expired(self.last_under_load, UNDER_LOAD_STICKY, now)
    }

    fn handle_handshake(&mut self, now: Instant, src: SocketAddr, datagram: &[u8]) -> Incoming {
        let under_load = self.under_load(now);
        let rl = &mut self.rate_limiter;
        let state = self
            .cookie_checker
            .validate(datagram, src, under_load, now, || rl.allow(src.ip(), now));
        let needs_cookie = match (under_load, state) {
            (true, MacState::ValidMacWithCookie) | (false, MacState::ValidMacButNoCookie) => false,
            (true, MacState::ValidMacButNoCookie) => true,
            _ => return Incoming::Nothing,
        };
        if needs_cookie {
            // Both handshake messages have the sender index at offset 4.
            let sender = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
            let reply = self.cookie_checker.create_reply(datagram, sender, src, now);
            return Incoming::WriteBack(Transmit {
                peer: None,
                dst: src,
                payload: reply.to_bytes().to_vec(),
            });
        }
        let result = if datagram[0] == TYPE_INITIATION {
            self.handle_initiation(now, src, datagram)
        } else {
            self.handle_response(now, src, datagram)
        };
        let Some((id, result)) = result else {
            return Incoming::Nothing;
        };
        if let Some(peer) = self.peer_mut(id) {
            peer.timers_any_authenticated_packet_received();
            peer.timers_any_authenticated_packet_traversal(now);
        }
        self.note(id);
        result
    }

    fn handle_initiation(
        &mut self,
        now: Instant,
        src: SocketAddr,
        datagram: &[u8],
    ) -> Option<(PeerId, Incoming)> {
        let msg = Initiation::parse(datagram)?;
        let first =
            noise::consume_initiation_static(&msg, &self.s.private_key, &self.s.public_key)?;
        let id = *self.by_key.get(&first.remote_static)?;
        let peer = self.peers[id.0 as usize].as_mut()?;
        if !noise::consume_initiation_peer(
            first,
            &msg,
            &mut peer.handshake,
            &peer.static_static,
            now,
        ) {
            return None;
        }
        peer.endpoint = Some(src);
        peer.rx_bytes += datagram.len() as u64;

        // wg_packet_send_handshake_response.
        peer.last_sent_handshake = Some(now);
        peer.release_handshake_index(&mut self.s);
        let index = self.s.alloc_index(id);
        let resp = noise::create_response(
            &mut peer.handshake,
            &peer_keys!(self.s, peer),
            index,
            crypto::generate_private_key(),
        );
        let Some(mut resp) = resp else {
            self.s.release(index);
            peer.handshake.zero();
            return None;
        };
        resp.reserved = peer.reserved;
        let mut bytes = resp.to_bytes();
        peer.cookie.add_macs(&mut bytes, now);
        let keys = noise::begin_session(&mut peer.handshake)?;
        let kp = Keypair::new(&keys, now);
        peer.install(&mut self.s, kp);
        peer.timers_session_derived(now);
        peer.timers_any_authenticated_packet_traversal(now);
        peer.timers_any_authenticated_packet_sent();
        peer.tx_bytes += bytes.len() as u64;
        Some((
            id,
            Incoming::WriteBack(Transmit {
                peer: Some(id),
                dst: src,
                payload: bytes.to_vec(),
            }),
        ))
    }

    fn handle_response(
        &mut self,
        now: Instant,
        src: SocketAddr,
        datagram: &[u8],
    ) -> Option<(PeerId, Incoming)> {
        let msg = Response::parse(datagram)?;
        let id = *self.s.indices.get(&msg.receiver)?;
        let peer = self.peers[id.0 as usize].as_mut()?;
        if peer.handshake.local_index != Some(msg.receiver)
            || peer.handshake.state != HandshakeState::CreatedInitiation
        {
            return None;
        }
        if !noise::consume_response(&mut peer.handshake, &msg, &peer_keys!(self.s, peer)) {
            return None;
        }
        peer.endpoint = Some(src);
        peer.rx_bytes += datagram.len() as u64;
        let keys = noise::begin_session(&mut peer.handshake)?;
        let kp = Keypair::new(&keys, now);
        peer.install(&mut self.s, kp);
        peer.timers_session_derived(now);
        peer.timers_handshake_complete(now);
        // Confirms the session to the responder: the staged packets, or a
        // keepalive.
        let mut out = Vec::new();
        peer.send_keepalive(&mut self.s, now, &mut out);
        self.pending.extend(out);
        Some((id, Incoming::Nothing))
    }

    fn handle_cookie_reply(&mut self, now: Instant, datagram: &[u8]) {
        let Some(msg) = CookieReply::parse(datagram) else {
            return;
        };
        let Some(&id) = self.s.indices.get(&msg.receiver) else {
            return;
        };
        if let Some(peer) = self.peer_mut(id) {
            if peer.cookie.consume_reply(&msg, now) {
                tracing::debug!("wireguard: took a cookie from {:?}", peer.endpoint);
            }
        }
    }

    fn handle_data(&mut self, now: Instant, src: SocketAddr, datagram: &[u8]) -> Incoming {
        let Some(header) = DataHeader::parse(datagram) else {
            return Incoming::Nothing;
        };
        let Some(&id) = self.s.indices.get(&header.receiver) else {
            return Incoming::Nothing;
        };
        let Some(peer) = self.peers[id.0 as usize].as_mut() else {
            return Incoming::Nothing;
        };
        let Some((slot, kp)) = peer.keypairs.find(header.receiver) else {
            return Incoming::Nothing;
        };
        if !kp.can_receive(now) {
            return Incoming::Nothing;
        }
        let mut buf = datagram[DATA_HEADER_LEN..].to_vec();
        if !kp.open(header.counter, &mut buf) {
            return Incoming::Nothing;
        }
        if !kp.replay.check_and_update(header.counter) {
            return Incoming::Nothing;
        }
        buf.truncate(buf.len() - crypto::TAG_LEN);

        let mut out = Vec::new();
        let (confirmed, dropped) = peer.keypairs.received_with(slot);
        if let Some(i) = dropped {
            self.s.release(i);
        }
        if confirmed {
            peer.timers_handshake_complete(now);
            peer.send_staged(&mut self.s, now, &mut out);
        }
        peer.endpoint = Some(src);
        peer.rx_bytes += datagram.len() as u64;
        peer.keep_key_fresh_receive(&mut self.s, now, &mut out);
        peer.timers_any_authenticated_packet_received();
        peer.timers_any_authenticated_packet_traversal(now);
        self.pending.extend(out);

        if buf.is_empty() {
            self.note(id);
            return Incoming::Nothing;
        }
        peer.timers_data_received(now);
        self.note(id);

        let Some((source, len)) = ip_source_and_len(&buf) else {
            return Incoming::Nothing;
        };
        if self.routes.lookup(source) != Some(&id) {
            tracing::debug!(
                "wireguard: dropping a packet from {} not in the peer's allowed IPs",
                source
            );
            return Incoming::Nothing;
        }
        buf.truncate(len);
        Incoming::Deliver {
            peer: id,
            packet: buf,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
