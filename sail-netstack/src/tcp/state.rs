use std::fmt;

use super::{NewReno, RtoEstimator};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SeqNumber(u32);

impl SeqNumber {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn wrapping_add(self, amount: usize) -> Self {
        let bytes = amount.to_le_bytes();
        let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Self(self.0.wrapping_add(low))
    }

    #[must_use]
    pub const fn before(self, other: Self) -> bool {
        i32::from_ne_bytes(self.0.wrapping_sub(other.0).to_ne_bytes()) < 0
    }

    #[must_use]
    pub const fn after(self, other: Self) -> bool {
        other.before(self)
    }

    #[must_use]
    pub const fn distance_from(self, earlier: Self) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const ACK: Self = Self(0x10);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & 0x1f)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegmentMeta {
    pub sequence: SeqNumber,
    pub acknowledgment: Option<SeqNumber>,
    pub flags: TcpFlags,
    pub window: u32,
    pub payload_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppEvent {
    Consumed(usize),
    Send(usize),
    Close,
    Abort,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimerEvent {
    Retransmission,
    DelayedAck,
    Persist,
    Keepalive,
    TimeWaitExpired,
    /// An orphaned flow waited too long in FIN-WAIT-2 for the peer's FIN.
    FinWait2Timeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpState {
    /// Active open: our SYN is out, no SYN from the peer yet.
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    CloseWait,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendControl {
    pub sequence: SeqNumber,
    pub acknowledgment: SeqNumber,
    pub flags: TcpFlags,
    pub window: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpAction {
    Send(SendControl),
    DefensiveAck(SendControl),
    SendPayload(SendControl),
    RetransmitPayload(SendControl),
    DeliverPayload {
        len: usize,
    },
    /// A passive open completed its handshake.
    Accepted,
    /// An active open completed its handshake.
    Connected,
    PeerHalfClosed,
    ArmRetransmission {
        after_ms: u64,
    },
    DisarmRetransmission,
    ArmDelayedAck,
    DisarmDelayedAck,
    ArmTimeWait,
    ChallengeAck,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpError {
    InvalidSyn,
    ReceiveCreditExceeded,
    ConsumedBeyondBuffered,
    InvalidSendState,
    SendWindowExceeded,
    SendOutstanding,
    Closed,
}

impl fmt::Display for TcpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSyn => formatter.write_str("invalid initial SYN"),
            Self::ReceiveCreditExceeded => formatter.write_str("TCP receive credit exceeded"),
            Self::ConsumedBeyondBuffered => {
                formatter.write_str("application consumed beyond buffered TCP bytes")
            }
            Self::InvalidSendState => formatter.write_str("TCP state does not permit sending"),
            Self::SendWindowExceeded => formatter.write_str("TCP peer window is too small"),
            Self::SendOutstanding => formatter.write_str("TCP payload is already in flight"),
            Self::Closed => formatter.write_str("TCP control block is closed"),
        }
    }
}

impl std::error::Error for TcpError {}

fn advertisable_receive_capacity(available: usize, window_scale: u8) -> usize {
    let quantum = 1_usize << window_scale.min(14);
    let representable = usize::from(u16::MAX) * quantum;
    available.min(representable) / quantum * quantum
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpTcb {
    state: TcpState,
    recv_next: SeqNumber,
    send_unacked: SeqNumber,
    send_next: SeqNumber,
    recv_capacity: usize,
    recv_buffered: usize,
    advertised_right_edge: SeqNumber,
    window_update_threshold: usize,
    peer_window: usize,
    send_window_last_seq: SeqNumber,
    send_window_last_ack: SeqNumber,
    receive_window_scale: u8,
    rto: RtoEstimator,
    congestion: NewReno,
    delayed_ack_pending: bool,
    pending_initial_payload_len: usize,
    pending_initial_fin: bool,
    /// Opened by `connect`, so completion is `Connected`, not `Accepted`.
    active_open: bool,
}

fn window_update_threshold(
    maximum_segment_size: usize,
    reserved_receive_capacity: usize,
    receive_window_scale: u8,
) -> usize {
    let scale_quantum = 1_usize
        .checked_shl(u32::from(receive_window_scale))
        .unwrap_or(usize::MAX);
    maximum_segment_size
        .max(1)
        .min(reserved_receive_capacity.div_ceil(2).max(1))
        .max(scale_quantum)
        .min(reserved_receive_capacity.max(1))
}

impl TcpTcb {
    /// Creates server-side state for an initial SYN after receive capacity has
    /// already been reserved. A FIN combined with the SYN is queued until the
    /// handshake enters `ESTABLISHED`, as required for other initial controls.
    ///
    /// # Errors
    ///
    /// Returns [`TcpError::InvalidSyn`] for a non-SYN or ACK/RST-bearing segment.
    pub fn from_syn(
        segment: TcpSegmentMeta,
        initial_send_sequence: SeqNumber,
        reserved_receive_capacity: usize,
    ) -> Result<(Self, Vec<TcpAction>), TcpError> {
        Self::from_syn_with_mss(
            segment,
            initial_send_sequence,
            reserved_receive_capacity,
            1_460,
        )
    }

    /// Creates server-side state with the effective local MSS used by `NewReno`.
    ///
    /// # Errors
    ///
    /// Returns [`TcpError::InvalidSyn`] for an invalid initial segment.
    pub fn from_syn_with_mss(
        segment: TcpSegmentMeta,
        initial_send_sequence: SeqNumber,
        reserved_receive_capacity: usize,
        maximum_segment_size: usize,
    ) -> Result<(Self, Vec<TcpAction>), TcpError> {
        Self::from_syn_with_options(
            segment,
            initial_send_sequence,
            reserved_receive_capacity,
            maximum_segment_size,
            0,
        )
    }

    /// Creates server-side state with negotiated transport parameters.
    ///
    /// # Errors
    ///
    /// Returns [`TcpError::InvalidSyn`] for an invalid initial segment.
    pub fn from_syn_with_options(
        segment: TcpSegmentMeta,
        initial_send_sequence: SeqNumber,
        reserved_receive_capacity: usize,
        maximum_segment_size: usize,
        receive_window_scale: u8,
    ) -> Result<(Self, Vec<TcpAction>), TcpError> {
        if !segment.flags.contains(TcpFlags::SYN)
            || segment.flags.contains(TcpFlags::ACK)
            || segment.flags.contains(TcpFlags::RST)
        {
            return Err(TcpError::InvalidSyn);
        }
        if segment.payload_len > reserved_receive_capacity {
            return Err(TcpError::ReceiveCreditExceeded);
        }
        let recv_next = segment.sequence.wrapping_add(1);
        let send_next = initial_send_sequence.wrapping_add(1);
        let receive_window_scale = receive_window_scale.min(14);
        // Initial payload is admitted from reserved credit before any window
        // was advertised, so window-scale quantization may round the window
        // below it. The right edge must still cover that payload, or it would
        // fall behind `recv_next` once the handshake applies it; a FIN is only
        // admitted strictly inside the window, as for in-order segments.
        let advertised_capacity =
            advertisable_receive_capacity(reserved_receive_capacity, receive_window_scale)
                .max(segment.payload_len);
        let pending_initial_fin =
            segment.flags.contains(TcpFlags::FIN) && segment.payload_len < advertised_capacity;
        let window_update_threshold = window_update_threshold(
            maximum_segment_size,
            reserved_receive_capacity,
            receive_window_scale,
        );
        let tcb = Self {
            state: TcpState::SynReceived,
            recv_next,
            send_unacked: initial_send_sequence,
            send_next,
            recv_capacity: reserved_receive_capacity,
            recv_buffered: 0,
            advertised_right_edge: recv_next.wrapping_add(advertised_capacity),
            window_update_threshold,
            peer_window: usize::try_from(segment.window).unwrap_or(usize::MAX),
            send_window_last_seq: segment.sequence,
            send_window_last_ack: SeqNumber::new(0),
            receive_window_scale,
            rto: RtoEstimator::default(),
            congestion: NewReno::new(maximum_segment_size),
            delayed_ack_pending: false,
            pending_initial_payload_len: segment.payload_len,
            pending_initial_fin,
            active_open: false,
        };
        let actions = vec![
            TcpAction::Send(tcb.control(TcpFlags::SYN.union(TcpFlags::ACK), initial_send_sequence)),
            TcpAction::ArmRetransmission {
                after_ms: tcb.rto.rto_ms(),
            },
        ];
        Ok((tcb, actions))
    }

    /// Creates client-side state for an active open after receive capacity
    /// has been reserved, and the SYN that starts it (RFC 9293 3.10.1).
    /// `receive_window_scale` is the shift offered in the SYN; the peer's
    /// sequence space is unknown until its SYN arrives.
    #[must_use]
    pub fn connect(
        initial_send_sequence: SeqNumber,
        reserved_receive_capacity: usize,
        maximum_segment_size: usize,
        receive_window_scale: u8,
    ) -> (Self, Vec<TcpAction>) {
        let receive_window_scale = receive_window_scale.min(14);
        let recv_next = SeqNumber::new(0);
        let tcb = Self {
            state: TcpState::SynSent,
            recv_next,
            send_unacked: initial_send_sequence,
            send_next: initial_send_sequence.wrapping_add(1),
            recv_capacity: reserved_receive_capacity,
            recv_buffered: 0,
            advertised_right_edge: recv_next.wrapping_add(advertisable_receive_capacity(
                reserved_receive_capacity,
                receive_window_scale,
            )),
            window_update_threshold: window_update_threshold(
                maximum_segment_size,
                reserved_receive_capacity,
                receive_window_scale,
            ),
            peer_window: 0,
            send_window_last_seq: SeqNumber::new(0),
            send_window_last_ack: SeqNumber::new(0),
            receive_window_scale,
            rto: RtoEstimator::default(),
            congestion: NewReno::new(maximum_segment_size),
            delayed_ack_pending: false,
            pending_initial_payload_len: 0,
            pending_initial_fin: false,
            active_open: true,
        };
        let actions = vec![
            TcpAction::Send(tcb.control(TcpFlags::SYN, initial_send_sequence)),
            TcpAction::ArmRetransmission {
                after_ms: tcb.rto.rto_ms(),
            },
        ];
        (tcb, actions)
    }

    #[must_use]
    pub const fn is_active_open(&self) -> bool {
        self.active_open
    }

    /// Withdraws the window scale offered in our SYN once the peer's SYN
    /// shows it does not scale: RFC 7323 1.3 applies scaling only when both
    /// SYNs carry the option. Only meaningful in SYN-SENT, before any window
    /// relative to the peer's sequence space was advertised.
    pub(crate) fn withdraw_receive_window_scale(&mut self) {
        if self.state != TcpState::SynSent {
            return;
        }
        self.receive_window_scale = 0;
        self.window_update_threshold = window_update_threshold(
            self.congestion.maximum_segment_size(),
            self.recv_capacity,
            0,
        );
    }

    #[must_use]
    pub const fn state(&self) -> TcpState {
        self.state
    }

    #[must_use]
    pub const fn recv_next(&self) -> SeqNumber {
        self.recv_next
    }

    #[must_use]
    pub(crate) fn receive_admission_left_edge(&self) -> SeqNumber {
        if self.state == TcpState::SynReceived {
            self.recv_next.wrapping_add(
                self.pending_initial_payload_len + usize::from(self.pending_initial_fin),
            )
        } else {
            self.recv_next
        }
    }

    #[must_use]
    pub const fn send_next(&self) -> SeqNumber {
        self.send_next
    }

    #[must_use]
    pub const fn send_unacked(&self) -> SeqNumber {
        self.send_unacked
    }

    #[must_use]
    pub fn send_available(&self) -> usize {
        let in_flight =
            usize::try_from(self.send_next.distance_from(self.send_unacked)).unwrap_or(usize::MAX);
        self.peer_window
            .min(
                self.congestion
                    .window()
                    .saturating_add(self.congestion.limited_transmit_allowance()),
            )
            .saturating_sub(in_flight)
    }

    #[must_use]
    pub const fn congestion_window(&self) -> usize {
        self.congestion.window()
    }

    pub fn record_rtt_sample(&mut self, sample_ms: u64) {
        self.rto.record_sample(sample_ms);
    }

    #[must_use]
    pub fn on_sack_loss(&mut self) -> Vec<TcpAction> {
        if !matches!(
            self.state,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::Closing
                | TcpState::CloseWait
                | TcpState::LastAck
        ) || self.send_unacked == self.send_next
            || (self.local_fin_outstanding() && !self.has_outstanding_payload())
        {
            return Vec::new();
        }
        let flight_size =
            usize::try_from(self.send_next.distance_from(self.send_unacked)).unwrap_or(usize::MAX);
        if !self.congestion.on_sack_loss(flight_size, self.send_next) {
            return Vec::new();
        }
        vec![TcpAction::RetransmitPayload(
            self.control(TcpFlags::ACK, self.send_unacked),
        )]
    }

    /// Promotes payload already admitted by the flow table into the contiguous
    /// receive stream. The table owns overlap checks and byte storage.
    ///
    /// # Errors
    ///
    /// Returns [`TcpError::ReceiveCreditExceeded`] when `amount` is zero or
    /// exceeds the reserved receive credit.
    pub fn accept_queued_payload(&mut self, amount: usize) -> Result<TcpAction, TcpError> {
        if amount == 0 || amount > self.receive_available() {
            return Err(TcpError::ReceiveCreditExceeded);
        }
        self.recv_buffered += amount;
        self.recv_next = self.recv_next.wrapping_add(amount);
        Ok(TcpAction::DeliverPayload { len: amount })
    }

    /// Applies a FIN that the flow table held behind an out-of-order gap.
    pub(crate) fn accept_queued_fin(&mut self) -> Vec<TcpAction> {
        self.recv_next = self.recv_next.wrapping_add(1);
        let mut actions = Vec::new();
        self.on_peer_fin(&mut actions);
        self.cancel_delayed_ack(&mut actions);
        actions.push(TcpAction::Send(self.control(TcpFlags::ACK, self.send_next)));
        actions
    }

    #[must_use]
    pub fn force_ack(&mut self) -> Vec<TcpAction> {
        let mut actions = Vec::new();
        self.cancel_delayed_ack(&mut actions);
        actions.push(TcpAction::Send(self.control(TcpFlags::ACK, self.send_next)));
        actions
    }

    #[must_use]
    pub(crate) fn reject_unacceptable_segment(&mut self) -> Vec<TcpAction> {
        let mut actions = Vec::new();
        self.cancel_delayed_ack(&mut actions);
        actions.push(TcpAction::DefensiveAck(
            self.control(TcpFlags::ACK, self.send_next),
        ));
        actions
    }

    #[must_use]
    pub const fn rto_ms(&self) -> u64 {
        self.rto.rto_ms()
    }

    #[must_use]
    pub const fn peer_window(&self) -> usize {
        self.peer_window
    }

    #[must_use]
    pub const fn recv_buffered(&self) -> usize {
        self.recv_buffered
    }

    #[must_use]
    pub const fn receive_available(&self) -> usize {
        self.recv_capacity - self.recv_buffered
    }

    #[must_use]
    pub fn advertised_window(&self) -> u16 {
        let distance = self.advertised_right_edge.distance_from(self.recv_next);
        u16::try_from(distance >> self.receive_window_scale).unwrap_or(u16::MAX)
    }

    #[must_use]
    pub const fn advertised_right_edge(&self) -> SeqNumber {
        self.advertised_right_edge
    }

    #[must_use]
    pub(crate) fn accepts_final_ack(&self, segment: TcpSegmentMeta) -> bool {
        self.state == TcpState::SynReceived
            && segment.flags.contains(TcpFlags::ACK)
            && !segment.flags.contains(TcpFlags::RST)
            && !segment.flags.contains(TcpFlags::SYN)
            && segment.acknowledgment == Some(self.send_next)
            && segment.sequence
                == self.recv_next.wrapping_add(
                    self.pending_initial_payload_len + usize::from(self.pending_initial_fin),
                )
    }

    #[must_use]
    pub(crate) fn final_ack_payload_capacity(&self) -> Option<usize> {
        (self.state == TcpState::SynReceived && !self.pending_initial_fin).then(|| {
            self.recv_capacity
                .saturating_sub(self.pending_initial_payload_len)
        })
    }

    #[must_use]
    pub(crate) fn accepts_sender_feedback(&self, segment: TcpSegmentMeta) -> bool {
        self.segment_acceptable(segment)
            && segment.flags.contains(TcpFlags::ACK)
            && !segment.flags.contains(TcpFlags::SYN)
            && !segment.flags.contains(TcpFlags::RST)
            && segment.acknowledgment.is_some_and(|acknowledgment| {
                !acknowledgment.before(self.send_unacked) && !acknowledgment.after(self.send_next)
            })
    }

    #[must_use]
    pub(crate) fn accepts_receive_sequence(&self, segment: TcpSegmentMeta) -> bool {
        self.segment_acceptable(segment)
    }

    /// # Errors
    ///
    /// Returns [`TcpError`] for a closed TCB or receive-credit violation.
    pub fn on_segment(&mut self, mut segment: TcpSegmentMeta) -> Result<Vec<TcpAction>, TcpError> {
        if self.state == TcpState::Closed {
            return Err(TcpError::Closed);
        }
        if self.state == TcpState::SynSent {
            return Ok(self.on_syn_sent_segment(segment));
        }
        if self.active_open && self.state == TcpState::SynReceived {
            segment = self.simultaneous_open_completion(segment);
        }
        if segment.flags.contains(TcpFlags::RST) {
            if segment.sequence == self.recv_next {
                self.state = TcpState::Closed;
                return Ok(vec![TcpAction::Closed]);
            }
            return if self.sequence_in_receive_window(segment.sequence) {
                Ok(vec![TcpAction::ChallengeAck])
            } else {
                Ok(Vec::new())
            };
        }
        let mut actions = Vec::new();

        if !self.complete_passive_handshake(segment, &mut actions) {
            return Ok(actions);
        }

        if !self.segment_acceptable(segment) {
            self.cancel_delayed_ack(&mut actions);
            actions.push(TcpAction::DefensiveAck(
                self.control(TcpFlags::ACK, self.send_next),
            ));
            return Ok(actions);
        }
        if segment.flags.contains(TcpFlags::SYN) {
            return Ok(vec![TcpAction::ChallengeAck]);
        }
        if !segment.flags.contains(TcpFlags::ACK) {
            return Ok(Vec::new());
        }
        if segment
            .acknowledgment
            .is_some_and(|acknowledgment| acknowledgment.after(self.send_next))
        {
            actions.push(TcpAction::DefensiveAck(
                self.control(TcpFlags::ACK, self.send_next),
            ));
            return Ok(actions);
        }

        self.trim_in_order_segment_to_receive_window(&mut segment);

        let old_peer_window = self.peer_window;
        self.update_send_window(segment);
        segment.window = u32::try_from(self.peer_window).unwrap_or(u32::MAX);

        self.process_ack(segment, old_peer_window, &mut actions);
        if self.state == TcpState::Closed {
            return Ok(actions);
        }
        if self.peer_receive_closed()
            && (segment.payload_len > 0 || segment.flags.contains(TcpFlags::FIN))
        {
            self.cancel_delayed_ack(&mut actions);
            actions.push(TcpAction::DefensiveAck(
                self.control(TcpFlags::ACK, self.send_next),
            ));
            return Ok(actions);
        }
        if segment.payload_len > 0 || segment.flags.contains(TcpFlags::FIN) {
            if segment.sequence != self.recv_next {
                self.cancel_delayed_ack(&mut actions);
                actions.push(TcpAction::DefensiveAck(
                    self.control(TcpFlags::ACK, self.send_next),
                ));
                return Ok(actions);
            }
            if segment.payload_len > self.receive_available() {
                return Err(TcpError::ReceiveCreditExceeded);
            }
            if segment.payload_len > 0 {
                self.recv_buffered += segment.payload_len;
                self.recv_next = self.recv_next.wrapping_add(segment.payload_len);
                actions.push(TcpAction::DeliverPayload {
                    len: segment.payload_len,
                });
            }
            if segment.flags.contains(TcpFlags::FIN) {
                self.recv_next = self.recv_next.wrapping_add(1);
                self.on_peer_fin(&mut actions);
                self.cancel_delayed_ack(&mut actions);
                actions.push(TcpAction::Send(self.control(TcpFlags::ACK, self.send_next)));
            } else if segment.payload_len > 0 {
                if self.delayed_ack_pending {
                    self.delayed_ack_pending = false;
                    actions.push(TcpAction::DisarmDelayedAck);
                    actions.push(TcpAction::Send(self.control(TcpFlags::ACK, self.send_next)));
                } else {
                    self.delayed_ack_pending = true;
                    actions.push(TcpAction::ArmDelayedAck);
                }
            }
        }
        Ok(actions)
    }

    /// RFC 9293 3.10.7.3: the SYN-SENT state accepts only an ACK of our SYN,
    /// a reset carrying that ACK, or the peer's SYN.
    fn on_syn_sent_segment(&mut self, segment: TcpSegmentMeta) -> Vec<TcpAction> {
        let is_reset = segment.flags.contains(TcpFlags::RST);
        let acknowledgment = if segment.flags.contains(TcpFlags::ACK) {
            match segment.acknowledgment {
                // Only the SYN is outstanding, so only its ACK is acceptable.
                Some(acknowledgment) if acknowledgment == self.send_next => Some(acknowledgment),
                Some(acknowledgment) if !is_reset => {
                    return vec![TcpAction::Send(SendControl {
                        sequence: acknowledgment,
                        acknowledgment: SeqNumber::new(0),
                        flags: TcpFlags::RST,
                        window: 0,
                    })];
                }
                _ => return Vec::new(),
            }
        } else {
            None
        };
        if is_reset {
            // Without an acceptable ACK a reset cannot be told from a forgery.
            if acknowledgment.is_none() {
                return Vec::new();
            }
            self.state = TcpState::Closed;
            return vec![TcpAction::DisarmRetransmission, TcpAction::Closed];
        }
        if !segment.flags.contains(TcpFlags::SYN) {
            return Vec::new();
        }
        // Data and FIN on the SYN are not taken; acknowledging only the SYN
        // makes the peer send them again once the connection is open.
        self.recv_next = segment.sequence.wrapping_add(1);
        self.advertised_right_edge = self.recv_next.wrapping_add(advertisable_receive_capacity(
            self.recv_capacity,
            self.receive_window_scale,
        ));
        self.peer_window = usize::try_from(segment.window).unwrap_or(usize::MAX);
        self.send_window_last_seq = segment.sequence;
        let Some(acknowledgment) = acknowledgment else {
            // Simultaneous open: answer the peer's SYN from SYN-RECEIVED.
            self.state = TcpState::SynReceived;
            return vec![
                TcpAction::Send(
                    self.control(TcpFlags::SYN.union(TcpFlags::ACK), self.send_unacked),
                ),
                TcpAction::ArmRetransmission {
                    after_ms: self.rto.rto_ms(),
                },
            ];
        };
        self.send_window_last_ack = acknowledgment;
        self.send_unacked = acknowledgment;
        self.state = TcpState::Established;
        vec![
            TcpAction::DisarmRetransmission,
            TcpAction::Connected,
            TcpAction::Send(self.control(TcpFlags::ACK, self.send_next)),
        ]
    }

    /// After a simultaneous open each side answers the other's SYN with a
    /// SYN-ACK, and receiving that SYN-ACK in SYN-RECEIVED completes the
    /// handshake (RFC 9293 figure 8). Its SYN occupies the sequence number
    /// before `recv_next`, so it is taken as the final ACK it carries.
    fn simultaneous_open_completion(&self, mut segment: TcpSegmentMeta) -> TcpSegmentMeta {
        let peer_syn = SeqNumber::new(self.recv_next.get().wrapping_sub(1));
        if segment.flags.contains(TcpFlags::SYN)
            && segment.flags.contains(TcpFlags::ACK)
            && !segment.flags.contains(TcpFlags::RST)
            && segment.sequence == peer_syn
            && segment.acknowledgment == Some(self.send_next)
        {
            segment.sequence = self.recv_next;
            segment.flags = TcpFlags::ACK;
            segment.payload_len = 0;
        }
        segment
    }

    fn complete_passive_handshake(
        &mut self,
        segment: TcpSegmentMeta,
        actions: &mut Vec<TcpAction>,
    ) -> bool {
        if self.state != TcpState::SynReceived {
            return true;
        }
        if !self.accepts_final_ack(segment) {
            if self.segment_acceptable(segment)
                && segment.flags.contains(TcpFlags::ACK)
                && segment
                    .acknowledgment
                    .is_some_and(|acknowledgment| acknowledgment != self.send_next)
            {
                let acknowledgment = segment
                    .acknowledgment
                    .expect("ACK-bearing segment checked above");
                actions.push(TcpAction::Send(self.control(TcpFlags::RST, acknowledgment)));
                return false;
            }
            actions.push(TcpAction::Send(
                self.control(TcpFlags::SYN.union(TcpFlags::ACK), self.send_unacked),
            ));
            actions.push(TcpAction::ArmRetransmission {
                after_ms: self.rto.rto_ms(),
            });
            return false;
        }

        self.send_unacked = self.send_next;
        self.state = TcpState::Established;
        actions.push(if self.active_open {
            TcpAction::Connected
        } else {
            TcpAction::Accepted
        });
        actions.push(TcpAction::DisarmRetransmission);
        if self.pending_initial_payload_len > 0 {
            let amount = self.pending_initial_payload_len;
            self.pending_initial_payload_len = 0;
            self.recv_buffered += amount;
            self.recv_next = self.recv_next.wrapping_add(amount);
            actions.push(TcpAction::DeliverPayload { len: amount });
            if !self.pending_initial_fin {
                self.delayed_ack_pending = true;
                actions.push(TcpAction::ArmDelayedAck);
            }
        }
        if self.pending_initial_fin {
            self.pending_initial_fin = false;
            self.recv_next = self.recv_next.wrapping_add(1);
            self.on_peer_fin(actions);
            self.cancel_delayed_ack(actions);
            actions.push(TcpAction::Send(self.control(TcpFlags::ACK, self.send_next)));
        }
        true
    }

    /// # Errors
    ///
    /// Returns [`TcpError`] for invalid application consumption or a closed TCB.
    pub fn on_app_event(&mut self, event: AppEvent) -> Result<Vec<TcpAction>, TcpError> {
        if self.state == TcpState::Closed {
            return Err(TcpError::Closed);
        }
        match event {
            AppEvent::Consumed(amount) => {
                if amount > self.recv_buffered {
                    return Err(TcpError::ConsumedBeyondBuffered);
                }
                self.recv_buffered -= amount;
                let candidate = self.recv_next.wrapping_add(advertisable_receive_capacity(
                    self.receive_available(),
                    self.receive_window_scale,
                ));
                let advancement = candidate.distance_from(self.advertised_right_edge);
                if candidate.after(self.advertised_right_edge)
                    && usize::try_from(advancement).unwrap_or(usize::MAX)
                        >= self.window_update_threshold
                {
                    self.advertised_right_edge = candidate;
                    let mut actions = Vec::new();
                    self.cancel_delayed_ack(&mut actions);
                    actions.push(TcpAction::Send(self.control(TcpFlags::ACK, self.send_next)));
                    return Ok(actions);
                }
                Ok(Vec::new())
            }
            AppEvent::Send(amount) => {
                if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
                    return Err(TcpError::InvalidSendState);
                }
                if amount > self.send_available() {
                    return Err(TcpError::SendWindowExceeded);
                }
                if amount == 0 {
                    return Ok(Vec::new());
                }
                let arm_retransmission = self.send_unacked == self.send_next;
                let sequence = self.send_next;
                self.send_next = self.send_next.wrapping_add(amount);
                let mut actions = Vec::new();
                self.cancel_delayed_ack(&mut actions);
                actions.push(TcpAction::SendPayload(
                    self.control(TcpFlags::ACK, sequence),
                ));
                if arm_retransmission {
                    actions.push(TcpAction::ArmRetransmission {
                        after_ms: self.rto.rto_ms(),
                    });
                }
                Ok(actions)
            }
            AppEvent::Close | AppEvent::Abort if self.state == TcpState::SynSent => {
                // Nothing reached the peer that a FIN or reset could refer to.
                self.state = TcpState::Closed;
                Ok(vec![TcpAction::DisarmRetransmission, TcpAction::Closed])
            }
            AppEvent::Close => {
                let mut actions = Vec::new();
                self.cancel_delayed_ack(&mut actions);
                actions.extend(self.start_close());
                Ok(actions)
            }
            AppEvent::Abort => {
                self.state = TcpState::Closed;
                let mut actions = Vec::new();
                self.cancel_delayed_ack(&mut actions);
                actions.extend([
                    TcpAction::Send(
                        self.control(TcpFlags::RST.union(TcpFlags::ACK), self.send_next),
                    ),
                    TcpAction::Closed,
                ]);
                Ok(actions)
            }
        }
    }

    /// # Errors
    ///
    /// Returns [`TcpError::Closed`] if the TCB has already closed.
    pub fn on_timer(&mut self, event: TimerEvent) -> Result<Vec<TcpAction>, TcpError> {
        if self.state == TcpState::Closed {
            return Err(TcpError::Closed);
        }
        match event {
            TimerEvent::Retransmission => {
                if self.send_unacked == self.send_next {
                    return Ok(Vec::new());
                }
                let flight_size = usize::try_from(self.send_next.distance_from(self.send_unacked))
                    .unwrap_or(usize::MAX);
                self.congestion.on_timeout(flight_size);
                self.rto.backoff();
                let action = match self.state {
                    TcpState::SynSent => {
                        TcpAction::Send(self.control(TcpFlags::SYN, self.send_unacked))
                    }
                    TcpState::SynReceived => TcpAction::Send(
                        self.control(TcpFlags::SYN.union(TcpFlags::ACK), self.send_unacked),
                    ),
                    TcpState::Established | TcpState::CloseWait => {
                        TcpAction::RetransmitPayload(self.control(TcpFlags::ACK, self.send_unacked))
                    }
                    TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
                        if self.has_outstanding_payload() =>
                    {
                        TcpAction::RetransmitPayload(self.control(TcpFlags::ACK, self.send_unacked))
                    }
                    TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck => TcpAction::Send(
                        self.control(TcpFlags::FIN.union(TcpFlags::ACK), self.send_unacked),
                    ),
                    _ => return Ok(Vec::new()),
                };
                Ok(vec![
                    action,
                    TcpAction::ArmRetransmission {
                        after_ms: self.rto.rto_ms(),
                    },
                ])
            }
            TimerEvent::DelayedAck if self.delayed_ack_pending => {
                self.delayed_ack_pending = false;
                Ok(vec![TcpAction::Send(
                    self.control(TcpFlags::ACK, self.send_next),
                )])
            }
            TimerEvent::TimeWaitExpired if self.state == TcpState::TimeWait => {
                self.state = TcpState::Closed;
                Ok(vec![TcpAction::Closed])
            }
            TimerEvent::DelayedAck
            | TimerEvent::Persist
            | TimerEvent::Keepalive
            | TimerEvent::TimeWaitExpired
            | TimerEvent::FinWait2Timeout => Ok(Vec::new()),
        }
    }

    fn process_ack(
        &mut self,
        segment: TcpSegmentMeta,
        old_peer_window: usize,
        actions: &mut Vec<TcpAction>,
    ) {
        let Some(ack) = segment.acknowledgment else {
            return;
        };
        if ack.after(self.send_unacked) && !ack.after(self.send_next) {
            let acknowledged_bytes =
                usize::try_from(ack.distance_from(self.send_unacked)).unwrap_or(usize::MAX);
            self.send_unacked = ack;
            if self.congestion.on_new_ack(acknowledged_bytes, ack)
                && self.send_unacked != self.send_next
            {
                actions.push(TcpAction::RetransmitPayload(
                    self.control(TcpFlags::ACK, self.send_unacked),
                ));
            }
            actions.push(TcpAction::DisarmRetransmission);
            if self.send_unacked != self.send_next {
                actions.push(TcpAction::ArmRetransmission {
                    after_ms: self.rto.rto_ms(),
                });
            }
        } else if ack == self.send_unacked
            && self.send_unacked != self.send_next
            && segment.payload_len == 0
            && usize::try_from(segment.window).unwrap_or(usize::MAX) == old_peer_window
            && self.congestion.on_duplicate_ack(
                usize::try_from(self.send_next.distance_from(self.send_unacked))
                    .unwrap_or(usize::MAX),
                self.send_next,
            )
        {
            actions.push(TcpAction::RetransmitPayload(
                self.control(TcpFlags::ACK, self.send_unacked),
            ));
        }
        match self.state {
            TcpState::FinWait1 if ack == self.send_next => self.state = TcpState::FinWait2,
            TcpState::Closing if ack == self.send_next => self.enter_time_wait(actions),
            TcpState::LastAck if ack == self.send_next => {
                self.state = TcpState::Closed;
                actions.push(TcpAction::Closed);
            }
            _ => {}
        }
    }

    fn update_send_window(&mut self, segment: TcpSegmentMeta) {
        let Some(acknowledgment) = segment.acknowledgment else {
            return;
        };
        if acknowledgment.before(self.send_unacked) || acknowledgment.after(self.send_next) {
            return;
        }
        if !self.segment_acceptable(segment) {
            return;
        }
        let fresh = segment.sequence.after(self.send_window_last_seq)
            || (segment.sequence == self.send_window_last_seq
                && (acknowledgment.after(self.send_window_last_ack)
                    || acknowledgment == self.send_window_last_ack));
        if fresh {
            self.peer_window = usize::try_from(segment.window).unwrap_or(usize::MAX);
            self.send_window_last_seq = segment.sequence;
            self.send_window_last_ack = acknowledgment;
        }
    }

    fn segment_acceptable(&self, segment: TcpSegmentMeta) -> bool {
        let window = self.advertised_right_edge.distance_from(self.recv_next);
        let length = segment.payload_len
            + usize::from(segment.flags.contains(TcpFlags::SYN))
            + usize::from(segment.flags.contains(TcpFlags::FIN));
        if window == 0 {
            return length == 0 && segment.sequence == self.recv_next;
        }
        if length == 0 {
            return self.sequence_in_receive_window(segment.sequence);
        }
        let segment_end = segment.sequence.wrapping_add(length);
        if segment.sequence.before(self.recv_next) {
            segment_end.after(self.recv_next)
        } else {
            segment.sequence.before(self.advertised_right_edge)
        }
    }

    fn trim_in_order_segment_to_receive_window(&self, segment: &mut TcpSegmentMeta) {
        if segment.sequence != self.recv_next {
            return;
        }

        let window = usize::try_from(self.advertised_right_edge.distance_from(self.recv_next))
            .unwrap_or(usize::MAX);
        segment.payload_len = segment.payload_len.min(window);
        if segment.flags.contains(TcpFlags::FIN) && segment.payload_len >= window {
            segment.flags = TcpFlags::from_bits(segment.flags.bits() & !TcpFlags::FIN.bits());
        }
    }

    fn sequence_in_receive_window(&self, sequence: SeqNumber) -> bool {
        !sequence.before(self.recv_next) && sequence.before(self.advertised_right_edge)
    }

    #[must_use]
    pub(crate) const fn peer_receive_closed(&self) -> bool {
        matches!(
            self.state,
            TcpState::CloseWait | TcpState::Closing | TcpState::LastAck | TcpState::TimeWait
        )
    }

    fn on_peer_fin(&mut self, actions: &mut Vec<TcpAction>) {
        actions.push(TcpAction::PeerHalfClosed);
        match self.state {
            TcpState::Established => self.state = TcpState::CloseWait,
            TcpState::FinWait1 if self.send_unacked == self.send_next => {
                self.enter_time_wait(actions);
            }
            TcpState::FinWait1 => self.state = TcpState::Closing,
            TcpState::FinWait2 => self.enter_time_wait(actions),
            TcpState::TimeWait => actions.push(TcpAction::ArmTimeWait),
            _ => {}
        }
    }

    fn local_fin_outstanding(&self) -> bool {
        matches!(
            self.state,
            TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
        )
    }

    fn has_outstanding_payload(&self) -> bool {
        self.local_fin_outstanding()
            && self.send_unacked != SeqNumber::new(self.send_next.get().wrapping_sub(1))
    }

    fn cancel_delayed_ack(&mut self, actions: &mut Vec<TcpAction>) {
        if self.delayed_ack_pending {
            self.delayed_ack_pending = false;
            actions.push(TcpAction::DisarmDelayedAck);
        }
    }

    fn start_close(&mut self) -> Vec<TcpAction> {
        match self.state {
            TcpState::Established => self.state = TcpState::FinWait1,
            TcpState::CloseWait => self.state = TcpState::LastAck,
            _ => return Vec::new(),
        }
        let sequence = self.send_next;
        self.send_next = self.send_next.wrapping_add(1);
        vec![
            TcpAction::Send(self.control(TcpFlags::FIN.union(TcpFlags::ACK), sequence)),
            TcpAction::ArmRetransmission {
                after_ms: self.rto.rto_ms(),
            },
        ]
    }

    fn enter_time_wait(&mut self, actions: &mut Vec<TcpAction>) {
        self.state = TcpState::TimeWait;
        actions.push(TcpAction::ArmTimeWait);
    }

    fn control(&self, flags: TcpFlags, sequence: SeqNumber) -> SendControl {
        // RFC 7323 2.2: the window in a SYN or SYN-ACK is never scaled.
        let window = if flags.contains(TcpFlags::SYN) {
            u16::try_from(self.advertised_right_edge.distance_from(self.recv_next))
                .unwrap_or(u16::MAX)
        } else {
            self.advertised_window()
        };
        SendControl {
            sequence,
            acknowledgment: self.recv_next,
            flags,
            window,
        }
    }
}
