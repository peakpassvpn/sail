//! Resource-bounded userspace TCP/IP data plane for sail.
//!
//! This crate owns protocol execution and resources. It intentionally does not
//! depend on sail's dispatcher, NAT manager, routing rules, or proxy protocols.

#![forbid(unsafe_code)]

pub mod api;
pub mod buffer;
pub mod engine;
pub mod ip;
pub mod metrics;
pub mod tcp;
pub mod timer;
mod trace;
pub mod udp;
pub mod wire;

pub use api::{
    ChecksumCapabilities, FlowDecision, FlowId, FlowKey, GsoCapabilities, IpEndpoint,
    NetworkGeneration, Packet, PacketBatch, PacketCapabilities, PacketIo, PacketToken, ShardId,
    TcpFlowToken, TransportProtocol, UdpFlowToken,
};
pub use buffer::{
    ArenaPacket, BudgetError, BudgetLease, BudgetProfile, BudgetSnapshot, PacketArena,
    PressureLevel, ResourceBudget, ResourceKind, ResourceLedger, SlabChain, SlabClass,
};
pub use engine::{
    classify_packet, EnqueueError, RoundStats, Route, RunnerConfig, RunnerError, RunnerState,
    Scheduler, SchedulerConfig, SchedulerSnapshot, ShardQueueError, ShardRouter, ShardRouterError,
    ShardRouterStats, ShardedPacketIo, ShardedPacketIoControl, ShardedPacketIoError,
    SingleShardRunner, StepOutcome, WorkClass,
};
pub use ip::{
    emit_icmp_echo_reply, emit_icmp_error, fragment_outbound_ip_packet, parse_icmp_packet,
    FragmentError, FragmentExpirations, FragmentReassembler, FragmentStats, IcmpErrorKind,
    IcmpMessage, ParsedIcmpPacket, PmtuError, PmtuStats, PmtuTable,
};
pub use metrics::StackStats;
pub use tcp::{
    emit_tcp_control, emit_tcp_segment, emit_tcp_segment_with_options, parse_tcp_segment,
    AcceptOverflowPolicy, AppEvent, NewReno, ParsedTcpSegment, RtoEstimator, SackBlock,
    SendControl, SeqNumber, TcpAction, TcpConnection, TcpError, TcpEvent, TcpFlags, TcpIngress,
    TcpOptions, TcpRead, TcpSegmentMeta, TcpState, TcpTable, TcpTableConfig, TcpTableError,
    TcpTableStats, TcpTcb, TcpTimerCancel, TcpTimerRequest, TimerEvent,
};
pub use timer::{TimerError, TimerId, TimerWheel};
pub use trace::{TraceEvent, TraceKind, TraceSnapshot, MAX_DEBUG_TRACE_EVENTS};
pub use udp::{UdpError, UdpFlowKey, UdpIngress, UdpTable, UdpTableStats};
pub use wire::{
    emit_udp_packet, parse_ip_packet, parse_udp_datagram, FragmentInfo, IpVersion, ParsedIpPacket,
    ParsedUdpDatagram, WireError,
};
