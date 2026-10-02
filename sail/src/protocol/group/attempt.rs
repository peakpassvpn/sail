//! What a failed connection through a member says of the member, for the
//! groups that test theirs: how far the attempt got, see `Stage`, and
//! whether that tells the member cannot be reached, see
//! `member_unreachable`.

use std::io;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::adapter::OutboundConnect;

/// How far an attempt through a member got when it failed, which tells
/// what the failure says of the member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Stage {
    /// Dialling something else than the member's own server: the
    /// destination (a direct member), or nothing (a member that dials by
    /// itself, a group, a QUIC protocol), whose failures cannot be told
    /// from the destination's.
    Elsewhere = 0,
    /// Dialling the member's server.
    DialingServer = 1,
    /// Its server dialled, the member's handshake over it.
    Handshake = 2,
}

/// The stage an attempt is at, as it moves on.
#[derive(Default)]
pub(crate) struct Progress(AtomicU8);

impl Progress {
    fn set(&self, stage: Stage) {
        self.0.store(stage as u8, Ordering::Relaxed);
    }

    pub(crate) fn get(&self) -> Stage {
        match self.0.load(Ordering::Relaxed) {
            1 => Stage::DialingServer,
            2 => Stage::Handshake,
            _ => Stage::Elsewhere,
        }
    }

    /// Before the member dials `connect`.
    pub(crate) fn dialing(&self, connect: &OutboundConnect) {
        self.set(match connect {
            OutboundConnect::Proxy(..) => Stage::DialingServer,
            _ => Stage::Elsewhere,
        });
    }

    /// The dial done, before the member's handshake.
    pub(crate) fn dialled(&self) {
        if self.get() == Stage::DialingServer {
            self.set(Stage::Handshake);
        }
    }
}

/// Whether a connection through a member that failed at `stage` with
/// `kind` says the member itself cannot be reached: a fallback marks it
/// down at once, and a urltest tests at once, as Mihomo tests at once
/// after a "connection refused" (adapter/outboundgroup/groupbase.go).
///
/// Conservatively: only what can only be the member's server's doing.
/// Its server refusing the dial, not answering it in time, or being out
/// of reach; then, the dial done, the server ending or garbling the
/// handshake (a TLS failure is `InvalidData`). Not what the destination
/// causes through a working server: a refusal the protocol reports (a
/// SOCKS reply, an HTTP proxy's status, a mux stream refused) comes as
/// another kind, `Other` or `ConnectionRefused` after the dial, and a
/// handshake that times out may be waiting on the destination, as SOCKS
/// waits for its connect. Nor anything a member that dials by itself or
/// dials the destination meets, which cannot be told apart. Those are
/// only counted, see `Checker::failed`.
pub(crate) fn member_unreachable(stage: Stage, kind: io::ErrorKind) -> bool {
    use io::ErrorKind::*;
    match stage {
        Stage::DialingServer => matches!(
            kind,
            ConnectionRefused
                | TimedOut
                | HostUnreachable
                | NetworkUnreachable
                | ConnectionReset
                | ConnectionAborted
        ),
        Stage::Handshake => matches!(kind, InvalidData | UnexpectedEof | ConnectionReset),
        Stage::Elsewhere => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_failures_of_the_members_server_mark_it_down() {
        use io::ErrorKind::*;
        for kind in [
            ConnectionRefused,
            TimedOut,
            HostUnreachable,
            ConnectionReset,
        ] {
            assert!(member_unreachable(Stage::DialingServer, kind), "{:?}", kind);
        }
        assert!(member_unreachable(Stage::Handshake, InvalidData));
        assert!(member_unreachable(Stage::Handshake, UnexpectedEof));
        // A refusal the protocol reports, a handshake waiting on the
        // destination, a DNS failure: not the server's.
        assert!(!member_unreachable(Stage::Handshake, Other));
        assert!(!member_unreachable(Stage::Handshake, ConnectionRefused));
        assert!(!member_unreachable(Stage::Handshake, TimedOut));
        assert!(!member_unreachable(Stage::DialingServer, Other));
        // The destination's, or what cannot be told from it.
        assert!(!member_unreachable(Stage::Elsewhere, ConnectionRefused));
        assert!(!member_unreachable(Stage::Elsewhere, TimedOut));
    }
}
