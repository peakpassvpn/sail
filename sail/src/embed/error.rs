//! What a call into an instance fails with: a kind a host can act on, and
//! a message for people.

use std::fmt;

/// What kind of failure: stable, so a host may map it to its own codes.
/// It only grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The configuration or the settings do not read, or do not build.
    Config,
    /// An argument is not one the call takes: a group that is no selector,
    /// a member it refuses, a URL that does not parse.
    InvalidArgument,
    /// The instance does not run.
    NotRunning,
    /// The instance is in no state for the call: starting or running
    /// already, stopping, being freed.
    State,
    /// No outbound, group, member, mode, provider, rule-set, inbound or
    /// user so named.
    NotFound,
    /// This build, this platform or this instance does not have what the
    /// call needs.
    Unsupported,
    /// The call's time ran out; what it asked for may still happen.
    Timeout,
    /// The start was stopped.
    Cancelled,
    /// A blocking call made on one of the instance's own threads, where it
    /// would wait on itself: a misuse, as from a `Platform` callback. The
    /// async calls never fail so; only the blocking wrappers (the C ABI's)
    /// do.
    WrongThread,
    /// A dial, a delay test or an update that was made, and failed.
    Failed,
    /// A system call failed.
    Io,
    /// sail panicked: the instance it panicked in has failed, and may be
    /// started again.
    Panicked,
    /// sail failed where it should not have; the message says how.
    Internal,
    /// A TUN's device name is in use: one configured, or, when none was,
    /// each one sail chose as free taken before it opened (a start again
    /// may well succeed). See `tun_name_taken`.
    TunNameTaken,
    /// A reload that adds, removes or changes an inbound which only a
    /// start sets up (a TUN). Nothing changed: stop and start to apply.
    NeedsRestart,
    /// A reload that was to replace an inbound on the address it had: the
    /// new one did not bind, and the one before could not listen again.
    /// The reload failed and that inbound, which the message names,
    /// listens no more; all else is as it was.
    InboundLost,
}

impl ErrorKind {
    /// The kind as a stable string, for logs and a host's own codes.
    pub fn code(self) -> &'static str {
        match self {
            ErrorKind::Config => "config",
            ErrorKind::InvalidArgument => "invalid_argument",
            ErrorKind::NotRunning => "not_running",
            ErrorKind::State => "state",
            ErrorKind::NotFound => "not_found",
            ErrorKind::Unsupported => "unsupported",
            ErrorKind::Timeout => "timeout",
            ErrorKind::Cancelled => "cancelled",
            ErrorKind::WrongThread => "wrong_thread",
            ErrorKind::Failed => "failed",
            ErrorKind::Io => "io",
            ErrorKind::Panicked => "panicked",
            ErrorKind::Internal => "internal",
            ErrorKind::TunNameTaken => "tun_name_taken",
            ErrorKind::NeedsRestart => "needs_restart",
            ErrorKind::InboundLost => "inbound_lost",
        }
    }
}

/// A failed call: its kind, and what to tell people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    left: Vec<crate::runtime::teardown::Left>,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            left: Vec::new(),
        }
    }

    /// What the run's teardown left in the system, which the message says
    /// too: of a failure, a failed start, or a stop that could not undo
    /// everything. Empty for every other error.
    pub fn left(&self) -> &[crate::runtime::teardown::Left] {
        &self.left
    }

    pub(crate) fn with_left(mut self, left: Vec<crate::runtime::teardown::Left>) -> Self {
        self.left = left;
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// `kind().code()`.
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn not_running() -> Self {
        Self::new(ErrorKind::NotRunning, "the instance is not running")
    }

    pub(crate) fn state(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::State, message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        #[cfg(feature = "inbound-tun")]
        if let crate::Error::Config(e) = &e {
            if e.chain().any(|e| {
                e.downcast_ref::<crate::protocol::tun::inbound::TunNameTaken>()
                    .is_some()
            }) {
                return Error::new(ErrorKind::TunNameTaken, format!("{:#}", e));
            }
        }
        let kind = match &e {
            crate::Error::Config(_) | crate::Error::NoConfigFile => ErrorKind::Config,
            crate::Error::Io(_) => ErrorKind::Io,
            crate::Error::InUse(_) => ErrorKind::State,
            crate::Error::Panicked(_) => ErrorKind::Panicked,
            crate::Error::NeedsRestart(_) => ErrorKind::NeedsRestart,
            crate::Error::InboundLost { .. } => ErrorKind::InboundLost,
            crate::Error::NoInbound(_) => ErrorKind::NotFound,
            _ => ErrorKind::Internal,
        };
        let message = match e {
            crate::Error::Config(e) => format!("{:#}", e),
            e => e.to_string(),
        };
        Error::new(kind, message)
    }
}

impl From<crate::control::ControlError> for Error {
    fn from(e: crate::control::ControlError) -> Self {
        use crate::control::ControlError as E;
        let kind = match &e {
            E::NotFound(_) | E::NoMode(_) | E::NoProvider(_) | E::NoRuleSet(_) => {
                ErrorKind::NotFound
            }
            E::NotSelector(_) | E::Rejected(_) | E::InvalidUrl(_) => ErrorKind::InvalidArgument,
            E::Failed(_) | E::UpdateFailed(_) => ErrorKind::Failed,
            E::Stopping => ErrorKind::State,
            E::Timeout => ErrorKind::Timeout,
            E::NoModes => ErrorKind::Unsupported,
        };
        Error::new(kind, e.to_string())
    }
}

impl From<crate::control::InboundError> for Error {
    fn from(e: crate::control::InboundError) -> Self {
        use crate::control::InboundError as E;
        match e {
            E::Failed(e) => e.into(),
            e => {
                let kind = match &e {
                    E::NoInbound(_) | E::NoUser(..) => ErrorKind::NotFound,
                    E::NotReloadable(_) => ErrorKind::Unsupported,
                    E::UserExists(..) => ErrorKind::State,
                    _ => ErrorKind::InvalidArgument,
                };
                Error::new(kind, e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod reload_errors {
    use super::*;

    /// The two failures a reload has of its own are told by kind, not by
    /// their text, and the inbound that was lost is named.
    #[test]
    fn a_reload_s_own_failures_have_kinds_of_their_own() {
        let needs = Error::from(crate::Error::NeedsRestart(
            "[tun-in] inbound: a tun inbound is changed only at a start; restart to apply".into(),
        ));
        assert_eq!(needs.kind(), ErrorKind::NeedsRestart);
        assert_eq!(needs.kind().code(), "needs_restart");
        assert!(needs.message().starts_with("[tun-in] inbound"));

        let lost = Error::from(crate::Error::InboundLost {
            tag: "in".into(),
            reason: "address in use".into(),
        });
        assert_eq!(lost.kind(), ErrorKind::InboundLost);
        assert_eq!(lost.kind().code(), "inbound_lost");
        assert!(lost.message().contains("[in] inbound: lost"), "{}", lost);
    }
}
