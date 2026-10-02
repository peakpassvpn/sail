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
        }
    }
}

/// A failed call: its kind, and what to tell people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
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
        let kind = match &e {
            crate::Error::Config(_) | crate::Error::NoConfigFile => ErrorKind::Config,
            crate::Error::Io(_) => ErrorKind::Io,
            crate::Error::InUse(_) => ErrorKind::State,
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
