//! nf_tables spoken over netlink, without nft(8) or libnftnl: enough to
//! build a ruleset -- tables, chains, sets, rules of the kernel's own
//! expressions -- and commit it as one transaction, and to list the tables
//! there are, which is how to tell nftables is available.
//!
//! ```ignore
//! let table = Table::new(Family::Inet, "sail");
//! let mut batch = Batch::new();
//! batch.del_table_if_exists(&table);
//! batch.add_table(&table);
//! batch.add_chain(&table, &Chain::base("prerouting", ChainType::Nat, Hook::Prerouting, -99));
//! let mut rule = meta_cmp(MetaKey::Mark, CmpOp::Eq, host_u32(0x2024)).to_vec();
//! rule.extend([Expr::Counter, verdict(Verdict::Return)]);
//! batch.add_rule(&table, "prerouting", &rule);
//! batch.commit()?;
//! ```
//!
//! The wire encoding is that of sagernet/nftables, which sing-tun builds
//! its `auto_redirect` ruleset with; the few places this differs say why.
//! The encoder is plain bytes and builds everywhere, so its tests run on
//! any host; talking to the kernel is Linux only.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod batch;
mod expr;
// The netlink framing and the socket serve the NFQUEUE consumer too.
pub(super) mod netlink;
#[cfg(target_os = "linux")]
pub(super) mod socket;
pub(super) mod sys;

pub use batch::*;
pub use expr::*;
#[cfg(target_os = "linux")]
pub use socket::{list_tables, TableInfo};

/// An nf_tables family, as the `NFPROTO_*` numbers have it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    Inet = 1,
    Ipv4 = 2,
    Arp = 3,
    Netdev = 5,
    Bridge = 7,
    Ipv6 = 10,
}

impl Family {
    pub fn from_u8(value: u8) -> Option<Family> {
        Some(match value {
            1 => Family::Inet,
            2 => Family::Ipv4,
            3 => Family::Arp,
            5 => Family::Netdev,
            7 => Family::Bridge,
            10 => Family::Ipv6,
            _ => return None,
        })
    }
}

impl std::fmt::Display for Family {
    /// The family as nft(8) writes it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Family::Inet => "inet",
            Family::Ipv4 => "ip",
            Family::Arp => "arp",
            Family::Netdev => "netdev",
            Family::Bridge => "bridge",
            Family::Ipv6 => "ip6",
        })
    }
}

#[derive(Debug)]
pub enum Error {
    /// The kernel refused a message, so the transaction was not applied:
    /// what the message did ("creating rule 12 in chain prerouting"), the
    /// errno, and what the kernel said about it, if anything.
    Kernel {
        what: String,
        errno: i32,
        message: Option<String>,
        /// How many other messages of the batch failed too; usually for
        /// want of what the first one would have made.
        others: usize,
    },
    /// The socket failed.
    Io(std::io::Error),
    /// The kernel said something that is not netlink as expected.
    Protocol(String),
}

impl Error {
    /// The errno the kernel or the socket failed with.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Error::Kernel { errno, .. } => Some(*errno),
            Error::Io(e) => e.raw_os_error(),
            Error::Protocol(_) => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Kernel {
                what,
                errno,
                message,
                others,
            } => {
                // strerror's words, without io::Error's " (os error N)".
                let os = std::io::Error::from_raw_os_error(*errno).to_string();
                let os = os.split(" (os error").next().unwrap_or_default();
                match errno_name(*errno) {
                    Some(name) => write!(f, "{}: {} ({})", what, name, os)?,
                    None => write!(f, "{}: errno {} ({})", what, errno, os)?,
                }
                if let Some(message) = message {
                    write!(f, ": {}", message)?;
                }
                match others {
                    0 => Ok(()),
                    1 => write!(f, "; 1 more message failed"),
                    n => write!(f, "; {} more messages failed", n),
                }
            }
            Error::Io(e) => write!(f, "nftables netlink: {}", e),
            Error::Protocol(s) => write!(f, "nftables netlink: {}", s),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e)
    }
}

/// The symbol of an errno nf_tables is known to answer with.
fn errno_name(errno: i32) -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        use libc::*;
        Some(match errno {
            EPERM => "EPERM",
            ENOENT => "ENOENT",
            EINTR => "EINTR",
            E2BIG => "E2BIG",
            EAGAIN => "EAGAIN",
            ENOMEM => "ENOMEM",
            EFAULT => "EFAULT",
            EBUSY => "EBUSY",
            EEXIST => "EEXIST",
            ENODEV => "ENODEV",
            EINVAL => "EINVAL",
            ENFILE => "ENFILE",
            ENOSPC => "ENOSPC",
            ERANGE => "ERANGE",
            ENAMETOOLONG => "ENAMETOOLONG",
            ELOOP => "ELOOP",
            EOVERFLOW => "EOVERFLOW",
            EMSGSIZE => "EMSGSIZE",
            EPROTONOSUPPORT => "EPROTONOSUPPORT",
            EOPNOTSUPP => "EOPNOTSUPP",
            EAFNOSUPPORT => "EAFNOSUPPORT",
            ENOBUFS => "ENOBUFS",
            _ => return None,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = errno;
        None
    }
}
