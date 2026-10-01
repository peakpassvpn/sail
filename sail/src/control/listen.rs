//! Where a control service listens: the FFI's command service and the
//! management API alike. A unix socket by default, made the user's only,
//! a stale file replaced only when no service answers there; else loopback
//! TCP, with a strong secret every call carries, compared in constant time.

use std::path::PathBuf;

/// The longest path a unix socket takes: `sun_path` less its NUL.
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
pub const SOCKET_PATH_MAX: usize = 104 - 1;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
pub const SOCKET_PATH_MAX: usize = 108 - 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ListenError {
    /// The address does not read, or is not one to listen on.
    #[error("{0}")]
    Config(String),
    /// A service answers at the path already.
    #[error("{0}: a service answers there already")]
    InUse(String),
    #[error("{0}")]
    Io(String),
}

/// Where a service listens, or a client connects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Unix(PathBuf),
    /// Loopback TCP, with the secret every call carries.
    Tcp(u16, String),
    /// A connected socket the host has (a macOS system extension's, which
    /// XPC passes): a client's only.
    Fd(i32),
}

#[derive(serde::Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct AddressJson {
    path: Option<PathBuf>,
    port: Option<u16>,
    secret: Option<String>,
    fd: Option<i32>,
}

impl Address {
    /// `{"path"}`, `{"port", "secret"}`, or, where `fd` may be, `{"fd"}`.
    pub fn read(json: &str, fd: bool) -> Result<Self, ListenError> {
        let a: AddressJson =
            serde_json::from_str(json).map_err(|e| ListenError::Config(e.to_string()))?;
        match (a.path, a.port, a.fd) {
            (Some(path), None, None) => {
                if a.secret.is_some() {
                    return Err(ListenError::Config(
                        "secret: a unix socket takes none".into(),
                    ));
                }
                let len = path.as_os_str().len();
                if len > SOCKET_PATH_MAX {
                    return Err(ListenError::Config(format!(
                        "path: {} is {} bytes, more than a unix socket's {}",
                        path.display(),
                        len,
                        SOCKET_PATH_MAX
                    )));
                }
                Ok(Address::Unix(path))
            }
            (None, Some(port), None) => {
                let secret = a.secret.unwrap_or_default();
                if let Some(why) = crate::generate::weak_secret(&secret) {
                    return Err(ListenError::Config(format!(
                        "secret: loopback TCP needs a strong one (`sail generate secret`): {}",
                        why
                    )));
                }
                Ok(Address::Tcp(port, secret))
            }
            (None, None, Some(n)) if fd => Ok(Address::Fd(n)),
            _ => Err(ListenError::Config(if fd {
                "one of path, port with secret, or fd".into()
            } else {
                "one of path, or port with secret".into()
            })),
        }
    }

    /// The secret calls carry, for TCP.
    pub fn secret(&self) -> Option<&str> {
        match self {
            Address::Tcp(_, secret) => Some(secret),
            _ => None,
        }
    }
}

/// A listener bound to an address.
pub enum Listener {
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    Tcp(tokio::net::TcpListener),
}

/// Binds `address`, from within a tokio runtime. A unix socket's file
/// there is replaced, unless a service answers at it; the new one is the
/// user's only (0600).
pub fn bind(address: &Address) -> Result<Listener, ListenError> {
    let io = |what: &str, e: std::io::Error| ListenError::Io(format!("{}: {}", what, e));
    match address {
        #[cfg(unix)]
        Address::Unix(path) => {
            let shown = path.display().to_string();
            if path.exists() {
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return Err(ListenError::InUse(shown));
                }
                std::fs::remove_file(path).map_err(|e| io(&shown, e))?;
            }
            let listener =
                std::os::unix::net::UnixListener::bind(path).map_err(|e| io(&shown, e))?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| io(&shown, e))?;
            listener.set_nonblocking(true).map_err(|e| io(&shown, e))?;
            tokio::net::UnixListener::from_std(listener)
                .map(Listener::Unix)
                .map_err(|e| io(&shown, e))
        }
        #[cfg(not(unix))]
        Address::Unix(_) => Err(ListenError::Config(
            "path: unix sockets are not served here".into(),
        )),
        Address::Tcp(port, _) => {
            let shown = format!("127.0.0.1:{}", port);
            let listener =
                std::net::TcpListener::bind(("127.0.0.1", *port)).map_err(|e| io(&shown, e))?;
            listener.set_nonblocking(true).map_err(|e| io(&shown, e))?;
            tokio::net::TcpListener::from_std(listener)
                .map(Listener::Tcp)
                .map_err(|e| io(&shown, e))
        }
        Address::Fd(_) => Err(ListenError::Config(
            "a service listens on a path or a port".into(),
        )),
    }
}

/// Whether the secret `given` is `secret`, in a time that does not tell
/// how much of it was.
pub fn same_secret(given: &[u8], secret: &[u8]) -> bool {
    given.len() == secret.len()
        && given
            .iter()
            .zip(secret)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_a_path_or_a_port_with_a_strong_secret() {
        assert_eq!(
            Address::read(r#"{"path": "/tmp/command.sock"}"#, false),
            Ok(Address::Unix("/tmp/command.sock".into()))
        );
        let long = format!(r#"{{"path": "/{}"}}"#, "x".repeat(SOCKET_PATH_MAX));
        let err = Address::read(&long, false).unwrap_err();
        assert!(err.to_string().contains("bytes, more than"), "{}", err);
        let strong = crate::generate::secret();
        assert!(matches!(
            Address::read(
                &format!(r#"{{"port": 7990, "secret": "{}"}}"#, strong),
                false
            ),
            Ok(Address::Tcp(7990, _))
        ));
        for weak in [r#"{"port": 7990}"#, r#"{"port": 7990, "secret": "short"}"#] {
            assert!(
                matches!(Address::read(weak, false), Err(ListenError::Config(_))),
                "{}",
                weak
            );
        }
        assert!(
            Address::read(r#"{"fd": 3}"#, false).is_err(),
            "a service takes no fd"
        );
        assert_eq!(Address::read(r#"{"fd": 3}"#, true), Ok(Address::Fd(3)));
        assert!(Address::read(r#"{"path": "/a", "port": 1}"#, false).is_err());
        assert!(Address::read(r#"{"nothing": 1}"#, false).is_err());
    }

    #[test]
    fn a_secret_is_the_same_only_whole() {
        assert!(same_secret(b"abc", b"abc"));
        assert!(!same_secret(b"abd", b"abc"));
        assert!(!same_secret(b"ab", b"abc"));
        assert!(!same_secret(b"", b"abc"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_socket_answered_at_is_kept_and_a_stale_one_replaced() {
        let path = std::env::temp_dir().join(format!("sail-listen-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let address = Address::Unix(path.clone());
        let first = bind(&address).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(matches!(bind(&address), Err(ListenError::InUse(_))));
        drop(first);
        let _ = std::fs::remove_file(&path);
    }
}
