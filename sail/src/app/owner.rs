//! Who opened a connection: the program and the user, or on Android the
//! package. Looked up only when something needs it (a rule's conditions
//! on it, or `route.find_process`), as sing-box's `needFindProcess`; once
//! a connection, and kept a few seconds by the client's socket, so that a
//! UDP flow's packets and a retried connection ask once. See
//! design-notes/connection-owner-lookup.md of the project.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::runtime::platform::ConnectionOwner;
use crate::session::Network;

/// How many sockets' owners are kept.
const CAPACITY: usize = 256;
/// How long an answer is taken, a miss too: a port another program takes
/// after it is looked up anew.
const KEPT: Duration = Duration::from_secs(5);

/// Who opened a connection, as far as it was found.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Found {
    /// The program's path.
    pub process: Option<String>,
    /// Its uid, user and packages.
    pub owner: Option<Arc<ConnectionOwner>>,
}

/// The client's socket a connection is looked up by: its network, its
/// own address, and the one it is connected to (a listener's, or through
/// a TUN its destination's).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Socket {
    pub network: Network,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// Whether the program is wanted, not only the user.
    pub process: bool,
}

/// The answers of the last few seconds.
pub(crate) struct Owners {
    kept: Mutex<lru::LruCache<Socket, (Instant, Found)>>,
}

impl Default for Owners {
    fn default() -> Self {
        Owners {
            kept: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(CAPACITY).expect("not zero"),
            )),
        }
    }
}

impl Owners {
    /// The answer kept for `socket`, if it is recent.
    pub(crate) fn get(&self, socket: &Socket) -> Option<Found> {
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        match kept.get(socket) {
            Some((at, found)) if at.elapsed() < KEPT => Some(found.clone()),
            Some(_) => {
                kept.pop(socket);
                None
            }
            None => None,
        }
    }

    /// Keeps `found` for `socket`.
    pub(crate) fn put(&self, socket: Socket, found: Found) {
        self.kept
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(socket, (Instant::now(), found));
    }
}

/// Who opened the connection of `socket`, as this system tells sail
/// itself; none where it does not (another machine's socket, or a
/// system sail cannot ask).
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn find(socket: &Socket) -> Found {
    let _ = socket;
    Found::default()
}

/// Linux: the socket's uid and inode from sock_diag, then, when the
/// program is wanted, the process holding it (platform::owner_linux). A
/// client's dual-stack socket sending to an IPv4 address is an IPv6 one:
/// looked for so too.
#[cfg(target_os = "linux")]
pub(crate) fn find(socket: &Socket) -> Found {
    use crate::platform::owner_linux;
    let protocol = match socket.network {
        Network::Tcp => libc::IPPROTO_TCP,
        Network::Udp => libc::IPPROTO_UDP,
    } as u8;
    let mapped = |a: SocketAddr| match a {
        SocketAddr::V4(v4) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
        v6 => v6,
    };
    let found = owner_linux::socket(protocol, socket.local, socket.remote)
        .ok()
        .flatten()
        .or_else(|| {
            socket.local.is_ipv4().then(|| {
                owner_linux::socket(protocol, mapped(socket.local), mapped(socket.remote))
                    .ok()
                    .flatten()
            })?
        });
    let Some(found) = found else {
        return Found::default();
    };
    let process = if socket.process {
        owner_linux::pid_of(found.inode, found.uid).and_then(owner_linux::path_of)
    } else {
        None
    };
    Found {
        process,
        owner: Some(Arc::new(ConnectionOwner {
            uid: found.uid,
            user: user_name(found.uid),
            packages: Vec::new(),
        })),
    }
}

/// macOS: the pid of the socket with the client's address in the kernel's
/// list (platform::owner_macos), then its path and uid. The list holds
/// every socket of the host: the program comes with it, wanted or not.
#[cfg(target_os = "macos")]
pub(crate) fn find(socket: &Socket) -> Found {
    use crate::platform::owner_macos;
    let tcp = socket.network == Network::Tcp;
    let Some(pid) = owner_macos::list(tcp)
        .ok()
        .and_then(|list| owner_macos::pid_in(&list, socket.local))
    else {
        return Found::default();
    };
    let Some((path, uid)) = owner_macos::process(pid) else {
        return Found::default();
    };
    Found {
        process: path.filter(|_| socket.process),
        owner: Some(Arc::new(ConnectionOwner {
            uid,
            user: user_name(uid),
            packages: Vec::new(),
        })),
    }
}

/// The name of the user `uid`, from the password database.
#[cfg(unix)]
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn user_name(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: zeroed is a valid passwd, filled by getpwuid_r.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: the buffers are as long as said, and live through the call.
    let ret = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut out) };
    if ret != 0 || out.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r wrote a C string into `buf`.
    Some(
        unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(port: u16) -> Socket {
        Socket {
            network: Network::Tcp,
            local: SocketAddr::from(([127, 0, 0, 1], port)),
            remote: SocketAddr::from(([127, 0, 0, 1], 80)),
            process: true,
        }
    }

    #[test]
    fn an_answer_is_kept_by_its_socket() {
        let owners = Owners::default();
        let found = Found {
            process: Some("/usr/bin/curl".into()),
            owner: None,
        };
        assert_eq!(owners.get(&socket(1)), None);
        owners.put(socket(1), found.clone());
        assert_eq!(owners.get(&socket(1)), Some(found));
        assert_eq!(owners.get(&socket(2)), None);
        // A miss is kept too.
        owners.put(socket(2), Found::default());
        assert_eq!(owners.get(&socket(2)), Some(Found::default()));
    }

    #[test]
    fn only_the_last_ones_are_kept() {
        let owners = Owners::default();
        for port in 0..=CAPACITY as u16 {
            owners.put(socket(port), Found::default());
        }
        assert_eq!(owners.get(&socket(0)), None);
        assert!(owners.get(&socket(CAPACITY as u16)).is_some());
    }

    /// This process's own connection, found as another's would be: its
    /// user, and its path when the program is wanted.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_connection_of_this_process_is_found() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut socket = Socket {
            network: Network::Tcp,
            local: client.local_addr().unwrap(),
            remote: client.peer_addr().unwrap(),
            process: false,
        };
        let found = find(&socket);
        // SAFETY: getuid cannot fail.
        assert_eq!(found.owner.as_ref().unwrap().uid, unsafe { libc::getuid() });
        assert_eq!(found.process, None);
        socket.process = true;
        let found = find(&socket);
        assert_eq!(
            std::path::PathBuf::from(found.process.unwrap())
                .canonicalize()
                .unwrap(),
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
        assert_eq!(user_name(0).as_deref(), Some("root"));
    }
}
