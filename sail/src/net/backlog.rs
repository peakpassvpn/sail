//! How many connections a listening socket queues before they are accepted:
//! the system's limit, as Go (and so sing-box) asks for it
//! (`maxListenerBacklog`, Go's net/sock_*.go), rather than a number of our
//! own.

/// `SOMAXCONN` where the system's limit cannot be read: Go's (128, and on
/// Windows the value that asks the system for its own maximum).
#[cfg(not(windows))]
const FALLBACK: i32 = 128;
#[cfg(windows)]
const FALLBACK: i32 = 0x7fff_ffff;

/// The backlog to listen with. Read once: a change to the system's limit
/// applies to sockets listening after a restart.
pub fn max_listener_backlog() -> i32 {
    static BACKLOG: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *BACKLOG.get_or_init(system)
}

/// `net.core.somaxconn`; above 65535, kept from 4.1 on, when the kernel
/// stopped storing it in 16 bits, as Go's `maxAckBacklog` keeps it.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn system() -> i32 {
    let Some(n) = std::fs::read_to_string("/proc/sys/net/core/somaxconn")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_owned))
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
    else {
        return FALLBACK;
    };
    if n <= u64::from(u16::MAX) {
        return n as i32;
    }
    let max = if kernel_at_least(4, 1) {
        u64::from(u32::MAX)
    } else {
        u64::from(u16::MAX)
    };
    i32::try_from(n.min(max)).unwrap_or(i32::MAX)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn kernel_at_least(major: u32, minor: u32) -> bool {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return false;
    }
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy();
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let a = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    let b = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    (a, b) >= (major, minor)
}

/// `kern.ipc.somaxconn`, at most 65535, as Go reads it.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn system() -> i32 {
    let mut n: u32 = 0;
    let mut len = std::mem::size_of::<u32>();
    let ret = unsafe {
        libc::sysctlbyname(
            c"kern.ipc.somaxconn".as_ptr(),
            &mut n as *mut u32 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || n == 0 {
        return FALLBACK;
    }
    n.min(u32::from(u16::MAX)) as i32
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn system() -> i32 {
    FALLBACK
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The system's limit, as its own tool shows it.
    #[test]
    fn the_backlog_is_the_system_s() {
        let backlog = max_listener_backlog();
        #[cfg(target_os = "linux")]
        {
            let n: i32 = std::fs::read_to_string("/proc/sys/net/core/somaxconn")
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert_eq!(backlog, n);
        }
        #[cfg(target_os = "macos")]
        {
            let out = std::process::Command::new("sysctl")
                .args(["-n", "kern.ipc.somaxconn"])
                .output()
                .unwrap();
            let n: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
            assert_eq!(backlog, n.min(65535));
        }
        assert!(backlog > 0);
    }

    /// A listener queues as many connections as the system lets it, as
    /// `ss` shows its backlog (Send-Q of a listening socket).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_listener_queues_the_system_s_backlog() {
        use std::io::Write;
        let listener = crate::net::TcpListener::bind_now(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let port = listener.io().local_addr().unwrap().port();
        let out = match std::process::Command::new("ss")
            .args(["-Hltn", &format!("sport = :{}", port)])
            .output()
        {
            Ok(out) if out.status.success() => out,
            _ => {
                let _ = writeln!(
                    std::io::stderr(),
                    "a_listener_queues_the_system_s_backlog: skipped, no ss"
                );
                return;
            }
        };
        let line = String::from_utf8_lossy(&out.stdout);
        // State, Recv-Q, Send-Q: a listener's Send-Q is its backlog.
        let send_q: i32 = line.split_whitespace().nth(2).unwrap().parse().unwrap();
        assert_eq!(send_q, max_listener_backlog(), "{}", line);
    }
}
