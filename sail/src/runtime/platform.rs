//! What only the host can do for an instance: the embedding app, the FFI
//! layer, or nothing at all for a command-line instance.

use std::fmt;
use std::sync::Arc;

/// Services an embedding host provides. Every one is optional: an instance
/// without a platform logs to its console and protects no sockets.
///
/// An Android app, for example, implements `protect_socket` by calling
/// `VpnService.protect` through JNI, and `log` with `__android_log_print`:
///
/// ```ignore
/// struct AndroidPlatform { vm: jni::JavaVM, service: jni::objects::GlobalRef }
///
/// impl sail::runtime::Platform for AndroidPlatform {
///     fn log(&self, line: &str) { /* __android_log_print(...) */ }
///     fn protects_sockets(&self) -> bool { true }
///     fn protect_socket(&self, fd: i32) -> std::io::Result<()> {
///         let mut env = self.vm.attach_current_thread_permanently().map_err(std::io::Error::other)?;
///         let ok = env
///             .call_method(&self.service, "protect", "(I)Z", &[fd.into()])
///             .and_then(|v| v.z())
///             .map_err(std::io::Error::other)?;
///         if ok { Ok(()) } else { Err(std::io::Error::other("VpnService.protect refused")) }
///     }
/// }
/// ```
pub trait Platform: Send + Sync {
    /// Takes one line of the instance's log, when `Host::log_to_system`
    /// asks for the system log.
    fn log(&self, line: &str);

    /// Whether `protect_socket` does anything; when it does not, a host
    /// may still protect sockets through `Host::socket_protect`.
    fn protects_sockets(&self) -> bool {
        false
    }

    /// Keeps an outbound socket, by its file descriptor, out of the VPN the
    /// host runs, before it connects.
    fn protect_socket(&self, fd: i32) -> std::io::Result<()> {
        let _ = fd;
        Ok(())
    }

    /// Whether `open_tun` opens the device of a TUN inbound; when it does
    /// not, the instance creates the device and its routes itself.
    fn opens_tun(&self) -> bool {
        false
    }

    /// Opens the device a TUN inbound asks for, addressed as `request`
    /// says and, with `auto_route`, carrying the system's traffic, as
    /// Android's `VpnService.Builder` does. The instance owns the returned
    /// file descriptor.
    fn open_tun(&self, request: &TunRequest) -> std::io::Result<i32> {
        let _ = request;
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    /// Whether `find_connection_owner` tells: the rules on the program a
    /// connection comes from (`package_name`, `user_id`, …) then match.
    fn finds_connection_owner(&self) -> bool {
        false
    }

    /// Who opened the connection `query` describes, as Android's
    /// `ConnectivityManager.getConnectionOwnerUid` and
    /// `PackageManager.getPackagesForUid` tell it; none when the host
    /// cannot tell. Asked of every connection, before it is routed, on the
    /// instance's threads, as sing-box's libbox asks on Android.
    fn find_connection_owner(
        &self,
        query: &ConnectionQuery,
    ) -> std::io::Result<Option<ConnectionOwner>> {
        let _ = query;
        Ok(None)
    }

    /// Told, while the instance starts and on the thread starting it, that
    /// the network it starts on is settled (`env.network`): before its
    /// outbounds are built, so before anything of it asks for a name.
    fn settled(&self, env: &Arc<crate::runtime::RuntimeEnv>) {
        let _ = env;
    }

    /// Told, while the instance starts and on the thread starting it, that
    /// its outbounds are built: `dialer` dials through them from now on,
    /// before the instance runs.
    fn dialable(&self, dialer: &crate::control::Dialer) {
        let _ = dialer;
    }

    /// Told once the instance runs, on the thread that started it, with
    /// what controls it; a stop asked for from here on stops it.
    fn running(&self, manager: &Arc<crate::RuntimeManager>) {
        let _ = manager;
    }
}

/// A connection whose owner the host is asked for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ConnectionQuery {
    /// `tcp` or `udp`.
    pub network: String,
    /// Where it comes from: the program's address.
    pub source: std::net::SocketAddr,
    /// Where it goes, as the program asked: an address, or a domain with
    /// its port.
    pub destination: String,
}

/// Who opened a connection, as the host tells it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionOwner {
    pub uid: u32,
    /// The user's name, where the host has one.
    #[serde(default)]
    pub user: Option<String>,
    /// Android: the packages that run as the uid.
    #[serde(default)]
    pub packages: Vec<String>,
}

/// The device a TUN inbound asks its host for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TunRequest {
    /// The name the configuration gives, which the host may not be able to
    /// honour.
    #[serde(rename = "interface_name")]
    pub name: String,
    pub mtu: u16,
    #[serde(serialize_with = "serialize_inet")]
    pub ipv4: Option<cidr::Ipv4Inet>,
    #[serde(serialize_with = "serialize_inet")]
    pub ipv6: Option<cidr::Ipv6Inet>,
    /// Routes all traffic into the device.
    pub auto_route: bool,
    /// Android: the apps the VPN takes in, and those it leaves out, as
    /// `VpnService.Builder` applies them.
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,
}

fn serialize_inet<I: fmt::Display, S: serde::Serializer>(
    inet: &Option<I>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match inet {
        Some(inet) => serializer.collect_str(inet),
        None => serializer.serialize_none(),
    }
}

/// A shared platform, compared by identity.
#[derive(Clone)]
pub struct PlatformRef(pub Arc<dyn Platform>);

impl fmt::Debug for PlatformRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Platform")
    }
}

impl PartialEq for PlatformRef {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for PlatformRef {}

impl std::ops::Deref for PlatformRef {
    type Target = dyn Platform;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

/// Collects log output into lines for `Platform::log`. The logger is the
/// process's and outlives the instance whose host it writes to, so it
/// holds the host weakly: once the instance is gone, so is the host's
/// platform (its `release` called), and the lines are dropped.
pub(crate) struct LineWriter {
    platform: std::sync::Weak<dyn Platform>,
    buf: Vec<u8>,
}

impl LineWriter {
    pub fn new(platform: PlatformRef) -> Self {
        LineWriter {
            platform: Arc::downgrade(&platform.0),
            buf: Vec::new(),
        }
    }
}

impl std::io::Write for LineWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        while let Some(end) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=end).collect();
            if let Some(platform) = self.platform.upgrade() {
                platform.log(String::from_utf8_lossy(&line[..end]).as_ref());
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl Platform for Recorder {
        fn log(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
    }

    #[test]
    fn log_output_reaches_the_platform_line_by_line() {
        let recorder = Arc::new(Recorder::default());
        let mut writer = LineWriter::new(PlatformRef(recorder.clone()));
        writer.write_all(b"first\nsec").unwrap();
        writer.write_all(b"ond\n").unwrap();
        writer.write_all(b"unfinished").unwrap();
        assert_eq!(*recorder.0.lock().unwrap(), ["first", "second"]);
    }

    #[test]
    fn the_writer_keeps_no_host_alive() {
        let recorder = Arc::new(Recorder::default());
        let mut writer = LineWriter::new(PlatformRef(recorder.clone()));
        writer.write_all(b"while it lives\n").unwrap();
        let weak = Arc::downgrade(&recorder);
        drop(recorder);
        assert!(weak.upgrade().is_none(), "the writer held the host");
        // Lines for a host that is gone are dropped.
        writer.write_all(b"after\n").unwrap();
    }
}
