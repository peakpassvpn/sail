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

/// Collects log output into lines for `Platform::log`.
pub(crate) struct LineWriter {
    platform: PlatformRef,
    buf: Vec<u8>,
}

impl LineWriter {
    pub fn new(platform: PlatformRef) -> Self {
        LineWriter {
            platform,
            buf: Vec::new(),
        }
    }
}

impl std::io::Write for LineWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        while let Some(end) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=end).collect();
            self.platform
                .log(String::from_utf8_lossy(&line[..end]).as_ref());
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
}
