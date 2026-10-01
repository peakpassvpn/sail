//! What the host does for an instance, through callbacks it gives with the
//! instance: keeping sockets out of its VPN and opening the TUN device;
//! and the system log of the target.

use std::ffi::{c_char, c_void, CString};
use std::sync::{Arc, Weak};

#[cfg(any(target_os = "ios", target_os = "macos", target_os = "android"))]
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    // bindgen re-exports C typedefs of enums, e.g. `log_id as log_id_t`.
    unused_imports
)]
#[allow(improper_ctypes, clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/system_log_bindings.rs"));
}

/// What the host does for an instance. Every callback may be null; each
/// is passed `context`, and may be called from any thread.
///
/// The host sets `struct_size` to `sizeof(SailPlatform)`: callbacks added
/// in later versions of this header are then read as null from a host
/// built against an earlier one.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SailPlatform {
    pub struct_size: u32,
    /// The host's, passed to every callback.
    pub context: *mut c_void,
    /// Called once, when sail no longer calls any callback of this
    /// platform: after the instance is freed and has stopped. From any
    /// thread.
    pub release: Option<extern "C" fn(context: *mut c_void)>,
    /// Keeps the outbound socket `fd` out of the host's VPN, before it
    /// connects (Android's `VpnService.protect`); returns whether it did.
    /// Called on the instance's threads, as it dials: it must not wait on
    /// sail, whose waiting calls fail there with SAIL_ERR_WRONG_THREAD.
    pub protect_socket: Option<extern "C" fn(fd: i32, context: *mut c_void) -> bool>,
    /// Opens the TUN device a TUN inbound asks for (Android's
    /// `VpnService.Builder.establish`, iOS's packet flow's utun), as the
    /// JSON `request` says: `interface_name`, `mtu`, `ipv4` and `ipv6` (an
    /// address with its prefix, or null), `auto_route`, and for Android
    /// `include_android_user`, `include_package`, `exclude_package`.
    /// Returns the device's file descriptor, which the instance then owns,
    /// or a negative number. With it, the host routes the device: sail
    /// changes no routes. Called while the instance starts, on the thread
    /// that starts it.
    pub open_tun: Option<extern "C" fn(request: *const c_char, context: *mut c_void) -> i32>,
}

impl SailPlatform {
    fn none() -> Self {
        SailPlatform {
            struct_size: std::mem::size_of::<SailPlatform>() as u32,
            context: std::ptr::null_mut(),
            release: None,
            protect_socket: None,
            open_tun: None,
        }
    }

    /// The host's platform, as much of it as the host's header has; none
    /// for null.
    ///
    /// # Safety
    ///
    /// A non-null `platform` points to at least `struct_size` bytes, of
    /// which `struct_size` is the first field.
    pub(crate) unsafe fn read(platform: *const SailPlatform) -> Result<Self, crate::Failure> {
        if platform.is_null() {
            return Ok(Self::none());
        }
        // SAFETY: the first field is readable when the pointer is valid.
        let size = unsafe { std::ptr::addr_of!((*platform).struct_size).read_unaligned() } as usize;
        if size < std::mem::offset_of!(SailPlatform, context) {
            return Err(crate::Failure::invalid(
                "SailPlatform.struct_size is too small",
            ));
        }
        let size = size.min(std::mem::size_of::<SailPlatform>());
        let mut raw = std::mem::MaybeUninit::<SailPlatform>::zeroed();
        // SAFETY: `size` bytes are the host's to read, and the fields they
        // do not cover are pointers or options of function pointers, which
        // zeroes make null.
        let mut out = unsafe {
            std::ptr::copy_nonoverlapping(platform as *const u8, raw.as_mut_ptr() as *mut u8, size);
            raw.assume_init()
        };
        out.struct_size = std::mem::size_of::<SailPlatform>() as u32;
        Ok(out)
    }
}

/// The host's callbacks for one instance, released when the last holder
/// drops them.
pub(crate) struct Callbacks(SailPlatform);

// SAFETY: the host's contract: its context may be passed to its callbacks
// from any thread.
unsafe impl Send for Callbacks {}
unsafe impl Sync for Callbacks {}

impl Callbacks {
    pub fn new(platform: SailPlatform) -> Arc<Self> {
        Arc::new(Self(platform))
    }

    /// Whether the host opens the TUN device, and protects sockets.
    pub fn given(&self) -> (bool, bool) {
        (self.0.open_tun.is_some(), self.0.protect_socket.is_some())
    }
}

impl Drop for Callbacks {
    fn drop(&mut self) {
        if let Some(release) = self.0.release {
            release(self.0.context);
        }
    }
}

/// The platform an instance runs with: the host's callbacks, the system
/// log, and the instance to tell once it runs.
pub(crate) struct FfiPlatform {
    pub callbacks: Arc<Callbacks>,
    pub instance: Weak<crate::instance::Instance>,
}

impl sail::runtime::Platform for FfiPlatform {
    fn log(&self, line: &str) {
        system_log(line);
    }

    fn protects_sockets(&self) -> bool {
        self.callbacks.0.protect_socket.is_some()
    }

    fn protect_socket(&self, fd: i32) -> std::io::Result<()> {
        match self.callbacks.0.protect_socket {
            Some(protect) if protect(fd, self.callbacks.0.context) => Ok(()),
            Some(_) => Err(std::io::Error::other("the host did not protect the socket")),
            None => Ok(()),
        }
    }

    fn opens_tun(&self) -> bool {
        self.callbacks.0.open_tun.is_some()
    }

    fn open_tun(&self, request: &sail::runtime::TunRequest) -> std::io::Result<i32> {
        let Some(open) = self.callbacks.0.open_tun else {
            return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        };
        let request = serde_json::to_string(request)
            .ok()
            .and_then(|json| CString::new(json).ok())
            .ok_or_else(|| std::io::Error::other("the tun request does not encode"))?;
        match open(request.as_ptr(), self.callbacks.0.context) {
            fd if fd >= 0 => Ok(fd),
            _ => Err(std::io::Error::other("the host could not open the tun")),
        }
    }

    fn running(&self, manager: &Arc<sail::RuntimeManager>) {
        if let Some(instance) = self.instance.upgrade() {
            instance.running(manager.clone());
        }
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn system_log(line: &str) {
    let Ok(line) = std::ffi::CString::new(line) else {
        return;
    };
    unsafe {
        // The line is an argument, not the format: it may hold a '%'.
        bindings::asl_log(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            bindings::ASL_LEVEL_NOTICE as i32,
            c"%s".as_ptr(),
            line.as_ptr(),
        );
    }
}

#[cfg(target_os = "android")]
fn system_log(line: &str) {
    let Ok(line) = std::ffi::CString::new(line) else {
        return;
    };
    unsafe {
        // The line is an argument, not the format: it may hold a '%'.
        bindings::__android_log_print(
            bindings::android_LogPriority_ANDROID_LOG_VERBOSE as std::os::raw::c_int,
            c"sail".as_ptr(),
            c"%s".as_ptr(),
            line.as_ptr(),
        );
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "android")))]
fn system_log(line: &str) {
    eprintln!("{}", line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RELEASED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn release(_: *mut c_void) {
        RELEASED.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn protect(_: i32, _: *mut c_void) -> bool {
        true
    }

    #[test]
    fn a_platform_of_an_earlier_header_reads_its_later_callbacks_as_null() {
        let mut older = SailPlatform {
            context: 7 as *mut c_void,
            release: Some(release),
            protect_socket: Some(protect),
            ..SailPlatform::none()
        };
        // A host whose header ends before protect_socket.
        older.struct_size = std::mem::offset_of!(SailPlatform, protect_socket) as u32;
        let read = unsafe { SailPlatform::read(&older) }.unwrap();
        assert_eq!(read.context as usize, 7);
        assert!(read.release.is_some());
        assert!(read.protect_socket.is_none(), "beyond its struct_size");
        assert!(unsafe { SailPlatform::read(std::ptr::null()) }
            .unwrap()
            .release
            .is_none());
        let tiny = SailPlatform {
            struct_size: 2,
            ..SailPlatform::none()
        };
        assert!(unsafe { SailPlatform::read(&tiny) }.is_err());
    }

    #[test]
    fn callbacks_are_released_once_when_the_last_holder_goes() {
        let before = RELEASED.load(Ordering::SeqCst);
        let callbacks = Callbacks::new(SailPlatform {
            release: Some(release),
            ..SailPlatform::none()
        });
        let other = callbacks.clone();
        drop(callbacks);
        assert_eq!(RELEASED.load(Ordering::SeqCst), before);
        drop(other);
        assert_eq!(RELEASED.load(Ordering::SeqCst), before + 1);
    }
}
