//! The platform the FFI provides to the instances it starts: the system
//! log of the target, and socket protection and the TUN device through
//! callbacks the host registers.

use std::ffi::{c_char, c_void, CString};
use std::sync::RwLock;

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

/// Protects the socket `fd`, returning whether it did; `context` is what
/// the host registered along with it.
pub type ProtectSocketCallback = extern "C" fn(fd: i32, context: *mut c_void) -> bool;

struct Protector {
    callback: ProtectSocketCallback,
    context: *mut c_void,
}

// The host guarantees the context is usable from any thread.
unsafe impl Send for Protector {}
unsafe impl Sync for Protector {}

static PROTECTOR: RwLock<Option<Protector>> = RwLock::new(None);

pub fn set_protector(callback: Option<ProtectSocketCallback>, context: *mut c_void) {
    *PROTECTOR.write().unwrap_or_else(|e| e.into_inner()) =
        callback.map(|callback| Protector { callback, context });
}

/// Opens the TUN device `request` describes, a JSON object, and returns its
/// file descriptor, or a negative number when it cannot; `context` is what
/// the host registered along with it.
pub type OpenTunCallback = extern "C" fn(request: *const c_char, context: *mut c_void) -> i32;

struct TunOpener {
    callback: OpenTunCallback,
    context: *mut c_void,
}

// The host guarantees the context is usable from any thread.
unsafe impl Send for TunOpener {}
unsafe impl Sync for TunOpener {}

static TUN_OPENER: RwLock<Option<TunOpener>> = RwLock::new(None);

pub fn set_tun_opener(callback: Option<OpenTunCallback>, context: *mut c_void) {
    *TUN_OPENER.write().unwrap_or_else(|e| e.into_inner()) =
        callback.map(|callback| TunOpener { callback, context });
}

pub struct FfiPlatform;

impl sail::runtime::Platform for FfiPlatform {
    fn log(&self, line: &str) {
        system_log(line);
    }

    fn protects_sockets(&self) -> bool {
        PROTECTOR
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    fn protect_socket(&self, fd: i32) -> std::io::Result<()> {
        match PROTECTOR.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(p) if (p.callback)(fd, p.context) => Ok(()),
            Some(_) => Err(std::io::Error::other("the host did not protect the socket")),
            None => Ok(()),
        }
    }

    fn opens_tun(&self) -> bool {
        TUN_OPENER
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    fn open_tun(&self, request: &sail::runtime::TunRequest) -> std::io::Result<i32> {
        let request = serde_json::to_string(request)
            .ok()
            .and_then(|json| CString::new(json).ok())
            .ok_or_else(|| std::io::Error::other("the tun request does not encode"))?;
        match TUN_OPENER
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            Some(o) => match (o.callback)(request.as_ptr(), o.context) {
                fd if fd >= 0 => Ok(fd),
                _ => Err(std::io::Error::other("the host could not open the tun")),
            },
            None => Err(std::io::Error::from(std::io::ErrorKind::Unsupported)),
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
