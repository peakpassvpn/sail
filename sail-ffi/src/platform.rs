//! The platform the FFI provides to the instances it starts: the system
//! log of the target, and socket protection through a callback the host
//! registers.

use std::ffi::c_void;
use std::sync::RwLock;

#[cfg(any(target_os = "ios", target_os = "macos", target_os = "android"))]
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code
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
    *PROTECTOR.write().unwrap() = callback.map(|callback| Protector { callback, context });
}

pub struct FfiPlatform;

impl sail::runtime::Platform for FfiPlatform {
    fn log(&self, line: &str) {
        system_log(line);
    }

    fn protects_sockets(&self) -> bool {
        PROTECTOR.read().unwrap().is_some()
    }

    fn protect_socket(&self, fd: i32) -> std::io::Result<()> {
        match PROTECTOR.read().unwrap().as_ref() {
            Some(p) if (p.callback)(fd, p.context) => Ok(()),
            Some(_) => Err(std::io::Error::other("the host did not protect the socket")),
            None => Ok(()),
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
