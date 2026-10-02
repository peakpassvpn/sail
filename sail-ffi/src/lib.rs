//! sail's C ABI, for the apps that embed it: instances by handle, what
//! they tell (traffic, connections, outbounds and groups, delays, the
//! mode, logs, state) and are told (selections, delay tests, the network,
//! reloads), and tools that need no instance.
//!
//! The contract every function keeps:
//! - Handles are 64-bit numbers, 0 never one. A handle freed, or never
//!   given, makes a call fail with `SAIL_ERR_NO_INSTANCE`; it is never
//!   undefined behaviour.
//! - Every call returns a `SAIL_*` code. Where it takes `char **err`, a
//!   failure writes a message there, sail's, freed with
//!   `sail_free_string`; success writes NULL. NULL for `err` asks for none.
//! - Strings passed in are NUL-terminated UTF-8, read during the call
//!   only. Strings returned are sail's, freed with `sail_free_string`.
//!   Structured data is JSON, sail's own shape (snake_case).
//! - Callbacks are called on the threads the function registering them
//!   names, never while sail holds a lock of its own. Their `context` is
//!   the host's; sail calls its `release` exactly once, after the last
//!   callback that passes it.
//! - A panic inside sail aborts the process in release builds, as a Go
//!   panic in libbox does.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, CStr, CString};

#[cfg(test)]
mod abi_tests;
#[cfg(feature = "command-server")]
mod command;
mod control;
mod events;
mod handles;
#[cfg(test)]
mod header_tests;
#[cfg(all(test, feature = "alloc-stats"))]
mod perf_tests;
#[cfg(all(test, feature = "alloc-stats"))]
use sail::alloc_stats;
// The measurement's allocator: perf_tests counts what the process makes.
#[cfg(all(test, feature = "alloc-stats"))]
#[global_allocator]
static ALLOC: sail::alloc_stats::Counting = sail::alloc_stats::Counting;
mod instance;
/// The JSON hosts are answered with: core's, which the management API
/// answers with too.
pub(crate) use sail::control::json;
mod platform;
mod tools;

pub use control::*;
pub use events::*;
pub use instance::*;
pub use platform::SailPlatform;
pub use tools::*;

/// Success.
pub const SAIL_OK: i32 = 0;
/// An argument is null, not UTF-8, or not what the call takes.
pub const SAIL_ERR_INVALID_ARGUMENT: i32 = 1;
/// The handle is not one sail gave, or it was freed.
pub const SAIL_ERR_NO_INSTANCE: i32 = 2;
/// The instance is not in a state the call can be made in: it is not
/// running, or is starting already.
pub const SAIL_ERR_STATE: i32 = 3;
/// The configuration, or the settings, do not read or do not build.
pub const SAIL_ERR_CONFIG: i32 = 4;
/// A system call, a connection or a delay test failed.
pub const SAIL_ERR_IO: i32 = 5;
/// No outbound, group, member, mode or operation so named.
pub const SAIL_ERR_NOT_FOUND: i32 = 6;
/// This build of sail, or this instance, does not have what the call
/// needs.
pub const SAIL_ERR_UNSUPPORTED: i32 = 7;
/// The operation was cancelled, or the start was stopped.
pub const SAIL_ERR_CANCELLED: i32 = 8;
/// The call's time ran out; what it asked for may still happen.
pub const SAIL_ERR_TIMEOUT: i32 = 9;
/// The call would wait on the thread it was made on: one of the
/// instance's own, as a `protect_socket` callback runs on.
pub const SAIL_ERR_WRONG_THREAD: i32 = 10;
/// sail failed where it should not have; the message says how.
pub const SAIL_ERR_INTERNAL: i32 = 11;

/// A failed call: its code, and what the host is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    pub code: i32,
    pub message: String,
}

impl Failure {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(SAIL_ERR_INVALID_ARGUMENT, message)
    }

    pub fn no_instance() -> Self {
        Self::new(
            SAIL_ERR_NO_INSTANCE,
            "no such instance: freed, or never one",
        )
    }

    pub fn state(message: impl Into<String>) -> Self {
        Self::new(SAIL_ERR_STATE, message)
    }
}

impl From<sail::Error> for Failure {
    fn from(e: sail::Error) -> Self {
        let code = match &e {
            sail::Error::Config(_) | sail::Error::NoConfigFile => SAIL_ERR_CONFIG,
            sail::Error::Io(_) => SAIL_ERR_IO,
            sail::Error::InUse(_) => SAIL_ERR_STATE,
            _ => SAIL_ERR_INTERNAL,
        };
        let message = match e {
            sail::Error::Config(e) => format!("{:#}", e),
            e => e.to_string(),
        };
        Failure::new(code, message)
    }
}

impl From<sail::control::ControlError> for Failure {
    fn from(e: sail::control::ControlError) -> Self {
        use sail::control::ControlError as E;
        let code = match &e {
            E::NotFound(_) | E::NoMode(_) | E::NoProvider(_) | E::NoRuleSet(_) => {
                SAIL_ERR_NOT_FOUND
            }
            E::NotSelector(_) | E::Rejected(_) | E::InvalidUrl(_) => SAIL_ERR_INVALID_ARGUMENT,
            E::Failed(_) | E::UpdateFailed(_) => SAIL_ERR_IO,
            E::Stopping => SAIL_ERR_STATE,
            E::Timeout => SAIL_ERR_TIMEOUT,
            E::NoModes => SAIL_ERR_UNSUPPORTED,
            _ => SAIL_ERR_INTERNAL,
        };
        Failure::new(code, e.to_string())
    }
}

/// Runs an entry point: its code, and its message written to `err`. No
/// panic unwinds into the host.
pub(crate) fn call(err: *mut *mut c_char, body: impl FnOnce() -> Result<(), Failure>) -> i32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
        .unwrap_or_else(|_| Err(Failure::new(SAIL_ERR_INTERNAL, "sail panicked")));
    let (code, message) = match result {
        Ok(()) => (SAIL_OK, None),
        Err(f) => (f.code, Some(f.message)),
    };
    if !err.is_null() {
        // SAFETY: the host passes a pointer it can take a string through.
        unsafe { *err = message.map_or(std::ptr::null_mut(), new_string) };
    }
    code
}

/// A string for the host to free with `sail_free_string`.
pub(crate) fn new_string(s: String) -> *mut c_char {
    // A NUL inside is left out: C cannot take it.
    CString::new(s.replace('\0', ""))
        .expect("the NULs were removed")
        .into_raw()
}

/// Writes `value`, as JSON, to `out`.
pub(crate) fn out_json(
    out: *mut *mut c_char,
    value: &impl serde::Serialize,
) -> Result<(), Failure> {
    if out.is_null() {
        return Err(Failure::invalid("the out pointer is null"));
    }
    let json =
        serde_json::to_string(value).map_err(|e| Failure::new(SAIL_ERR_INTERNAL, e.to_string()))?;
    // SAFETY: checked non-null; the host passes a pointer it can take a
    // string through.
    unsafe { *out = new_string(json) };
    Ok(())
}

/// Writes `value` to `out`, a pointer the host gives.
pub(crate) fn out_value<T>(out: *mut T, value: T) -> Result<(), Failure> {
    if out.is_null() {
        return Err(Failure::invalid("the out pointer is null"));
    }
    // SAFETY: checked non-null; the host passes a pointer to a T.
    unsafe { *out = value };
    Ok(())
}

/// The UTF-8 string at `ptr`, for the call.
///
/// # Safety
///
/// A non-null `ptr` points to a NUL-terminated string valid for `'a`.
pub(crate) unsafe fn str_arg<'a>(ptr: *const c_char, what: &str) -> Result<&'a str, Failure> {
    if ptr.is_null() {
        return Err(Failure::invalid(format!("{} is null", what)));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| Failure::invalid(format!("{} is not UTF-8", what)))
}

/// As `str_arg`, null being none.
///
/// # Safety
///
/// As `str_arg`.
pub(crate) unsafe fn opt_str_arg<'a>(
    ptr: *const c_char,
    what: &str,
) -> Result<Option<&'a str>, Failure> {
    if ptr.is_null() {
        Ok(None)
    } else {
        unsafe { str_arg(ptr, what) }.map(Some)
    }
}

/// Frees a string sail returned. Null is ignored.
///
/// @param s The string; not to be used after.
#[no_mangle]
pub unsafe extern "C" fn sail_free_string(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: sail made it with CString::into_raw.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// What this build of sail is, as JSON: `{"version", "features":
/// ["inbound-tun", "outbound-vless", …]}`, the release and the modules
/// compiled in. The features say what was built, not which functions or
/// fields there are: there is no version number to compare (see the
/// header's contract).
///
/// @param out Takes the JSON, the host's to free.
/// @param err Takes the message of a failure, or null.
#[no_mangle]
pub unsafe extern "C" fn sail_capabilities(out: *mut *mut c_char, err: *mut *mut c_char) -> i32 {
    call(err, || {
        out_json(
            out,
            &json::Capabilities {
                version: env!("CARGO_PKG_VERSION"),
                features: sail::control::features(),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_becomes_an_internal_error_with_its_message() {
        let mut err = std::ptr::null_mut();
        assert_eq!(call(&mut err, || panic!("boom")), SAIL_ERR_INTERNAL);
        let message = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_owned();
        unsafe { sail_free_string(err) };
        assert_eq!(message, "sail panicked");
        assert_eq!(call(&mut err, || Ok(())), SAIL_OK);
        assert!(err.is_null());
        assert_eq!(
            call(std::ptr::null_mut(), || Err(Failure::invalid("x"))),
            SAIL_ERR_INVALID_ARGUMENT
        );
    }

    #[test]
    fn the_capabilities_name_the_release_and_the_features() {
        let mut out = std::ptr::null_mut();
        assert_eq!(
            unsafe { sail_capabilities(&mut out, std::ptr::null_mut()) },
            SAIL_OK
        );
        let json: serde_json::Value =
            serde_json::from_str(unsafe { CStr::from_ptr(out) }.to_str().unwrap()).unwrap();
        unsafe { sail_free_string(out) };
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        assert!(json.get("api_version").is_none() && json.get("json_version").is_none());
        assert!(json["features"].as_array().unwrap().len() > 1);
        assert_eq!(
            unsafe { sail_capabilities(std::ptr::null_mut(), std::ptr::null_mut()) },
            SAIL_ERR_INVALID_ARGUMENT
        );
    }
}
