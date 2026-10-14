#![no_main]

use std::ffi::{c_char, c_void, CString};
use std::ptr;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

/// An instance never started: what its control functions read of their
/// arguments is read, and then they fail, as nothing runs.
fn idle() -> u64 {
    static INSTANCE: OnceLock<u64> = OnceLock::new();
    *INSTANCE.get_or_init(|| {
        let mut instance = 0;
        let code = unsafe {
            sail_ffi::sail_instance_new(ptr::null(), ptr::null(), &mut instance, ptr::null_mut())
        };
        assert_eq!(code, 0, "an instance of the default settings");
        instance
    })
}

extern "C" fn event(_kind: u32, _json: *const c_char, _context: *mut c_void) {}

/// A failure says why, and a success does not.
fn told(code: i32, err: *mut c_char) {
    if code == 0 {
        assert!(err.is_null(), "an error with SAIL_OK");
    } else {
        assert!(!err.is_null(), "code {} without saying why", code);
        unsafe { sail_ffi::sail_free_string(err) };
    }
}

// The strings a host passes the control functions of an instance: JSON
// (an inbound, a reload's options, a subscription's options), share
// links, a dial's host, and names. The first byte says which function,
// the second a number it takes, the rest is the string.
fuzz_target!(|data: &[u8]| {
    let [which, n, text @ ..] = data else {
        return;
    };
    // A C string ends at its first NUL: two strings for those that take two.
    let mut parts = text.splitn(2, |b| *b == 0);
    let Ok(first) = CString::new(parts.next().unwrap_or_default()) else {
        return;
    };
    let second = parts.next().and_then(|rest| CString::new(rest).ok());
    let second = second.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    let instance = idle();
    let mut err = ptr::null_mut();
    let code = unsafe {
        match which % 12 {
            0 => sail_ffi::sail_add_inbound(instance, first.as_ptr(), &mut err),
            1 => {
                let mut out = ptr::null_mut();
                let code = sail_ffi::sail_instance_reload_with(
                    instance,
                    second,
                    first.as_ptr(),
                    &mut out,
                    &mut err,
                );
                if !out.is_null() {
                    sail_ffi::sail_free_string(out);
                }
                code
            }
            2 => {
                let mut subscription = 0;
                let code = sail_ffi::sail_subscribe(
                    instance,
                    u32::from(*n),
                    first.as_ptr(),
                    Some(event),
                    ptr::null_mut(),
                    None,
                    &mut subscription,
                    &mut err,
                );
                if code == 0 {
                    sail_ffi::sail_unsubscribe(subscription, ptr::null_mut());
                }
                code
            }
            3 => {
                let mut out = ptr::null_mut();
                let code = sail_ffi::sail_import_share_links(first.as_ptr(), &mut out, &mut err);
                if !out.is_null() {
                    sail_ffi::sail_free_string(out);
                }
                code
            }
            4 => {
                let mut fd = -1;
                let network = if *n % 2 == 0 { c"tcp" } else { c"udp" };
                let code = sail_ffi::sail_dial(
                    instance,
                    c"direct".as_ptr(),
                    network.as_ptr(),
                    first.as_ptr(),
                    u16::from(*n) * 257,
                    1,
                    &mut fd,
                    &mut err,
                );
                assert!(code != 0 && fd == -1, "a dial through an instance never started");
                code
            }
            5 => sail_ffi::sail_select(instance, first.as_ptr(), second, &mut err),
            6 => sail_ffi::sail_set_mode(instance, first.as_ptr(), &mut err),
            7 => {
                let mut ms = 0;
                sail_ffi::sail_delay(instance, first.as_ptr(), second, 1, &mut ms, &mut err)
            }
            8 => {
                let mut closed = 0;
                sail_ffi::sail_remove_inbound(instance, first.as_ptr(), &mut closed, &mut err)
            }
            9 => sail_ffi::sail_update_provider(instance, first.as_ptr(), &mut err),
            10 => sail_ffi::sail_update_rule_set(instance, first.as_ptr(), &mut err),
            _ => sail_ffi::sail_set_network_state(instance, first.as_ptr(), &mut err),
        }
    };
    told(code, err);
});
