#![no_main]

use std::ffi::CString;
use std::ptr;

use libfuzzer_sys::fuzz_target;

// The settings a host makes an instance with (`sail_instance_new`): the
// C ABI's own keys and the core's start settings. No instance is started.
fuzz_target!(|data: &[u8]| {
    // A C string ends at its first NUL.
    let Ok(settings) = CString::new(data) else {
        return;
    };
    let mut instance = 0;
    let mut err = ptr::null_mut();
    let code =
        unsafe { sail_ffi::sail_instance_new(settings.as_ptr(), ptr::null(), &mut instance, &mut err) };
    if code == 0 {
        assert!(err.is_null(), "an error with SAIL_OK");
        sail_ffi::sail_instance_free(instance);
    } else {
        assert!(!err.is_null(), "code {} without saying why", code);
        unsafe { sail_ffi::sail_free_string(err) };
    }
});
