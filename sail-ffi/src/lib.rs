#![allow(clippy::missing_safety_doc)]
use std::{ffi::CStr, os::raw::c_char};

mod platform;

/// No error.
pub const ERR_OK: i32 = 0;
/// Config path error.
pub const ERR_CONFIG_PATH: i32 = 1;
/// Config parsing error.
pub const ERR_CONFIG: i32 = 2;
/// IO error.
pub const ERR_IO: i32 = 3;
/// Config file watcher error.
pub const ERR_WATCHER: i32 = 4;
/// Async channel send error.
pub const ERR_ASYNC_CHANNEL_SEND: i32 = 5;
/// Sync channel receive error.
pub const ERR_SYNC_CHANNEL_RECV: i32 = 6;
/// Runtime manager error.
pub const ERR_RUNTIME_MANAGER: i32 = 7;
/// No associated config file.
pub const ERR_NO_CONFIG_FILE: i32 = 8;
/// No data found.
pub const ERR_NO_DATA: i32 = 9;
/// Invalid start settings.
pub const ERR_SETTINGS: i32 = 10;
/// A required pointer argument is null.
pub const ERR_INVALID_ARGUMENT: i32 = 11;
/// The call panicked; the instance may be in any state.
pub const ERR_PANIC: i32 = 12;

/// Runs the body of an entry point, returning `on_panic` if it panics, so
/// that no panic unwinds into the host. (A build with `panic = "abort"`
/// aborts first; the code under it is written not to panic.)
fn guard<T>(on_panic: T, body: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(on_panic)
}

/// The UTF-8 string at `ptr`: ERR_INVALID_ARGUMENT if it is null, and
/// `not_utf8` if it is not UTF-8.
///
/// # Safety
///
/// A non-null `ptr` must point to a NUL-terminated string that stays
/// valid for `'a`.
unsafe fn c_str<'a>(ptr: *const c_char, not_utf8: i32) -> Result<&'a str, i32> {
    if ptr.is_null() {
        return Err(ERR_INVALID_ARGUMENT);
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| not_utf8)
}

/// The instance `rt_id`, if it runs.
fn runtime_manager(rt_id: u16) -> Option<std::sync::Arc<sail::RuntimeManager>> {
    sail::runtime_managers().get(&rt_id).cloned()
}

/// A runtime for a blocking call into a running instance.
fn call_runtime() -> Result<tokio::runtime::Runtime, i32> {
    tokio::runtime::Runtime::new().map_err(|_| ERR_IO)
}

/// The tuning and host described by `settings`, a JSON object (see
/// `sail::runtime::StartSettings`), or the defaults when it is null. The
/// host is given the FFI's platform: the system log, which iOS and Android
/// log to unless told otherwise, and the socket protector registered with
/// `sail_set_socket_protector`.
unsafe fn start_settings(
    settings: *const c_char,
) -> Result<(sail::runtime::RuntimeOptions, sail::runtime::Host), i32> {
    let mut parsed = if settings.is_null() {
        sail::runtime::StartSettings::default()
    } else {
        let json = unsafe { c_str(settings, ERR_SETTINGS) }?;
        sail::runtime::StartSettings::from_json(json).map_err(|e| {
            eprintln!("{}", e);
            ERR_SETTINGS
        })?
    };
    parsed
        .log_to_system
        .get_or_insert(cfg!(any(target_os = "ios", target_os = "android")));
    let (options, mut host) = parsed.resolve().map_err(|e| {
        eprintln!("{}", e);
        ERR_SETTINGS
    })?;
    host.platform = Some(sail::runtime::PlatformRef(std::sync::Arc::new(
        platform::FfiPlatform,
    )));
    Ok((options, host))
}

/// Registers the function that keeps outbound sockets out of the host's
/// VPN (Android's `VpnService.protect`), for the instances started after
/// it; null unregisters it.
///
/// @param callback Called with each outbound socket's file descriptor and
///                 `context` before it connects; returns whether the socket
///                 is protected. It may be called from any thread.
/// @param context Passed back to `callback`.
#[no_mangle]
pub extern "C" fn sail_set_socket_protector(
    callback: Option<platform::ProtectSocketCallback>,
    context: *mut std::ffi::c_void,
) {
    guard((), || platform::set_protector(callback, context));
}

/// Registers the function that opens the TUN device a TUN inbound needs
/// (Android's `VpnService.Builder.establish`, the utun of iOS's packet
/// tunnel), for the instances started after it; null unregisters it. With
/// it registered, the host also routes the device: an instance neither
/// creates one nor changes routes.
///
/// @param callback Called with a JSON object and `context` when a TUN
///                 inbound starts: `interface_name`, `mtu`, `ipv4` and
///                 `ipv6` (an address with its prefix, such as
///                 `"172.19.0.1/30"`, or null), and `auto_route` (whether
///                 all traffic is routed into the device). Returns the
///                 device's file descriptor, which the instance then owns,
///                 or a negative number when it cannot open it. It may be
///                 called from any thread.
/// @param context Passed back to `callback`.
#[no_mangle]
pub extern "C" fn sail_set_tun_opener(
    callback: Option<platform::OpenTunCallback>,
    context: *mut std::ffi::c_void,
) {
    guard((), || platform::set_tun_opener(callback, context));
}

/// `start_settings` as the environment offline checks run with.
unsafe fn start_env(settings: *const c_char) -> Result<sail::runtime::RuntimeEnv, i32> {
    let (options, host) = unsafe { start_settings(settings) }?;
    Ok(sail::runtime::RuntimeEnv {
        options,
        host,
        ..Default::default()
    })
}

fn to_errno(e: sail::Error) -> i32 {
    match e {
        sail::Error::Config(..) => ERR_CONFIG,
        sail::Error::NoConfigFile => ERR_NO_CONFIG_FILE,
        sail::Error::Io(..) => ERR_IO,
        #[cfg(feature = "auto-reload")]
        sail::Error::Watcher(..) => ERR_WATCHER,
        sail::Error::AsyncChannelSend(..) => ERR_ASYNC_CHANNEL_SEND,
        sail::Error::SyncChannelRecv(..) => ERR_SYNC_CHANNEL_RECV,
        sail::Error::RuntimeManager => ERR_RUNTIME_MANAGER,
    }
}

/// Starts sail with options, on a successful start this function blocks the current
/// thread.
///
/// @note This is not a stable API, parameters will change from time to time.
///
/// @param rt_id A unique ID to associate this sail instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file: .json for sing-box's format
///                    (Clash's .yaml / .yml and Surge's .conf are to follow).
/// @param auto_reload Enabls auto reloading when config file changes are detected,
///                    takes effect only when the "auto-reload" feature is enabled.
/// @param multi_thread Whether to use a multi-threaded runtime.
/// @param auto_threads Sets the number of runtime worker threads automatically,
///                     takes effect only when multi_thread is true.
/// @param threads Sets the number of runtime worker threads, takes effect when
///                     multi_thread is true, but can be overridden by auto_threads.
/// @param stack_size Sets stack size of the runtime worker threads, takes effect when
///                   multi_thread is true.
/// @param settings Tuning and host options as a JSON object, or null for the
///                 defaults: `{"profile": "mobile", "set": ["relay.buffer_size=32"],
///                 "data_dir": "...", "cache_dir": "...", "log_to_system": true,
///                 "socket_protect": "/path/or/host:port"}`.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn sail_run_with_options(
    rt_id: u16,
    config_path: *const c_char,
    auto_reload: bool, // requires this parameter anyway
    multi_thread: bool,
    auto_threads: bool,
    threads: i32,
    stack_size: i32,
    settings: *const c_char,
) -> i32 {
    guard(ERR_PANIC, || {
        let (runtime, host) = match unsafe { start_settings(settings) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        let config_path = match unsafe { c_str(config_path, ERR_CONFIG_PATH) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (Ok(threads), Ok(stack_size)) = (usize::try_from(threads), usize::try_from(stack_size))
        else {
            return ERR_INVALID_ARGUMENT;
        };
        if let Err(e) = sail::util::run_with_options(
            rt_id,
            config_path.to_string(),
            #[cfg(feature = "auto-reload")]
            auto_reload,
            multi_thread,
            auto_threads,
            threads,
            stack_size,
            runtime,
            host,
        ) {
            return to_errno(e);
        }
        ERR_OK
    })
}

/// Starts sail with a single-threaded runtime, on a successful start this function
/// blocks the current thread.
///
/// @param rt_id A unique ID to associate this sail instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file: .json for sing-box's format
///                    (Clash's .yaml / .yml and Surge's .conf are to follow).
/// @param settings Tuning and host options as a JSON object, or null for the
///                 defaults: `{"profile": "mobile", "set": ["relay.buffer_size=32"],
///                 "data_dir": "...", "cache_dir": "...", "log_to_system": true,
///                 "socket_protect": "/path/or/host:port"}`.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
pub unsafe extern "C" fn sail_run(
    rt_id: u16,
    config_path: *const c_char,
    settings: *const c_char,
) -> i32 {
    guard(ERR_PANIC, || {
        let (runtime, host) = match unsafe { start_settings(settings) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        let config_path = match unsafe { c_str(config_path, ERR_CONFIG_PATH) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        let opts = sail::StartOptions {
            config: sail::Config::File(config_path.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: sail::RuntimeOption::SingleThread,
            runtime,
            host,
        };
        if let Err(e) = sail::start(rt_id, opts) {
            return to_errno(e);
        }
        ERR_OK
    })
}

/// Starts sail like `sail_run`, with the configuration given as a string.
/// @param settings Tuning and host options as a JSON object, or null for the
///                 defaults: `{"profile": "mobile", "set": ["relay.buffer_size=32"],
///                 "data_dir": "...", "cache_dir": "...", "log_to_system": true,
///                 "socket_protect": "/path/or/host:port"}`.
#[no_mangle]
pub unsafe extern "C" fn sail_run_with_config_string(
    rt_id: u16,
    config: *const c_char,
    settings: *const c_char,
) -> i32 {
    guard(ERR_PANIC, || {
        let (runtime, host) = match unsafe { start_settings(settings) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        let config = match unsafe { c_str(config, ERR_CONFIG_PATH) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        let opts = sail::StartOptions {
            config: sail::Config::Str(config.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: sail::RuntimeOption::SingleThread,
            runtime,
            host,
        };
        if let Err(e) = sail::start(rt_id, opts) {
            return to_errno(e);
        }
        ERR_OK
    })
}

/// Reloads DNS servers, outbounds and routing rules from the config file.
///
/// @param rt_id The ID of the sail instance to reload.
///
/// @return Returns ERR_OK on success.
#[no_mangle]
pub extern "C" fn sail_reload(rt_id: u16) -> i32 {
    guard(ERR_PANIC, || match sail::reload(rt_id) {
        Ok(()) => ERR_OK,
        Err(e) => to_errno(e),
    })
}

/// Shuts down sail.
///
/// @param rt_id The ID of the sail instance to reload.
///
/// @return Returns true on success, false otherwise.
#[no_mangle]
pub extern "C" fn sail_shutdown(rt_id: u16) -> bool {
    guard(false, || sail::shutdown(rt_id))
}

/// Tells the TUN inbound that the platform's network changed, for example
/// after a switch between Wi-Fi and cellular. Flows of the previous network
/// are reset, and new ones start on the current network.
///
/// @param rt_id The ID of the sail instance.
/// @param mtu The new interface MTU, or 0 to keep the current one.
///
/// @return ERR_OK on success.
#[no_mangle]
pub extern "C" fn sail_network_changed(rt_id: u16, mtu: u16) -> i32 {
    guard(ERR_PANIC, || {
        let mtu = (mtu != 0).then_some(usize::from(mtu));
        match sail::network_changed(rt_id, mtu) {
            Ok(()) => ERR_OK,
            Err(e) => to_errno(e),
        }
    })
}

/// Tests the configuration.
///
/// @param config_path The path of the config file: .json for sing-box's format
///                    (Clash's .yaml / .yml and Surge's .conf are to follow).
/// @param settings The start settings the instance would run with, or null.
/// @return Returns ERR_OK on success, i.e no syntax error.
#[no_mangle]
pub unsafe extern "C" fn sail_test_config(
    config_path: *const c_char,
    settings: *const c_char,
) -> i32 {
    guard(ERR_PANIC, || {
        let env = match unsafe { start_env(settings) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        let config_path = match unsafe { c_str(config_path, ERR_CONFIG_PATH) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        match sail::test_config_with(config_path, &env) {
            Ok(()) => ERR_OK,
            Err(e) => to_errno(e),
        }
    })
}

/// Tests all outbounds connectivity and latency.
///
/// @param config The content of the config file.
/// @param concurrency The maximum number of concurrent tests.
/// @param timeout_sec The timeout in seconds for each test.
/// @param context User-provided context pointer to be passed back to the callback.
/// @param callback The callback function to receive results.
///                 Arguments: tag (string), tcp_latency (ms, -1 if failed), udp_latency (ms, -1 if failed), context.
/// @param settings The start settings the instance would run with, or null.
/// @return Returns ERR_OK on success.
#[no_mangle]
pub unsafe extern "C" fn sail_test_outbounds(
    config: *const c_char,
    concurrency: u32,
    timeout_sec: u32,
    context: *mut std::ffi::c_void,
    callback: Option<extern "C" fn(*const c_char, i32, i32, *mut std::ffi::c_void)>,
    settings: *const c_char,
) -> i32 {
    // The context goes to the callback, called from the runtime this call
    // blocks on, so it stays valid throughout.
    struct SendPtr(*mut std::ffi::c_void);
    unsafe impl Send for SendPtr {}
    unsafe impl Sync for SendPtr {}

    guard(ERR_PANIC, || {
        let Some(callback) = callback else {
            return ERR_INVALID_ARGUMENT;
        };
        let env = match unsafe { start_env(settings) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        let config_str = match unsafe { c_str(config, ERR_CONFIG_PATH) } {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ctx = SendPtr(context);
        let config = match sail::config::from_string(config_str) {
            Ok(c) => c,
            Err(e) => return to_errno(sail::Error::Config(e)),
        };
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return ERR_IO,
        };

        rt.block_on(async move {
            use futures::StreamExt;
            let timeout = if timeout_sec > 0 {
                Some(std::time::Duration::from_secs(timeout_sec as u64))
            } else {
                None
            };
            let Ok(mut stream) =
                sail::util::stream_outbounds_tests(&config, timeout, concurrency as usize, &env)
                    .await
            else {
                println!("Failed to start stream_outbounds_tests");
                return;
            };
            while let Some((tag, (tcp_res, udp_res))) = stream.next().await {
                // A tag cannot hold a NUL for C; one from the config that
                // does is passed without it.
                let tag_cstring =
                    std::ffi::CString::new(tag.replace('\0', "")).expect("the NULs were removed");
                let tcp_latency = match tcp_res {
                    Ok(d) => i32::try_from(d.as_millis()).unwrap_or(i32::MAX),
                    Err(e) => {
                        println!("TCP test failed for {}: {:?}", tag, e);
                        -1
                    }
                };
                let udp_latency = match udp_res {
                    Ok(d) => i32::try_from(d.as_millis()).unwrap_or(i32::MAX),
                    Err(e) => {
                        println!("UDP test failed for {}: {:?}", tag, e);
                        -1
                    }
                };
                callback(tag_cstring.as_ptr(), tcp_latency, udp_latency, ctx.0);
            }
        });
        ERR_OK
    })
}

/// Runs a health check for an outbound.
///
/// This performs an active health check by sending a PING to healthcheck.sail
/// and waiting for a PONG response through the specified outbound, testing both
/// TCP and UDP protocols.
///
/// @param rt_id The ID of the sail instance.
/// @param outbound_tag The tag of the outbound to test.
/// @param timeout_ms Timeout in milliseconds (0 for default 4 seconds).
/// @return Returns ERR_OK if either TCP or UDP health check succeeds, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn sail_health_check(
    rt_id: u16,
    outbound_tag: *const c_char,
    timeout_ms: u64,
) -> i32 {
    use std::time::Duration;

    guard(ERR_PANIC, || {
        let outbound_tag = match unsafe { c_str(outbound_tag, ERR_CONFIG_PATH) } {
            Ok(tag) => tag.to_string(),
            Err(e) => return e,
        };
        let Some(m) = runtime_manager(rt_id) else {
            return to_errno(sail::Error::RuntimeManager);
        };
        let rt = match call_runtime() {
            Ok(rt) => rt,
            Err(e) => return e,
        };
        let timeout = if timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(timeout_ms))
        };
        match rt.block_on(async move { m.health_check_outbound(&outbound_tag, timeout).await }) {
            Ok((tcp_res, udp_res)) => {
                if tcp_res.is_ok() || udp_res.is_ok() {
                    ERR_OK
                } else {
                    ERR_IO
                }
            }
            Err(e) => to_errno(e),
        }
    })
}

/// The last time a connection through `outbound_tag` of instance `rt_id`
/// succeeded, in seconds since the epoch.
unsafe fn last_active(rt_id: u16, outbound_tag: *const c_char) -> Result<Option<u32>, i32> {
    let outbound_tag = unsafe { c_str(outbound_tag, ERR_CONFIG_PATH) }?.to_string();
    let m = runtime_manager(rt_id).ok_or_else(|| to_errno(sail::Error::RuntimeManager))?;
    let rt = call_runtime()?;
    rt.block_on(async move { m.get_outbound_last_peer_active(&outbound_tag).await })
        .map_err(to_errno)
}

/// Gets the last active time for an outbound.
///
/// This returns the timestamp of the last successful connection through the outbound.
///
/// @param rt_id The ID of the sail instance.
/// @param outbound_tag The tag of the outbound.
/// @param timestamp_s Pointer to store the timestamp in seconds since epoch.
/// @return Returns ERR_OK on success, ERR_NO_DATA if no active time found, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn sail_get_last_active(
    rt_id: u16,
    outbound_tag: *const c_char,
    timestamp_s: *mut u32,
) -> i32 {
    guard(ERR_PANIC, || {
        if timestamp_s.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        match unsafe { last_active(rt_id, outbound_tag) } {
            Ok(Some(ts)) => {
                unsafe { *timestamp_s = ts };
                ERR_OK
            }
            Ok(None) => ERR_NO_DATA,
            Err(e) => e,
        }
    })
}

/// Gets seconds since last active time for an outbound.
///
/// This returns the number of seconds elapsed since the last successful
/// connection through the specified outbound.
///
/// @param rt_id The ID of the sail instance.
/// @param outbound_tag The tag of the outbound.
/// @param since_s Pointer to store the seconds since last active.
/// @return Returns ERR_OK on success, ERR_NO_DATA if no active time found, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn sail_get_since_last_active(
    rt_id: u16,
    outbound_tag: *const c_char,
    since_s: *mut u32,
) -> i32 {
    guard(ERR_PANIC, || {
        if since_s.is_null() {
            return ERR_INVALID_ARGUMENT;
        }
        match unsafe { last_active(rt_id, outbound_tag) } {
            Ok(Some(ts)) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                unsafe { *since_s = now.saturating_sub(ts) };
                ERR_OK
            }
            Ok(None) => ERR_NO_DATA,
            Err(e) => e,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_are_errors() {
        unsafe {
            assert_eq!(
                sail_run(1, std::ptr::null(), std::ptr::null()),
                ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                sail_test_config(std::ptr::null(), std::ptr::null()),
                ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                sail_health_check(1, std::ptr::null(), 0),
                ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                sail_get_last_active(1, c"x".as_ptr(), std::ptr::null_mut()),
                ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                sail_test_outbounds(
                    c"{}".as_ptr(),
                    1,
                    1,
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null()
                ),
                ERR_INVALID_ARGUMENT
            );
        }
    }

    #[test]
    fn calls_into_a_missing_instance_are_errors() {
        let mut ts = 0;
        unsafe {
            assert_eq!(
                sail_get_last_active(u16::MAX, c"x".as_ptr(), &mut ts),
                ERR_RUNTIME_MANAGER
            );
            assert_eq!(
                sail_health_check(u16::MAX, c"x".as_ptr(), 0),
                ERR_RUNTIME_MANAGER
            );
        }
        assert!(!sail_shutdown(u16::MAX));
    }

    #[test]
    fn a_panic_becomes_an_error_code() {
        assert_eq!(guard(ERR_PANIC, || panic!("boom")), ERR_PANIC);
        assert_eq!(guard(ERR_PANIC, || ERR_OK), ERR_OK);
    }
}
