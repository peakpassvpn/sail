//! What needs no instance: the start settings, checking a configuration,
//! reading share links, the data files a configuration reads, and testing
//! each outbound of a configuration.

use std::ffi::{c_char, c_void, CString};

use crate::{call, opt_str_arg, out_json, str_arg, Failure, SAIL_ERR_CONFIG};

/// The tuning and host that `settings` (the core's JSON, see
/// `sail::runtime::StartSettings`) says, or the defaults: on iOS and
/// Android, the "mobile" profile and the system log unless it says.
pub(crate) fn start_settings(
    settings: Option<&str>,
) -> Result<(sail::runtime::RuntimeOptions, sail::runtime::Host), Failure> {
    let mut parsed = match settings {
        None => sail::runtime::StartSettings::default(),
        Some(json) => sail::runtime::StartSettings::from_json(json)
            .map_err(|e| Failure::new(SAIL_ERR_CONFIG, format!("{:#}", e)))?,
    };
    let phone = cfg!(any(target_os = "ios", target_os = "android"));
    parsed.log_to_system.get_or_insert(phone);
    // A phone runs with the phone's budget unless the host says otherwise.
    if phone {
        parsed.profile.get_or_insert_with(|| "mobile".to_string());
    }
    parsed
        .resolve()
        .map_err(|e| Failure::new(SAIL_ERR_CONFIG, format!("{:#}", e)))
}

/// `start_settings` as the environment offline checks run with, the system
/// log given where it is asked for.
fn start_env(settings: Option<&str>) -> Result<sail::runtime::RuntimeEnv, Failure> {
    let (options, mut host) = start_settings(settings)?;
    if host.log_to_system {
        host.platform = Some(sail::runtime::PlatformRef(std::sync::Arc::new(
            crate::platform::FfiPlatform {
                callbacks: crate::platform::Callbacks::new(unsafe {
                    crate::platform::SailPlatform::read(std::ptr::null())
                }?),
                instance: std::sync::Weak::new(),
            },
        )));
    }
    Ok(sail::runtime::RuntimeEnv {
        options,
        host,
        ..Default::default()
    })
}

/// Checks the configuration file at `path`: it reads and builds, as an
/// instance with `settings` would start it, without starting.
///
/// @param settings The instance's settings, or null.
/// @param out Takes JSON, or null for none: `{"warnings": [...]}`, what a
///     start would warn of (fields sail ignores, deprecated ones, what
///     building it logged as a warning), as `sail -T` prints them.
/// @param err Takes what is wrong with it, or null.
#[no_mangle]
pub unsafe extern "C" fn sail_check_config(
    path: *const c_char,
    settings: *const c_char,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let path = unsafe { str_arg(path, "path") }?;
        let settings = unsafe { opt_str_arg(settings, "settings") }?;
        let env = start_env(settings)?;
        let warnings = sail::test_config_with_warnings(path, &env).map_err(Failure::from)?;
        if out.is_null() {
            return Ok(());
        }
        out_json(out, &serde_json::json!({ "warnings": warnings }))
    })
}

/// Reads share links into sing-box outbounds.
///
/// @param input A share link, or a subscription: base64, or a link a line.
/// @param out Takes JSON: `{"outbounds": [...], "warnings": [...]}`, an
///     outbound for each link read and a warning for each line that is not
///     one (no warning holds a password, a UUID or a key).
#[no_mangle]
pub unsafe extern "C" fn sail_import_share_links(
    input: *const c_char,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let input = unsafe { str_arg(input, "input") }?;
        let (outbounds, warnings) = sail::config::share_link::parse_subscription(input);
        out_json(
            out,
            &serde_json::json!({ "outbounds": outbounds, "warnings": warnings }),
        )
    })
}

/// The data files (assets) the configuration at `path` reads: `asn.mmdb`,
/// `geo.mmdb`, `site.dat`, or files it names. sail downloads none: the
/// host fetches the missing ones into the data directory.
///
/// @param settings The instance's settings (its `data_dir` places the
///     files), or null.
/// @param out Takes JSON: `{"assets": [{"name", "kind" ("mmdb" or
///     "site"), "path", "used_by": [the fields that read it],
///     "present"}]}`.
#[no_mangle]
pub unsafe extern "C" fn sail_required_assets(
    path: *const c_char,
    settings: *const c_char,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let path = unsafe { str_arg(path, "path") }?;
        let settings = unsafe { opt_str_arg(settings, "settings") }?;
        let env = start_env(settings)?;
        let config = sail::config::from_file_for(path, &env.host)
            .map_err(|e| Failure::new(SAIL_ERR_CONFIG, format!("{}: {:#}", path, e)))?;
        out_json(
            out,
            &serde_json::json!({ "assets": sail::assets::required(&config, &env) }),
        )
    })
}

/// Takes one outbound's results: its tag, the TCP and UDP latencies in
/// milliseconds (-1 for a failure), and the context.
pub type SailOutboundTestCallback =
    extern "C" fn(tag: *const c_char, tcp_ms: i32, udp_ms: i32, context: *mut c_void);

/// Tests each outbound of the configuration `config` (its text) through,
/// without an instance: TCP and UDP, as sail's health check does. Returns
/// when every one is tested; `callback` is called on the calling thread,
/// once for each, as it is tested.
///
/// @param concurrency How many at once.
/// @param timeout_ms For each test; 0 for no limit.
#[no_mangle]
pub unsafe extern "C" fn sail_test_outbounds(
    config: *const c_char,
    settings: *const c_char,
    concurrency: u32,
    timeout_ms: u32,
    callback: Option<
        extern "C" fn(tag: *const c_char, tcp_ms: i32, udp_ms: i32, context: *mut c_void),
    >,
    context: *mut c_void,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let callback = callback.ok_or_else(|| Failure::invalid("the callback is null"))?;
        let config = unsafe { str_arg(config, "config") }?;
        let settings = unsafe { opt_str_arg(settings, "settings") }?;
        let env = start_env(settings)?;
        let config = sail::config::from_string_for(config, &env.host)
            .map_err(|e| Failure::new(SAIL_ERR_CONFIG, format!("{:#}", e)))?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Failure::new(crate::SAIL_ERR_IO, e.to_string()))?;
        let timeout =
            (timeout_ms > 0).then(|| std::time::Duration::from_millis(u64::from(timeout_ms)));
        rt.block_on(async move {
            use futures::StreamExt;
            let mut stream = sail::util::stream_outbounds_tests(
                &config,
                timeout,
                concurrency.max(1) as usize,
                &env,
            )
            .await
            .map_err(|e| Failure::new(SAIL_ERR_CONFIG, format!("{:#}", e)))?;
            let ms = |r: &anyhow::Result<std::time::Duration>| match r {
                Ok(d) => i32::try_from(d.as_millis()).unwrap_or(i32::MAX),
                Err(_) => -1,
            };
            while let Some((tag, (tcp, udp))) = stream.next().await {
                let tag = CString::new(tag.replace('\0', "")).expect("the NULs were removed");
                callback(tag.as_ptr(), ms(&tcp), ms(&udp), context);
            }
            Ok(())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn take(s: *mut c_char) -> String {
        let out = unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_owned();
        unsafe { crate::sail_free_string(s) };
        out
    }

    #[test]
    fn share_links_are_read_into_json_the_host_frees() {
        let mut out = std::ptr::null_mut();
        assert_eq!(
            unsafe { sail_import_share_links(std::ptr::null(), &mut out, std::ptr::null_mut()) },
            crate::SAIL_ERR_INVALID_ARGUMENT
        );
        let input = c"trojan://pw@example.com:443#a\nssr://x\nvless://no@example.com:1";
        assert_eq!(
            unsafe { sail_import_share_links(input.as_ptr(), &mut out, std::ptr::null_mut()) },
            crate::SAIL_OK
        );
        let value: serde_json::Value = serde_json::from_str(&take(out)).unwrap();
        assert_eq!(value["outbounds"].as_array().unwrap().len(), 1);
        assert_eq!(value["outbounds"][0]["tag"], "a");
        assert_eq!(value["warnings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn the_assets_a_configuration_reads_are_json_and_a_bad_one_an_error() {
        let dir = std::env::temp_dir().join(format!("sail-ffi-assets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("c.json");
        std::fs::write(
            &config,
            r#"{ "outbounds": [{ "type": "direct" }],
                 "route": { "rules": [{ "ip_asn": 1, "outbound": "direct" }] } }"#,
        )
        .unwrap();
        let path = CString::new(config.to_str().unwrap()).unwrap();
        let settings = CString::new(serde_json::json!({ "data_dir": dir }).to_string()).unwrap();
        let mut out = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                sail_required_assets(
                    path.as_ptr(),
                    settings.as_ptr(),
                    &mut out,
                    std::ptr::null_mut(),
                )
            },
            crate::SAIL_OK
        );
        let value: serde_json::Value = serde_json::from_str(&take(out)).unwrap();
        assert_eq!(value["assets"][0]["name"], "asn.mmdb", "{}", value);
        assert_eq!(value["assets"][0]["present"], false);
        let mut err = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                sail_required_assets(
                    c"/nonexistent/c.json".as_ptr(),
                    std::ptr::null(),
                    &mut out,
                    &mut err,
                )
            },
            SAIL_ERR_CONFIG
        );
        assert!(take(err).contains("/nonexistent/c.json"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_configuration_is_checked_with_its_error_told() {
        let dir = std::env::temp_dir().join(format!("sail-ffi-check-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.json");
        std::fs::write(&good, r#"{ "outbounds": [{ "type": "direct" }] }"#).unwrap();
        let bad = dir.join("bad.json");
        std::fs::write(&bad, r#"{ "outbounds": [{ "type": "nothing" }] }"#).unwrap();
        let warned = dir.join("warned.json");
        std::fs::write(
            &warned,
            r#"{ "outbounds": [{ "type": "direct", "tcp_multi_path": true }] }"#,
        )
        .unwrap();
        let path = |p: &std::path::Path| CString::new(p.to_str().unwrap()).unwrap();
        let null = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            unsafe { sail_check_config(path(&good).as_ptr(), std::ptr::null(), null, &mut err) },
            crate::SAIL_OK,
            "the warnings not asked for"
        );
        assert!(err.is_null());
        let mut out = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                sail_check_config(path(&good).as_ptr(), std::ptr::null(), &mut out, &mut err)
            },
            crate::SAIL_OK
        );
        let none: serde_json::Value = serde_json::from_str(&take(out)).unwrap();
        assert_eq!(none, serde_json::json!({ "warnings": [] }));
        let mut out = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                sail_check_config(path(&warned).as_ptr(), std::ptr::null(), &mut out, &mut err)
            },
            crate::SAIL_OK
        );
        let warned: serde_json::Value = serde_json::from_str(&take(out)).unwrap();
        let warnings = warned["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().unwrap().contains("tcp_multi_path")),
            "{}",
            warned
        );
        let mut out = std::ptr::null_mut();
        assert_eq!(
            unsafe { sail_check_config(path(&bad).as_ptr(), std::ptr::null(), &mut out, &mut err) },
            SAIL_ERR_CONFIG
        );
        assert!(out.is_null(), "nothing given on a failure");
        assert!(take(err).contains("nothing"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
