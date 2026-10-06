//! The C ABI as a host calls it: through the `extern "C"` functions only,
//! with real instances. What 4.2 asks of it: many instances, starts and
//! stops again and again, callbacks that call back in, a host that dies,
//! and nothing left behind or waiting for ever.

use std::ffi::{c_char, c_void, CStr, CString};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::*;

/// One test at a time: they count the process's threads and files.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Runs `body`, failing if it takes longer than `limit`: a deadlock fails
/// the test rather than hanging it.
fn within<T: Send + 'static>(limit: Duration, body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(limit) {
        Ok(out) => out,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("the test body panicked"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("did not finish within {:?}: a deadlock?", limit)
        }
    }
}

fn take(s: *mut c_char) -> String {
    assert!(!s.is_null());
    let out = unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_owned();
    unsafe { sail_free_string(s) };
    out
}

/// Fails with the call's message unless it succeeded.
fn ok(what: &str, f: impl FnOnce(*mut *mut c_char) -> i32) {
    let mut err = std::ptr::null_mut();
    let code = f(&mut err);
    if code != SAIL_OK {
        let message = if err.is_null() {
            String::new()
        } else {
            take(err)
        };
        panic!("{}: code {}: {}", what, code, message);
    }
    assert!(err.is_null());
}

/// The code a call fails with, its message freed.
fn code(f: impl FnOnce(*mut *mut c_char) -> i32) -> i32 {
    let mut err = std::ptr::null_mut();
    let code = f(&mut err);
    if !err.is_null() {
        take(err);
    }
    code
}

fn json_of(f: impl FnOnce(*mut *mut c_char, *mut *mut c_char) -> i32) -> serde_json::Value {
    let mut out = std::ptr::null_mut();
    let mut err = std::ptr::null_mut();
    let code = f(&mut out, &mut err);
    if code != SAIL_OK {
        panic!(
            "code {}: {}",
            code,
            if err.is_null() {
                String::new()
            } else {
                take(err)
            }
        );
    }
    serde_json::from_str(&take(out)).unwrap()
}

/// A port on 127.0.0.1 that nothing has now, for TCP and UDP. From below
/// the range the system gives the sockets that ask for no port, so that
/// no connection these tests make is given it before it is bound, and in
/// turn, so that none is given twice here: the rule of sail's test
/// harness (`free_port` in sail/tests/it/common.rs), which this follows.
fn free_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    const FROM: u16 = 10_000;
    // Linux gives 32768 and up unless told otherwise, which is read;
    // macOS and Windows 49152 and up.
    let mut below = 32_768;
    #[cfg(target_os = "linux")]
    if let Some(low) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse::<u16>().ok())
    {
        if low >= FROM + 5_000 {
            below = below.min(low);
        }
    }
    let count = usize::from(below - FROM);
    // Where this process begins: far from where another does, most often.
    let first = (std::process::id() as usize).wrapping_mul(7919);
    for _ in 0..count {
        let turn = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let port = FROM + (first.wrapping_add(turn) % count) as u16;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
            && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
        {
            return port;
        }
    }
    panic!("no free port on 127.0.0.1");
}

fn config(port: u16) -> String {
    serde_json::json!({
        "log": { "level": "info" },
        "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [
            { "type": "selector", "tag": "sel", "outbounds": ["a", "b"] },
            { "type": "direct", "tag": "a" },
            { "type": "direct", "tag": "b" },
        ],
        "route": { "final": "sel" },
    })
    .to_string()
}

fn new_instance(settings: Option<&str>, platform: Option<&SailPlatform>) -> SailInstance {
    let settings = settings.map(|s| CString::new(s).unwrap());
    let mut instance = 0;
    ok("new", |err| unsafe {
        sail_instance_new(
            settings.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            platform.map_or(std::ptr::null(), |p| p as *const _),
            &mut instance,
            err,
        )
    });
    assert_ne!(instance, 0);
    instance
}

fn start(instance: SailInstance, config: &str) {
    let config = CString::new(config).unwrap();
    ok("start", |err| unsafe {
        sail_instance_start(instance, config.as_ptr(), err)
    });
}

/// Starts `instance` with the configuration `config` makes for a port
/// free a moment ago, and returns that port. A port picked free is free
/// only until another test takes it before the start binds it; then the
/// start is tried again on another, a few times.
fn start_on_free_port(instance: SailInstance, config: impl Fn(u16) -> String) -> u16 {
    let mut last = String::new();
    for _ in 0..5 {
        let port = free_port();
        let text = CString::new(config(port)).unwrap();
        let mut err = std::ptr::null_mut();
        let code = unsafe { sail_instance_start(instance, text.as_ptr(), &mut err) };
        if code == SAIL_OK {
            return port;
        }
        last = if err.is_null() {
            String::new()
        } else {
            take(err)
        };
        // "Address already in use"; Windows: "Only one usage of each socket address".
        if !last.contains("in use") && !last.contains("Only one usage") {
            break;
        }
    }
    panic!("start: {}", last);
}

fn stop(instance: SailInstance) {
    ok("stop", |err| sail_instance_stop(instance, 10_000, err));
}

fn state(instance: SailInstance) -> String {
    json_of(|out, err| unsafe { sail_instance_state(instance, out, err) })["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A connection through the instance's SOCKS inbound to an echo server;
/// what it sent comes back.
fn echo_through(port: u16) {
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target = echo.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = echo.accept() {
            let mut buf = [0u8; 64];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 || s.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    });
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // SOCKS5: no authentication, then CONNECT to the echo server.
    s.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).unwrap();
    let std::net::SocketAddr::V4(v4) = target else {
        unreachable!()
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "the SOCKS connect failed");
    s.write_all(b"ping").unwrap();
    let mut back = [0u8; 4];
    s.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"ping");
}

/// A server answering every request `204 No Content`, as a delay test's
/// URL does.
fn no_content_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
            });
        }
    });
    format!("http://{}/generate_204", addr)
}

/// What a host's callbacks were told, and how often a context was
/// released.
#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<(u32, serde_json::Value)>>,
    arrived: Condvar,
    released: AtomicUsize,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A context for sail: released by `release_recorder`.
    fn context(self: &Arc<Self>) -> *mut c_void {
        Arc::into_raw(self.clone()) as *mut c_void
    }

    /// Waits for an event of `kind` that `test` takes.
    fn wait(&self, kind: u32, test: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut events = self.events.lock().unwrap();
        loop {
            if let Some((_, event)) = events.iter().find(|(k, e)| *k == kind && test(e)) {
                return event.clone();
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "no such event of kind {}: {:?}",
                kind,
                events
            );
            events = self.arrived.wait_timeout(events, left).unwrap().0;
        }
    }

    fn count(&self, kind: u32) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| *k == kind)
            .count()
    }
}

extern "C" fn record(kind: u32, json: *const c_char, context: *mut c_void) {
    let recorder = unsafe { &*(context as *const Recorder) };
    let json = unsafe { CStr::from_ptr(json) }.to_str().unwrap();
    recorder
        .events
        .lock()
        .unwrap()
        .push((kind, serde_json::from_str(json).unwrap()));
    recorder.arrived.notify_all();
}

extern "C" fn release_recorder(context: *mut c_void) {
    let recorder = unsafe { Arc::from_raw(context as *const Recorder) };
    recorder.released.fetch_add(1, Ordering::SeqCst);
}

fn subscribe(
    instance: SailInstance,
    kind: u32,
    options: Option<&str>,
    recorder: &Arc<Recorder>,
    callback: SailEventCallback,
) -> SailSubscription {
    let options = options.map(|o| CString::new(o).unwrap());
    let mut sub = 0;
    ok("subscribe", |err| unsafe {
        sail_subscribe(
            instance,
            kind,
            options.as_ref().map_or(std::ptr::null(), |o| o.as_ptr()),
            Some(callback),
            recorder.context(),
            Some(release_recorder),
            &mut sub,
            err,
        )
    });
    sub
}

fn platform_of(recorder: &Arc<Recorder>) -> SailPlatform {
    SailPlatform {
        struct_size: std::mem::size_of::<SailPlatform>() as u32,
        context: recorder.context(),
        release: Some(release_recorder),
        protect_socket: None,
        open_tun: None,
        service_stop: None,
        service_reload: None,
        find_connection_owner: None,
    }
}

/// Waits until `f` holds, for up to 10 s.
fn eventually(what: &str, f: impl Fn() -> bool) {
    eventually_within(Duration::from_secs(10), what, f)
}

/// Waits until `f` holds, for up to `limit`.
fn eventually_within(limit: Duration, what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + limit;
    while !f() {
        assert!(Instant::now() < deadline, "{}", what);
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn an_instance_is_driven_through_the_c_abi() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        let host = Recorder::new();
        let platform = platform_of(&host);
        let instance = new_instance(Some(r#"{"log_lines": 50}"#), Some(&platform));
        assert_eq!(state(instance), "idle");
        // Not running yet: what needs it says so.
        assert_eq!(
            code(|err| unsafe { sail_traffic(instance, &mut std::ptr::null_mut(), err) }),
            SAIL_ERR_STATE
        );
        let states = Recorder::new();
        let state_sub = subscribe(instance, SAIL_EVENT_STATE, None, &states, record);

        let port = free_port();
        start(instance, &config(port));
        assert_eq!(state(instance), "running");
        states.wait(SAIL_EVENT_STATE, |e| e["state"] == "running");
        let bad = CString::new("{").unwrap();
        assert_eq!(
            code(|err| unsafe { sail_instance_start(instance, bad.as_ptr(), err) }),
            SAIL_ERR_STATE,
            "started twice"
        );

        // Traffic and connections.
        echo_through(port);
        let traffic = json_of(|out, err| unsafe { sail_traffic(instance, out, err) });
        assert!(traffic["up_total"].as_u64().unwrap() >= 4, "{}", traffic);
        let connections = json_of(|out, err| unsafe { sail_connections(instance, out, err) });
        assert!(connections["connections"].is_array());
        let mut n = u64::MAX;
        ok("close all", |err| unsafe {
            sail_close_all_connections(instance, &mut n, err)
        });
        let mut closed = true;
        ok("close", |err| unsafe {
            sail_close_connection(instance, u64::MAX, &mut closed, err)
        });
        assert!(!closed);

        // Outbounds, groups, selecting.
        let groups = json_of(|out, err| unsafe { sail_groups(instance, out, err) });
        assert_eq!(groups["outbounds"][0]["tag"], "sel");
        assert_eq!(groups["outbounds"][0]["group"]["selected"], "a");
        let (sel, b, c) = (c"sel", c"b", c"c");
        ok("select", |err| unsafe {
            sail_select(instance, sel.as_ptr(), b.as_ptr(), err)
        });
        assert_eq!(
            code(|err| unsafe { sail_select(instance, sel.as_ptr(), c.as_ptr(), err) }),
            SAIL_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            code(|err| unsafe { sail_select(instance, c.as_ptr(), b.as_ptr(), err) }),
            SAIL_ERR_NOT_FOUND
        );
        let outbounds = json_of(|out, err| unsafe { sail_outbounds(instance, out, err) });
        assert_eq!(outbounds["outbounds"].as_array().unwrap().len(), 3);
        assert_eq!(outbounds["outbounds"][0]["group"]["selected"], "b");

        // Delays: one waited for, and a group's measured without waiting,
        // told by the outbounds events.
        let url = CString::new(no_content_server()).unwrap();
        let a = c"a";
        let mut delay = 0;
        ok("delay", |err| unsafe {
            sail_delay(instance, a.as_ptr(), url.as_ptr(), 5_000, &mut delay, err)
        });
        assert!(delay >= 1);
        let outbound_events = Recorder::new();
        let outbounds_sub = subscribe(
            instance,
            SAIL_EVENT_OUTBOUNDS,
            Some(r#"{"interval_ms": 100}"#),
            &outbound_events,
            record,
        );
        let mut op = 0;
        ok("url test", |err| unsafe {
            sail_url_test(instance, sel.as_ptr(), url.as_ptr(), 5_000, &mut op, err)
        });
        assert_ne!(op, 0);
        outbound_events.wait(SAIL_EVENT_OUTBOUNDS, |e| {
            e["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["tag"] == "b")
                .is_some_and(|b| !b["history"].as_array().unwrap().is_empty())
        });
        eventually("the test ended", || {
            code(|err| sail_cancel(op, err)) == SAIL_ERR_NOT_FOUND
        });

        // No Clash API, yet modes, as libbox gives its apps.
        let mode = json_of(|out, err| unsafe { sail_mode(instance, out, err) });
        assert_eq!(
            mode,
            serde_json::json!({ "mode": "Rule", "modes": ["Rule"] })
        );
        let caps = json_of(|out, err| unsafe { sail_instance_capabilities(instance, out, err) });
        assert_eq!(caps["has_tun"], false);
        assert_eq!(caps["has_modes"], true);

        // A reload with another configuration, then a bad one that leaves
        // it as it was.
        let reloaded = CString::new(
            serde_json::json!({
                "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port }],
                "outbounds": [
                    { "type": "selector", "tag": "sel", "outbounds": ["a", "b", "c"] },
                    { "type": "direct", "tag": "a" }, { "type": "direct", "tag": "b" },
                    { "type": "direct", "tag": "c" },
                ],
                "route": { "final": "sel" },
            })
            .to_string(),
        )
        .unwrap();
        ok("reload", |err| unsafe {
            sail_instance_reload(instance, reloaded.as_ptr(), err)
        });
        ok("select c", |err| unsafe {
            sail_select(instance, sel.as_ptr(), c.as_ptr(), err)
        });
        assert_eq!(
            code(|err| unsafe { sail_instance_reload(instance, bad.as_ptr(), err) }),
            SAIL_ERR_CONFIG
        );
        assert_eq!(state(instance), "running");
        echo_through(port);

        // Logs: kept, cleared.
        let logs = Recorder::new();
        let log_sub = subscribe(
            instance,
            SAIL_EVENT_LOG,
            Some(r#"{"level": "info"}"#),
            &logs,
            record,
        );
        let first = logs.wait(SAIL_EVENT_LOG, |e| e["reset"] == true);
        assert!(!first["lines"].as_array().unwrap().is_empty(), "{}", first);
        assert!(
            first["lines"].as_array().unwrap().len() <= 50,
            "kept at most log_lines"
        );
        ok("clear logs", |err| sail_clear_logs(instance, err));
        logs.wait(SAIL_EVENT_LOG, |e| {
            e["reset"] == true && e["lines"].as_array().unwrap().is_empty()
        });

        // Stopped, started again, stopped.
        stop(instance);
        assert_eq!(state(instance), "stopped");
        states.wait(SAIL_EVENT_STATE, |e| e["state"] == "stopped");
        stop(instance);
        start(instance, &config(port));
        echo_through(port);
        stop(instance);

        for sub in [state_sub, outbounds_sub, log_sub] {
            ok("unsubscribe", |err| sail_unsubscribe(sub, err));
            assert_eq!(code(|err| sail_unsubscribe(sub, err)), SAIL_ERR_NO_INSTANCE);
        }
        for recorder in [&states, &outbound_events, &logs] {
            assert_eq!(recorder.released.load(Ordering::SeqCst), 1);
        }
        assert_eq!(host.released.load(Ordering::SeqCst), 0, "not freed yet");
        sail_instance_free(instance);
        eventually("the platform released once", || {
            host.released.load(Ordering::SeqCst) == 1
        });
        assert_eq!(
            code(|err| unsafe { sail_instance_state(instance, &mut std::ptr::null_mut(), err) }),
            SAIL_ERR_NO_INSTANCE
        );
    });
}

#[test]
fn handles_freed_or_never_given_are_errors() {
    let _serial = serial();
    for bad in [0, 1, u64::MAX] {
        assert_eq!(
            code(|err| sail_instance_stop(bad, 0, err)),
            SAIL_ERR_NO_INSTANCE
        );
        assert_eq!(code(|err| sail_unsubscribe(bad, err)), SAIL_ERR_NO_INSTANCE);
        sail_instance_free(bad);
    }
    let instance = new_instance(None, None);
    sail_instance_free(instance);
    sail_instance_free(instance);
    let again = new_instance(None, None);
    assert_ne!(instance, again, "a freed handle is not given again");
    assert_eq!(state(again), "idle");
    assert_eq!(
        code(|err| unsafe { sail_instance_state(instance, &mut std::ptr::null_mut(), err) }),
        SAIL_ERR_NO_INSTANCE
    );
    // A bad argument is an error, not a crash.
    let mut out = 0;
    assert_eq!(
        code(|err| unsafe { sail_instance_new(c"{".as_ptr(), std::ptr::null(), &mut out, err) }),
        SAIL_ERR_CONFIG
    );
    assert_eq!(
        code(|err| unsafe {
            sail_instance_new(
                c"{\"nothing\": 1}".as_ptr(),
                std::ptr::null(),
                &mut out,
                err,
            )
        }),
        SAIL_ERR_CONFIG,
        "unknown settings are refused"
    );
    assert_eq!(
        code(|err| unsafe { sail_instance_start(again, std::ptr::null(), err) }),
        SAIL_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        code(|err| unsafe { sail_instance_start(again, c"{ \"outbounds\": 1 }".as_ptr(), err) }),
        SAIL_ERR_CONFIG
    );
    assert_eq!(state(again), "failed");
    sail_instance_free(again);
}

/// The process's threads, as the system counts them.
fn threads() -> usize {
    #[cfg(target_os = "linux")]
    return std::fs::read_dir("/proc/self/task").unwrap().count();
    #[cfg(not(target_os = "linux"))]
    {
        let out = std::process::Command::new("ps")
            .args(["-M", "-p", &std::process::id().to_string()])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .count()
            .saturating_sub(1)
    }
}

/// The process's open files.
fn files() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

/// The process's threads and files once they have held for 6 s, within
/// 90 s: what an instance before left to end on its own (a blocking
/// thread finishing its task, on a loaded machine) has ended, so that it is
/// not counted as the baseline and a leak of one thread still shows.
fn settled() -> (usize, usize) {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut seen = (threads(), files());
    let mut since = Instant::now();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        let now = (threads(), files());
        if now != seen {
            (seen, since) = (now, Instant::now());
        } else if since.elapsed() >= Duration::from_secs(6) {
            break;
        }
    }
    seen
}

#[test]
fn starts_and_stops_leave_nothing_behind() {
    let _serial = serial();
    within(Duration::from_secs(300), || {
        let port = free_port();
        // What other tests left, if one failed, is not counted.
        let (instances0, ids0, subs0) = (
            instance::live_instances(),
            instance::ids_held(),
            events::live_subscriptions(),
        );
        // Once first: what the process sets up once (logging) is not
        // counted as left behind.
        let warm = new_instance(None, None);
        start(warm, &config(port));
        stop(warm);
        sail_instance_free(warm);
        eventually("the warm-up instance is gone", || {
            instance::ids_held() == ids0
        });
        let (threads0, files0) = settled();

        let host = Recorder::new();
        let platform = platform_of(&host);
        let instance = new_instance(None, Some(&platform));
        let events = Recorder::new();
        let sub = subscribe(instance, SAIL_EVENT_STATE, None, &events, record);
        for _ in 0..200 {
            start(instance, &config(port));
            stop(instance);
        }
        assert!(events.count(SAIL_EVENT_STATE) > 0);
        ok("unsubscribe", |err| sail_unsubscribe(sub, err));
        sail_instance_free(instance);
        for _ in 0..50 {
            let instance = new_instance(None, None);
            sail_instance_free(instance);
        }
        eventually("every instance gone", || {
            instance::live_instances() == instances0 && instance::ids_held() == ids0
        });
        assert_eq!(events::live_subscriptions(), subs0);
        eventually("the platform released", || {
            host.released.load(Ordering::SeqCst) == 1
        });
        assert_eq!(host.released.load(Ordering::SeqCst), 1, "released once");
        assert_eq!(events.released.load(Ordering::SeqCst), 1);
        // What an instance leaves to end on its own ends soon after it
        // stops; a loaded machine takes longer.
        eventually_within(
            Duration::from_secs(60),
            &format!("threads back to {} and files to {}", threads0, files0),
            || threads() <= threads0 && files() <= files0,
        );
    });
}

/// A stop's report: none before any stop, then what it could not end or
/// undo (nothing here); a state that has not failed has no kind and
/// leaves nothing.
#[test]
fn a_stop_tells_what_it_could_not_end_or_undo() {
    let _serial = serial();
    within(Duration::from_secs(30), || {
        let instance = new_instance(None, None);
        let report = json_of(|out, err| unsafe { sail_instance_stop_report(instance, out, err) });
        assert!(report.is_null(), "{}", report);
        start_on_free_port(instance, config);
        let state = json_of(|out, err| unsafe { sail_instance_state(instance, out, err) });
        assert!(state["error_kind"].is_null(), "{}", state);
        assert_eq!(state["left"], serde_json::json!([]), "{}", state);
        stop(instance);
        let report = json_of(|out, err| unsafe { sail_instance_stop_report(instance, out, err) });
        assert_eq!(report["tasks"], serde_json::json!([]), "{}", report);
        assert_eq!(report["left"], serde_json::json!([]), "{}", report);
        assert!(report["waited_ms"].is_u64(), "{}", report);
        sail_instance_free(instance);
    });
}

/// A connection through it is told once routed; the other kinds are
/// followed, quiet here.
#[test]
fn what_happens_is_told_as_it_happens() {
    let _serial = serial();
    within(Duration::from_secs(30), || {
        let instance = new_instance(None, None);
        let routed = Recorder::new();
        subscribe(instance, SAIL_EVENT_ROUTED, None, &routed, record);
        let quiet = Recorder::new();
        for kind in [
            SAIL_EVENT_DNS,
            SAIL_EVENT_GROUP,
            SAIL_EVENT_DIAL,
            SAIL_EVENT_USER,
            SAIL_EVENT_SYSTEM,
        ] {
            subscribe(instance, kind, None, &quiet, record);
        }
        let port = start_on_free_port(instance, config);
        echo_through(port);
        routed.wait(SAIL_EVENT_ROUTED, |e| {
            e["inbound"] == "socks-in" && e["action"] == "outbound"
        });
        stop(instance);
        sail_instance_free(instance);
    });
}

/// An inbound added while it runs listens and carries connections; removed,
/// it closes them and listens no more; one not there is not found.
#[test]
fn inbounds_are_added_and_removed_while_it_runs() {
    let _serial = serial();
    within(Duration::from_secs(30), || {
        let instance = new_instance(None, None);
        start_on_free_port(instance, config);
        let mut added = 0;
        for _ in 0..5 {
            let port = free_port();
            let inbound = CString::new(
                serde_json::json!({
                    "type": "socks", "tag": "extra", "listen": "127.0.0.1", "listen_port": port,
                })
                .to_string(),
            )
            .unwrap();
            if code(|err| unsafe { sail_add_inbound(instance, inbound.as_ptr(), err) }) == SAIL_OK {
                added = port;
                break;
            }
        }
        assert_ne!(added, 0, "the inbound was added");
        echo_through(added);
        let tag = CString::new("extra").unwrap();
        let mut closed = u64::MAX;
        ok("remove", |err| unsafe {
            sail_remove_inbound(instance, tag.as_ptr(), &mut closed, err)
        });
        assert_ne!(closed, u64::MAX);
        assert!(std::net::TcpStream::connect(("127.0.0.1", added)).is_err());
        assert_eq!(
            code(|err| unsafe {
                sail_remove_inbound(instance, tag.as_ptr(), std::ptr::null_mut(), err)
            }),
            SAIL_ERR_NOT_FOUND
        );
        stop(instance);
        sail_instance_free(instance);
    });
}

/// A reload tells what became of the inbound: the same configuration
/// again leaves it untouched, and nothing else is built again.
#[test]
fn a_reload_tells_what_became_of_each_inbound() {
    let _serial = serial();
    within(Duration::from_secs(30), || {
        let instance = new_instance(None, None);
        let port = start_on_free_port(instance, config);
        let text = CString::new(config(port)).unwrap();
        let report = json_of(|out, err| unsafe {
            sail_instance_reload_report(instance, text.as_ptr(), out, err)
        });
        assert_eq!(report["path"], "inbounds_only", "{}", report);
        assert_eq!(
            report["inbounds"],
            serde_json::json!([{ "tag": "socks-in", "change": "untouched" }]),
            "{}",
            report
        );
        assert_eq!(report["notes"], serde_json::json!([]), "{}", report);
        stop(instance);
        sail_instance_free(instance);
    });
}

/// A reload with options rechecks the connections open when they ask it
/// to, and its report tells the recheck; without them it tells none, and
/// an option it does not know fails it, the instance as it was.
#[test]
fn a_reload_with_options_tells_its_recheck() {
    let _serial = serial();
    within(Duration::from_secs(30), || {
        let instance = new_instance(None, None);
        let port = start_on_free_port(instance, config);
        let text = CString::new(config(port)).unwrap();
        let report = json_of(|out, err| unsafe {
            sail_instance_reload_with(
                instance,
                text.as_ptr(),
                c"{\"recheck_open\": \"close_rejected\"}".as_ptr(),
                out,
                err,
            )
        });
        assert_eq!(
            report["recheck"],
            serde_json::json!({ "closed": [], "differ": [] }),
            "{}",
            report
        );
        let report = json_of(|out, err| unsafe {
            sail_instance_reload_with(instance, text.as_ptr(), std::ptr::null(), out, err)
        });
        assert!(report.get("recheck").is_none(), "{}", report);
        let mut out = std::ptr::null_mut();
        assert_eq!(
            code(|err| unsafe {
                sail_instance_reload_with(
                    instance,
                    text.as_ptr(),
                    c"{\"recheck\": \"close_rejected\"}".as_ptr(),
                    &mut out,
                    err,
                )
            }),
            SAIL_ERR_INVALID_ARGUMENT
        );
        assert!(out.is_null());
        stop(instance);
        sail_instance_free(instance);
    });
}

/// A stop's bound is the host's to set; the traffic counts the faults
/// (none here), and their event is followed.
#[test]
fn faults_are_counted_and_followed() {
    let _serial = serial();
    within(Duration::from_secs(30), || {
        let instance = new_instance(Some(r#"{"stop_within_ms": 500}"#), None);
        let faults = Recorder::new();
        subscribe(instance, SAIL_EVENT_FAULT, None, &faults, record);
        start_on_free_port(instance, config);
        let traffic = json_of(|out, err| unsafe { sail_traffic(instance, out, err) });
        assert_eq!(traffic["faults"], 0, "{}", traffic);
        stop(instance);
        assert!(faults.events.lock().unwrap().is_empty());
        sail_instance_free(instance);
    });
}

#[test]
fn instances_run_at_once_each_with_its_own_events() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        let instances: Vec<SailInstance> = (0..4).map(|_| new_instance(None, None)).collect();
        let logs: Vec<Arc<Recorder>> = instances
            .iter()
            .map(|i| {
                let logs = Recorder::new();
                subscribe(*i, SAIL_EVENT_LOG, None, &logs, record);
                logs
            })
            .collect();
        // Started at once, each on a port of its own, bound as it starts.
        let starters: Vec<_> = instances
            .iter()
            .map(|i| {
                let i = *i;
                std::thread::spawn(move || start_on_free_port(i, config))
            })
            .collect();
        let ports: Vec<u16> = starters.into_iter().map(|s| s.join().unwrap()).collect();
        for (i, port) in ports.iter().enumerate() {
            echo_through(*port);
            let own = format!("127.0.0.1:{}", port);
            logs[i].wait(SAIL_EVENT_LOG, |e| {
                e["lines"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|l| l["message"].as_str().unwrap().contains(&own))
            });
            for (j, other) in ports.iter().enumerate() {
                if i != j {
                    let other = format!("listening tcp 127.0.0.1:{}", other);
                    let events = logs[i].events.lock().unwrap();
                    assert!(
                        !events.iter().any(|(_, e)| e["lines"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|l| l["message"].as_str().unwrap().contains(&other))),
                        "instance {} logged instance {}'s line",
                        i,
                        j
                    );
                }
            }
        }
        for i in &instances {
            stop(*i);
            sail_instance_free(*i);
        }
        for log in &logs {
            eventually("released", || log.released.load(Ordering::SeqCst) == 1);
        }
    });
}

/// Whether a connection through the SOCKS inbound at `port` is let through:
/// what it sends comes back. sail answers the SOCKS request before it
/// routes, so a rule that rejects shows only in the data.
fn socks_connects(port: u16) -> bool {
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let std::net::SocketAddr::V4(v4) = echo.local_addr().unwrap() else {
        unreachable!()
    };
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = echo.accept() {
            let mut buf = [0u8; 4];
            if s.read_exact(&mut buf).is_ok() {
                let _ = s.write_all(&buf);
            }
        }
    });
    let attempt = || -> std::io::Result<bool> {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port))?;
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        s.write_all(&[5, 1, 0])?;
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply)?;
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&v4.ip().octets());
        request.extend_from_slice(&v4.port().to_be_bytes());
        s.write_all(&request)?;
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply)?;
        if reply[1] != 0 {
            return Ok(false);
        }
        s.write_all(b"ping")?;
        let mut back = [0u8; 4];
        s.read_exact(&mut back)?;
        Ok(&back == b"ping")
    };
    attempt().unwrap_or(false)
}

#[test]
fn an_instance_without_a_clash_api_has_modes_as_libbox_gives_them() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        let port = free_port();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "route": { "rules": [{ "clash_mode": "Global", "action": "reject" }] },
        })
        .to_string();
        let instance = new_instance(None, None);
        start(instance, &config);
        let mode = json_of(|out, err| unsafe { sail_mode(instance, out, err) });
        assert_eq!(
            mode,
            serde_json::json!({ "mode": "Rule", "modes": ["Rule", "Global"] })
        );
        assert!(socks_connects(port), "the Global rule matched in Rule");
        ok("set mode", |err| unsafe {
            sail_set_mode(instance, c"global".as_ptr(), err)
        });
        let mode = json_of(|out, err| unsafe { sail_mode(instance, out, err) });
        assert_eq!(mode["mode"], "Global");
        assert!(!socks_connects(port), "the Global rule did not match");
        assert_eq!(
            code(|err| unsafe { sail_set_mode(instance, c"Nothing".as_ptr(), err) }),
            SAIL_ERR_NOT_FOUND
        );
        stop(instance);
        sail_instance_free(instance);
    });
}

/// What the re-entering callbacks do, by what they are told.
struct Reentrant {
    recorder: Arc<Recorder>,
    instance: SailInstance,
    subscription: Mutex<SailSubscription>,
    code: Mutex<Option<i32>>,
}

extern "C" fn unsubscribe_itself(kind: u32, json: *const c_char, context: *mut c_void) {
    let this = unsafe { &*(context as *const Reentrant) };
    record(kind, json, Arc::as_ptr(&this.recorder) as *mut c_void);
    let sub = *this.subscription.lock().unwrap();
    if sub != 0 {
        *this.code.lock().unwrap() = Some(code(|err| sail_unsubscribe(sub, err)));
    }
}

extern "C" fn stop_and_free_on_running(kind: u32, json: *const c_char, context: *mut c_void) {
    let this = unsafe { &*(context as *const Reentrant) };
    let state: serde_json::Value =
        serde_json::from_str(unsafe { CStr::from_ptr(json) }.to_str().unwrap()).unwrap();
    record(kind, json, Arc::as_ptr(&this.recorder) as *mut c_void);
    if state["state"] == "running" {
        // Waits for the stop from the events thread: the stop needs none of
        // it.
        let stopped = code(|err| sail_instance_stop(this.instance, 10_000, err));
        let _ = state_of(this.instance);
        sail_instance_free(this.instance);
        *this.code.lock().unwrap() = Some(stopped);
    }
}

fn state_of(instance: SailInstance) -> i32 {
    let mut out = std::ptr::null_mut();
    let code = unsafe { sail_instance_state(instance, &mut out, std::ptr::null_mut()) };
    if !out.is_null() {
        take(out);
    }
    code
}

extern "C" fn release_reentrant(context: *mut c_void) {
    let this = unsafe { Box::from_raw(context as *mut Reentrant) };
    this.recorder.released.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn callbacks_may_call_back_into_sail() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        let port = free_port();
        let instance = new_instance(None, None);
        start(instance, &config(port));

        // A status callback that ends its own subscription.
        let recorder = Recorder::new();
        let this = Box::into_raw(Box::new(Reentrant {
            recorder: recorder.clone(),
            instance,
            subscription: Mutex::new(0),
            code: Mutex::new(None),
        }));
        let mut sub = 0;
        ok("subscribe", |err| unsafe {
            sail_subscribe(
                instance,
                SAIL_EVENT_STATUS,
                c"{\"interval_ms\": 100}".as_ptr(),
                Some(unsubscribe_itself),
                this as *mut c_void,
                Some(release_reentrant),
                &mut sub,
                err,
            )
        });
        unsafe { *(*this).subscription.lock().unwrap() = sub };
        eventually("it ended itself, released once", || {
            recorder.released.load(Ordering::SeqCst) == 1
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            recorder.count(SAIL_EVENT_STATUS),
            1,
            "no event after it ended"
        );
        stop(instance);
        sail_instance_free(instance);

        // A state callback that stops and frees its instance.
        let instance = new_instance(None, None);
        let recorder = Recorder::new();
        let this = Box::into_raw(Box::new(Reentrant {
            recorder: recorder.clone(),
            instance,
            subscription: Mutex::new(0),
            code: Mutex::new(None),
        }));
        let mut sub = 0;
        ok("subscribe", |err| unsafe {
            sail_subscribe(
                instance,
                SAIL_EVENT_STATE,
                std::ptr::null(),
                Some(stop_and_free_on_running),
                this as *mut c_void,
                Some(release_reentrant),
                &mut sub,
                err,
            )
        });
        let config = CString::new(config(port)).unwrap();
        // The start may see the stop the callback asked for, or not.
        let started = code(|err| unsafe { sail_instance_start(instance, config.as_ptr(), err) });
        assert!(
            started == SAIL_OK || started == SAIL_ERR_CANCELLED || started == SAIL_ERR_NO_INSTANCE,
            "{}",
            started
        );
        eventually("freed from its callback, released once", || {
            recorder.released.load(Ordering::SeqCst) == 1
        });
        assert_eq!(state_of(instance), SAIL_ERR_NO_INSTANCE);
    });
}

extern "C" fn slow(kind: u32, json: *const c_char, context: *mut c_void) {
    record(kind, json, context);
    std::thread::sleep(Duration::from_millis(1500));
}

#[test]
fn a_slow_callback_holds_up_only_its_events() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        let port = free_port();
        let instance = new_instance(None, None);
        start(instance, &config(port));
        let recorder = Recorder::new();
        let sub = subscribe(
            instance,
            SAIL_EVENT_STATUS,
            Some(r#"{"interval_ms": 100}"#),
            &recorder,
            slow,
        );
        recorder.wait(SAIL_EVENT_STATUS, |_| true);
        // The callback sleeps now: traffic and calls go on.
        let begun = Instant::now();
        echo_through(port);
        let _ = json_of(|out, err| unsafe { sail_traffic(instance, out, err) });
        assert!(
            begun.elapsed() < Duration::from_millis(1000),
            "{:?}",
            begun.elapsed()
        );
        stop(instance);
        ok("unsubscribe", |err| sail_unsubscribe(sub, err));
        assert_eq!(recorder.released.load(Ordering::SeqCst), 1);
        sail_instance_free(instance);
    });
}

#[test]
fn a_stop_while_it_starts_cancels_the_start() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        // A rule-set from a server that never answers holds the start.
        let hang = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let hang_port = hang.local_addr().unwrap().port();
        let (accepted_tx, accepted) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for s in hang.incoming() {
                held.push(s);
                let _ = accepted_tx.send(());
            }
        });
        let port = free_port();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "route": {
                "rule_set": [{ "type": "remote", "tag": "s", "format": "source",
                               "url": format!("http://127.0.0.1:{}/s.json", hang_port) }],
                "rules": [{ "rule_set": "s", "action": "reject" }],
            },
        })
        .to_string();
        let instance = new_instance(None, None);
        let starting = std::thread::spawn(move || {
            let config = CString::new(config).unwrap();
            code(|err| unsafe { sail_instance_start(instance, config.as_ptr(), err) })
        });
        accepted.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(state(instance), "starting");
        stop(instance);
        assert_eq!(starting.join().unwrap(), SAIL_ERR_CANCELLED);
        assert_eq!(state(instance), "stopped");
        sail_instance_free(instance);
    });
}

struct Protector {
    instance: Mutex<SailInstance>,
    codes: Mutex<Vec<i32>>,
}

extern "C" fn protect_and_call_back(_fd: i32, context: *mut c_void) -> bool {
    let this = unsafe { &*(context as *const Protector) };
    let instance = *this.instance.lock().unwrap();
    let code = code(|err| unsafe { sail_traffic(instance, &mut std::ptr::null_mut(), err) });
    this.codes.lock().unwrap().push(code);
    true
}

#[test]
fn a_call_that_would_wait_on_its_own_thread_fails() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        let protector = Arc::new(Protector {
            instance: Mutex::new(0),
            codes: Mutex::new(Vec::new()),
        });
        let platform = SailPlatform {
            struct_size: std::mem::size_of::<SailPlatform>() as u32,
            context: Arc::as_ptr(&protector) as *mut c_void,
            release: None,
            protect_socket: Some(protect_and_call_back),
            open_tun: None,
            service_stop: None,
            service_reload: None,
            find_connection_owner: None,
        };
        let instance = new_instance(None, Some(&platform));
        *protector.instance.lock().unwrap() = instance;
        let port = free_port();
        start(instance, &config(port));
        // The direct outbound's socket is protected as it dials.
        echo_through(port);
        let codes = protector.codes.lock().unwrap().clone();
        assert!(!codes.is_empty(), "the socket was not protected");
        assert!(
            codes.iter().all(|c| *c == SAIL_ERR_WRONG_THREAD),
            "{:?}",
            codes
        );
        stop(instance);
        sail_instance_free(instance);
    });
}

/// Where the child instance of the next test keeps its cache.
const CHILD_DIR: &str = "SAIL_FFI_TEST_CHILD_DIR";

fn cached_config(port: u16) -> String {
    let mut config: serde_json::Value = serde_json::from_str(&config(port)).unwrap();
    config["experimental"] =
        serde_json::json!({ "cache_file": { "enabled": true, "path": "cache.db" } });
    config.to_string()
}

/// Run by the next test in a process of its own: an instance with a cache
/// file, running until the process is killed.
#[test]
#[ignore = "run by an_instance_killed_with_its_process_starts_again"]
fn child_instance() {
    let Ok(dir) = std::env::var(CHILD_DIR) else {
        return;
    };
    let settings = serde_json::json!({ "cache_dir": dir, "data_dir": dir }).to_string();
    let instance = new_instance(Some(&settings), None);
    start(instance, &cached_config(free_port()));
    ok("select", |err| unsafe {
        sail_select(instance, c"sel".as_ptr(), c"b".as_ptr(), err)
    });
    std::fs::write(std::path::Path::new(&dir).join("ready"), "").unwrap();
    std::thread::sleep(Duration::from_secs(600));
}

#[test]
fn an_instance_killed_with_its_process_starts_again() {
    let _serial = serial();
    let dir = std::env::temp_dir().join(format!("sail-ffi-killed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "abi_tests::child_instance",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_DIR, &dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    eventually("the child runs", || dir.join("ready").exists());
    // As a phone kills an app: no stop, no cleanup.
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(dir.join("cache.db").exists());
    within(Duration::from_secs(60), move || {
        let settings = serde_json::json!({ "cache_dir": dir, "data_dir": dir }).to_string();
        let instance = new_instance(Some(&settings), None);
        let port = free_port();
        start(instance, &cached_config(port));
        echo_through(port);
        stop(instance);
        sail_instance_free(instance);
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// The command service, as an app's UI process reaches its tunnel
/// process's instance: through a client handle, the same calls.
#[cfg(feature = "command-server")]
mod command {
    use super::*;

    /// A socket path short enough for any system's `sun_path`.
    fn socket(name: &str) -> std::path::PathBuf {
        let path =
            std::path::PathBuf::from(format!("/tmp/sail-{}-{}.sock", name, std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn serve(instance: SailInstance, options: &str) -> i32 {
        let options = CString::new(options).unwrap();
        code(|err| unsafe { sail_instance_serve(instance, options.as_ptr(), err) })
    }

    fn connect(options: &str) -> Result<SailInstance, i32> {
        let options = CString::new(options).unwrap();
        let mut client = 0;
        match code(|err| unsafe { sail_client_connect(options.as_ptr(), &mut client, err) }) {
            SAIL_OK => Ok(client),
            code => Err(code),
        }
    }

    /// The JSON of `call` for the instance and for the client, which must
    /// be the same.
    fn same(
        instance: SailInstance,
        client: SailInstance,
        call: impl Fn(SailInstance, *mut *mut c_char, *mut *mut c_char) -> i32,
    ) -> serde_json::Value {
        let local = json_of(|out, err| call(instance, out, err));
        let remote = json_of(|out, err| call(client, out, err));
        assert_eq!(local, remote);
        local
    }

    /// A subscription's server: `/sub` a list that says what it used,
    /// `/broken` a failure.
    fn subscription_server() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let response = if request.starts_with("GET /sub ") {
                    // Clash's YAML, as a proxy-provider holds it.
                    let body =
                        "proxies:\n  - { name: s1, type: socks5, server: 127.0.0.1, port: 1 }\n";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                         subscription-userinfo: upload=1; download=2; total=3; expire=1767225600\r\n\
                         Connection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = s.write_all(response.as_bytes());
            }
        });
        port
    }

    #[test]
    fn providers_and_rule_sets_are_told_and_updated_here_and_through_a_client() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let web = subscription_server();
            let path = socket("providers");
            let instance = new_instance(None, None);
            let options = serde_json::json!({ "path": path }).to_string();
            assert_eq!(serve(instance, &options), SAIL_OK);
            let client = connect(&options).unwrap();
            let config = serde_json::json!({
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": free_port() }],
                "outbounds": [
                    { "type": "selector", "tag": "g", "providers": ["p", "sub"] },
                    { "type": "direct", "tag": "direct" },
                ],
                "outbound_providers": [{
                    "type": "inline", "tag": "p",
                    "outbounds": [{ "type": "direct", "tag": "m1" }, { "type": "direct", "tag": "m2" }]
                }, {
                    "type": "remote", "tag": "sub",
                    "url": format!("http://127.0.0.1:{}/sub", web), "download_detour": "direct"
                }, {
                    "type": "remote", "tag": "broken",
                    "url": format!("http://127.0.0.1:{}/broken", web), "download_detour": "direct"
                }],
                "route": {
                    "rule_set": [{
                        "type": "inline", "tag": "r",
                        "rules": [{ "domain_suffix": ["a.example"] }]
                    }],
                    "rules": [{ "rule_set": "r", "outbound": "direct" }],
                },
            });
            start(instance, &config.to_string());
            // A remote provider is downloaded once the instance runs.
            eventually("the subscription is downloaded", || {
                json_of(|o, e| unsafe { sail_providers(instance, o, e) })["providers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["tag"] == "sub" && p["members"] == 1)
            });

            let providers = same(instance, client, |i, o, e| unsafe {
                sail_providers(i, o, e)
            });
            let by_tag = |tag: &str| {
                providers["providers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["tag"] == tag)
                    .cloned()
                    .unwrap_or_else(|| panic!("no provider {}: {}", tag, providers))
            };
            let inline = by_tag("p");
            assert_eq!(inline["source"], "inline");
            assert_eq!(inline["members"], 2);
            let sub = by_tag("sub");
            assert_eq!(sub["source"], "remote");
            assert_eq!(sub["members"], 1);
            assert_eq!(
                sub["subscription"],
                serde_json::json!({ "upload": 1, "download": 2, "total": 3, "expire_ms": 1_767_225_600_000u64 })
            );
            assert!(sub["updated_ms"].as_u64().is_some());

            // An update waits for it; one that fails says so, and the list
            // tells the failure, without the URL.
            ok("update", |err| unsafe {
                sail_update_provider(client, c"sub".as_ptr(), err)
            });
            assert_eq!(
                code(|err| unsafe { sail_update_provider(instance, c"broken".as_ptr(), err) }),
                SAIL_ERR_IO
            );
            assert_eq!(
                code(|err| unsafe { sail_update_provider(client, c"broken".as_ptr(), err) }),
                SAIL_ERR_IO,
                "the instance's own code, through the service"
            );
            let providers = same(instance, client, |i, o, e| unsafe {
                sail_providers(i, o, e)
            });
            let broken = providers["providers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["tag"] == "broken")
                .cloned()
                .unwrap();
            let error = broken["failure"]["error"].as_str().unwrap();
            assert!(!error.is_empty());
            assert!(!error.contains(&format!("127.0.0.1:{}", web)), "{}", error);
            for call in [sail_update_provider, sail_update_rule_set] {
                assert_eq!(
                    code(|err| unsafe { call(instance, c"nope".as_ptr(), err) }),
                    SAIL_ERR_NOT_FOUND
                );
                assert_eq!(
                    code(|err| unsafe { call(client, c"nope".as_ptr(), err) }),
                    SAIL_ERR_NOT_FOUND
                );
            }

            let rule_sets = same(instance, client, |i, o, e| unsafe {
                sail_rule_sets(i, o, e)
            });
            assert_eq!(rule_sets["rule_sets"][0]["tag"], "r");
            assert_eq!(rule_sets["rule_sets"][0]["source"], "inline");
            ok("update rule-set", |err| unsafe {
                sail_update_rule_set(client, c"r".as_ptr(), err)
            });

            stop(instance);
            sail_instance_free(client);
            sail_instance_free(instance);
        });
    }

    /// A service of another release lacks a call: it fails as unsupported,
    /// and the client goes on, as a host needs when an app is updated
    /// while its old system extension still runs.
    #[test]
    fn a_call_the_service_lacks_is_unsupported_and_the_client_goes_on() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let path = socket("lacks");
            let instance = new_instance(None, None);
            let options = serde_json::json!({ "path": path }).to_string();
            assert_eq!(serve(instance, &options), SAIL_OK);
            let handle = connect(&options).unwrap();
            start(instance, &config(free_port()));
            let client = crate::command::client::client(handle).unwrap();
            let mut grpc = tonic::client::Grpc::new(client.raw.clone());
            let failed = client
                .block(async move {
                    grpc.ready()
                        .await
                        .map_err(|e| tonic::Status::unknown(e.to_string()))?;
                    grpc.unary::<crate::command::proto::Empty, crate::command::proto::Empty, _>(
                        tonic::Request::new(crate::command::proto::Empty {}),
                        http::uri::PathAndQuery::from_static(
                            "/sail.command.v1.Started/AFutureCall",
                        ),
                        tonic_prost::ProstCodec::default(),
                    )
                    .await
                })
                .unwrap()
                .unwrap_err();
            assert_eq!(
                crate::command::failure_of(failed).code,
                SAIL_ERR_UNSUPPORTED
            );
            // The same client still answers.
            assert_eq!(state(handle), "running");
            let capabilities = json_of(|o, e| unsafe { sail_instance_capabilities(handle, o, e) });
            assert_eq!(capabilities["version"], env!("CARGO_PKG_VERSION"));
            stop(instance);
            sail_instance_free(handle);
            sail_instance_free(instance);
        });
    }

    #[test]
    fn a_client_cannot_dial() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let path = socket("dial");
            let instance = new_instance(None, None);
            let options = serde_json::json!({ "path": path }).to_string();
            assert_eq!(serve(instance, &options), SAIL_OK);
            let client = connect(&options).unwrap();
            start(instance, &config(free_port()));
            let mut fd = -1;
            assert_eq!(
                code(|err| unsafe {
                    sail_dial(
                        client,
                        c"a".as_ptr(),
                        c"tcp".as_ptr(),
                        c"127.0.0.1".as_ptr(),
                        1,
                        1_000,
                        &mut fd,
                        err,
                    )
                }),
                SAIL_ERR_UNSUPPORTED,
                "a descriptor does not cross processes"
            );
            assert_eq!(fd, -1);
            stop(instance);
            sail_instance_free(client);
            sail_instance_free(instance);
        });
    }

    #[test]
    fn a_client_answers_as_the_instance_it_reaches() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let path = socket("parity");
            let instance = new_instance(None, None);
            let options = serde_json::json!({ "path": path }).to_string();
            assert_eq!(serve(instance, &options), SAIL_OK);
            // Served while idle, as libbox's is.
            let client = connect(&options).unwrap();
            assert_ne!(client, instance);
            assert_eq!(state(client), "idle");
            assert_eq!(
                code(|err| unsafe { sail_traffic(client, &mut std::ptr::null_mut(), err) }),
                SAIL_ERR_STATE,
                "the instance's own code, through the service"
            );
            let states = Recorder::new();
            subscribe(client, SAIL_EVENT_STATE, None, &states, record);

            let port = free_port();
            start(instance, &config(port));
            states.wait(SAIL_EVENT_STATE, |e| e["state"] == "running");
            assert_eq!(state(client), "running");
            echo_through(port);

            same(instance, client, |i, o, e| unsafe {
                sail_outbounds(i, o, e)
            });
            same(instance, client, |i, o, e| unsafe { sail_groups(i, o, e) });
            same(instance, client, |i, o, e| unsafe { sail_mode(i, o, e) });
            same(instance, client, |i, o, e| unsafe {
                sail_instance_capabilities(i, o, e)
            });
            let traffic = json_of(|out, err| unsafe { sail_traffic(client, out, err) });
            assert!(traffic["up_total"].as_u64().unwrap() >= 4);

            // Selecting and the mode, through the client, seen here.
            ok("select", |err| unsafe {
                sail_select(client, c"sel".as_ptr(), c"b".as_ptr(), err)
            });
            let groups = json_of(|out, err| unsafe { sail_groups(instance, out, err) });
            assert_eq!(groups["outbounds"][0]["group"]["selected"], "b");
            assert_eq!(
                code(|err| unsafe { sail_select(client, c"sel".as_ptr(), c"x".as_ptr(), err) }),
                SAIL_ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                code(|err| unsafe { sail_select(client, c"x".as_ptr(), c"b".as_ptr(), err) }),
                SAIL_ERR_NOT_FOUND
            );
            ok("set mode", |err| unsafe {
                sail_set_mode(client, c"Rule".as_ptr(), err)
            });

            // Delays: one waited for, and a group's told by the outbounds.
            let url = CString::new(no_content_server()).unwrap();
            let mut delay = 0;
            ok("delay", |err| unsafe {
                sail_delay(client, c"a".as_ptr(), url.as_ptr(), 5_000, &mut delay, err)
            });
            assert!(delay >= 1);
            let outbounds = Recorder::new();
            subscribe(
                client,
                SAIL_EVENT_OUTBOUNDS,
                Some(r#"{"interval_ms": 100}"#),
                &outbounds,
                record,
            );
            let mut op = u64::MAX;
            ok("url test", |err| unsafe {
                sail_url_test(client, c"sel".as_ptr(), url.as_ptr(), 5_000, &mut op, err)
            });
            assert_eq!(op, 0, "a client's test is not cancelled");
            outbounds.wait(SAIL_EVENT_OUTBOUNDS, |e| {
                e["outbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|o| o["tag"] == "b" && !o["history"].as_array().unwrap().is_empty())
            });

            // Logs and connections, followed through the client.
            let logs = Recorder::new();
            subscribe(
                client,
                SAIL_EVENT_LOG,
                Some(r#"{"level": "info"}"#),
                &logs,
                record,
            );
            logs.wait(SAIL_EVENT_LOG, |e| e["reset"] == true);
            let connections = Recorder::new();
            subscribe(
                client,
                SAIL_EVENT_CONNECTIONS,
                Some(r#"{"interval_ms": 100}"#),
                &connections,
                record,
            );
            connections.wait(SAIL_EVENT_CONNECTIONS, |e| e["connections"].is_array());
            ok("clear logs", |err| sail_clear_logs(client, err));
            logs.wait(SAIL_EVENT_LOG, |e| {
                e["reset"] == true && e["lines"].as_array().unwrap().is_empty()
            });
            let mut closed = 0;
            ok("close all", |err| unsafe {
                sail_close_all_connections(client, &mut closed, err)
            });

            // What only the tunnel process's host does.
            assert_eq!(
                code(|err| unsafe { sail_instance_start(client, c"{}".as_ptr(), err) }),
                SAIL_ERR_UNSUPPORTED
            );
            assert_eq!(
                code(|err| unsafe { sail_set_network_state(client, c"{}".as_ptr(), err) }),
                SAIL_ERR_UNSUPPORTED
            );
            assert_eq!(serve(client, &options), SAIL_ERR_UNSUPPORTED);

            // A stop through the client: sail stops it, the host giving no
            // stop of its own.
            ok("stop", |err| sail_instance_stop(client, 0, err));
            states.wait(SAIL_EVENT_STATE, |e| e["state"] == "stopped");

            // The service closes: each subscription is told, once, and
            // released.
            assert_eq!(
                code(|err| unsafe { sail_instance_serve(instance, std::ptr::null(), err) }),
                SAIL_OK
            );
            for recorder in [&states, &outbounds, &logs, &connections] {
                recorder.wait(SAIL_EVENT_DISCONNECTED, |_| true);
                eventually("released", || recorder.released.load(Ordering::SeqCst) == 1);
                assert_eq!(recorder.count(SAIL_EVENT_DISCONNECTED), 1);
            }
            assert!(!path.exists(), "the socket file is removed");
            assert_eq!(
                code(|err| unsafe { sail_instance_state(client, &mut std::ptr::null_mut(), err) }),
                SAIL_ERR_IO
            );
            sail_instance_free(client);
            sail_instance_free(instance);
        });
    }

    struct Host {
        instance: Mutex<SailInstance>,
        reloads: AtomicUsize,
        stops: AtomicUsize,
    }

    /// The host's reload: it reloads the instance, as an app reloads its
    /// profile, calling back into sail from the service's thread.
    extern "C" fn host_reload(context: *mut c_void) -> i32 {
        let host = unsafe { &*(context as *const Host) };
        host.reloads.fetch_add(1, Ordering::SeqCst);
        let instance = *host.instance.lock().unwrap();
        code(|err| unsafe { sail_instance_reload(instance, std::ptr::null(), err) })
    }

    extern "C" fn host_stop(context: *mut c_void) -> i32 {
        let host = unsafe { &*(context as *const Host) };
        host.stops.fetch_add(1, Ordering::SeqCst);
        let instance = *host.instance.lock().unwrap();
        code(|err| sail_instance_stop(instance, 10_000, err))
    }

    #[test]
    fn a_clients_stop_and_reload_go_through_the_host() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let host = Arc::new(Host {
                instance: Mutex::new(0),
                reloads: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
            });
            let platform = SailPlatform {
                struct_size: std::mem::size_of::<SailPlatform>() as u32,
                context: Arc::as_ptr(&host) as *mut c_void,
                release: None,
                protect_socket: None,
                open_tun: None,
                service_stop: Some(host_stop),
                service_reload: Some(host_reload),
                find_connection_owner: None,
            };
            let instance = new_instance(None, Some(&platform));
            *host.instance.lock().unwrap() = instance;
            let dir = std::env::temp_dir().join(format!("sail-ffi-reload-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let file = dir.join("config.json");
            let port = free_port();
            std::fs::write(&file, config(port)).unwrap();
            let path = CString::new(file.to_str().unwrap()).unwrap();
            ok("start", |err| unsafe {
                sail_instance_start_file(instance, path.as_ptr(), err)
            });
            let socket = socket("host");
            assert_eq!(
                serve(instance, &serde_json::json!({ "path": socket }).to_string()),
                SAIL_OK
            );
            let client = connect(&serde_json::json!({ "path": socket }).to_string()).unwrap();
            ok("reload", |err| unsafe {
                sail_instance_reload(client, std::ptr::null(), err)
            });
            assert_eq!(host.reloads.load(Ordering::SeqCst), 1);
            assert_eq!(
                code(|err| unsafe { sail_instance_reload(client, c"{}".as_ptr(), err) }),
                SAIL_ERR_UNSUPPORTED
            );
            ok("stop", |err| sail_instance_stop(client, 0, err));
            assert_eq!(host.stops.load(Ordering::SeqCst), 1);
            assert_eq!(state(instance), "stopped");
            sail_instance_free(client);
            sail_instance_free(instance);
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn a_socket_in_use_is_kept_and_a_stale_one_replaced() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let path = socket("stale");
            let options = serde_json::json!({ "path": path }).to_string();
            // A file left by a process that died.
            drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
            assert!(path.exists());
            let first = new_instance(None, None);
            assert_eq!(serve(first, &options), SAIL_OK);
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            // Another instance does not take a path served.
            let second = new_instance(None, None);
            assert_eq!(serve(second, &options), SAIL_ERR_STATE);
            assert!(connect(&options).is_ok());
            // Too long a path is an error, said so.
            let long =
                serde_json::json!({ "path": format!("/tmp/{}", "x".repeat(200)) }).to_string();
            assert_eq!(serve(second, &long), SAIL_ERR_CONFIG);
            sail_instance_free(second);
            sail_instance_free(first);
            eventually("removed when freed", || !path.exists());
            // Nothing there to connect to.
            assert_eq!(connect(&options), Err(SAIL_ERR_IO));
        });
    }

    #[test]
    fn loopback_tcp_takes_the_secret_only() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let port = free_port();
            let secret = sail::generate::secret();
            let instance = new_instance(None, None);
            assert_eq!(
                serve(
                    instance,
                    &serde_json::json!({ "port": port, "secret": "short" }).to_string()
                ),
                SAIL_ERR_CONFIG
            );
            assert_eq!(
                serve(
                    instance,
                    &serde_json::json!({ "port": port, "secret": secret }).to_string()
                ),
                SAIL_OK
            );
            let wrong =
                serde_json::json!({ "port": port, "secret": sail::generate::secret() }).to_string();
            assert_eq!(connect(&wrong), Err(SAIL_ERR_INVALID_ARGUMENT));
            let client =
                connect(&serde_json::json!({ "port": port, "secret": secret }).to_string())
                    .unwrap();
            assert_eq!(state(client), "idle");
            sail_instance_free(client);
            sail_instance_free(instance);
        });
    }
}

/// Who opened a connection, as an Android host tells it (2.13).
mod owner {
    use super::*;

    /// A host that tells each connection to the blocked port is
    /// `com.blocked`'s, and the others `com.allowed`'s, with a reply as long
    /// as `packages` makes it.
    struct Owners {
        blocked: Mutex<u16>,
        padding: usize,
        calls: AtomicUsize,
        /// Connections to this port the host takes its time to tell of,
        /// as a stalled binder call would; how many it is telling of now.
        slow: Mutex<u16>,
        stalled: AtomicUsize,
    }

    extern "C" fn find(
        query: *const c_char,
        out: *mut c_char,
        out_len: usize,
        context: *mut c_void,
    ) -> isize {
        let owners = unsafe { &*(context as *const Owners) };
        owners.calls.fetch_add(1, Ordering::SeqCst);
        let query: serde_json::Value =
            serde_json::from_str(unsafe { CStr::from_ptr(query) }.to_str().unwrap()).unwrap();
        let slow = format!(":{}", *owners.slow.lock().unwrap());
        if query["destination"].as_str().unwrap().ends_with(&slow) {
            owners.stalled.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(4));
            owners.stalled.fetch_sub(1, Ordering::SeqCst);
        }
        let blocked = format!(":{}", *owners.blocked.lock().unwrap());
        let package = if query["destination"].as_str().unwrap().ends_with(&blocked) {
            "com.blocked"
        } else {
            "com.allowed"
        };
        let mut packages = vec![package.to_string()];
        packages.extend((0..owners.padding).map(|i| format!("com.padding.number{:04}", i)));
        let reply =
            serde_json::json!({ "uid": 10123, "user": null, "packages": packages }).to_string();
        if reply.len() > out_len {
            return -(reply.len() as isize);
        }
        unsafe { std::ptr::copy_nonoverlapping(reply.as_ptr(), out as *mut u8, reply.len()) };
        reply.len() as isize
    }

    fn platform(owners: &Arc<Owners>) -> SailPlatform {
        SailPlatform {
            struct_size: std::mem::size_of::<SailPlatform>() as u32,
            context: Arc::as_ptr(owners) as *mut c_void,
            release: None,
            protect_socket: None,
            open_tun: None,
            service_stop: None,
            service_reload: None,
            find_connection_owner: Some(find),
        }
    }

    fn config(port: u16, rule: serde_json::Value) -> String {
        serde_json::json!({
            "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "route": { "rules": [rule] },
        })
        .to_string()
    }

    /// A connection through the SOCKS inbound at `port` to an echo server,
    /// kept open; the echo server's port with it.
    fn open_through_socks(port: u16) -> (std::net::TcpStream, u16) {
        let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = echo.accept() {
                let mut buf = [0u8; 64];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        });
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(&[5, 1, 0]).unwrap();
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply).unwrap();
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        s.write_all(&request).unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).unwrap();
        s.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).unwrap();
        (s, echo_port)
    }

    /// The host may take its time to tell (a binder call on Android):
    /// meanwhile, on the instance's one thread, other connections go on.
    #[test]
    fn a_slow_answer_holds_up_no_other_connection() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let owners = Arc::new(Owners {
                blocked: Mutex::new(0),
                padding: 0,
                calls: AtomicUsize::new(0),
                slow: Mutex::new(0),
                stalled: AtomicUsize::new(0),
            });
            let instance = new_instance(None, Some(&platform(&owners)));
            let port = free_port();
            start(
                instance,
                &config(
                    port,
                    serde_json::json!({ "package_name": "com.blocked", "action": "reject" }),
                ),
            );
            let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            *owners.slow.lock().unwrap() = target.local_addr().unwrap().port();
            let slow_port = target.local_addr().unwrap().port();
            let slow = std::thread::spawn(move || {
                let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
                s.write_all(&[5, 1, 0]).unwrap();
                let mut reply = [0u8; 2];
                s.read_exact(&mut reply).unwrap();
                let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
                request.extend_from_slice(&slow_port.to_be_bytes());
                s.write_all(&request).unwrap();
                let mut reply = [0u8; 10];
                let _ = s.read_exact(&mut reply);
                drop(target);
            });
            eventually("the host is asked", || {
                owners.stalled.load(Ordering::SeqCst) == 1
            });
            let begun = std::time::Instant::now();
            let (_kept, _) = open_through_socks(port);
            assert!(
                begun.elapsed() < Duration::from_secs(2),
                "a connection waited {:?} on the host's answer for another",
                begun.elapsed()
            );
            assert_eq!(
                owners.stalled.load(Ordering::SeqCst),
                1,
                "the slow answer was in"
            );
            slow.join().unwrap();
            stop(instance);
            sail_instance_free(instance);
        });
    }

    #[test]
    fn a_package_rule_routes_by_the_app_the_host_names() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let owners = Arc::new(Owners {
                blocked: Mutex::new(0),
                padding: 0,
                calls: AtomicUsize::new(0),
                slow: Mutex::new(0),
                stalled: AtomicUsize::new(0),
            });
            let instance = new_instance(None, Some(&platform(&owners)));
            let port = free_port();
            start(
                instance,
                &config(
                    port,
                    serde_json::json!({ "package_name": "com.blocked", "action": "reject" }),
                ),
            );
            // com.allowed's goes through, and is listed with its app.
            let (open, echo_port) = open_through_socks(port);
            let connections = json_of(|out, err| unsafe { sail_connections(instance, out, err) });
            let c = connections["connections"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["destination"] == format!("127.0.0.1:{}", echo_port))
                .cloned()
                .unwrap();
            assert_eq!(c["uid"], 10123);
            assert_eq!(c["packages"], serde_json::json!(["com.allowed"]));
            drop(open);
            // com.blocked's is rejected.
            let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            *owners.blocked.lock().unwrap() = echo.local_addr().unwrap().port();
            drop(echo);
            assert!(!socks_connects_to(port, *owners.blocked.lock().unwrap()));
            assert!(owners.calls.load(Ordering::SeqCst) >= 2);
            stop(instance);
            sail_instance_free(instance);
        });
    }

    /// Whether a connection through the SOCKS inbound at `port` to
    /// 127.0.0.1:`target` echoes.
    fn socks_connects_to(port: u16, target: u16) -> bool {
        let echo = std::net::TcpListener::bind(("127.0.0.1", target)).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = echo.accept() {
                let mut buf = [0u8; 4];
                if s.read_exact(&mut buf).is_ok() {
                    let _ = s.write_all(&buf);
                }
            }
        });
        let attempt = || -> std::io::Result<bool> {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port))?;
            s.set_read_timeout(Some(Duration::from_secs(3)))?;
            s.write_all(&[5, 1, 0])?;
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply)?;
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&target.to_be_bytes());
            s.write_all(&request)?;
            let mut reply = [0u8; 10];
            s.read_exact(&mut reply)?;
            s.write_all(b"ping")?;
            let mut back = [0u8; 4];
            s.read_exact(&mut back)?;
            Ok(&back == b"ping")
        };
        attempt().unwrap_or(false)
    }

    #[test]
    fn a_long_answer_is_asked_for_again_with_the_room_it_needs() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let owners = Arc::new(Owners {
                blocked: Mutex::new(0),
                // About 2.5 KiB of package names: more than the first ask.
                padding: 100,
                calls: AtomicUsize::new(0),
                slow: Mutex::new(0),
                stalled: AtomicUsize::new(0),
            });
            let instance = new_instance(None, Some(&platform(&owners)));
            let port = free_port();
            start(
                instance,
                &config(
                    port,
                    serde_json::json!({ "package_name": "com.padding.number0099", "outbound": "direct" }),
                ),
            );
            let (open, _) = open_through_socks(port);
            let connections = json_of(|out, err| unsafe { sail_connections(instance, out, err) });
            assert_eq!(
                connections["connections"][0]["packages"]
                    .as_array()
                    .unwrap()
                    .len(),
                101
            );
            assert_eq!(
                owners.calls.load(Ordering::SeqCst),
                2,
                "asked once more, with room"
            );
            drop(open);
            stop(instance);
            sail_instance_free(instance);
        });
    }

    #[test]
    fn without_a_host_that_tells_a_package_rule_is_an_error() {
        let _serial = serial();
        let instance = new_instance(None, None);
        let mut rules = vec![
            serde_json::json!({ "package_name": "com.x", "action": "reject" }),
            serde_json::json!({ "package_name_regex": "^com\\.", "action": "reject" }),
        ];
        // Where sail finds the user itself (Linux, macOS), a rule on it
        // needs no host.
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            rules.push(serde_json::json!({ "user_id": [10123], "action": "reject" }));
            rules.push(serde_json::json!({ "user": ["u0_a123"], "action": "reject" }));
        }
        for rule in rules {
            let config = CString::new(config(free_port(), rule.clone())).unwrap();
            let mut err = std::ptr::null_mut();
            let code = unsafe { sail_instance_start(instance, config.as_ptr(), &mut err) };
            let message = take(err);
            assert_eq!(code, SAIL_ERR_CONFIG, "{}", rule);
            assert!(message.contains("find_connection_owner"), "{}", message);
        }
        sail_instance_free(instance);
    }

    extern "C" fn no_tun(_: *const c_char, _: *mut c_void) -> i32 {
        -1
    }

    #[test]
    fn a_host_tun_refuses_what_a_vpn_service_cannot_apply() {
        let _serial = serial();
        let platform = SailPlatform {
            open_tun: Some(no_tun),
            ..platform(&Arc::new(Owners {
                blocked: Mutex::new(0),
                padding: 0,
                calls: AtomicUsize::new(0),
                slow: Mutex::new(0),
                stalled: AtomicUsize::new(0),
            }))
        };
        let instance = new_instance(None, Some(&platform));
        for (field, value, said) in [
            (
                "include_uid",
                serde_json::json!([1000]),
                "platform: unsupported uid options",
            ),
            (
                "exclude_uid_range",
                serde_json::json!(["1000:2000"]),
                "platform: unsupported uid options",
            ),
            (
                "include_android_user",
                serde_json::json!([0]),
                "platform: unsupported android_user option",
            ),
        ] {
            let mut tun =
                serde_json::json!({ "type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"] });
            tun[field] = value;
            let config = CString::new(
                serde_json::json!({ "inbounds": [tun], "outbounds": [{ "type": "direct" }] })
                    .to_string(),
            )
            .unwrap();
            let mut err = std::ptr::null_mut();
            let code = unsafe { sail_instance_start(instance, config.as_ptr(), &mut err) };
            let message = take(err);
            assert_eq!(code, SAIL_ERR_CONFIG, "{}", field);
            assert!(message.contains(said), "{}: {}", field, message);
        }
        sail_instance_free(instance);
    }
}

#[test]
fn a_change_of_network_is_followed() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        let instance = new_instance(None, None);
        start(instance, &config(free_port()));
        let changes = Recorder::new();
        subscribe(instance, SAIL_EVENT_NETWORK, None, &changes, record);
        let push = |state: &str| {
            let state = CString::new(state).unwrap();
            ok("set network", |err| unsafe {
                sail_set_network_state(instance, state.as_ptr(), err)
            });
        };
        // The first the instance hears of is no change; the next is.
        push(r#"{"type": "wifi", "interface": "wlan0", "ssid": "home"}"#);
        push(r#"{"type": "cellular", "interface": "rmnet0"}"#);
        let change = changes.wait(SAIL_EVENT_NETWORK, |e| e["new"]["interface"] == "rmnet0");
        assert_eq!(change["reason"], "host");
        assert_eq!(change["old"]["ssid"], "home");
        assert!(change["generation"].as_u64().unwrap() >= 1);
        stop(instance);
        sail_instance_free(instance);
        eventually("released", || changes.released.load(Ordering::SeqCst) == 1);
    });
}

/// A member's HTTP server, answering every request `204 No Content`,
/// until it stops: then its port refuses connections.
struct Member {
    port: u16,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Member {
    fn serve() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let Ok((mut s, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                std::thread::spawn(move || {
                    let _ = s.set_nonblocking(false);
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 {
                            return;
                        }
                        let ok = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
                        if s.write_all(ok).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { port, stop }
    }

    /// Stops it, and returns once its port refuses connections.
    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        eventually("the member's port is closed", || {
            std::net::TcpStream::connect(("127.0.0.1", self.port)).is_err()
        });
    }
}

#[test]
fn a_group_switch_is_followed_at_once() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        let (a, b) = (Member::serve(), Member::serve());
        let port = free_port();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [
                {
                    "type": "fallback", "tag": "fb", "outbounds": ["a", "b"],
                    "url": "http://probe.test/generate_204", "interval": "1h", "lazy": false,
                },
                { "type": "redirect", "tag": "a", "server": "127.0.0.1", "server_port": a.port },
                { "type": "redirect", "tag": "b", "server": "127.0.0.1", "server_port": b.port },
            ],
            "route": { "final": "fb" },
        })
        .to_string();
        let instance = new_instance(None, None);
        start(instance, &config);
        let events = Recorder::new();
        // Looked at every 5 s: what comes sooner came of a change.
        subscribe(
            instance,
            SAIL_EVENT_OUTBOUNDS,
            Some(r#"{"interval_ms": 5000}"#),
            &events,
            record,
        );
        let fb = |e: &serde_json::Value, tag: &str| {
            e["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["tag"] == tag)
                .cloned()
                .unwrap()
        };
        // The first round done: both members up, [a] selected.
        events.wait(SAIL_EVENT_OUTBOUNDS, |e| {
            fb(e, "fb")["group"]["selected"] == "a"
                && fb(e, "b")["history"]
                    .as_array()
                    .is_some_and(|h| !h.is_empty())
        });
        // Nothing changes: nothing more is told.
        let told = events.count(SAIL_EVENT_OUTBOUNDS);
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(events.count(SAIL_EVENT_OUTBOUNDS), told);

        // [a] refuses a connection: the group leaves it, and that is told
        // well before the next look.
        a.stop();
        let switched = Instant::now();
        // A connection through the group; held open while it is routed.
        let mut conn = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        conn.write_all(&[5, 1, 0]).unwrap();
        let mut reply = [0u8; 2];
        conn.read_exact(&mut reply).unwrap();
        conn.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).unwrap();
        events.wait(SAIL_EVENT_OUTBOUNDS, |e| {
            fb(e, "fb")["group"]["selected"] == "b"
        });
        assert!(
            switched.elapsed() < Duration::from_secs(1),
            "told after {:?}",
            switched.elapsed()
        );
        drop(conn);
        stop(instance);
        sail_instance_free(instance);
        eventually("released", || events.released.load(Ordering::SeqCst) == 1);
    });
}

extern "C" fn protect_any(_fd: i32, _context: *mut c_void) -> bool {
    true
}

/// The system log (iOS's and Android's default) writes to the host's
/// platform for as long as the instance lives, and keeps it no longer.
#[test]
fn the_system_log_lets_the_platform_go_with_the_instance() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        for settings in [
            r#"{"profile": "mobile", "log_to_system": true}"#,
            r#"{"profile": "desktop", "log_to_system": true}"#,
        ] {
            let host = Recorder::new();
            let mut platform = platform_of(&host);
            platform.protect_socket = Some(protect_any);
            let instance = new_instance(Some(settings), Some(&platform));
            let port = free_port();
            start(instance, &config(port));
            echo_through(port);
            stop(instance);
            sail_instance_free(instance);
            eventually(&format!("released, with {}", settings), || {
                host.released.load(Ordering::SeqCst) == 1
            });
        }
    });
}

/// No secret of the configuration comes out through the C ABI: not in the
/// log lines a host follows at trace, not in what it reads of the
/// instance, not in the error a mistaken secret is refused with.
#[test]
fn no_secret_comes_out_through_the_c_abi() {
    const PASSWORD: &str = "pw-7e57-s3cr3t";
    const UUID: &str = "5ec7e7a1-1111-4111-8111-111111111111";
    // 32 bytes of 0x44, a Shadowsocks 2022 key.
    const PSK: &str = "REREREREREREREREREREREREREREREREREREREREREQ=";
    // 32 bytes of 0x33 and of 0x55, WireGuard keys.
    const WG_PRIVATE: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=";
    const WG_PRESHARED: &str = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=";
    const TOKEN: &str = "sub-7e57-t0ken";
    let secrets = [PASSWORD, UUID, PSK, WG_PRIVATE, WG_PRESHARED, TOKEN];
    let leaks = move |text: &str| -> Vec<&str> {
        secrets
            .iter()
            .copied()
            .filter(|s| text.contains(s))
            .collect()
    };
    let _serial = serial();
    within(Duration::from_secs(60), move || {
        let port = free_port();
        let config = serde_json::json!({
            "log": { "level": "trace" },
            "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [
                { "type": "selector", "tag": "sel",
                  "outbounds": ["direct", "trojan", "vless", "ss", "hy2"], "providers": "sub" },
                { "type": "direct", "tag": "direct" },
                { "type": "trojan", "tag": "trojan", "server": "127.0.0.1", "server_port": 9,
                  "password": PASSWORD, "tls": { "enabled": true, "server_name": "localhost" } },
                { "type": "vless", "tag": "vless", "server": "127.0.0.1", "server_port": 9, "uuid": UUID },
                { "type": "shadowsocks", "tag": "ss", "server": "127.0.0.1", "server_port": 9,
                  "method": "2022-blake3-aes-256-gcm", "password": PSK },
                { "type": "hysteria2", "tag": "hy2", "server": "127.0.0.1", "server_port": 9,
                  "password": PASSWORD, "tls": { "enabled": true, "server_name": "localhost" } },
            ],
            "endpoints": [{ "type": "wireguard", "tag": "wg", "address": ["10.0.0.2/32"],
                "private_key": WG_PRIVATE,
                "peers": [{ "address": "127.0.0.1", "port": 9, "public_key": WG_PRIVATE,
                            "pre_shared_key": WG_PRESHARED, "allowed_ips": ["0.0.0.0/0"] }] }],
            "outbound_providers": [{ "type": "remote", "tag": "sub",
                "url": format!("http://127.0.0.1:9/sub?token={}", TOKEN) }],
            "route": { "final": "direct" },
        })
        .to_string();
        let instance = new_instance(Some(r#"{"log_lines": 10000}"#), None);
        let logs = Recorder::new();
        let log_sub = subscribe(
            instance,
            SAIL_EVENT_LOG,
            Some(r#"{"level": "trace"}"#),
            &logs,
            record,
        );
        start(instance, &config);
        echo_through(port);
        let sub = c"sub";
        // The download fails, and says so without the URL's token.
        let _ = code(|err| unsafe { sail_update_provider(instance, sub.as_ptr(), err) });
        let mut told = String::new();
        for value in [
            json_of(|out, err| unsafe { sail_instance_state(instance, out, err) }),
            json_of(|out, err| unsafe { sail_outbounds(instance, out, err) }),
            json_of(|out, err| unsafe { sail_groups(instance, out, err) }),
            json_of(|out, err| unsafe { sail_connections(instance, out, err) }),
            json_of(|out, err| unsafe { sail_providers(instance, out, err) }),
            json_of(|out, err| unsafe { sail_rule_sets(instance, out, err) }),
        ] {
            told.push_str(&value.to_string());
        }
        stop(instance);
        ok("unsubscribe", |err| sail_unsubscribe(log_sub, err));
        let logged = serde_json::to_string(&*logs.events.lock().unwrap()).unwrap();
        assert!(
            logged.len() > 1000,
            "too little logged at trace: {}",
            logged
        );
        assert_eq!(leaks(&told), Vec::<&str>::new(), "{}", told);
        assert_eq!(leaks(&logged), Vec::<&str>::new(), "{}", logged);

        // Refused: the error names the field, not its value.
        let bad = "not-a-uuid-7e57-s3cr3t";
        let refused = config.replace(UUID, bad);
        let config = CString::new(refused).unwrap();
        let mut err = std::ptr::null_mut();
        let code = unsafe { sail_instance_start(instance, config.as_ptr(), &mut err) };
        assert_ne!(code, SAIL_OK);
        let message = take(err);
        assert!(!message.contains(bad), "{}", message);
        sail_instance_free(instance);
    });
}

/// A connection through a named outbound, handed to the host as one end of
/// a socket pair (`sail_dial`).
#[cfg(unix)]
mod dial {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::{UnixDatagram, UnixStream};

    /// An instance whose rules reject everything: what is dialled goes
    /// through the outbound named, never the rules. `stuck` is a SOCKS
    /// server that takes the connection and never answers.
    fn start_rejecting(instance: SailInstance, stuck: u16) {
        start(
            instance,
            &serde_json::json!({
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": free_port() }],
                "outbounds": [
                    { "type": "direct", "tag": "a" },
                    { "type": "socks", "tag": "stuck", "server": "127.0.0.1", "server_port": stuck },
                ],
                "route": { "rules": [{ "network": ["tcp", "udp"], "action": "reject" }] },
            })
            .to_string(),
        );
    }

    fn dial(
        instance: SailInstance,
        outbound: &str,
        network: &str,
        port: u16,
        timeout_ms: u32,
    ) -> Result<i32, i32> {
        let (outbound, network) = (
            CString::new(outbound).unwrap(),
            CString::new(network).unwrap(),
        );
        let mut fd = -1;
        match code(|err| unsafe {
            sail_dial(
                instance,
                outbound.as_ptr(),
                network.as_ptr(),
                c"127.0.0.1".as_ptr(),
                port,
                timeout_ms,
                &mut fd,
                err,
            )
        }) {
            SAIL_OK => Ok(fd),
            code => Err(code),
        }
    }

    /// The instance's connections dialled by the host.
    fn dialled(instance: SailInstance) -> Vec<serde_json::Value> {
        json_of(|out, err| unsafe { sail_connections(instance, out, err) })["connections"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["inbound_tag"] == "control")
            .cloned()
            .collect()
    }

    fn tcp_echo() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 || s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    fn udp_echo() -> u16 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(&buf[..n], from);
            }
        });
        port
    }

    /// A SOCKS server that takes connections and never answers.
    fn silent() -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    #[test]
    fn a_stream_through_the_outbound_named_and_gone_when_closed() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let (_silent, stuck) = silent();
            let instance = new_instance(None, None);
            start_rejecting(instance, stuck);
            let fd = dial(instance, "a", "tcp", tcp_echo(), 5_000).unwrap();
            // SAFETY: sail gave the descriptor to the host, which owns it.
            let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .write_all(b"through a, the rules rejecting all")
                .unwrap();
            let mut back = [0u8; 34];
            stream.read_exact(&mut back).unwrap();
            assert_eq!(&back, b"through a, the rules rejecting all");
            let listed = dialled(instance);
            assert_eq!(listed.len(), 1, "{:?}", listed);
            assert_eq!(listed[0]["network"], "tcp");
            assert_eq!(listed[0]["inbound_type"], "control");
            assert_eq!(listed[0]["chains"], serde_json::json!(["a"]));
            drop(stream);
            eventually("gone once the host closed it", || {
                dialled(instance).is_empty()
            });
            stop(instance);
            sail_instance_free(instance);
        });
    }

    #[test]
    fn datagrams_kept_whole_both_ways_and_gone_when_closed() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let (_silent, stuck) = silent();
            let instance = new_instance(None, None);
            start_rejecting(instance, stuck);
            let fd = dial(instance, "a", "udp", udp_echo(), 5_000).unwrap();
            // SAFETY: as above. A SOCK_SEQPACKET end on Linux reads and
            // writes as a datagram socket does.
            let socket = unsafe { UnixDatagram::from_raw_fd(fd) };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = vec![0u8; 65536];
            // Larger than any link's MTU, and empty: each whole, as sent.
            for size in [3000usize, 0, 1] {
                let sent: Vec<u8> = (0..size).map(|i| i as u8).collect();
                socket.send(&sent).unwrap();
                let n = socket.recv(&mut buf).unwrap();
                assert_eq!(&buf[..n], &sent[..], "a datagram of {} bytes", size);
            }
            let listed = dialled(instance);
            assert_eq!(listed.len(), 1, "{:?}", listed);
            assert_eq!(listed[0]["network"], "udp");
            drop(socket);
            eventually("gone once the host closed it", || {
                dialled(instance).is_empty()
            });
            stop(instance);
            sail_instance_free(instance);
        });
    }

    #[test]
    fn what_fails_says_why() {
        let _serial = serial();
        within(Duration::from_secs(60), || {
            let (_silent, stuck) = silent();
            let instance = new_instance(None, None);
            assert_eq!(
                dial(instance, "a", "tcp", 1, 1_000),
                Err(SAIL_ERR_STATE),
                "not running"
            );
            start_rejecting(instance, stuck);
            assert_eq!(
                dial(instance, "nope", "tcp", 1, 1_000),
                Err(SAIL_ERR_NOT_FOUND)
            );
            assert_eq!(
                dial(instance, "a", "sctp", 1, 1_000),
                Err(SAIL_ERR_INVALID_ARGUMENT)
            );
            // Nothing listens there.
            let closed = free_port();
            assert_eq!(dial(instance, "a", "tcp", closed, 5_000), Err(SAIL_ERR_IO));
            // The SOCKS server never answers the handshake.
            assert_eq!(
                dial(instance, "stuck", "tcp", 80, 300),
                Err(SAIL_ERR_TIMEOUT)
            );
            assert!(dialled(instance).is_empty(), "a failed dial is not listed");
            stop(instance);
            sail_instance_free(instance);
        });
    }
}
