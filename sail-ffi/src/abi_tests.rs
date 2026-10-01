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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    }
}

/// Waits until `f` holds, for up to 10 s.
fn eventually(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
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
        let (threads0, files0) = (threads(), files());

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
        assert_eq!(host.released.load(Ordering::SeqCst), 1);
        assert_eq!(events.released.load(Ordering::SeqCst), 1);
        eventually(
            &format!("threads back to {} and files to {}", threads0, files0),
            || threads() <= threads0 && files() <= files0,
        );
    });
}

#[test]
fn instances_run_at_once_each_with_its_own_events() {
    let _serial = serial();
    within(Duration::from_secs(60), || {
        let ports: Vec<u16> = (0..4).map(|_| free_port()).collect();
        let instances: Vec<SailInstance> = ports.iter().map(|_| new_instance(None, None)).collect();
        let logs: Vec<Arc<Recorder>> = instances
            .iter()
            .map(|i| {
                let logs = Recorder::new();
                subscribe(*i, SAIL_EVENT_LOG, None, &logs, record);
                logs
            })
            .collect();
        let starters: Vec<_> = instances
            .iter()
            .zip(&ports)
            .map(|(i, p)| {
                let (i, config) = (*i, config(*p));
                std::thread::spawn(move || start(i, &config))
            })
            .collect();
        for s in starters {
            s.join().unwrap();
        }
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
