//! What the host asks of a running instance, once: its traffic and
//! connections, its outbounds and groups, delays, the mode, the network.
//! Each is sail's `control` layer, as the Clash API and the command
//! service read it. Calls that wait on the instance fail with
//! SAIL_ERR_WRONG_THREAD on its own threads.

use std::ffi::c_char;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::handles::Table;
use crate::instance::{instance, SailInstance};
use crate::{call, json, opt_str_arg, out_json, out_value, str_arg, Failure};

/// A delay test running, as the host holds it; 0 is none.
pub type SailOperation = u64;

static OPERATIONS: Mutex<Table<Mutex<Option<tokio::task::AbortHandle>>>> = Mutex::new(Table::new());

fn operations() -> std::sync::MutexGuard<'static, Table<Mutex<Option<tokio::task::AbortHandle>>>> {
    OPERATIONS.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the instance sent and received, as JSON: `{"up_total",
/// "down_total", "connections", "memory"}`.
#[no_mangle]
pub unsafe extern "C" fn sail_traffic(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let traffic =
            self::instance(instance)?.run(|m| Box::pin(async move { m.traffic().await }))?;
        out_json(out, &json::Traffic::of(&traffic))
    })
}

/// The connections open, as JSON: `{"connections": [{"id", "network",
/// "inbound_type", "inbound_tag", "source", "destination", "host",
/// "process", "user", "upload", "download", "start", "chains", "rule"}]}`,
/// by id.
#[no_mangle]
pub unsafe extern "C" fn sail_connections(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let connections =
            self::instance(instance)?.run(|m| Box::pin(async move { m.connections().await }))?;
        out_json(
            out,
            &json::Connections {
                connections: connections.iter().map(json::Connection::of).collect(),
            },
        )
    })
}

/// Closes the connection `id`: its reads and writes fail.
///
/// @param closed Takes whether there was one so numbered; may be null.
#[no_mangle]
pub unsafe extern "C" fn sail_close_connection(
    instance: SailInstance,
    id: u64,
    closed: *mut bool,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let found = self::instance(instance)?
            .run(move |m| Box::pin(async move { m.close_connection(id).await }))?;
        if !closed.is_null() {
            out_value(closed, found)?;
        }
        Ok(())
    })
}

/// Closes every connection open.
///
/// @param count Takes how many; may be null.
#[no_mangle]
pub unsafe extern "C" fn sail_close_all_connections(
    instance: SailInstance,
    count: *mut u64,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let n = self::instance(instance)?
            .run(|m| Box::pin(async move { m.close_all_connections().await }))?;
        if !count.is_null() {
            out_value(count, n as u64)?;
        }
        Ok(())
    })
}

/// The outbounds, members of outbound providers too, as JSON:
/// `{"outbounds": [{"tag", "kind" (Mihomo's type name), "protocol"
/// (sing-box's, null for a provider's member), "provider", "udp",
/// "history": [{"time_ms", "delay_ms" (null for a failure)}], "group":
/// {"selected", "members", "selectable"} or null}]}`.
#[no_mangle]
pub unsafe extern "C" fn sail_outbounds(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let outbounds =
            self::instance(instance)?.run(|m| Box::pin(async move { m.outbounds().await }))?;
        out_json(
            out,
            &json::Outbounds {
                outbounds: outbounds.iter().map(json::Outbound::of).collect(),
            },
        )
    })
}

/// The groups: the outbounds that select among members, as
/// `sail_outbounds` gives them.
#[no_mangle]
pub unsafe extern "C" fn sail_groups(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let groups =
            self::instance(instance)?.run(|m| Box::pin(async move { m.groups().await }))?;
        out_json(
            out,
            &json::Outbounds {
                outbounds: groups.iter().map(json::Outbound::of).collect(),
            },
        )
    })
}

/// Selects `member` of the selector `group`; the choice is kept in the
/// cache file, as sing-box keeps it.
///
/// @return SAIL_ERR_NOT_FOUND with no such group; SAIL_ERR_INVALID_ARGUMENT
///     when it is not a selector, or has no such member.
#[no_mangle]
pub unsafe extern "C" fn sail_select(
    instance: SailInstance,
    group: *const c_char,
    member: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let group = unsafe { str_arg(group, "group") }?.to_string();
        let member = unsafe { str_arg(member, "member") }?.to_string();
        self::instance(instance)?
            .run(move |m| Box::pin(async move { m.select(&group, &member).await }))?
            .map_err(Failure::from)
    })
}

fn timeout(timeout_ms: u32) -> Result<Duration, Failure> {
    match timeout_ms {
        0 => Err(Failure::invalid("the timeout is 0")),
        ms => Ok(Duration::from_millis(u64::from(ms))),
    }
}

/// Measures the delay of the outbound `tag` now, with an HTTP request to
/// `url` (sing-box's default when null), and waits for it; it is kept among
/// the outbound's delays, a failure too.
///
/// @param delay_ms Takes the delay, in milliseconds.
/// @return SAIL_ERR_IO when the request failed; SAIL_ERR_TIMEOUT.
#[no_mangle]
pub unsafe extern "C" fn sail_delay(
    instance: SailInstance,
    tag: *const c_char,
    url: *const c_char,
    timeout_ms: u32,
    delay_ms: *mut u64,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        if delay_ms.is_null() {
            return Err(Failure::invalid("the out pointer is null"));
        }
        let tag = unsafe { str_arg(tag, "tag") }?.to_string();
        let url = unsafe { opt_str_arg(url, "url") }?.map(str::to_owned);
        let timeout = timeout(timeout_ms)?;
        let delay = self::instance(instance)?.run(move |m| {
            Box::pin(async move { m.url_test(&tag, url.as_deref(), timeout).await })
        })??;
        out_value(delay_ms, delay.as_millis().max(1) as u64)
    })
}

/// Measures delays without waiting, as sing-box's apps do: of the outbound
/// `tag`, or of each member of the group `tag`. Each is kept among the
/// outbound's delays, which `sail_outbounds` and the outbounds events tell.
///
/// @param operation Takes the test's handle, for `sail_cancel`; may be null.
#[no_mangle]
pub unsafe extern "C" fn sail_url_test(
    instance: SailInstance,
    tag: *const c_char,
    url: *const c_char,
    timeout_ms: u32,
    operation: *mut SailOperation,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let tag = unsafe { str_arg(tag, "tag") }?.to_string();
        let url = unsafe { opt_str_arg(url, "url") }?.map(str::to_owned);
        let timeout = timeout(timeout_ms)?;
        let instance = self::instance(instance)?;
        let manager = instance.manager()?;
        let group = instance
            .run({
                let tag = tag.clone();
                move |m| Box::pin(async move { m.outbound(&tag).await })
            })?
            .ok_or_else(|| Failure::from(sail::control::ControlError::NotFound(tag.clone())))?
            .group
            .is_some();
        let slot = Arc::new(Mutex::new(None));
        let op = operations().insert(slot.clone());
        let runtime = manager.handle().clone();
        let task = runtime.spawn(async move {
            if group {
                let _ = manager
                    .url_test_members(&tag, url.as_deref(), timeout)
                    .await;
            } else {
                let _ = manager.url_test(&tag, url.as_deref(), timeout).await;
            }
            operations().remove(op);
        });
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(task.abort_handle());
        if !operation.is_null() {
            out_value(operation, op)?;
        }
        Ok(())
    })
}

/// Cancels a delay test `sail_url_test` started.
///
/// @return SAIL_ERR_NOT_FOUND when it has ended.
#[no_mangle]
pub extern "C" fn sail_cancel(operation: SailOperation, err: *mut *mut c_char) -> i32 {
    call(err, || {
        let slot = operations().remove(operation).ok_or_else(|| {
            Failure::new(crate::SAIL_ERR_NOT_FOUND, "no such operation, or it ended")
        })?;
        if let Some(task) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        Ok(())
    })
}

/// The mode rules match and the modes they name, as JSON: `{"mode",
/// "modes"}`.
///
/// @return SAIL_ERR_UNSUPPORTED when the configuration has no Clash API,
///     so no mode, as in sing-box.
#[no_mangle]
pub unsafe extern "C" fn sail_mode(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let mode = self::instance(instance)?
            .manager()?
            .mode()
            .ok_or_else(|| Failure::from(sail::control::ControlError::NoModes))?;
        out_json(
            out,
            &json::Mode {
                mode: mode.current,
                modes: mode.modes,
            },
        )
    })
}

/// Switches the mode to `mode`, matched as it is, then in any case, among
/// the modes; kept in the cache file.
///
/// @return SAIL_ERR_NOT_FOUND for a mode not among them.
#[no_mangle]
pub unsafe extern "C" fn sail_set_mode(
    instance: SailInstance,
    mode: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let mode = unsafe { str_arg(mode, "mode") }?;
        self::instance(instance)?
            .manager()?
            .set_mode(mode)
            .map_err(Failure::from)
    })
}

/// Tells the running instance what network the host is on, whenever it
/// changes: the rules on the network (`wifi_ssid`, `network_type`, …) and
/// the `network` groups match it. Once told, sail's own detection is left.
///
/// @param state JSON: `{"type": "wifi" | "cellular" | "ethernet" |
///     "other", "interface", "ssid", "bssid", "gateway", "addresses":
///     ["192.168.1.2/24"], "mcc_mnc", "expensive", "constrained"}`, every
///     field optional.
/// @return SAIL_ERR_CONFIG for a state that does not read.
#[no_mangle]
pub unsafe extern "C" fn sail_set_network_state(
    instance: SailInstance,
    state: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let state = unsafe { str_arg(state, "state") }?;
        let id = self::instance(instance)?.id;
        sail::set_network_state(id, state).map_err(Failure::from)
    })
}

/// Tells the TUN inbound that the host's network changed, as after a
/// switch between Wi-Fi and cellular: flows of the previous network are
/// reset, and new ones start on the current one.
///
/// @param mtu The interface's new MTU, or 0 to keep it.
/// @return SAIL_ERR_CONFIG when there is no TUN inbound.
#[no_mangle]
pub extern "C" fn sail_network_changed(
    instance: SailInstance,
    mtu: u16,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let instance = self::instance(instance)?;
        if instance.on_own_thread() {
            return Err(Failure::new(
                crate::SAIL_ERR_WRONG_THREAD,
                "called on a thread of the instance's own",
            ));
        }
        instance.manager()?;
        let mtu = (mtu != 0).then_some(usize::from(mtu));
        sail::network_changed(instance.id, mtu).map_err(Failure::from)
    })
}

/// Forgets the lines of the instance's log kept; its log subscriptions are
/// sent `reset`.
#[no_mangle]
pub extern "C" fn sail_clear_logs(instance: SailInstance, err: *mut *mut c_char) -> i32 {
    call(err, || {
        self::instance(instance)?.log.clear();
        Ok(())
    })
}

/// What the running instance does and needs, as JSON: `{"has_tun",
/// "opens_tun" (the host opens its device), "protects_sockets",
/// "needs_network" (the host should tell it the network), "has_modes"}`.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_capabilities(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let instance = self::instance(instance)?;
        let manager = instance.manager()?;
        let (opens_tun, protects_sockets) = instance.host_callbacks();
        out_json(
            out,
            &json::InstanceCapabilities {
                has_tun: manager.has_tun(),
                opens_tun: opens_tun && manager.has_tun(),
                protects_sockets,
                needs_network: manager.needs_network(),
                has_modes: manager.mode().is_some(),
            },
        )
    })
}
