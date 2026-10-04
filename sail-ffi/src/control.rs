//! What the host asks of a running instance, once: its traffic and
//! connections, its outbounds and groups, delays, the mode, the network.
//! Each is sail's `control` layer, as the Clash API reads it; through a
//! command service client, the same, from the instance its service
//! serves. Calls that wait on the instance fail with
//! SAIL_ERR_WRONG_THREAD on its own threads.

use std::ffi::c_char;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::handles::Table;
use crate::instance::{local, target, SailInstance, Target};
use crate::{call, json, opt_str_arg, out_json, out_value, str_arg, Failure};

#[cfg(feature = "command-server")]
use crate::command::proto;

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
        let traffic = match target(instance)? {
            Target::Local(i) => {
                json::Traffic::of(&i.run(|m| Box::pin(async move { m.traffic().await }))?)
            }
            #[cfg(feature = "command-server")]
            Target::Remote(c) => c
                .unary(|mut s| async move { s.get_traffic(proto::Empty {}).await })?
                .into(),
        };
        out_json(out, &traffic)
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
        let connections: Vec<json::Connection> = match target(instance)? {
            Target::Local(i) => i
                .run(|m| Box::pin(async move { m.connections().await }))?
                .iter()
                .map(json::Connection::of)
                .collect(),
            #[cfg(feature = "command-server")]
            Target::Remote(c) => c
                .unary(|mut s| async move { s.get_connections(proto::Empty {}).await })?
                .connections
                .into_iter()
                .map(Into::into)
                .collect(),
        };
        out_json(out, &json::Connections { connections })
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
        let found = match target(instance)? {
            Target::Local(i) => {
                i.run(move |m| Box::pin(async move { m.close_connection(id).await }))?
            }
            #[cfg(feature = "command-server")]
            Target::Remote(c) => {
                c.unary(move |mut s| async move {
                    s.close_connection(proto::CloseConnectionRequest { id })
                        .await
                })?
                .closed
            }
        };
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
        let n = match target(instance)? {
            Target::Local(i) => {
                i.run(|m| Box::pin(async move { m.close_all_connections().await }))? as u64
            }
            #[cfg(feature = "command-server")]
            Target::Remote(c) => {
                c.unary(|mut s| async move { s.close_all_connections(proto::Empty {}).await })?
                    .count
            }
        };
        if !count.is_null() {
            out_value(count, n)?;
        }
        Ok(())
    })
}

fn outbounds(instance: SailInstance, groups: bool) -> Result<json::Outbounds, Failure> {
    Ok(json::Outbounds {
        outbounds: match target(instance)? {
            Target::Local(i) => i
                .run(move |m| {
                    Box::pin(async move {
                        if groups {
                            m.groups().await
                        } else {
                            m.outbounds().await
                        }
                    })
                })?
                .iter()
                .map(json::Outbound::of)
                .collect(),
            #[cfg(feature = "command-server")]
            Target::Remote(c) => c
                .unary(move |mut s| async move {
                    s.get_outbounds(proto::OutboundsRequest { groups }).await
                })?
                .outbounds
                .into_iter()
                .map(Into::into)
                .collect(),
        },
    })
}

/// The outbounds, members of outbound providers too, as JSON:
/// `{"outbounds": [{"tag", "kind" (Mihomo's type name), "protocol"
/// (sing-box's, null for a provider's member), "provider", "udp",
/// "history": [{"time_ms", "delay_ms" (null for a failure)}], "group":
/// {"selected", "members", "selectable"} or null}]}`, in the
/// configuration's order.
#[no_mangle]
pub unsafe extern "C" fn sail_outbounds(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || out_json(out, &outbounds(instance, false)?))
}

/// The groups: the outbounds that select among members, as
/// `sail_outbounds` gives them.
#[no_mangle]
pub unsafe extern "C" fn sail_groups(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || out_json(out, &outbounds(instance, true)?))
}

/// Adds an inbound to the running instance: `inbound` is one, as
/// sing-box's configuration has it (`{"type", "tag", "listen",
/// "listen_port", ...}`). It listens when this returns. Not kept: a reload
/// or a start goes by the configuration.
///
/// @return SAIL_ERR_CONFIG when it does not read or build (a tag in use, a
///     TUN, which only a start sets up); SAIL_ERR_IO when it cannot listen;
///     SAIL_ERR_STATE when the instance does not
///     run; SAIL_ERR_UNSUPPORTED through a command service client.
#[no_mangle]
pub unsafe extern "C" fn sail_add_inbound(
    instance: SailInstance,
    inbound: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let inbound = unsafe { str_arg(inbound, "inbound") }?;
        match target(instance)? {
            Target::Local(i) => i.add_inbound(inbound),
            #[cfg(feature = "command-server")]
            Target::Remote(_) => Err(Failure::new(
                crate::SAIL_ERR_UNSUPPORTED,
                "inbounds are added in the tunnel process",
            )),
        }
    })
}

/// Removes the inbound `tag` from the running instance: it stops
/// listening, and the connections it accepted are closed at once, those of
/// other inbounds not touched. Not kept: a reload or a start goes by the
/// configuration.
///
/// @param closed Takes how many connections it closed, or null.
/// @return SAIL_ERR_NOT_FOUND with no such inbound; SAIL_ERR_STATE when
///     the instance does not run; SAIL_ERR_UNSUPPORTED through a command
///     service client.
#[no_mangle]
pub unsafe extern "C" fn sail_remove_inbound(
    instance: SailInstance,
    tag: *const c_char,
    closed: *mut u64,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let tag = unsafe { str_arg(tag, "tag") }?;
        let count = match target(instance)? {
            Target::Local(i) => i.remove_inbound(tag)?,
            #[cfg(feature = "command-server")]
            Target::Remote(_) => {
                return Err(Failure::new(
                    crate::SAIL_ERR_UNSUPPORTED,
                    "inbounds are removed in the tunnel process",
                ))
            }
        };
        if !closed.is_null() {
            unsafe { *closed = count as u64 };
        }
        Ok(())
    })
}

/// Selects `member` of the selector `group`; the choice is kept in the
/// cache file, as sing-box keeps it. A fallback is pinned to `member`
/// instead, as Mihomo pins it: it goes there while the member is up.
///
/// @return SAIL_ERR_NOT_FOUND with no such group; SAIL_ERR_INVALID_ARGUMENT
///     when it is neither a selector nor a fallback, or has no such member.
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
        match target(instance)? {
            Target::Local(i) => i
                .run(move |m| Box::pin(async move { m.select(&group, &member).await }))?
                .map_err(Failure::from),
            #[cfg(feature = "command-server")]
            Target::Remote(c) => c
                .unary(move |mut s| async move {
                    s.select_outbound(proto::SelectOutboundRequest { group, member })
                        .await
                })
                .map(|_| ()),
        }
    })
}

/// The outbound providers, as JSON: `{"providers": [{"tag", "source":
/// "remote" | "local" | "inline", "members", "updated_ms",
/// "next_update_ms" (null when it is not updated by itself), "failure":
/// {"at_ms", "error"} (the last update's, null after a success),
/// "subscription": {"upload", "download", "total", "expire_ms"} (what the
/// server says of it, or null)}]}`, in the configuration's order. No URL:
/// a subscription's carries its token. Their members are among
/// `sail_outbounds`, with their `provider`.
#[no_mangle]
pub unsafe extern "C" fn sail_providers(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let providers = match target(instance)? {
            Target::Local(i) => i
                .run(|m| Box::pin(async move { m.providers().await }))?
                .iter()
                .map(json::Provider::of)
                .collect(),
            #[cfg(feature = "command-server")]
            Target::Remote(c) => c
                .unary(|mut s| async move { s.get_providers(proto::Empty {}).await })?
                .providers
                .into_iter()
                .map(Into::into)
                .collect(),
        };
        out_json(out, &json::Providers { providers })
    })
}

/// Downloads the outbound provider `tag` again, or reads its file again,
/// and waits until its members are in place.
///
/// @return SAIL_ERR_NOT_FOUND with no such provider; SAIL_ERR_IO when the
///     update failed, which `sail_providers` then tells too;
///     SAIL_ERR_STATE when the instance is stopping.
#[no_mangle]
pub unsafe extern "C" fn sail_update_provider(
    instance: SailInstance,
    tag: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let tag = unsafe { str_arg(tag, "tag") }?.to_string();
        match target(instance)? {
            Target::Local(i) => i
                .run(move |m| Box::pin(async move { m.update_provider(&tag).await }))?
                .map_err(Failure::from),
            #[cfg(feature = "command-server")]
            Target::Remote(c) => c
                .unary(
                    move |mut s| async move { s.update_provider(proto::TagRequest { tag }).await },
                )
                .map(|_| ()),
        }
    })
}

/// The rule-sets, as JSON: `{"rule_sets": [{"tag", "source": "remote" |
/// "local" | "inline", "format", "behavior", "rules", "updated_ms",
/// "next_update_ms", "failure": {"at_ms", "error"}}]}`, by tag.
#[no_mangle]
pub unsafe extern "C" fn sail_rule_sets(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let rule_sets = match target(instance)? {
            Target::Local(i) => i
                .run(|m| Box::pin(async move { m.rule_sets().await }))?
                .iter()
                .map(json::RuleSet::of)
                .collect(),
            #[cfg(feature = "command-server")]
            Target::Remote(c) => c
                .unary(|mut s| async move { s.get_rule_sets(proto::Empty {}).await })?
                .rule_sets
                .into_iter()
                .map(Into::into)
                .collect(),
        };
        out_json(out, &json::RuleSets { rule_sets })
    })
}

/// Downloads the remote rule-set `tag` again and waits until its rules are
/// in place; a local or inline one is as it is.
///
/// @return SAIL_ERR_NOT_FOUND with no such rule-set; SAIL_ERR_IO when the
///     update failed; SAIL_ERR_STATE when the instance is stopping.
#[no_mangle]
pub unsafe extern "C" fn sail_update_rule_set(
    instance: SailInstance,
    tag: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let tag = unsafe { str_arg(tag, "tag") }?.to_string();
        match target(instance)? {
            Target::Local(i) => i
                .run(move |m| Box::pin(async move { m.update_rule_set(&tag).await }))?
                .map_err(Failure::from),
            #[cfg(feature = "command-server")]
            Target::Remote(c) => c
                .unary(
                    move |mut s| async move { s.update_rule_set(proto::TagRequest { tag }).await },
                )
                .map(|_| ()),
        }
    })
}

/// Connects to `host`:`port` through the outbound `outbound` alone,
/// whatever the rules say, and waits until it is connected: the outbound's
/// handshake done. The connection is counted and listed as one of its own,
/// its inbound `control`, until it ends.
///
/// @param network `tcp` or `udp`.
/// @param fd Takes one end of a socket pair that sail relays through the
///     outbound: the host's to own, read, write and close; closing it ends
///     the connection. TCP: a stream. UDP: one message per datagram, both
///     ways, to and from `host`:`port` alone; SOCK_SEQPACKET on Linux and
///     Android, SOCK_DGRAM on Apple's systems, each end's buffers 256 KiB.
/// @return SAIL_ERR_NOT_FOUND with no such outbound; SAIL_ERR_TIMEOUT
///     when `timeout_ms` passed first; SAIL_ERR_IO when the outbound
///     failed to connect; SAIL_ERR_STATE when the instance does not run;
///     SAIL_ERR_UNSUPPORTED through a command service client (a descriptor
///     does not cross processes) and on Windows.
#[no_mangle]
pub unsafe extern "C" fn sail_dial(
    instance: SailInstance,
    outbound: *const c_char,
    network: *const c_char,
    host: *const c_char,
    port: u16,
    timeout_ms: u32,
    fd: *mut i32,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        if fd.is_null() {
            return Err(Failure::invalid("the out pointer is null"));
        }
        let outbound = unsafe { str_arg(outbound, "outbound") }?.to_string();
        let network = match unsafe { str_arg(network, "network") }? {
            "tcp" => sail::session::Network::Tcp,
            "udp" => sail::session::Network::Udp,
            other => {
                return Err(Failure::invalid(format!(
                    "network: tcp or udp, not {:?}",
                    other
                )))
            }
        };
        let host = unsafe { str_arg(host, "host") }?.to_string();
        let destination = sail::session::SocksAddr::try_from((host, port))
            .map_err(|e| Failure::invalid(format!("host: {}", e)))?;
        let timeout = timeout(timeout_ms)?;
        // One arm without the command service, two with it.
        #[allow(clippy::infallible_destructuring_match)]
        let instance = match target(instance)? {
            Target::Local(i) => i,
            #[cfg(feature = "command-server")]
            Target::Remote(_) => {
                return Err(Failure::new(
                    crate::SAIL_ERR_UNSUPPORTED,
                    "a descriptor does not cross processes: dial in the tunnel process",
                ))
            }
        };
        dial_fd(instance, outbound, network, destination, timeout, fd)
    })
}

#[cfg(unix)]
fn dial_fd(
    instance: Arc<crate::instance::Instance>,
    outbound: String,
    network: sail::session::Network,
    destination: sail::session::SocksAddr,
    timeout: Duration,
    fd: *mut i32,
) -> Result<(), Failure> {
    use std::os::fd::IntoRawFd;
    let owned = instance.run(move |m| {
        Box::pin(async move { m.dial_fd(&outbound, network, destination, timeout).await })
    })??;
    out_value(fd, owned.into_raw_fd())
}

#[cfg(not(unix))]
fn dial_fd(
    _: Arc<crate::instance::Instance>,
    _: String,
    _: sail::session::Network,
    _: sail::session::SocksAddr,
    _: Duration,
    _: *mut i32,
) -> Result<(), Failure> {
    Err(Failure::new(
        crate::SAIL_ERR_UNSUPPORTED,
        "no socket pair on Windows: use the stream through sail::control::dial",
    ))
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
        let delay = match target(instance)? {
            Target::Local(i) => i
                .run(move |m| {
                    Box::pin(async move { m.url_test(&tag, url.as_deref(), timeout).await })
                })??
                .as_millis()
                .max(1) as u64,
            #[cfg(feature = "command-server")]
            Target::Remote(c) => {
                c.unary(move |mut s| async move {
                    s.delay(proto::UrlTestRequest {
                        tag,
                        url: url.unwrap_or_default(),
                        timeout_ms,
                    })
                    .await
                })?
                .delay_ms
            }
        };
        out_value(delay_ms, delay)
    })
}

/// Measures delays without waiting, as sing-box's apps do: of the outbound
/// `tag`, or of each member of the group `tag`. Each is kept among the
/// outbound's delays, which `sail_outbounds` and the outbounds events tell.
///
/// @param operation Takes the test's handle, for `sail_cancel`; may be
///     null. Through a command service client, it takes 0: a test there is
///     not cancelled.
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
        // One arm without the command service, two with it.
        #[allow(clippy::infallible_destructuring_match)]
        let instance = match target(instance)? {
            Target::Local(i) => i,
            #[cfg(feature = "command-server")]
            Target::Remote(c) => {
                c.unary(move |mut s| async move {
                    s.url_test(proto::UrlTestRequest {
                        tag,
                        url: url.unwrap_or_default(),
                        timeout_ms,
                    })
                    .await
                })?;
                if !operation.is_null() {
                    out_value(operation, 0)?;
                }
                return Ok(());
            }
        };
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
/// "modes"}`. An instance has modes though its configuration has no Clash
/// API, as libbox's apps do: `Rule`, unless the cache file kept another.
#[no_mangle]
pub unsafe extern "C" fn sail_mode(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let mode = match target(instance)? {
            Target::Local(i) => {
                let mode = i
                    .manager()?
                    .mode()
                    .ok_or_else(|| Failure::from(sail::control::ControlError::NoModes))?;
                json::Mode {
                    mode: mode.current,
                    modes: mode.modes,
                }
            }
            #[cfg(feature = "command-server")]
            Target::Remote(c) => {
                let status =
                    c.unary(|mut s| async move { s.get_clash_mode_status(proto::Empty {}).await })?;
                json::Mode {
                    mode: status.mode,
                    modes: status.modes,
                }
            }
        };
        out_json(out, &mode)
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
        let mode = unsafe { str_arg(mode, "mode") }?.to_string();
        match target(instance)? {
            Target::Local(i) => i.manager()?.set_mode(&mode).map_err(Failure::from),
            #[cfg(feature = "command-server")]
            Target::Remote(c) => c
                .unary(
                    move |mut s| async move { s.set_clash_mode(proto::ClashMode { mode }).await },
                )
                .map(|_| ()),
        }
    })
}

/// Tells the running instance what network the host is on, whenever it
/// changes: the rules on the network (`wifi_ssid`, `network_type`, …) and
/// the `network` groups match it. Once told, sail's own detection is left.
/// The tunnel process's host tells it, as libbox's does: not a client.
///
/// @param state JSON: `{"type": "wifi" | "cellular" | "ethernet" |
///     "other", "interface", "ssid", "bssid", "gateway", "addresses":
///     ["192.168.1.2/24"], "mcc_mnc", "expensive", "constrained",
///     "captive", "interfaces"}`, every field optional. `captive`: behind a
///     captive portal, as the host says; every connection then goes
///     straight out, whatever the rules say, until it clears.
///     `interfaces`: every interface sail may dial out of, the default's
///     among them, each `{"name", "type", "addresses", "expensive",
///     "constrained"}`, for a connection's choice of network
///     (`network_strategy`); the fields above describe the default network
///     and are what the rules go by.
/// @return SAIL_ERR_CONFIG for a state that does not read.
#[no_mangle]
pub unsafe extern "C" fn sail_set_network_state(
    instance: SailInstance,
    state: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let state = unsafe { str_arg(state, "state") }?;
        let id = local(instance)?.id;
        sail::set_network_state(id, state).map_err(Failure::from)
    })
}

/// Tells the TUN inbound that the host's network changed, as after a
/// switch between Wi-Fi and cellular: flows of the previous network are
/// reset, and new ones start on the current one. The tunnel process's
/// host tells it: not a client.
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
        let instance = local(instance)?;
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
    call(err, || match target(instance)? {
        Target::Local(i) => {
            i.log.clear();
            Ok(())
        }
        #[cfg(feature = "command-server")]
        Target::Remote(c) => c
            .unary(|mut s| async move { s.clear_logs(proto::Empty {}).await })
            .map(|_| ()),
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
        let capabilities = match target(instance)? {
            Target::Local(i) => {
                let manager = i.manager()?;
                let (opens_tun, protects_sockets) = i.host_callbacks();
                json::InstanceCapabilities {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    has_tun: manager.has_tun(),
                    opens_tun: opens_tun && manager.has_tun(),
                    protects_sockets,
                    needs_network: manager.needs_network(),
                    has_modes: manager.mode().is_some(),
                }
            }
            #[cfg(feature = "command-server")]
            Target::Remote(c) => {
                let state =
                    c.unary(|mut s| async move { s.get_service_status(proto::Empty {}).await })?;
                if state.state != "running" {
                    return Err(Failure::state("the instance is not running"));
                }
                let v = c.unary(|mut s| async move { s.get_version(proto::Empty {}).await })?;
                json::InstanceCapabilities {
                    version: v.version,
                    has_tun: v.has_tun,
                    opens_tun: v.opens_tun,
                    protects_sockets: v.protects_sockets,
                    needs_network: v.needs_network,
                    has_modes: v.has_modes,
                }
            }
        };
        out_json(out, &capabilities)
    })
}
