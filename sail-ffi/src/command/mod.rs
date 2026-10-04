//! The command service, as sing-box's libbox serves one to its apps: the
//! tunnel process serves its instance over a unix socket (or loopback TCP
//! with a secret), and the app's UI process connects as a client. A client
//! handle answers the same C functions an instance handle does, with the
//! same JSON, so the UI's code is the same in either process.
//!
//! The messages are the C ABI's JSON as protobuf; the errors carry sail's
//! code, so a call fails with the same SAIL_* code either way.

#[allow(clippy::all, missing_docs, unused_qualifications)]
pub(crate) mod proto;

pub(crate) mod client;
pub(crate) mod server;

use crate::{json, Failure};

/// The metadata a status carries sail's code in.
const CODE: &str = "sail-code";
/// The metadata a client gives its secret in, as libbox's do.
const SECRET: &str = "x-command-secret";

pub(crate) use sail::control::listen::Address;

/// A unix socket or a descriptor asked for where there are none.
#[cfg(not(unix))]
pub(crate) fn off_unix() -> Failure {
    Failure::new(
        crate::SAIL_ERR_UNSUPPORTED,
        "unix sockets and descriptors are not on this system: use {\"port\", \"secret\"}",
    )
}

/// What a listening address that does not do is, here.
pub(crate) fn listen_failure(e: sail::control::listen::ListenError) -> Failure {
    use sail::control::listen::ListenError as E;
    let code = match &e {
        E::Config(_) => crate::SAIL_ERR_CONFIG,
        E::InUse(_) => crate::SAIL_ERR_STATE,
        E::Io(_) => crate::SAIL_ERR_IO,
    };
    Failure::new(code, e.to_string())
}

/// `failure` as gRPC tells it, with sail's code.
pub(crate) fn status_of(failure: Failure) -> tonic::Status {
    use tonic::Code;
    let code = match failure.code {
        crate::SAIL_ERR_INVALID_ARGUMENT | crate::SAIL_ERR_CONFIG => Code::InvalidArgument,
        crate::SAIL_ERR_NOT_FOUND => Code::NotFound,
        crate::SAIL_ERR_STATE | crate::SAIL_ERR_NO_INSTANCE => Code::FailedPrecondition,
        crate::SAIL_ERR_UNSUPPORTED => Code::Unimplemented,
        crate::SAIL_ERR_TIMEOUT => Code::DeadlineExceeded,
        crate::SAIL_ERR_CANCELLED => Code::Cancelled,
        crate::SAIL_ERR_IO => Code::Unavailable,
        _ => Code::Internal,
    };
    let mut status = tonic::Status::new(code, failure.message);
    if let Ok(value) = failure.code.to_string().parse() {
        status.metadata_mut().insert(CODE, value);
    }
    status
}

/// What a call that failed with `status` fails with here.
pub(crate) fn failure_of(status: tonic::Status) -> Failure {
    use tonic::Code;
    let code = status
        .metadata()
        .get(CODE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(match status.code() {
            Code::InvalidArgument => crate::SAIL_ERR_INVALID_ARGUMENT,
            Code::NotFound => crate::SAIL_ERR_NOT_FOUND,
            Code::FailedPrecondition => crate::SAIL_ERR_STATE,
            Code::Unimplemented => crate::SAIL_ERR_UNSUPPORTED,
            Code::DeadlineExceeded => crate::SAIL_ERR_TIMEOUT,
            Code::Cancelled => crate::SAIL_ERR_CANCELLED,
            Code::Unauthenticated | Code::PermissionDenied => crate::SAIL_ERR_INVALID_ARGUMENT,
            Code::Unavailable | Code::Unknown => crate::SAIL_ERR_IO,
            _ => crate::SAIL_ERR_INTERNAL,
        });
    Failure::new(code, status.message().to_string())
}

impl From<&json::State> for proto::ServiceStatus {
    fn from(s: &json::State) -> Self {
        Self {
            state: s.state.clone(),
            error: s.error.clone(),
            started_at_ms: s.started_at_ms,
            error_kind: s.error_kind.clone(),
            left: s
                .left
                .iter()
                .map(|l| proto::LeftBehind {
                    kind: l.kind.clone(),
                    resource: l.resource.clone(),
                    why: l.why.clone(),
                    clear: l.clear.clone(),
                })
                .collect(),
        }
    }
}

impl From<proto::ServiceStatus> for json::State {
    fn from(s: proto::ServiceStatus) -> Self {
        Self {
            state: s.state,
            error: s.error,
            error_kind: s.error_kind,
            left: s
                .left
                .into_iter()
                .map(|l| json::Left {
                    kind: l.kind,
                    resource: l.resource,
                    why: l.why,
                    clear: l.clear,
                })
                .collect(),
            started_at_ms: s.started_at_ms,
        }
    }
}

impl From<&json::Traffic> for proto::Traffic {
    fn from(t: &json::Traffic) -> Self {
        Self {
            up_total: t.up_total,
            down_total: t.down_total,
            connections: t.connections as u64,
            memory: t.memory,
            faults: t.faults,
        }
    }
}

impl From<proto::Traffic> for json::Traffic {
    fn from(t: proto::Traffic) -> Self {
        Self {
            up_total: t.up_total,
            down_total: t.down_total,
            connections: t.connections as usize,
            memory: t.memory,
            faults: t.faults,
        }
    }
}

impl From<&json::Status> for proto::Status {
    fn from(s: &json::Status) -> Self {
        Self {
            up: s.up,
            down: s.down,
            up_total: s.up_total,
            down_total: s.down_total,
            connections: s.connections as u64,
            memory: s.memory,
            faults: s.faults,
        }
    }
}

impl From<proto::Status> for json::Status {
    fn from(s: proto::Status) -> Self {
        Self {
            up: s.up,
            down: s.down,
            up_total: s.up_total,
            down_total: s.down_total,
            connections: s.connections as usize,
            memory: s.memory,
            faults: s.faults,
        }
    }
}

impl From<&json::Connection> for proto::Connection {
    fn from(c: &json::Connection) -> Self {
        Self {
            id: c.id,
            network: c.network.clone(),
            inbound_type: c.inbound_type.clone(),
            inbound_tag: c.inbound_tag.clone(),
            source: c.source.clone(),
            destination: c.destination.clone(),
            host: c.host.clone(),
            sniff_host: c.sniff_host.clone(),
            dial_domain_source: c.dial_domain_source.clone(),
            process: c.process.clone(),
            user: c.user.clone(),
            uid: c.uid,
            packages: c.packages.clone(),
            upload: c.upload,
            download: c.download,
            start: c.start,
            chains: c.chains.clone(),
            rule: c.rule.clone(),
        }
    }
}

impl From<proto::Connection> for json::Connection {
    fn from(c: proto::Connection) -> Self {
        Self {
            id: c.id,
            network: c.network,
            inbound_type: c.inbound_type,
            inbound_tag: c.inbound_tag,
            source: c.source,
            destination: c.destination,
            host: c.host,
            sniff_host: c.sniff_host,
            dial_domain_source: c.dial_domain_source,
            process: c.process,
            user: c.user,
            uid: c.uid,
            packages: c.packages,
            upload: c.upload,
            download: c.download,
            start: c.start,
            chains: c.chains,
            rule: c.rule,
        }
    }
}

impl From<&json::Outbound> for proto::Outbound {
    fn from(o: &json::Outbound) -> Self {
        Self {
            tag: o.tag.clone(),
            kind: o.kind.clone(),
            protocol: o.protocol.clone(),
            provider: o.provider.clone(),
            udp: o.udp,
            history: o
                .history
                .iter()
                .map(|d| proto::Delay {
                    time_ms: d.time_ms,
                    delay_ms: d.delay_ms,
                })
                .collect(),
            group: o.group.as_ref().map(|g| proto::Group {
                selected: g.selected.clone(),
                members: g.members.clone(),
                selectable: g.selectable,
            }),
        }
    }
}

impl From<proto::Outbound> for json::Outbound {
    fn from(o: proto::Outbound) -> Self {
        Self {
            tag: o.tag,
            kind: o.kind,
            protocol: o.protocol,
            provider: o.provider,
            udp: o.udp,
            history: o
                .history
                .into_iter()
                .map(|d| json::Delay {
                    time_ms: d.time_ms,
                    delay_ms: d.delay_ms,
                })
                .collect(),
            group: o.group.map(|g| json::Group {
                selected: g.selected,
                members: g.members,
                selectable: g.selectable,
            }),
        }
    }
}

impl From<&json::Log> for proto::Log {
    fn from(l: &json::Log) -> Self {
        Self {
            reset: l.reset,
            lines: l
                .lines
                .iter()
                .map(|l| proto::LogLine {
                    level: l.level.clone(),
                    message: l.message.clone(),
                    time_ms: l.time_ms,
                })
                .collect(),
            dropped: l.dropped,
        }
    }
}

impl From<proto::Log> for json::Log {
    fn from(l: proto::Log) -> Self {
        Self {
            reset: l.reset,
            lines: l
                .lines
                .into_iter()
                .map(|l| json::LogLine {
                    level: l.level,
                    message: l.message,
                    time_ms: l.time_ms,
                })
                .collect(),
            dropped: l.dropped,
        }
    }
}

impl From<&json::Failure> for proto::UpdateFailure {
    fn from(f: &json::Failure) -> Self {
        Self {
            at_ms: f.at_ms,
            error: f.error.clone(),
        }
    }
}

impl From<proto::UpdateFailure> for json::Failure {
    fn from(f: proto::UpdateFailure) -> Self {
        Self {
            at_ms: f.at_ms,
            error: f.error,
        }
    }
}

impl From<&json::Provider> for proto::Provider {
    fn from(p: &json::Provider) -> Self {
        Self {
            tag: p.tag.clone(),
            source: p.source.clone(),
            members: p.members,
            updated_ms: p.updated_ms,
            next_update_ms: p.next_update_ms,
            failure: p.failure.as_ref().map(Into::into),
            subscription: p.subscription.as_ref().map(|s| proto::Subscription {
                upload: s.upload,
                download: s.download,
                total: s.total,
                expire_ms: s.expire_ms,
            }),
        }
    }
}

impl From<proto::Provider> for json::Provider {
    fn from(p: proto::Provider) -> Self {
        Self {
            tag: p.tag,
            source: p.source,
            members: p.members,
            updated_ms: p.updated_ms,
            next_update_ms: p.next_update_ms,
            failure: p.failure.map(Into::into),
            subscription: p.subscription.map(|s| json::Subscription {
                upload: s.upload,
                download: s.download,
                total: s.total,
                expire_ms: s.expire_ms,
            }),
        }
    }
}

impl From<&json::RuleSet> for proto::RuleSet {
    fn from(r: &json::RuleSet) -> Self {
        Self {
            tag: r.tag.clone(),
            source: r.source.clone(),
            format: r.format.clone(),
            behavior: r.behavior.clone(),
            rules: r.rules,
            updated_ms: r.updated_ms,
            next_update_ms: r.next_update_ms,
            failure: r.failure.as_ref().map(Into::into),
        }
    }
}

impl From<proto::RuleSet> for json::RuleSet {
    fn from(r: proto::RuleSet) -> Self {
        Self {
            tag: r.tag,
            source: r.source,
            format: r.format,
            behavior: r.behavior,
            rules: r.rules,
            updated_ms: r.updated_ms,
            next_update_ms: r.next_update_ms,
            failure: r.failure.map(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_crosses_with_its_code() {
        for code in [
            crate::SAIL_ERR_NOT_FOUND,
            crate::SAIL_ERR_STATE,
            crate::SAIL_ERR_WRONG_THREAD,
            crate::SAIL_ERR_UNSUPPORTED,
        ] {
            let back = failure_of(status_of(Failure::new(code, "why")));
            assert_eq!(back, Failure::new(code, "why"));
        }
        // From a server that gives no code: by gRPC's.
        assert_eq!(
            failure_of(tonic::Status::not_found("x")).code,
            crate::SAIL_ERR_NOT_FOUND
        );
    }
}
