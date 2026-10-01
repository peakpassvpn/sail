// What a host follows of an instance: each kind of event as a stream.
// Ending the stream (or dropping its iterator) ends the subscription; the
// instance freed, or a client's connection lost, ends the stream.

import Foundation
import SailC

public enum EventKind: UInt32, Sendable {
    case state = 1
    case log = 2
    case status = 3
    case connections = 4
    case outbounds = 5
    case network = 6
    /// A client's connection lost: the last event of its subscriptions.
    case disconnected = 7
}

final class EventBox {
    let continuation: AsyncThrowingStream<String, Error>.Continuation
    init(_ continuation: AsyncThrowingStream<String, Error>.Continuation) {
        self.continuation = continuation
    }
}

/// Each event's JSON, yielded on sail's events thread.
private let onEvent: @convention(c) (UInt32, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = {
    kind, json, context in
    let box = Unmanaged<EventBox>.fromOpaque(context!).takeUnretainedValue()
    let event = String(cString: json!)
    if kind == EventKind.disconnected.rawValue {
        box.continuation.finish(throwing: SailError(code: SailError.io, message: "disconnected: \(event)"))
    } else {
        box.continuation.yield(event)
    }
}

/// The subscription's end: once, after its last event.
private let onRelease: @convention(c) (UnsafeMutableRawPointer?) -> Void = { context in
    let box = Unmanaged<EventBox>.fromOpaque(context!).takeRetainedValue()
    box.continuation.finish()
}

extension Sail {
    /// The events of `kind`, as sail's JSON.
    ///
    /// - Parameter options: JSON: `{"interval_ms"}`, `{"level", "backlog"}`.
    public func events(_ kind: EventKind, options: String? = nil) -> AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { continuation in
            let context = Unmanaged.passRetained(EventBox(continuation)).toOpaque()
            var subscription: UInt64 = 0
            do {
                try withOptionalCString(options) { options in
                    try check {
                        sail_subscribe(handle, kind.rawValue, options, onEvent, context, onRelease, &subscription, $0)
                    }
                }
            } catch {
                // A call that fails takes nothing of the context.
                Unmanaged<EventBox>.fromOpaque(context).release()
                continuation.finish(throwing: error)
                return
            }
            let ended = subscription
            continuation.onTermination = { _ in
                // Not here: Swift calls this holding the stream's lock, and
                // sail_unsubscribe waits for the subscription's release,
                // whose finish() takes that lock. Ended by sail already,
                // unsubscribing is no harm.
                DispatchQueue.global().async { _ = sail_unsubscribe(ended, nil) }
            }
        }
    }

    func typed<T: Decodable>(_ kind: EventKind, _ type: T.Type, options: String?) -> AsyncThrowingStream<T, Error> {
        let raw = events(kind, options: options)
        return AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    for try await json in raw {
                        continuation.yield(try decode(type, json))
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public func states() -> AsyncThrowingStream<State, Error> {
        typed(.state, State.self, options: nil)
    }

    public func logs(level: String? = nil, backlog: Bool = true) -> AsyncThrowingStream<Log, Error> {
        var options: [String: Any] = ["backlog": backlog]
        if let level { options["level"] = level }
        let json = String(data: try! JSONSerialization.data(withJSONObject: options), encoding: .utf8)
        return typed(.log, Log.self, options: json)
    }

    public func statuses(intervalMs: UInt64 = 1000) -> AsyncThrowingStream<Status, Error> {
        typed(.status, Status.self, options: "{\"interval_ms\": \(intervalMs)}")
    }

    public func connectionUpdates(intervalMs: UInt64 = 1000) -> AsyncThrowingStream<[Connection], Error> {
        let raw = typed(.connections, Connections.self, options: "{\"interval_ms\": \(intervalMs)}")
        return AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    for try await update in raw { continuation.yield(update.connections) }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public func outboundUpdates(intervalMs: UInt64 = 250) -> AsyncThrowingStream<[Outbound], Error> {
        let raw = typed(.outbounds, Outbounds.self, options: "{\"interval_ms\": \(intervalMs)}")
        return AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    for try await update in raw { continuation.yield(update.outbounds) }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}
