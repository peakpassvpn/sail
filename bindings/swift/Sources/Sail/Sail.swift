// sail for Swift: an instance, or a client of one served in another
// process, through the C ABI. docs/ffi.md is the contract this keeps.

import Foundation
import SailC

/// What the host does for an instance; each is optional. Called on sail's
/// threads, never the main one: `protectSocket` as the instance dials,
/// `openTun` while it starts, the service ones when a client asks.
public struct Platform {
    /// Keeps the socket out of the host's VPN; returns whether it did.
    public var protectSocket: ((Int32) -> Bool)?
    /// Opens the TUN device the JSON request asks for; its descriptor, or
    /// a negative number.
    public var openTun: ((String) -> Int32)?
    /// Stops the instance as the host does, for a client; a SAIL code.
    public var serviceStop: (() -> Int32)?
    /// Reloads it as the host does, for a client; a SAIL code.
    public var serviceReload: (() -> Int32)?
    /// Who opened a connection; nil when the host cannot tell. Asked of
    /// every connection as it is routed, on sail's threads: be quick.
    public var findConnectionOwner: ((ConnectionQuery) -> ConnectionOwner?)?

    public init(
        protectSocket: ((Int32) -> Bool)? = nil,
        openTun: ((String) -> Int32)? = nil,
        serviceStop: (() -> Int32)? = nil,
        serviceReload: (() -> Int32)? = nil,
        findConnectionOwner: ((ConnectionQuery) -> ConnectionOwner?)? = nil
    ) {
        self.protectSocket = protectSocket
        self.openTun = openTun
        self.serviceStop = serviceStop
        self.serviceReload = serviceReload
        self.findConnectionOwner = findConnectionOwner
    }
}

final class PlatformBox {
    let platform: Platform
    init(_ platform: Platform) { self.platform = platform }

    static func of(_ context: UnsafeMutableRawPointer?) -> Platform {
        Unmanaged<PlatformBox>.fromOpaque(context!).takeUnretainedValue().platform
    }
}

/// Runs a call taking `char **err`, throwing what it failed with.
func check(_ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32) throws {
    var err: UnsafeMutablePointer<CChar>?
    let code = body(&err)
    guard code != 0 else { return }
    let message = err.map { String(cString: $0) } ?? ""
    if let err { sail_free_string(err) }
    throw SailError(code: code, message: message)
}

/// Runs a call answering JSON, freeing sail's string.
func json(
    _ body: (
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
    ) -> Int32
) throws -> String {
    var out: UnsafeMutablePointer<CChar>?
    try check { body(&out, $0) }
    defer { if let out { sail_free_string(out) } }
    return out.map { String(cString: $0) } ?? ""
}

func withOptionalCString<R>(_ string: String?, _ body: (UnsafePointer<CChar>?) throws -> R) rethrows -> R {
    if let string { return try string.withCString { try body($0) } }
    return try body(nil)
}

/// An instance, or a client reaching one in another process: the same
/// calls either way. Freed when released.
public final class Sail {
    let handle: UInt64

    init(handle: UInt64) {
        self.handle = handle
    }

    /// Makes an instance, idle until started.
    ///
    /// - Parameters:
    ///   - settings: JSON: the core's start settings and `log_lines`,
    ///     `worker_threads`, `stack_size`; nil for the defaults.
    ///   - platform: What the host does for it.
    public convenience init(settings: String? = nil, platform: Platform? = nil) throws {
        var handle: UInt64 = 0
        var raw = SailPlatform()
        raw.struct_size = UInt32(MemoryLayout<SailPlatform>.size)
        if let platform {
            raw.context = Unmanaged.passRetained(PlatformBox(platform)).toOpaque()
            raw.release = { Unmanaged<PlatformBox>.fromOpaque($0!).release() }
            if platform.protectSocket != nil {
                raw.protect_socket = { fd, context in PlatformBox.of(context).protectSocket!(fd) }
            }
            if platform.openTun != nil {
                raw.open_tun = { request, context in
                    PlatformBox.of(context).openTun!(String(cString: request!))
                }
            }
            if platform.serviceStop != nil {
                raw.service_stop = { context in PlatformBox.of(context).serviceStop!() }
            }
            if platform.serviceReload != nil {
                raw.service_reload = { context in PlatformBox.of(context).serviceReload!() }
            }
            if platform.findConnectionOwner != nil {
                raw.find_connection_owner = { query, out, outLen, context in
                    let find = PlatformBox.of(context).findConnectionOwner!
                    guard let query = try? decode(ConnectionQuery.self, String(cString: query!)),
                          let owner = find(query),
                          let reply = try? JSONEncoder().encode(owner)
                    else { return 0 }
                    // Too small: what it needs, to be asked again with.
                    guard reply.count <= outLen else { return -reply.count }
                    reply.withUnsafeBytes { bytes in
                        out!.withMemoryRebound(to: UInt8.self, capacity: outLen) {
                            $0.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: reply.count)
                        }
                    }
                    return reply.count
                }
            }
        }
        do {
            try withOptionalCString(settings) { settings in
                try check { sail_instance_new(settings, &raw, &handle, $0) }
            }
        } catch {
            // A call that fails takes nothing of the context.
            if let context = raw.context { Unmanaged<PlatformBox>.fromOpaque(context).release() }
            throw error
        }
        self.init(handle: handle)
    }

    /// Connects to the command service an instance serves in another
    /// process: `{"path"}`, `{"port", "secret"}` or `{"fd"}`.
    public static func connect(_ options: String) throws -> Sail {
        var handle: UInt64 = 0
        try check { sail_client_connect(options, &handle, $0) }
        return Sail(handle: handle)
    }

    deinit {
        sail_instance_free(handle)
    }

    /// What this build of sail has.
    public static func capabilities() throws -> Capabilities {
        try decode(Capabilities.self, json { sail_capabilities($0, $1) })
    }

    // MARK: Lifecycle

    /// Starts it with the configuration `config` (sing-box's JSON, Clash's
    /// YAML, a Surge profile); returns once it runs, or throws why not.
    public func start(config: String) throws {
        try check { sail_instance_start(handle, config, $0) }
    }

    /// Starts it from the file at `path`.
    public func start(file path: String) throws {
        try check { sail_instance_start_file(handle, path, $0) }
    }

    /// Reloads it with `config`, or from its file when nil.
    public func reload(config: String? = nil) throws {
        try withOptionalCString(config) { config in
            try check { sail_instance_reload(handle, config, $0) }
        }
    }

    /// `reload`, telling what became of each inbound; in the tunnel process
    /// only.
    public func reloadReport(config: String? = nil) throws -> ReloadReport {
        try withOptionalCString(config) { config in
            try decode(ReloadReport.self, json { sail_instance_reload_report(handle, config, $0, $1) })
        }
    }

    /// Stops it, waiting up to `timeoutMs` (0: asks only).
    public func stop(timeoutMs: UInt32 = 10_000) throws {
        try check { sail_instance_stop(handle, timeoutMs, $0) }
    }

    /// Serves it to other processes: `{"path"}` or `{"port", "secret"}`;
    /// nil stops serving.
    public func serve(_ options: String?) throws {
        try withOptionalCString(options) { options in
            try check { sail_instance_serve(handle, options, $0) }
        }
    }

    public func state() throws -> State {
        try decode(State.self, json { sail_instance_state(handle, $0, $1) })
    }

    /// What the last stop, or the end of the last run, could not end or
    /// undo; nil before any stop.
    public func stopReport() throws -> StopReport? {
        try decode(StopReport?.self, json { sail_instance_stop_report(handle, $0, $1) })
    }

    public func capabilities() throws -> InstanceCapabilities {
        try decode(InstanceCapabilities.self, json { sail_instance_capabilities(handle, $0, $1) })
    }

    // MARK: What it tells

    public func traffic() throws -> Traffic {
        try decode(Traffic.self, json { sail_traffic(handle, $0, $1) })
    }

    public func connections() throws -> [Connection] {
        try decode(Connections.self, json { sail_connections(handle, $0, $1) }).connections
    }

    @discardableResult
    public func closeConnection(_ id: UInt64) throws -> Bool {
        var closed = false
        try check { sail_close_connection(handle, id, &closed, $0) }
        return closed
    }

    @discardableResult
    public func closeAllConnections() throws -> UInt64 {
        var count: UInt64 = 0
        try check { sail_close_all_connections(handle, &count, $0) }
        return count
    }

    public func outbounds() throws -> [Outbound] {
        try decode(Outbounds.self, json { sail_outbounds(handle, $0, $1) }).outbounds
    }

    public func groups() throws -> [Outbound] {
        try decode(Outbounds.self, json { sail_groups(handle, $0, $1) }).outbounds
    }

    /// The outbound providers, in the configuration's order.
    public func providers() throws -> [Provider] {
        try decode(Providers.self, json { sail_providers(handle, $0, $1) }).providers
    }

    /// Updates the provider `tag` now, and waits until its members are in
    /// place.
    public func updateProvider(_ tag: String) throws {
        try check { sail_update_provider(handle, tag, $0) }
    }

    public func ruleSets() throws -> [RuleSet] {
        try decode(RuleSets.self, json { sail_rule_sets(handle, $0, $1) }).ruleSets
    }

    /// Updates the remote rule-set `tag` now, and waits.
    public func updateRuleSet(_ tag: String) throws {
        try check { sail_update_rule_set(handle, tag, $0) }
    }

    // MARK: What it is told

    public func select(group: String, member: String) throws {
        try check { sail_select(handle, group, member, $0) }
    }

    /// Connects to `host`:`port` through the outbound `outbound` alone,
    /// whatever the rules say, and waits until it is connected. The handle
    /// is one end of a socket pair sail relays through the outbound: a
    /// stream for TCP, one message per datagram for UDP. Closing it ends
    /// the connection. Through a client, and on Windows, unsupported.
    public func dial(
        outbound: String,
        network: DialNetwork,
        host: String,
        port: UInt16,
        timeoutMs: UInt32 = 5_000
    ) throws -> FileHandle {
        var fd: Int32 = -1
        try check { sail_dial(handle, outbound, network.rawValue, host, port, timeoutMs, &fd, $0) }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    /// Measures `tag`'s delay now, and waits; in milliseconds.
    public func delay(tag: String, url: String? = nil, timeoutMs: UInt32 = 5_000) throws -> UInt64 {
        var delay: UInt64 = 0
        try withOptionalCString(url) { url in
            try check { sail_delay(handle, tag, url, timeoutMs, &delay, $0) }
        }
        return delay
    }

    /// Measures without waiting (a group's members, for a group); the
    /// delays come in the outbounds events. Returns the test, to cancel.
    @discardableResult
    public func urlTest(tag: String, url: String? = nil, timeoutMs: UInt32 = 5_000) throws -> UInt64 {
        var operation: UInt64 = 0
        try withOptionalCString(url) { url in
            try check { sail_url_test(handle, tag, url, timeoutMs, &operation, $0) }
        }
        return operation
    }

    public static func cancel(_ operation: UInt64) throws {
        try check { sail_cancel(operation, $0) }
    }

    public func mode() throws -> Mode {
        try decode(Mode.self, json { sail_mode(handle, $0, $1) })
    }

    public func setMode(_ mode: String) throws {
        try check { sail_set_mode(handle, mode, $0) }
    }

    /// The network the host is on, as JSON: `{"type", "ssid", …}`.
    public func setNetworkState(_ state: String) throws {
        try check { sail_set_network_state(handle, state, $0) }
    }

    public func networkChanged(mtu: UInt16 = 0) throws {
        try check { sail_network_changed(handle, mtu, $0) }
    }

    public func clearLogs() throws {
        try check { sail_clear_logs(handle, $0) }
    }
}
