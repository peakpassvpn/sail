// What sail answers with: its JSON (sail::control::json), decoded.

import Foundation

/// A call that failed: its `SAIL_ERR_*` code, and what sail said.
public struct SailError: Error, CustomStringConvertible, Equatable {
    public let code: Int32
    public let message: String

    public var description: String { "sail error \(code): \(message)" }

    public static let invalidArgument: Int32 = 1
    public static let noInstance: Int32 = 2
    public static let state: Int32 = 3
    public static let config: Int32 = 4
    public static let io: Int32 = 5
    public static let notFound: Int32 = 6
    public static let unsupported: Int32 = 7
    public static let cancelled: Int32 = 8
    public static let timeout: Int32 = 9
    public static let wrongThread: Int32 = 10
    public static let `internal`: Int32 = 11
}

public struct State: Decodable, Equatable, Sendable {
    /// idle, starting, running, stopping, stopped or failed.
    public let state: String
    public let error: String?
    public let startedAtMs: UInt64?
}

public struct Traffic: Decodable, Equatable, Sendable {
    public let upTotal: UInt64
    public let downTotal: UInt64
    public let connections: Int
    public let memory: UInt64
}

/// A status event: the traffic, and its rate in bytes a second.
public struct Status: Decodable, Equatable, Sendable {
    public let up: UInt64
    public let down: UInt64
    public let upTotal: UInt64
    public let downTotal: UInt64
    public let connections: Int
    public let memory: UInt64
}

public struct Connection: Decodable, Equatable, Sendable {
    public let id: UInt64
    public let network: String
    public let inboundType: String
    public let inboundTag: String
    public let source: String
    public let destination: String
    public let host: String?
    public let process: String?
    public let user: String?
    public let upload: UInt64
    public let download: UInt64
    /// Unix seconds.
    public let start: UInt32
    public let chains: [String]
    public let rule: String?
}

public struct Delay: Decodable, Equatable, Sendable {
    public let timeMs: UInt64
    /// nil for a test that failed.
    public let delayMs: UInt64?
}

public struct Group: Decodable, Equatable, Sendable {
    public let selected: String
    public let members: [String]
    public let selectable: Bool
}

public struct Outbound: Decodable, Equatable, Sendable {
    public let tag: String
    /// Mihomo's type name: Selector, Vless, Direct.
    public let kind: String
    /// sing-box's type; nil for a provider's member.
    public let `protocol`: String?
    public let provider: String?
    public let udp: Bool
    public let history: [Delay]
    public let group: Group?
}

public struct Mode: Decodable, Equatable, Sendable {
    public let mode: String
    public let modes: [String]
}

public struct LogLine: Decodable, Equatable, Sendable {
    public let level: String
    public let message: String
    public let timeMs: UInt64
}

/// A log event: `reset` drops the lines had so far.
public struct Log: Decodable, Equatable, Sendable {
    public let reset: Bool
    public let lines: [LogLine]
    public let dropped: UInt64
}

public struct InstanceCapabilities: Decodable, Equatable, Sendable {
    public let hasTun: Bool
    public let opensTun: Bool
    public let protectsSockets: Bool
    public let needsNetwork: Bool
    public let hasModes: Bool
}

public struct Capabilities: Decodable, Equatable, Sendable {
    public let apiVersion: UInt32
    public let jsonVersion: UInt32
    public let version: String
    public let features: [String]
}

struct Connections: Decodable { let connections: [Connection] }
struct Outbounds: Decodable { let outbounds: [Outbound] }

let decoder: JSONDecoder = {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return decoder
}()

func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
    try decoder.decode(type, from: Data(json.utf8))
}
