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
    /// The domain it goes to: the destination's, else the name it was
    /// dialled as, else the one sniffed.
    public let host: String?
    /// The domain a sniff found, from a TLS server name or an HTTP Host.
    public let sniffHost: String?
    /// Where the name it was dialled as came from, `sniff` or
    /// `reverse_mapping`; nil where it was dialled as asked.
    public let dialDomainSource: String?
    public let process: String?
    public let user: String?
    /// Who opened it, as the host told (Android).
    public let uid: UInt32?
    public let packages: [String]
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

/// A connection whose owner the host is asked for.
public struct ConnectionQuery: Decodable, Equatable, Sendable {
    /// tcp or udp.
    public let network: String
    public let source: String
    public let destination: String
}

/// Who opened a connection, as the host tells sail.
public struct ConnectionOwner: Encodable, Equatable, Sendable {
    public let uid: UInt32
    public let user: String?
    public let packages: [String]

    public init(uid: UInt32, user: String? = nil, packages: [String] = []) {
        self.uid = uid
        self.user = user
        self.packages = packages
    }
}

/// An update's failure: when, and why (with no URL in it).
public struct UpdateFailure: Decodable, Equatable, Sendable {
    public let atMs: UInt64
    public let error: String
}

/// What a subscription's server says of it.
public struct Subscription: Decodable, Equatable, Sendable {
    public let upload: UInt64
    public let download: UInt64
    public let total: UInt64
    public let expireMs: UInt64?
}

/// An outbound provider: its members are among the outbounds.
public struct Provider: Decodable, Equatable, Sendable {
    public let tag: String
    /// remote, local or inline.
    public let source: String
    public let members: UInt64
    public let updatedMs: UInt64?
    /// Nil when it is not updated by itself.
    public let nextUpdateMs: UInt64?
    /// The last update's, nil after a success.
    public let failure: UpdateFailure?
    public let subscription: Subscription?
}

public struct RuleSet: Decodable, Equatable, Sendable {
    public let tag: String
    /// remote, local or inline.
    public let source: String
    public let format: String?
    public let behavior: String?
    public let rules: UInt64
    public let updatedMs: UInt64?
    public let nextUpdateMs: UInt64?
    public let failure: UpdateFailure?
}

/// What `dial` connects.
public enum DialNetwork: String, Sendable {
    case tcp
    case udp
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
    /// The sail release the instance runs: through a client, the tunnel
    /// process's, which may differ from `Sail.capabilities()`' after an
    /// update. Nil from an older sail.
    public let version: String?
    public let hasTun: Bool
    public let opensTun: Bool
    public let protectsSockets: Bool
    public let needsNetwork: Bool
    public let hasModes: Bool
}

/// sail's JSON carries no version: it only grows. Decoding ignores what a
/// newer sail adds, and every field added from now on is optional, so that
/// an older sail's JSON, without it, decodes too.
public struct Capabilities: Decodable, Equatable, Sendable {
    /// The sail release.
    public let version: String
    /// The modules compiled in: what was built, not which calls there are.
    public let features: [String]
}

struct Connections: Decodable { let connections: [Connection] }
struct Outbounds: Decodable { let outbounds: [Outbound] }
struct Providers: Decodable { let providers: [Provider] }
struct RuleSets: Decodable { let ruleSets: [RuleSet] }

let decoder: JSONDecoder = {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return decoder
}()

func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
    try decoder.decode(type, from: Data(json.utf8))
}
