// The Swift package against libsail: real instances, through Swift only.

import Foundation
import XCTest
@testable import Sail

/// A free TCP port on loopback.
func freePort() -> UInt16 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    addr.sin_port = 0
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafeMutablePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            _ = bind(fd, $0, len)
            _ = getsockname(fd, $0, &len)
        }
    }
    return UInt16(bigEndian: addr.sin_port)
}

/// A loopback server answering each connection with `answer` (what it
/// read when nil: an echo), on a thread of its own.
func serve(answer: [UInt8]? = nil) -> UInt16 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    var yes: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafeMutablePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            _ = bind(fd, $0, len)
            _ = getsockname(fd, $0, &len)
        }
    }
    listen(fd, 16)
    Thread.detachNewThread {
        while true {
            let client = accept(fd, nil, nil)
            if client < 0 { return }
            Thread.detachNewThread {
                var buf = [UInt8](repeating: 0, count: 1024)
                let n = read(client, &buf, buf.count)
                if n > 0 {
                    let out = answer ?? Array(buf[0..<n])
                    _ = out.withUnsafeBytes { write(client, $0.baseAddress, out.count) }
                }
                close(client)
            }
        }
    }
    return UInt16(bigEndian: addr.sin_port)
}

/// Sends "ping" through the SOCKS inbound at `port` to an echo server;
/// whether it came back.
func echoThroughSocks(_ port: UInt16) -> Bool {
    let echo = serve()
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    defer { close(fd) }
    var timeout = timeval(tv_sec: 5, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    addr.sin_port = port.bigEndian
    let connected = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 else { return false }
    func send(_ bytes: [UInt8]) { _ = bytes.withUnsafeBytes { write(fd, $0.baseAddress, bytes.count) } }
    func receive(_ count: Int) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, count - got) }
            if n <= 0 { return nil }
            got += n
        }
        return buf
    }
    send([5, 1, 0])
    guard receive(2) != nil else { return false }
    send([5, 1, 0, 1, 127, 0, 0, 1, UInt8(echo >> 8), UInt8(echo & 0xff)])
    guard let reply = receive(10), reply[1] == 0 else { return false }
    send(Array("ping".utf8))
    return receive(4) == Array("ping".utf8)
}

func config(port: UInt16) -> String {
    """
    {
      "log": { "level": "info" },
      "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": \(port) }],
      "outbounds": [
        { "type": "selector", "tag": "sel", "outbounds": ["a", "b"] },
        { "type": "direct", "tag": "a" },
        { "type": "direct", "tag": "b" }
      ],
      "route": { "final": "sel" }
    }
    """
}

/// The first element of `stream` that `test` takes, within 10 s.
func first<T>(_ stream: AsyncThrowingStream<T, Error>, where test: @escaping (T) -> Bool) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            for try await value in stream where test(value) { return value }
            throw SailError(code: SailError.io, message: "the stream ended")
        }
        group.addTask {
            try await Task.sleep(nanoseconds: 10_000_000_000)
            throw SailError(code: SailError.timeout, message: "no such event")
        }
        let value = try await group.next()!
        group.cancelAll()
        return value
    }
}

/// Counts its own going: what the platform's closures hold.
final class Tracked: @unchecked Sendable {
    static let lock = NSLock()
    static var gone = 0
    deinit {
        Tracked.lock.lock()
        Tracked.gone += 1
        Tracked.lock.unlock()
    }
}

final class SailTests: XCTestCase {
    func testCapabilities() throws {
        let capabilities = try Sail.capabilities()
        XCTAssertEqual(capabilities.apiVersion, 4)
        XCTAssertEqual(capabilities.jsonVersion, 5)
        XCTAssertTrue(capabilities.features.contains("inbound-socks"))
    }

    func testAnInstanceIsDrivenFromSwift() async throws {
        let sail = try Sail(settings: "{\"log_lines\": 100}")
        XCTAssertEqual(try sail.state().state, "idle")
        XCTAssertThrowsError(try sail.traffic()) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.state)
        }
        let port = freePort()
        try sail.start(config: config(port: port))
        XCTAssertEqual(try sail.state().state, "running")
        XCTAssertThrowsError(try sail.start(config: "{}")) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.state)
        }
        XCTAssertTrue(echoThroughSocks(port))
        XCTAssertGreaterThanOrEqual(try sail.traffic().upTotal, 4)

        XCTAssertEqual(try sail.outbounds().map(\.tag), ["sel", "a", "b"])
        XCTAssertEqual(try sail.groups().first?.group?.selected, "a")
        try sail.select(group: "sel", member: "b")
        XCTAssertEqual(try sail.groups().first?.group?.selected, "b")
        XCTAssertThrowsError(try sail.select(group: "sel", member: "c")) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.invalidArgument)
        }
        XCTAssertEqual(try sail.mode(), Mode(mode: "Rule", modes: ["Rule"]))

        let url = "http://127.0.0.1:\(serve(answer: Array("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".utf8)))/"
        XCTAssertGreaterThanOrEqual(try sail.delay(tag: "a", url: url), 1)
        XCTAssertEqual(try sail.outbounds().first { $0.tag == "a" }?.history.count, 1)

        let logs = try await first(sail.logs(level: "info")) { $0.reset }
        XCTAssertFalse(logs.lines.isEmpty)

        try sail.stop()
        XCTAssertEqual(try sail.state().state, "stopped")
        try sail.start(config: config(port: port))
        XCTAssertTrue(echoThroughSocks(port))
        try sail.stop()
    }

    func testStatesAreFollowed() async throws {
        let sail = try Sail()
        let states = sail.states()
        try sail.start(config: config(port: freePort()))
        let running = try await first(states) { $0.state == "running" }
        XCTAssertNotNil(running.startedAtMs)
        try sail.stop()
    }

    func testAClientAnswersAsTheInstance() async throws {
        let path = "/tmp/sail-swift-\(getpid()).sock"
        let sail = try Sail()
        try sail.serve("{\"path\": \"\(path)\"}")
        let port = freePort()
        try sail.start(config: config(port: port))
        let client = try Sail.connect("{\"path\": \"\(path)\"}")
        XCTAssertEqual(try client.state().state, "running")
        XCTAssertEqual(try client.outbounds(), try sail.outbounds())
        try client.select(group: "sel", member: "b")
        XCTAssertEqual(try sail.groups().first?.group?.selected, "b")
        XCTAssertThrowsError(try client.start(config: "{}")) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.unsupported)
        }
        let statuses = client.statuses(intervalMs: 100)
        _ = try await first(statuses) { _ in true }
        // The service closes: the client's streams end, with the reason.
        let states = client.states()
        _ = try await first(states) { $0.state == "running" }
        try sail.serve(nil)
        do {
            for try await _ in states {}
            XCTFail("the stream did not fail")
        } catch let error as SailError {
            XCTAssertEqual(error.code, SailError.io)
        }
        try sail.stop()
    }

    func testThePlatformGoesWithTheInstance() throws {
        let before = Tracked.gone
        do {
            let tracked = Tracked()
            let sail = try Sail(platform: Platform(protectSocket: { _ in _ = tracked; return true }))
            let port = freePort()
            try sail.start(config: config(port: port))
            XCTAssertTrue(echoThroughSocks(port))
            try sail.stop()
        }
        // Freed with the instance, once it stopped.
        let deadline = Date().addingTimeInterval(10)
        while Tracked.gone == before && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        XCTAssertEqual(Tracked.gone, before + 1)
    }

    func testTheHostSaysWhichAppOpenedAConnection() throws {
        let asked = NSLock()
        var queries: [ConnectionQuery] = []
        let sail = try Sail(platform: Platform(findConnectionOwner: { query in
            asked.lock()
            queries.append(query)
            asked.unlock()
            return ConnectionOwner(uid: 10123, packages: ["com.blocked"])
        }))
        let port = freePort()
        try sail.start(config: """
        {
          "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": \(port) }],
          "outbounds": [{ "type": "direct" }],
          "route": { "rules": [{ "package_name": "com.blocked", "action": "reject" }] }
        }
        """)
        XCTAssertFalse(echoThroughSocks(port), "the app's connection was not rejected")
        asked.lock()
        XCTAssertEqual(queries.first?.network, "tcp")
        asked.unlock()
        try sail.stop()
    }

    func testProvidersAndRuleSetsAreToldAndUpdated() throws {
        let sail = try Sail()
        try sail.start(config: """
        {
          "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": \(freePort()) }],
          "outbounds": [{ "type": "selector", "tag": "g", "providers": "p" }, { "type": "direct", "tag": "direct" }],
          "outbound_providers": [{ "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "m1" }, { "type": "direct", "tag": "m2" }] }],
          "route": {
            "rule_set": [{ "type": "inline", "tag": "r", "rules": [{ "domain_suffix": ["a.example"] }] }],
            "rules": [{ "rule_set": "r", "outbound": "direct" }]
          }
        }
        """)
        let providers = try sail.providers()
        XCTAssertEqual(providers.first?.tag, "p")
        XCTAssertEqual(providers.first?.source, "inline")
        XCTAssertEqual(providers.first?.members, 2)
        try sail.updateProvider("p")
        XCTAssertThrowsError(try sail.updateProvider("nope")) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.notFound)
        }
        XCTAssertEqual(try sail.ruleSets().first?.tag, "r")
        try sail.updateRuleSet("r")
        try sail.stop()
    }

    func testADialGoesThroughTheOutboundNamed() throws {
        let sail = try Sail()
        try sail.start(config: config(port: freePort()))
        let echo = serve()
        let handle = try sail.dial(outbound: "a", network: .tcp, host: "127.0.0.1", port: echo)
        try handle.write(contentsOf: Data("ping".utf8))
        var back = Data()
        while back.count < 4, let more = try handle.read(upToCount: 4 - back.count), !more.isEmpty {
            back.append(more)
        }
        XCTAssertEqual(String(data: back, encoding: .utf8), "ping")
        XCTAssertEqual(try sail.connections().filter { $0.inboundTag == "control" }.count, 1)
        try handle.close()
        XCTAssertThrowsError(try sail.dial(outbound: "nope", network: .tcp, host: "127.0.0.1", port: echo)) { error in
            XCTAssertEqual((error as? SailError)?.code, SailError.notFound)
        }
        try sail.stop()
    }

    func testStartsAndStopsAgainAndAgain() throws {
        let sail = try Sail()
        let port = freePort()
        for _ in 0..<50 {
            try sail.start(config: config(port: port))
            try sail.stop()
        }
        XCTAssertTrue(true)
    }

    func testABadConfigurationSaysWhy() throws {
        let sail = try Sail()
        XCTAssertThrowsError(try sail.start(config: "{ \"outbounds\": 1 }")) { error in
            let error = error as? SailError
            XCTAssertEqual(error?.code, SailError.config)
            XCTAssertFalse(error?.message.isEmpty ?? true)
        }
        XCTAssertEqual(try sail.state().state, "failed")
        XCTAssertThrowsError(try Sail(settings: "{\"nothing\": 1}"))
    }
}
