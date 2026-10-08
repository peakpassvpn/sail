// swift-tools-version:5.9
// sail for Swift: the C ABI (sail-ffi/include/sail.h) as Swift, from
// bindings/swift. At the repository's root so that an app adds it by URL:
//
//   .package(url: "https://github.com/peakpassvpn/sail", from: "<version>")
//
// Here SailC is libsail, sail-ffi's static library, which
// `bindings/swift/test.sh` builds and links for the tests; a release's tag
// has SailC as the XCFramework the release publishes.

import PackageDescription

let package = Package(
    name: "Sail",
    platforms: [.macOS(.v13), .iOS(.v15)],
    products: [
        .library(name: "Sail", targets: ["Sail"]),
    ],
    targets: [
        .binaryTarget(name: "SailC", url: "https://github.com/peakpassvpn/sail/releases/download/v0.19.0/SailC.xcframework.zip", checksum: "645c5b0eb0504e6bf7bc1d2a67ff886c7c850e6f9eee71c70a38abde0cc64047"),
        .target(name: "Sail", dependencies: ["SailC"], path: "bindings/swift/Sources/Sail"),
        .testTarget(name: "SailTests", dependencies: ["Sail"], path: "bindings/swift/Tests/SailTests"),
    ]
)
