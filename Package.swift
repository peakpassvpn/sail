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
        .binaryTarget(name: "SailC", url: "https://github.com/peakpassvpn/sail/releases/download/v0.16.0/SailC.xcframework.zip", checksum: "933fdeb77abe87322c99eb8894c6fd797621d679e770e61b172c88a2ee38f672"),
        .target(name: "Sail", dependencies: ["SailC"], path: "bindings/swift/Sources/Sail"),
        .testTarget(name: "SailTests", dependencies: ["Sail"], path: "bindings/swift/Tests/SailTests"),
    ]
)
