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
        .binaryTarget(name: "SailC", url: "https://github.com/peakpassvpn/sail/releases/download/v0.23.0/SailC.xcframework.zip", checksum: "d5c2729af4a9845607f9c19072aa4476df42cc48fe978838c4ec0ca8b52abc91"),
        .target(name: "Sail", dependencies: ["SailC"], path: "bindings/swift/Sources/Sail"),
        .testTarget(name: "SailTests", dependencies: ["Sail"], path: "bindings/swift/Tests/SailTests"),
    ]
)
