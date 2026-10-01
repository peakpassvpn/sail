// swift-tools-version:5.9
// sail for Swift: the C ABI (sail-ffi/include/sail.h) as Swift. It links
// libsail, sail-ffi's static library: `bindings/swift/test.sh` builds it
// and runs the tests; an app links the XCFramework a release makes.

import PackageDescription

let package = Package(
    name: "Sail",
    platforms: [.macOS(.v13), .iOS(.v15)],
    products: [
        .library(name: "Sail", targets: ["Sail"]),
    ],
    targets: [
        .systemLibrary(name: "SailC", path: "Sources/SailC"),
        .target(name: "Sail", dependencies: ["SailC"]),
        .testTarget(name: "SailTests", dependencies: ["Sail"]),
    ]
)
