// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DidmeKit",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
    ],
    products: [
        .library(
            name: "DidmeKit",
            targets: ["DidmeKit"]
        ),
    ],
    dependencies: [
        // PQC libs
        .package(
            url: "https://github.com/leif-ibsen/SwiftDilithium",
            from: "3.5.0"
        ),
        .package(
            url: "https://github.com/leif-ibsen/SwiftKyber",
            from: "3.4.0"
        ),

        // Required by Dilithium & Kyber
        .package(
            url: "https://github.com/leif-ibsen/ASN1",
            from: "2.7.0"
        ),
        .package(
            url: "https://github.com/leif-ibsen/BigInt",
            from: "1.21.0"
        ),
        .package(
            url: "https://github.com/leif-ibsen/Digest",
            from: "1.13.0"
        ),
        // Protobuf
        .package(
                url: "https://github.com/apple/swift-protobuf",
                from: "1.33.3"
            ),
    ],
    targets: [
        .target(
            name: "DidmeKit",
            dependencies: [
                "SwiftDilithium",
                "SwiftKyber",
                "ASN1",
                "BigInt",
                "Digest",
                "SwiftProtobuf"
            ],
            path: "Sources/DidmeKit"
        ),
        .testTarget(
            name: "DidmeKitTests",
            dependencies: ["DidmeKit"],
            path: "Tests/DidmeKitTests"
        )
    ]
)
