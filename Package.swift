// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/fpseverino/swift-pqcrypto.git", branch: "post-quantum"),
        .package(path: "../swift-certificates"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
    ],
    targets: [
        .target(
            name: "JWTKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-pqcrypto"),
                .product(name: "_CryptoExtras", package: "swift-pqcrypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "BigInt", package: "BigInt"),
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "JWTKitTests",
            dependencies: [
                "JWTKit",
            ],
            resources: [
                .copy("TestVectors"),
                .copy("TestCertificates"),
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .enableUpcomingFeature("ConciseMagicFile"),
            ]
        ),
    ]
)
