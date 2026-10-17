// swift-tools-version:6.1
import PackageDescription

let package = Package(
    name: "AuthenticationService",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        // Transport-agnostic core: tools, OAuth client, sessions, data store.
        .library(name: "AuthenticationKit", targets: ["AuthenticationKit"]),
        // NIO host that serves the core over Streamable HTTP.
        .library(name: "AuthenticationHTTP", targets: ["AuthenticationHTTP"]),
        // The server binary. `--transport stdio` (default) or `--transport http`.
        .executable(name: "authentication-mcp", targets: ["AuthenticationMCPServer"]),
    ],
    dependencies: [
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", from: "0.12.1"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.4.0"),
    ],
    targets: [
        .target(
            name: "AuthenticationKit",
            dependencies: [
                .product(name: "MCP", package: "swift-sdk"),
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .target(
            name: "AuthenticationHTTP",
            dependencies: [
                "AuthenticationKit",
                .product(name: "MCP", package: "swift-sdk"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .executableTarget(
            name: "AuthenticationMCPServer",
            dependencies: [
                "AuthenticationKit",
                "AuthenticationHTTP",
                .product(name: "MCP", package: "swift-sdk"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "AuthenticationHTTPTests",
            dependencies: [
                "AuthenticationHTTP",
                .product(name: "MCP", package: "swift-sdk"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "AuthenticationKitTests",
            dependencies: [
                "AuthenticationKit",
                .product(name: "MCP", package: "swift-sdk"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
