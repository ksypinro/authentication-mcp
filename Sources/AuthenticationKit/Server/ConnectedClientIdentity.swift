import Foundation

/// The MCP client's self-reported name for one connection, once known.
///
/// `Client.Info` arrives exactly once, in the `initialize` handshake, via a
/// closure the SDK calls before any tool dispatch (`Server.start(_:initializeHook:)`).
/// The tool-call handler is a *different* closure, registered separately in
/// `AuthenticationMCPServer.make`, so the two need a shared place to hand the
/// name across — a plain captured `var` cannot cross two `@Sendable` closures
/// under Swift 6 strict concurrency. This actor is that place: written once by
/// the initialize hook, read on every later tool call.
public actor ConnectedClientIdentity {
    private var name: String?

    public init() {}

    /// Records the name reported at `initialize`. Called at most once per
    /// connection — the MCP spec forbids a second `initialize` on the same
    /// connection, and the SDK enforces it.
    func record(name: String) {
        self.name = name
    }

    /// A label safe to drop straight into a log line.
    ///
    /// The MCP spec guarantees `initialize` completes before any other request
    /// reaches a handler — the SDK's own `checkInitialized()` rejects a tool
    /// call otherwise — so a tool-call handler reading this has always seen it
    /// already set. `"unknown"` only guards against that invariant changing
    /// out from under this code, not a case that occurs in practice.
    public var label: String {
        get async { name ?? "unknown" }
    }
}
