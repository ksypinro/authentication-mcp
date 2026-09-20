import Foundation

/// The MCP client's self-reported name for the tool call currently executing.
///
/// Bound once, around dispatch of a single `tools/call`, in
/// `AuthenticationMCPServer`'s `CallTool` handler. Everything invoked from
/// there — `AuthenticationService` → `SessionStore` →
/// `AuthenticationCoordinator`, however many calls deep — can read it back via
/// ``annotate(_:)`` without any of those functions taking an extra parameter
/// just to carry it further down. This mirrors how the SDK itself carries
/// per-request context: `MCP.Server` exposes the in-flight HTTP request the
/// same way, as a `@TaskLocal` (`Server.currentHandlerContext`).
///
/// Nothing outside a live tool call ever binds this, so it reads `nil` for the
/// standalone `auth login`/`logout`/`status` CLI, which never goes through
/// `AuthenticationService` at all — audit entries written from there simply
/// omit `client_name`, rather than showing a stale or invented value.
enum ClientContext {
    @TaskLocal static var clientName: String?

    /// Merges the current client name into an audit `detail` dictionary, if
    /// one is bound. The single call every audit site uses instead of
    /// repeating the same `if let` around every `detail:` literal.
    static func annotate(_ detail: [String: String]) -> [String: String] {
        guard let clientName else { return detail }
        var detail = detail
        detail["client_name"] = clientName
        return detail
    }
}
