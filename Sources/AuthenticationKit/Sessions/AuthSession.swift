import Foundation
import MCP

/// Identifies the MCP connection a session belongs to.
///
/// A stdio server has exactly one owner for its lifetime. An HTTP server has one
/// per Streamable HTTP session, and sessions are never visible across owners —
/// that boundary is what stops one HTTP client from using another's credentials
/// by guessing a session id.
public struct SessionOwner: Hashable, Sendable, CustomStringConvertible {
    public let rawValue: String

    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    /// The single owner used by the stdio transport.
    public static let stdio = SessionOwner("stdio")

    public var description: String { rawValue }
}

/// An authenticated session: token material plus the bookkeeping around it.
///
/// The token material never leaves the process. ``AuthSession/snapshot`` is the
/// only representation that reaches a tool result.
public struct AuthSession: Sendable, Identifiable {
    public let id: String
    public let owner: SessionOwner
    public internal(set) var tokens: TokenSet
    public let createdAt: Date
    public internal(set) var lastUsedAt: Date
    /// A label for the authorization server that issued the credentials.
    public let providerDescription: String

    /// The principal this session acts as. Falls back to the session id when the
    /// authorization server issued no subject, so data ownership is always
    /// well-defined.
    public var subject: String {
        tokens.subject ?? "anonymous:\(id)"
    }

    public var principalName: String? {
        tokens.principalName
    }

    public var scopes: Set<Scope> {
        tokens.scopes
    }

    init(
        id: String,
        owner: SessionOwner,
        tokens: TokenSet,
        createdAt: Date,
        lastUsedAt: Date,
        providerDescription: String
    ) {
        self.id = id
        self.owner = owner
        self.tokens = tokens
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
        self.providerDescription = providerDescription
    }

    /// The safe, model-visible view of a session.
    ///
    /// Deliberately excludes every token field. A model that could read an access
    /// token could replay it against the upstream API from anywhere; a session id
    /// is meaningless outside this process.
    public var snapshot: Value {
        .object(compacting: [
            ("session_id", .string(id)),
            ("subject", .string(subject)),
            ("principal_name", principalName.map(Value.string)),
            ("scopes", .array(scopes.sortedRawValues.map(Value.string))),
            ("token_type", .string(tokens.tokenType)),
            ("provider", .string(providerDescription)),
            ("created_at", .string(Timestamps.string(from: createdAt))),
            ("expires_at", tokens.expiresAt.map { .string(Timestamps.string(from: $0)) }),
            ("expires_in_seconds", tokens.secondsUntilExpiry.map { .int(Int($0)) }),
            ("can_refresh", .bool(tokens.refreshToken != nil)),
        ])
    }
}

/// Why a session could not be used.
public enum SessionError: Error, Sendable, Equatable {
    /// No such session for this caller. Also returned when a session exists but
    /// belongs to a different connection — the two cases are deliberately
    /// indistinguishable so session ids cannot be probed.
    case notFound(sessionID: String?)
    /// The caller has never authenticated on this connection.
    case notAuthenticated
    /// The session's credentials expired and could not be refreshed.
    case expired(sessionID: String, underlying: String?)
    /// The session is valid but lacks a scope the tool requires.
    case insufficientScope(required: Scope, granted: [String])
    /// More than one session exists and the caller did not say which to use.
    case ambiguous(sessionIDs: [String])
}

extension SessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notFound(let sessionID):
            if let sessionID { return "No active session with id '\(sessionID)'." }
            return "No active session."
        case .notAuthenticated:
            return "Not authenticated. Call `authenticate` first."
        case .expired(let sessionID, let underlying):
            let detail = underlying.map { " (\($0))" } ?? ""
            return
                "Session '\(sessionID)' has expired and could not be refreshed\(detail). "
                + "Call `authenticate` to sign in again."
        case .insufficientScope(let required, let granted):
            return
                "This operation requires the '\(required)' scope, but the session was granted "
                + "[\(granted.joined(separator: ", "))]. Re-authenticate requesting '\(required)'."
        case .ambiguous(let sessionIDs):
            return
                "More than one session is active ([\(sessionIDs.joined(separator: ", "))]). "
                + "Pass `session_id` to choose one."
        }
    }
}
