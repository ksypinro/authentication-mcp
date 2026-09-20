import Foundation
import MCP

/// A machine-readable classification for every way a tool call can fail.
///
/// Models recover far better from a stable code plus a concrete next step than
/// from prose alone, so every failure carries both.
public enum ToolErrorCode: String, Sendable, Codable {
    case invalidInput = "invalid_input"
    case notAuthenticated = "not_authenticated"
    case sessionNotFound = "session_not_found"
    case sessionExpired = "session_expired"
    case sessionAmbiguous = "session_ambiguous"
    case insufficientScope = "insufficient_scope"
    case authorizationDenied = "authorization_denied"
    case authorizationExpired = "authorization_expired"
    case authorizationFailed = "authorization_failed"
    case recordNotFound = "record_not_found"
    case versionConflict = "version_conflict"
    case payloadTooLarge = "payload_too_large"
    case rateLimited = "rate_limited"
    case storageFailure = "storage_failure"
    case upstreamUnavailable = "upstream_unavailable"
    case internalFailure = "internal_failure"
}

/// A tool failure, ready to be rendered as a `CallTool.Result`.
///
/// Reported through `isError: true` rather than as a JSON-RPC error, because a
/// protocol error is invisible to the model — it never reaches the conversation,
/// so the model cannot correct itself. Only genuinely protocol-level problems
/// (an unknown tool name) are raised as `MCPError`.
public struct ToolFailure: Error, Sendable {
    public let code: ToolErrorCode
    public let message: String
    /// What the caller should do next. Rendered into the text content.
    public let remediation: String?
    /// Whether retrying the same call unchanged could succeed.
    public let isRetryable: Bool
    /// Extra machine-readable fields, e.g. the conflicting version.
    public let details: [String: Value]

    public init(
        code: ToolErrorCode,
        message: String,
        remediation: String? = nil,
        isRetryable: Bool = false,
        details: [String: Value] = [:]
    ) {
        self.code = code
        self.message = message
        self.remediation = remediation
        self.isRetryable = isRetryable
        self.details = details
    }

    public var callToolResult: CallTool.Result {
        var errorFields: [String: Value] = [
            "code": .string(code.rawValue),
            "message": .string(message),
            "retryable": .bool(isRetryable),
        ]
        if let remediation { errorFields["remediation"] = .string(remediation) }
        // Declared fields win over `details`, so a detail key can never overwrite
        // the error code a caller branches on.
        errorFields.merge(details) { existing, _ in existing }

        let structured: [String: Value] = [
            "ok": .bool(false),
            "error": .object(errorFields),
        ]

        let text = remediation.map { "\(message)\n\n\($0)" } ?? message
        return CallTool.Result(
            content: [.text(text: text, annotations: nil, _meta: nil)],
            structuredContent: .object(structured),
            isError: true)
    }
}

/// Builds the success half of a tool result.
public enum ToolResponse {
    /// A result carrying both a structured payload and a human-readable rendering.
    ///
    /// Both halves are always sent: `structuredContent` is what a client validates
    /// against `outputSchema`, and the text block is what reaches models whose
    /// clients do not surface structured content.
    public static func success(_ payload: Value, summary: String? = nil) -> CallTool.Result {
        var fields = payload.objectValue ?? [:]
        fields["ok"] = .bool(true)
        let structured = Value.object(fields)

        let text = summary.map { "\($0)\n\n\(structured.prettyJSONString)" }
            ?? structured.prettyJSONString

        // Typed as `Value?` on purpose: `CallTool.Result` also has a generic
        // `structuredContent: some Codable` initializer that throws, and a
        // non-optional `Value` would bind to that one instead.
        let structuredContent: Value? = structured
        return CallTool.Result(
            content: [.text(text: text, annotations: nil, _meta: nil)],
            structuredContent: structuredContent,
            isError: false)
    }
}

// MARK: - Domain errors → ToolFailure

extension ToolFailure {

    /// Maps any error thrown below the tool layer onto a typed failure.
    ///
    /// Centralised so that no handler has to remember the mapping, and so an
    /// unrecognised error can never leak an internal description to the model.
    public static func from(_ error: Error) -> ToolFailure {
        switch error {
        case let failure as ToolFailure:
            return failure

        case let inputError as ToolInputError:
            return ToolFailure(
                code: .invalidInput,
                message: inputError.message,
                remediation: "Correct the arguments and call the tool again.")

        case let sessionError as SessionError:
            return from(sessionError)

        case let storeError as DataStoreError:
            return from(storeError)

        case let oauthError as OAuthError:
            return from(oauthError)

        case let credentialError as CredentialError:
            return ToolFailure(
                code: credentialError == .notSignedIn ? .notAuthenticated : .sessionExpired,
                message: credentialError.localizedDescription,
                remediation:
                    "Run `authentication-mcp auth login` in a terminal, or call "
                    + "`authenticate` to sign in from here.")

        case let secretStoreError as SecretStoreError:
            return ToolFailure(
                code: .storageFailure,
                message: secretStoreError.localizedDescription,
                remediation:
                    "Check access to the credential store, or set "
                    + "AUTH_MCP_CREDENTIAL_BACKEND=file to bypass the keychain.",
                isRetryable: true)

        default:
            return ToolFailure(
                code: .internalFailure,
                message: "The server hit an unexpected error while handling this call.",
                remediation: "Retry once; if it persists, check the server logs.",
                isRetryable: true)
        }
    }

    private static func from(_ error: SessionError) -> ToolFailure {
        switch error {
        case .notAuthenticated:
            return ToolFailure(
                code: .notAuthenticated,
                message: error.localizedDescription,
                remediation: "Call `authenticate`, then retry this call.")

        case .notFound(let sessionID):
            return ToolFailure(
                code: .sessionNotFound,
                message: error.localizedDescription,
                remediation: "Call `authenticate` to create a new session.",
                details: sessionID.map { ["session_id": .string($0)] } ?? [:])

        case .expired(let sessionID, _):
            return ToolFailure(
                code: .sessionExpired,
                message: error.localizedDescription,
                remediation: "Call `authenticate` to sign in again, then retry.",
                details: ["session_id": .string(sessionID)])

        case .insufficientScope(let required, let granted):
            return ToolFailure(
                code: .insufficientScope,
                message: error.localizedDescription,
                remediation:
                    "Call `authenticate` with scopes including '\(required)' and `force: true`.",
                details: [
                    "required_scope": .string(required.rawValue),
                    "granted_scopes": .array(granted.map(Value.string)),
                ])

        case .ambiguous(let sessionIDs):
            return ToolFailure(
                code: .sessionAmbiguous,
                message: error.localizedDescription,
                remediation: "Pass `session_id` naming the session you mean.",
                details: ["session_ids": .array(sessionIDs.map(Value.string))])
        }
    }

    private static func from(_ error: DataStoreError) -> ToolFailure {
        switch error {
        case .notFound(let id), .accessDenied(let id):
            return ToolFailure(
                code: .recordNotFound,
                message: error.localizedDescription,
                remediation: "Check the id, or create the record with `updatedData`.",
                details: ["id": .string(id)])

        case .versionConflict(let id, let expected, let actual):
            return ToolFailure(
                code: .versionConflict,
                message: error.localizedDescription,
                remediation:
                    "Call `fetchData` for '\(id)', reapply your change to the current value, "
                    + "then call `updatedData` with `expected_version: \(actual)`.",
                isRetryable: true,
                details: [
                    "id": .string(id),
                    "expected_version": .int(expected),
                    "current_version": .int(actual),
                ])

        case .invalidIdentifier, .notMergeable:
            return ToolFailure(
                code: .invalidInput,
                message: error.localizedDescription,
                remediation: "Correct the arguments and call the tool again.")

        case .payloadTooLarge(let bytes, let limit):
            return ToolFailure(
                code: .payloadTooLarge,
                message: error.localizedDescription,
                remediation: "Split the value across several records, or store less data.",
                details: ["bytes": .int(bytes), "limit": .int(limit)])

        case .storageFailure:
            return ToolFailure(
                code: .storageFailure,
                message: error.localizedDescription,
                remediation: "Retry once; if it persists, check the server logs.",
                isRetryable: true)
        }
    }

    private static func from(_ error: OAuthError) -> ToolFailure {
        switch error {
        case .accessDenied(let reason):
            return ToolFailure(
                code: .authorizationDenied,
                message: reason.map { "Sign-in was declined: \($0)" } ?? "Sign-in was declined.",
                remediation: "Ask the user whether they meant to decline before trying again.")

        case .authorizationExpired:
            return ToolFailure(
                code: .authorizationExpired,
                message: "The sign-in request expired before it was approved.",
                remediation: "Call `authenticate` again without a `flow_id` to get a fresh code.",
                isRetryable: true)

        case .unknownFlow(let handle):
            return ToolFailure(
                code: .authorizationExpired,
                message: "Sign-in flow '\(handle)' is no longer active.",
                remediation: "Call `authenticate` again without a `flow_id`.",
                isRetryable: true,
                details: ["flow_id": .string(handle)])

        case .transportFailure, .discoveryFailed:
            return ToolFailure(
                code: .upstreamUnavailable,
                message: error.localizedDescription,
                remediation: "The authorization server is unreachable. Retry shortly.",
                isRetryable: true)

        case .insufficientScopeGranted(let requested, let granted):
            return ToolFailure(
                code: .insufficientScope,
                message: error.localizedDescription,
                remediation: "Ask the user to approve the missing scopes, or proceed with fewer.",
                details: [
                    "requested_scopes": .array(requested.map(Value.string)),
                    "granted_scopes": .array(granted.map(Value.string)),
                ])

        case .serverRejected(let code, _):
            return ToolFailure(
                code: .authorizationFailed,
                message: error.localizedDescription,
                remediation: error.isRetryable
                    ? "Retry shortly." : "Check the server's OAuth configuration.",
                isRetryable: error.isRetryable,
                details: ["oauth_error": .string(code)])

        case .stateMismatch:
            // A redirect failed CSRF validation. Say so plainly: this can mean an
            // attempted interception, and it should not be retried silently.
            return ToolFailure(
                code: .authorizationFailed,
                message: "The sign-in redirect failed its security check and was discarded.",
                remediation:
                    "Start a fresh sign-in. If this repeats, stop and investigate — the "
                    + "redirect may have been tampered with.")

        default:
            return ToolFailure(
                code: .authorizationFailed,
                message: error.localizedDescription,
                remediation: "Check the server's OAuth configuration.",
                isRetryable: error.isRetryable)
        }
    }
}
