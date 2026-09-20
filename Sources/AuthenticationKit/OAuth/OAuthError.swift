import Foundation

/// Failures raised by the OAuth client layer.
///
/// `serverRejected` carries the authorization server's own `error` code verbatim
/// (RFC 6749 §5.2) so callers can branch on machine-readable values such as
/// `access_denied` or `invalid_grant` rather than on message text.
public enum OAuthError: Error, Sendable, Equatable {
    /// Metadata discovery found no usable authorization server document.
    case discoveryFailed(reason: String)
    /// The authorization server does not advertise an endpoint this flow needs.
    case endpointUnavailable(name: String)
    /// The authorization server returned an OAuth error response.
    case serverRejected(code: String, description: String?)
    /// The server's response was not valid JSON, or was missing required fields.
    case malformedResponse(reason: String)
    /// The redirect came back with a `state` that does not match the one we sent.
    case stateMismatch
    /// The user declined the authorization request.
    case accessDenied(reason: String?)
    /// The user did not complete the flow before the grant expired.
    case authorizationExpired
    /// No flow exists for the supplied handle — expired, cancelled, or never issued.
    case unknownFlow(handle: String)
    /// The loopback redirect listener could not be started.
    case loopbackListenerFailed(reason: String)
    /// A network-level failure talking to the authorization server.
    case transportFailure(reason: String)
    /// The server issued a token, but it was missing the scopes the caller asked for.
    case insufficientScopeGranted(requested: [String], granted: [String])
    /// Configuration is incomplete or contradictory.
    case invalidConfiguration(reason: String)
}

extension OAuthError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .discoveryFailed(let reason):
            return "Authorization server discovery failed: \(reason)"
        case .endpointUnavailable(let name):
            return "The authorization server does not support a required endpoint: \(name)"
        case .serverRejected(let code, let description):
            if let description { return "Authorization server returned '\(code)': \(description)" }
            return "Authorization server returned '\(code)'"
        case .malformedResponse(let reason):
            return "Malformed response from authorization server: \(reason)"
        case .stateMismatch:
            return "Authorization redirect failed CSRF state validation"
        case .accessDenied(let reason):
            return "Authorization was denied\(reason.map { ": \($0)" } ?? "")"
        case .authorizationExpired:
            return "The authorization request expired before it was approved"
        case .unknownFlow(let handle):
            return "No pending authorization matches flow '\(handle)'"
        case .loopbackListenerFailed(let reason):
            return "Could not start the local redirect listener: \(reason)"
        case .transportFailure(let reason):
            return "Could not reach the authorization server: \(reason)"
        case .insufficientScopeGranted(let requested, let granted):
            return
                "Authorization server granted [\(granted.joined(separator: ", "))] "
                + "but [\(requested.joined(separator: ", "))] was requested"
        case .invalidConfiguration(let reason):
            return "Invalid OAuth configuration: \(reason)"
        }
    }

    /// Whether retrying the same operation could plausibly succeed.
    public var isRetryable: Bool {
        switch self {
        case .transportFailure, .discoveryFailed:
            return true
        case .serverRejected(let code, _):
            return code == "temporarily_unavailable" || code == "server_error"
        default:
            return false
        }
    }
}
