import Foundation

/// How the human proves who they are.
public enum AuthorizationMode: String, Sendable, Codable, CaseIterable {
    /// RFC 8628 device authorization grant: the server shows a URL and a short
    /// code, and the user approves on any device. The only mode that works when
    /// the server has no access to the user's browser — a remote HTTP deployment,
    /// or an MCP client on another machine.
    case device
    /// RFC 8252 authorization code with PKCE over a loopback redirect. The server
    /// opens the local browser and catches the redirect on 127.0.0.1.
    case browser
    /// Authorization code with PKCE where the *client* catches the redirect and
    /// hands it back. For a client registration whose redirect URI is fixed and
    /// not ours to receive — a custom scheme such as `myapp://callback` — the
    /// server cannot listen for it, so whatever drives the user's browser
    /// captures the redirect and returns it through
    /// ``AuthorizationProvider/completeAuthorization(handle:redirectURL:)``.
    case handoff
    /// Pick the best mode: `browser` when the server shares a machine with the
    /// user (stdio transport) and the AS supports it, `device` otherwise. Never
    /// picks `handoff`, which only works when the caller can capture a redirect.
    case automatic
}

/// What the human has to do to finish an in-flight authorization.
public struct UserInteraction: Sendable, Equatable, Codable {
    public let mode: AuthorizationMode
    /// The URL the user opens.
    public let verificationURL: URL
    /// Device flow only: the same URL with the code already filled in, when the
    /// authorization server provides one (RFC 8628 `verification_uri_complete`).
    public let verificationURLComplete: URL?
    /// Device flow only: the short code the user types.
    public let userCode: String?
    /// Hand-off flow only: the redirect URI the authorization server will send
    /// the browser to. The client watches for a navigation to it and returns the
    /// full URL it saw.
    public let redirectURI: URL?
    /// When this authorization request stops being accepted.
    public let expiresAt: Date
    /// A sentence to show the user, ready to be surfaced verbatim by a client.
    public let instructions: String

    public init(
        mode: AuthorizationMode,
        verificationURL: URL,
        verificationURLComplete: URL? = nil,
        userCode: String? = nil,
        redirectURI: URL? = nil,
        expiresAt: Date,
        instructions: String
    ) {
        self.mode = mode
        self.verificationURL = verificationURL
        self.verificationURLComplete = verificationURLComplete
        self.userCode = userCode
        self.redirectURI = redirectURI
        self.expiresAt = expiresAt
        self.instructions = instructions
    }
}

/// An authorization that has been started but not yet approved.
public struct AuthorizationStart: Sendable {
    /// Opaque handle the caller passes back to resume polling. Safe to show a model:
    /// it identifies a flow, it is not a credential for the upstream API.
    public let handle: String
    public let interaction: UserInteraction

    public init(handle: String, interaction: UserInteraction) {
        self.handle = handle
        self.interaction = interaction
    }
}

/// The state of an authorization the caller is waiting on.
public enum AuthorizationOutcome: Sendable {
    /// Still waiting on the human. Carries the interaction again so a client that
    /// lost the first response can re-display the code.
    case pending(UserInteraction)
    case completed(TokenSet)
    case denied(reason: String?)
    case expired
}

/// The result of attempting to revoke a session's credentials.
///
/// Revocation is best-effort by design: RFC 7009 §2.2 requires the authorization
/// server to answer 200 even for a token it does not recognise, and the local
/// session must be destroyed either way. This type records what actually happened
/// so the tool can tell the truth about it rather than always claiming success.
public struct RevocationReport: Sendable, Equatable {
    public enum Result: String, Sendable, Codable {
        /// The authorization server accepted the revocation.
        case revoked
        /// There was no token of this kind to revoke.
        case notPresent = "not_present"
        /// The authorization server does not publish a revocation endpoint.
        case unsupported
        /// The call failed; the local session was still destroyed.
        case failed
    }

    public let accessToken: Result
    public let refreshToken: Result
    /// Why revocation failed upstream, when it did.
    public let failureReason: String?

    public init(accessToken: Result, refreshToken: Result, failureReason: String? = nil) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.failureReason = failureReason
    }

    /// True when nothing was left un-revoked at the authorization server.
    public var isCompleteUpstream: Bool {
        [accessToken, refreshToken].allSatisfy { $0 == .revoked || $0 == .notPresent }
    }
}

/// The seam between the MCP tools and whatever actually issues credentials.
///
/// ``OAuthAuthorizationProvider`` talks to a real OAuth 2.1 authorization server.
/// ``MockAuthorizationProvider`` implements the same contract in-process for
/// development and tests. Nothing above this protocol knows which one it has.
public protocol AuthorizationProvider: Sendable {
    /// A short label for the provider, surfaced in tool output and logs.
    var providerDescription: String { get }

    /// Starts an authorization, returning what the user has to do next.
    func beginAuthorization(
        scopes: Set<Scope>,
        mode: AuthorizationMode
    ) async throws -> AuthorizationStart

    /// Waits up to `timeout` for a started authorization to be approved.
    ///
    /// Returns `.pending` rather than throwing when the deadline passes with the
    /// flow still alive, so the caller can return control to the model and resume
    /// later with the same handle.
    func awaitAuthorization(
        handle: String,
        timeout: TimeInterval
    ) async throws -> AuthorizationOutcome

    /// Finishes a `handoff` authorization with the redirect the client captured.
    ///
    /// The URL arrives through the model's context, so it is treated as
    /// untrusted: it must match the flow's redirect URI and carry the flow's
    /// `state` before its code goes anywhere near the token endpoint.
    ///
    /// - Throws: ``OAuthError/redirectRejected(reason:)`` when the URL is not a
    ///   redirect for this flow at all; the flow stays alive so the caller can
    ///   send the right one.
    func completeAuthorization(
        handle: String,
        redirectURL: URL
    ) async throws -> AuthorizationOutcome

    /// Abandons a started authorization and releases its resources.
    func cancelAuthorization(handle: String) async

    /// Exchanges a refresh token for a fresh access token.
    func refresh(_ tokens: TokenSet) async throws -> TokenSet

    /// Revokes both tokens at the authorization server. Never throws: the caller
    /// must be able to destroy the local session regardless of the outcome.
    func revoke(_ tokens: TokenSet) async -> RevocationReport
}

extension AuthorizationProvider {
    /// Providers that never start a `handoff` flow have nothing to complete.
    public func completeAuthorization(
        handle: String,
        redirectURL: URL
    ) async throws -> AuthorizationOutcome {
        throw OAuthError.redirectRejected(
            reason: "this provider does not accept a client-captured redirect")
    }
}
