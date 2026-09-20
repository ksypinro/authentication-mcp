import Foundation
import Logging

/// An in-process ``AuthorizationProvider`` for development and tests.
///
/// It honours the same contract as ``OAuthAuthorizationProvider`` — pending
/// flows, user codes, expiry, refresh, revocation — without any network calls, so
/// the four tools can be exercised end to end before an authorization server is
/// wired up. It issues tokens that are valid only to this process.
///
/// - Important: never select this provider in production. ``ServerConfiguration``
///   requires it to be requested explicitly and the server logs a warning at
///   startup when it is active.
public actor MockAuthorizationProvider: AuthorizationProvider {

    /// How a started authorization gets resolved.
    public enum ApprovalPolicy: Sendable, Equatable {
        /// Approved as soon as it is polled — the fastest path for tests.
        case immediate
        /// Approved once this much time has passed, so a caller can observe the
        /// `pending` state the way it would against a real device flow.
        case afterDelay(TimeInterval)
        /// Stays pending until ``approve(userCode:)`` or ``deny(userCode:reason:)``
        /// is called.
        case manual
        /// Always denied, for exercising the failure path.
        case denied(reason: String)
    }

    public nonisolated var providerDescription: String { "mock (in-process, non-production)" }

    private let policy: ApprovalPolicy
    private let subject: String
    private let principalName: String
    private let grantedScopes: Set<Scope>?
    private let accessTokenLifetime: TimeInterval
    private let flowLifetime: TimeInterval
    private let logger: Logger
    private let now: @Sendable () -> Date

    private var flows: [String: MockFlow] = [:]
    private var revokedTokens: Set<String> = []
    private var issuedTokenCount = 0

    private struct MockFlow {
        let userCode: String
        let scopes: Set<Scope>
        let interaction: UserInteraction
        let startedAt: Date
        var decision: Decision

        enum Decision: Equatable {
            case undecided
            case approved
            case denied(reason: String)
        }
    }

    public init(
        policy: ApprovalPolicy = .immediate,
        subject: String = "mock-user-1",
        principalName: String = "Mock User",
        /// Scopes to grant. `nil` grants exactly what was requested, which is what
        /// a cooperative authorization server does.
        grantedScopes: Set<Scope>? = nil,
        accessTokenLifetime: TimeInterval = 3600,
        flowLifetime: TimeInterval = 300,
        logger: Logger,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.policy = policy
        self.subject = subject
        self.principalName = principalName
        self.grantedScopes = grantedScopes
        self.accessTokenLifetime = accessTokenLifetime
        self.flowLifetime = flowLifetime
        self.logger = logger
        self.now = now
    }

    // MARK: - AuthorizationProvider

    public func beginAuthorization(
        scopes: Set<Scope>,
        mode: AuthorizationMode
    ) async throws -> AuthorizationStart {
        let requestedScopes = scopes.isEmpty ? Scope.defaults : scopes
        let userCode = Self.makeUserCode()
        let handle = "mockflow_" + UUID().uuidString.prefix(8).lowercased()
        let resolvedMode: AuthorizationMode = (mode == .automatic) ? .device : mode

        let verificationURL = URL(string: "https://example.invalid/device")!
        let interaction = UserInteraction(
            mode: resolvedMode,
            verificationURL: verificationURL,
            verificationURLComplete: URL(
                string: "https://example.invalid/device?user_code=\(userCode)"),
            userCode: userCode,
            expiresAt: now().addingTimeInterval(flowLifetime),
            instructions:
                "Mock provider: no browser needed. This request will be "
                + policyDescription + ".")

        flows[handle] = MockFlow(
            userCode: userCode,
            scopes: requestedScopes,
            interaction: interaction,
            startedAt: now(),
            decision: initialDecision())

        logger.notice(
            "Mock authorization started — not a real identity provider",
            metadata: ["flow": .string(handle), "user_code": .string(userCode)])

        return AuthorizationStart(handle: handle, interaction: interaction)
    }

    public func awaitAuthorization(
        handle: String,
        timeout: TimeInterval
    ) async throws -> AuthorizationOutcome {
        guard var flow = flows[handle] else { throw OAuthError.unknownFlow(handle: handle) }

        if now() >= flow.interaction.expiresAt {
            flows.removeValue(forKey: handle)
            return .expired
        }

        // Apply a delayed policy once its delay has elapsed.
        if case .afterDelay(let delay) = policy, flow.decision == .undecided,
            now().timeIntervalSince(flow.startedAt) >= delay
        {
            flow.decision = .approved
            flows[handle] = flow
        }

        switch flow.decision {
        case .approved:
            flows.removeValue(forKey: handle)
            return .completed(issueTokens(scopes: flow.scopes))

        case .denied(let reason):
            flows.removeValue(forKey: handle)
            return .denied(reason: reason)

        case .undecided:
            // Wait out the caller's window in case a delayed approval lands inside it.
            if case .afterDelay(let delay) = policy {
                let remainingDelay = delay - now().timeIntervalSince(flow.startedAt)
                if remainingDelay > 0 && remainingDelay <= timeout {
                    try await Task.sleep(for: .seconds(remainingDelay))
                    flows[handle]?.decision = .approved
                    if let updated = flows.removeValue(forKey: handle) {
                        return .completed(issueTokens(scopes: updated.scopes))
                    }
                }
            }
            return .pending(flow.interaction)
        }
    }

    public func cancelAuthorization(handle: String) async {
        flows.removeValue(forKey: handle)
    }

    public func refresh(_ tokens: TokenSet) async throws -> TokenSet {
        guard let refreshToken = tokens.refreshToken else {
            throw OAuthError.serverRejected(
                code: "invalid_grant", description: "this session has no refresh token")
        }
        guard !revokedTokens.contains(refreshToken) else {
            throw OAuthError.serverRejected(
                code: "invalid_grant", description: "refresh token has been revoked")
        }

        let issuedAt = now()
        issuedTokenCount += 1
        return tokens.renewed(
            accessToken: "mock_access_\(issuedTokenCount)_\(UUID().uuidString.prefix(8))",
            tokenType: "Bearer",
            refreshToken: nil,  // Keep the existing one: this mock does not rotate.
            idToken: nil,
            scopes: nil,
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(accessTokenLifetime))
    }

    public func revoke(_ tokens: TokenSet) async -> RevocationReport {
        revokedTokens.insert(tokens.accessToken)
        let refreshResult: RevocationReport.Result
        if let refreshToken = tokens.refreshToken {
            revokedTokens.insert(refreshToken)
            refreshResult = .revoked
        } else {
            refreshResult = .notPresent
        }
        return RevocationReport(accessToken: .revoked, refreshToken: refreshResult)
    }

    // MARK: - Test control surface

    /// Approves a flow identified by the code the user would have typed.
    public func approve(userCode: String) {
        guard let handle = flows.first(where: { $0.value.userCode == userCode })?.key else { return }
        flows[handle]?.decision = .approved
    }

    /// Denies a flow identified by its user code.
    public func deny(userCode: String, reason: String = "the user declined the request") {
        guard let handle = flows.first(where: { $0.value.userCode == userCode })?.key else { return }
        flows[handle]?.decision = .denied(reason: reason)
    }

    /// Whether a token has been revoked here. Lets tests assert that
    /// `revokeAuthentication` really reached the provider.
    public func isRevoked(_ token: String) -> Bool {
        revokedTokens.contains(token)
    }

    public var pendingFlowCount: Int { flows.count }

    // MARK: - Internals

    private func initialDecision() -> MockFlow.Decision {
        switch policy {
        case .immediate: return .approved
        case .denied(let reason): return .denied(reason: reason)
        case .afterDelay, .manual: return .undecided
        }
    }

    private var policyDescription: String {
        switch policy {
        case .immediate: return "approved immediately"
        case .afterDelay(let delay): return "approved after \(Int(delay))s"
        case .manual: return "approved only when a test approves it"
        case .denied: return "denied"
        }
    }

    private func issueTokens(scopes: Set<Scope>) -> TokenSet {
        issuedTokenCount += 1
        let issuedAt = now()
        return TokenSet(
            accessToken: "mock_access_\(issuedTokenCount)_\(UUID().uuidString.prefix(8))",
            tokenType: "Bearer",
            refreshToken: "mock_refresh_\(issuedTokenCount)_\(UUID().uuidString.prefix(8))",
            idToken: nil,
            scopes: grantedScopes ?? scopes,
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(accessTokenLifetime),
            subject: subject,
            principalName: principalName,
            issuer: URL(string: "https://example.invalid"))
    }

    /// A short, unambiguous code in the style RFC 8628 §6.1 recommends: an
    /// alphabet without characters that are easily confused when read aloud.
    private static func makeUserCode() -> String {
        let alphabet = Array("BCDFGHJKLMNPQRSTVWXZ")
        var generator = SystemRandomNumberGenerator()
        let code = (0..<8).map { _ in alphabet.randomElement(using: &generator)! }
        return String(code[0..<4]) + "-" + String(code[4..<8])
    }
}
