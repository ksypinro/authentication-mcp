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
        /// Set for a hand-off flow: the `state` its redirect must carry.
        var handoffState: String? = nil
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

        if resolvedMode == .handoff {
            return beginHandoff(handle: handle, userCode: userCode, scopes: requestedScopes)
        }

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

    /// The redirect URI a mock hand-off flow pretends is registered.
    public static let handoffRedirectURI = URL(string: "myapp://callback")!

    /// Starts a hand-off flow. There is no page behind the sign-in URL; a caller
    /// completes the flow by sending `myapp://callback?code=<anything>&state=<state>`,
    /// taking `state` from the sign-in URL's query, as a real capture would.
    private func beginHandoff(
        handle: String,
        userCode: String,
        scopes: Set<Scope>
    ) -> AuthorizationStart {
        let state = UUID().uuidString.lowercased()
        let interaction = UserInteraction(
            mode: .handoff,
            verificationURL: URL(string: "https://example.invalid/authorize?state=\(state)")!,
            redirectURI: Self.handoffRedirectURI,
            expiresAt: now().addingTimeInterval(flowLifetime),
            instructions: "Mock provider: no browser needed. Send back a redirect carrying the state.")

        flows[handle] = MockFlow(
            userCode: userCode,
            scopes: scopes,
            interaction: interaction,
            startedAt: now(),
            handoffState: state,
            decision: policy == .immediate ? .undecided : initialDecision())

        logger.notice(
            "Mock hand-off authorization started — not a real identity provider",
            metadata: ["flow": .string(handle)])

        return AuthorizationStart(handle: handle, interaction: interaction)
    }

    public func completeAuthorization(
        handle: String,
        redirectURL: URL
    ) async throws -> AuthorizationOutcome {
        guard let flow = flows[handle] else { throw OAuthError.unknownFlow(handle: handle) }

        if now() >= flow.interaction.expiresAt {
            flows.removeValue(forKey: handle)
            return .expired
        }
        guard let expectedState = flow.handoffState else {
            throw OAuthError.redirectRejected(
                reason: "this sign-in is not waiting for a redirect; only a 'handoff' flow takes one")
        }
        guard OAuthAuthorizationProvider.isRedirect(redirectURL, to: Self.handoffRedirectURI) else {
            throw OAuthError.redirectRejected(
                reason: "it does not point at \(Self.handoffRedirectURI.absoluteString)")
        }

        // From here the flow is spent whatever happens, as with the real provider.
        flows.removeValue(forKey: handle)

        let items = URLComponents(url: redirectURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let query = Dictionary(
            items.map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { first, _ in first })
        guard let state = query["state"], constantTimeEquals(state, expectedState) else {
            throw OAuthError.stateMismatch
        }
        if query["error"] == "access_denied" {
            return .denied(reason: query["error_description"])
        }
        if case .denied(let reason) = flow.decision {
            return .denied(reason: reason)
        }
        guard let code = query["code"], !code.isEmpty else {
            throw OAuthError.malformedResponse(reason: "redirect carried neither code nor error")
        }
        return .completed(issueTokens(scopes: flow.scopes))
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

        // A hand-off flow only moves when the redirect is handed back.
        if flow.handoffState != nil {
            return .pending(flow.interaction)
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
            // Honour the caller's wait the way a real server's poll does, so a
            // client is paced by `wait_seconds` rather than spinning on instant
            // `pending` replies — and pick up a manual approval made meanwhile.
            if timeout > 0 {
                try await Task.sleep(for: .seconds(timeout))
                if let current = flows[handle], current.decision == .approved {
                    flows.removeValue(forKey: handle)
                    return .completed(issueTokens(scopes: current.scopes))
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
