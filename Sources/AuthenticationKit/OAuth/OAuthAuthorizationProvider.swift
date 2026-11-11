import Foundation
import Logging
import MCP

/// An ``AuthorizationProvider`` that speaks OAuth 2.1 to a real authorization server.
///
/// Supports three interactive flows and shares everything else between them:
///
/// - **Device authorization grant** (RFC 8628) — the default. The user approves on
///   whatever device has a browser, which is the only thing that works when this
///   server runs remotely or the MCP client is on another machine.
/// - **Authorization code with PKCE** (RFC 7636, over an RFC 8252 loopback
///   redirect) — used when the server shares a machine with the user.
/// - **Authorization code with PKCE, redirect handed back by the client** — for a
///   client registration whose redirect URI is fixed and not the server's to
///   receive (a custom scheme). The MCP client captures the redirect and returns
///   it through ``completeAuthorization(handle:redirectURL:)``.
///
/// Refresh follows RFC 6749 §6 and revocation RFC 7009.
public actor OAuthAuthorizationProvider: AuthorizationProvider {

    public nonisolated var providerDescription: String {
        "OAuth 2.1 (\(configuration.issuer.absoluteString))"
    }

    private let configuration: OAuthProviderConfiguration
    private let discovery: MetadataDiscovery
    private let tokenClient: TokenEndpointClient
    private let logger: Logger
    private let now: @Sendable () -> Date
    /// Whether the server can reach the user's own browser. False for a remote
    /// HTTP deployment, where `automatic` must resolve to the device grant.
    private let canReachUserBrowser: Bool

    private var pendingFlows: [String: PendingFlow] = [:]

    public init(
        configuration: OAuthProviderConfiguration,
        http: any HTTPExchanging = URLSessionHTTPClient.makeDefault(),
        logger: Logger,
        canReachUserBrowser: Bool = true,
        now: @escaping @Sendable () -> Date = { Date() }
    ) throws {
        try configuration.validate()
        self.configuration = configuration
        self.discovery = MetadataDiscovery(http: http, logger: logger)
        self.tokenClient = TokenEndpointClient(
            http: http, authentication: configuration.authentication, logger: logger)
        self.logger = logger
        self.canReachUserBrowser = canReachUserBrowser
        self.now = now
    }

    /// Seeds discovery with a metadata document instead of fetching it.
    public func preloadMetadata(_ metadata: AuthorizationServerMetadata) async {
        await discovery.preload(metadata, for: configuration.issuer)
    }

    // MARK: - Pending flow state

    private enum PendingFlow {
        case device(DeviceFlow)
        case browser(BrowserFlow)
        case handoff(HandoffFlow)

        var interaction: UserInteraction {
            switch self {
            case .device(let flow): return flow.interaction
            case .browser(let flow): return flow.interaction
            case .handoff(let flow): return flow.interaction
            }
        }

        var expiresAt: Date {
            interaction.expiresAt
        }
    }

    private struct DeviceFlow {
        let deviceCode: String
        let scopes: Set<Scope>
        let interaction: UserInteraction
        /// Seconds between polls. Grows when the server answers `slow_down`.
        var pollInterval: TimeInterval
        var nextPollAllowedAt: Date
    }

    /// What an authorization-code exchange needs, however the redirect arrives.
    private struct CodeGrant {
        let codeVerifier: String
        let stateNonce: String
        let redirectURI: URL
        let scopes: Set<Scope>
    }

    /// A code flow whose redirect the client captures. It holds no listener and
    /// no task: nothing happens until the redirect is handed back.
    private struct HandoffFlow {
        let grant: CodeGrant
        let interaction: UserInteraction
    }

    private struct BrowserFlow {
        let listener: LoopbackRedirectListener
        let grant: CodeGrant
        let interaction: UserInteraction
        /// Started eagerly at `beginAuthorization` so the redirect is caught even
        /// if the caller takes a while to come back and wait for it.
        let redirectTask: Task<URL, Error>
    }

    // MARK: - Beginning an authorization

    public func beginAuthorization(
        scopes: Set<Scope>,
        mode: AuthorizationMode
    ) async throws -> AuthorizationStart {
        let requestedScopes = scopes.isEmpty ? configuration.defaultScopes : scopes
        let metadata = try await discovery.metadata(for: configuration.issuer)
        let resolvedMode = try resolve(mode: mode, using: metadata)

        expirePendingFlows()

        switch resolvedMode {
        case .device:
            return try await beginDeviceFlow(scopes: requestedScopes, metadata: metadata)
        case .browser:
            return try await beginBrowserFlow(scopes: requestedScopes, metadata: metadata)
        case .handoff:
            return try beginHandoffFlow(scopes: requestedScopes, metadata: metadata)
        case .automatic:
            // `resolve` never returns `.automatic`.
            throw OAuthError.invalidConfiguration(reason: "unresolved authorization mode")
        }
    }

    /// Turns `.automatic` into a concrete mode, and verifies that an explicitly
    /// requested mode is actually usable.
    private func resolve(
        mode: AuthorizationMode,
        using metadata: AuthorizationServerMetadata
    ) throws -> AuthorizationMode {
        switch mode {
        case .device:
            guard metadata.supportsDeviceGrant || deviceEndpoint(from: metadata) != nil else {
                throw OAuthError.endpointUnavailable(name: "device_authorization_endpoint")
            }
            return .device
        case .browser:
            guard authorizationEndpoint(from: metadata) != nil else {
                throw OAuthError.endpointUnavailable(name: "authorization_endpoint")
            }
            return .browser
        case .handoff:
            guard configuration.handoffRedirectURI != nil else {
                throw OAuthError.invalidConfiguration(
                    reason: "hand-off sign-in is not configured; set AUTH_MCP_OAUTH_REDIRECT_URI "
                        + "to the redirect URI registered for this client")
            }
            guard authorizationEndpoint(from: metadata) != nil else {
                throw OAuthError.endpointUnavailable(name: "authorization_endpoint")
            }
            return .handoff
        case .automatic:
            if canReachUserBrowser, authorizationEndpoint(from: metadata) != nil {
                return .browser
            }
            if deviceEndpoint(from: metadata) != nil || metadata.supportsDeviceGrant {
                return .device
            }
            guard authorizationEndpoint(from: metadata) != nil else {
                throw OAuthError.endpointUnavailable(
                    name: "authorization_endpoint or device_authorization_endpoint")
            }
            return .browser
        }
    }

    private func beginDeviceFlow(
        scopes: Set<Scope>,
        metadata: AuthorizationServerMetadata
    ) async throws -> AuthorizationStart {
        guard let endpoint = deviceEndpoint(from: metadata) else {
            throw OAuthError.endpointUnavailable(name: "device_authorization_endpoint")
        }

        let response = try await tokenClient.requestDeviceAuthorization(
            endpoint: endpoint,
            scopes: scopes,
            resource: configuration.resourceIndicator)

        let expiresAt = now().addingTimeInterval(
            min(response.expiresIn, configuration.authorizationTimeout))

        let interaction = UserInteraction(
            mode: .device,
            verificationURL: response.verificationURI,
            verificationURLComplete: response.verificationURIComplete,
            userCode: response.userCode,
            expiresAt: expiresAt,
            instructions: Self.deviceInstructions(
                url: response.verificationURIComplete ?? response.verificationURI,
                code: response.userCode,
                hasPrefilledURL: response.verificationURIComplete != nil))

        let handle = Self.makeHandle()
        // RFC 8628 §3.5: absent an `interval`, poll no faster than every 5 seconds.
        let interval = response.interval ?? 5
        pendingFlows[handle] = .device(
            DeviceFlow(
                deviceCode: response.deviceCode,
                scopes: scopes,
                interaction: interaction,
                pollInterval: interval,
                nextPollAllowedAt: now().addingTimeInterval(interval)))

        logger.info(
            "Started device authorization",
            metadata: [
                "flow": .string(handle),
                "scopes": .string(scopes.scopeString),
                "expires_in": .stringConvertible(Int(response.expiresIn)),
            ])

        return AuthorizationStart(handle: handle, interaction: interaction)
    }

    private func beginBrowserFlow(
        scopes: Set<Scope>,
        metadata: AuthorizationServerMetadata
    ) async throws -> AuthorizationStart {
        guard let endpoint = authorizationEndpoint(from: metadata) else {
            throw OAuthError.endpointUnavailable(name: "authorization_endpoint")
        }
        let pkce = try makePKCEPair(metadata: metadata)
        let stateNonce = Self.makeNonce()

        let listener = LoopbackRedirectListener(logger: logger)
        let redirectURI = try await listener.start(preferredPort: configuration.loopbackPort)

        let authorizationURL = try buildAuthorizationURL(
            endpoint: endpoint,
            redirectURI: redirectURI,
            scopes: scopes,
            stateNonce: stateNonce,
            codeChallenge: pkce.challenge)

        let timeout = configuration.authorizationTimeout
        let redirectTask = Task { try await listener.waitForRedirect(timeout: timeout) }

        let interaction = UserInteraction(
            mode: .browser,
            verificationURL: authorizationURL,
            userCode: nil,
            expiresAt: now().addingTimeInterval(timeout),
            instructions:
                "Approve the sign-in request in the browser window that just opened. "
                + "If no window appeared, open the authorization URL manually.")

        let handle = Self.makeHandle()
        pendingFlows[handle] = .browser(
            BrowserFlow(
                listener: listener,
                grant: CodeGrant(
                    codeVerifier: pkce.verifier,
                    stateNonce: stateNonce,
                    redirectURI: redirectURI,
                    scopes: scopes),
                interaction: interaction,
                redirectTask: redirectTask))

        if configuration.opensBrowserAutomatically {
            Self.openInBrowser(authorizationURL, logger: logger)
        }

        logger.info(
            "Started browser authorization",
            metadata: [
                "flow": .string(handle),
                "scopes": .string(scopes.scopeString),
                "redirect_uri": .string(redirectURI.absoluteString),
            ])

        return AuthorizationStart(handle: handle, interaction: interaction)
    }

    private func beginHandoffFlow(
        scopes: Set<Scope>,
        metadata: AuthorizationServerMetadata
    ) throws -> AuthorizationStart {
        guard let endpoint = authorizationEndpoint(from: metadata) else {
            throw OAuthError.endpointUnavailable(name: "authorization_endpoint")
        }
        guard let redirectURI = configuration.handoffRedirectURI else {
            throw OAuthError.invalidConfiguration(reason: "hand-off sign-in is not configured")
        }
        let pkce = try makePKCEPair(metadata: metadata)
        let stateNonce = Self.makeNonce()

        let authorizationURL = try buildAuthorizationURL(
            endpoint: endpoint,
            redirectURI: redirectURI,
            scopes: scopes,
            stateNonce: stateNonce,
            codeChallenge: pkce.challenge)

        let interaction = UserInteraction(
            mode: .handoff,
            verificationURL: authorizationURL,
            redirectURI: redirectURI,
            expiresAt: now().addingTimeInterval(configuration.authorizationTimeout),
            instructions:
                "Sign in in the browser window that opens. "
                + "It closes by itself once sign-in is done.")

        let handle = Self.makeHandle()
        pendingFlows[handle] = .handoff(
            HandoffFlow(
                grant: CodeGrant(
                    codeVerifier: pkce.verifier,
                    stateNonce: stateNonce,
                    redirectURI: redirectURI,
                    scopes: scopes),
                interaction: interaction))

        logger.info(
            "Started hand-off authorization",
            metadata: [
                "flow": .string(handle),
                "scopes": .string(scopes.scopeString),
                "redirect_uri": .string(redirectURI.absoluteString),
            ])

        return AuthorizationStart(handle: handle, interaction: interaction)
    }

    /// A fresh PKCE verifier and its S256 challenge.
    private func makePKCEPair(
        metadata: AuthorizationServerMetadata
    ) throws -> (verifier: String, challenge: String) {
        // OAuth 2.1 makes PKCE mandatory for this grant. A server that publishes
        // its supported methods and omits S256 cannot run the flow safely.
        if metadata.explicitlyRejectsS256PKCE {
            throw OAuthError.invalidConfiguration(
                reason: "authorization server does not support PKCE S256, which OAuth 2.1 requires")
        }
        let verifier = PKCE.makeVerifier()
        do {
            return (verifier, try PKCE.makeChallenge(from: verifier))
        } catch {
            throw OAuthError.invalidConfiguration(
                reason: "PKCE S256 is unavailable on this platform")
        }
    }

    private func buildAuthorizationURL(
        endpoint: URL,
        redirectURI: URL,
        scopes: Set<Scope>,
        stateNonce: String,
        codeChallenge: String
    ) throws -> URL {
        guard var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false) else {
            throw OAuthError.malformedResponse(reason: "authorization_endpoint is not a valid URL")
        }

        var queryItems = components.queryItems ?? []
        queryItems.append(contentsOf: [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: configuration.authentication.clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
            URLQueryItem(name: "state", value: stateNonce),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ])
        if !scopes.isEmpty {
            queryItems.append(URLQueryItem(name: "scope", value: scopes.scopeString))
        }
        if let resource = configuration.resourceIndicator {
            queryItems.append(URLQueryItem(name: "resource", value: resource.absoluteString))
        }
        // Provider-specific parameters last, and only for names not already set,
        // so configuration can add to the request but never silently override
        // `code_challenge` or `state`.
        let reservedNames = Set(queryItems.map(\.name))
        for (name, value) in configuration.additionalAuthorizationParameters.sorted(by: {
            $0.key < $1.key
        }) where !reservedNames.contains(name) {
            queryItems.append(URLQueryItem(name: name, value: value))
        }
        components.queryItems = queryItems

        guard let url = components.url else {
            throw OAuthError.malformedResponse(reason: "could not build the authorization URL")
        }
        return url
    }

    // MARK: - Awaiting completion

    public func awaitAuthorization(
        handle: String,
        timeout: TimeInterval
    ) async throws -> AuthorizationOutcome {
        guard let flow = pendingFlows[handle] else {
            throw OAuthError.unknownFlow(handle: handle)
        }

        if now() >= flow.expiresAt {
            await discard(handle: handle)
            return .expired
        }

        let deadline = now().addingTimeInterval(max(0, timeout))

        switch flow {
        case .device(let deviceFlow):
            return try await awaitDeviceFlow(handle: handle, flow: deviceFlow, deadline: deadline)
        case .browser(let browserFlow):
            return try await awaitBrowserFlow(handle: handle, flow: browserFlow, deadline: deadline)
        case .handoff(let handoffFlow):
            // Nothing arrives by waiting: this flow only moves when the client
            // hands the redirect back, so the caller gets control straight away.
            return .pending(handoffFlow.interaction)
        }
    }

    // MARK: - Completing a hand-off

    public func completeAuthorization(
        handle: String,
        redirectURL: URL
    ) async throws -> AuthorizationOutcome {
        guard let flow = pendingFlows[handle] else {
            throw OAuthError.unknownFlow(handle: handle)
        }
        if now() >= flow.expiresAt {
            await discard(handle: handle)
            return .expired
        }
        guard case .handoff(let handoffFlow) = flow else {
            throw OAuthError.redirectRejected(
                reason: "this sign-in is not waiting for a redirect; only a 'handoff' flow takes one")
        }
        // A URL for somewhere else is a caller mistake, not an attack on this
        // flow — the model may have passed the sign-in URL back, say. Nothing has
        // been sent anywhere, so the flow stays alive for the right URL.
        let expected = handoffFlow.grant.redirectURI
        guard Self.isRedirect(redirectURL, to: expected) else {
            throw OAuthError.redirectRejected(
                reason: "it does not point at \(expected.absoluteString)")
        }

        // Single use, like the loopback listener: the flow is claimed before the
        // first suspension, so a second redirect for the same handle — replayed,
        // or racing this one — finds nothing to complete.
        pendingFlows.removeValue(forKey: handle)
        return try await exchangeAuthorizationCode(
            redirectURL: redirectURL, handle: handle, grant: handoffFlow.grant, label: "Hand-off")
    }

    /// Whether `url` is a redirect to `redirectURI`, ignoring its query.
    ///
    /// Scheme and host compare case-insensitively (RFC 3986 §6.2.2.1); the path
    /// compares exactly, as an authorization server compares it.
    static func isRedirect(_ url: URL, to redirectURI: URL) -> Bool {
        guard
            let candidate = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let expected = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false)
        else { return false }
        return candidate.scheme?.lowercased() == expected.scheme?.lowercased()
            && candidate.host?.lowercased() == expected.host?.lowercased()
            && candidate.port == expected.port
            && candidate.path == expected.path
            && candidate.user == nil && candidate.password == nil
    }

    private func awaitDeviceFlow(
        handle: String,
        flow: DeviceFlow,
        deadline: Date
    ) async throws -> AuthorizationOutcome {
        let metadata = try await discovery.metadata(for: configuration.issuer)
        guard let tokenEndpoint = tokenEndpoint(from: metadata) else {
            throw OAuthError.endpointUnavailable(name: "token_endpoint")
        }

        var currentFlow = flow
        while true {
            // The flow itself can expire before the caller's deadline.
            if now() >= currentFlow.interaction.expiresAt {
                await discard(handle: handle)
                return .expired
            }

            // Honour the server-mandated polling interval, but never sleep past
            // the caller's deadline — returning `.pending` keeps the model in
            // control rather than blocking the tool call indefinitely.
            let waitUntil = min(currentFlow.nextPollAllowedAt, currentFlow.interaction.expiresAt)
            if waitUntil > now() {
                if waitUntil > deadline {
                    persist(handle: handle, flow: currentFlow)
                    // Hold the call until the caller's deadline before reporting
                    // `pending`, as `wait_seconds` promises. Returning at once
                    // whenever the next poll falls after the deadline turned a
                    // client asking to wait 2s against a 5s interval into a busy
                    // loop of instant replies.
                    let remaining = deadline.timeIntervalSince(now())
                    if remaining > 0 { try await Task.sleep(for: .seconds(remaining)) }
                    return .pending(currentFlow.interaction)
                }
                try await Task.sleep(for: .seconds(waitUntil.timeIntervalSince(now())))
            }

            do {
                var parameters = [
                    "grant_type": OAuthConstants.deviceCodeGrant,
                    "device_code": currentFlow.deviceCode,
                ]
                if let resource = configuration.resourceIndicator {
                    parameters["resource"] = resource.absoluteString
                }

                let response = try await tokenClient.requestToken(
                    endpoint: tokenEndpoint, parameters: parameters)
                let tokens = response.makeTokenSet(
                    requestedScopes: currentFlow.scopes,
                    issuer: metadata.issuer,
                    now: now())

                await discard(handle: handle)
                logger.info("Device authorization approved", metadata: ["flow": .string(handle)])
                return .completed(tokens)

            } catch let error as OAuthError {
                switch try deviceOutcome(for: error, flow: &currentFlow, handle: handle) {
                case .some(let outcome):
                    return outcome
                case .none:
                    continue  // authorization_pending / slow_down: keep polling.
                }
            }
        }
    }

    /// Interprets a device-flow polling error.
    ///
    /// Returns `nil` when polling should continue, a terminal outcome otherwise,
    /// and rethrows anything that is not a recognised polling condition.
    private func deviceOutcome(
        for error: OAuthError,
        flow: inout DeviceFlow,
        handle: String
    ) throws -> AuthorizationOutcome? {
        guard case .serverRejected(let code, let description) = error else { throw error }

        switch code {
        case OAuthConstants.authorizationPending:
            flow.nextPollAllowedAt = now().addingTimeInterval(flow.pollInterval)
            persist(handle: handle, flow: flow)
            return nil

        case OAuthConstants.slowDown:
            // RFC 8628 §3.5: increase the interval by 5 seconds and keep going.
            flow.pollInterval += 5
            flow.nextPollAllowedAt = now().addingTimeInterval(flow.pollInterval)
            persist(handle: handle, flow: flow)
            logger.debug(
                "Device polling slowed down",
                metadata: ["interval": .stringConvertible(Int(flow.pollInterval))])
            return nil

        case OAuthConstants.expiredToken:
            pendingFlows.removeValue(forKey: handle)
            return .expired

        case OAuthConstants.accessDenied:
            pendingFlows.removeValue(forKey: handle)
            return .denied(reason: description)

        default:
            pendingFlows.removeValue(forKey: handle)
            throw error
        }
    }

    private func awaitBrowserFlow(
        handle: String,
        flow: BrowserFlow,
        deadline: Date
    ) async throws -> AuthorizationOutcome {
        let remaining = deadline.timeIntervalSince(now())
        guard remaining > 0 else { return .pending(flow.interaction) }

        // Race the redirect against the caller's deadline. The redirect task is
        // owned by the flow, so losing this race leaves it running for the next call.
        enum RaceResult: Sendable {
            case redirected(URL)
            case deadlineReached
        }

        let result: RaceResult
        do {
            result = try await withThrowingTaskGroup(of: RaceResult.self) { group in
                group.addTask { .redirected(try await flow.redirectTask.value) }
                group.addTask {
                    try? await Task.sleep(for: .seconds(remaining))
                    return .deadlineReached
                }
                defer { group.cancelAll() }
                guard let first = try await group.next() else {
                    throw OAuthError.authorizationExpired
                }
                return first
            }
        } catch is CancellationError {
            return .pending(flow.interaction)
        } catch let error as OAuthError where error == .authorizationExpired {
            await discard(handle: handle)
            return .expired
        }

        switch result {
        case .deadlineReached:
            return .pending(flow.interaction)
        case .redirected(let redirectURL):
            return try await exchangeAuthorizationCode(
                redirectURL: redirectURL, handle: handle, grant: flow.grant, label: "Browser")
        }
    }

    private func exchangeAuthorizationCode(
        redirectURL: URL,
        handle: String,
        grant: CodeGrant,
        label: String
    ) async throws -> AuthorizationOutcome {
        guard let components = URLComponents(url: redirectURL, resolvingAgainstBaseURL: false) else {
            await discard(handle: handle)
            throw OAuthError.malformedResponse(reason: "redirect URL could not be parsed")
        }
        let query = Dictionary(
            (components.queryItems ?? []).map { ($0.name, $0.value ?? "") },
            uniquingKeysWith: { first, _ in first })

        // CSRF check first: an attacker-supplied redirect must not reach the
        // token endpoint, even to report an error.
        guard let returnedState = query["state"], constantTimeEquals(returnedState, grant.stateNonce)
        else {
            await discard(handle: handle)
            throw OAuthError.stateMismatch
        }

        if let errorCode = query["error"] {
            await discard(handle: handle)
            if errorCode == OAuthConstants.accessDenied {
                return .denied(reason: query["error_description"])
            }
            throw OAuthError.serverRejected(
                code: errorCode, description: query["error_description"])
        }

        guard let code = query["code"], !code.isEmpty else {
            await discard(handle: handle)
            throw OAuthError.malformedResponse(reason: "redirect carried neither code nor error")
        }

        let metadata = try await discovery.metadata(for: configuration.issuer)
        guard let tokenEndpoint = tokenEndpoint(from: metadata) else {
            await discard(handle: handle)
            throw OAuthError.endpointUnavailable(name: "token_endpoint")
        }

        var parameters = [
            "grant_type": OAuthConstants.authorizationCodeGrant,
            "code": code,
            "redirect_uri": grant.redirectURI.absoluteString,
            "code_verifier": grant.codeVerifier,
        ]
        if let resource = configuration.resourceIndicator {
            parameters["resource"] = resource.absoluteString
        }

        do {
            let response = try await tokenClient.requestToken(
                endpoint: tokenEndpoint, parameters: parameters)
            let tokens = response.makeTokenSet(
                requestedScopes: grant.scopes, issuer: metadata.issuer, now: now())
            await discard(handle: handle)
            logger.info("\(label) authorization approved", metadata: ["flow": .string(handle)])
            return .completed(tokens)
        } catch {
            await discard(handle: handle)
            throw error
        }
    }

    public func cancelAuthorization(handle: String) async {
        await discard(handle: handle)
    }

    // MARK: - Refresh

    public func refresh(_ tokens: TokenSet) async throws -> TokenSet {
        guard let refreshToken = tokens.refreshToken else {
            throw OAuthError.serverRejected(
                code: "invalid_grant", description: "this session has no refresh token")
        }

        let metadata = try await discovery.metadata(for: configuration.issuer)
        guard let tokenEndpoint = tokenEndpoint(from: metadata) else {
            throw OAuthError.endpointUnavailable(name: "token_endpoint")
        }

        var parameters = [
            "grant_type": OAuthConstants.refreshTokenGrant,
            "refresh_token": refreshToken,
        ]
        // RFC 6749 §6: a refresh may narrow scope but never widen it, so the
        // previously granted set is the correct request.
        if !tokens.scopes.isEmpty { parameters["scope"] = tokens.scopes.scopeString }
        if let resource = configuration.resourceIndicator {
            parameters["resource"] = resource.absoluteString
        }

        let response = try await tokenClient.requestToken(
            endpoint: tokenEndpoint, parameters: parameters)
        let issuedAt = now()

        let renewed = tokens.renewed(
            accessToken: response.accessToken,
            tokenType: response.tokenType,
            refreshToken: response.refreshToken,
            idToken: response.idToken,
            scopes: response.scope.map { Set(scopeString: $0) },
            issuedAt: issuedAt,
            expiresAt: response.expiresIn.map { issuedAt.addingTimeInterval($0) })

        logger.info(
            "Refreshed access token",
            metadata: [
                "subject": .string(renewed.subject ?? "unknown"),
                "rotated_refresh_token": .stringConvertible(response.refreshToken != nil),
            ])
        return renewed
    }

    // MARK: - Revocation

    public func revoke(_ tokens: TokenSet) async -> RevocationReport {
        let metadata: AuthorizationServerMetadata
        do {
            metadata = try await discovery.metadata(for: configuration.issuer)
        } catch {
            return RevocationReport(
                accessToken: .failed,
                refreshToken: .failed,
                failureReason: "discovery failed: \(error.localizedDescription)")
        }

        guard let endpoint = revocationEndpoint(from: metadata) else {
            return RevocationReport(
                accessToken: .unsupported,
                refreshToken: .unsupported,
                failureReason: "the authorization server publishes no revocation endpoint")
        }

        var failureReason: String?

        // RFC 7009 §2.1 note: revoking the refresh token normally invalidates the
        // whole grant, so it goes first. The access token is revoked afterwards
        // regardless, because servers are only *encouraged* to cascade.
        var refreshResult = RevocationReport.Result.notPresent
        if let refreshToken = tokens.refreshToken {
            do {
                _ = try await tokenClient.revokeToken(
                    endpoint: endpoint, token: refreshToken,
                    typeHint: OAuthConstants.refreshTokenHint)
                refreshResult = .revoked
            } catch {
                refreshResult = .failed
                failureReason = error.localizedDescription
            }
        }

        var accessResult = RevocationReport.Result.notPresent
        do {
            _ = try await tokenClient.revokeToken(
                endpoint: endpoint, token: tokens.accessToken,
                typeHint: OAuthConstants.accessTokenHint)
            accessResult = .revoked
        } catch {
            accessResult = .failed
            failureReason = failureReason ?? error.localizedDescription
        }

        logger.info(
            "Revocation completed",
            metadata: [
                "access_token": .string(accessResult.rawValue),
                "refresh_token": .string(refreshResult.rawValue),
            ])

        return RevocationReport(
            accessToken: accessResult, refreshToken: refreshResult, failureReason: failureReason)
    }

    // MARK: - Endpoint resolution

    private func authorizationEndpoint(from metadata: AuthorizationServerMetadata) -> URL? {
        configuration.endpointOverrides.authorizationEndpoint ?? metadata.authorizationEndpoint
    }

    private func tokenEndpoint(from metadata: AuthorizationServerMetadata) -> URL? {
        configuration.endpointOverrides.tokenEndpoint ?? metadata.tokenEndpoint
    }

    private func deviceEndpoint(from metadata: AuthorizationServerMetadata) -> URL? {
        configuration.endpointOverrides.deviceAuthorizationEndpoint
            ?? metadata.deviceAuthorizationEndpoint
    }

    private func revocationEndpoint(from metadata: AuthorizationServerMetadata) -> URL? {
        configuration.endpointOverrides.revocationEndpoint ?? metadata.revocationEndpoint
    }

    // MARK: - Flow bookkeeping

    private func persist(handle: String, flow: DeviceFlow) {
        pendingFlows[handle] = .device(flow)
    }

    private func discard(handle: String) async {
        guard let flow = pendingFlows.removeValue(forKey: handle) else { return }
        if case .browser(let browserFlow) = flow {
            browserFlow.redirectTask.cancel()
            await browserFlow.listener.stop()
        }
    }

    /// Drops flows whose deadline has passed, releasing their listeners.
    private func expirePendingFlows() {
        let currentTime = now()
        for (handle, flow) in pendingFlows where currentTime >= flow.expiresAt {
            let expired = pendingFlows.removeValue(forKey: handle)
            if case .browser(let browserFlow) = expired {
                browserFlow.redirectTask.cancel()
                Task { await browserFlow.listener.stop() }
            }
        }
    }

    /// Exposed for tests: how many authorizations are in flight.
    public var pendingFlowCount: Int { pendingFlows.count }

    // MARK: - Helpers

    private static func makeHandle() -> String {
        "flow_" + makeNonce(byteCount: 12)
    }

    /// A cryptographically random, URL-safe nonce.
    ///
    /// `SystemRandomNumberGenerator` is the platform CSPRNG (`arc4random_buf` on
    /// Darwin), which is what a CSRF `state` value and a flow handle need.
    private static func makeNonce(byteCount: Int = 24) -> String {
        var generator = SystemRandomNumberGenerator()
        var bytes = [UInt8](repeating: 0, count: byteCount)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: 0...255, using: &generator)
        }
        return Data(bytes).base64URLEncodedStringWithoutPadding()
    }

    private static func deviceInstructions(url: URL, code: String, hasPrefilledURL: Bool) -> String {
        if hasPrefilledURL {
            return
                "Open \(url.absoluteString) and confirm the code \(code) to finish signing in. "
                + "The code is shown so you can check it matches the page."
        }
        return "Go to \(url.absoluteString) and enter the code \(code) to finish signing in."
    }

    /// Opens a URL in the user's default browser without linking AppKit.
    private static func openInBrowser(_ url: URL, logger: Logger) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = [url.absoluteString]
        do {
            try process.run()
        } catch {
            logger.warning(
                "Could not open the browser automatically",
                metadata: ["error": .string(error.localizedDescription)])
        }
    }
}

/// Compares two strings without leaking their contents through timing.
///
/// The `state` nonce is a CSRF token; comparing it with `==` would exit at the
/// first differing byte and make it measurably guessable.
func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
    let left = Array(lhs.utf8)
    let right = Array(rhs.utf8)
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for index in left.indices {
        difference |= left[index] ^ right[index]
    }
    return difference == 0
}

extension Data {
    /// base64url without padding, as used for PKCE and nonces.
    func base64URLEncodedStringWithoutPadding() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
