import Foundation
import Testing

@testable import AuthenticationKit

@Suite("OAuth 2.1 provider")
struct OAuthProviderTests {

    private func makeProvider(
        http: ScriptedHTTPClient,
        configuration: OAuthProviderConfiguration = Fixtures.oauthConfiguration(),
        canReachUserBrowser: Bool = false
    ) throws -> OAuthAuthorizationProvider {
        try OAuthAuthorizationProvider(
            configuration: configuration,
            http: http,
            logger: makeSilentLogger(),
            canReachUserBrowser: canReachUserBrowser)
    }

    // MARK: - Discovery

    @Test("Discovery tries the RFC 8414 well-known location")
    func discoveryUsesWellKnownPath() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        let provider = try makeProvider(http: http)

        _ = try await provider.beginAuthorization(scopes: [.dataRead], mode: .device)

        let discoveryRequests = http.requests(toPath: "/.well-known/oauth-authorization-server")
        #expect(discoveryRequests.count == 1)
        #expect(discoveryRequests[0].method == "GET")
    }

    @Test("A discovery document declaring a different issuer is rejected")
    func discoveryRejectsIssuerMismatch() async throws {
        let http = ScriptedHTTPClient()
        // Both well-known paths answer with the wrong issuer, so every candidate fails.
        for path in [
            "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration",
        ] {
            http.stub(
                path: path,
                reply: .json(
                    Fixtures.discoveryDocument(issuerOverride: "https://attacker.example")))
        }
        let provider = try makeProvider(http: http)

        await #expect(throws: OAuthError.self) {
            try await provider.beginAuthorization(scopes: [.dataRead], mode: .device)
        }
    }

    @Test("Metadata is cached, so a second flow does not re-fetch it")
    func discoveryIsCached() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        let provider = try makeProvider(http: http)

        _ = try await provider.beginAuthorization(scopes: [.dataRead], mode: .device)
        _ = try await provider.beginAuthorization(scopes: [.dataRead], mode: .device)

        #expect(http.requests(toPath: "/.well-known/oauth-authorization-server").count == 1)
    }

    // MARK: - Device grant

    @Test("The device grant surfaces the user code and verification URL")
    func deviceFlowStart() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        let provider = try makeProvider(http: http)

        let start = try await provider.beginAuthorization(scopes: [.dataRead], mode: .device)

        #expect(start.interaction.userCode == "WXYZ-1234")
        #expect(start.interaction.mode == .device)
        #expect(
            start.interaction.verificationURLComplete?.absoluteString
                == "https://as.example.com/activate?user_code=WXYZ-1234")
        #expect(start.interaction.instructions.contains("WXYZ-1234"))

        // The resource indicator must be sent so the token is audience-restricted.
        let deviceRequest = try #require(http.requests(toPath: "/device").first)
        #expect(deviceRequest.form["resource"] == "https://api.example.com")
        #expect(deviceRequest.form["scope"] == "data:read")
        #expect(deviceRequest.form["client_id"] == "test-client")
    }

    @Test("Polling keeps going through authorization_pending and then completes")
    func deviceFlowPollsUntilApproved() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [
            .oauthError("authorization_pending"),
            .oauthError("authorization_pending"),
            Fixtures.tokenResponse(accessToken: "granted-token"),
        ])
        let provider = try makeProvider(http: http)

        let start = try await provider.beginAuthorization(scopes: Scope.defaults, mode: .device)
        let outcome = try await provider.awaitAuthorization(handle: start.handle, timeout: 5)

        guard case .completed(let tokens) = outcome else {
            Issue.record("expected completion, got \(outcome)")
            return
        }
        #expect(tokens.accessToken == "granted-token")
        #expect(tokens.refreshToken == "refresh-1")
        #expect(tokens.scopes == Scope.defaults)
        #expect(http.requests(toPath: "/token").count == 3)

        // The flow is cleaned up once it completes.
        #expect(await provider.pendingFlowCount == 0)
    }

    @Test("A slow_down response lengthens the interval and returns control to the caller")
    func deviceFlowHonoursSlowDown() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [
            .oauthError("slow_down"),
            Fixtures.tokenResponse(),
        ])
        let provider = try makeProvider(http: http)

        let start = try await provider.beginAuthorization(scopes: Scope.defaults, mode: .device)
        // A zero timeout means the post-slow_down wait pushes past the deadline,
        // so the call returns `pending` rather than sleeping out the new interval.
        let outcome = try await provider.awaitAuthorization(handle: start.handle, timeout: 0)

        guard case .pending = outcome else {
            Issue.record("expected pending after slow_down, got \(outcome)")
            return
        }
        #expect(http.requests(toPath: "/token").count == 1)
        #expect(await provider.pendingFlowCount == 1, "the flow must stay resumable")
    }

    @Test("A denied authorization is reported as denied, not as a crash")
    func deviceFlowDenied() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [
            .oauthError("access_denied", description: "user said no")
        ])
        let provider = try makeProvider(http: http)

        let start = try await provider.beginAuthorization(scopes: Scope.defaults, mode: .device)
        let outcome = try await provider.awaitAuthorization(handle: start.handle, timeout: 5)

        guard case .denied(let reason) = outcome else {
            Issue.record("expected denial, got \(outcome)")
            return
        }
        #expect(reason == "user said no")
    }

    @Test("An expired device code is reported as expired")
    func deviceFlowExpired() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [.oauthError("expired_token")])
        let provider = try makeProvider(http: http)

        let start = try await provider.beginAuthorization(scopes: Scope.defaults, mode: .device)
        let outcome = try await provider.awaitAuthorization(handle: start.handle, timeout: 5)

        guard case .expired = outcome else {
            Issue.record("expected expiry, got \(outcome)")
            return
        }
    }

    @Test("An unrecognised polling error stops the flow instead of spinning")
    func deviceFlowUnknownErrorStops() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [.oauthError("invalid_client")])
        let provider = try makeProvider(http: http)

        let start = try await provider.beginAuthorization(scopes: Scope.defaults, mode: .device)
        await #expect(throws: OAuthError.serverRejected(code: "invalid_client", description: nil)) {
            try await provider.awaitAuthorization(handle: start.handle, timeout: 5)
        }
        #expect(await provider.pendingFlowCount == 0)
    }

    @Test("Polling an unknown flow reports it rather than hanging")
    func unknownFlow() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        let provider = try makeProvider(http: http)

        await #expect(throws: OAuthError.unknownFlow(handle: "flow_nope")) {
            try await provider.awaitAuthorization(handle: "flow_nope", timeout: 1)
        }
    }

    @Test("The device grant is refused when the server does not offer it")
    func deviceGrantUnavailable() async throws {
        let http = ScriptedHTTPClient()
        http.stub(
            path: "/.well-known/oauth-authorization-server",
            reply: .json(Fixtures.discoveryDocument(includeDevice: false)))
        let provider = try makeProvider(http: http)

        await #expect(throws: OAuthError.endpointUnavailable(name: "device_authorization_endpoint")) {
            try await provider.beginAuthorization(scopes: Scope.defaults, mode: .device)
        }
    }

    @Test("automatic mode picks the device grant when no browser is reachable")
    func automaticPrefersDeviceWithoutBrowser() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        let provider = try makeProvider(http: http, canReachUserBrowser: false)

        let start = try await provider.beginAuthorization(scopes: Scope.defaults, mode: .automatic)
        #expect(start.interaction.mode == .device)
    }

    // MARK: - Refresh

    @Test("Refresh exchanges the refresh token and keeps identity fields")
    func refreshKeepsIdentity() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [
            .json([
                "access_token": "fresh-access",
                "token_type": "Bearer",
                "expires_in": 3600,
            ])
        ])
        let provider = try makeProvider(http: http)

        let original = TokenSet(
            accessToken: "old-access",
            refreshToken: "refresh-1",
            scopes: Scope.defaults,
            expiresAt: Date().addingTimeInterval(10),
            subject: "user-42",
            principalName: "User Forty-Two",
            issuer: Fixtures.issuer)

        let renewed = try await provider.refresh(original)

        #expect(renewed.accessToken == "fresh-access")
        // The response omitted these; they must carry over rather than vanish.
        #expect(renewed.refreshToken == "refresh-1")
        #expect(renewed.subject == "user-42")
        #expect(renewed.principalName == "User Forty-Two")
        #expect(renewed.scopes == Scope.defaults)

        let request = try #require(http.requests(toPath: "/token").last)
        #expect(request.form["grant_type"] == "refresh_token")
        #expect(request.form["refresh_token"] == "refresh-1")
    }

    @Test("A rotated refresh token replaces the old one")
    func refreshRotation() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [
            Fixtures.tokenResponse(accessToken: "a2", refreshToken: "refresh-2")
        ])
        let provider = try makeProvider(http: http)

        let renewed = try await provider.refresh(
            TokenSet(accessToken: "a1", refreshToken: "refresh-1", scopes: Scope.defaults))

        #expect(renewed.refreshToken == "refresh-2")
    }

    @Test("Refreshing without a refresh token fails cleanly")
    func refreshWithoutToken() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        let provider = try makeProvider(http: http)

        await #expect(throws: OAuthError.self) {
            try await provider.refresh(
                TokenSet(accessToken: "a", refreshToken: nil, scopes: Scope.defaults))
        }
    }

    // MARK: - Revocation

    @Test("Revocation sends both tokens with the right type hints")
    func revokesBothTokens() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        let provider = try makeProvider(http: http)

        let report = await provider.revoke(
            TokenSet(accessToken: "access-1", refreshToken: "refresh-1", scopes: Scope.defaults))

        #expect(report.accessToken == .revoked)
        #expect(report.refreshToken == .revoked)
        #expect(report.isCompleteUpstream)

        let revocations = http.requests(toPath: "/revoke")
        #expect(revocations.count == 2)
        // The refresh token goes first: revoking it usually drops the whole grant.
        #expect(revocations[0].form["token"] == "refresh-1")
        #expect(revocations[0].form["token_type_hint"] == "refresh_token")
        #expect(revocations[1].form["token"] == "access-1")
        #expect(revocations[1].form["token_type_hint"] == "access_token")
    }

    @Test("A server with no revocation endpoint is reported, not silently ignored")
    func revocationUnsupported() async throws {
        let http = ScriptedHTTPClient()
        http.stub(
            path: "/.well-known/oauth-authorization-server",
            reply: .json(Fixtures.discoveryDocument(includeRevocation: false)))
        let provider = try makeProvider(http: http)

        let report = await provider.revoke(
            TokenSet(accessToken: "a", refreshToken: "r", scopes: []))

        #expect(report.accessToken == .unsupported)
        #expect(report.refreshToken == .unsupported)
        #expect(!report.isCompleteUpstream)
        #expect(report.failureReason != nil)
    }

    @Test("A failing revocation endpoint is reported as failed, and never throws")
    func revocationFailure() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        http.stub(path: "/revoke", reply: .oauthError("server_error", status: 500))
        let provider = try makeProvider(http: http)

        let report = await provider.revoke(
            TokenSet(accessToken: "a", refreshToken: "r", scopes: []))

        #expect(report.accessToken == .failed)
        #expect(report.refreshToken == .failed)
        #expect(!report.isCompleteUpstream)
    }

    @Test("A session with no refresh token reports it as absent, not failed")
    func revocationWithoutRefreshToken() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        let provider = try makeProvider(http: http)

        let report = await provider.revoke(
            TokenSet(accessToken: "a", refreshToken: nil, scopes: []))

        #expect(report.refreshToken == .notPresent)
        #expect(report.accessToken == .revoked)
        #expect(report.isCompleteUpstream)
    }

    // MARK: - Configuration

    @Test("A plaintext non-loopback issuer is refused")
    func rejectsInsecureIssuer() {
        let configuration = OAuthProviderConfiguration(
            issuer: URL(string: "http://as.example.com")!,
            authentication: .publicClient(clientID: "x"))
        #expect(throws: OAuthError.self) { try configuration.validate() }
    }

    @Test("A plaintext loopback issuer is allowed, for local development")
    func allowsLoopbackIssuer() throws {
        let configuration = OAuthProviderConfiguration(
            issuer: URL(string: "http://127.0.0.1:9000")!,
            authentication: .publicClient(clientID: "x"))
        try configuration.validate()
    }

    @Test("Basic client authentication is sent in the Authorization header")
    func clientSecretBasic() async throws {
        let http = Fixtures.deviceFlowClient(pollReplies: [Fixtures.tokenResponse()])
        let configuration = OAuthProviderConfiguration(
            issuer: Fixtures.issuer,
            authentication: .clientSecretBasic(clientID: "id", clientSecret: "s3cr3t"))
        let provider = try makeProvider(http: http, configuration: configuration)

        _ = try await provider.beginAuthorization(scopes: [.dataRead], mode: .device)

        let request = try #require(http.requests(toPath: "/device").first)
        let expected = "Basic " + Data("id:s3cr3t".utf8).base64EncodedString()
        #expect(request.headers["Authorization"] == expected)
        // The secret must not also be duplicated into the form body.
        #expect(request.form["client_secret"] == nil)
    }
}
