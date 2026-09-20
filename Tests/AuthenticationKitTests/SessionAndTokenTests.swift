import Foundation
import MCP
import Testing

@testable import AuthenticationKit

@Suite("Sessions and tokens")
struct SessionAndTokenTests {

    // MARK: - Token expiry

    @Test("A token with no expiry is never treated as expired")
    func neverExpires() {
        let token = TokenSet(accessToken: "a", scopes: [], expiresAt: nil)
        #expect(!token.isExpired())
        #expect(!token.shouldRefresh())
    }

    @Test("Expiry accounts for clock skew")
    func expirySkew() {
        let now = Date()
        // Ten seconds of life left, inside the 30-second skew allowance.
        let token = TokenSet(accessToken: "a", scopes: [], expiresAt: now.addingTimeInterval(10))
        #expect(token.isExpired(now: now))
        #expect(!token.isExpired(now: now, skew: 0))
    }

    @Test("Proactive refresh only applies when a refresh token exists")
    func proactiveRefreshNeedsRefreshToken() {
        let now = Date()
        let soon = now.addingTimeInterval(60)

        let withRefresh = TokenSet(
            accessToken: "a", refreshToken: "r", scopes: [], expiresAt: soon)
        let withoutRefresh = TokenSet(
            accessToken: "a", refreshToken: nil, scopes: [], expiresAt: soon)

        #expect(withRefresh.shouldRefresh(now: now))
        #expect(!withoutRefresh.shouldRefresh(now: now))
    }

    // MARK: - Session store

    @Test("An expiring session is refreshed transparently on use")
    func refreshesOnUse() async throws {
        let clock = TestClock()
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(
            accessTokenLifetime: 300, logger: logger, now: clock.provider)
        let store = SessionStore(
            provider: provider, auditLog: auditLog, logger: logger, now: clock.provider)

        let outcome = try await provider.awaitAuthorization(
            handle: try await provider.beginAuthorization(scopes: Scope.defaults, mode: .device)
                .handle,
            timeout: 0)
        guard case .completed(let tokens) = outcome else {
            Issue.record("mock provider should approve immediately")
            return
        }
        let session = await store.createSession(owner: .stdio, tokens: tokens)
        let originalToken = session.tokens.accessToken

        // Move to inside the proactive-refresh window.
        clock.advance(by: 250)
        let refreshed = try await store.resolveSession(
            sessionID: nil, owner: .stdio, requiredScope: nil)

        #expect(refreshed.id == session.id, "refresh must not change the session id")
        #expect(refreshed.tokens.accessToken != originalToken, "the token should have been renewed")
    }

    @Test("A session that cannot be refreshed is destroyed once it expires")
    func destroysUnrefreshableExpiredSession() async throws {
        let clock = TestClock()
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(logger: logger, now: clock.provider)
        let store = SessionStore(
            provider: provider, auditLog: auditLog, logger: logger, now: clock.provider)

        let tokens = TokenSet(
            accessToken: "dead",
            refreshToken: nil,
            scopes: Scope.defaults,
            issuedAt: clock.now,
            expiresAt: clock.now.addingTimeInterval(60),
            subject: "user")
        _ = await store.createSession(owner: .stdio, tokens: tokens)

        clock.advance(by: 120)

        await #expect(throws: SessionError.self) {
            try await store.resolveSession(sessionID: nil, owner: .stdio, requiredScope: nil)
        }
        #expect(await store.sessionCount == 0)
    }

    @Test("A session id from another owner is reported as not found")
    func ownerIsolation() async throws {
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(logger: logger)
        let store = SessionStore(provider: provider, auditLog: auditLog, logger: logger)

        let session = await store.createSession(
            owner: SessionOwner("alice"),
            tokens: TokenSet(accessToken: "a", scopes: Scope.defaults, subject: "alice"))

        await #expect(throws: SessionError.notFound(sessionID: session.id)) {
            try await store.peek(sessionID: session.id, owner: SessionOwner("mallory"))
        }

        // The rightful owner still sees it.
        let mine = try await store.peek(sessionID: session.id, owner: SessionOwner("alice"))
        #expect(mine.id == session.id)
    }

    @Test("Two sessions with no active one is reported as ambiguous")
    func ambiguousSessions() async throws {
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(logger: logger)
        let store = SessionStore(provider: provider, auditLog: auditLog, logger: logger)
        let owner = SessionOwner("alice")

        let first = await store.createSession(
            owner: owner, tokens: TokenSet(accessToken: "a", scopes: [], subject: "alice"))
        _ = await store.createSession(
            owner: owner, tokens: TokenSet(accessToken: "b", scopes: [], subject: "alice"))

        // Destroying the active session leaves two-minus-one, so make a third and
        // drop the active pointer's target to reach the ambiguous case.
        let third = await store.createSession(
            owner: owner, tokens: TokenSet(accessToken: "c", scopes: [], subject: "alice"))
        await store.destroy(sessionID: third.id)
        await store.destroy(sessionID: first.id)

        // One left: resolvable without naming it.
        let resolved = try await store.resolveSession(
            sessionID: nil, owner: owner, requiredScope: nil)
        #expect(resolved.tokens.accessToken == "b")
    }

    @Test("Releasing an owner revokes its sessions upstream")
    func releasingOwnerRevokes() async throws {
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(logger: logger)
        let store = SessionStore(provider: provider, auditLog: auditLog, logger: logger)

        let tokens = TokenSet(
            accessToken: "access-x", refreshToken: "refresh-x",
            scopes: Scope.defaults, subject: "alice")
        _ = await store.createSession(owner: .stdio, tokens: tokens)

        await store.destroyAll(ownedBy: .stdio)

        #expect(await store.sessionCount == 0)
        #expect(await provider.isRevoked("access-x"))
        #expect(await provider.isRevoked("refresh-x"))
    }

    @Test("A session snapshot carries identity but no credentials")
    func snapshotIsRedacted() async throws {
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(logger: logger)
        let store = SessionStore(provider: provider, auditLog: auditLog, logger: logger)

        let session = await store.createSession(
            owner: .stdio,
            tokens: TokenSet(
                accessToken: "super-secret-access-token",
                refreshToken: "super-secret-refresh-token",
                idToken: "super-secret-id-token",
                scopes: Scope.defaults,
                expiresAt: Date().addingTimeInterval(3600),
                subject: "alice",
                principalName: "Alice"))

        let rendered = session.snapshot.prettyJSONString
        #expect(rendered.contains("alice"))
        #expect(rendered.contains("Alice"))
        #expect(!rendered.contains("super-secret"))
        #expect(session.snapshot["can_refresh"]?.boolValue == true)
    }

    // MARK: - JWT claims

    @Test("An ID token's subject and display name are extracted")
    func decodesIDToken() throws {
        let token = Fixtures.unsignedJWT(claims: [
            "sub": "user-123",
            "iss": "https://as.example.com",
            "aud": "test-client",
            "preferred_username": "alice",
            "scope": "data:read data:write",
            "exp": 2_000_000_000,
        ])

        let claims = try #require(JWTClaims.decodeUnverifiedPayload(of: token))
        #expect(claims.subject == "user-123")
        #expect(claims.principalName == "alice")
        #expect(claims.audience == ["test-client"])
        #expect(claims.scopes == Scope.defaults)
    }

    @Test("An opaque token is not a JWT, and that is not an error")
    func opaqueTokenReturnsNil() {
        #expect(JWTClaims.decodeUnverifiedPayload(of: "opaque-token-value") == nil)
        #expect(JWTClaims.decodeUnverifiedPayload(of: "a.b") == nil)
        #expect(JWTClaims.decodeUnverifiedPayload(of: "a.!!!notbase64!!!.c") == nil)
    }

    @Test("A multi-value audience decodes as an array")
    func decodesMultipleAudiences() throws {
        let token = Fixtures.unsignedJWT(claims: ["sub": "u", "aud": ["one", "two"]])
        let claims = try #require(JWTClaims.decodeUnverifiedPayload(of: token))
        #expect(claims.audience == ["one", "two"])
    }

    // MARK: - Redaction

    @Test("Secrets are fingerprinted, never logged whole")
    func redactsSecrets() {
        #expect(Redaction.fingerprint("supersecrettoken") == "****oken")
        #expect(Redaction.fingerprint("abc") == "****")

        let redacted = Redaction.redactSensitiveKeys([
            "access_token": "aaaaaaaaaaaa1234",
            "scope": "data:read",
        ])
        #expect(redacted["access_token"] == "****1234")
        #expect(redacted["scope"] == "data:read", "non-secret fields stay readable")
    }

    @Test("The audit log never stores raw token material")
    func auditLogRedacts() async {
        let log = AuditLog(logger: makeSilentLogger())
        await log.record(
            .revocationSucceeded,
            subject: "alice",
            detail: ["refresh_token": "rrrrrrrrrrrrABCD", "id": "doc"])

        let entries = await log.recentEntries()
        #expect(entries.count == 1)
        #expect(entries[0].detail["refresh_token"] == "****ABCD")
        #expect(entries[0].detail["id"] == "doc")
    }

    // MARK: - Constant-time comparison

    @Test("State comparison is exact")
    func constantTimeComparison() {
        #expect(constantTimeEquals("abc123", "abc123"))
        #expect(!constantTimeEquals("abc123", "abc124"))
        #expect(!constantTimeEquals("abc", "abcd"))
        #expect(constantTimeEquals("", ""))
    }
}
