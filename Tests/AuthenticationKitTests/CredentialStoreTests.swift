import Foundation
import MCP
import Testing

@testable import AuthenticationKit

@Suite("Credential persistence")
struct CredentialStoreTests {

    /// A store in a throwaway directory, always file-backed.
    ///
    /// The keychain is deliberately avoided in tests: it is shared machine state,
    /// and on an unsigned test binary it can prompt.
    private func makeStore(
        clock: TestClock = TestClock()
    ) throws -> (store: CredentialStore, directory: URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-creds-\(UUID().uuidString)")
        let store = try CredentialStore.make(
            serviceName: "test",
            directory: directory,
            preferredBackend: .file,
            logger: makeSilentLogger(),
            now: clock.provider)
        return (store, directory)
    }

    private func makeCredential(
        account: String = "user@example.com",
        subject: String = "sub-1",
        accessToken: String = "access-1",
        refreshToken: String? = "refresh-1",
        expiresIn: TimeInterval? = 3600,
        scopes: Set<Scope> = Scope.defaults,
        now: Date = Date()
    ) -> StoredCredential {
        StoredCredential.make(
            from: TokenSet(
                accessToken: accessToken,
                refreshToken: refreshToken,
                scopes: scopes,
                issuedAt: now,
                expiresAt: expiresIn.map { now.addingTimeInterval($0) },
                subject: subject,
                principalName: account,
                issuer: URL(string: "https://as.example.com")),
            issuer: URL(string: "https://as.example.com")!,
            now: now)
    }

    // MARK: - Round trip

    @Test("A saved credential survives a new store over the same directory")
    func survivesRestart() async throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = makeCredential()
        try await store.save(credential)

        // A second instance stands in for a fresh process.
        let reopened = try CredentialStore.make(
            serviceName: "test", directory: directory,
            preferredBackend: .file, logger: makeSilentLogger())

        let loaded = try #require(try await reopened.load())
        #expect(loaded.account == credential.account)
        #expect(loaded.tokens.accessToken == "access-1")
        #expect(loaded.tokens.refreshToken == "refresh-1")
        #expect(loaded.entry.hasRefreshToken)
    }

    @Test("The index file holds no secret material")
    func indexHasNoSecrets() async throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await store.save(
            makeCredential(accessToken: "SECRET-ACCESS", refreshToken: "SECRET-REFRESH"))

        // The whole point of the split: `auth status` reads this file, and it must
        // never be able to leak a token.
        let indexText = try String(contentsOf: await store.indexURL, encoding: .utf8)
        #expect(indexText.contains("user@example.com"))
        #expect(!indexText.contains("SECRET-ACCESS"))
        #expect(!indexText.contains("SECRET-REFRESH"))
    }

    @Test("Secret files are owner-only")
    func secretFilePermissions() async throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await store.save(makeCredential())

        let secretsDirectory = directory.appendingPathComponent("secrets")
        let files = try FileManager.default.contentsOfDirectory(
            at: secretsDirectory, includingPropertiesForKeys: nil)
        let secretFile = try #require(files.first { $0.pathExtension == "json" })

        let attributes = try FileManager.default.attributesOfItem(atPath: secretFile.path)
        let permissions = try #require(attributes[.posixPermissions] as? NSNumber)
        #expect(permissions.int16Value == 0o600)
    }

    @Test("Deleting removes both halves")
    func deleteRemovesEverything() async throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await store.save(makeCredential())
        try await store.delete(account: "user@example.com")

        #expect(try await store.load() == nil)
        #expect(try await store.accounts().isEmpty)
        #expect(try await store.activeAccount() == nil)
    }

    @Test("Deleting something that is not there succeeds")
    func deleteIsIdempotent() async throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await store.delete(account: "nobody@example.com")
        #expect(try await store.load() == nil)
    }

    @Test("An index entry with no stored secret is discarded, not reported as signed in")
    func healsOrphanedIndexEntry() async throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await store.save(makeCredential())

        // Simulate the secret being removed out from under the index — a keychain
        // wiped by the user, say. Reporting a sign-in that cannot mint a token
        // would strand the caller.
        let secretsDirectory = directory.appendingPathComponent("secrets")
        for file in try FileManager.default.contentsOfDirectory(
            at: secretsDirectory, includingPropertiesForKeys: nil)
        {
            try FileManager.default.removeItem(at: file)
        }

        #expect(try await store.load() == nil)
        #expect(try await store.accounts().isEmpty, "the orphaned entry should be dropped")
    }

    @Test("A corrupt index is treated as empty rather than fatal")
    func survivesCorruptIndex() async throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await store.save(makeCredential())
        try Data("{ not json at all".utf8).write(to: await store.indexURL)

        #expect(try await store.accounts().isEmpty)
        #expect(try await store.load() == nil)
    }

    @Test("Several accounts coexist, with one active")
    func multipleAccounts() async throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await store.save(makeCredential(account: "a@example.com", subject: "sub-a"))
        try await store.save(
            makeCredential(account: "b@example.com", subject: "sub-b"), makeActive: false)

        #expect(try await store.accounts().count == 2)
        #expect(try await store.activeAccount() == "a@example.com")

        try await store.setActiveAccount("b@example.com")
        #expect(try await store.load()?.account == "b@example.com")
        // Naming an account explicitly still reaches the other one.
        #expect(try await store.load(account: "a@example.com")?.account == "a@example.com")
    }

    @Test("Deleting the active account promotes another rather than stranding them")
    func deletingActivePromotes() async throws {
        let (store, directory) = try makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try await store.save(makeCredential(account: "a@example.com", subject: "sub-a"))
        try await store.save(makeCredential(account: "b@example.com", subject: "sub-b"))
        try await store.delete(account: "b@example.com")

        #expect(try await store.activeAccount() == "a@example.com")
    }

    // MARK: - Account naming

    @Test("An email from the ID token becomes the account name")
    func prefersEmailAsAccountName() {
        let idToken = Fixtures.unsignedJWT(claims: [
            "sub": "1158", "email": "sam@example.com",
        ])
        let tokens = TokenSet(
            accessToken: "a", idToken: idToken, scopes: [], subject: "1158")

        // Far more legible in `auth status` and in a keychain entry than "1158".
        #expect(StoredCredential.accountName(for: tokens, fallback: nil) == "sam@example.com")
    }

    @Test("Without an email, the subject is used")
    func fallsBackToSubject() {
        let tokens = TokenSet(accessToken: "a", scopes: [], subject: "1158")
        #expect(StoredCredential.accountName(for: tokens, fallback: nil) == "1158")
    }
}

@Suite("Authentication coordinator")
struct AuthenticationCoordinatorTests {

    private func makeCoordinator(
        policy: MockAuthorizationProvider.ApprovalPolicy = .immediate,
        accessTokenLifetime: TimeInterval = 3600,
        clock: TestClock = TestClock()
    ) throws -> (
        coordinator: AuthenticationCoordinator,
        provider: MockAuthorizationProvider,
        store: CredentialStore,
        directory: URL
    ) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-coord-\(UUID().uuidString)")
        let logger = makeSilentLogger()
        let provider = MockAuthorizationProvider(
            policy: policy,
            subject: "sub-1",
            accessTokenLifetime: accessTokenLifetime,
            logger: logger,
            now: clock.provider)
        let store = try CredentialStore.make(
            serviceName: "test", directory: directory,
            preferredBackend: .file, logger: logger, now: clock.provider)
        let coordinator = AuthenticationCoordinator(
            provider: provider,
            credentialStore: store,
            issuer: URL(string: "https://as.example.com")!,
            logger: logger,
            now: clock.provider)
        return (coordinator, provider, store, directory)
    }

    @Test("Signing in persists a credential")
    func signInPersists() async throws {
        let (coordinator, _, store, directory) = try makeCoordinator()
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try await coordinator.signIn()

        #expect(credential.entry.subject == "sub-1")
        #expect(credential.entry.hasRefreshToken)
        #expect(try await store.load()?.account == credential.account)
    }

    @Test("A declined sign-in persists nothing")
    func deniedSignInPersistsNothing() async throws {
        let (coordinator, _, store, directory) = try makeCoordinator(
            policy: .denied(reason: "no"))
        defer { try? FileManager.default.removeItem(at: directory) }

        await #expect(throws: OAuthError.self) {
            try await coordinator.signIn()
        }
        #expect(try await store.load() == nil)
    }

    @Test("An expiring credential is refreshed and the new one written back")
    func refreshesAndPersists() async throws {
        let clock = TestClock()
        let (coordinator, _, store, directory) = try makeCoordinator(
            accessTokenLifetime: 300, clock: clock)
        defer { try? FileManager.default.removeItem(at: directory) }

        let original = try await coordinator.signIn()
        clock.advance(by: 250)

        let renewed = try #require(try await coordinator.currentCredential())
        #expect(renewed.tokens.accessToken != original.tokens.accessToken)
        // Persisting immediately matters: a rotated refresh token that is not
        // written back locks the user out permanently.
        #expect(try await store.load()?.tokens.accessToken == renewed.tokens.accessToken)
        // The original sign-in time is preserved across refreshes.
        #expect(renewed.entry.obtainedAt == original.entry.obtainedAt)
    }

    @Test("A still-valid credential is returned without contacting the provider")
    func doesNotRefreshEarly() async throws {
        let clock = TestClock()
        let (coordinator, _, _, directory) = try makeCoordinator(clock: clock)
        defer { try? FileManager.default.removeItem(at: directory) }

        let original = try await coordinator.signIn()
        clock.advance(by: 60)

        let current = try #require(try await coordinator.currentCredential())
        #expect(current.tokens.accessToken == original.tokens.accessToken)
    }

    @Test("Nothing signed in reads as nil, not as an error")
    func noCredentialIsNotAnError() async throws {
        let (coordinator, _, _, directory) = try makeCoordinator()
        defer { try? FileManager.default.removeItem(at: directory) }

        #expect(try await coordinator.currentCredential() == nil)
    }

    @Test("Signing out revokes upstream and removes the credential")
    func signOutRevokesAndClears() async throws {
        let (coordinator, provider, store, directory) = try makeCoordinator()
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try await coordinator.signIn()
        let report = try await coordinator.signOut()

        #expect(report.accounts == [credential.account])
        #expect(try await store.load() == nil)
        #expect(await provider.isRevoked(credential.tokens.accessToken))
        #expect(await provider.isRevoked(credential.tokens.refreshToken ?? ""))
    }

    @Test("Signing out when nothing is stored reports an empty result")
    func signOutIsIdempotent() async throws {
        let (coordinator, _, _, directory) = try makeCoordinator()
        defer { try? FileManager.default.removeItem(at: directory) }

        let report = try await coordinator.signOut()
        #expect(report.isEmpty)
    }

    @Test("An expired credential with no refresh token is discarded")
    func expiredWithoutRefreshTokenIsRemoved() async throws {
        let clock = TestClock()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-norefresh-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let logger = makeSilentLogger()
        let store = try CredentialStore.make(
            serviceName: "test", directory: directory,
            preferredBackend: .file, logger: logger, now: clock.provider)
        let coordinator = AuthenticationCoordinator(
            provider: MockAuthorizationProvider(logger: logger, now: clock.provider),
            credentialStore: store,
            issuer: URL(string: "https://as.example.com")!,
            logger: logger,
            now: clock.provider)

        try await store.save(
            StoredCredential.make(
                from: TokenSet(
                    accessToken: "a",
                    refreshToken: nil,
                    scopes: Scope.defaults,
                    issuedAt: clock.now,
                    expiresAt: clock.now.addingTimeInterval(60),
                    subject: "sub-1"),
                issuer: URL(string: "https://as.example.com")!,
                now: clock.now))

        clock.advance(by: 120)

        await #expect(throws: CredentialError.self) {
            try await coordinator.currentCredential()
        }
        #expect(try await store.load() == nil, "an unusable credential should not linger")
    }
}

@Suite("Persistent sign-in through the tools")
struct PersistentSessionTests {

    private func makeService(
        directory: URL,
        clock: TestClock = TestClock()
    ) throws -> (service: AuthenticationService, coordinator: AuthenticationCoordinator) {
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(
            subject: "sub-1", logger: logger, now: clock.provider)
        let credentialStore = try CredentialStore.make(
            serviceName: "test", directory: directory,
            preferredBackend: .file, logger: logger, now: clock.provider)
        let coordinator = AuthenticationCoordinator(
            provider: provider,
            credentialStore: credentialStore,
            issuer: URL(string: "https://as.example.com")!,
            logger: logger,
            now: clock.provider)
        let sessionStore = SessionStore(
            provider: provider,
            auditLog: auditLog,
            logger: logger,
            coordinator: coordinator,
            now: clock.provider)
        let service = AuthenticationService(
            provider: provider,
            sessionStore: sessionStore,
            dataStore: InMemoryDataStore(now: clock.provider),
            auditLog: auditLog,
            logger: logger)
        return (service, coordinator)
    }

    @Test("Tools work from a stored credential with no authenticate call")
    func hydratesWithoutAuthenticating() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-hydrate-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        // Stands in for `auth login` in a terminal.
        let (_, coordinator) = try makeService(directory: directory)
        try await coordinator.signIn()

        // A separate service instance stands in for the MCP server process.
        let (service, _) = try makeService(directory: directory)
        let result = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object(["a": .int(1)])],
            owner: .stdio)

        #expect(result.isOK, "the stored credential should have been used automatically")
    }

    @Test("A disconnect does not revoke a persisted sign-in")
    func disconnectKeepsCredential() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-disconnect-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let (service, coordinator) = try makeService(directory: directory)
        try await coordinator.signIn()

        // What the server does when the MCP client goes away.
        await service.releaseOwner(.stdio)

        #expect(
            try await coordinator.currentCredential() != nil,
            "closing a client must not sign the user out")

        let afterwards = try await service.call(
            name: "fetchData", arguments: ["id": .string("doc")], owner: .stdio)
        #expect(afterwards.errorCode == "record_not_found", "still authenticated")
    }

    @Test("revokeAuthentication clears the stored credential for good")
    func revokeClearsPersistedCredential() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-revoke-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let (service, coordinator) = try makeService(directory: directory)
        try await coordinator.signIn()

        let revoked = try await service.call(
            name: "revokeAuthentication", arguments: [:], owner: .stdio)
        #expect(revoked.isOK)

        #expect(try await coordinator.currentCredential() == nil)

        let afterwards = try await service.call(
            name: "fetchData", arguments: ["id": .string("doc")], owner: .stdio)
        #expect(afterwards.errorCode == "not_authenticated")
    }

    @Test("An HTTP session cannot borrow the machine owner's stored credential")
    func httpOwnersDoNotHydrate() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-httpowner-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let (service, coordinator) = try makeService(directory: directory)
        try await coordinator.signIn()

        // The stored credential belongs to whoever runs the binary. Handing it to
        // a remote HTTP client would be a privilege escalation, not a feature.
        let remote = try await service.call(
            name: "fetchData",
            arguments: ["id": .string("doc")],
            owner: SessionOwner("http:some-remote-session"))

        #expect(remote.errorCode == "not_authenticated")
    }

    @Test("Signing in through the tool also persists")
    func toolSignInPersists() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-toolpersist-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let (service, coordinator) = try makeService(directory: directory)
        let result = try await service.call(name: "authenticate", arguments: [:], owner: .stdio)
        #expect(result.isOK)

        // An in-conversation sign-in should survive a restart exactly like a CLI one.
        #expect(try await coordinator.currentCredential() != nil)
    }
}
