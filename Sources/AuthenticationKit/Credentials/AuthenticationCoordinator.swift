import Foundation
import Logging

/// Drives sign-in, silent renewal and sign-out against a persistent store.
///
/// This is the layer that turns the stateless OAuth client into "signed in until
/// I sign out". It is shared by the `auth` subcommands and by the MCP server, so
/// a credential obtained in a terminal is the same one the server serves tools
/// with.
public actor AuthenticationCoordinator {

    private let provider: any AuthorizationProvider
    private let credentialStore: CredentialStore
    private let issuer: URL
    private let defaultScopes: Set<Scope>
    private let auditLog: AuditLog?
    private let logger: Logger
    private let now: @Sendable () -> Date

    public init(
        provider: any AuthorizationProvider,
        credentialStore: CredentialStore,
        issuer: URL,
        defaultScopes: Set<Scope> = Scope.defaults,
        auditLog: AuditLog? = nil,
        logger: Logger,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.provider = provider
        self.credentialStore = credentialStore
        self.issuer = issuer
        self.defaultScopes = defaultScopes
        self.auditLog = auditLog
        self.logger = logger
        self.now = now
    }

    // MARK: - Sign in

    /// What a caller learns while an interactive sign-in is in progress.
    public enum Progress: Sendable {
        /// The user must now do something — open a URL, type a code.
        case awaitingUser(UserInteraction)
        /// Still waiting, after the given number of seconds.
        case stillWaiting(elapsed: TimeInterval)
    }

    /// Runs an interactive sign-in to completion and persists the result.
    ///
    /// Blocks until the user approves, declines, or the request expires — which
    /// is right for a CLI, where a human is watching. The MCP tool path uses the
    /// non-blocking ``AuthenticationService`` flow instead.
    @discardableResult
    public func signIn(
        scopes: Set<Scope>? = nil,
        mode: AuthorizationMode = .automatic,
        timeout: TimeInterval = 300,
        onProgress: @Sendable (Progress) -> Void = { _ in }
    ) async throws -> StoredCredential {
        let requestedScopes = scopes ?? defaultScopes
        let start = try await provider.beginAuthorization(scopes: requestedScopes, mode: mode)

        await auditLog?.record(
            .authenticationStarted,
            detail: ClientContext.annotate(
                ["mode": start.interaction.mode.rawValue, "scopes": requestedScopes.scopeString]))

        onProgress(.awaitingUser(start.interaction))

        let began = now()
        while true {
            let outcome = try await provider.awaitAuthorization(
                handle: start.handle, timeout: 5)

            switch outcome {
            case .completed(let tokens):
                return try await persist(tokens, requestedScopes: requestedScopes)

            case .denied(let reason):
                await auditLog?.record(
                    .authenticationFailed,
                    detail: ClientContext.annotate(["stage": "user", "error": reason ?? "denied"]))
                throw OAuthError.accessDenied(reason: reason)

            case .expired:
                await auditLog?.record(
                    .authenticationFailed, detail: ClientContext.annotate(["stage": "expiry"]))
                throw OAuthError.authorizationExpired

            case .pending:
                let elapsed = now().timeIntervalSince(began)
                guard elapsed < timeout else {
                    await provider.cancelAuthorization(handle: start.handle)
                    throw OAuthError.authorizationExpired
                }
                onProgress(.stillWaiting(elapsed: elapsed))
            }
        }
    }

    /// Persists a token set obtained elsewhere — for instance by the MCP
    /// `authenticate` tool — so an in-conversation sign-in survives a restart
    /// exactly like a `auth login` does.
    @discardableResult
    public func persist(_ tokens: TokenSet) async throws -> StoredCredential {
        try await persist(tokens, requestedScopes: tokens.scopes)
    }

    private func persist(
        _ tokens: TokenSet,
        requestedScopes: Set<Scope>
    ) async throws -> StoredCredential {
        let credential = StoredCredential.make(from: tokens, issuer: issuer, now: now())
        try await credentialStore.save(credential)

        await auditLog?.record(
            .authenticationSucceeded,
            subject: credential.entry.subject,
            detail: ClientContext.annotate([
                "account": credential.account,
                "scopes": credential.entry.scopes.joined(separator: " "),
                "has_refresh_token": String(credential.entry.hasRefreshToken),
            ]))

        if !credential.entry.hasRefreshToken {
            // Worth a loud warning: everything works for about an hour and then
            // silently stops. With Google this means `access_type=offline` was
            // missing, or the user had already consented and `prompt=consent`
            // was not sent, so no new refresh token was issued.
            logger.warning(
                """
                The provider issued no refresh token, so this sign-in will stop working \
                when the access token expires. For Google, send access_type=offline and \
                prompt=consent on the authorization request.
                """)
        }

        let missing = requestedScopes.filter { !$0.isSatisfied(by: tokens.scopes) }
        if !missing.isEmpty {
            logger.warning(
                "The provider granted a narrower scope set than requested",
                metadata: ["withheld": .string(missing.sortedRawValues.joined(separator: " "))])
        }

        return credential
    }

    // MARK: - Silent renewal

    /// The credential to use right now, refreshed if it is close to expiry.
    ///
    /// Returns `nil` when nothing is signed in. Throws only when a credential
    /// exists but cannot be made usable — in which case it has been removed, and
    /// the caller should tell the user to sign in again.
    public func currentCredential(account: String? = nil) async throws -> StoredCredential? {
        guard let stored = try await credentialStore.load(account: account) else { return nil }

        let tokens = stored.tokens
        guard tokens.isExpired(now: now()) || tokens.shouldRefresh(now: now()) else {
            return stored
        }

        guard tokens.refreshToken != nil else {
            guard tokens.isExpired(now: now()) else { return stored }
            try await credentialStore.delete(account: stored.account)
            throw CredentialError.expiredWithoutRefreshToken(account: stored.account)
        }

        do {
            let renewed = try await provider.refresh(tokens)
            let updated = StoredCredential.make(
                from: renewed, issuer: issuer, previous: stored, now: now())
            // Persist immediately: the provider may have rotated the refresh
            // token, and losing the new one locks the user out permanently.
            try await credentialStore.save(updated, makeActive: false)

            await auditLog?.record(
                .authenticationRefreshed,
                subject: updated.entry.subject,
                detail: ClientContext.annotate(["account": updated.account]))

            return updated
        } catch {
            guard tokens.isExpired(now: now()) else {
                // A proactive refresh failed but the current token still works;
                // a transient outage should not break this call.
                logger.warning(
                    "Proactive refresh failed; continuing with the current access token",
                    metadata: ["error": .string(error.localizedDescription)])
                return stored
            }

            try? await credentialStore.delete(account: stored.account)
            await auditLog?.record(
                .authenticationFailed,
                subject: stored.entry.subject,
                detail: ClientContext.annotate(
                    ["stage": "refresh", "error": error.localizedDescription]))
            throw CredentialError.refreshFailed(
                account: stored.account, reason: error.localizedDescription)
        }
    }

    // MARK: - Sign out

    public struct SignOutReport: Sendable {
        public let accounts: [String]
        public let revocation: RevocationReport?

        public var isEmpty: Bool { accounts.isEmpty }
    }

    /// Revokes upstream and removes the credential locally.
    ///
    /// The local credential is removed whatever the provider says — a user who
    /// asked to sign out must end up signed out even when the network is down.
    @discardableResult
    public func signOut(account: String? = nil, allAccounts: Bool = false) async throws
        -> SignOutReport
    {
        // `??` takes an autoclosure, which cannot contain an `await`, so the
        // fallback is resolved explicitly.
        let requestedAccount: String?
        if let account {
            requestedAccount = account
        } else {
            requestedAccount = try await credentialStore.activeAccount()
        }

        let targets: [String]
        if allAccounts {
            targets = try await credentialStore.accounts().map(\.account)
        } else if let requestedAccount {
            targets = [requestedAccount]
        } else {
            targets = []
        }

        guard !targets.isEmpty else {
            return SignOutReport(accounts: [], revocation: nil)
        }

        var lastReport: RevocationReport?
        for target in targets {
            if let stored = try? await credentialStore.load(account: target) {
                lastReport = await provider.revoke(stored.tokens)
                await auditLog?.record(
                    lastReport?.isCompleteUpstream == true
                        ? .revocationSucceeded : .revocationFailed,
                    subject: stored.entry.subject,
                    detail: ClientContext.annotate(["account": target]))
            }
            try await credentialStore.delete(account: target)
        }

        return SignOutReport(accounts: targets, revocation: lastReport)
    }

    // MARK: - Status

    public func accounts() async throws -> [CredentialIndexEntry] {
        try await credentialStore.accounts()
    }

    public func activeAccount() async throws -> String? {
        try await credentialStore.activeAccount()
    }

    public func storageDescription() async -> String {
        await credentialStore.describedLocation
    }
}

/// Failures specific to persisted credentials.
public enum CredentialError: Error, Sendable, Equatable, LocalizedError {
    case notSignedIn
    case refreshFailed(account: String, reason: String)
    case expiredWithoutRefreshToken(account: String)

    public var errorDescription: String? {
        switch self {
        case .notSignedIn:
            return "Not signed in."
        case .refreshFailed(let account, let reason):
            return
                "The stored credential for '\(account)' could not be renewed (\(reason)). "
                + "It has been removed; sign in again."
        case .expiredWithoutRefreshToken(let account):
            return
                "The credential for '\(account)' expired and no refresh token was stored, "
                + "so it could not be renewed. Sign in again."
        }
    }
}
