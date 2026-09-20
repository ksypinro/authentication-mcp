import Foundation
import Logging

/// Holds live sessions and the in-flight authorizations that will become them.
///
/// The store is the only place token material lives. It is an actor, so the
/// refresh-on-read path cannot race: two concurrent `fetchData` calls on an
/// expiring session serialise here and only one refresh reaches the provider.
public actor SessionStore {

    private let provider: any AuthorizationProvider
    private let auditLog: AuditLog
    private let logger: Logger
    private let idleTimeout: TimeInterval
    private let now: @Sendable () -> Date

    /// Persistent credential storage, when sign-in should survive restarts.
    private let coordinator: AuthenticationCoordinator?
    /// The one connection allowed to use the persisted credential.
    ///
    /// The stored credential belongs to whoever runs this binary, so it may only
    /// serve the local process — `SessionOwner.stdio`. Letting an HTTP session
    /// hydrate from it would hand every remote client the machine owner's
    /// identity, which is a privilege escalation, not a convenience.
    private let persistenceOwner: SessionOwner

    private var sessions: [String: AuthSession] = [:]
    /// The session a caller gets when it does not name one.
    private var activeSessionIDs: [SessionOwner: String] = [:]
    /// Authorizations started but not yet approved, so `authenticate` can resume
    /// the caller's own flow without being handed a handle back.
    private var pendingHandles: [SessionOwner: String] = [:]
    /// Guards against one connection holding an unbounded number of sessions.
    private let maxSessionsPerOwner: Int

    public init(
        provider: any AuthorizationProvider,
        auditLog: AuditLog,
        logger: Logger,
        idleTimeout: TimeInterval = 86_400,
        maxSessionsPerOwner: Int = 8,
        coordinator: AuthenticationCoordinator? = nil,
        persistenceOwner: SessionOwner = .stdio,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.provider = provider
        self.auditLog = auditLog
        self.logger = logger
        self.idleTimeout = idleTimeout
        self.maxSessionsPerOwner = maxSessionsPerOwner
        self.coordinator = coordinator
        self.persistenceOwner = persistenceOwner
        self.now = now
    }

    /// Whether this owner's sign-in is backed by the persistent credential store.
    public func hasPersistentCredentials(for owner: SessionOwner) -> Bool {
        coordinator != nil && owner == persistenceOwner
    }

    // MARK: - Creating sessions

    /// Registers a freshly issued token set as a session owned by `owner`.
    public func createSession(owner: SessionOwner, tokens: TokenSet) async -> AuthSession {
        let session = AuthSession(
            id: Self.makeSessionID(),
            owner: owner,
            tokens: tokens,
            createdAt: now(),
            lastUsedAt: now(),
            providerDescription: provider.providerDescription)

        sessions[session.id] = session
        activeSessionIDs[owner] = session.id
        pendingHandles[owner] = nil

        evictExcessSessions(for: owner)

        // A sign-in that happened through the MCP tool should persist too, so the
        // user does not have to repeat it on the next run.
        if let coordinator, owner == persistenceOwner {
            do {
                try await coordinator.persist(tokens)
            } catch {
                // The session is live either way; failing to persist costs the
                // user a re-login later, not this call.
                logger.warning(
                    "Could not persist the credential; this sign-in will not survive a restart",
                    metadata: ["error": .string(error.localizedDescription)])
            }
        }

        await auditLog.record(
            .authenticationSucceeded,
            subject: session.subject,
            sessionID: session.id,
            detail: ClientContext.annotate([
                "owner": owner.rawValue,
                "scopes": session.scopes.scopeString,
                "provider": provider.providerDescription,
            ]))

        return session
    }

    // MARK: - Pending authorizations

    public func recordPendingHandle(_ handle: String, for owner: SessionOwner) {
        pendingHandles[owner] = handle
    }

    public func pendingHandle(for owner: SessionOwner) -> String? {
        pendingHandles[owner]
    }

    public func clearPendingHandle(for owner: SessionOwner) {
        pendingHandles[owner] = nil
    }

    // MARK: - Reading sessions

    /// The session a caller should use, refreshing it if it is close to expiry.
    ///
    /// - Parameters:
    ///   - sessionID: an explicit session, or `nil` for the connection's active one.
    ///   - owner: the connection making the call. Sessions owned by anyone else
    ///     are reported as ``SessionError/notFound(sessionID:)``.
    ///   - requiredScope: checked after the session resolves, so an expired
    ///     session reports expiry rather than a misleading scope error.
    public func resolveSession(
        sessionID: String?,
        owner: SessionOwner,
        requiredScope: Scope?
    ) async throws -> AuthSession {
        let usable: AuthSession
        if sessionID == nil, let persisted = try await persistedSession(owner: owner) {
            usable = persisted
        } else {
            usable = try await refreshIfNeeded(locate(sessionID: sessionID, owner: owner))
        }

        if let requiredScope, !requiredScope.isSatisfied(by: usable.scopes) {
            await auditLog.record(
                .authorizationDenied,
                subject: usable.subject,
                sessionID: usable.id,
                detail: ClientContext.annotate([
                    "required_scope": requiredScope.rawValue,
                    "granted_scopes": usable.scopes.scopeString,
                ]))
            throw SessionError.insufficientScope(
                required: requiredScope, granted: usable.scopes.sortedRawValues)
        }

        touch(usable.id)
        return usable
    }

    /// Looks up a session without refreshing it. Used by `revokeAuthentication`,
    /// which has no reason to renew credentials it is about to destroy.
    public func peek(sessionID: String?, owner: SessionOwner) throws -> AuthSession {
        try locate(sessionID: sessionID, owner: owner)
    }

    public func sessions(ownedBy owner: SessionOwner) -> [AuthSession] {
        sessions.values
            .filter { $0.owner == owner }
            .sorted { $0.createdAt < $1.createdAt }
    }

    public func activeSessionID(for owner: SessionOwner) -> String? {
        activeSessionIDs[owner]
    }

    private func locate(sessionID: String?, owner: SessionOwner) throws -> AuthSession {
        if let sessionID {
            // An id that exists but is owned elsewhere reports `notFound`, the
            // same as an id that never existed: a caller must not be able to
            // discover another connection's session ids by probing.
            guard let session = sessions[sessionID], session.owner == owner else {
                throw SessionError.notFound(sessionID: sessionID)
            }
            return session
        }

        if let activeID = activeSessionIDs[owner], let session = sessions[activeID] {
            return session
        }

        let owned = sessions(ownedBy: owner)
        switch owned.count {
        case 0: throw SessionError.notAuthenticated
        case 1: return owned[0]
        default: throw SessionError.ambiguous(sessionIDs: owned.map(\.id))
        }
    }

    // MARK: - Persistent credentials

    /// The session backed by the stored credential, refreshed if needed.
    ///
    /// Returns `nil` when this owner has no persistent storage, or nothing is
    /// signed in — both ordinary states that fall through to the in-memory path.
    private func persistedSession(owner: SessionOwner) async throws -> AuthSession? {
        guard let coordinator, owner == persistenceOwner else { return nil }

        // Serve from memory while the access token is comfortably valid. Without
        // this every tool call would hit the keychain, which is slow and on macOS
        // can prompt the user.
        if let activeID = activeSessionIDs[owner], let session = sessions[activeID],
            !session.tokens.isExpired(now: now()), !session.tokens.shouldRefresh(now: now())
        {
            return session
        }

        guard let credential = try await coordinator.currentCredential() else { return nil }

        if let activeID = activeSessionIDs[owner], var session = sessions[activeID],
            session.tokens.subject == credential.entry.subject
        {
            // Same principal: keep the session id stable across a token refresh
            // so a caller holding one does not see it disappear.
            session.tokens = credential.tokens
            session.lastUsedAt = now()
            sessions[activeID] = session
            return session
        }

        let session = AuthSession(
            id: Self.makeSessionID(),
            owner: owner,
            tokens: credential.tokens,
            createdAt: credential.entry.obtainedAt,
            lastUsedAt: now(),
            providerDescription: provider.providerDescription)
        sessions[session.id] = session
        activeSessionIDs[owner] = session.id
        evictExcessSessions(for: owner)

        logger.debug(
            "Restored session from the stored credential",
            metadata: ["account": .string(credential.account)])
        return session
    }

    /// Revokes and removes the stored credential, if there is one.
    ///
    /// Needed because a credential created by `auth login` in a terminal has no
    /// in-memory session until a tool call hydrates one. Without this, asking the
    /// assistant to sign out would report "nothing to revoke" and leave the
    /// credential on disk — the opposite of what the user asked for.
    ///
    /// Does not refresh on the way: renewing a token in order to revoke it would
    /// turn a provider outage into an inability to sign out.
    public func signOutStoredCredential(
        owner: SessionOwner
    ) async -> (accounts: [String], report: RevocationReport?) {
        guard let coordinator, owner == persistenceOwner else { return ([], nil) }
        guard let result = try? await coordinator.signOut() else { return ([], nil) }
        return (result.accounts, result.revocation)
    }

    /// Drops an owner's in-memory sessions without revoking anything.
    ///
    /// This is what a disconnect should do once credentials are persistent: the
    /// user signed in deliberately and expects to stay signed in, so closing a
    /// client must not throw their credential away. Explicit sign-out still goes
    /// through ``revokeAndDestroy(_:)``.
    public func releaseSessions(ownedBy owner: SessionOwner) async {
        for session in sessions(ownedBy: owner) {
            sessions.removeValue(forKey: session.id)
        }
        activeSessionIDs[owner] = nil
        if let handle = pendingHandles.removeValue(forKey: owner) {
            await provider.cancelAuthorization(handle: handle)
        }
    }

    // MARK: - Refresh

    /// Refreshes a session's tokens when they are expiring, or have expired.
    ///
    /// Refresh failures on a still-valid token are swallowed deliberately: a
    /// transient authorization-server outage should not break a call that the
    /// current token can still serve.
    private func refreshIfNeeded(_ session: AuthSession) async throws -> AuthSession {
        let isExpired = session.tokens.isExpired(now: now())
        guard isExpired || session.tokens.shouldRefresh(now: now()) else { return session }

        guard session.tokens.refreshToken != nil else {
            guard isExpired else { return session }
            destroy(sessionID: session.id)
            throw SessionError.expired(
                sessionID: session.id, underlying: "no refresh token was issued")
        }

        do {
            let renewed = try await provider.refresh(session.tokens)
            var updated = session
            updated.tokens = renewed
            updated.lastUsedAt = now()
            sessions[session.id] = updated

            await auditLog.record(
                .authenticationRefreshed,
                subject: updated.subject,
                sessionID: updated.id,
                detail: ClientContext.annotate(
                    ["expires_at": renewed.expiresAt.map(Timestamps.string(from:)) ?? "never"]))

            return updated
        } catch {
            guard isExpired else {
                logger.warning(
                    "Proactive token refresh failed; continuing with the current token",
                    metadata: [
                        "session": .string(session.id),
                        "error": .string(error.localizedDescription),
                    ])
                return session
            }

            destroy(sessionID: session.id)
            await auditLog.record(
                .authenticationFailed,
                subject: session.subject,
                sessionID: session.id,
                detail: ClientContext.annotate(
                    ["stage": "refresh", "error": error.localizedDescription]))
            throw SessionError.expired(
                sessionID: session.id, underlying: error.localizedDescription)
        }
    }

    // MARK: - Destroying sessions

    /// Revokes a session's credentials upstream and removes it locally.
    ///
    /// The local session is destroyed whatever the authorization server says, so
    /// this process stops holding credentials even when the server is unreachable.
    public func revokeAndDestroy(_ session: AuthSession) async -> RevocationReport {
        let report: RevocationReport
        if let coordinator, session.owner == persistenceOwner {
            // Route through the coordinator so the stored credential is removed
            // as well; otherwise the next run would silently sign back in.
            let signOut = try? await coordinator.signOut()
            report =
                signOut?.revocation
                ?? RevocationReport(accessToken: .notPresent, refreshToken: .notPresent)
        } else {
            report = await provider.revoke(session.tokens)
        }
        destroy(sessionID: session.id)

        await auditLog.record(
            report.isCompleteUpstream ? .revocationSucceeded : .revocationFailed,
            subject: session.subject,
            sessionID: session.id,
            detail: ClientContext.annotate(
                [
                    "access_token": report.accessToken.rawValue,
                    "refresh_token": report.refreshToken.rawValue,
                    "reason": report.failureReason ?? "",
                ].filter { !$0.value.isEmpty }))

        return report
    }

    /// Drops a session without contacting the authorization server.
    public func destroy(sessionID: String) {
        guard let removed = sessions.removeValue(forKey: sessionID) else { return }
        if activeSessionIDs[removed.owner] == sessionID {
            activeSessionIDs[removed.owner] = sessions(ownedBy: removed.owner).last?.id
        }
    }

    /// Revokes and removes everything owned by one connection. Called on disconnect.
    @discardableResult
    public func destroyAll(ownedBy owner: SessionOwner) async -> [RevocationReport] {
        let owned = sessions(ownedBy: owner)
        var reports: [RevocationReport] = []
        for session in owned {
            reports.append(await revokeAndDestroy(session))
        }
        activeSessionIDs[owner] = nil
        if let handle = pendingHandles.removeValue(forKey: owner) {
            await provider.cancelAuthorization(handle: handle)
        }
        return reports
    }

    private func touch(_ sessionID: String) {
        sessions[sessionID]?.lastUsedAt = now()
    }

    /// Keeps a single connection from accumulating sessions without bound by
    /// dropping the least recently used ones.
    private func evictExcessSessions(for owner: SessionOwner) {
        let owned = sessions(ownedBy: owner).sorted { $0.lastUsedAt < $1.lastUsedAt }
        guard owned.count > maxSessionsPerOwner else { return }
        for session in owned.prefix(owned.count - maxSessionsPerOwner) {
            logger.info(
                "Evicting least recently used session",
                metadata: ["session": .string(session.id), "owner": .string(owner.rawValue)])
            destroy(sessionID: session.id)
        }
    }

    /// Drops sessions untouched for longer than the idle timeout.
    public func expireIdleSessions() async {
        let cutoff = now().addingTimeInterval(-idleTimeout)
        for session in sessions.values where session.lastUsedAt < cutoff {
            logger.info("Expiring idle session", metadata: ["session": .string(session.id)])
            destroy(sessionID: session.id)
        }
    }

    public var sessionCount: Int { sessions.count }

    private static func makeSessionID() -> String {
        var generator = SystemRandomNumberGenerator()
        var bytes = [UInt8](repeating: 0, count: 16)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: 0...255, using: &generator)
        }
        return "sess_" + Data(bytes).base64URLEncodedStringWithoutPadding()
    }
}
