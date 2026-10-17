import Foundation
import Logging
import MCP

/// The implementation behind the four tools.
///
/// Transport-agnostic and MCP-agnostic apart from its `CallTool.Result` return
/// type: ``AuthenticationMCPServer`` adapts it to the protocol, and the tests
/// drive it directly. Every dependency — authorization provider, data store,
/// clock — is injected, so nothing here reaches for a global.
public actor AuthenticationService {

    private let provider: any AuthorizationProvider
    private let sessionStore: SessionStore
    private let dataStore: any DataStore
    private let rateLimiter: RateLimiter
    private let auditLog: AuditLog
    private let logger: Logger
    private let defaultScopes: Set<Scope>
    private let scopePolicy: ScopePolicy

    public init(
        provider: any AuthorizationProvider,
        sessionStore: SessionStore,
        dataStore: any DataStore,
        rateLimiter: RateLimiter = RateLimiter(),
        auditLog: AuditLog,
        logger: Logger,
        defaultScopes: Set<Scope> = Scope.defaults,
        scopePolicy: ScopePolicy = .default
    ) {
        self.provider = provider
        self.sessionStore = sessionStore
        self.dataStore = dataStore
        self.rateLimiter = rateLimiter
        self.auditLog = auditLog
        self.logger = logger
        self.defaultScopes = defaultScopes
        self.scopePolicy = scopePolicy
    }

    /// Dispatches a tool call, converting any thrown error into an `isError` result.
    ///
    /// - Throws: ``MCPError/methodNotFound(_:)`` only, for an unknown tool name.
    ///   Everything else comes back as a result the model can read and act on.
    public func call(
        name: String,
        arguments: [String: Value]?,
        owner: SessionOwner
    ) async throws -> CallTool.Result {
        do {
            switch name {
            case ToolCatalog.Name.authenticate:
                return try await authenticate(ToolArguments(arguments, toolName: name), owner: owner)
            case ToolCatalog.Name.revokeAuthentication:
                return try await revokeAuthentication(
                    ToolArguments(arguments, toolName: name), owner: owner)
            case ToolCatalog.Name.fetchData:
                return try await fetchData(ToolArguments(arguments, toolName: name), owner: owner)
            case ToolCatalog.Name.updatedData:
                return try await updatedData(ToolArguments(arguments, toolName: name), owner: owner)
            default:
                throw MCPError.methodNotFound("No tool named '\(name)'")
            }
        } catch let error as MCPError {
            throw error
        } catch {
            var failure = ToolFailure.from(error)

            // Point at the right fix. When credentials persist, signing in from a
            // terminal is the durable path; the in-conversation tool is the
            // fallback, not the other way round.
            if failure.code == .notAuthenticated,
                await sessionStore.hasPersistentCredentials(for: owner)
            {
                failure = ToolFailure(
                    code: failure.code,
                    message: failure.message,
                    remediation:
                        "Tell the user to run `authentication-mcp auth login` in a terminal — "
                        + "that sign-in persists until they run `auth logout`. Alternatively "
                        + "call `authenticate` to sign in from here.",
                    isRetryable: failure.isRetryable,
                    details: failure.details)
            }

            if failure.code == .internalFailure {
                // The model gets a generic message; the detail goes to the operator.
                logger.error(
                    "Unhandled error in tool call",
                    metadata: [
                        "tool": .string(name),
                        "error": .string(String(describing: error)),
                    ])
            }
            return failure.callToolResult
        }
    }

    // MARK: - authenticate

    private static let authenticateParameters: Set<String> = [
        "scopes", "mode", "flow_id", "wait_seconds", "force",
    ]

    private func authenticate(
        _ arguments: ToolArguments,
        owner: SessionOwner
    ) async throws -> CallTool.Result {
        try arguments.rejectUnknownParameters(allowed: Self.authenticateParameters)

        try await enforceRateLimit(owner: owner, limit: .poll, tool: "authenticate.check")

        let requestedScopes = try arguments.optionalStringArray("scopes")
            .map { Set($0.map(Scope.init)) } ?? defaultScopes
        let mode = try arguments.optionalEnum("mode", as: AuthorizationMode.self, default: .automatic)
        let explicitFlowID = try arguments.optionalString("flow_id")
        let waitSeconds = try arguments.clampedInt(
            "wait_seconds", default: 30, minimum: 0, maximum: 120)
        let force = try arguments.optionalBool("force", default: false)

        // Reusing a live session is the common case and must stay cheap: a model
        // that calls `authenticate` before every read should not trigger a new
        // sign-in each time.
        if !force, explicitFlowID == nil,
            let existing = try? await sessionStore.resolveSession(
                sessionID: nil, owner: owner, requiredScope: nil),
            requestedScopes.allSatisfy({ $0.isSatisfied(by: existing.scopes) })
        {
            return ToolResponse.success(
                .object([
                    "status": .string("authenticated"),
                    "session": existing.snapshot,
                ]),
                summary: "Already signed in as \(existing.principalName ?? existing.subject).")
        }

        // Resume an in-flight authorization rather than starting a second one:
        // starting over would invalidate the code the user is currently looking at.
        let resumableHandle: String?
        if let explicitFlowID {
            resumableHandle = explicitFlowID
        } else if force {
            resumableHandle = nil
        } else {
            resumableHandle = await sessionStore.pendingHandle(for: owner)
        }

        let handle: String
        let startedInteraction: UserInteraction?
        if let resumableHandle {
            handle = resumableHandle
            startedInteraction = nil
        } else {
            if force, let stale = await sessionStore.pendingHandle(for: owner) {
                await provider.cancelAuthorization(handle: stale)
                await sessionStore.clearPendingHandle(for: owner)
            }
            // Only starting a flow is rate-limited: it is the call that reaches the
            // authorization server's device or authorize endpoint and creates new
            // pending state. Resuming a flow with its `flow_id` is not charged —
            // the provider already paces its token-endpoint polls to the server's
            // `interval` and `slow_down`, and over HTTP the device grant is the only
            // way to sign in, so a client polling every few seconds while a person
            // types a code on their phone is the normal case, not abuse.
            try await enforceRateLimit(owner: owner, limit: .authentication, tool: "authenticate")
            let start = try await provider.beginAuthorization(scopes: requestedScopes, mode: mode)
            await sessionStore.recordPendingHandle(start.handle, for: owner)
            await auditLog.record(
                .authenticationStarted,
                detail: ClientContext.annotate([
                    "owner": owner.rawValue,
                    "mode": start.interaction.mode.rawValue,
                    "scopes": requestedScopes.scopeString,
                ]))
            handle = start.handle
            startedInteraction = start.interaction
        }

        let outcome: AuthorizationOutcome
        do {
            outcome = try await provider.awaitAuthorization(
                handle: handle, timeout: TimeInterval(waitSeconds))
        } catch let error as OAuthError {
            await sessionStore.clearPendingHandle(for: owner)
            await auditLog.record(
                .authenticationFailed,
                detail: ClientContext.annotate(["stage": "await", "error": error.localizedDescription]))
            // An explicitly supplied handle that no longer exists is worth
            // distinguishing from a generic failure, so the model retries correctly.
            throw error
        }

        switch outcome {
        case .completed(let tokens):
            await sessionStore.clearPendingHandle(for: owner)

            let missing = requestedScopes.filter { !$0.isSatisfied(by: tokens.scopes) }
            let session = await sessionStore.createSession(owner: owner, tokens: tokens)

            var payload: [String: Value] = [
                "status": .string("authenticated"),
                "session": session.snapshot,
            ]
            // A narrowed grant is legal (RFC 6749 §3.3) but changes what the other
            // tools can do, so it is surfaced rather than discovered later.
            if !missing.isEmpty {
                payload["scope_warning"] = .string(
                    "The provider granted a narrower scope set than requested; "
                        + "[\(missing.sortedRawValues.joined(separator: ", "))] was withheld.")
            }

            return ToolResponse.success(
                .object(payload),
                summary: "Signed in as \(session.principalName ?? session.subject).")

        case .pending(let interaction):
            return ToolResponse.success(
                .object(compacting: [
                    ("status", .string("pending")),
                    ("flow_id", .string(handle)),
                    ("user_code", interaction.userCode.map(Value.string)),
                    ("verification_url", .string(interaction.verificationURL.absoluteString)),
                    (
                        "verification_url_complete",
                        interaction.verificationURLComplete.map { .string($0.absoluteString) }
                    ),
                    ("expires_at", .string(Timestamps.string(from: interaction.expiresAt))),
                    ("instructions", .string(interaction.instructions)),
                ]),
                summary: pendingSummary(interaction, startedNow: startedInteraction != nil))

        case .denied(let reason):
            await sessionStore.clearPendingHandle(for: owner)
            await auditLog.record(
                .authenticationFailed,
                detail: ClientContext.annotate(["stage": "user", "error": reason ?? "denied"]))
            throw OAuthError.accessDenied(reason: reason)

        case .expired:
            await sessionStore.clearPendingHandle(for: owner)
            await auditLog.record(
                .authenticationFailed, detail: ClientContext.annotate(["stage": "expiry"]))
            throw OAuthError.authorizationExpired
        }
    }

    private func pendingSummary(_ interaction: UserInteraction, startedNow: Bool) -> String {
        let lead = startedNow ? "Sign-in started." : "Still waiting for the user."
        if let code = interaction.userCode {
            let url = (interaction.verificationURLComplete ?? interaction.verificationURL)
                .absoluteString
            return "\(lead) Ask the user to open \(url) and enter the code \(code)."
        }
        return "\(lead) \(interaction.instructions)"
    }

    // MARK: - revokeAuthentication

    private static let revokeParameters: Set<String> = ["session_id", "all_sessions"]

    private func revokeAuthentication(
        _ arguments: ToolArguments,
        owner: SessionOwner
    ) async throws -> CallTool.Result {
        try arguments.rejectUnknownParameters(allowed: Self.revokeParameters)
        try await enforceRateLimit(owner: owner, limit: .authentication, tool: "revokeAuthentication")

        let explicitSessionID = try arguments.optionalString("session_id")
        let allSessions = try arguments.optionalBool("all_sessions", default: false)

        // Cancel any half-finished sign-in too; otherwise a pending flow could
        // complete after the user believed they had signed out.
        if let pending = await sessionStore.pendingHandle(for: owner) {
            await provider.cancelAuthorization(handle: pending)
            await sessionStore.clearPendingHandle(for: owner)
        }

        let targets: [AuthSession]
        if allSessions {
            targets = await sessionStore.sessions(ownedBy: owner)
        } else if let session = try? await sessionStore.peek(
            sessionID: explicitSessionID, owner: owner)
        {
            targets = [session]
        } else {
            targets = []
        }

        // No live session may still mean a stored credential — one created by
        // `auth login` in a terminal and not yet used in this process. A sign-out
        // has to reach that too, or the user stays signed in after being told
        // there was nothing to revoke.
        if targets.isEmpty, explicitSessionID == nil {
            let stored = await sessionStore.signOutStoredCredential(owner: owner)
            guard !stored.accounts.isEmpty else {
                // Genuinely nothing to do. Idempotent success, not an error:
                // reporting a failure would push a model into a retry loop over a
                // sign-out that has already happened.
                return ToolResponse.success(
                    .object([
                        "revoked_session_ids": .array([]),
                        "upstream_complete": .bool(true),
                    ]),
                    summary: "There was no active session to revoke.")
            }

            let complete = stored.report?.isCompleteUpstream ?? true
            return ToolResponse.success(
                .object(compacting: [
                    ("revoked_session_ids", .array([])),
                    ("revoked_accounts", .array(stored.accounts.map(Value.string))),
                    ("upstream_complete", .bool(complete)),
                    ("warning", stored.report?.failureReason.map(Value.string)),
                ]),
                summary:
                    "Signed out \(stored.accounts.joined(separator: ", ")) and removed the "
                    + "stored credential.")
        }

        var revokedIDs: [Value] = []
        var accessResult = RevocationReport.Result.notPresent
        var refreshResult = RevocationReport.Result.notPresent
        var warnings: [String] = []
        var upstreamComplete = true

        for session in targets {
            let report = await sessionStore.revokeAndDestroy(session)
            revokedIDs.append(.string(session.id))
            accessResult = Self.combine(accessResult, report.accessToken)
            refreshResult = Self.combine(refreshResult, report.refreshToken)
            if !report.isCompleteUpstream {
                upstreamComplete = false
                if let reason = report.failureReason { warnings.append(reason) }
            }
        }

        let summary: String
        if revokedIDs.isEmpty {
            summary = "There was no active session to revoke."
        } else if upstreamComplete {
            summary = "Revoked \(revokedIDs.count) session(s); the provider confirmed it."
        } else {
            summary =
                "Destroyed \(revokedIDs.count) local session(s), but the provider did not "
                + "confirm revocation — the tokens may stay valid upstream until they expire."
        }

        return ToolResponse.success(
            .object(compacting: [
                ("revoked_session_ids", .array(revokedIDs)),
                ("access_token", .string(accessResult.rawValue)),
                ("refresh_token", .string(refreshResult.rawValue)),
                ("upstream_complete", .bool(upstreamComplete)),
                (
                    "warning",
                    warnings.isEmpty ? nil : .string(Set(warnings).sorted().joined(separator: "; "))
                ),
            ]),
            summary: summary)
    }

    /// Folds several revocation results into one, keeping the worst outcome.
    private static func combine(
        _ lhs: RevocationReport.Result,
        _ rhs: RevocationReport.Result
    ) -> RevocationReport.Result {
        let severity: [RevocationReport.Result: Int] = [
            .notPresent: 0, .revoked: 1, .unsupported: 2, .failed: 3,
        ]
        return (severity[lhs] ?? 0) >= (severity[rhs] ?? 0) ? lhs : rhs
    }

    // MARK: - fetchData

    private static let fetchParameters: Set<String> = [
        "id", "ID", "session_id", "include_metadata",
    ]

    private func fetchData(
        _ arguments: ToolArguments,
        owner: SessionOwner
    ) async throws -> CallTool.Result {
        try arguments.rejectUnknownParameters(allowed: Self.fetchParameters)
        try await enforceRateLimit(owner: owner, limit: .read, tool: "fetchData")

        let id = try arguments.requiredString(
            "id", aliases: ["ID"], maxLength: DataStoreLimits.maximumIdentifierLength)
        let sessionID = try arguments.optionalString("session_id")
        let includeMetadata = try arguments.optionalBool("include_metadata", default: true)

        let session = try await sessionStore.resolveSession(
            sessionID: sessionID, owner: owner, requiredScope: scopePolicy.read)

        let record = try await dataStore.fetch(id: id, owner: session.subject)

        await auditLog.record(
            .dataRead,
            subject: session.subject,
            sessionID: session.id,
            detail: ClientContext.annotate(["id": id, "version": String(record.version)]))

        return ToolResponse.success(
            .object(compacting: [
                ("id", .string(record.id)),
                ("value", record.value),
                ("metadata", includeMetadata ? record.metadata : nil),
            ]),
            summary: "Read '\(record.id)' at version \(record.version).")
    }

    // MARK: - updatedData

    private static let updateParameters: Set<String> = [
        "id", "ID", "value", "Value", "session_id", "expected_version", "merge",
    ]

    private func updatedData(
        _ arguments: ToolArguments,
        owner: SessionOwner
    ) async throws -> CallTool.Result {
        try arguments.rejectUnknownParameters(allowed: Self.updateParameters)
        try await enforceRateLimit(owner: owner, limit: .write, tool: "updatedData")

        let id = try arguments.requiredString(
            "id", aliases: ["ID"], maxLength: DataStoreLimits.maximumIdentifierLength)
        let value = try arguments.requiredObject("value", aliases: ["Value"])
        let sessionID = try arguments.optionalString("session_id")
        let expectedVersion = try arguments.optionalInt("expected_version", minimum: 0)
        let merge = try arguments.optionalBool("merge", default: false)

        let session = try await sessionStore.resolveSession(
            sessionID: sessionID, owner: owner, requiredScope: scopePolicy.write)

        let result = try await dataStore.upsert(
            id: id,
            value: value,
            owner: session.subject,
            expectedVersion: expectedVersion,
            merge: merge)

        await auditLog.record(
            .dataWritten,
            subject: session.subject,
            sessionID: session.id,
            detail: ClientContext.annotate([
                "id": id,
                "version": String(result.record.version),
                "created": String(result.didCreate),
                "merge": String(merge),
                "guarded": String(expectedVersion != nil),
            ]))

        let action = result.didCreate ? "Created" : "Updated"
        return ToolResponse.success(
            .object(compacting: [
                ("id", .string(result.record.id)),
                ("version", .int(result.record.version)),
                ("previous_version", result.previousVersion.map(Value.int)),
                ("created", .bool(result.didCreate)),
                ("etag", .string(result.record.etag)),
                ("updated_at", .string(Timestamps.string(from: result.record.updatedAt))),
                ("value", result.record.value),
            ]),
            summary: "\(action) '\(result.record.id)' at version \(result.record.version).")
    }

    // MARK: - Shared

    private func enforceRateLimit(
        owner: SessionOwner,
        limit: RateLimiter.Limit,
        tool: String
    ) async throws {
        let decision = await rateLimiter.consume(key: "\(owner.rawValue):\(tool)", limit: limit)
        guard !decision.isAllowed else { return }

        await auditLog.record(
            .rateLimited,
            detail: ClientContext.annotate(["tool": tool, "owner": owner.rawValue]))
        throw ToolFailure(
            code: .rateLimited,
            message: "Too many `\(tool)` calls.",
            remediation: "Wait \(Int(decision.retryAfter)) seconds before trying again.",
            isRetryable: true,
            details: ["retry_after_seconds": .int(Int(decision.retryAfter))])
    }

    /// Releases what a connection held. Called when a transport closes.
    ///
    /// With persistent credentials this drops in-memory state only: the user
    /// signed in deliberately and expects to stay signed in, so closing a client
    /// must not revoke their tokens. Without persistence there is nowhere to keep
    /// them, and holding live tokens in a process nobody is talking to has no
    /// upside — so they are revoked.
    public func releaseOwner(_ owner: SessionOwner) async {
        if await sessionStore.hasPersistentCredentials(for: owner) {
            await sessionStore.releaseSessions(ownedBy: owner)
        } else {
            await sessionStore.destroyAll(ownedBy: owner)
        }
    }

    /// Periodic housekeeping: idle sessions and stale rate-limit buckets.
    public func performMaintenance() async {
        await sessionStore.expireIdleSessions()
        await rateLimiter.evictIdleBuckets()
    }
}
