import Foundation
import MCP
import Testing

@testable import AuthenticationKit

@Suite("Tools")
struct ToolTests {

    private let owner = SessionOwner("test")

    // MARK: - Catalog

    @Test("All four tools are published with schemas")
    func catalogShape() {
        let tools = ToolCatalog.allTools
        #expect(tools.map(\.name) == [
            "authenticate", "revokeAuthentication", "fetchData", "updatedData",
        ])
        for tool in tools {
            #expect(tool.description?.isEmpty == false, "\(tool.name) needs a description")
            #expect(tool.inputSchema.objectValue?["type"]?.stringValue == "object", "\(tool.name)")
            #expect(tool.outputSchema != nil, "\(tool.name) should declare an output schema")
        }
    }

    @Test("Required parameters match the documented API")
    func requiredParameters() throws {
        func required(_ tool: Tool) -> [String] {
            (tool.inputSchema.objectValue?["required"]?.arrayValue ?? [])
                .compactMap(\.stringValue)
        }
        #expect(required(ToolCatalog.authenticate).isEmpty)
        #expect(required(ToolCatalog.revokeAuthentication).isEmpty)
        #expect(required(ToolCatalog.fetchData) == ["id"])
        #expect(Set(required(ToolCatalog.updatedData)) == ["id", "value"])
    }

    @Test("Read and write tools carry accurate behaviour hints")
    func annotations() {
        #expect(ToolCatalog.fetchData.annotations.readOnlyHint == true)
        #expect(ToolCatalog.updatedData.annotations.readOnlyHint == false)
        // Repeating a bare write is not safe, so it must not claim idempotency.
        #expect(ToolCatalog.updatedData.annotations.idempotentHint == false)
        #expect(ToolCatalog.revokeAuthentication.annotations.idempotentHint == true)
    }

    // MARK: - Authentication gate

    @Test("Data tools refuse to run before authentication", arguments: ["fetchData", "updatedData"])
    func requiresAuthentication(_ toolName: String) async throws {
        let (service, _, _, _) = makeTestService()
        let arguments: [String: Value] =
            toolName == "fetchData"
            ? ["id": .string("doc")]
            : ["id": .string("doc"), "value": .object(["a": .int(1)])]

        let result = try await service.call(name: toolName, arguments: arguments, owner: owner)

        #expect(result.isError == true)
        #expect(result.errorCode == "not_authenticated")
    }

    @Test("Authenticating returns a session id but never a token")
    func authenticateReturnsNoTokens() async throws {
        let (service, _, _, _) = makeTestService()

        let result = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        #expect(result.isOK)
        #expect(result.structured["status"]?.stringValue == "authenticated")
        #expect(result.sessionID?.hasPrefix("sess_") == true)

        // The whole payload, text included, must be free of token material.
        let rendered = result.textContent + (result.structuredContent?.prettyJSONString ?? "")
        #expect(!rendered.contains("mock_access"))
        #expect(!rendered.contains("mock_refresh"))
        #expect(!rendered.lowercased().contains("access_token"))
    }

    @Test("Authenticating twice reuses the live session")
    func authenticateIsIdempotent() async throws {
        let (service, _, _, _) = makeTestService()

        let first = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        let second = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        #expect(first.sessionID == second.sessionID)
        #expect(second.textContent.contains("Already signed in"))
    }

    @Test("force: true starts a fresh sign-in even when a session exists")
    func forceStartsNewSession() async throws {
        let (service, _, _, _) = makeTestService()

        let first = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        let second = try await service.call(
            name: "authenticate", arguments: ["force": .bool(true)], owner: owner)

        #expect(first.sessionID != second.sessionID)
    }

    @Test("A sign-in awaiting the user returns a pending result with a code")
    func pendingAuthorization() async throws {
        let (service, provider, _, _) = makeTestService(policy: .manual)

        let pending = try await service.call(
            name: "authenticate", arguments: ["wait_seconds": .int(0)], owner: owner)

        #expect(pending.isOK)
        #expect(pending.structured["status"]?.stringValue == "pending")
        let flowID = try #require(pending.structured["flow_id"]?.stringValue)
        let userCode = try #require(pending.structured["user_code"]?.stringValue)
        #expect(pending.structured["verification_url"] != nil)

        // Approve out of band, the way a user would, then resume the same flow.
        await provider.approve(userCode: userCode)

        let completed = try await service.call(
            name: "authenticate",
            arguments: ["flow_id": .string(flowID), "wait_seconds": .int(0)],
            owner: owner)

        #expect(completed.structured["status"]?.stringValue == "authenticated")
        #expect(completed.sessionID != nil)
    }

    @Test("Calling authenticate again resumes the pending flow instead of restarting it")
    func resumesPendingFlow() async throws {
        let (service, _, _, _) = makeTestService(policy: .manual)

        let first = try await service.call(
            name: "authenticate", arguments: ["wait_seconds": .int(0)], owner: owner)
        let second = try await service.call(
            name: "authenticate", arguments: ["wait_seconds": .int(0)], owner: owner)

        // A second flow would invalidate the code the user is already looking at.
        #expect(first.structured["flow_id"] == second.structured["flow_id"])
        #expect(first.structured["user_code"] == second.structured["user_code"])
    }

    @Test("A declined sign-in is surfaced as a denial")
    func deniedAuthorization() async throws {
        let (service, _, _, _) = makeTestService(policy: .denied(reason: "nope"))

        let result = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        #expect(result.isError == true)
        #expect(result.errorCode == "authorization_denied")
    }

    // MARK: - Scope enforcement

    @Test("Writing without data:write is refused with a remediation")
    func writeRequiresWriteScope() async throws {
        let (service, _, _, _) = makeTestService(grantedScopes: [.dataRead])
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let result = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object(["a": .int(1)])],
            owner: owner)

        #expect(result.errorCode == "insufficient_scope")
        #expect(result.structured["error"]?["required_scope"]?.stringValue == "data:write")
        #expect(result.textContent.contains("data:write"))
    }

    @Test("Reading is allowed with only data:read")
    func readOnlySessionCanRead() async throws {
        let (service, _, store, _) = makeTestService(grantedScopes: [.dataRead])
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        _ = try await store.upsert(
            id: "doc", value: .object(["a": .int(1)]),
            owner: "test-subject", expectedVersion: nil, merge: false)

        let result = try await service.call(
            name: "fetchData", arguments: ["id": .string("doc")], owner: owner)

        #expect(result.isOK)
    }

    @Test("A narrowed grant is reported rather than discovered later")
    func narrowedGrantWarns() async throws {
        let (service, _, _, _) = makeTestService(grantedScopes: [.dataRead])

        let result = try await service.call(
            name: "authenticate",
            arguments: ["scopes": .array([.string("data:read"), .string("data:write")])],
            owner: owner)

        #expect(result.isOK)
        #expect(result.structured["scope_warning"]?.stringValue?.contains("data:write") == true)
    }

    // MARK: - Data round trip

    @Test("A record written through the tool reads back through the tool")
    func writeThenRead() async throws {
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let written = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object(["name": .string("Sam")])],
            owner: owner)

        #expect(written.isOK)
        #expect(written.structured["created"]?.boolValue == true)
        #expect(written.structured["version"]?.intValue == 1)

        let read = try await service.call(
            name: "fetchData", arguments: ["id": .string("doc")], owner: owner)

        #expect(read.structured["value"] == .object(["name": .string("Sam")]))
        #expect(read.structured["metadata"]?["version"]?.intValue == 1)
        #expect(read.structured["metadata"]?["etag"]?.stringValue == "W/\"1\"")
    }

    @Test("include_metadata: false omits the metadata block")
    func metadataCanBeOmitted() async throws {
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        _ = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object([:])],
            owner: owner)

        let read = try await service.call(
            name: "fetchData",
            arguments: ["id": .string("doc"), "include_metadata": .bool(false)],
            owner: owner)

        #expect(read.structured["metadata"] == nil)
        #expect(read.structured["value"] != nil)
    }

    @Test("A version conflict names the current version in its remediation")
    func versionConflictGuidesRecovery() async throws {
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        _ = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object(["v": .int(1)])],
            owner: owner)

        let conflict = try await service.call(
            name: "updatedData",
            arguments: [
                "id": .string("doc"),
                "value": .object(["v": .int(2)]),
                "expected_version": .int(7),
            ],
            owner: owner)

        #expect(conflict.errorCode == "version_conflict")
        #expect(conflict.structured["error"]?["current_version"]?.intValue == 1)
        #expect(conflict.textContent.contains("expected_version: 1"))
    }

    @Test("Records written by one principal are invisible to another")
    func recordsAreScopedToTheSubject() async throws {
        let clock = TestClock()
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let dataStore = InMemoryDataStore(now: clock.provider)

        func makeService(subject: String) -> AuthenticationService {
            let provider = MockAuthorizationProvider(
                subject: subject, logger: logger, now: clock.provider)
            let sessions = SessionStore(
                provider: provider, auditLog: auditLog, logger: logger, now: clock.provider)
            return AuthenticationService(
                provider: provider,
                sessionStore: sessions,
                dataStore: dataStore,
                auditLog: auditLog,
                logger: logger)
        }

        let alice = makeService(subject: "alice")
        let mallory = makeService(subject: "mallory")

        _ = try await alice.call(name: "authenticate", arguments: [:], owner: SessionOwner("a"))
        _ = try await alice.call(
            name: "updatedData",
            arguments: ["id": .string("private"), "value": .object(["x": .int(1)])],
            owner: SessionOwner("a"))

        _ = try await mallory.call(name: "authenticate", arguments: [:], owner: SessionOwner("m"))
        let stolen = try await mallory.call(
            name: "fetchData", arguments: ["id": .string("private")], owner: SessionOwner("m"))

        // Reported as "not found", not "forbidden", so ids cannot be enumerated.
        #expect(stolen.errorCode == "record_not_found")
    }

    @Test("One connection cannot use another connection's session id")
    func sessionsAreScopedToTheConnection() async throws {
        let (service, _, _, _) = makeTestService()

        let authenticated = try await service.call(
            name: "authenticate", arguments: [:], owner: SessionOwner("connection-1"))
        let sessionID = try #require(authenticated.sessionID)

        let borrowed = try await service.call(
            name: "fetchData",
            arguments: ["id": .string("doc"), "session_id": .string(sessionID)],
            owner: SessionOwner("connection-2"))

        #expect(borrowed.errorCode == "session_not_found")
    }

    // MARK: - Revocation

    @Test("Revoking destroys the session and reaches the provider")
    func revokeDestroysSession() async throws {
        let (service, provider, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let revoked = try await service.call(
            name: "revokeAuthentication", arguments: [:], owner: owner)

        #expect(revoked.isOK)
        #expect(revoked.structured["revoked_session_ids"]?.arrayValue?.count == 1)
        #expect(revoked.structured["upstream_complete"]?.boolValue == true)
        #expect(await provider.pendingFlowCount == 0)

        let afterwards = try await service.call(
            name: "fetchData", arguments: ["id": .string("doc")], owner: owner)
        #expect(afterwards.errorCode == "not_authenticated")
    }

    @Test("Revoking with nothing signed in succeeds quietly")
    func revokeIsIdempotent() async throws {
        let (service, _, _, _) = makeTestService()

        let result = try await service.call(
            name: "revokeAuthentication", arguments: [:], owner: owner)

        #expect(result.isOK)
        #expect(result.structured["revoked_session_ids"]?.arrayValue?.isEmpty == true)
    }

    @Test("all_sessions revokes every session on the connection")
    func revokeAllSessions() async throws {
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        _ = try await service.call(
            name: "authenticate", arguments: ["force": .bool(true)], owner: owner)

        let revoked = try await service.call(
            name: "revokeAuthentication",
            arguments: ["all_sessions": .bool(true)],
            owner: owner)

        #expect(revoked.structured["revoked_session_ids"]?.arrayValue?.count == 2)
    }

    // MARK: - Input validation

    @Test("A missing required parameter is named in the error")
    func missingRequiredParameter() async throws {
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let result = try await service.call(name: "fetchData", arguments: [:], owner: owner)

        #expect(result.errorCode == "invalid_input")
        #expect(result.errorMessage?.contains("`id`") == true)
    }

    @Test("The specification's ID and Value spellings are accepted")
    func acceptsSpecCapitalisation() async throws {
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let written = try await service.call(
            name: "updatedData",
            arguments: ["ID": .string("doc"), "Value": .object(["a": .int(1)])],
            owner: owner)
        #expect(written.isOK)

        let read = try await service.call(
            name: "fetchData", arguments: ["ID": .string("doc")], owner: owner)
        #expect(read.isOK)
    }

    @Test("A non-object value is rejected with an explanation")
    func rejectsNonObjectValue() async throws {
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let result = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .array([.int(1)])],
            owner: owner)

        #expect(result.errorCode == "invalid_input")
        #expect(result.errorMessage?.contains("JSON object") == true)
    }

    @Test("A JSON object sent as a string is recovered")
    func recoversStringifiedObject() async throws {
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let result = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .string(#"{"a":1}"#)],
            owner: owner)

        #expect(result.isOK)
        #expect(result.structured["value"] == .object(["a": .int(1)]))
    }

    @Test("A misspelled parameter is reported instead of silently ignored")
    func rejectsUnknownParameter() async throws {
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        _ = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object(["v": .int(1)])],
            owner: owner)

        // A dropped `expected_version` would silently turn a guarded write into
        // an unguarded one, so this must fail loudly.
        let result = try await service.call(
            name: "updatedData",
            arguments: [
                "id": .string("doc"),
                "value": .object(["v": .int(2)]),
                "expected_versoin": .int(1),
            ],
            owner: owner)

        #expect(result.errorCode == "invalid_input")
        #expect(result.errorMessage?.contains("expected_versoin") == true)
    }

    @Test("An unknown mode lists the accepted values")
    func rejectsUnknownMode() async throws {
        let (service, _, _, _) = makeTestService()

        let result = try await service.call(
            name: "authenticate", arguments: ["mode": .string("telepathy")], owner: owner)

        #expect(result.errorCode == "invalid_input")
        #expect(result.errorMessage?.contains("device") == true)
    }

    @Test("An unknown tool name is a protocol error, not a tool result")
    func unknownToolIsProtocolError() async throws {
        let (service, _, _, _) = makeTestService()

        await #expect(throws: MCPError.self) {
            try await service.call(name: "noSuchTool", arguments: [:], owner: owner)
        }
    }

    // MARK: - Rate limiting

    @Test("Excessive calls are rate limited with a retry hint")
    func rateLimiting() async throws {
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(logger: logger)
        let sessions = SessionStore(provider: provider, auditLog: auditLog, logger: logger)
        let service = AuthenticationService(
            provider: provider,
            sessionStore: sessions,
            dataStore: InMemoryDataStore(),
            rateLimiter: RateLimiter(),
            auditLog: auditLog,
            logger: logger)

        // `authenticate` has a burst capacity of 5 and refills slowly.
        var sawRateLimit = false
        for _ in 0..<12 {
            let result = try await service.call(
                name: "authenticate", arguments: ["force": .bool(true)], owner: owner)
            if result.errorCode == "rate_limited" {
                sawRateLimit = true
                #expect(result.structured["error"]?["retry_after_seconds"] != nil)
                break
            }
        }
        #expect(sawRateLimit, "repeated forced sign-ins should eventually be rate limited")
    }
}

@Suite("Result payload shape")
struct ResultPayloadTests {

    @Test("Absent fields are omitted, not emitted as JSON null")
    func compactingOmitsAbsentFields() {
        // `Value` is ExpressibleByNilLiteral, so a ternary against a non-optional
        // branch yields `Value.null` rather than `Optional.none`. Both must be
        // dropped, or clients see a null where they expected no key at all.
        let includeIt = false
        let payload = Value.object(compacting: [
            ("present", .string("here")),
            ("explicitNone", Optional<Value>.none),
            ("ternaryNil", includeIt ? .string("x") : nil),
            ("literalNull", Value.null),
        ])

        let fields = payload.objectValue ?? [:]
        #expect(fields.keys.sorted() == ["present"])
    }

    @Test("A create result omits previous_version, and an update includes it")
    func previousVersionOnlyOnUpdate() async throws {
        let (service, _, _, _) = makeTestService()
        let owner = SessionOwner("payload")
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let created = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object(["a": .int(1)])],
            owner: owner)
        #expect(created.structured["previous_version"] == nil)

        let updated = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object(["a": .int(2)])],
            owner: owner)
        #expect(updated.structured["previous_version"]?.intValue == 1)
    }

    @Test("A clean revocation carries no warning field")
    func revocationOmitsWarningWhenClean() async throws {
        let (service, _, _, _) = makeTestService()
        let owner = SessionOwner("payload")
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let revoked = try await service.call(
            name: "revokeAuthentication", arguments: [:], owner: owner)

        #expect(revoked.structured["warning"] == nil)
    }

    @Test("Every tool result declares whether it succeeded")
    func resultsCarryAnOkFlag() async throws {
        let (service, _, _, _) = makeTestService()
        let owner = SessionOwner("payload")

        let failed = try await service.call(
            name: "fetchData", arguments: ["id": .string("x")], owner: owner)
        #expect(failed.structured["ok"]?.boolValue == false)

        let succeeded = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        #expect(succeeded.structured["ok"]?.boolValue == true)
    }
}
