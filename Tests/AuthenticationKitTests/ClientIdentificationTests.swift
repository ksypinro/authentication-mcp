import Foundation
import Logging
import MCP
import Testing

@testable import AuthenticationKit

@Suite("Client identification")
struct ClientIdentificationTests {

    /// One end of a fully wired connection: a real SDK `Client` connected to a
    /// real `AuthenticationMCPServer.make()` server — the same builder stdio
    /// and HTTP use — over `InMemoryTransport.createConnectedPair()`.
    ///
    /// Going through `make()` rather than a bare `Server(...)` is the point:
    /// it is what proves `clientIdentificationHook` and the `tools/call`
    /// handler are actually sharing the same `ConnectedClientIdentity`, not
    /// just that each works in isolation.
    private struct Connection {
        let client: Client
        let server: Server
        let auditLog: AuditLog
        let debugLog: CapturingLogHandler
    }

    private func connect(
        clientName: String,
        clientVersion: String = "1.0.0",
        clientTitle: String? = nil
    ) async throws -> Connection {
        let (service, _, _, auditLog) = makeTestService()
        let (logger, debugLog) = makeCapturingLogger()

        let owner = SessionOwner("test-connection")
        let clientIdentity = ConnectedClientIdentity()

        let server = await AuthenticationMCPServer.make(
            service: service, owner: owner, clientIdentity: clientIdentity, logger: logger)

        let (clientTransport, serverTransport) = await InMemoryTransport.createConnectedPair()
        try await server.start(
            transport: serverTransport,
            initializeHook: AuthenticationMCPServer.clientIdentificationHook(
                owner: owner, clientIdentity: clientIdentity, auditLog: auditLog, logger: logger))

        let client = Client(name: clientName, version: clientVersion, title: clientTitle)
        _ = try await client.connect(transport: clientTransport)

        return Connection(client: client, server: server, auditLog: auditLog, debugLog: debugLog)
    }

    private func teardown(_ connection: Connection) async {
        await connection.client.disconnect()
        await connection.server.stop()
    }

    // MARK: - initialize handshake → audit log

    @Test("A real initialize handshake records the client's name and version")
    func handshakeRecordsClientIdentity() async throws {
        let connection = try await connect(clientName: "codex-cli", clientVersion: "0.9.2")
        defer { Task { await teardown(connection) } }

        let entries = await connection.auditLog.recentEntries()
        let entry = try #require(entries.first { $0.event == .clientConnected })

        #expect(entry.detail["client_name"] == "codex-cli")
        #expect(entry.detail["client_version"] == "0.9.2")
        #expect(entry.detail["owner"] == "test-connection")
    }

    @Test("A client with no title is recorded without one, not with a placeholder")
    func handlesMissingTitleCleanly() async throws {
        let connection = try await connect(clientName: "bare-client", clientTitle: nil)
        defer { Task { await teardown(connection) } }

        let entry = try #require(
            await connection.auditLog.recentEntries().first { $0.event == .clientConnected })
        #expect(entry.detail["client_title"] == nil)
    }

    @Test("The client name never reaches the audit log as sensitive")
    func clientNameIsNotRedacted() {
        // A sanity check on top of `Redaction`: "client_name" must not collide
        // with a key `Redaction.isSensitive` would fingerprint, or every client
        // name would show up in logs as "****ame".
        #expect(!Redaction.isSensitive(key: "client_name"))
        #expect(!Redaction.isSensitive(key: "client_version"))
    }

    // MARK: - tools/call → debug log

    @Test("A tool call's debug log line carries the client name from initialize")
    func toolCallDebugLogCarriesClientName() async throws {
        let connection = try await connect(clientName: "claude-ai", clientVersion: "1.2.0")
        defer { Task { await teardown(connection) } }

        _ = try await connection.client.callTool(name: "authenticate", arguments: [:])

        let line = try #require(connection.debugLog.entries(matching: "tools/call").first)
        #expect(line.metadata["tool"] == .string("authenticate"))
        #expect(line.metadata["client_name"] == .string("claude-ai"))
        #expect(line.metadata["owner"] == .string("test-connection"))
    }

    @Test("Two different clients each get their own name on their own tool calls")
    func distinguishesTwoClientsAcrossToolCalls() async throws {
        let claude = try await connect(clientName: "claude-ai")
        defer { Task { await teardown(claude) } }
        let codex = try await connect(clientName: "codex-cli")
        defer { Task { await teardown(codex) } }

        _ = try await claude.client.callTool(name: "authenticate", arguments: [:])
        _ = try await codex.client.callTool(name: "authenticate", arguments: [:])

        let claudeLine = try #require(claude.debugLog.entries(matching: "tools/call").first)
        let codexLine = try #require(codex.debugLog.entries(matching: "tools/call").first)

        #expect(claudeLine.metadata["client_name"] == .string("claude-ai"))
        #expect(codexLine.metadata["client_name"] == .string("codex-cli"))
    }

    @Test("A second tool call on the same connection still carries the name")
    func nameSurvivesAcrossMultipleCalls() async throws {
        // Guards against an implementation that reads the name once and then
        // forgets it, rather than a stable per-connection record.
        let connection = try await connect(clientName: "claude-ai")
        defer { Task { await teardown(connection) } }

        _ = try await connection.client.callTool(name: "authenticate", arguments: [:])
        _ = try await connection.client.callTool(
            name: "fetchData", arguments: ["id": .string("doc")])

        let toolCallLines = connection.debugLog.entries(matching: "tools/call")
        #expect(toolCallLines.count == 2)
        #expect(toolCallLines.allSatisfy { $0.metadata["client_name"] == .string("claude-ai") })
    }

    // MARK: - tools/call → audit log

    @Test("A sign-in's whole audit trail carries the client name, start to finish")
    func authenticateAuditTrailCarriesClientName() async throws {
        let connection = try await connect(clientName: "codex-cli")
        defer { Task { await teardown(connection) } }

        _ = try await connection.client.callTool(name: "authenticate", arguments: [:])

        let entries = await connection.auditLog.recentEntries()
        let started = try #require(entries.first { $0.event == .authenticationStarted })
        let succeeded = try #require(entries.first { $0.event == .authenticationSucceeded })

        #expect(started.detail["client_name"] == "codex-cli")
        #expect(succeeded.detail["client_name"] == "codex-cli")
    }

    @Test("fetchData and updatedData audit entries carry the client name")
    func dataToolAuditEntriesCarryClientName() async throws {
        let connection = try await connect(clientName: "claude-ai")
        defer { Task { await teardown(connection) } }

        _ = try await connection.client.callTool(name: "authenticate", arguments: [:])
        _ = try await connection.client.callTool(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object(["a": .int(1)])])
        _ = try await connection.client.callTool(
            name: "fetchData", arguments: ["id": .string("doc")])

        let entries = await connection.auditLog.recentEntries()
        let written = try #require(entries.first { $0.event == .dataWritten })
        let read = try #require(entries.first { $0.event == .dataRead })

        #expect(written.detail["client_name"] == "claude-ai")
        #expect(read.detail["client_name"] == "claude-ai")
    }

    @Test("A rate-limited call's audit entry carries the client name too")
    func rateLimitedAuditEntryCarriesClientName() async throws {
        let connection = try await connect(clientName: "codex-cli")
        defer { Task { await teardown(connection) } }

        // `authenticate` has a burst capacity of 5 (see `RateLimiter.Limit`).
        for _ in 0..<12 {
            _ = try await connection.client.callTool(
                name: "authenticate", arguments: ["force": .bool(true)])
        }

        let entries = await connection.auditLog.recentEntries()
        let limited = try #require(entries.first { $0.event == .rateLimited })
        #expect(limited.detail["client_name"] == "codex-cli")
    }

    @Test("Two connections' audit trails never mix up which client did what")
    func auditEntriesDoNotLeakBetweenConnections() async throws {
        let claude = try await connect(clientName: "claude-ai")
        defer { Task { await teardown(claude) } }
        let codex = try await connect(clientName: "codex-cli")
        defer { Task { await teardown(codex) } }

        _ = try await claude.client.callTool(name: "authenticate", arguments: [:])
        _ = try await codex.client.callTool(name: "authenticate", arguments: [:])

        let claudeNames = await claude.auditLog.recentEntries().compactMap {
            $0.detail["client_name"]
        }
        let codexNames = await codex.auditLog.recentEntries().compactMap {
            $0.detail["client_name"]
        }

        #expect(Set(claudeNames) == ["claude-ai"])
        #expect(Set(codexNames) == ["codex-cli"])
    }

    @Test("The standalone auth CLI path never attaches a client name")
    func cliDrivenCoordinatorOmitsClientName() async throws {
        // `auth login`/`logout`/`status` call `AuthenticationCoordinator`
        // directly — no MCP connection, no `tools/call` dispatch, so
        // `ClientContext.clientName` is never bound here. Its audit entries
        // must say nothing about a client, not invent or carry over a stale one.
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(logger: logger)
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-cli-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credentialStore = try CredentialStore.make(
            serviceName: "test", directory: directory, preferredBackend: .file, logger: logger)
        let coordinator = AuthenticationCoordinator(
            provider: provider,
            credentialStore: credentialStore,
            issuer: URL(string: "https://as.example.com")!,
            auditLog: auditLog,
            logger: logger)

        _ = try await coordinator.signIn()

        let entries = await auditLog.recentEntries()
        #expect(!entries.isEmpty)
        for entry in entries {
            #expect(entry.detail["client_name"] == nil)
        }
    }
}
