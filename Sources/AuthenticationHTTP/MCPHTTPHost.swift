import AuthenticationKit
import Foundation
import Logging
import MCP

@preconcurrency import NIOCore
@preconcurrency import NIOHTTP1
@preconcurrency import NIOPosix

/// Serves the MCP server over the Streamable HTTP transport.
///
/// One `StatefulHTTPServerTransport` and one `MCP.Server` per HTTP session, all
/// sharing a single ``AuthenticationService``. Each session gets its own
/// ``SessionOwner``, which is what keeps one client's credentials invisible to
/// another. When a session ends — DELETE, idle timeout, or shutdown — its owner
/// is released and its sessions are revoked.
public actor MCPHTTPHost {

    public struct Configuration: Sendable {
        public var host: String
        public var port: Int
        /// The path the MCP endpoint is served at.
        public var endpoint: String
        /// How long an idle HTTP session survives.
        public var sessionTimeout: TimeInterval
        /// Hosts permitted in the `Origin` header. Empty disables the check, which
        /// is only safe behind a proxy that performs its own origin validation.
        public var allowedOrigins: [String]
        /// SSE reconnection hint, in milliseconds.
        public var retryInterval: Int?

        public init(
            host: String = "127.0.0.1",
            port: Int = 8080,
            endpoint: String = "/mcp",
            sessionTimeout: TimeInterval = 3600,
            allowedOrigins: [String] = [],
            retryInterval: Int? = nil
        ) {
            self.host = host
            self.port = port
            self.endpoint = endpoint
            self.sessionTimeout = sessionTimeout
            self.allowedOrigins = allowedOrigins
            self.retryInterval = retryInterval
        }
    }

    private struct SessionContext {
        let server: Server
        let transport: StatefulHTTPServerTransport
        let owner: SessionOwner
        let createdAt: Date
        var lastAccessedAt: Date
    }

    private let configuration: Configuration
    private let assembly: ServiceAssembly
    private var sessions: [String: SessionContext] = [:]
    private var channel: Channel?
    private var eventLoopGroup: MultiThreadedEventLoopGroup?
    private var maintenanceTask: Task<Void, Never>?

    nonisolated let logger: Logger

    public init(configuration: Configuration, assembly: ServiceAssembly, logger: Logger) {
        self.configuration = configuration
        self.assembly = assembly
        self.logger = logger
    }

    nonisolated var endpointPath: String { configuration.endpoint }

    // MARK: - Lifecycle

    /// Binds the listener and serves until ``stop()`` is called.
    public func run() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        eventLoopGroup = group

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(NIOAdapter(host: self))
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)

        let channel = try await bootstrap.bind(
            host: configuration.host, port: configuration.port
        ).get()
        self.channel = channel

        logger.info(
            "MCP HTTP endpoint listening",
            metadata: [
                "url": .string(
                    "http://\(configuration.host):\(configuration.port)\(configuration.endpoint)")
            ])

        maintenanceTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                await self?.runMaintenance()
            }
        }

        try await channel.closeFuture.get()
    }

    public func stop() async {
        maintenanceTask?.cancel()
        maintenanceTask = nil

        for sessionID in sessions.keys {
            await closeSession(sessionID, reason: "server shutting down")
        }

        try? await channel?.close()
        channel = nil
        try? await eventLoopGroup?.shutdownGracefully()
        eventLoopGroup = nil
        logger.info("MCP HTTP endpoint stopped")
    }

    // MARK: - Routing

    /// Routes one HTTP request to its session's transport.
    func handle(_ request: HTTPRequest) async -> HTTPResponse {
        // A tiny liveness endpoint, so a container orchestrator does not have to
        // speak MCP to know whether the process is up.
        if request.path == "/healthz" {
            return .data(
                Data(#"{"status":"ok"}"#.utf8),
                headers: ["Content-Type": "application/json"])
        }

        guard request.path == configuration.endpoint else {
            return .error(statusCode: 404, .invalidRequest("Not Found"))
        }

        let sessionID = request.header(HTTPHeaderName.sessionID)

        if let sessionID, var context = sessions[sessionID] {
            context.lastAccessedAt = Date()
            sessions[sessionID] = context

            let response = await context.transport.handleRequest(request)

            // A successful DELETE is the client saying it is done with the session.
            if request.method.uppercased() == "DELETE", response.statusCode == 200 {
                await closeSession(sessionID, reason: "client ended the session")
            }
            return response
        }

        if request.method.uppercased() == "POST",
            let body = request.body,
            isInitializeRequest(body)
        {
            return await createSession(handling: request)
        }

        if sessionID != nil {
            return .error(
                statusCode: 404, .invalidRequest("Session not found or expired"))
        }
        return .error(
            statusCode: 400,
            .invalidRequest("Missing \(HTTPHeaderName.sessionID) header"))
    }

    /// Whether a JSON-RPC body is an `initialize` request.
    ///
    /// The SDK's own detector is package-internal, so this reproduces the single
    /// check the host needs: does this body start a new session?
    private func isInitializeRequest(_ body: Data) -> Bool {
        guard let json = try? JSONSerialization.jsonObject(with: body) else { return false }
        if let object = json as? [String: Any] {
            return object["method"] as? String == "initialize"
        }
        if let batch = json as? [[String: Any]] {
            return batch.contains { $0["method"] as? String == "initialize" }
        }
        return false
    }

    // MARK: - Sessions

    private struct FixedSessionIDGenerator: SessionIDGenerator {
        let sessionID: String
        func generateSessionID() -> String { sessionID }
    }

    private func createSession(handling request: HTTPRequest) async -> HTTPResponse {
        let sessionID = UUID().uuidString
        let owner = SessionOwner("http:\(sessionID)")

        let transport = StatefulHTTPServerTransport(
            sessionIDGenerator: FixedSessionIDGenerator(sessionID: sessionID),
            validationPipeline: makeValidationPipeline(),
            retryInterval: configuration.retryInterval,
            logger: logger)

        do {
            let clientIdentity = ConnectedClientIdentity()
            let server = await AuthenticationMCPServer.make(
                service: assembly.service, owner: owner, clientIdentity: clientIdentity,
                logger: logger)
            try await server.start(
                transport: transport,
                initializeHook: AuthenticationMCPServer.clientIdentificationHook(
                    owner: owner, clientIdentity: clientIdentity, auditLog: assembly.auditLog,
                    logger: logger))

            sessions[sessionID] = SessionContext(
                server: server,
                transport: transport,
                owner: owner,
                createdAt: Date(),
                lastAccessedAt: Date())

            let response = await transport.handleRequest(request)
            if case .error = response {
                sessions.removeValue(forKey: sessionID)
                await transport.disconnect()
                await assembly.service.releaseOwner(owner)
            } else {
                logger.info("MCP session opened", metadata: ["session": .string(sessionID)])
            }
            return response
        } catch {
            await transport.disconnect()
            await assembly.service.releaseOwner(owner)
            logger.error(
                "Could not open MCP session",
                metadata: ["error": .string(error.localizedDescription)])
            return .error(statusCode: 500, .internalError("Could not open a session"))
        }
    }

    private func closeSession(_ sessionID: String, reason: String) async {
        guard let context = sessions.removeValue(forKey: sessionID) else { return }
        await context.transport.disconnect()
        await context.server.stop()
        // Revoke whatever this client authenticated: when the connection is gone,
        // holding its tokens serves no purpose and widens the blast radius of a
        // later compromise.
        await assembly.service.releaseOwner(context.owner)
        logger.info(
            "MCP session closed",
            metadata: ["session": .string(sessionID), "reason": .string(reason)])
    }

    private func runMaintenance() async {
        let cutoff = Date().addingTimeInterval(-configuration.sessionTimeout)
        for (sessionID, context) in sessions where context.lastAccessedAt < cutoff {
            await closeSession(sessionID, reason: "idle timeout")
        }
        await assembly.service.performMaintenance()
    }

    /// The request validators applied before a request reaches the transport.
    ///
    /// Origin checking defends a localhost-bound server against DNS rebinding: a
    /// page in the user's browser can otherwise reach 127.0.0.1 and drive this
    /// server with the user's own credentials.
    private func makeValidationPipeline() -> any HTTPRequestValidationPipeline {
        let originValidator: OriginValidator
        if configuration.allowedOrigins.isEmpty {
            originValidator = isLoopbackBinding
                ? OriginValidator.localhost(port: configuration.port)
                : OriginValidator.disabled
        } else {
            originValidator = OriginValidator(
                allowedHosts: configuration.allowedOrigins,
                allowedOrigins: configuration.allowedOrigins)
        }

        return StandardValidationPipeline(validators: [
            originValidator,
            AcceptHeaderValidator(mode: .sseRequired),
            ContentTypeValidator(),
            ProtocolVersionValidator(),
            SessionValidator(),
        ])
    }

    private var isLoopbackBinding: Bool {
        ["127.0.0.1", "localhost", "::1"].contains(configuration.host)
    }

    /// Open HTTP session count, for tests and metrics.
    public var openSessionCount: Int { sessions.count }
}
