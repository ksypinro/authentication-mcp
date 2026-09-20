import AuthenticationHTTP
import AuthenticationKit
import Foundation
import Logging
import MCP

/// Runs the MCP server on one transport or the other.
enum ServeRuntime {

    static func runStdio(assembly: ServiceAssembly, logger: Logger) async throws {
        let owner = SessionOwner.stdio
        let clientIdentity = ConnectedClientIdentity()
        let server = await AuthenticationMCPServer.make(
            service: assembly.service, owner: owner, clientIdentity: clientIdentity, logger: logger)

        // Report sign-in state at startup so a misconfigured client is obvious
        // from the server log rather than from a confusing tool failure later.
        if let coordinator = assembly.coordinator {
            // `try?` on a throwing call that already returns an optional flattens
            // to a single level, so one binding is enough here.
            if let active = try? await coordinator.activeAccount() {
                logger.info("Using the stored credential", metadata: ["account": .string(active)])
            } else {
                logger.notice(
                    """
                    No stored credential. Run `authentication-mcp auth login`, or call the
                    `authenticate` tool to sign in from the conversation.
                    """)
            }
        }

        let transport = StdioTransport(logger: logger)
        try await server.start(
            transport: transport,
            initializeHook: AuthenticationMCPServer.clientIdentificationHook(
                owner: owner, clientIdentity: clientIdentity, auditLog: assembly.auditLog,
                logger: logger))

        logger.info("Listening on stdio")

        let maintenance = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(300))
                await assembly.service.performMaintenance()
            }
        }
        defer { maintenance.cancel() }

        await server.waitUntilCompleted()

        // Drops in-memory state. With persistence on this deliberately does NOT
        // revoke: the user signed in on purpose and expects to stay signed in.
        await assembly.service.releaseOwner(owner)
        logger.info("stdio client disconnected")
    }

    static func runHTTP(
        assembly: ServiceAssembly,
        host: String?,
        port: Int?,
        endpoint: String?,
        logger: Logger
    ) async throws {
        let configuration = MCPHTTPHost.Configuration(
            host: host ?? EnvironmentConfiguration.value("AUTH_MCP_HTTP_HOST") ?? "127.0.0.1",
            port: port ?? EnvironmentConfiguration.value("AUTH_MCP_HTTP_PORT").flatMap(Int.init)
                ?? 8080,
            endpoint: endpoint ?? EnvironmentConfiguration.value("AUTH_MCP_HTTP_ENDPOINT") ?? "/mcp",
            sessionTimeout: TimeInterval(
                EnvironmentConfiguration.value("AUTH_MCP_HTTP_SESSION_TIMEOUT").flatMap(Int.init)
                    ?? 3600),
            allowedOrigins: EnvironmentConfiguration.list("AUTH_MCP_ALLOWED_ORIGINS") ?? [])

        if configuration.host != "127.0.0.1" && configuration.host != "localhost"
            && configuration.allowedOrigins.isEmpty
        {
            logger.warning(
                """
                Binding a non-loopback interface with no AUTH_MCP_ALLOWED_ORIGINS set. \
                Origin checking is disabled, so anything that can reach this port can \
                drive the server. Set AUTH_MCP_ALLOWED_ORIGINS, or front it with a proxy \
                that validates Origin.
                """,
                metadata: ["host": .string(configuration.host)])
        }

        let httpHost = MCPHTTPHost(
            configuration: configuration, assembly: assembly, logger: logger)

        try await withTaskCancellationHandler {
            try await httpHost.run()
        } onCancel: {
            Task { await httpHost.stop() }
        }
    }
}
