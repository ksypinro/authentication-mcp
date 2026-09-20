import Foundation
import Logging
import MCP

/// Builds a configured MCP `Server` in front of an ``AuthenticationService``.
///
/// One server instance per connection. For stdio that is one for the process
/// lifetime; for Streamable HTTP it is one per HTTP session, each with its own
/// ``SessionOwner`` so credentials never cross between clients — while the
/// service, session store and data store stay shared.
public enum AuthenticationMCPServer {

    public static let name = "authentication-service"
    public static let version = "1.0.0"

    /// Guidance the client shows to the model once, at connection time.
    ///
    /// Describes the ordering constraint the schemas cannot express on their own:
    /// authenticate first, and expect sign-in to take more than one call.
    public static let instructions = """
        This server exposes four tools over an authenticated session.

        Call `authenticate` before `fetchData` or `updatedData`. Signing in needs a \
        human, so `authenticate` usually returns `status: "pending"` with a \
        `verification_url` and a `user_code` — relay both to the user verbatim, then \
        call `authenticate` again with the same `flow_id` until it returns \
        `status: "authenticated"`. Starting a second flow invalidates the code the \
        user is already looking at.

        Access tokens are never returned. Carry the `session_id` from `authenticate` \
        to the other tools, or omit it to use the connection's active session.

        Records are per-principal: `fetchData` only sees records owned by the signed-in \
        subject. When updating a record you have read, pass its `version` as \
        `expected_version` so a concurrent change is reported instead of overwritten.

        `revokeAuthentication` signs out and is safe to call more than once.
        """

    /// Creates a server bound to one connection.
    ///
    /// - Parameter clientIdentity: shared with whatever `initializeHook` this
    ///   server is started with (see `clientIdentificationHook`), so the name
    ///   the client gave at `initialize` can be folded into every subsequent
    ///   `tools/call` log line. Pass a fresh instance per connection.
    public static func make(
        service: AuthenticationService,
        owner: SessionOwner,
        clientIdentity: ConnectedClientIdentity,
        logger: Logger
    ) async -> Server {
        let server = Server(
            name: name,
            version: version,
            title: "Authentication Service",
            instructions: instructions,
            capabilities: Server.Capabilities(
                logging: .init(),
                tools: .init(listChanged: false)))

        await server.withMethodHandler(ListTools.self) { _ in
            ListTools.Result(tools: ToolCatalog.allTools)
        }

        await server.withMethodHandler(CallTool.self) { parameters in
            // `logger.debug`'s `metadata:` parameter is `@autoclosure` in
            // swift-log, which cannot contain `await` — so the dictionary is
            // built as a plain value first.
            let clientName = await clientIdentity.label
            logger.debug(
                "tools/call",
                metadata: [
                    "tool": .string(parameters.name),
                    "owner": .string(owner.rawValue),
                    "client_name": .string(clientName),
                ])
            // Bound around the whole call tree so every audit entry written
            // anywhere below — in AuthenticationService, SessionStore, or
            // AuthenticationCoordinator — can attach it via `ClientContext.annotate`.
            return try await ClientContext.$clientName.withValue(clientName) {
                try await service.call(
                    name: parameters.name,
                    arguments: parameters.arguments,
                    owner: owner)
            }
        }

        return server
    }

    /// Builds the `initializeHook` that records which MCP client connected.
    ///
    /// `Client.Info` — name, version, and an optional title — arrives exactly
    /// once, at the start of the connection, before any tool call. The SDK's
    /// `Server` actor keeps it as a private property with no getter afterward,
    /// so this hook is the only place it can ever be observed; pass the result
    /// to `Server.start(transport:initializeHook:)`.
    ///
    /// - Important: this is an identification signal, not an authentication
    ///   one. `clientInfo` is whatever the client says it is, sent over an
    ///   unauthenticated local pipe or HTTP session — useful for logs, audit
    ///   trails, and per-client policy, never as a security boundary. Two
    ///   different integrations (say, Claude and Codex) each launch their own
    ///   process on stdio, so this never has to arbitrate between them on one
    ///   connection — it just names, for the log, which one this connection is.
    ///
    /// - Parameter clientIdentity: written here so `make`'s `tools/call`
    ///   handler can read the name back on every later call. Pass the same
    ///   instance to both.
    public static func clientIdentificationHook(
        owner: SessionOwner,
        clientIdentity: ConnectedClientIdentity,
        auditLog: AuditLog,
        logger: Logger
    ) -> @Sendable (Client.Info, Client.Capabilities) async throws -> Void {
        { clientInfo, _ in
            await clientIdentity.record(name: clientInfo.name)

            var metadata: Logger.Metadata = [
                "owner": .string(owner.rawValue),
                "client_name": .string(clientInfo.name),
                "client_version": .string(clientInfo.version),
            ]
            if let title = clientInfo.title {
                metadata["client_title"] = .string(title)
            }
            logger.info("MCP client connected", metadata: metadata)

            await auditLog.record(
                .clientConnected,
                detail: [
                    "owner": owner.rawValue,
                    "client_name": clientInfo.name,
                    "client_version": clientInfo.version,
                ])
        }
    }
}
