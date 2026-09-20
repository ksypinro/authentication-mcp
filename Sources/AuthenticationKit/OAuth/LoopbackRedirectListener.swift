import Foundation
import Logging
import Network

/// A single-shot HTTP listener on 127.0.0.1 that catches the authorization
/// redirect for the browser flow.
///
/// RFC 8252 §7.3 makes loopback the correct redirect target for a native client:
/// it needs no registered custom scheme, and binding to an ephemeral port (`0`)
/// avoids collisions with whatever else is running on the machine. The listener
/// accepts exactly one redirect and then stops, so it cannot be reused by a later
/// request to smuggle in a different authorization code.
actor LoopbackRedirectListener {
    private let logger: Logger
    private var listener: NWListener?
    private var continuation: CheckedContinuation<URL, Error>?
    private var boundPort: UInt16?
    private var hasDelivered = false

    /// The path the authorization server redirects to.
    static let callbackPath = "/oauth/callback"

    init(logger: Logger) {
        self.logger = logger
    }

    /// Binds the listener and returns the redirect URI to send to the authorization server.
    func start(preferredPort: UInt16 = 0) throws -> URL {
        guard listener == nil else {
            throw OAuthError.loopbackListenerFailed(reason: "listener already started")
        }

        let parameters = NWParameters.tcp
        parameters.acceptLocalOnly = true
        parameters.allowLocalEndpointReuse = true

        let listener: NWListener
        do {
            if preferredPort == 0 {
                listener = try NWListener(using: parameters)
            } else {
                guard let port = NWEndpoint.Port(rawValue: preferredPort) else {
                    throw OAuthError.loopbackListenerFailed(reason: "invalid port \(preferredPort)")
                }
                listener = try NWListener(using: parameters, on: port)
            }
        } catch let error as OAuthError {
            throw error
        } catch {
            throw OAuthError.loopbackListenerFailed(reason: error.localizedDescription)
        }

        listener.newConnectionHandler = { [weak self] connection in
            guard let self else {
                connection.cancel()
                return
            }
            Task { await self.handle(connection) }
        }

        let queue = DispatchQueue(label: "authentication-service.loopback")
        listener.start(queue: queue)
        self.listener = listener

        // NWListener assigns the ephemeral port asynchronously; wait briefly for it.
        let deadline = Date().addingTimeInterval(2)
        while listener.port?.rawValue == nil && Date() < deadline {
            usleep(5_000)
        }
        guard let port = listener.port?.rawValue else {
            listener.cancel()
            self.listener = nil
            throw OAuthError.loopbackListenerFailed(reason: "the OS did not assign a port")
        }
        boundPort = port

        guard let url = URL(string: "http://127.0.0.1:\(port)\(Self.callbackPath)") else {
            throw OAuthError.loopbackListenerFailed(reason: "could not build the redirect URI")
        }
        logger.debug("Loopback redirect listener bound", metadata: ["port": .stringConvertible(port)])
        return url
    }

    /// Waits for the redirect, or throws ``OAuthError/authorizationExpired`` at the deadline.
    func waitForRedirect(timeout: TimeInterval) async throws -> URL {
        guard listener != nil else {
            throw OAuthError.loopbackListenerFailed(reason: "listener is not running")
        }

        let timeoutTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(timeout))
            guard !Task.isCancelled else { return }
            await self?.fail(with: OAuthError.authorizationExpired)
        }
        defer { timeoutTask.cancel() }

        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        if let continuation {
            self.continuation = nil
            continuation.resume(throwing: OAuthError.authorizationExpired)
        }
    }

    // MARK: - Connection handling

    private func handle(_ connection: NWConnection) {
        connection.start(queue: DispatchQueue(label: "authentication-service.loopback.connection"))
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) {
            [weak self] data, _, _, _ in
            guard let self else {
                connection.cancel()
                return
            }
            Task { await self.processRequest(data: data, on: connection) }
        }
    }

    private func processRequest(data: Data?, on connection: NWConnection) {
        guard let data, let requestLine = Self.firstLine(of: data) else {
            respond(on: connection, status: "400 Bad Request", body: Self.errorPage)
            return
        }

        // "GET /oauth/callback?code=... HTTP/1.1"
        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2, parts[0] == "GET" else {
            respond(on: connection, status: "405 Method Not Allowed", body: Self.errorPage)
            return
        }

        let target = String(parts[1])
        guard let port = boundPort,
            let url = URL(string: "http://127.0.0.1:\(port)\(target)"),
            url.path == Self.callbackPath
        else {
            // Browsers ask for /favicon.ico on the same origin; answering 404 keeps
            // that from being mistaken for the redirect.
            respond(on: connection, status: "404 Not Found", body: Self.errorPage)
            return
        }

        respond(on: connection, status: "200 OK", body: Self.successPage)
        deliver(url)
    }

    private func deliver(_ url: URL) {
        guard !hasDelivered, let continuation else { return }
        hasDelivered = true
        self.continuation = nil
        continuation.resume(returning: url)
        listener?.cancel()
        listener = nil
    }

    private func fail(with error: Error) {
        guard !hasDelivered, let continuation else { return }
        hasDelivered = true
        self.continuation = nil
        continuation.resume(throwing: error)
        listener?.cancel()
        listener = nil
    }

    private nonisolated func respond(on connection: NWConnection, status: String, body: String) {
        let response = """
            HTTP/1.1 \(status)\r
            Content-Type: text/html; charset=utf-8\r
            Content-Length: \(body.utf8.count)\r
            Cache-Control: no-store\r
            Connection: close\r
            \r
            \(body)
            """
        connection.send(
            content: Data(response.utf8),
            completion: .contentProcessed { _ in connection.cancel() })
    }

    private nonisolated static func firstLine(of data: Data) -> String? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        return text.split(separator: "\r\n", maxSplits: 1).first.map(String.init)
    }

    private static let successPage = """
        <!doctype html><html><head><meta charset="utf-8"><title>Signed in</title>
        <style>body{font:16px -apple-system,system-ui,sans-serif;display:grid;place-items:center;
        height:100vh;margin:0;color:#111;background:#fafafa}main{text-align:center;max-width:32rem}
        h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#555}
        @media(prefers-color-scheme:dark){body{background:#151515;color:#eee}p{color:#aaa}}</style>
        </head><body><main><h1>Signed in</h1>
        <p>You can close this tab and return to your assistant.</p></main></body></html>
        """

    private static let errorPage = """
        <!doctype html><html><head><meta charset="utf-8"><title>Not found</title></head>
        <body><p>Nothing here.</p></body></html>
        """
}
