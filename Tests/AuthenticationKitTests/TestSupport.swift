import Foundation
import Logging
import MCP

@testable import AuthenticationKit

// MARK: - Logging

/// A logger that discards everything, so test output stays readable.
///
/// `SwiftLogNoOpLogHandler` comes from swift-log itself, so it tracks any future
/// additions to the `LogHandler` protocol without this file having to.
func makeSilentLogger() -> Logger {
    Logger(label: "test", factory: { _ in SwiftLogNoOpLogHandler() })
}

// MARK: - Clock

/// A clock the test drives by hand, for exercising expiry and rate limiting
/// without sleeping.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(_ start: Date = Date(timeIntervalSince1970: 1_700_000_000)) {
        current = start
    }

    var now: Date {
        lock.withLock { current }
    }

    func advance(by interval: TimeInterval) {
        lock.withLock { current += interval }
    }

    /// A closure to hand to any component that takes `now:`.
    var provider: @Sendable () -> Date {
        { [self] in self.now }
    }
}

// MARK: - Capturing logger

/// A `LogHandler` that records every call instead of discarding it.
///
/// `makeSilentLogger()` is right for tests that don't care what gets logged;
/// this is for the handful that need to assert on the metadata a log line
/// actually carried — proving a value flowed all the way into the log call,
/// rather than trusting that it probably did.
final class CapturingLogHandler: LogHandler, @unchecked Sendable {
    struct Entry {
        let level: Logger.Level
        let message: String
        let metadata: Logger.Metadata
    }

    private let lock = NSLock()
    private var entries: [Entry] = []

    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { nil }
        set { _ = newValue }
    }

    func log(event: LogEvent) {
        lock.withLock {
            entries.append(
                Entry(
                    level: event.level, message: "\(event.message)", metadata: event.metadata ?? [:]))
        }
    }

    /// Entries whose message contains `text`, oldest first.
    func entries(matching text: String) -> [Entry] {
        lock.withLock { entries.filter { $0.message.contains(text) } }
    }
}

/// A logger backed by a `CapturingLogHandler`, with that handler returned
/// alongside it so a test can inspect what was logged.
///
/// `Logger(label:factory:)` calls `factory` once, synchronously, to build the
/// handler backing this specific `Logger` value — unlike
/// `LoggingSystem.bootstrap`, which is global and can only be set once per
/// process. Returning the same instance from the factory is what makes it
/// inspectable afterward.
func makeCapturingLogger() -> (logger: Logger, handler: CapturingLogHandler) {
    let handler = CapturingLogHandler()
    var logger = Logger(label: "test-capture", factory: { _ in handler })
    logger.logLevel = .trace
    return (logger, handler)
}

// MARK: - Scripted HTTP

/// A scripted ``HTTPExchanging`` that answers by URL path.
///
/// Lets the OAuth tests drive discovery, device authorization, polling, refresh
/// and revocation deterministically — including multi-step sequences such as
/// `authorization_pending` followed by success.
final class ScriptedHTTPClient: HTTPExchanging, @unchecked Sendable {

    struct Reply {
        let statusCode: Int
        let body: Data

        static func json(_ object: [String: Any], status: Int = 200) -> Reply {
            Reply(
                statusCode: status,
                body: try! JSONSerialization.data(withJSONObject: object))
        }

        static func oauthError(_ code: String, description: String? = nil, status: Int = 400) -> Reply {
            var object: [String: Any] = ["error": code]
            if let description { object["error_description"] = description }
            return .json(object, status: status)
        }

        static let notFound = Reply(statusCode: 404, body: Data("{}".utf8))
    }

    struct RecordedRequest {
        let url: URL
        let method: String
        let headers: [String: String]
        /// The form body, decoded into parameters.
        let form: [String: String]
    }

    private let lock = NSLock()
    /// Queued replies per path; the last one repeats once the queue runs dry.
    private var queues: [String: [Reply]] = [:]
    private var recorded: [RecordedRequest] = []

    init() {}

    /// Queues replies for a path, answered in order.
    func stub(path: String, replies: [Reply]) {
        lock.withLock { queues[path] = replies }
    }

    func stub(path: String, reply: Reply) {
        stub(path: path, replies: [reply])
    }

    var requests: [RecordedRequest] {
        lock.withLock { recorded }
    }

    func requests(toPath path: String) -> [RecordedRequest] {
        requests.filter { $0.url.path == path }
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url else {
            throw OAuthError.transportFailure(reason: "request had no URL")
        }

        // Scoped locking: `lock()`/`unlock()` are unavailable in async contexts
        // because a suspension between them would hold the lock across an await.
        let reply = lock.withLock { () -> Reply in
            recorded.append(
                RecordedRequest(
                    url: url,
                    method: request.httpMethod ?? "GET",
                    headers: request.allHTTPHeaderFields ?? [:],
                    form: Self.decodeForm(request.httpBody)))

            guard var queue = queues[url.path], !queue.isEmpty else { return .notFound }
            let next = queue.removeFirst()
            // The final reply sticks, so a test does not have to queue one entry
            // per poll when the answer stops changing.
            queues[url.path] = queue.isEmpty ? [next] : queue
            return next
        }

        let response = HTTPURLResponse(
            url: url, statusCode: reply.statusCode, httpVersion: "HTTP/1.1", headerFields: nil)!
        return (reply.body, response)
    }

    private static func decodeForm(_ body: Data?) -> [String: String] {
        guard let body, let text = String(data: body, encoding: .utf8) else { return [:] }
        var result: [String: String] = [:]
        for pair in text.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let key = String(parts[0]).removingPercentEncoding ?? String(parts[0])
            let value = String(parts[1]).removingPercentEncoding ?? String(parts[1])
            result[key] = value
        }
        return result
    }
}

// MARK: - Fixtures

enum Fixtures {
    static let issuer = URL(string: "https://as.example.com")!

    /// A discovery document advertising every endpoint this server uses.
    static func discoveryDocument(
        includeDevice: Bool = true,
        includeRevocation: Bool = true,
        issuerOverride: String? = nil
    ) -> [String: Any] {
        var document: [String: Any] = [
            "issuer": issuerOverride ?? issuer.absoluteString,
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token",
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["data:read", "data:write"],
        ]
        if includeDevice {
            document["device_authorization_endpoint"] = "https://as.example.com/device"
        }
        if includeRevocation {
            document["revocation_endpoint"] = "https://as.example.com/revoke"
        }
        return document
    }

    static func oauthConfiguration(
        scopes: Set<Scope> = Scope.defaults
    ) -> OAuthProviderConfiguration {
        OAuthProviderConfiguration(
            issuer: issuer,
            authentication: .publicClient(clientID: "test-client"),
            defaultScopes: scopes,
            resourceIndicator: URL(string: "https://api.example.com"),
            authorizationTimeout: 300,
            opensBrowserAutomatically: false)
    }

    /// Wires a client stubbed for a full, successful device-grant sign-in.
    static func deviceFlowClient(
        pollReplies: [ScriptedHTTPClient.Reply]
    ) -> ScriptedHTTPClient {
        let client = ScriptedHTTPClient()
        client.stub(
            path: "/.well-known/oauth-authorization-server",
            reply: .json(discoveryDocument()))
        client.stub(
            path: "/device",
            reply: .json([
                "device_code": "DEV-CODE-1",
                "user_code": "WXYZ-1234",
                "verification_uri": "https://as.example.com/activate",
                "verification_uri_complete": "https://as.example.com/activate?user_code=WXYZ-1234",
                "expires_in": 600,
                // Zero keeps the test from sleeping between polls.
                "interval": 0,
            ]))
        client.stub(path: "/token", replies: pollReplies)
        client.stub(path: "/revoke", reply: .json([:]))
        return client
    }

    static func tokenResponse(
        accessToken: String = "access-1",
        refreshToken: String? = "refresh-1",
        scope: String? = "data:read data:write",
        expiresIn: Int? = 3600
    ) -> ScriptedHTTPClient.Reply {
        var object: [String: Any] = [
            "access_token": accessToken,
            "token_type": "Bearer",
        ]
        if let refreshToken { object["refresh_token"] = refreshToken }
        if let scope { object["scope"] = scope }
        if let expiresIn { object["expires_in"] = expiresIn }
        return .json(object)
    }

    /// Builds an unsigned JWT with the given payload, for ID-token parsing tests.
    static func unsignedJWT(claims: [String: Any]) -> String {
        func encode(_ object: [String: Any]) -> String {
            let data = try! JSONSerialization.data(withJSONObject: object)
            return data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        return "\(encode(["alg": "none", "typ": "JWT"])).\(encode(claims)).signature"
    }
}

// MARK: - Service assembly for tests

/// Builds a service backed by the mock provider and an in-memory store.
func makeTestService(
    policy: MockAuthorizationProvider.ApprovalPolicy = .immediate,
    grantedScopes: Set<Scope>? = nil,
    subject: String = "test-subject",
    clock: TestClock = TestClock()
) -> (
    service: AuthenticationService,
    provider: MockAuthorizationProvider,
    store: InMemoryDataStore,
    auditLog: AuditLog
) {
    let logger = makeSilentLogger()
    let auditLog = AuditLog(logger: logger)
    let provider = MockAuthorizationProvider(
        policy: policy,
        subject: subject,
        grantedScopes: grantedScopes,
        logger: logger,
        now: clock.provider)
    let dataStore = InMemoryDataStore(now: clock.provider)
    let sessionStore = SessionStore(
        provider: provider,
        auditLog: auditLog,
        logger: logger,
        now: clock.provider)
    let service = AuthenticationService(
        provider: provider,
        sessionStore: sessionStore,
        dataStore: dataStore,
        auditLog: auditLog,
        logger: logger)
    return (service, provider, dataStore, auditLog)
}

// MARK: - Result helpers

extension CallTool.Result {
    var structured: [String: Value] {
        structuredContent?.objectValue ?? [:]
    }

    var isOK: Bool {
        structured["ok"]?.boolValue == true && isError != true
    }

    /// The `error.code` of a failed result, if there is one.
    var errorCode: String? {
        structured["error"]?.objectValue?["code"]?.stringValue
    }

    var errorMessage: String? {
        structured["error"]?.objectValue?["message"]?.stringValue
    }

    var textContent: String {
        content.compactMap { item -> String? in
            if case .text(let text, _, _) = item { return text }
            return nil
        }.joined(separator: "\n")
    }

    var sessionID: String? {
        structured["session"]?.objectValue?["session_id"]?.stringValue
    }
}
