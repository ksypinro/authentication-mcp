import Foundation
import Logging

/// A structured, append-only record of security-relevant events.
///
/// Every authentication, revocation and write passes through here. The log is
/// deliberately separate from the diagnostic logger: it carries a fixed schema so
/// it can be shipped to a SIEM, and it never records token material — only
/// fingerprints (see ``Redaction``).
public actor AuditLog {

    public enum Event: String, Sendable, Codable {
        /// An MCP client completed the `initialize` handshake on this connection.
        case clientConnected = "client.connected"
        case authenticationStarted = "authentication.started"
        case authenticationSucceeded = "authentication.succeeded"
        case authenticationFailed = "authentication.failed"
        case authenticationRefreshed = "authentication.refreshed"
        case authorizationDenied = "authorization.denied"
        case revocationSucceeded = "revocation.succeeded"
        case revocationFailed = "revocation.failed"
        case dataRead = "data.read"
        case dataWritten = "data.written"
        case rateLimited = "rate_limited"
    }

    public struct Entry: Sendable, Codable {
        public let timestamp: Date
        public let event: Event
        /// The authenticated subject, when one is known.
        public let subject: String?
        /// The opaque session identifier, never the token.
        public let sessionID: String?
        /// Free-form, already-redacted detail fields.
        public let detail: [String: String]

        public init(
            timestamp: Date = Date(),
            event: Event,
            subject: String? = nil,
            sessionID: String? = nil,
            detail: [String: String] = [:]
        ) {
            self.timestamp = timestamp
            self.event = event
            self.subject = subject
            self.sessionID = sessionID
            self.detail = Redaction.redactSensitiveKeys(detail)
        }
    }

    private let logger: Logger
    private let retainedEntryLimit: Int
    private var entries: [Entry] = []

    public init(logger: Logger, retainedEntryLimit: Int = 1000) {
        self.logger = logger
        self.retainedEntryLimit = retainedEntryLimit
    }

    public func record(_ entry: Entry) {
        entries.append(entry)
        if entries.count > retainedEntryLimit {
            entries.removeFirst(entries.count - retainedEntryLimit)
        }

        var metadata: Logger.Metadata = [
            "event": .string(entry.event.rawValue),
            "timestamp": .string(Timestamps.string(from: entry.timestamp)),
        ]
        if let subject = entry.subject { metadata["subject"] = .string(subject) }
        if let sessionID = entry.sessionID { metadata["session"] = .string(sessionID) }
        for (key, value) in entry.detail {
            metadata[key] = .string(value)
        }

        switch entry.event {
        case .authenticationFailed, .authorizationDenied, .revocationFailed, .rateLimited:
            logger.warning("audit", metadata: metadata)
        default:
            logger.info("audit", metadata: metadata)
        }
    }

    public func record(
        _ event: Event,
        subject: String? = nil,
        sessionID: String? = nil,
        detail: [String: String] = [:]
    ) {
        record(Entry(event: event, subject: subject, sessionID: sessionID, detail: detail))
    }

    /// The most recent entries, newest last. Exposed for tests and operator tooling.
    public func recentEntries(limit: Int = 100) -> [Entry] {
        Array(entries.suffix(limit))
    }
}
