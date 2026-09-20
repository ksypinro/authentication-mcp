import Foundation
import Logging

enum LoggingBootstrap {

    /// Routes all logging to stderr.
    ///
    /// Non-negotiable for the stdio transport: stdout carries the JSON-RPC stream,
    /// and a single stray log line there corrupts the protocol and drops the
    /// connection. Sending everything to stderr keeps the two transports identical
    /// in behaviour and keeps logs visible in a client's server log pane.
    static func configure(level: Logger.Level) {
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardError(label: label)
            handler.logLevel = level
            return handler
        }
    }

    static func parseLevel(_ raw: String?) -> Logger.Level {
        guard let raw, let level = Logger.Level(rawValue: raw.lowercased()) else { return .info }
        return level
    }
}
