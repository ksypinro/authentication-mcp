import Foundation

/// RFC 3339 formatting, shared by tool results and the audit log so every
/// timestamp the server emits has the same shape.
///
/// Uses `Date.ISO8601FormatStyle` rather than `ISO8601DateFormatter`: the format
/// style is a `Sendable` value type, so it can be a shared constant, while the
/// formatter is a reference type that cannot cross actor boundaries safely.
public enum Timestamps {
    private static let style = Date.ISO8601FormatStyle(
        includingFractionalSeconds: true,
        timeZone: TimeZone(secondsFromGMT: 0) ?? .gmt)

    public static func string(from date: Date) -> String {
        date.formatted(style)
    }

    public static func date(from string: String) -> Date? {
        try? Date(string, strategy: style)
    }
}
