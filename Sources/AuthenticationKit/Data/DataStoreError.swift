import Foundation

/// Failures a ``DataStore`` can report.
public enum DataStoreError: Error, Sendable, Equatable {
    case notFound(id: String)
    /// The caller is not the record's owner. Reported as ``notFound`` at the tool
    /// boundary so record ids belonging to other subjects cannot be enumerated.
    case accessDenied(id: String)
    /// The record changed since the caller read it.
    case versionConflict(id: String, expected: Int, actual: Int)
    /// The identifier is empty, too long, or contains disallowed characters.
    case invalidIdentifier(reason: String)
    /// The payload exceeds the configured size limit.
    case payloadTooLarge(bytes: Int, limit: Int)
    /// A merge was requested against a value that is not a JSON object.
    case notMergeable(reason: String)
    /// The backing store itself failed.
    case storageFailure(reason: String)
}

extension DataStoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notFound(let id), .accessDenied(let id):
            // Identical text for both: see the note on `accessDenied`.
            return "No record with id '\(id)'."
        case .versionConflict(let id, let expected, let actual):
            return
                "Record '\(id)' was modified by someone else: expected version \(expected), "
                + "current version is \(actual). Re-read it with `fetchData` and retry."
        case .invalidIdentifier(let reason):
            return "Invalid record id: \(reason)"
        case .payloadTooLarge(let bytes, let limit):
            return "Value is \(bytes) bytes, which exceeds the \(limit) byte limit."
        case .notMergeable(let reason):
            return "Cannot merge: \(reason)"
        case .storageFailure(let reason):
            return "Storage failure: \(reason)"
        }
    }
}
