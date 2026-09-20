import Foundation
import MCP

/// One stored document.
public struct DataRecord: Sendable, Codable, Equatable {
    public let id: String
    public let value: Value
    /// Monotonic revision counter, starting at 1. Drives optimistic concurrency.
    public let version: Int
    /// The subject that owns the record. Only this subject can read or write it.
    public let owner: String
    public let createdAt: Date
    public let updatedAt: Date
    /// The subject of the last write, kept separate from `owner` so a future
    /// sharing model does not need a migration.
    public let updatedBy: String

    public init(
        id: String,
        value: Value,
        version: Int,
        owner: String,
        createdAt: Date,
        updatedAt: Date,
        updatedBy: String
    ) {
        self.id = id
        self.value = value
        self.version = version
        self.owner = owner
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.updatedBy = updatedBy
    }

    /// A weak entity tag over the version, in the HTTP sense. Clients that
    /// already speak `If-Match` can round-trip this instead of a bare integer.
    public var etag: String {
        "W/\"\(version)\""
    }

    /// Parses a version out of either an ETag or a plain integer string.
    public static func version(fromETag etag: String) -> Int? {
        let trimmed =
            etag
            .replacingOccurrences(of: "W/", with: "")
            .trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
        return Int(trimmed)
    }

    /// The metadata block returned alongside the value.
    public var metadata: Value {
        .object([
            "version": .int(version),
            "etag": .string(etag),
            "owner": .string(owner),
            "created_at": .string(Timestamps.string(from: createdAt)),
            "updated_at": .string(Timestamps.string(from: updatedAt)),
            "updated_by": .string(updatedBy),
        ])
    }
}

/// The outcome of a write.
public struct DataWriteResult: Sendable, Equatable {
    public let record: DataRecord
    /// True when the write created the record rather than updating one.
    public let didCreate: Bool
    /// The version before this write; `nil` for a create.
    public let previousVersion: Int?

    public init(record: DataRecord, didCreate: Bool, previousVersion: Int?) {
        self.record = record
        self.didCreate = didCreate
        self.previousVersion = previousVersion
    }
}
