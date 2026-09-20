import Foundation
import MCP

/// The seam between the data tools and whatever actually persists documents.
///
/// Two implementations ship: ``InMemoryDataStore`` (the default, process-lifetime)
/// and ``FileDataStore`` (a JSON file, durable across restarts). Swapping in
/// Postgres, Redis, or a call to an upstream REST API means conforming to this
/// protocol and changing one line in `ServerConfiguration` — nothing in the tool
/// layer knows which store it has.
///
/// Implementations must enforce that `owner` matches the record's owner and
/// report a mismatch as ``DataStoreError/accessDenied(id:)``. Ownership is not
/// checked above this layer.
public protocol DataStore: Sendable {

    /// Reads one record.
    ///
    /// - Throws: ``DataStoreError/notFound(id:)`` or ``DataStoreError/accessDenied(id:)``.
    func fetch(id: String, owner: String) async throws -> DataRecord

    /// Creates or updates a record.
    ///
    /// - Parameters:
    ///   - expectedVersion: when non-nil, the write applies only if the stored
    ///     version matches, and otherwise throws
    ///     ``DataStoreError/versionConflict(id:expected:actual:)``. Pass `0` to
    ///     assert the record does not yet exist.
    ///   - merge: shallow-merges top-level keys into the existing object instead
    ///     of replacing the whole value.
    func upsert(
        id: String,
        value: Value,
        owner: String,
        expectedVersion: Int?,
        merge: Bool
    ) async throws -> DataWriteResult

    /// Every record owned by a subject, oldest first. Used by tests and tooling.
    func records(ownedBy owner: String) async throws -> [DataRecord]
}

/// Limits and rules shared by every ``DataStore`` implementation.
public enum DataStoreLimits {
    /// Largest serialized value accepted, in bytes.
    public static let maximumValueBytes = 256 * 1024
    public static let maximumIdentifierLength = 256

    /// Validates a record identifier.
    ///
    /// Identifiers become file paths in ``FileDataStore`` and map keys elsewhere,
    /// so path separators and dot segments are rejected outright rather than
    /// escaped — a `..` in an id must never be able to reach outside the store.
    public static func validate(identifier: String) throws {
        guard !identifier.isEmpty else {
            throw DataStoreError.invalidIdentifier(reason: "the id is empty")
        }
        guard identifier.count <= maximumIdentifierLength else {
            throw DataStoreError.invalidIdentifier(
                reason: "the id is longer than \(maximumIdentifierLength) characters")
        }
        guard !identifier.contains("/"), !identifier.contains("\\") else {
            throw DataStoreError.invalidIdentifier(reason: "the id contains a path separator")
        }
        guard identifier != ".", identifier != ".." else {
            throw DataStoreError.invalidIdentifier(reason: "the id is a path component")
        }
        guard !identifier.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F })
        else {
            throw DataStoreError.invalidIdentifier(reason: "the id contains control characters")
        }
    }

    /// Validates a value's serialized size.
    public static func validate(value: Value) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(value) else {
            throw DataStoreError.storageFailure(reason: "value could not be serialized to JSON")
        }
        guard data.count <= maximumValueBytes else {
            throw DataStoreError.payloadTooLarge(
                bytes: data.count, limit: maximumValueBytes)
        }
    }

    /// Shallow-merges `incoming` over `existing`.
    ///
    /// Only top-level keys are merged; a nested object in `incoming` replaces the
    /// one it shadows wholesale. Deep merge is deliberately not offered — its
    /// semantics for arrays and for deleting a key are ambiguous enough that a
    /// caller is better served reading, editing and writing the whole value.
    /// An explicit `null` deletes the key, following JSON Merge Patch (RFC 7386).
    public static func merge(existing: Value, incoming: Value) throws -> Value {
        guard case .object(let existingFields) = existing else {
            throw DataStoreError.notMergeable(reason: "the stored value is not a JSON object")
        }
        guard case .object(let incomingFields) = incoming else {
            throw DataStoreError.notMergeable(reason: "the supplied value is not a JSON object")
        }

        var merged = existingFields
        for (key, value) in incomingFields {
            if value.isNull {
                merged.removeValue(forKey: key)
            } else {
                merged[key] = value
            }
        }
        return .object(merged)
    }
}
