import Foundation
import MCP

/// A ``DataStore`` that persists every record as one JSON file in a directory.
///
/// Chosen over a single-file store so that concurrent writes to different records
/// never contend, and so a corrupt record cannot take the whole dataset with it.
/// Writes go to a temporary file and are then moved into place, which is atomic
/// within a filesystem — a crash mid-write leaves the previous version intact
/// rather than a truncated file.
public actor FileDataStore: DataStore {
    private let directory: URL
    private let now: @Sendable () -> Date
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(directory: URL, now: @escaping @Sendable () -> Date = { Date() }) throws {
        self.directory = directory
        self.now = now

        // Dates go through `Timestamps` rather than `.iso8601`, whose built-in
        // strategy truncates to whole seconds. Without this a record read back
        // from disk would carry a coarser `updated_at` than the same record read
        // from `InMemoryDataStore`, and the two stores would stop being
        // interchangeable in exactly the way the `DataStore` contract promises.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(Timestamps.string(from: date))
        }
        self.encoder = encoder

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let text = try container.decode(String.self)
            guard let date = Timestamps.date(from: text) else {
                throw DecodingError.dataCorruptedError(
                    in: container, debugDescription: "'\(text)' is not an RFC 3339 timestamp")
            }
            return date
        }
        self.decoder = decoder

        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                // Records contain user data and are readable only by the owner.
                attributes: [.posixPermissions: 0o700])
        } catch {
            throw DataStoreError.storageFailure(
                reason: "could not create \(directory.path): \(error.localizedDescription)")
        }
    }

    public func fetch(id: String, owner: String) async throws -> DataRecord {
        try DataStoreLimits.validate(identifier: id)
        guard let record = try readRecord(id: id) else { throw DataStoreError.notFound(id: id) }
        guard record.owner == owner else { throw DataStoreError.accessDenied(id: id) }
        return record
    }

    public func upsert(
        id: String,
        value: Value,
        owner: String,
        expectedVersion: Int?,
        merge: Bool
    ) async throws -> DataWriteResult {
        try DataStoreLimits.validate(identifier: id)

        let existing = try readRecord(id: id)
        if let existing, existing.owner != owner {
            throw DataStoreError.accessDenied(id: id)
        }

        if let expectedVersion {
            let actual = existing?.version ?? 0
            guard actual == expectedVersion else {
                throw DataStoreError.versionConflict(
                    id: id, expected: expectedVersion, actual: actual)
            }
        }

        let resolvedValue: Value
        if merge, let existing {
            resolvedValue = try DataStoreLimits.merge(existing: existing.value, incoming: value)
        } else {
            resolvedValue = value
        }
        try DataStoreLimits.validate(value: resolvedValue)

        let timestamp = now()
        let record = DataRecord(
            id: id,
            value: resolvedValue,
            version: (existing?.version ?? 0) + 1,
            owner: owner,
            createdAt: existing?.createdAt ?? timestamp,
            updatedAt: timestamp,
            updatedBy: owner)

        try writeRecord(record)

        return DataWriteResult(
            record: record,
            didCreate: existing == nil,
            previousVersion: existing?.version)
    }

    public func records(ownedBy owner: String) async throws -> [DataRecord] {
        let urls: [URL]
        do {
            urls = try FileManager.default.contentsOfDirectory(
                at: directory, includingPropertiesForKeys: nil)
        } catch {
            throw DataStoreError.storageFailure(reason: error.localizedDescription)
        }

        return
            urls
            .filter { $0.pathExtension == "json" }
            .compactMap { try? decoder.decode(DataRecord.self, from: Data(contentsOf: $0)) }
            .filter { $0.owner == owner }
            .sorted { $0.createdAt < $1.createdAt }
    }

    // MARK: - File access

    /// Maps a record id to a filename.
    ///
    /// The id is percent-encoded rather than used verbatim: ids are validated
    /// against path separators already, but encoding also handles case-insensitive
    /// filesystems, reserved names, and characters a filesystem would reject.
    private func fileURL(for id: String) -> URL {
        let encoded = FormEncoding.percentEncode(id)
        return directory.appendingPathComponent("\(encoded).json")
    }

    private func readRecord(id: String) throws -> DataRecord? {
        let url = fileURL(for: id)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        do {
            return try decoder.decode(DataRecord.self, from: Data(contentsOf: url))
        } catch {
            throw DataStoreError.storageFailure(
                reason: "record '\(id)' on disk is unreadable: \(error.localizedDescription)")
        }
    }

    private func writeRecord(_ record: DataRecord) throws {
        let destination = fileURL(for: record.id)
        let temporary = directory.appendingPathComponent(".\(UUID().uuidString).tmp")

        do {
            let data = try encoder.encode(record)
            try data.write(to: temporary, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            // `replaceItemAt` is the atomic swap; it also removes the temp file.
            _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw DataStoreError.storageFailure(
                reason: "could not write record '\(record.id)': \(error.localizedDescription)")
        }
    }
}
