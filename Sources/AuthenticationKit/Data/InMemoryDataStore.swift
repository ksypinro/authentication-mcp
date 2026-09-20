import Foundation
import MCP

/// The default ``DataStore``: records live in the process and are lost on exit.
///
/// Suitable for development, tests, and deployments where the MCP server is a
/// stateless front end over something else. Use ``FileDataStore`` when records
/// need to survive a restart.
public actor InMemoryDataStore: DataStore {
    private var records: [String: DataRecord] = [:]
    private let now: @Sendable () -> Date

    public init(now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
    }

    /// Creates a store pre-populated with records, for demos and tests.
    public init(
        seed: [(id: String, value: Value, owner: String)],
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.now = now
        let timestamp = now()
        for entry in seed {
            records[entry.id] = DataRecord(
                id: entry.id,
                value: entry.value,
                version: 1,
                owner: entry.owner,
                createdAt: timestamp,
                updatedAt: timestamp,
                updatedBy: entry.owner)
        }
    }

    public func fetch(id: String, owner: String) async throws -> DataRecord {
        try DataStoreLimits.validate(identifier: id)
        guard let record = records[id] else { throw DataStoreError.notFound(id: id) }
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

        let existing = records[id]
        if let existing, existing.owner != owner {
            throw DataStoreError.accessDenied(id: id)
        }

        // `expectedVersion == 0` is the "must not already exist" assertion.
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
        records[id] = record

        return DataWriteResult(
            record: record,
            didCreate: existing == nil,
            previousVersion: existing?.version)
    }

    public func records(ownedBy owner: String) async throws -> [DataRecord] {
        records.values
            .filter { $0.owner == owner }
            .sorted { $0.createdAt < $1.createdAt }
    }

    /// Total record count across all owners. For tests and metrics.
    public var count: Int { records.count }
}
