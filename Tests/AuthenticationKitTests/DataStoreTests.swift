import Foundation
import MCP
import Testing

@testable import AuthenticationKit

@Suite("Data store")
struct DataStoreTests {

    /// Runs the shared contract against every implementation, so the file-backed
    /// store cannot quietly drift from the in-memory one.
    static func makeStores() throws -> [(name: String, store: any DataStore, cleanup: () -> Void)] {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-tests-\(UUID().uuidString)")
        return [
            ("in-memory", InMemoryDataStore(), {}),
            (
                "file", try FileDataStore(directory: directory),
                { try? FileManager.default.removeItem(at: directory) }
            ),
        ]
    }

    @Test("Create, read back, and increment the version")
    func createAndRead() async throws {
        for (name, store, cleanup) in try Self.makeStores() {
            defer { cleanup() }

            let created = try await store.upsert(
                id: "doc", value: .object(["a": .int(1)]),
                owner: "alice", expectedVersion: nil, merge: false)
            #expect(created.didCreate, "\(name): first write should create")
            #expect(created.record.version == 1, "\(name)")
            #expect(created.previousVersion == nil, "\(name)")

            let fetched = try await store.fetch(id: "doc", owner: "alice")
            #expect(fetched.value == .object(["a": .int(1)]), "\(name)")
            #expect(fetched.etag == "W/\"1\"", "\(name)")

            let updated = try await store.upsert(
                id: "doc", value: .object(["a": .int(2)]),
                owner: "alice", expectedVersion: nil, merge: false)
            #expect(!updated.didCreate, "\(name)")
            #expect(updated.record.version == 2, "\(name)")
            #expect(updated.previousVersion == 1, "\(name)")
        }
    }

    @Test("Records are invisible to other owners")
    func ownerIsolation() async throws {
        for (name, store, cleanup) in try Self.makeStores() {
            defer { cleanup() }

            _ = try await store.upsert(
                id: "secret", value: .object(["x": .int(1)]),
                owner: "alice", expectedVersion: nil, merge: false)

            await #expect(throws: DataStoreError.accessDenied(id: "secret"), "\(name)") {
                try await store.fetch(id: "secret", owner: "mallory")
            }
            // A write by another owner must not clobber the record either.
            await #expect(throws: DataStoreError.accessDenied(id: "secret"), "\(name)") {
                try await store.upsert(
                    id: "secret", value: .object(["x": .int(99)]),
                    owner: "mallory", expectedVersion: nil, merge: false)
            }
            let intact = try await store.fetch(id: "secret", owner: "alice")
            #expect(intact.value == .object(["x": .int(1)]), "\(name)")
        }
    }

    @Test("A stale expected_version is rejected with the current version")
    func versionConflict() async throws {
        for (name, store, cleanup) in try Self.makeStores() {
            defer { cleanup() }

            _ = try await store.upsert(
                id: "doc", value: .object(["v": .int(1)]),
                owner: "alice", expectedVersion: nil, merge: false)
            _ = try await store.upsert(
                id: "doc", value: .object(["v": .int(2)]),
                owner: "alice", expectedVersion: 1, merge: false)

            await #expect(
                throws: DataStoreError.versionConflict(id: "doc", expected: 1, actual: 2),
                "\(name)"
            ) {
                try await store.upsert(
                    id: "doc", value: .object(["v": .int(3)]),
                    owner: "alice", expectedVersion: 1, merge: false)
            }
        }
    }

    @Test("expected_version 0 asserts the record does not exist yet")
    func createOnlyAssertion() async throws {
        for (name, store, cleanup) in try Self.makeStores() {
            defer { cleanup() }

            let created = try await store.upsert(
                id: "fresh", value: .object([:]),
                owner: "alice", expectedVersion: 0, merge: false)
            #expect(created.didCreate, "\(name)")

            await #expect(
                throws: DataStoreError.versionConflict(id: "fresh", expected: 0, actual: 1),
                "\(name)"
            ) {
                try await store.upsert(
                    id: "fresh", value: .object([:]),
                    owner: "alice", expectedVersion: 0, merge: false)
            }
        }
    }

    @Test("Merge adds and replaces top-level keys, and null deletes one")
    func mergeSemantics() async throws {
        for (name, store, cleanup) in try Self.makeStores() {
            defer { cleanup() }

            _ = try await store.upsert(
                id: "doc",
                value: .object(["keep": .string("yes"), "change": .int(1), "drop": .bool(true)]),
                owner: "alice", expectedVersion: nil, merge: false)

            let merged = try await store.upsert(
                id: "doc",
                value: .object(["change": .int(2), "added": .string("new"), "drop": .null]),
                owner: "alice", expectedVersion: nil, merge: true)

            #expect(
                merged.record.value == .object([
                    "keep": .string("yes"),
                    "change": .int(2),
                    "added": .string("new"),
                ]), "\(name)")
        }
    }

    @Test("Replace mode discards keys the new value omits")
    func replaceSemantics() async throws {
        let store = InMemoryDataStore()
        _ = try await store.upsert(
            id: "doc", value: .object(["a": .int(1), "b": .int(2)]),
            owner: "alice", expectedVersion: nil, merge: false)

        let replaced = try await store.upsert(
            id: "doc", value: .object(["a": .int(9)]),
            owner: "alice", expectedVersion: nil, merge: false)

        #expect(replaced.record.value == .object(["a": .int(9)]))
    }

    @Test("Record ids that could escape the store are rejected", arguments: [
        "", "../etc/passwd", "a/b", "a\\b", ".", "..",
    ])
    func rejectsDangerousIdentifiers(_ id: String) async throws {
        let store = InMemoryDataStore()
        await #expect(throws: DataStoreError.self) {
            try await store.fetch(id: id, owner: "alice")
        }
    }

    @Test("Oversized values are rejected before they are stored")
    func payloadLimit() async throws {
        let store = InMemoryDataStore()
        let huge = String(repeating: "x", count: DataStoreLimits.maximumValueBytes + 1)

        await #expect(throws: DataStoreError.self) {
            try await store.upsert(
                id: "big", value: .object(["blob": .string(huge)]),
                owner: "alice", expectedVersion: nil, merge: false)
        }
        // The failed write must not have created a partial record.
        await #expect(throws: DataStoreError.notFound(id: "big")) {
            try await store.fetch(id: "big", owner: "alice")
        }
    }

    @Test("Merging into a non-object value is refused rather than guessed at")
    func mergeAgainstNonObject() async throws {
        #expect(throws: DataStoreError.self) {
            try DataStoreLimits.merge(existing: .string("scalar"), incoming: .object([:]))
        }
    }

    @Test("The file store survives a restart")
    func filePersistence() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-persist-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let first = try FileDataStore(directory: directory)
        _ = try await first.upsert(
            id: "durable", value: .object(["n": .int(7)]),
            owner: "alice", expectedVersion: nil, merge: false)

        // A second instance over the same directory stands in for a restart.
        let second = try FileDataStore(directory: directory)
        let record = try await second.fetch(id: "durable", owner: "alice")
        #expect(record.value == .object(["n": .int(7)]))
        #expect(record.version == 1)
    }

    @Test("Timestamps keep sub-second precision across a file round trip")
    func filePreservesTimestampPrecision() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-time-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        // A time with a fractional component the built-in .iso8601 strategy
        // would silently truncate.
        let instant = Date(timeIntervalSince1970: 1_700_000_000.456)
        let store = try FileDataStore(directory: directory, now: { instant })

        _ = try await store.upsert(
            id: "doc", value: .object([:]), owner: "alice", expectedVersion: nil, merge: false)
        let reread = try await FileDataStore(directory: directory)
            .fetch(id: "doc", owner: "alice")

        #expect(abs(reread.updatedAt.timeIntervalSince(instant)) < 0.002)
    }

    @Test("ETags round-trip back to a version number")
    func etagParsing() {
        #expect(DataRecord.version(fromETag: "W/\"12\"") == 12)
        #expect(DataRecord.version(fromETag: "\"12\"") == 12)
        #expect(DataRecord.version(fromETag: "12") == 12)
        #expect(DataRecord.version(fromETag: "not-a-version") == nil)
    }

    @Test("Concurrent unguarded writes all land, and the version counts them")
    func concurrentWrites() async throws {
        let store = InMemoryDataStore()
        _ = try await store.upsert(
            id: "counter", value: .object(["n": .int(0)]),
            owner: "alice", expectedVersion: nil, merge: false)

        await withTaskGroup(of: Void.self) { group in
            for index in 1...20 {
                group.addTask {
                    _ = try? await store.upsert(
                        id: "counter", value: .object(["n": .int(index)]),
                        owner: "alice", expectedVersion: nil, merge: false)
                }
            }
        }

        let final = try await store.fetch(id: "counter", owner: "alice")
        #expect(final.version == 21, "every write should have been applied exactly once")
    }
}
