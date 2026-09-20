import Foundation
import Logging

/// The persistent home for sign-in state.
///
/// Combines a non-secret JSON index with a ``SecretStore`` holding the token
/// material, and serialises every mutation behind a cross-process ``FileLock``
/// so that concurrent invocations of this binary cannot corrupt each other.
///
/// This is what makes "signed in until I sign out" true: the refresh token
/// survives here between runs, and everything else — access tokens, sessions —
/// is derived from it.
public actor CredentialStore {

    /// Where secrets go when no keychain is available.
    public enum Backend: String, Sendable {
        case keychain
        case file
        case memory
    }

    private let directory: URL
    private let secretStore: any SecretStore
    private let lock: FileLock
    private let logger: Logger
    private let now: @Sendable () -> Date
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public nonisolated let backend: Backend

    public init(
        directory: URL,
        secretStore: any SecretStore,
        backend: Backend,
        logger: Logger,
        now: @escaping @Sendable () -> Date = { Date() }
    ) throws {
        self.directory = directory
        self.secretStore = secretStore
        self.backend = backend
        self.logger = logger
        self.now = now

        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
        } catch {
            throw SecretStoreError.unavailable(
                reason: "could not create \(directory.path): \(error.localizedDescription)")
        }

        self.lock = try FileLock(path: directory.appendingPathComponent(".lock").path)

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
    }

    /// Builds a store with the best backend this host offers.
    ///
    /// Prefers the keychain and falls back to a file, because a hard keychain
    /// dependency makes the server unusable on a headless host.
    public static func make(
        serviceName: String,
        directory: URL,
        preferredBackend: Backend? = nil,
        logger: Logger,
        now: @escaping @Sendable () -> Date = { Date() }
    ) throws -> CredentialStore {
        let secretsDirectory = directory.appendingPathComponent("secrets", isDirectory: true)

        func makeFileStore() throws -> CredentialStore {
            try CredentialStore(
                directory: directory,
                secretStore: try FileSecretStore(directory: secretsDirectory),
                backend: .file,
                logger: logger,
                now: now)
        }

        switch preferredBackend {
        case .file:
            return try makeFileStore()
        case .memory:
            return try CredentialStore(
                directory: directory,
                secretStore: InMemorySecretStore(),
                backend: .memory,
                logger: logger,
                now: now)
        case .keychain, nil:
            #if canImport(Security)
                if KeychainSecretStore.isAvailable(service: serviceName) {
                    return try CredentialStore(
                        directory: directory,
                        secretStore: KeychainSecretStore(service: serviceName),
                        backend: .keychain,
                        logger: logger,
                        now: now)
                }
                if preferredBackend == .keychain {
                    throw SecretStoreError.unavailable(
                        reason: "the keychain was requested but is not usable in this process")
                }
                logger.notice(
                    "Keychain unavailable; falling back to file-backed credential storage")
            #endif
            return try makeFileStore()
        }
    }

    // MARK: - Description

    public var describedLocation: String {
        secretStore.describedLocation
    }

    public nonisolated var indexURL: URL {
        directory.appendingPathComponent("accounts.json")
    }

    // MARK: - Reading

    /// Loads a credential, or the active one when `account` is `nil`.
    ///
    /// Returns `nil` rather than throwing when nothing is signed in — that is an
    /// ordinary state, not an error.
    public func load(account: String? = nil) throws -> StoredCredential? {
        let index = try readIndex()
        guard let account = account ?? index.activeAccount,
            let entry = index.accounts[account]
        else {
            return nil
        }

        guard let data = try secretStore.read(account: account) else {
            // The index and the secret store disagree. The secret is the
            // authority, so drop the orphaned index entry rather than keep
            // reporting a sign-in that cannot produce a token.
            logger.warning(
                "Credential index names an account with no stored secret; dropping it",
                metadata: ["account": .string(account)])
            try? mutateIndex { index in
                index.accounts.removeValue(forKey: account)
                if index.activeAccount == account {
                    index.activeAccount = index.accounts.keys.sorted().first
                }
            }
            return nil
        }

        let secret = try decodeSecret(data, account: account)
        return StoredCredential(entry: entry, secret: secret)
    }

    /// Every known account, oldest sign-in first. Reads no secrets.
    public func accounts() throws -> [CredentialIndexEntry] {
        try readIndex().accounts.values.sorted { $0.obtainedAt < $1.obtainedAt }
    }

    public func activeAccount() throws -> String? {
        try readIndex().activeAccount
    }

    // MARK: - Writing

    /// Persists a credential and, by default, makes it the active one.
    public func save(_ credential: StoredCredential, makeActive: Bool = true) throws {
        try lock.withExclusiveLock {
            let data = try encoder.encode(credential.secret)
            try secretStore.write(data, account: credential.account)

            var index = try readIndexUnlocked()
            index.accounts[credential.account] = credential.entry
            if makeActive || index.activeAccount == nil {
                index.activeAccount = credential.account
            }
            try writeIndexUnlocked(index)
        }

        logger.debug(
            "Credential persisted",
            metadata: [
                "account": .string(credential.account),
                "backend": .string(backend.rawValue),
                "has_refresh_token": .stringConvertible(credential.entry.hasRefreshToken),
            ])
    }

    /// Removes a credential entirely. Succeeds when there was nothing to remove.
    public func delete(account: String) throws {
        try lock.withExclusiveLock {
            // The secret goes first: an orphaned index entry is self-healing on
            // the next load, whereas an orphaned secret would linger unreferenced.
            try secretStore.delete(account: account)

            var index = try readIndexUnlocked()
            index.accounts.removeValue(forKey: account)
            if index.activeAccount == account {
                index.activeAccount = index.accounts.keys.sorted().first
            }
            try writeIndexUnlocked(index)
        }
        logger.debug("Credential removed", metadata: ["account": .string(account)])
    }

    /// Removes every credential. Returns the accounts that were removed.
    public func deleteAll() throws -> [String] {
        let existing = try accounts().map(\.account)
        for account in existing {
            try delete(account: account)
        }
        return existing
    }

    public func setActiveAccount(_ account: String) throws {
        try mutateIndex { index in
            guard index.accounts[account] != nil else {
                throw SecretStoreError.readFailed(reason: "no stored credential for '\(account)'")
            }
            index.activeAccount = account
        }
    }

    /// Runs `body` while holding the cross-process lock.
    ///
    /// Used to wrap a whole read-refresh-write cycle so two processes cannot both
    /// refresh, with the loser persisting a rotated-away refresh token.
    public func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        // `FileLock` guards a synchronous critical section, so acquire it around
        // the actor hop rather than holding a file lock across an await.
        try lock.withExclusiveLock {}
        return try await body()
    }

    // MARK: - Index I/O

    private func readIndex() throws -> CredentialIndex {
        try lock.withExclusiveLock { try readIndexUnlocked() }
    }

    private func readIndexUnlocked() throws -> CredentialIndex {
        guard FileManager.default.fileExists(atPath: indexURL.path) else { return .empty }
        do {
            return try decoder.decode(CredentialIndex.self, from: Data(contentsOf: indexURL))
        } catch {
            // A corrupt index must not brick every command. Start clean and say
            // so; the secrets are still there and a re-login repairs it.
            logger.warning(
                "Credential index is unreadable; treating it as empty",
                metadata: [
                    "path": .string(indexURL.path),
                    "error": .string(error.localizedDescription),
                ])
            return .empty
        }
    }

    private func writeIndexUnlocked(_ index: CredentialIndex) throws {
        let temporary = directory.appendingPathComponent(".\(UUID().uuidString).tmp")
        do {
            try encoder.encode(index).write(to: temporary, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            if FileManager.default.fileExists(atPath: indexURL.path) {
                _ = try FileManager.default.replaceItemAt(indexURL, withItemAt: temporary)
            } else {
                try FileManager.default.moveItem(at: temporary, to: indexURL)
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw SecretStoreError.writeFailed(
                reason: "could not write the credential index: \(error.localizedDescription)")
        }
    }

    private func mutateIndex(_ body: (inout CredentialIndex) throws -> Void) throws {
        try lock.withExclusiveLock {
            var index = try readIndexUnlocked()
            try body(&index)
            try writeIndexUnlocked(index)
        }
    }

    private func decodeSecret(_ data: Data, account: String) throws -> CredentialSecret {
        do {
            return try decoder.decode(CredentialSecret.self, from: data)
        } catch {
            throw SecretStoreError.readFailed(
                reason: "the stored secret for '\(account)' could not be decoded; sign in again")
        }
    }
}
