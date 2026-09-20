import Foundation

/// Where the token material physically lives.
///
/// Two implementations ship: ``KeychainSecretStore`` (the default on macOS) and
/// ``FileSecretStore`` (the fallback). The fallback is not optional extra work —
/// a headless Linux box or a container has no Secret Service daemon, and a hard
/// keychain dependency would make the server unusable there. `gh` degrades the
/// same way, storing its token in `hosts.yml` when no keyring is available.
public protocol SecretStore: Sendable {
    /// A short phrase naming where secrets go, for `auth status` and logs.
    var describedLocation: String { get }

    /// Reads the blob for an account, or `nil` when there is none.
    func read(account: String) throws -> Data?

    /// Writes (or replaces) the blob for an account.
    func write(_ data: Data, account: String) throws

    /// Removes the blob. Succeeds when there was nothing to remove.
    func delete(account: String) throws
}

/// Failures from a secret store.
public enum SecretStoreError: Error, Sendable, Equatable, LocalizedError {
    case unavailable(reason: String)
    case accessDenied(reason: String)
    case writeFailed(reason: String)
    case readFailed(reason: String)

    public var errorDescription: String? {
        switch self {
        case .unavailable(let reason):
            return "Credential storage is unavailable: \(reason)"
        case .accessDenied(let reason):
            return "Access to stored credentials was denied: \(reason)"
        case .writeFailed(let reason):
            return "Could not save the credential: \(reason)"
        case .readFailed(let reason):
            return "Could not read the stored credential: \(reason)"
        }
    }
}

/// A secret store that keeps everything in memory. For tests.
public final class InMemorySecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: Data] = [:]

    public init() {}

    public var describedLocation: String { "memory (not persisted)" }

    public func read(account: String) throws -> Data? {
        lock.withLock { storage[account] }
    }

    public func write(_ data: Data, account: String) throws {
        lock.withLock { storage[account] = data }
    }

    public func delete(account: String) throws {
        _ = lock.withLock { storage.removeValue(forKey: account) }
    }
}
