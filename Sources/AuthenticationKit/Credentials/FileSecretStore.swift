import Foundation

/// Stores secrets as `0600` files in a `0700` directory.
///
/// The fallback for hosts with no keychain: headless Linux, containers, CI. The
/// secret is at rest in plaintext, so any process running as this user can read
/// it — which is precisely the trade the keychain exists to avoid. Callers
/// should prefer ``KeychainSecretStore`` and land here only when it is
/// unavailable, and ``describedLocation`` says so plainly in `auth status`.
public struct FileSecretStore: SecretStore {
    private let directory: URL

    public init(directory: URL) throws {
        self.directory = directory
        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
        } catch {
            throw SecretStoreError.unavailable(
                reason: "could not create \(directory.path): \(error.localizedDescription)")
        }
        // A directory that already existed may have looser permissions than we
        // would have created, so tighten it rather than trusting it.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }

    public var describedLocation: String {
        "file at \(directory.path) (plaintext, 0600)"
    }

    public func read(account: String) throws -> Data? {
        let url = fileURL(for: account)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        do {
            return try Data(contentsOf: url)
        } catch {
            throw SecretStoreError.readFailed(reason: error.localizedDescription)
        }
    }

    public func write(_ data: Data, account: String) throws {
        let destination = fileURL(for: account)
        let temporary = directory.appendingPathComponent(".\(UUID().uuidString).tmp")
        do {
            try data.write(to: temporary, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: temporary.path)
            if FileManager.default.fileExists(atPath: destination.path) {
                _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
            } else {
                try FileManager.default.moveItem(at: temporary, to: destination)
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw SecretStoreError.writeFailed(reason: error.localizedDescription)
        }
    }

    public func delete(account: String) throws {
        let url = fileURL(for: account)
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        do {
            try FileManager.default.removeItem(at: url)
        } catch {
            throw SecretStoreError.writeFailed(reason: error.localizedDescription)
        }
    }

    /// Percent-encodes the account so an email address is a safe filename.
    private func fileURL(for account: String) -> URL {
        directory.appendingPathComponent("\(FormEncoding.percentEncode(account)).json")
    }
}
