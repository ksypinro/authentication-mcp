import Foundation
import Security

/// Stores secrets as generic-password items in the macOS Keychain.
///
/// Items are keyed by `(service, account)`, matching how `gh` files its token —
/// `svce="gh:github.com"`, `acct="<username>"`. Keeping the issuer host in the
/// service name means one binary can hold credentials for several providers
/// without collision.
///
/// - Note: keychain items are bound to the code signature of the process that
///   created them. A locally built, unsigned binary gets a fresh signature on
///   every `swift build`, so macOS may prompt for permission again after a
///   rebuild. That is expected during development and does not happen with a
///   signed release build. Use the file store to avoid the prompts entirely.
public struct KeychainSecretStore: SecretStore {
    /// The keychain service name, e.g. `authentication-mcp:accounts.google.com`.
    public let service: String

    public init(service: String) {
        self.service = service
    }

    public var describedLocation: String { "macOS Keychain (\(service))" }

    /// Reports whether the keychain is usable at all.
    ///
    /// A process with no Keychain access — some sandboxes, some CI runners —
    /// should fall back to the file store rather than fail every command.
    public static func isAvailable(service: String) -> Bool {
        let probe = "__availability_probe__"
        let store = KeychainSecretStore(service: service)
        do {
            try store.write(Data("probe".utf8), account: probe)
            try store.delete(account: probe)
            return true
        } catch {
            return false
        }
    }

    public func read(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw SecretStoreError.readFailed(reason: "keychain returned an unexpected type")
            }
            return data
        case errSecItemNotFound:
            return nil
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
            throw SecretStoreError.accessDenied(reason: Self.message(for: status))
        default:
            throw SecretStoreError.readFailed(reason: Self.message(for: status))
        }
    }

    public func write(_ data: Data, account: String) throws {
        // Try an update first; an add on an existing item fails with duplicate.
        let updateStatus = SecItemUpdate(
            baseQuery(account: account) as CFDictionary,
            [kSecValueData as String: data] as CFDictionary)

        if updateStatus == errSecSuccess { return }

        guard updateStatus == errSecItemNotFound else {
            if updateStatus == errSecUserCanceled || updateStatus == errSecAuthFailed {
                throw SecretStoreError.accessDenied(reason: Self.message(for: updateStatus))
            }
            throw SecretStoreError.writeFailed(reason: Self.message(for: updateStatus))
        }

        var attributes = baseQuery(account: account)
        attributes[kSecValueData as String] = data
        attributes[kSecAttrDescription as String] = "MCP server OAuth credential"
        // The credential is needed by a background MCP server launched at login,
        // so it must survive a locked screen — but it should never sync to iCloud
        // or leave this device in a backup.
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let addStatus = SecItemAdd(attributes as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw SecretStoreError.writeFailed(reason: Self.message(for: addStatus))
        }
    }

    public func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        // Not found means the caller's goal is already met.
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecretStoreError.writeFailed(reason: Self.message(for: status))
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    private static func message(for status: OSStatus) -> String {
        if let text = SecCopyErrorMessageString(status, nil) as String? {
            return "\(text) (OSStatus \(status))"
        }
        return "OSStatus \(status)"
    }
}
