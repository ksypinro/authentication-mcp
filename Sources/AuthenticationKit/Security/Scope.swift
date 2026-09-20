import Foundation

/// An OAuth scope required by a tool.
///
/// Scopes are compared case-sensitively as the OAuth specs require, but this type
/// also understands two conventions that real authorization servers use:
///
/// - `*` grants everything.
/// - A trailing `:*` grants every action in a namespace, so `data:*` satisfies
///   both `data:read` and `data:write`.
public struct Scope: Hashable, Sendable, CustomStringConvertible, Codable {
    public let rawValue: String

    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    public var description: String { rawValue }

    // The scopes this server's own tools require.
    public static let dataRead = Scope("data:read")
    public static let dataWrite = Scope("data:write")

    /// The default scope set requested when the caller does not name any.
    public static let defaults: Set<Scope> = [.dataRead, .dataWrite]

    // OpenID Connect scopes, which Google and most OIDC providers understand.
    public static let openID = Scope("openid")
    public static let email = Scope("email")
    public static let profile = Scope("profile")

    /// The minimum useful Google scope set: enough to learn who signed in.
    ///
    /// `openid` and `email` are what populate the ID token's `sub` and email, and
    /// the email is what the credential is filed under. Add API scopes such as
    /// `https://www.googleapis.com/auth/drive.readonly` on top.
    public static let googleDefaults: Set<Scope> = [.openID, .email, .profile]

    /// Whether a set of granted scopes satisfies this one.
    public func isSatisfied(by granted: Set<Scope>) -> Bool {
        if granted.contains(self) { return true }
        if granted.contains(Scope("*")) { return true }

        // Namespace wildcard: `data:*` covers `data:read`.
        guard let separatorIndex = rawValue.lastIndex(of: ":") else { return false }
        let namespace = rawValue[rawValue.startIndex..<separatorIndex]
        return granted.contains(Scope("\(namespace):*"))
    }
}

extension Set where Element == Scope {
    /// Parses the space-separated scope string used in OAuth requests and responses.
    public init(scopeString: String) {
        let parts = scopeString.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" })
        self = Set(parts.map { Scope(String($0)) })
    }

    /// Serializes to the space-separated form, sorted so the output is stable.
    public var scopeString: String {
        map(\.rawValue).sorted().joined(separator: " ")
    }

    public var sortedRawValues: [String] {
        map(\.rawValue).sorted()
    }
}

/// Which scope each data operation requires.
///
/// Configurable because the right answer depends entirely on the provider. The
/// defaults (`data:read` / `data:write`) suit an authorization server you
/// control. Google will never issue those, so a Google deployment must either
/// map these onto real Google scopes — `https://www.googleapis.com/auth/drive.readonly`,
/// say — or set ``unrestricted`` and let the upstream API be the authority on
/// what the token may do.
public struct ScopePolicy: Sendable, Equatable {
    /// The scope `fetchData` requires. `nil` means no local check.
    public var read: Scope?
    /// The scope `updatedData` requires. `nil` means no local check.
    public var write: Scope?

    public init(read: Scope?, write: Scope?) {
        self.read = read
        self.write = write
    }

    /// The built-in scopes, for an authorization server you configure yourself.
    public static let `default` = ScopePolicy(read: .dataRead, write: .dataWrite)

    /// No local scope enforcement.
    ///
    /// Correct when the upstream API enforces its own authorization — checking a
    /// scope this server cannot interpret would only produce false refusals.
    public static let unrestricted = ScopePolicy(read: nil, write: nil)
}
