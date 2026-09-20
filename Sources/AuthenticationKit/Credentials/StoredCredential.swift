import Foundation

/// The non-secret half of a stored credential.
///
/// Kept separate from the token material on purpose. This half lives in a plain
/// JSON file so that `auth status` — and the server's own startup path — can
/// answer "who is signed in?" without touching the keychain, which on macOS may
/// prompt the user. `gh` makes the same split: `hosts.yml` holds the account
/// name and git protocol, while the token itself is a keychain item.
public struct CredentialIndexEntry: Codable, Sendable, Equatable {
    /// The key this credential is stored under: an email address when the
    /// provider supplies one, otherwise the subject identifier.
    public let account: String
    /// The `sub` claim — the provider's stable identifier for the principal.
    public let subject: String
    /// A display name, when the provider supplied one.
    public let principalName: String?
    public let issuer: URL
    public let scopes: [String]
    /// When the credential was first obtained, i.e. when the user signed in.
    public let obtainedAt: Date
    /// When the credential was last written, including silent refreshes.
    public let updatedAt: Date
    /// When the current access token expires. Lets `auth status` report
    /// freshness without reading the secret.
    public let accessTokenExpiresAt: Date?
    /// Whether a refresh token is held, i.e. whether the session renews itself.
    ///
    /// Surfaced because its absence is the single most common reason a sign-in
    /// that "worked" stops working an hour later.
    public let hasRefreshToken: Bool

    public init(
        account: String,
        subject: String,
        principalName: String?,
        issuer: URL,
        scopes: [String],
        obtainedAt: Date,
        updatedAt: Date,
        accessTokenExpiresAt: Date?,
        hasRefreshToken: Bool
    ) {
        self.account = account
        self.subject = subject
        self.principalName = principalName
        self.issuer = issuer
        self.scopes = scopes
        self.obtainedAt = obtainedAt
        self.updatedAt = updatedAt
        self.accessTokenExpiresAt = accessTokenExpiresAt
        self.hasRefreshToken = hasRefreshToken
    }
}

/// The secret half: everything that must never reach a log, a model, or a
/// world-readable file.
struct CredentialSecret: Codable, Sendable, Equatable {
    let accessToken: String
    let tokenType: String
    let refreshToken: String?
    let idToken: String?
}

/// A credential as the rest of the program uses it: index entry plus secret.
public struct StoredCredential: Sendable, Equatable {
    public let entry: CredentialIndexEntry
    let secret: CredentialSecret

    init(entry: CredentialIndexEntry, secret: CredentialSecret) {
        self.entry = entry
        self.secret = secret
    }

    public var account: String { entry.account }

    /// Rebuilds the in-memory token set the OAuth layer works with.
    public var tokens: TokenSet {
        TokenSet(
            accessToken: secret.accessToken,
            tokenType: secret.tokenType,
            refreshToken: secret.refreshToken,
            idToken: secret.idToken,
            scopes: Set(entry.scopes.map(Scope.init)),
            issuedAt: entry.updatedAt,
            expiresAt: entry.accessTokenExpiresAt,
            subject: entry.subject,
            principalName: entry.principalName,
            issuer: entry.issuer)
    }

    /// Builds a credential from a freshly issued token set.
    ///
    /// - Parameter previous: the credential being replaced, when this is a
    ///   refresh rather than a new sign-in. `obtainedAt` carries over from it so
    ///   "signed in since" keeps meaning the original sign-in.
    public static func make(
        from tokens: TokenSet,
        issuer: URL,
        previous: StoredCredential? = nil,
        now: Date = Date()
    ) -> StoredCredential {
        let account = Self.accountName(for: tokens, fallback: previous?.account)
        return StoredCredential(
            entry: CredentialIndexEntry(
                account: account,
                subject: tokens.subject ?? previous?.entry.subject ?? account,
                principalName: tokens.principalName ?? previous?.entry.principalName,
                issuer: tokens.issuer ?? issuer,
                scopes: tokens.scopes.sortedRawValues,
                obtainedAt: previous?.entry.obtainedAt ?? now,
                updatedAt: now,
                accessTokenExpiresAt: tokens.expiresAt,
                hasRefreshToken: tokens.refreshToken != nil),
            secret: CredentialSecret(
                accessToken: tokens.accessToken,
                tokenType: tokens.tokenType,
                refreshToken: tokens.refreshToken,
                idToken: tokens.idToken))
    }

    /// Picks the human-meaningful key to file a credential under.
    ///
    /// An email reads far better in `auth status` and in a keychain entry than an
    /// opaque subject id, so it wins when the ID token carried one.
    static func accountName(for tokens: TokenSet, fallback: String?) -> String {
        if let email = tokens.idToken
            .flatMap(JWTClaims.decodeUnverifiedPayload(of:))?
            .principalName, email.contains("@")
        {
            return email
        }
        if let name = tokens.principalName, name.contains("@") { return name }
        return tokens.subject ?? fallback ?? "default"
    }
}

/// The on-disk index: every known account plus which one is active.
struct CredentialIndex: Codable, Sendable {
    var activeAccount: String?
    var accounts: [String: CredentialIndexEntry]

    static let empty = CredentialIndex(activeAccount: nil, accounts: [:])
}
