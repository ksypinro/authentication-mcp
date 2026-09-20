import Foundation

/// The credentials issued by an authorization server for one authenticated principal.
///
/// Instances never leave the server process. Tools hand callers an opaque session
/// id; the token material stays in ``SessionStore`` and is attached to upstream
/// requests by the server itself. See ``Redaction`` for the reasoning.
public struct TokenSet: Sendable, Codable, Equatable {
    public let accessToken: String
    public let tokenType: String
    public let refreshToken: String?
    /// The OIDC ID token, when the authorization server issued one.
    public let idToken: String?
    public let scopes: Set<Scope>
    public let issuedAt: Date
    public let expiresAt: Date?
    /// The `sub` claim identifying the authenticated principal.
    public let subject: String?
    /// A human-readable label for the principal (`preferred_username`, `email`, or `name`).
    public let principalName: String?
    /// The issuer this token came from, used to detect an authorization server swap.
    public let issuer: URL?

    public init(
        accessToken: String,
        tokenType: String = "Bearer",
        refreshToken: String? = nil,
        idToken: String? = nil,
        scopes: Set<Scope>,
        issuedAt: Date = Date(),
        expiresAt: Date? = nil,
        subject: String? = nil,
        principalName: String? = nil,
        issuer: URL? = nil
    ) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.scopes = scopes
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.subject = subject
        self.principalName = principalName
        self.issuer = issuer
    }

    /// Default clock-skew allowance when deciding whether a token is still usable.
    public static let expiryskew: TimeInterval = 30

    /// Whether the token is expired, or close enough that it should not be used.
    ///
    /// A token with no `expiresAt` never expires from this server's point of view;
    /// the upstream API remains the authority and a 401 will still be surfaced.
    public func isExpired(now: Date = Date(), skew: TimeInterval = TokenSet.expiryskew) -> Bool {
        guard let expiresAt else { return false }
        return now.addingTimeInterval(skew) >= expiresAt
    }

    /// Whether the token should be refreshed proactively, before it actually expires.
    ///
    /// Refreshing inside this window keeps a long `fetchData` call from failing
    /// halfway through because the token died mid-request.
    public func shouldRefresh(now: Date = Date(), window: TimeInterval = 120) -> Bool {
        guard refreshToken != nil, let expiresAt else { return false }
        return now.addingTimeInterval(window) >= expiresAt
    }

    public var secondsUntilExpiry: TimeInterval? {
        expiresAt.map { max(0, $0.timeIntervalSinceNow) }
    }

    /// Replaces the token material while keeping identity fields that a refresh
    /// response typically omits.
    ///
    /// Refresh responses often return only `access_token` and `expires_in`; RFC 6749
    /// §6 also allows the server to omit `scope` when it is unchanged, and to rotate
    /// or withhold the refresh token. Carrying the previous values forward keeps a
    /// refreshed session from silently losing its subject or its scopes.
    public func renewed(
        accessToken: String,
        tokenType: String?,
        refreshToken: String?,
        idToken: String?,
        scopes: Set<Scope>?,
        issuedAt: Date,
        expiresAt: Date?
    ) -> TokenSet {
        TokenSet(
            accessToken: accessToken,
            tokenType: tokenType ?? self.tokenType,
            refreshToken: refreshToken ?? self.refreshToken,
            idToken: idToken ?? self.idToken,
            scopes: scopes ?? self.scopes,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            subject: subject,
            principalName: principalName,
            issuer: issuer
        )
    }
}
