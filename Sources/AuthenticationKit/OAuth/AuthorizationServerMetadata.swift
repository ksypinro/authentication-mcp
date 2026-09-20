import Foundation

/// Authorization server metadata, as published at
/// `/.well-known/oauth-authorization-server` (RFC 8414) or
/// `/.well-known/openid-configuration` (OpenID Connect Discovery).
///
/// Only the fields this server acts on are modelled; unknown fields are ignored so
/// a provider adding new metadata does not break decoding.
public struct AuthorizationServerMetadata: Sendable, Codable, Equatable {
    public let issuer: URL
    public let authorizationEndpoint: URL?
    public let tokenEndpoint: URL?
    public let deviceAuthorizationEndpoint: URL?
    public let revocationEndpoint: URL?
    public let userinfoEndpoint: URL?
    public let registrationEndpoint: URL?
    public let scopesSupported: [String]?
    public let grantTypesSupported: [String]?
    public let codeChallengeMethodsSupported: [String]?
    public let tokenEndpointAuthMethodsSupported: [String]?

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case deviceAuthorizationEndpoint = "device_authorization_endpoint"
        case revocationEndpoint = "revocation_endpoint"
        case userinfoEndpoint = "userinfo_endpoint"
        case registrationEndpoint = "registration_endpoint"
        case scopesSupported = "scopes_supported"
        case grantTypesSupported = "grant_types_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
        case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
    }

    public init(
        issuer: URL,
        authorizationEndpoint: URL? = nil,
        tokenEndpoint: URL? = nil,
        deviceAuthorizationEndpoint: URL? = nil,
        revocationEndpoint: URL? = nil,
        userinfoEndpoint: URL? = nil,
        registrationEndpoint: URL? = nil,
        scopesSupported: [String]? = nil,
        grantTypesSupported: [String]? = nil,
        codeChallengeMethodsSupported: [String]? = nil,
        tokenEndpointAuthMethodsSupported: [String]? = nil
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.userinfoEndpoint = userinfoEndpoint
        self.registrationEndpoint = registrationEndpoint
        self.scopesSupported = scopesSupported
        self.grantTypesSupported = grantTypesSupported
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
        self.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
    }

    /// Whether the server advertises RFC 8628 device authorization.
    ///
    /// Some servers expose the endpoint without listing the grant, so the endpoint's
    /// presence alone is treated as support.
    public var supportsDeviceGrant: Bool {
        deviceAuthorizationEndpoint != nil
            || (grantTypesSupported?.contains(OAuthConstants.deviceCodeGrant) ?? false)
    }

    /// Whether the server advertises PKCE with S256.
    ///
    /// OAuth 2.1 requires PKCE for the authorization code grant. RFC 8414 says a
    /// server omitting `code_challenge_methods_supported` does not support PKCE,
    /// but many deployments omit it while supporting S256 — so absence is treated
    /// as unknown here and the flow continues, rather than refusing outright.
    public var declaresS256PKCE: Bool {
        codeChallengeMethodsSupported?.contains { $0.caseInsensitiveCompare("S256") == .orderedSame }
            ?? false
    }

    public var explicitlyRejectsS256PKCE: Bool {
        guard let methods = codeChallengeMethodsSupported, !methods.isEmpty else { return false }
        return !declaresS256PKCE
    }
}

/// String constants from the OAuth specifications, kept in one place so a typo in
/// a grant type surfaces at compile time rather than as a runtime rejection.
public enum OAuthConstants {
    public static let authorizationCodeGrant = "authorization_code"
    public static let refreshTokenGrant = "refresh_token"
    public static let deviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code"
    public static let clientCredentialsGrant = "client_credentials"

    // RFC 8628 §3.5 polling errors.
    public static let authorizationPending = "authorization_pending"
    public static let slowDown = "slow_down"
    public static let expiredToken = "expired_token"
    public static let accessDenied = "access_denied"

    // RFC 7009 token type hints.
    public static let accessTokenHint = "access_token"
    public static let refreshTokenHint = "refresh_token"

    public static let wellKnownOAuth = "/.well-known/oauth-authorization-server"
    public static let wellKnownOpenID = "/.well-known/openid-configuration"
}
