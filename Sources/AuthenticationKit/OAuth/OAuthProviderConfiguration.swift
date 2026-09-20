import Foundation

/// Everything the server needs to talk to one authorization server.
///
/// Built from environment variables or CLI flags; see `README.md` for the full
/// list and `ServerConfiguration` for the parsing.
public struct OAuthProviderConfiguration: Sendable, Equatable {

    /// How this client authenticates to the token endpoint.
    ///
    /// OAuth 2.1 allows public clients (no secret) when PKCE is used. A server
    /// process that can hold a secret should use one; a locally installed stdio
    /// server generally cannot, and `.publicClient` is the honest choice there.
    public enum ClientAuthentication: Sendable, Equatable {
        /// `token_endpoint_auth_method=none`. Requires PKCE.
        case publicClient(clientID: String)
        /// `client_secret_basic` — credentials in the Authorization header.
        case clientSecretBasic(clientID: String, clientSecret: String)
        /// `client_secret_post` — credentials in the form body.
        case clientSecretPost(clientID: String, clientSecret: String)

        public var clientID: String {
            switch self {
            case .publicClient(let id): return id
            case .clientSecretBasic(let id, _): return id
            case .clientSecretPost(let id, _): return id
            }
        }

        public var clientSecret: String? {
            switch self {
            case .publicClient: return nil
            case .clientSecretBasic(_, let secret): return secret
            case .clientSecretPost(_, let secret): return secret
            }
        }
    }

    /// The issuer URL. Discovery documents are resolved relative to it.
    public let issuer: URL
    public let authentication: ClientAuthentication
    /// Scopes requested when the caller does not name any.
    public let defaultScopes: Set<Scope>
    /// RFC 8707 resource indicator, identifying the API the token is for.
    ///
    /// Sending it keeps the issued token audience-restricted, so a token minted for
    /// this server cannot be replayed against a different API on the same issuer.
    public let resourceIndicator: URL?
    /// Endpoints to use instead of the discovered ones. Useful for providers whose
    /// published metadata is incomplete.
    public let endpointOverrides: EndpointOverrides
    /// Loopback port for the browser redirect. `0` asks the OS for a free port,
    /// which is the RFC 8252 §7.3 recommendation.
    public let loopbackPort: UInt16
    /// How long a user has to complete an interactive authorization.
    public let authorizationTimeout: TimeInterval
    /// Whether to open the system browser automatically for the `browser` mode.
    public let opensBrowserAutomatically: Bool

    /// Extra query parameters appended to the authorization request.
    ///
    /// The authorization endpoint is where providers put their non-standard
    /// knobs, and two of Google's are load-bearing:
    ///
    /// - `access_type=offline` — without it Google returns **no refresh token**,
    ///   so the sign-in silently stops working once the access token expires.
    /// - `prompt=consent` — without it a user who has already consented gets no
    ///   *new* refresh token on a later authorization, which is why this tends to
    ///   work in testing and fail for returning users.
    ///
    /// Applies to the authorization-code flow only; the device grant has its own
    /// endpoint and does not take these.
    public let additionalAuthorizationParameters: [String: String]

    public struct EndpointOverrides: Sendable, Equatable {
        public var authorizationEndpoint: URL?
        public var tokenEndpoint: URL?
        public var deviceAuthorizationEndpoint: URL?
        public var revocationEndpoint: URL?

        public init(
            authorizationEndpoint: URL? = nil,
            tokenEndpoint: URL? = nil,
            deviceAuthorizationEndpoint: URL? = nil,
            revocationEndpoint: URL? = nil
        ) {
            self.authorizationEndpoint = authorizationEndpoint
            self.tokenEndpoint = tokenEndpoint
            self.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint
            self.revocationEndpoint = revocationEndpoint
        }

        public static let none = EndpointOverrides()
    }

    public init(
        issuer: URL,
        authentication: ClientAuthentication,
        defaultScopes: Set<Scope> = Scope.defaults,
        resourceIndicator: URL? = nil,
        endpointOverrides: EndpointOverrides = .none,
        loopbackPort: UInt16 = 0,
        authorizationTimeout: TimeInterval = 300,
        opensBrowserAutomatically: Bool = true,
        additionalAuthorizationParameters: [String: String] = [:]
    ) {
        self.issuer = issuer
        self.authentication = authentication
        self.defaultScopes = defaultScopes
        self.resourceIndicator = resourceIndicator
        self.endpointOverrides = endpointOverrides
        self.loopbackPort = loopbackPort
        self.authorizationTimeout = authorizationTimeout
        self.opensBrowserAutomatically = opensBrowserAutomatically
        self.additionalAuthorizationParameters = additionalAuthorizationParameters
    }

    // MARK: - Provider presets

    /// Configuration for Google as the identity provider.
    ///
    /// Google publishes full OIDC discovery at `accounts.google.com`, so the
    /// endpoints are found automatically. Two things are worth knowing:
    ///
    /// - Google does **not** implement Dynamic Client Registration, so the client
    ///   must be pre-registered in the Google Cloud Console as a *Desktop app*.
    /// - Google issues a `client_secret` for desktop clients and its token
    ///   endpoint does not accept `none` authentication, so one must be sent.
    ///   That secret ships inside the binary and is not really a secret — PKCE is
    ///   what actually protects the flow. Treat it as a client identifier.
    public static func google(
        clientID: String,
        clientSecret: String,
        scopes: Set<Scope> = Scope.googleDefaults,
        loopbackPort: UInt16 = 0,
        opensBrowserAutomatically: Bool = true
    ) -> OAuthProviderConfiguration {
        OAuthProviderConfiguration(
            issuer: URL(string: "https://accounts.google.com")!,
            authentication: .clientSecretPost(clientID: clientID, clientSecret: clientSecret),
            defaultScopes: scopes,
            loopbackPort: loopbackPort,
            opensBrowserAutomatically: opensBrowserAutomatically,
            additionalAuthorizationParameters: [
                "access_type": "offline",
                "prompt": "consent",
            ])
    }

    /// Rejects configurations that cannot produce a working flow.
    public func validate() throws {
        guard let scheme = issuer.scheme?.lowercased() else {
            throw OAuthError.invalidConfiguration(reason: "issuer URL has no scheme")
        }
        // RFC 8252 §8.6 and OAuth 2.1 require TLS for the authorization server, with
        // loopback exempt so a locally hosted development server still works.
        let isLoopback = ["localhost", "127.0.0.1", "::1"].contains(issuer.host ?? "")
        guard scheme == "https" || (scheme == "http" && isLoopback) else {
            throw OAuthError.invalidConfiguration(
                reason: "issuer must use https (http is allowed only for loopback hosts)")
        }
        guard !authentication.clientID.isEmpty else {
            throw OAuthError.invalidConfiguration(reason: "client_id is empty")
        }
    }
}
