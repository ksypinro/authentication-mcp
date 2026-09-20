import AuthenticationKit
import Foundation
import Logging

/// Reads the server's configuration from the environment.
///
/// Secrets belong in the environment rather than in flags: command lines are
/// visible to every process on the machine through `ps`, and MCP clients store
/// their server configuration as an `env` block anyway.
enum EnvironmentConfiguration {

    static func value(_ key: String) -> String? {
        guard let raw = ProcessInfo.processInfo.environment[key] else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    static func flag(_ key: String, default defaultValue: Bool) -> Bool {
        guard let raw = value(key)?.lowercased() else { return defaultValue }
        return ["1", "true", "yes", "on"].contains(raw)
    }

    static func url(_ key: String) throws -> URL? {
        guard let raw = value(key) else { return nil }
        guard let url = URL(string: raw), url.scheme != nil else {
            throw ConfigurationError("\(key) is not a valid absolute URL: '\(raw)'")
        }
        return url
    }

    /// Parses `a=1,b=2` into a dictionary, for provider-specific knobs.
    static func keyValuePairs(_ key: String) -> [String: String] {
        guard let raw = value(key) else { return [:] }
        var result: [String: String] = [:]
        for pair in raw.split(separator: ",") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            result[String(parts[0]).trimmingCharacters(in: .whitespaces)] =
                String(parts[1]).trimmingCharacters(in: .whitespaces)
        }
        return result
    }

    static func list(_ key: String) -> [String]? {
        value(key)?
            .split(whereSeparator: { $0 == "," || $0 == " " })
            .map(String.init)
    }

    // MARK: - Assembled options

    /// Builds the whole `ServiceOptions` graph from the environment.
    ///
    /// - Parameters:
    ///   - persistCredentialsByDefault: whether persistence is on when
    ///     `AUTH_MCP_PERSIST_CREDENTIALS` is unset. True for stdio, false for
    ///     HTTP, where there is no single user to store a credential for.
    ///   - forcePersistence: the `auth` subcommands require a credential store,
    ///     so they override the environment rather than fail confusingly.
    static func serviceOptions(
        canReachUserBrowser: Bool,
        persistCredentialsByDefault: Bool,
        forcePersistence: Bool = false
    ) throws -> ServiceOptions {
        let provider = try providerSelection(canReachUserBrowser: canReachUserBrowser)

        let persist =
            forcePersistence || flag("AUTH_MCP_PERSIST_CREDENTIALS", default: persistCredentialsByDefault)

        var credentials = CredentialPersistence.disabled
        if persist {
            let issuer: URL
            if case .oauth(let configuration) = provider {
                issuer = configuration.issuer
            } else {
                issuer = URL(string: "https://mock.invalid")!
            }

            let backend = try credentialBackend()
            if let directory = value("AUTH_MCP_CREDENTIAL_DIR") {
                let url = URL(
                    fileURLWithPath: (directory as NSString).expandingTildeInPath)
                credentials = .enabled(
                    directory: url,
                    backend: backend,
                    serviceName: "authentication-mcp:\(issuer.host ?? "default")")
            } else {
                credentials = .standard(issuer: issuer, backend: backend)
            }
        }

        return ServiceOptions(
            provider: provider,
            dataStore: try dataStoreSelection(),
            defaultScopes: scopes(),
            canReachUserBrowser: canReachUserBrowser,
            credentials: credentials,
            scopePolicy: scopePolicy(for: provider))
    }

    static func credentialBackend() throws -> CredentialStore.Backend? {
        guard let raw = value("AUTH_MCP_CREDENTIAL_BACKEND")?.lowercased() else { return nil }
        guard let backend = CredentialStore.Backend(rawValue: raw) else {
            throw ConfigurationError(
                "AUTH_MCP_CREDENTIAL_BACKEND must be keychain, file, or memory — got '\(raw)'.")
        }
        return backend
    }

    /// Which scope each data tool requires.
    ///
    /// The built-in `data:read` / `data:write` only make sense against an
    /// authorization server you configure. Google will never issue them, so a
    /// Google deployment defaults to no local scope check and lets the upstream
    /// API be the authority — otherwise every call would fail on a scope the
    /// provider cannot grant.
    static func scopePolicy(for provider: ProviderSelection) -> ScopePolicy {
        func scope(_ key: String, default defaultValue: Scope?) -> Scope? {
            guard let raw = value(key) else { return defaultValue }
            let normalized = raw.lowercased()
            if normalized == "none" || normalized == "off" { return nil }
            return Scope(raw)
        }

        let isGoogle: Bool
        if case .oauth(let configuration) = provider {
            isGoogle = configuration.issuer.host == "accounts.google.com"
        } else {
            isGoogle = false
        }

        let defaults: ScopePolicy = isGoogle ? .unrestricted : .default
        return ScopePolicy(
            read: scope("AUTH_MCP_SCOPE_READ", default: defaults.read),
            write: scope("AUTH_MCP_SCOPE_WRITE", default: defaults.write))
    }

    // MARK: - Provider

    /// Builds the provider selection from `AUTH_MCP_PROVIDER` and its companions.
    static func providerSelection(
        canReachUserBrowser: Bool
    ) throws -> ProviderSelection {
        let kind = value("AUTH_MCP_PROVIDER")?.lowercased() ?? "oauth"

        switch kind {
        case "mock":
            return .mock(try mockPolicy())

        case "google":
            guard let clientID = value("AUTH_MCP_GOOGLE_CLIENT_ID") else {
                throw ConfigurationError(
                    """
                    AUTH_MCP_GOOGLE_CLIENT_ID is required when AUTH_MCP_PROVIDER is 'google'.
                    Create an OAuth client of type 'Desktop app' in the Google Cloud Console,
                    under APIs & Services -> Credentials.
                    """)
            }
            guard let clientSecret = value("AUTH_MCP_GOOGLE_CLIENT_SECRET") else {
                throw ConfigurationError(
                    """
                    AUTH_MCP_GOOGLE_CLIENT_SECRET is required. Google issues one even for
                    desktop clients, and its token endpoint does not accept 'none'
                    authentication. It ships inside the binary and is not truly secret;
                    PKCE is what protects the flow.
                    """)
            }

            let configuration = OAuthProviderConfiguration.google(
                clientID: clientID,
                clientSecret: clientSecret,
                scopes: list("AUTH_MCP_OAUTH_SCOPES").map { Set($0.map(Scope.init)) }
                    ?? Scope.googleDefaults,
                loopbackPort: UInt16(value("AUTH_MCP_OAUTH_LOOPBACK_PORT").flatMap(Int.init) ?? 0),
                opensBrowserAutomatically: flag(
                    "AUTH_MCP_OAUTH_OPEN_BROWSER", default: canReachUserBrowser))
            do {
                try configuration.validate()
            } catch {
                throw ConfigurationError(error.localizedDescription)
            }
            return .oauth(configuration)

        case "oauth":
            guard let issuer = try url("AUTH_MCP_OAUTH_ISSUER") else {
                throw ConfigurationError(
                    """
                    AUTH_MCP_OAUTH_ISSUER is required when AUTH_MCP_PROVIDER is 'oauth'. \
                    Set it to your authorization server's issuer URL, or set \
                    AUTH_MCP_PROVIDER=mock to run without one.
                    """)
            }
            guard let clientID = value("AUTH_MCP_OAUTH_CLIENT_ID") else {
                throw ConfigurationError("AUTH_MCP_OAUTH_CLIENT_ID is required for 'oauth'.")
            }

            let secret = value("AUTH_MCP_OAUTH_CLIENT_SECRET")
            let method = value("AUTH_MCP_OAUTH_AUTH_METHOD")?.lowercased()
                ?? (secret == nil ? "none" : "basic")

            let authentication: OAuthProviderConfiguration.ClientAuthentication
            switch method {
            case "none":
                authentication = .publicClient(clientID: clientID)
            case "basic", "client_secret_basic":
                guard let secret else {
                    throw ConfigurationError(
                        "AUTH_MCP_OAUTH_CLIENT_SECRET is required for auth method '\(method)'.")
                }
                authentication = .clientSecretBasic(clientID: clientID, clientSecret: secret)
            case "post", "client_secret_post":
                guard let secret else {
                    throw ConfigurationError(
                        "AUTH_MCP_OAUTH_CLIENT_SECRET is required for auth method '\(method)'.")
                }
                authentication = .clientSecretPost(clientID: clientID, clientSecret: secret)
            default:
                throw ConfigurationError(
                    "AUTH_MCP_OAUTH_AUTH_METHOD must be one of none, basic, post — got '\(method)'.")
            }

            let overrides = OAuthProviderConfiguration.EndpointOverrides(
                authorizationEndpoint: try url("AUTH_MCP_OAUTH_AUTHORIZATION_ENDPOINT"),
                tokenEndpoint: try url("AUTH_MCP_OAUTH_TOKEN_ENDPOINT"),
                deviceAuthorizationEndpoint: try url("AUTH_MCP_OAUTH_DEVICE_ENDPOINT"),
                revocationEndpoint: try url("AUTH_MCP_OAUTH_REVOCATION_ENDPOINT"))

            let configuration = OAuthProviderConfiguration(
                issuer: issuer,
                authentication: authentication,
                defaultScopes: scopes(),
                resourceIndicator: try url("AUTH_MCP_OAUTH_RESOURCE"),
                endpointOverrides: overrides,
                loopbackPort: UInt16(value("AUTH_MCP_OAUTH_LOOPBACK_PORT").flatMap(Int.init) ?? 0),
                authorizationTimeout: TimeInterval(
                    value("AUTH_MCP_OAUTH_TIMEOUT_SECONDS").flatMap(Int.init) ?? 300),
                opensBrowserAutomatically: flag(
                    "AUTH_MCP_OAUTH_OPEN_BROWSER", default: canReachUserBrowser),
                additionalAuthorizationParameters: keyValuePairs(
                    "AUTH_MCP_OAUTH_EXTRA_AUTH_PARAMS"))

            do {
                try configuration.validate()
            } catch {
                throw ConfigurationError(error.localizedDescription)
            }
            return .oauth(configuration)

        default:
            throw ConfigurationError(
                "AUTH_MCP_PROVIDER must be 'oauth', 'google', or 'mock' — got '\(kind)'.")
        }
    }

    private static func mockPolicy() throws -> MockAuthorizationProvider.ApprovalPolicy {
        guard let raw = value("AUTH_MCP_MOCK_POLICY")?.lowercased() else { return .immediate }
        switch raw {
        case "immediate": return .immediate
        case "manual": return .manual
        case "deny", "denied": return .denied(reason: "the mock provider is configured to deny")
        default:
            // "delay:15"
            let parts = raw.split(separator: ":")
            if parts.count == 2, parts[0] == "delay", let seconds = Double(parts[1]) {
                return .afterDelay(seconds)
            }
            throw ConfigurationError(
                "AUTH_MCP_MOCK_POLICY must be immediate, manual, deny, or delay:<seconds>.")
        }
    }

    static func scopes() -> Set<Scope> {
        guard let raw = list("AUTH_MCP_OAUTH_SCOPES") else { return Scope.defaults }
        return Set(raw.map(Scope.init))
    }

    // MARK: - Data store

    static func dataStoreSelection() throws -> DataStoreSelection {
        let kind = value("AUTH_MCP_STORE")?.lowercased() ?? "memory"
        switch kind {
        case "memory", "in-memory":
            return .inMemory
        case "file":
            let path = value("AUTH_MCP_STORE_PATH")
                ?? FileManager.default.currentDirectoryPath + "/.authentication-service/records"
            return .directory(URL(fileURLWithPath: (path as NSString).expandingTildeInPath))
        default:
            throw ConfigurationError("AUTH_MCP_STORE must be 'memory' or 'file' — got '\(kind)'.")
        }
    }
}

/// A configuration problem, reported with enough detail to fix it.
struct ConfigurationError: Error, LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? { message }
}
