import Foundation
import Logging
import MCP

/// Which authorization provider to run with.
public enum ProviderSelection: Sendable {
    /// A real OAuth 2.1 authorization server.
    case oauth(OAuthProviderConfiguration)
    /// The in-process mock. Development and tests only.
    case mock(MockAuthorizationProvider.ApprovalPolicy)
}

/// Which data store to run with.
public enum DataStoreSelection: Sendable {
    /// Process-lifetime storage. The default.
    case inMemory
    /// One JSON file per record under this directory.
    case directory(URL)
    /// An implementation supplied by the host application.
    case custom(any DataStore)
}

/// Whether sign-in survives a restart, and where it is kept.
public enum CredentialPersistence: Sendable {
    /// Credentials live only as long as the process. Correct for a shared HTTP
    /// deployment, where there is no single user to store a credential for.
    case disabled
    /// Credentials are written to a keychain or file under `directory`.
    ///
    /// - Parameters:
    ///   - backend: force a specific store, or `nil` to prefer the keychain and
    ///     fall back to a file when none is available.
    ///   - serviceName: the keychain service name; include the provider host so
    ///     one binary can hold credentials for several providers.
    case enabled(directory: URL, backend: CredentialStore.Backend?, serviceName: String)

    /// Persistence under the platform config directory, keyed to an issuer.
    public static func standard(
        issuer: URL,
        applicationName: String = "authentication-mcp",
        backend: CredentialStore.Backend? = nil
    ) -> CredentialPersistence {
        let base = FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent(applicationName, isDirectory: true)
        let host = issuer.host ?? "default"
        return .enabled(
            directory: base,
            backend: backend,
            serviceName: "\(applicationName):\(host)")
    }
}

/// Everything needed to construct a running service.
public struct ServiceOptions: Sendable {
    public var provider: ProviderSelection
    public var dataStore: DataStoreSelection
    /// Scopes requested when a caller does not name any.
    public var defaultScopes: Set<Scope>
    /// How long a session may sit unused before it is dropped.
    public var sessionIdleTimeout: TimeInterval
    /// Whether this process can open the user's own browser. False for a remote
    /// HTTP deployment, which forces `automatic` mode onto the device grant.
    public var canReachUserBrowser: Bool
    /// Whether sign-in survives a restart.
    public var credentials: CredentialPersistence
    /// Which scope each data tool requires.
    public var scopePolicy: ScopePolicy

    public init(
        provider: ProviderSelection,
        dataStore: DataStoreSelection = .inMemory,
        defaultScopes: Set<Scope> = Scope.defaults,
        sessionIdleTimeout: TimeInterval = 86_400,
        canReachUserBrowser: Bool = true,
        credentials: CredentialPersistence = .disabled,
        scopePolicy: ScopePolicy = .default
    ) {
        self.provider = provider
        self.dataStore = dataStore
        self.defaultScopes = defaultScopes
        self.sessionIdleTimeout = sessionIdleTimeout
        self.canReachUserBrowser = canReachUserBrowser
        self.credentials = credentials
        self.scopePolicy = scopePolicy
    }

    /// The issuer these options authenticate against, when there is a real one.
    public var issuer: URL? {
        guard case .oauth(let configuration) = provider else { return nil }
        return configuration.issuer
    }
}

/// A constructed service and the collaborators worth holding onto.
///
/// The pieces are exposed rather than hidden so a host can run maintenance,
/// inspect the audit log, or drive the mock provider from a test.
public struct ServiceAssembly: Sendable {
    public let service: AuthenticationService
    public let sessionStore: SessionStore
    public let auditLog: AuditLog
    public let provider: any AuthorizationProvider
    public let dataStore: any DataStore
    /// Present when credentials persist; the `auth` subcommands drive this.
    public let coordinator: AuthenticationCoordinator?
    public let credentialStore: CredentialStore?

    /// Builds the whole object graph.
    public static func make(
        options: ServiceOptions,
        logger: Logger
    ) throws -> ServiceAssembly {
        // Tag audit output so it can be filtered out of ordinary diagnostics.
        var auditLogger = logger
        auditLogger[metadataKey: "component"] = "audit"
        let auditLog = AuditLog(logger: auditLogger)

        let provider: any AuthorizationProvider
        switch options.provider {
        case .oauth(let configuration):
            provider = try OAuthAuthorizationProvider(
                configuration: configuration,
                logger: logger,
                canReachUserBrowser: options.canReachUserBrowser)
        case .mock(let policy):
            logger.warning(
                """
                Using the in-process mock authorization provider. It issues tokens that \
                mean nothing to any real system — never run this in production.
                """)
            provider = MockAuthorizationProvider(policy: policy, logger: logger)
        }

        let dataStore: any DataStore
        switch options.dataStore {
        case .inMemory:
            dataStore = InMemoryDataStore()
        case .directory(let url):
            dataStore = try FileDataStore(directory: url)
        case .custom(let store):
            dataStore = store
        }

        var credentialStore: CredentialStore?
        var coordinator: AuthenticationCoordinator?

        if case .enabled(let directory, let backend, let serviceName) = options.credentials {
            let store = try CredentialStore.make(
                serviceName: serviceName,
                directory: directory,
                preferredBackend: backend,
                logger: logger)
            credentialStore = store
            coordinator = AuthenticationCoordinator(
                provider: provider,
                credentialStore: store,
                // The mock provider has no real issuer; a placeholder keeps the
                // credential well-formed without pretending it came from anywhere.
                issuer: options.issuer ?? URL(string: "https://mock.invalid")!,
                defaultScopes: options.defaultScopes,
                auditLog: auditLog,
                logger: logger)
        }

        let sessionStore = SessionStore(
            provider: provider,
            auditLog: auditLog,
            logger: logger,
            idleTimeout: options.sessionIdleTimeout,
            coordinator: coordinator)

        let service = AuthenticationService(
            provider: provider,
            sessionStore: sessionStore,
            dataStore: dataStore,
            auditLog: auditLog,
            logger: logger,
            defaultScopes: options.defaultScopes,
            scopePolicy: options.scopePolicy)

        return ServiceAssembly(
            service: service,
            sessionStore: sessionStore,
            auditLog: auditLog,
            provider: provider,
            dataStore: dataStore,
            coordinator: coordinator,
            credentialStore: credentialStore)
    }
}
