import ArgumentParser
import AuthenticationKit
import Foundation
import Logging

/// Shared plumbing for the subcommands: logging, assembly, and output.
enum CommandSupport {

    /// Bootstraps logging to stderr.
    ///
    /// `default` differs per command: the server wants `info`, while `auth status`
    /// should print nothing but its own report unless something is wrong.
    static func bootstrapLogging(level: String?, default defaultLevel: Logger.Level = .info)
        -> Logger
    {
        let resolved =
            level.flatMap { Logger.Level(rawValue: $0.lowercased()) }
            ?? EnvironmentConfiguration.value("AUTH_MCP_LOG_LEVEL")
                .flatMap { Logger.Level(rawValue: $0.lowercased()) }
            ?? defaultLevel

        LoggingBootstrap.configure(level: resolved)
        var logger = Logger(label: "authentication-service")
        logger[metadataKey: "version"] = .string(AuthenticationMCPServer.version)
        return logger
    }

    /// Builds the coordinator the `auth` subcommands drive.
    ///
    /// Persistence is forced on here: an `auth` command that did not persist
    /// would have no observable effect.
    static func makeCoordinator(logger: Logger) async throws -> AuthenticationCoordinator {
        let options = try EnvironmentConfiguration.serviceOptions(
            canReachUserBrowser: true,
            persistCredentialsByDefault: true,
            forcePersistence: true)
        let assembly = try ServiceAssembly.make(options: options, logger: logger)

        guard let coordinator = assembly.coordinator else {
            throw ConfigurationError(
                "Credential storage is disabled, so there is nothing for `auth` to act on. "
                    + "Unset AUTH_MCP_PERSIST_CREDENTIALS, or set it to true.")
        }
        return coordinator
    }

    // MARK: - Sign-in output

    /// Tells the user what to do to finish signing in.
    ///
    /// Goes to stderr so that stdout stays clean for the result, which keeps
    /// `auth login` usable in a pipeline.
    static func describe(_ interaction: UserInteraction) {
        var lines: [String] = []

        if let code = interaction.userCode {
            let url = (interaction.verificationURLComplete ?? interaction.verificationURL)
                .absoluteString
            lines.append("! First copy your one-time code: \(code)")
            lines.append("  Open \(url) and enter it to sign in.")
        } else {
            lines.append("  Opening \(interaction.verificationURL.absoluteString)")
            lines.append("  Approve the sign-in in your browser.")
            lines.append("  If no window opened, paste the URL above into a browser.")
        }

        FileHandle.standardError.write(Data((lines.joined(separator: "\n") + "\n").utf8))
    }

    /// A dot-per-poll progress line on stderr.
    ///
    /// The sign-in callback is `@Sendable`, so its state cannot be a captured
    /// local variable; this holds it behind a lock instead.
    final class WaitingIndicator: @unchecked Sendable {
        private let lock = NSLock()
        private var hasStarted = false

        func tick() {
            let isFirst: Bool = lock.withLock {
                defer { hasStarted = true }
                return !hasStarted
            }
            FileHandle.standardError.write(Data((isFirst ? "Waiting." : ".").utf8))
        }

        func finish() {
            let needsNewline: Bool = lock.withLock { hasStarted }
            if needsNewline {
                FileHandle.standardError.write(Data("\n".utf8))
            }
        }
    }

    // MARK: - Status output

    static func printStatusText(
        accounts: [CredentialIndexEntry],
        active: String?,
        location: String
    ) {
        guard !accounts.isEmpty else {
            print("Not signed in.")
            print("  Run `authentication-mcp auth login` to sign in.")
            print("  Storage: \(location)")
            return
        }

        // Grouped by issuer, the way `gh auth status` groups by host.
        let byIssuer = Dictionary(grouping: accounts) { $0.issuer.host ?? $0.issuer.absoluteString }
        for issuer in byIssuer.keys.sorted() {
            print(issuer)
            for entry in byIssuer[issuer] ?? [] {
                let isActive = entry.account == active
                print("  ✓ Signed in as \(entry.account)")
                print("  - Active account: \(isActive)")
                if let name = entry.principalName, name != entry.account {
                    print("  - Name: \(name)")
                }
                print("  - Subject: \(entry.subject)")
                print("  - Scopes: \(entry.scopes.joined(separator: ", "))")
                print("  - Access token: \(describeExpiry(entry.accessTokenExpiresAt))")
                print(
                    "  - Refresh token: "
                        + (entry.hasRefreshToken
                            ? "present (stays signed in)"
                            : "MISSING — this sign-in will stop working at expiry"))
                print("  - Signed in since: \(Timestamps.string(from: entry.obtainedAt))")
            }
        }
        print("  Storage: \(location)")
    }

    /// Renders an access-token expiry the way a person reads it.
    private static func describeExpiry(_ expiresAt: Date?) -> String {
        guard let expiresAt else { return "no expiry reported" }
        let remaining = expiresAt.timeIntervalSinceNow
        guard remaining > 0 else {
            // Expected and harmless: the next call refreshes it.
            return "expired (will be renewed on next use)"
        }
        let minutes = Int(remaining / 60)
        return minutes >= 60
            ? "valid for \(minutes / 60)h \(minutes % 60)m"
            : "valid for \(minutes)m"
    }

    static func printStatusJSON(
        accounts: [CredentialIndexEntry],
        active: String?,
        location: String
    ) throws {
        let payload: [String: Any] = [
            "signed_in": !accounts.isEmpty,
            "active_account": active as Any,
            "storage": location,
            "accounts": accounts.map { entry in
                [
                    "account": entry.account,
                    "subject": entry.subject,
                    "principal_name": entry.principalName as Any,
                    "issuer": entry.issuer.absoluteString,
                    "scopes": entry.scopes,
                    "obtained_at": Timestamps.string(from: entry.obtainedAt),
                    "updated_at": Timestamps.string(from: entry.updatedAt),
                    "access_token_expires_at": entry.accessTokenExpiresAt
                        .map(Timestamps.string(from:)) as Any,
                    "has_refresh_token": entry.hasRefreshToken,
                    "is_active": entry.account == active,
                ]
            },
        ]
        let data = try JSONSerialization.data(
            withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        print(String(data: data, encoding: .utf8) ?? "{}")
    }

    // MARK: - Configuration summary

    static func printConfigurationSummary(
        options: ServiceOptions,
        transportName: String
    ) throws {
        var lines: [String] = ["Configuration OK", ""]
        lines.append("  transport:      \(transportName)")

        switch options.provider {
        case .oauth(let configuration):
            lines.append("  provider:       oauth")
            lines.append("  issuer:         \(configuration.issuer.absoluteString)")
            lines.append("  client_id:      \(configuration.authentication.clientID)")
            let method: String
            switch configuration.authentication {
            case .publicClient: method = "none (public client, PKCE required)"
            case .clientSecretBasic: method = "client_secret_basic"
            case .clientSecretPost: method = "client_secret_post"
            }
            lines.append("  auth method:    \(method)")
            if let resource = configuration.resourceIndicator {
                lines.append("  resource:       \(resource.absoluteString)")
            }
            if !configuration.additionalAuthorizationParameters.isEmpty {
                let extras = configuration.additionalAuthorizationParameters
                    .sorted { $0.key < $1.key }
                    .map { "\($0.key)=\($0.value)" }
                    .joined(separator: " ")
                lines.append("  extra auth params: \(extras)")
            }
        case .mock(let policy):
            lines.append("  provider:       mock (NOT FOR PRODUCTION) — policy \(policy)")
        }

        switch options.dataStore {
        case .inMemory: lines.append("  store:          in-memory (not durable)")
        case .directory(let url): lines.append("  store:          file at \(url.path)")
        case .custom: lines.append("  store:          custom")
        }

        switch options.credentials {
        case .disabled:
            lines.append("  credentials:    not persisted (sign-in ends with the process)")
        case .enabled(let directory, let backend, let serviceName):
            lines.append(
                "  credentials:    persisted — \(backend?.rawValue ?? "keychain, file fallback")")
            lines.append("  credential dir: \(directory.path)")
            lines.append("  keychain svc:   \(serviceName)")
        }

        lines.append("  default scopes: \(options.defaultScopes.scopeString)")
        let read = options.scopePolicy.read?.rawValue ?? "(none)"
        let write = options.scopePolicy.write?.rawValue ?? "(none)"
        lines.append("  required scopes: read=\(read) write=\(write)")
        lines.append("")
        lines.append("  tools:          \(ToolCatalog.Name.all.joined(separator: ", "))")

        // stdout is free here: --check never speaks JSON-RPC.
        print(lines.joined(separator: "\n"))
    }
}
