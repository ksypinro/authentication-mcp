import ArgumentParser
import AuthenticationKit
import Foundation
import Logging

@main
struct AuthenticationMCPCommand: AsyncParsableCommand {

    static let configuration = CommandConfiguration(
        commandName: "authentication-mcp",
        abstract:
            "An MCP server exposing authenticate, revokeAuthentication, fetchData and updatedData.",
        discussion: """
            Credentials and endpoints are read from the environment; see README.md for \
            the full list.

            Sign in once from a terminal, and every later run — including the one your \
            MCP client launches — reuses the stored credential until you sign out:

              authentication-mcp auth login       # opens a browser, stores the credential
              authentication-mcp auth status      # who is signed in, and for how long
              authentication-mcp auth logout      # revoke and forget

            With no subcommand the server starts on stdio, which is what an MCP client \
            invokes.
            """,
        subcommands: [Serve.self, Auth.self],
        defaultSubcommand: Serve.self)
}

// MARK: - serve

struct Serve: AsyncParsableCommand {

    static let configuration = CommandConfiguration(
        commandName: "serve",
        abstract: "Run the MCP server.",
        discussion: """
            Examples:
              authentication-mcp                          # stdio, for a local MCP client
              authentication-mcp serve --transport http --port 8080
              AUTH_MCP_PROVIDER=mock authentication-mcp    # no identity provider needed
            """)

    enum TransportKind: String, ExpressibleByArgument, CaseIterable {
        case stdio
        case http
    }

    @Option(
        name: .long,
        help: "How clients connect: 'stdio' for a local client, 'http' for Streamable HTTP.")
    var transport: TransportKind?

    @Option(name: .long, help: "Interface to bind when serving HTTP.")
    var host: String?

    @Option(name: .long, help: "Port to bind when serving HTTP.")
    var port: Int?

    @Option(name: .long, help: "Path the MCP endpoint is served at.")
    var endpoint: String?

    @Option(name: .long, help: "Log level: trace, debug, info, notice, warning, error, critical.")
    var logLevel: String?

    @Flag(name: .long, help: "Validate the configuration, print a summary, and exit.")
    var check: Bool = false

    func run() async throws {
        let logger = CommandSupport.bootstrapLogging(level: logLevel)

        let resolvedTransport =
            transport
            ?? TransportKind(
                rawValue: EnvironmentConfiguration.value("AUTH_MCP_TRANSPORT")?.lowercased()
                    ?? "stdio")
            ?? .stdio

        // Over HTTP the server may be on a different machine from the user, so it
        // cannot assume it can open their browser; that forces `automatic` sign-in
        // onto the device grant.
        let canReachUserBrowser = resolvedTransport == .stdio

        let options = try EnvironmentConfiguration.serviceOptions(
            canReachUserBrowser: canReachUserBrowser,
            // A shared HTTP deployment has no single user to store a credential
            // for, so persistence is a stdio-only default.
            persistCredentialsByDefault: resolvedTransport == .stdio)

        if check {
            try CommandSupport.printConfigurationSummary(
                options: options, transportName: resolvedTransport.rawValue)
            return
        }

        let assembly = try ServiceAssembly.make(options: options, logger: logger)

        switch resolvedTransport {
        case .stdio:
            try await ServeRuntime.runStdio(assembly: assembly, logger: logger)
        case .http:
            try await ServeRuntime.runHTTP(
                assembly: assembly,
                host: host,
                port: port,
                endpoint: endpoint,
                logger: logger)
        }
    }
}

// MARK: - auth

struct Auth: AsyncParsableCommand {

    static let configuration = CommandConfiguration(
        commandName: "auth",
        abstract: "Sign in, sign out, and inspect stored credentials.",
        discussion: """
            Sign-in is deliberate and happens here, in a terminal — not silently \
            inside an assistant conversation. The credential is stored in the system \
            keychain where one is available, and the MCP server reads it on every run, \
            refreshing it silently, until you run `auth logout`.
            """,
        subcommands: [Login.self, Logout.self, Status.self],
        defaultSubcommand: Status.self)

    // MARK: login

    struct Login: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "login",
            abstract: "Sign in and store the credential.")

        @Option(
            name: .long,
            help: "Scopes to request, space- or comma-separated. Defaults to the configured set.")
        var scopes: String?

        @Flag(name: .long, help: "Show a code to enter on another device instead of opening a browser.")
        var device: Bool = false

        @Flag(name: .long, help: "Open a browser on this machine and catch the redirect on loopback.")
        var browser: Bool = false

        @Option(name: .long, help: "Seconds to wait for you to finish signing in.")
        var timeout: Int = 300

        @Option(name: .long, help: "Log level for diagnostics on stderr.")
        var logLevel: String?

        func run() async throws {
            let logger = CommandSupport.bootstrapLogging(level: logLevel, default: .warning)
            let coordinator = try await CommandSupport.makeCoordinator(logger: logger)

            if device && browser {
                throw ValidationError("Pass either --device or --browser, not both.")
            }
            let mode: AuthorizationMode = device ? .device : (browser ? .browser : .automatic)

            let requested: Set<Scope>? = scopes.map { raw in
                Set(
                    raw.split(whereSeparator: { $0 == " " || $0 == "," })
                        .map { Scope(String($0)) })
            }

            let waiting = CommandSupport.WaitingIndicator()
            let credential = try await coordinator.signIn(
                scopes: requested,
                mode: mode,
                timeout: TimeInterval(timeout)
            ) { progress in
                switch progress {
                case .awaitingUser(let interaction):
                    CommandSupport.describe(interaction)
                case .stillWaiting:
                    waiting.tick()
                }
            }
            waiting.finish()

            let location = await coordinator.storageDescription()
            print("✓ Signed in as \(credential.account)")
            if let name = credential.entry.principalName, name != credential.account {
                print("  Name:          \(name)")
            }
            print("  Scopes:        \(credential.entry.scopes.joined(separator: ", "))")
            print("  Stored in:     \(location)")

            if credential.entry.hasRefreshToken {
                print("  Stays signed in until you run `authentication-mcp auth logout`.")
            } else {
                // The difference between "works" and "works for an hour".
                print("""
                  ! No refresh token was issued, so this sign-in will stop working when the
                    access token expires. For Google, the authorization request needs
                    access_type=offline and prompt=consent.
                """)
            }
        }
    }

    // MARK: logout

    struct Logout: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "logout",
            abstract: "Revoke the stored credential and forget it.")

        @Option(name: .long, help: "The account to sign out. Defaults to the active one.")
        var account: String?

        @Flag(name: .long, help: "Sign out every stored account.")
        var all: Bool = false

        @Option(name: .long, help: "Log level for diagnostics on stderr.")
        var logLevel: String?

        func run() async throws {
            let logger = CommandSupport.bootstrapLogging(level: logLevel, default: .warning)
            let coordinator = try await CommandSupport.makeCoordinator(logger: logger)

            let report = try await coordinator.signOut(account: account, allAccounts: all)

            guard !report.isEmpty else {
                print("Not signed in; nothing to do.")
                return
            }

            for account in report.accounts {
                print("✓ Signed out \(account)")
            }

            // Be honest about the difference between "forgotten here" and
            // "revoked at the provider" — the tokens may still be live upstream.
            if let revocation = report.revocation, !revocation.isCompleteUpstream {
                print("""
                  ! The provider did not confirm revocation\
                \(revocation.failureReason.map { " (\($0))" } ?? "").
                    The credential is gone from this machine, but the tokens may stay
                    valid upstream until they expire.
                """)
            }
        }
    }

    // MARK: status

    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "status",
            abstract: "Show who is signed in.",
            discussion: """
                Exits non-zero when nothing is signed in, so it can gate a script.
                """)

        @Flag(name: .long, help: "Emit JSON instead of text.")
        var json: Bool = false

        @Option(name: .long, help: "Log level for diagnostics on stderr.")
        var logLevel: String?

        func run() async throws {
            let logger = CommandSupport.bootstrapLogging(level: logLevel, default: .critical)
            let coordinator = try await CommandSupport.makeCoordinator(logger: logger)

            // Reads the index only — no keychain access, so this never prompts.
            let accounts = try await coordinator.accounts()
            let active = try await coordinator.activeAccount()
            let location = await coordinator.storageDescription()

            if json {
                try CommandSupport.printStatusJSON(
                    accounts: accounts, active: active, location: location)
            } else {
                CommandSupport.printStatusText(
                    accounts: accounts, active: active, location: location)
            }

            guard !accounts.isEmpty else {
                throw ExitCode(1)
            }
        }
    }
}
