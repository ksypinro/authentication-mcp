import MCP
import Testing

@testable import AuthenticationHTTP

@Suite("Host allowlist")
struct HostAllowlistTests {

    /// Runs a request with the given headers through the SDK's real
    /// `OriginValidator`, built the same way `MCPHTTPHost` builds it.
    /// Returns the HTTP status it would reject with, or `nil` when accepted.
    private func status(
        host: String?, origin: String? = nil, allowlist: HostAllowlist?
    ) -> Int? {
        let validator = allowlist.map {
            OriginValidator(allowedHosts: $0.hosts, allowedOrigins: $0.origins)
        } ?? .disabled

        var headers: [String: String] = [:]
        if let host { headers["Host"] = host }
        if let origin { headers["Origin"] = origin }

        return validator.validate(
            HTTPRequest(method: "POST", headers: headers),
            context: HTTPValidationContext(httpMethod: "POST")
        )?.statusCode
    }

    // MARK: - The bug this type exists to fix

    @Test("A schemed entry, as the README documents it, accepts the Host header")
    func schemedEntryAcceptsHost() {
        let allowlist = HostAllowlist.make(
            entries: ["http://192.168.0.225:8080"], bindHost: "0.0.0.0", port: 8080)

        // Before the fix this was a 421 on every request.
        #expect(status(host: "192.168.0.225:8080", allowlist: allowlist) == nil)
    }

    @Test("A bare entry accepts a browser's Origin header")
    func bareEntryAcceptsOrigin() {
        let allowlist = HostAllowlist.make(
            entries: ["192.168.0.225:8080"], bindHost: "0.0.0.0", port: 8080)

        // Before the fix this was a 403 for any browser-based client.
        #expect(
            status(host: "192.168.0.225:8080", origin: "http://192.168.0.225:8080",
                   allowlist: allowlist) == nil)
    }

    @Test("Either spelling produces the same allowlist")
    func spellingsAreEquivalent() {
        let schemed = HostAllowlist.make(
            entries: ["http://mymac.local:8080"], bindHost: "0.0.0.0", port: 8080)
        let bare = HostAllowlist.make(
            entries: ["mymac.local:8080"], bindHost: "0.0.0.0", port: 8080)
        #expect(schemed == bare)
    }

    // MARK: - DNS rebinding is still refused

    @Test("A name that is not on the list is refused", arguments: [
        "evil.example:8080", "192.168.0.99:8080", "192.168.0.225:9999",
    ])
    func unlistedHostIsRefused(_ host: String) {
        let allowlist = HostAllowlist.make(
            entries: ["192.168.0.225:8080"], bindHost: "0.0.0.0", port: 8080)
        #expect(status(host: host, allowlist: allowlist) == 421)
    }

    @Test("A foreign browser Origin is refused even when the Host is right")
    func foreignOriginIsRefused() {
        let allowlist = HostAllowlist.make(
            entries: ["192.168.0.225:8080"], bindHost: "0.0.0.0", port: 8080)
        #expect(
            status(host: "192.168.0.225:8080", origin: "https://evil.example",
                   allowlist: allowlist) == 403)
    }

    // MARK: - Defaults

    @Test("Binding one specific address allows exactly that address, unconfigured")
    func specificBindDerivesItsOwnAddress() throws {
        let allowlist = try #require(
            HostAllowlist.make(entries: [], bindHost: "192.168.0.225", port: 8080))
        #expect(status(host: "192.168.0.225:8080", allowlist: allowlist) == nil)
        #expect(status(host: "evil.example:8080", allowlist: allowlist) == 421)
    }

    @Test("The bound address stays allowed when other names are configured too")
    func boundAddressSurvivesConfiguredNames() {
        // Binding 192.168.0.225 and also listing the .local name must not make
        // the IP itself start failing with 421.
        let allowlist = HostAllowlist.make(
            entries: ["mymac.local:8080"], bindHost: "192.168.0.225", port: 8080)
        #expect(status(host: "192.168.0.225:8080", allowlist: allowlist) == nil)
        #expect(status(host: "mymac.local:8080", allowlist: allowlist) == nil)
        #expect(status(host: "evil.example:8080", allowlist: allowlist) == 421)
    }

    @Test("A wildcard bind with nothing configured cannot derive a list")
    func wildcardBindReturnsNil() {
        #expect(HostAllowlist.make(entries: [], bindHost: "0.0.0.0", port: 8080) == nil)
        #expect(HostAllowlist.make(entries: [], bindHost: "::", port: 8080) == nil)
    }

    @Test("Loopback stays reachable whatever else is configured")
    func loopbackAlwaysAllowed() {
        let allowlist = HostAllowlist.make(
            entries: ["192.168.0.225:8080"], bindHost: "0.0.0.0", port: 8080)
        #expect(status(host: "127.0.0.1:8080", allowlist: allowlist) == nil)
        #expect(status(host: "localhost:8080", allowlist: allowlist) == nil)
    }

    @Test("The loopback default matches the SDK's own localhost validator")
    func loopbackBindKeepsPreviousBehavior() {
        let allowlist = HostAllowlist.make(entries: [], bindHost: "127.0.0.1", port: 8080)
        #expect(status(host: "localhost:8080", allowlist: allowlist) == nil)
        #expect(status(host: "192.168.0.225:8080", allowlist: allowlist) == 421)
    }

    // MARK: - Spelling details

    @Test("Mixed-case .local names match whichever case the client sends")
    func caseVariantsAccepted() {
        let allowlist = HostAllowlist.make(
            entries: ["Kazis-MacBook-Pro.local:8080"], bindHost: "0.0.0.0", port: 8080)
        #expect(status(host: "Kazis-MacBook-Pro.local:8080", allowlist: allowlist) == nil)
        #expect(status(host: "kazis-macbook-pro.local:8080", allowlist: allowlist) == nil)
    }

    @Test("An entry with no port matches any port, for a proxy on 443")
    func portlessEntryMatchesAnyPort() {
        let allowlist = HostAllowlist.make(
            entries: ["https://mymac.local"], bindHost: "127.0.0.1", port: 8080)
        #expect(status(host: "mymac.local", allowlist: allowlist) == nil)
        #expect(status(host: "mymac.local:8443", allowlist: allowlist) == nil)
        #expect(
            status(host: "mymac.local", origin: "https://mymac.local",
                   allowlist: allowlist) == nil)
    }

    @Test("Port detection is not fooled by IPv6 colons")
    func ipv6PortDetection() {
        #expect(HostAllowlist.hasPort("[::1]:8080"))
        #expect(!HostAllowlist.hasPort("[::1]"))
        #expect(HostAllowlist.hasPort("mymac.local:*"))
        #expect(!HostAllowlist.hasPort("mymac.local"))
    }

    @Test("A trailing path in an entry is ignored")
    func pathIsStripped() {
        #expect(HostAllowlist.authority(from: "http://192.168.0.225:8080/mcp") == "192.168.0.225:8080")
    }
}
