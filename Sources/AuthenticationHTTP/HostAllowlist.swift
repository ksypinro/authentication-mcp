import Foundation

/// Which `Host` and `Origin` header values the HTTP endpoint accepts.
///
/// The SDK's `OriginValidator` checks two different headers against two
/// different lists, and the two are spelled differently:
///
/// - `Host` is sent by every client and has no scheme: `192.168.0.225:8080`.
/// - `Origin` is sent only by browsers and carries one: `http://192.168.0.225:8080`.
///
/// Configuration (`AUTH_MCP_ALLOWED_ORIGINS`) is a single list a person types
/// in either spelling. This type derives both lists from it. Passing one raw
/// list as both — which is what this server did before — means no entry can
/// ever satisfy both checks: a schemed entry rejects every `Host` with a 421,
/// a bare one rejects every browser `Origin` with a 403.
///
/// Matching is on the *hostname*, which is what defends against DNS rebinding:
/// a page served from `evil.example` that resolves to this machine still sends
/// `Host: evil.example`, and is refused.
public struct HostAllowlist: Sendable, Equatable {
    /// Accepted `Host` header values, e.g. `192.168.0.225:8080`.
    public let hosts: [String]
    /// Accepted `Origin` header values, e.g. `http://192.168.0.225:8080`.
    public let origins: [String]

    /// Builds the allowlist for a listener.
    ///
    /// - Parameters:
    ///   - entries: configured names, each as `host`, `host:port`, `host:*`, or
    ///     `http(s)://host[:port]`. A trailing path is ignored.
    ///   - bindHost: the address the listener is bound to.
    ///   - port: the port the listener is bound to.
    /// - Returns: `nil` when nothing can be derived — a wildcard bind with no
    ///   configured names. The caller then runs with the check disabled and
    ///   should say so loudly, because any name that resolves to this machine
    ///   will be accepted.
    public static func make(entries: [String], bindHost: String, port: Int) -> HostAllowlist? {
        // Same-machine clients always reach the server as loopback, whatever
        // interface it is bound to, so loopback names are always allowed.
        var authorities = ["127.0.0.1", "localhost", "[::1]"].map { "\($0):\(port)" }

        // The SDK compares header values with exact `==`, but clients disagree on
        // case: browsers and Node lowercase the host they send, curl and Python
        // send it as typed. `.local` names are often mixed-case
        // (`Kazis-MacBook-Pro.local`), so both spellings are accepted.
        let configured = entries
            .map(Self.authority(from:))
            .filter { !$0.isEmpty }
            .flatMap { [$0, $0.lowercased()] }

        if isWildcard(bindHost) && configured.isEmpty {
            return nil
        }
        if !isWildcard(bindHost) && !isLoopback(bindHost) {
            // Bound to one specific address, so that address is always a name a
            // remote client can legitimately use — whether or not other names
            // (a `.local` hostname, say) are configured too. With nothing else
            // configured this makes the common LAN setup safe by default.
            authorities.append("\(bracketedIfIPv6(bindHost)):\(port)")
        }
        authorities.append(contentsOf: configured)

        var hosts: [String] = []
        var origins: [String] = []
        for authority in authorities {
            // A name with no port matches it on any port: clients omit the port
            // only for 80/443, which is exactly the reverse-proxy case.
            let variants = hasPort(authority) ? [authority] : [authority, "\(authority):*"]
            for variant in variants {
                hosts.append(variant)
                // https too: a TLS-terminating proxy in front sends https origins.
                origins.append("http://\(variant)")
                origins.append("https://\(variant)")
            }
        }

        return HostAllowlist(hosts: deduplicated(hosts), origins: deduplicated(origins))
    }

    // MARK: - Parsing

    /// Reduces a configured entry to its `host[:port]` authority.
    static func authority(from entry: String) -> String {
        var value = entry.trimmingCharacters(in: .whitespacesAndNewlines)
        for scheme in ["http://", "https://"] where value.lowercased().hasPrefix(scheme) {
            value.removeFirst(scheme.count)
        }
        if let slash = value.firstIndex(of: "/") {
            value = String(value[..<slash])
        }
        return value
    }

    /// Whether an authority ends in an explicit port (or the `:*` wildcard).
    ///
    /// Takes the text after the last colon, so `[::1]` (no port) and
    /// `[::1]:8080` (port) are told apart correctly.
    static func hasPort(_ authority: String) -> Bool {
        guard let colon = authority.lastIndex(of: ":") else { return false }
        let tail = authority[authority.index(after: colon)...]
        return tail == "*" || (!tail.isEmpty && tail.allSatisfy(\.isNumber))
    }

    static func isWildcard(_ host: String) -> Bool {
        ["0.0.0.0", "::", "*", ""].contains(host)
    }

    static func isLoopback(_ host: String) -> Bool {
        ["127.0.0.1", "localhost", "::1"].contains(host)
    }

    private static func bracketedIfIPv6(_ host: String) -> String {
        host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
    }

    private static func deduplicated(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}
