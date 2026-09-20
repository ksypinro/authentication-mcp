import Foundation
import Logging

/// Resolves an issuer URL to its authorization server metadata.
///
/// Tries the RFC 8414 well-known locations and the OpenID Connect one in the
/// order the specs prescribe. RFC 8414 §3.1 inserts the well-known segment
/// *before* any issuer path component, which differs from the OpenID Connect
/// convention of appending it — providers exist in the wild that only implement
/// one, so both spellings are attempted.
public actor MetadataDiscovery {
    private let http: any HTTPExchanging
    private let logger: Logger
    private var cache: [URL: (metadata: AuthorizationServerMetadata, fetchedAt: Date)] = [:]
    private let cacheLifetime: TimeInterval

    public init(
        http: any HTTPExchanging,
        logger: Logger,
        cacheLifetime: TimeInterval = 3600
    ) {
        self.http = http
        self.logger = logger
        self.cacheLifetime = cacheLifetime
    }

    /// The candidate metadata URLs for an issuer, in priority order.
    public nonisolated func candidateURLs(for issuer: URL) -> [URL] {
        guard var components = URLComponents(url: issuer, resolvingAgainstBaseURL: false) else {
            return []
        }
        let issuerPath = components.path.hasSuffix("/")
            ? String(components.path.dropLast())
            : components.path

        var candidates: [URL] = []
        for wellKnown in [OAuthConstants.wellKnownOAuth, OAuthConstants.wellKnownOpenID] {
            // RFC 8414: /.well-known/oauth-authorization-server/tenant-one
            components.path = wellKnown + issuerPath
            if let url = components.url { candidates.append(url) }

            // OIDC Discovery: /tenant-one/.well-known/openid-configuration
            if !issuerPath.isEmpty {
                components.path = issuerPath + wellKnown
                if let url = components.url { candidates.append(url) }
            }
        }
        return candidates
    }

    /// Fetches and caches metadata for `issuer`.
    ///
    /// - Parameter forceRefresh: bypasses the cache, for when a provider has
    ///   rotated an endpoint and the cached document has gone stale.
    public func metadata(
        for issuer: URL,
        forceRefresh: Bool = false
    ) async throws -> AuthorizationServerMetadata {
        if !forceRefresh, let cached = cache[issuer],
            Date().timeIntervalSince(cached.fetchedAt) < cacheLifetime
        {
            return cached.metadata
        }

        var lastFailure: String = "no candidate URLs could be built for \(issuer)"
        for candidate in candidateURLs(for: issuer) {
            do {
                let metadata = try await fetch(candidate)
                // RFC 8414 §3.3: the issuer in the document MUST match the one
                // requested. A mismatch means the document was served by, or for,
                // a different authorization server.
                guard metadata.issuer.normalizedForIssuerComparison
                        == issuer.normalizedForIssuerComparison
                else {
                    lastFailure =
                        "issuer mismatch: document declares \(metadata.issuer), expected \(issuer)"
                    logger.warning(
                        "Discarding discovery document with mismatched issuer",
                        metadata: [
                            "candidate": .string(candidate.absoluteString),
                            "declared": .string(metadata.issuer.absoluteString),
                        ])
                    continue
                }

                cache[issuer] = (metadata, Date())
                logger.debug(
                    "Discovered authorization server metadata",
                    metadata: ["source": .string(candidate.absoluteString)])
                return metadata
            } catch {
                lastFailure = "\(candidate.absoluteString): \(error.localizedDescription)"
                continue
            }
        }

        throw OAuthError.discoveryFailed(reason: lastFailure)
    }

    /// Seeds the cache directly. Used when metadata is configured rather than discovered.
    public func preload(_ metadata: AuthorizationServerMetadata, for issuer: URL) {
        cache[issuer] = (metadata, Date())
    }

    private func fetch(_ url: URL) async throws -> AuthorizationServerMetadata {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await http.send(request)
        guard (200..<300).contains(response.statusCode) else {
            throw OAuthError.discoveryFailed(reason: "HTTP \(response.statusCode)")
        }
        do {
            return try JSONDecoder().decode(AuthorizationServerMetadata.self, from: data)
        } catch {
            throw OAuthError.malformedResponse(
                reason: "discovery document could not be decoded: \(error.localizedDescription)")
        }
    }
}

extension URL {
    /// Issuer comparison per RFC 8414 ignores a trailing slash but is otherwise exact.
    var normalizedForIssuerComparison: String {
        let string = absoluteString
        return string.hasSuffix("/") ? String(string.dropLast()) : string
    }
}
