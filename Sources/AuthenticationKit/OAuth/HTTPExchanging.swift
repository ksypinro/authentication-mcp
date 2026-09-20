import Foundation

/// The single seam through which the OAuth layer reaches the network.
///
/// Everything OAuth-related goes through this protocol so tests can drive the
/// full flow — discovery, device authorization, polling, refresh, revocation —
/// against a scripted transport without a live authorization server and without
/// `URLProtocol` swizzling.
public protocol HTTPExchanging: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// The production implementation, backed by `URLSession`.
public struct URLSessionHTTPClient: HTTPExchanging {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    /// A session tuned for authorization-server traffic: short timeouts, no
    /// caching of token responses, and no cookies (an authorization server must
    /// never treat this client as a logged-in browser session).
    public static func makeDefault(timeout: TimeInterval = 20) -> URLSessionHTTPClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout * 2
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        return URLSessionHTTPClient(session: URLSession(configuration: configuration))
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            let (data, response) = try await session.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                throw OAuthError.malformedResponse(reason: "response was not HTTP")
            }
            return (data, httpResponse)
        } catch let error as OAuthError {
            throw error
        } catch {
            throw OAuthError.transportFailure(reason: error.localizedDescription)
        }
    }
}

// MARK: - Form encoding

enum FormEncoding {
    /// `application/x-www-form-urlencoded`, per the OAuth request format.
    ///
    /// Keys are sorted so request bodies are deterministic, which makes tests and
    /// captured traffic readable.
    static func encode(_ parameters: [String: String]) -> Data {
        let body =
            parameters
            .sorted { $0.key < $1.key }
            .map { "\(percentEncode($0.key))=\(percentEncode($0.value))" }
            .joined(separator: "&")
        return Data(body.utf8)
    }

    /// Percent-encodes per RFC 6749 Appendix B: everything outside the unreserved
    /// set is escaped, and a space becomes `%20` rather than `+`.
    static func percentEncode(_ string: String) -> String {
        let unreserved = CharacterSet(
            charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        return string.addingPercentEncoding(withAllowedCharacters: unreserved) ?? string
    }
}
