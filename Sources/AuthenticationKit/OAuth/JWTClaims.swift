import Foundation

/// The claims this server reads out of an OIDC ID token.
///
/// **On signature verification:** the ID token is read only when it arrives
/// directly from the token endpoint over the TLS channel this process opened.
/// OpenID Connect Core §3.1.3.7 item 6 explicitly permits skipping signature
/// validation in exactly that case, because TLS already authenticates the issuer
/// and the token never passed through an untrusted party. An ID token obtained
/// any other way must not be parsed with this type.
public struct JWTClaims: Sendable, Equatable {
    public let subject: String?
    public let issuer: String?
    public let audience: [String]
    public let expiresAt: Date?
    public let issuedAt: Date?
    /// `preferred_username`, `email`, or `name` — whichever the issuer provided.
    public let principalName: String?
    /// Scopes carried in the token itself, when the issuer puts them there.
    public let scopes: Set<Scope>?

    /// Decodes the payload of a compact-serialized JWT without verifying it.
    ///
    /// Returns `nil` for anything that is not a well-formed three-part JWT — an
    /// opaque access token, for instance, which is perfectly normal and not an error.
    public static func decodeUnverifiedPayload(of token: String) -> JWTClaims? {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, let payload = base64URLDecode(String(segments[1])) else {
            return nil
        }
        guard let json = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
            return nil
        }

        let audience: [String]
        switch json["aud"] {
        case let single as String: audience = [single]
        case let multiple as [String]: audience = multiple
        default: audience = []
        }

        let principalName =
            json["preferred_username"] as? String
            ?? json["email"] as? String
            ?? json["name"] as? String

        let scopes: Set<Scope>?
        if let scopeString = json["scope"] as? String {
            scopes = Set(scopeString: scopeString)
        } else if let scopeArray = json["scp"] as? [String] {
            scopes = Set(scopeArray.map(Scope.init))
        } else {
            scopes = nil
        }

        return JWTClaims(
            subject: json["sub"] as? String,
            issuer: json["iss"] as? String,
            audience: audience,
            expiresAt: (json["exp"] as? Double).map { Date(timeIntervalSince1970: $0) },
            issuedAt: (json["iat"] as? Double).map { Date(timeIntervalSince1970: $0) },
            principalName: principalName,
            scopes: scopes
        )
    }

    /// base64url (RFC 4648 §5) with the padding the JWT spec omits.
    static func base64URLDecode(_ string: String) -> Data? {
        var base64 =
            string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }
}
