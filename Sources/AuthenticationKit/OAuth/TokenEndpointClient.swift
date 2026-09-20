import Foundation
import Logging

/// The raw JSON body of a successful token response (RFC 6749 §5.1).
struct TokenEndpointResponse: Decodable {
    let accessToken: String
    let tokenType: String?
    let expiresIn: Double?
    let refreshToken: String?
    let idToken: String?
    let scope: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case idToken = "id_token"
        case scope
    }
}

/// An OAuth error response (RFC 6749 §5.2).
struct TokenEndpointErrorResponse: Decodable {
    let error: String
    let errorDescription: String?
    let errorURI: String?
    /// RFC 8628 §3.5: the server may lengthen the device-flow polling interval.
    let interval: Double?

    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
        case errorURI = "error_uri"
        case interval
    }
}

/// The device authorization response (RFC 8628 §3.2).
struct DeviceAuthorizationResponse: Decodable {
    let deviceCode: String
    let userCode: String
    let verificationURI: URL
    let verificationURIComplete: URL?
    let expiresIn: Double
    let interval: Double?

    enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationURI = "verification_uri"
        case verificationURIComplete = "verification_uri_complete"
        case expiresIn = "expires_in"
        case interval
    }

    /// Google's device endpoint returns `verification_url` rather than the
    /// spec-mandated `verification_uri`. Accepting both costs nothing and avoids
    /// a confusing hard failure against a widely used provider.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        deviceCode = try container.decode(String.self, forKey: .deviceCode)
        userCode = try container.decode(String.self, forKey: .userCode)
        expiresIn = try container.decodeIfPresent(Double.self, forKey: .expiresIn) ?? 600
        interval = try container.decodeIfPresent(Double.self, forKey: .interval)

        if let uri = try container.decodeIfPresent(URL.self, forKey: .verificationURI) {
            verificationURI = uri
        } else if let legacy = try decoder.container(keyedBy: LegacyKeys.self)
            .decodeIfPresent(URL.self, forKey: .verificationURL)
        {
            verificationURI = legacy
        } else {
            throw DecodingError.keyNotFound(
                CodingKeys.verificationURI,
                .init(
                    codingPath: container.codingPath,
                    debugDescription: "device response has neither verification_uri nor verification_url"
                ))
        }

        if let complete = try container.decodeIfPresent(URL.self, forKey: .verificationURIComplete) {
            verificationURIComplete = complete
        } else {
            verificationURIComplete = try decoder.container(keyedBy: LegacyKeys.self)
                .decodeIfPresent(URL.self, forKey: .verificationURLComplete)
        }
    }

    private enum LegacyKeys: String, CodingKey {
        case verificationURL = "verification_url"
        case verificationURLComplete = "verification_url_complete"
    }
}

/// Performs the POST requests that make up the OAuth token lifecycle: code
/// exchange, device authorization, polling, refresh, and revocation.
struct TokenEndpointClient: Sendable {
    let http: any HTTPExchanging
    let authentication: OAuthProviderConfiguration.ClientAuthentication
    let logger: Logger

    // MARK: - Token requests

    /// Sends a token request and decodes the result, mapping OAuth error bodies
    /// onto ``OAuthError/serverRejected(code:description:)``.
    func requestToken(
        endpoint: URL,
        parameters: [String: String]
    ) async throws -> TokenEndpointResponse {
        let (data, response) = try await post(endpoint: endpoint, parameters: parameters)

        guard (200..<300).contains(response.statusCode) else {
            throw decodeError(data: data, statusCode: response.statusCode)
        }
        do {
            return try JSONDecoder().decode(TokenEndpointResponse.self, from: data)
        } catch {
            throw OAuthError.malformedResponse(
                reason: "token response could not be decoded: \(error.localizedDescription)")
        }
    }

    /// Starts a device authorization request (RFC 8628 §3.1).
    func requestDeviceAuthorization(
        endpoint: URL,
        scopes: Set<Scope>,
        resource: URL?
    ) async throws -> DeviceAuthorizationResponse {
        var parameters: [String: String] = [:]
        if !scopes.isEmpty { parameters["scope"] = scopes.scopeString }
        if let resource { parameters["resource"] = resource.absoluteString }

        let (data, response) = try await post(endpoint: endpoint, parameters: parameters)
        guard (200..<300).contains(response.statusCode) else {
            throw decodeError(data: data, statusCode: response.statusCode)
        }
        do {
            return try JSONDecoder().decode(DeviceAuthorizationResponse.self, from: data)
        } catch {
            throw OAuthError.malformedResponse(
                reason: "device authorization response could not be decoded: "
                    + error.localizedDescription)
        }
    }

    /// Revokes a single token (RFC 7009).
    ///
    /// Returns `true` when the authorization server accepted the revocation. A
    /// 200 for an unknown token also counts as accepted — §2.2 requires that
    /// response precisely so a client cannot probe token validity here.
    func revokeToken(
        endpoint: URL,
        token: String,
        typeHint: String
    ) async throws -> Bool {
        let parameters = [
            "token": token,
            "token_type_hint": typeHint,
        ]
        let (data, response) = try await post(endpoint: endpoint, parameters: parameters)

        if (200..<300).contains(response.statusCode) { return true }

        // §2.2.1: `unsupported_token_type` means this token kind cannot be revoked
        // here. Surface it rather than reporting a clean revocation.
        throw decodeError(data: data, statusCode: response.statusCode)
    }

    // MARK: - Request construction

    private func post(
        endpoint: URL,
        parameters: [String: String]
    ) async throws -> (Data, HTTPURLResponse) {
        var parameters = parameters
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue(
            "application/x-www-form-urlencoded;charset=UTF-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        switch authentication {
        case .publicClient(let clientID):
            parameters["client_id"] = clientID
        case .clientSecretPost(let clientID, let clientSecret):
            parameters["client_id"] = clientID
            parameters["client_secret"] = clientSecret
        case .clientSecretBasic(let clientID, let clientSecret):
            // RFC 6749 §2.3.1: both halves are form-urlencoded before base64.
            let credentials =
                "\(FormEncoding.percentEncode(clientID)):\(FormEncoding.percentEncode(clientSecret))"
            let encoded = Data(credentials.utf8).base64EncodedString()
            request.setValue("Basic \(encoded)", forHTTPHeaderField: "Authorization")
        }

        request.httpBody = FormEncoding.encode(parameters)

        logger.debug(
            "OAuth request",
            metadata: [
                "endpoint": .string(endpoint.absoluteString),
                "parameters": .string(
                    Redaction.redactSensitiveKeys(parameters).keys.sorted().joined(separator: ",")),
            ])

        return try await http.send(request)
    }

    /// Turns an error body into a typed error, falling back to the status code
    /// when the body is not a well-formed OAuth error response.
    private func decodeError(data: Data, statusCode: Int) -> OAuthError {
        if let decoded = try? JSONDecoder().decode(TokenEndpointErrorResponse.self, from: data) {
            return .serverRejected(code: decoded.error, description: decoded.errorDescription)
        }
        let body = String(data: data.prefix(256), encoding: .utf8) ?? ""
        return .serverRejected(
            code: "http_\(statusCode)", description: body.isEmpty ? nil : body)
    }
}

// MARK: - Response → TokenSet

extension TokenEndpointResponse {
    /// Builds a ``TokenSet``, filling in identity from the ID token when present.
    ///
    /// `scope` is omitted by servers that granted exactly what was asked for
    /// (RFC 6749 §5.1), so the requested set is used as the fallback.
    func makeTokenSet(
        requestedScopes: Set<Scope>,
        issuer: URL?,
        now: Date = Date()
    ) -> TokenSet {
        let claims = idToken.flatMap(JWTClaims.decodeUnverifiedPayload(of:))
        let grantedScopes = scope.map { Set(scopeString: $0) } ?? claims?.scopes ?? requestedScopes

        return TokenSet(
            accessToken: accessToken,
            tokenType: tokenType ?? "Bearer",
            refreshToken: refreshToken,
            idToken: idToken,
            scopes: grantedScopes,
            issuedAt: now,
            expiresAt: expiresIn.map { now.addingTimeInterval($0) },
            subject: claims?.subject,
            principalName: claims?.principalName,
            issuer: issuer
        )
    }
}
