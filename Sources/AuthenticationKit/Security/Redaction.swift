import Foundation

/// Helpers that keep secrets out of anything a model or a log file can see.
///
/// The server holds access tokens, refresh tokens and PKCE verifiers. None of
/// them are ever returned from a tool call — tools hand back an opaque session id
/// instead — and none of them are logged in full. A model that can read a bearer
/// token can replay it anywhere; a session id is only meaningful to this process.
public enum Redaction {

    /// Renders a secret as a short, non-reversible fingerprint safe for logs.
    ///
    /// Shows the last four characters so an operator can correlate a log line with
    /// a token they hold, without the log itself being usable as a credential.
    public static func fingerprint(_ secret: String) -> String {
        guard secret.count > 4 else { return "****" }
        return "****" + secret.suffix(4)
    }

    /// Redacts the values of known-sensitive keys anywhere in a JSON-ish dictionary.
    public static func redactSensitiveKeys(_ dictionary: [String: String]) -> [String: String] {
        dictionary.reduce(into: [:]) { result, pair in
            result[pair.key] = isSensitive(key: pair.key) ? fingerprint(pair.value) : pair.value
        }
    }

    static let sensitiveKeys: Set<String> = [
        "access_token", "refresh_token", "id_token", "client_secret", "code",
        "code_verifier", "device_code", "authorization", "password", "assertion",
        "client_assertion",
    ]

    public static func isSensitive(key: String) -> Bool {
        sensitiveKeys.contains(key.lowercased())
    }
}
