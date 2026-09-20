import Foundation
import MCP

// Conveniences for reading `Value` trees out of tool arguments and for building
// result payloads without pages of `.object([...])` noise.
extension Value {

    /// Subscript into an object value. Returns `nil` for non-objects.
    public subscript(key: String) -> Value? {
        objectValue?[key]
    }

    /// The value as a `Double`, accepting either JSON number representation.
    public var numberValue: Double? {
        switch self {
        case .int(let value): return Double(value)
        case .double(let value): return value
        default: return nil
        }
    }

    /// The value as an `Int`, accepting a `double` that holds an exact integer.
    ///
    /// JSON has one number type, so a client sending `1` may encode it as `1.0`.
    /// Rejecting that would be needlessly strict.
    public var integerValue: Int? {
        switch self {
        case .int(let value): return value
        case .double(let value) where value.rounded() == value && value.magnitude < 9.007e15:
            return Int(value)
        default: return nil
        }
    }

    /// Builds an object from key/value pairs, omitting any whose value is absent.
    ///
    /// Both `Optional.none` and `Value.null` count as absent. Treating `.null` as
    /// absent is not just convenience: `Value` conforms to `ExpressibleByNilLiteral`,
    /// so in an expression like `flag ? someValue : nil` Swift unifies the branches
    /// as `Value` and turns the `nil` into `Value.null` rather than `Optional.none`.
    /// Collapsing both here means a call site cannot accidentally emit a JSON null
    /// where it meant to omit the key. It also matches the input side, where
    /// ``Optional/presentValue`` already reads `null` as "not supplied".
    public static func object(compacting pairs: [(String, Value?)]) -> Value {
        var result: [String: Value] = [:]
        for (key, value) in pairs {
            guard let value, !value.isNull else { continue }
            result[key] = value
        }
        return .object(result)
    }

    /// Pretty-prints the value as JSON for the human-readable half of a tool result.
    public var prettyJSONString: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(self),
            let string = String(data: data, encoding: .utf8)
        else {
            return String(describing: self)
        }
        return string
    }
}

extension Optional where Wrapped == Value {
    /// `.null` and a missing key mean the same thing at this layer: absent.
    public var presentValue: Value? {
        guard let self, !self.isNull else { return nil }
        return self
    }
}
