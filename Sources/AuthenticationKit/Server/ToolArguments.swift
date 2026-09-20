import Foundation
import MCP

/// A bad tool call, described well enough that a model can fix it and retry.
public struct ToolInputError: Error, Sendable, LocalizedError, Equatable {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var errorDescription: String? { message }
}

/// Typed, validating access to a tool call's arguments.
///
/// MCP tool arguments arrive as an untyped `[String: Value]`. Clients vary in how
/// strictly they follow a schema, so every value is validated here rather than
/// force-unwrapped, and every failure carries a message naming the parameter and
/// what was expected.
public struct ToolArguments: Sendable {
    private let arguments: [String: Value]
    private let toolName: String

    public init(_ arguments: [String: Value]?, toolName: String) {
        self.arguments = arguments ?? [:]
        self.toolName = toolName
    }

    public var isEmpty: Bool { arguments.isEmpty }

    public var keys: Set<String> { Set(arguments.keys) }

    /// Looks a key up, trying `aliases` if the canonical name is absent.
    ///
    /// The declared schema uses lower_snake_case, but this API was specified with
    /// `ID` and `Value`, and models do sometimes echo a spec's capitalisation.
    /// Accepting both spellings costs nothing and turns a confusing "missing
    /// required parameter" into a successful call.
    private func value(for key: String, aliases: [String]) -> Value? {
        if let value = arguments[key].presentValue { return value }
        for alias in aliases {
            if let value = arguments[alias].presentValue { return value }
        }
        return nil
    }

    // MARK: - Strings

    public func requiredString(
        _ key: String,
        aliases: [String] = [],
        maxLength: Int? = nil
    ) throws -> String {
        guard let value = value(for: key, aliases: aliases) else {
            throw ToolInputError("`\(toolName)` requires the `\(key)` parameter.")
        }
        guard let string = value.stringValue else {
            throw ToolInputError("`\(key)` must be a string, but was \(describe(value)).")
        }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw ToolInputError("`\(key)` must not be empty.")
        }
        if let maxLength, trimmed.count > maxLength {
            throw ToolInputError("`\(key)` must be at most \(maxLength) characters.")
        }
        return trimmed
    }

    public func optionalString(_ key: String, aliases: [String] = []) throws -> String? {
        guard let value = value(for: key, aliases: aliases) else { return nil }
        guard let string = value.stringValue else {
            throw ToolInputError("`\(key)` must be a string, but was \(describe(value)).")
        }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// An optional string constrained to a `CaseIterable` enum, so an unknown
    /// value is reported with the full list of what is accepted.
    public func optionalEnum<T: RawRepresentable & CaseIterable>(
        _ key: String,
        as type: T.Type,
        default defaultValue: T
    ) throws -> T where T.RawValue == String {
        guard let raw = try optionalString(key) else { return defaultValue }
        guard let parsed = T(rawValue: raw.lowercased()) else {
            let allowed = T.allCases.map { "'\($0.rawValue)'" }.joined(separator: ", ")
            throw ToolInputError("`\(key)` must be one of \(allowed), but was '\(raw)'.")
        }
        return parsed
    }

    // MARK: - Numbers and booleans

    public func optionalInt(
        _ key: String,
        minimum: Int? = nil,
        maximum: Int? = nil
    ) throws -> Int? {
        guard let value = value(for: key, aliases: []) else { return nil }
        guard let integer = value.integerValue else {
            throw ToolInputError("`\(key)` must be an integer, but was \(describe(value)).")
        }
        if let minimum, integer < minimum {
            throw ToolInputError("`\(key)` must be at least \(minimum).")
        }
        if let maximum, integer > maximum {
            throw ToolInputError("`\(key)` must be at most \(maximum).")
        }
        return integer
    }

    /// An integer clamped into range rather than rejected.
    ///
    /// Used for `wait_seconds`, where an out-of-range value has an obvious
    /// intended meaning and failing the call would be unhelpfully pedantic.
    public func clampedInt(
        _ key: String,
        default defaultValue: Int,
        minimum: Int,
        maximum: Int
    ) throws -> Int {
        guard let value = value(for: key, aliases: []) else { return defaultValue }
        guard let integer = value.integerValue else {
            throw ToolInputError("`\(key)` must be an integer, but was \(describe(value)).")
        }
        return min(maximum, max(minimum, integer))
    }

    public func optionalBool(_ key: String, default defaultValue: Bool) throws -> Bool {
        guard let value = value(for: key, aliases: []) else { return defaultValue }
        if let boolean = value.boolValue { return boolean }
        // Some clients stringify booleans on the way through.
        if let string = value.stringValue?.lowercased() {
            if ["true", "yes", "1"].contains(string) { return true }
            if ["false", "no", "0"].contains(string) { return false }
        }
        throw ToolInputError("`\(key)` must be a boolean, but was \(describe(value)).")
    }

    // MARK: - Composites

    public func optionalStringArray(_ key: String, maximumCount: Int = 64) throws -> [String]? {
        guard let value = value(for: key, aliases: []) else { return nil }

        // A single string where an array is expected is a common and harmless slip.
        if let single = value.stringValue {
            return single.split(separator: " ").map(String.init)
        }
        guard let array = value.arrayValue else {
            throw ToolInputError("`\(key)` must be an array of strings.")
        }
        guard array.count <= maximumCount else {
            throw ToolInputError("`\(key)` must contain at most \(maximumCount) entries.")
        }
        return try array.map { element in
            guard let string = element.stringValue else {
                throw ToolInputError(
                    "`\(key)` must contain only strings, but held \(describe(element)).")
            }
            return string
        }
    }

    /// A required JSON object.
    ///
    /// Objects specifically, not any JSON value: `merge` needs top-level keys, and
    /// a record whose value is a bare scalar cannot carry them.
    public func requiredObject(_ key: String, aliases: [String] = []) throws -> Value {
        guard let value = value(for: key, aliases: aliases) else {
            throw ToolInputError("`\(toolName)` requires the `\(key)` parameter.")
        }
        if value.objectValue != nil { return value }

        // Clients occasionally send a JSON object as a string. Recover when the
        // string really does parse as one.
        if let string = value.stringValue,
            let data = string.data(using: .utf8),
            let decoded = try? JSONDecoder().decode(Value.self, from: data),
            decoded.objectValue != nil
        {
            return decoded
        }

        throw ToolInputError(
            "`\(key)` must be a JSON object, but was \(describe(value)). "
                + "Wrap scalars or arrays in an object, for example {\"items\": [...]}.")
    }

    /// Reports parameters the schema does not declare.
    ///
    /// The schemas set `additionalProperties: false`, but nothing obliges a client
    /// to enforce that. Surfacing a typo beats silently ignoring a parameter the
    /// caller believed was applied — `expected_version` misspelled and dropped
    /// would turn a guarded write into an unguarded one.
    public func rejectUnknownParameters(allowed: Set<String>) throws {
        let unknown = keys.subtracting(allowed).sorted()
        guard !unknown.isEmpty else { return }
        throw ToolInputError(
            "`\(toolName)` does not accept \(unknown.map { "`\($0)`" }.joined(separator: ", ")). "
                + "Accepted parameters: \(allowed.sorted().map { "`\($0)`" }.joined(separator: ", ")).")
    }

    private func describe(_ value: Value) -> String {
        switch value {
        case .null: return "null"
        case .bool: return "a boolean"
        case .int, .double: return "a number"
        case .string: return "a string"
        case .data: return "binary data"
        case .array: return "an array"
        case .object: return "an object"
        }
    }
}
