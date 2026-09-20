import Foundation
import MCP

/// A very small JSON Schema builder.
///
/// MCP tool schemas are just `Value` trees, and writing them as nested dictionary
/// literals is unreadable and easy to get subtly wrong. These helpers keep the
/// schemas in `ToolCatalog` declarative while still producing plain JSON Schema
/// that any MCP client can consume.
public enum JSONSchema {

    /// An object schema. Properties listed in `required` are marked required, and
    /// `additionalProperties` defaults to `false` so clients get told about typos
    /// instead of having unknown keys silently dropped.
    public static func object(
        description: String? = nil,
        properties: [String: Value],
        required: [String] = [],
        additionalProperties: Bool = false
    ) -> Value {
        var schema: [String: Value] = [
            "type": .string("object"),
            "properties": .object(properties),
            "additionalProperties": .bool(additionalProperties),
        ]
        if let description { schema["description"] = .string(description) }
        if !required.isEmpty {
            schema["required"] = .array(required.map { .string($0) })
        }
        return .object(schema)
    }

    /// A free-form JSON object: any keys, any values. Used for `updatedData`'s payload.
    public static func freeformObject(_ description: String) -> Value {
        .object([
            "type": .string("object"),
            "description": .string(description),
            "additionalProperties": .bool(true),
        ])
    }

    public static func string(
        _ description: String,
        minLength: Int? = nil,
        maxLength: Int? = nil,
        pattern: String? = nil,
        enumValues: [String]? = nil,
        default defaultValue: String? = nil,
        examples: [String]? = nil
    ) -> Value {
        var schema: [String: Value] = [
            "type": .string("string"),
            "description": .string(description),
        ]
        if let minLength { schema["minLength"] = .int(minLength) }
        if let maxLength { schema["maxLength"] = .int(maxLength) }
        if let pattern { schema["pattern"] = .string(pattern) }
        if let enumValues { schema["enum"] = .array(enumValues.map { .string($0) }) }
        if let defaultValue { schema["default"] = .string(defaultValue) }
        if let examples { schema["examples"] = .array(examples.map { .string($0) }) }
        return .object(schema)
    }

    public static func integer(
        _ description: String,
        minimum: Int? = nil,
        maximum: Int? = nil,
        default defaultValue: Int? = nil
    ) -> Value {
        var schema: [String: Value] = [
            "type": .string("integer"),
            "description": .string(description),
        ]
        if let minimum { schema["minimum"] = .int(minimum) }
        if let maximum { schema["maximum"] = .int(maximum) }
        if let defaultValue { schema["default"] = .int(defaultValue) }
        return .object(schema)
    }

    public static func boolean(_ description: String, default defaultValue: Bool? = nil) -> Value {
        var schema: [String: Value] = [
            "type": .string("boolean"),
            "description": .string(description),
        ]
        if let defaultValue { schema["default"] = .bool(defaultValue) }
        return .object(schema)
    }

    public static func array(
        _ description: String,
        items: Value,
        maxItems: Int? = nil,
        uniqueItems: Bool = false
    ) -> Value {
        var schema: [String: Value] = [
            "type": .string("array"),
            "description": .string(description),
            "items": items,
        ]
        if let maxItems { schema["maxItems"] = .int(maxItems) }
        if uniqueItems { schema["uniqueItems"] = .bool(true) }
        return .object(schema)
    }

    /// A string carrying an RFC 3339 timestamp.
    public static func timestamp(_ description: String) -> Value {
        .object([
            "type": .string("string"),
            "format": .string("date-time"),
            "description": .string(description),
        ])
    }

    /// Wraps a schema so that `null` is also accepted — the JSON Schema way of
    /// saying "this field is always present but may be empty".
    public static func nullable(_ schema: Value) -> Value {
        guard case var .object(fields) = schema, case let .string(type)? = fields["type"] else {
            return schema
        }
        fields["type"] = .array([.string(type), .string("null")])
        return .object(fields)
    }
}
