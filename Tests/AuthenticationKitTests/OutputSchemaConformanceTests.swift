import Foundation
import MCP
import Testing

@testable import AuthenticationKit

/// Checks that every result a tool actually returns conforms to the
/// `outputSchema` that tool declares.
///
/// The MCP spec requires it, and clients built on the TypeScript SDK enforce
/// it: they validate each result and reject one that doesn't match. Nothing
/// caught the gap before, because neither the Swift SDK client nor the Python
/// drivers used during development validate — so every successful call failed
/// in the MCP Inspector while passing everywhere else.
@Suite("Output schema conformance")
struct OutputSchemaConformanceTests {

    private let owner = SessionOwner.stdio

    private func expectConforms(
        _ result: CallTool.Result,
        to tool: Tool,
        _ label: String,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        guard let schema = tool.outputSchema, let content = result.structuredContent else {
            Issue.record("\(label): missing schema or structured content",
                         sourceLocation: sourceLocation)
            return
        }
        let violations = SchemaValidator.violations(of: content, against: schema)
        #expect(violations.isEmpty, "\(tool.name) — \(label): \(violations)",
                sourceLocation: sourceLocation)
    }

    // MARK: - The validator itself

    @Test("The validator rejects an undeclared field, so these tests cannot pass vacuously")
    func validatorCatchesUndeclaredFields() {
        let schema = JSONSchema.object(properties: ["a": JSONSchema.string("a")], required: ["a"])
        #expect(SchemaValidator.violations(of: .object(["a": .string("x")]), against: schema).isEmpty)
        #expect(!SchemaValidator.violations(
            of: .object(["a": .string("x"), "ok": .bool(true)]), against: schema).isEmpty)
        #expect(!SchemaValidator.violations(of: .object([:]), against: schema).isEmpty)
    }

    // MARK: - authenticate

    @Test("authenticate: authenticated, pending, narrowed grant, denied, bad input")
    func authenticateConforms() async throws {
        let tool = ToolCatalog.authenticate

        let (immediate, _, _, _) = makeTestService()
        expectConforms(
            try await immediate.call(name: "authenticate", arguments: [:], owner: owner),
            to: tool, "authenticated")
        expectConforms(
            try await immediate.call(name: "authenticate", arguments: [:], owner: owner),
            to: tool, "already signed in")

        let (manual, _, _, _) = makeTestService(policy: .manual)
        expectConforms(
            try await manual.call(
                name: "authenticate", arguments: ["wait_seconds": .int(0)], owner: owner),
            to: tool, "pending")

        let (narrowed, _, _, _) = makeTestService(grantedScopes: [.dataRead])
        let warned = try await narrowed.call(
            name: "authenticate",
            arguments: ["scopes": .array([.string("data:read"), .string("data:write")])],
            owner: owner)
        #expect(warned.structured["scope_warning"] != nil)
        expectConforms(warned, to: tool, "narrowed grant")

        let (denied, _, _, _) = makeTestService(policy: .denied(reason: "no"))
        expectConforms(
            try await denied.call(name: "authenticate", arguments: [:], owner: owner),
            to: tool, "denied")

        expectConforms(
            try await immediate.call(
                name: "authenticate", arguments: ["mode": .string("telepathy")], owner: owner),
            to: tool, "invalid input")
    }

    // MARK: - revokeAuthentication

    @Test("revokeAuthentication: nothing to revoke, live session, stored credential only")
    func revokeConforms() async throws {
        let tool = ToolCatalog.revokeAuthentication

        let (service, _, _, _) = makeTestService()
        expectConforms(
            try await service.call(name: "revokeAuthentication", arguments: [:], owner: owner),
            to: tool, "nothing to revoke")
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        expectConforms(
            try await service.call(name: "revokeAuthentication", arguments: [:], owner: owner),
            to: tool, "live session")

        // A credential stored by `auth login`, never hydrated in this process:
        // the path that returns `revoked_accounts`.
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authservice-schema-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let logger = makeSilentLogger()
        let auditLog = AuditLog(logger: logger)
        let provider = MockAuthorizationProvider(logger: logger)
        let coordinator = AuthenticationCoordinator(
            provider: provider,
            credentialStore: try CredentialStore.make(
                serviceName: "test", directory: directory, preferredBackend: .file, logger: logger),
            issuer: URL(string: "https://as.example.com")!,
            logger: logger)
        try await coordinator.signIn()
        let persistent = AuthenticationService(
            provider: provider,
            sessionStore: SessionStore(
                provider: provider, auditLog: auditLog, logger: logger, coordinator: coordinator),
            dataStore: InMemoryDataStore(),
            auditLog: auditLog,
            logger: logger)

        let stored = try await persistent.call(
            name: "revokeAuthentication", arguments: [:], owner: owner)
        #expect(stored.structured["revoked_accounts"] != nil)
        expectConforms(stored, to: tool, "stored credential")
    }

    // MARK: - fetchData

    @Test("fetchData: with and without metadata, not signed in, missing record, bad input")
    func fetchConforms() async throws {
        let tool = ToolCatalog.fetchData
        let (service, _, _, _) = makeTestService()

        expectConforms(
            try await service.call(name: "fetchData", arguments: ["id": .string("doc")], owner: owner),
            to: tool, "not signed in")

        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)
        _ = try await service.call(
            name: "updatedData",
            arguments: ["id": .string("doc"), "value": .object(["a": .int(1)])], owner: owner)

        expectConforms(
            try await service.call(name: "fetchData", arguments: ["id": .string("doc")], owner: owner),
            to: tool, "with metadata")
        expectConforms(
            try await service.call(
                name: "fetchData",
                arguments: ["id": .string("doc"), "include_metadata": .bool(false)], owner: owner),
            to: tool, "without metadata")
        expectConforms(
            try await service.call(name: "fetchData", arguments: ["id": .string("nope")], owner: owner),
            to: tool, "missing record")
        expectConforms(
            try await service.call(name: "fetchData", arguments: [:], owner: owner),
            to: tool, "missing id")
    }

    // MARK: - updatedData

    @Test("updatedData: create, update, version conflict")
    func updateConforms() async throws {
        let tool = ToolCatalog.updatedData
        let (service, _, _, _) = makeTestService()
        _ = try await service.call(name: "authenticate", arguments: [:], owner: owner)

        let doc: [String: Value] = ["id": .string("doc"), "value": .object(["a": .int(1)])]
        expectConforms(
            try await service.call(name: "updatedData", arguments: doc, owner: owner),
            to: tool, "create")
        expectConforms(
            try await service.call(name: "updatedData", arguments: doc, owner: owner),
            to: tool, "update")

        var stale = doc
        stale["expected_version"] = .int(99)
        expectConforms(
            try await service.call(name: "updatedData", arguments: stale, owner: owner),
            to: tool, "version conflict")
    }
}

// MARK: - A minimal JSON Schema validator

/// Validates a `Value` against the subset of JSON Schema `JSONSchema` emits:
/// `type`, `properties`, `required`, `additionalProperties`, `enum`, `const`,
/// `items`, `anyOf`. Annotations (`description`, `format`, `default`,
/// `examples`) are ignored, as a validator ignores them by default.
enum SchemaValidator {

    static func violations(of value: Value, against schema: Value, at path: String = "$") -> [String] {
        guard let rules = schema.objectValue else { return [] }
        var problems: [String] = []

        if let options = rules["anyOf"]?.arrayValue {
            let matched = options.contains { violations(of: value, against: $0, at: path).isEmpty }
            if !matched {
                let reasons = options.map { violations(of: value, against: $0, at: path) }
                problems.append("\(path): matches no anyOf branch \(reasons)")
            }
        }

        if let expected = rules["const"], value != expected {
            problems.append("\(path): expected const \(expected), got \(value)")
        }
        if let allowed = rules["enum"]?.arrayValue, !allowed.contains(value) {
            problems.append("\(path): \(value) not in enum")
        }

        if let type = rules["type"] {
            let types = type.arrayValue?.compactMap(\.stringValue) ?? [type.stringValue].compactMap { $0 }
            if !types.contains(where: { matches(value, type: $0) }) {
                problems.append("\(path): expected \(types), got \(value)")
                return problems
            }
        }

        if case .object(let fields) = value {
            let properties = rules["properties"]?.objectValue ?? [:]
            for name in rules["required"]?.arrayValue?.compactMap(\.stringValue) ?? []
            where fields[name] == nil {
                problems.append("\(path): missing required '\(name)'")
            }
            for (name, field) in fields {
                if let propertySchema = properties[name] {
                    problems += violations(of: field, against: propertySchema, at: "\(path).\(name)")
                } else if rules["additionalProperties"]?.boolValue == false {
                    problems.append("\(path): undeclared property '\(name)'")
                }
            }
        }

        if case .array(let elements) = value, let itemSchema = rules["items"] {
            for (index, element) in elements.enumerated() {
                problems += violations(of: element, against: itemSchema, at: "\(path)[\(index)]")
            }
        }

        return problems
    }

    private static func matches(_ value: Value, type: String) -> Bool {
        switch (type, value) {
        case ("object", .object), ("array", .array), ("string", .string),
             ("boolean", .bool), ("null", .null), ("integer", .int), ("number", .int),
             ("number", .double):
            return true
        case ("integer", .double(let number)):
            return number.rounded() == number
        default:
            return false
        }
    }
}
