# Contributing

Thanks for considering a contribution. This project is small enough that most
changes can be reviewed in one pass — the notes below just cover the things
that would otherwise take a round of back-and-forth to explain.

## Getting set up

Requires Swift 6.1+ (Xcode 16+ on macOS, or the Swift toolchain on Linux).

```bash
git clone https://github.com/ksypinro/authentication-mcp.git
cd authentication-mcp
swift build
swift test
```

No identity provider is needed to build or test. The full suite runs against
an in-process mock authorization provider and an in-memory data store:

```bash
AUTH_MCP_PROVIDER=mock swift run authentication-mcp auth login
AUTH_MCP_PROVIDER=mock swift run authentication-mcp
```

`swift run authentication-mcp serve --check` validates a configuration and
prints a summary without starting anything — useful while iterating on
`EnvironmentConfiguration`.

## Before opening a PR

- `swift build` and `swift test` both pass, with no new warnings.
- New behavior has a test. This codebase leans heavily on driving real
  collaborators — a real `SessionStore`, a real `AuthenticationCoordinator`,
  a real SDK `Client`/`Server` pair over `InMemoryTransport` — rather than
  mocking the object under test itself. See
  [`Tests/AuthenticationKitTests/ClientIdentificationTests.swift`](Tests/AuthenticationKitTests/ClientIdentificationTests.swift)
  for the pattern: it runs an actual `initialize` handshake and an actual
  `tools/call`, not just a unit test of a closure in isolation.
- A behavior change that affects what a tool returns or requires also updates
  its schema and description in
  [`ToolCatalog.swift`](Sources/AuthenticationKit/Server/ToolCatalog.swift) —
  the schema is the only contract a model ever sees, so it has to stay honest.
- Anything touching [`ARCHITECTURE.md`](ARCHITECTURE.md)'s subject matter
  (a new module, a changed request path, a new persistence mechanism) gets
  that document updated in the same PR. Docs that drift from the code are
  worse than no docs.

## Code conventions this project actually follows

Skimming the existing source is the fastest way to absorb these, but the
short version:

- **Every non-trivial type gets a doc comment explaining *why* it exists**,
  not a restatement of its name. Search the codebase for `/// Needed because`
  or `/// so that` for the pattern — a comment earns its place by carrying
  information a reader couldn't get from the signature.
- **Actors guard every piece of state more than one caller can touch** —
  `SessionStore`, `CredentialStore`, `RateLimiter`, `AuditLog` are all actors,
  not classes with a lock, specifically so a concurrent refresh-on-read can't
  race two callers into refreshing the same token twice.
- **Ambient, per-call context is a `@TaskLocal`, not a threaded parameter.**
  `ClientContext.clientName` carries the connecting MCP client's name from the
  `initialize` handshake down through `AuthenticationService` → `SessionStore`
  → `AuthenticationCoordinator` without any of those three putting an extra
  parameter on every method just to relay it. This mirrors the pattern the
  MCP Swift SDK itself uses for the in-flight HTTP request
  (`Server.currentHandlerContext`) — match it rather than inventing a second
  convention.
- **Tool failures are results, not thrown protocol errors.** A `CallTool.Result`
  with `isError: true` reaches the model and can be corrected; an `MCPError`
  reaches only the client's error handling and is invisible to the
  conversation. `ToolFailure.from(_:)` in
  [`ToolResult.swift`](Sources/AuthenticationKit/Server/ToolResult.swift) is
  the single place that maps every internal error type onto a stable code and
  a remediation string — extend it there, don't throw a new error type past it.
- **Every field a tool returns is in its `outputSchema`, and every capability
  advertised is implemented.** Clients built on the TypeScript SDK validate each
  result against the declared schema and reject one that doesn't match; some call
  every advertised capability right after connecting. `ToolCatalog.resultSchema`
  covers the shared `ok`/`error` fields;
  [`OutputSchemaConformanceTests.swift`](Tests/AuthenticationKitTests/OutputSchemaConformanceTests.swift)
  runs each tool's real results through its own schema — add a case there when a
  tool gains a new result shape.
- **Token material never leaves `Credentials/` or `OAuth/`.** If you find
  yourself passing an access or refresh token string into `Server/` or across
  a tool boundary, that's a sign the design needs another look, not a reason
  to add a redaction step after the fact. Sessions carry an opaque
  `session_id`; nothing else.
- **A `Value` literal's `nil` branch is not `Optional.none`.** `MCP.Value`
  conforms to `ExpressibleByNilLiteral`, so `condition ? someValue : nil` in a
  ternary silently produces `Value.null`, not an absent key. Build optional
  tool-result fields with `Value.object(compacting:)`, which already treats
  both as "omit this key" — see
  [`Value+Convenience.swift`](Sources/AuthenticationKit/Support/Value+Convenience.swift).
- **A dictionary literal handed to `logger.debug`/`.info` cannot contain
  `await`.** swift-log's `metadata:` parameter is `@autoclosure`. Resolve the
  async value into a `let` first, then build the literal.

## Reporting a security issue

This project stores OAuth credentials and mediates access to a user's data.
If you find a vulnerability — a way to read another session's token, bypass
scope enforcement, or otherwise break the isolation between two connections —
please **do not** open a public issue. Use GitHub's private vulnerability
reporting (the "Report a vulnerability" button under this repo's Security
tab) so it can be fixed before it's public.

Anything short of an actual vulnerability — a confusing error message, a
missing test, a design question — is welcome as a regular issue.

## Everything else

Bug reports, docs fixes, and small focused PRs are welcome without any
advance discussion. For a larger change — a new persistence backend, a new
transport, a new grant type — opening an issue first will save you a rewrite
if the direction turns out to be a mismatch for the project.
