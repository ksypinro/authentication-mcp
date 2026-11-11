# AuthenticationService

[![Swift](https://img.shields.io/badge/Swift-6.1%2B-F05138?logo=swift&logoColor=white)](https://www.swift.org)
[![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](Package.swift)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Server-blueviolet)](https://modelcontextprotocol.io)

An MCP server in Swift exposing four tools over an authenticated OAuth 2.1 session:

| Tool | Purpose |
| --- | --- |
| `authenticate` | Start or complete sign-in; returns a session handle |
| `revokeAuthentication` | Revoke credentials upstream and destroy the session |
| `fetchData(id)` | Read one record belonging to the signed-in principal |
| `updatedData(id, value)` | Create or update a record, with optimistic concurrency |

Sign in once from a terminal; every later run — including the one your MCP client
launches — reuses the stored credential until you sign out. Speaks both MCP
transports (stdio and Streamable HTTP) from one core.

📖 **[ARCHITECTURE.md](ARCHITECTURE.md)** traces the actual mechanisms — request
lifecycle, both OAuth grants, the credential store split, sign-in/out — as diagrams
that render right here on GitHub.

🌐 **[LOCAL_NETWORK.md](LOCAL_NETWORK.md)** walks through hosting the server on one
machine and using it from Claude Code, Codex, Claude Desktop or the MCP Inspector
on other devices on your network.

## Quick start

```bash
swift build

# Sign in once. Opens a browser, stores the credential in your keychain.
./.build/debug/authentication-mcp auth login

# Who am I, and for how long?
./.build/debug/authentication-mcp auth status

# Run the server (this is what an MCP client invokes).
./.build/debug/authentication-mcp

# Force sign out.
./.build/debug/authentication-mcp auth logout
```

To try it with no identity provider at all:

```bash
AUTH_MCP_PROVIDER=mock ./.build/debug/authentication-mcp auth login
```

Validate a real configuration without starting anything:

```bash
./.build/debug/authentication-mcp serve --check
```

## Staying signed in

**The refresh token is the persistent credential.** Access tokens expire in about
an hour; what makes sign-in feel permanent is a stored refresh token that mints
new access tokens silently. Sign-out means revoking it upstream *and* deleting it
locally.

Sign-in is a deliberate act in a terminal — the model does not decide when you
authenticate. The MCP server only ever *reads* the credential:

```
                    ┌──────────────────────────────────────┐
                    │           CredentialStore            │
                    │  keychain:  refresh + access token   │
                    │  file:      accounts.json (0600)     │
                    └──────────────────────────────────────┘
                         ▲                        ▲
              writes     │                        │   reads + refreshes
        ┌────────────────┴──────┐      ┌──────────┴───────────────┐
        │  auth login/logout    │      │  serve  (stdio)          │
        └───────────────────────┘      └──────────────────────────┘
```

### Secret in the keychain, index on disk

`accounts.json` holds the account name, subject, scopes and expiry — and **no
token**. The token is a keychain item keyed by `(service, account)`. `auth status`
therefore answers "who is signed in?" without touching the keychain, so it never
prompts. This is the same split `gh` uses (`hosts.yml` + a `gh:github.com`
keychain item).

The file backend is a fallback, not an afterthought: a headless Linux box or a
container has no Secret Service daemon. It stores the secret in plaintext at
`0600`, and `auth status` says so.

### What survives what

| Event | Credential |
| --- | --- |
| MCP client disconnects | **kept** — you signed in on purpose |
| Server process restarts | **kept** |
| Access token expires | **renewed silently** from the refresh token |
| `auth logout` | revoked upstream, deleted locally |
| `revokeAuthentication` tool | same as `auth logout` |
| Refresh fails permanently | deleted, with an error telling you to sign in again |

## Using Google

Google works out of the box, but three of its behaviours will cost you a day if
you meet them by surprise.

### 1. Register the client

Google does **not** implement Dynamic Client Registration, so you must pre-register:
Google Cloud Console → *APIs & Services → Credentials → Create credentials →
OAuth client ID → **Desktop app***.

```bash
export AUTH_MCP_PROVIDER=google
export AUTH_MCP_GOOGLE_CLIENT_ID=123....apps.googleusercontent.com
export AUTH_MCP_GOOGLE_CLIENT_SECRET=GOCSPX-...
export AUTH_MCP_OAUTH_SCOPES="openid,email,https://www.googleapis.com/auth/drive.readonly"

authentication-mcp auth login
```

The `client_secret` ships inside your binary and is **not really secret** — Google
requires one for desktop clients because its token endpoint does not accept
`none` authentication. PKCE is what actually protects the flow. Treat it as a
client identifier.

### 2. `access_type=offline` is what gives you a refresh token

Without it Google returns only an access token, and your sign-in silently stops
working an hour later. Without `prompt=consent`, a user who has already consented
gets no *new* refresh token — so it works in testing and fails for returning
users. The `google` provider sends both automatically; `auth login` warns loudly
if no refresh token comes back.

### 3. ⚠️ Testing-status apps expire refresh tokens after 7 days

An OAuth app left in **Testing** publishing status issues refresh tokens that die
after seven days, with no obvious cause. Move the app to **In production** — for
non-sensitive scopes this needs no review.

Also worth knowing: **sensitive** scopes (Gmail, Calendar, Drive) require app
verification, and **restricted** ones additionally require an annual third-party
security assessment. Decide early whether this is only for you or for others.
Google adjusts these rules; confirm them in the Console as you build.

### Scopes

`data:read` / `data:write` only make sense against an authorization server you
control. Google will never issue them, so a Google deployment defaults to **no
local scope check** and lets the Google API be the authority. Override with
`AUTH_MCP_SCOPE_READ` / `AUTH_MCP_SCOPE_WRITE` to map the tools onto real scopes.

## Design

### Tokens never reach the model

`authenticate` returns a `session_id`, never an access token. An access token can
be replayed against the upstream API from anywhere; a session id is meaningless
outside this process. `Redaction` fingerprints secrets to their last four
characters, and the audit log redacts before it writes.

### Sign-in takes more than one call

A human has to approve, and that does not fit in one tool call. `authenticate`
returns `status: "pending"` with a `user_code` and a `verification_url`, and the
model polls with the returned `flow_id`. Calling `authenticate` again *without* a
`flow_id` resumes the pending flow rather than starting a second one — starting
over would invalidate the code the user is looking at. A sign-in completed this
way is persisted exactly like a `auth login`.

### Two grants, picked automatically

- **Device authorization grant** (RFC 8628) — approve on any device. The only
  thing that works when the server is remote from the user.
- **Authorization code + PKCE** (RFC 7636) over a loopback redirect (RFC 8252) —
  the server opens the local browser and catches the redirect on 127.0.0.1.

`mode: "automatic"` picks `browser` for stdio and `device` otherwise. Force either
with `auth login --browser` / `--device`.

### Hand-off, for a redirect URI that is not ours to receive

Some client registrations have one fixed redirect URI the server cannot listen
on — a custom scheme such as `myapp://callback`, which the browser hands to the
operating system. Set `AUTH_MCP_OAUTH_REDIRECT_URI` to it and `authenticate`
gains `mode: "handoff"`: the same authorization code + PKCE grant, with the
redirect caught on the user's machine and handed back.

1. `authenticate(mode: "handoff")` returns `flow_id`, `verification_url` and
   `redirect_uri`, at once.
2. The model opens the URL with a capture tool —
   [`Tools/redirect-capture`](Tools/redirect-capture) is one — which returns the
   redirect before the OS can open an app.
3. `authenticate(flow_id, redirect_url)` checks the URL and exchanges the code.

The redirect passes through the model's context, so the server treats it as
untrusted: it must point at the registered URI and carry the flow's `state`,
it is accepted once, and the code in it is useless without the PKCE verifier,
which never leaves the server. `automatic` never picks this mode, because it only
works when the caller can capture a redirect.

### Connection-scoped sessions

Sessions are bound to a `SessionOwner` — the stdio process, or one HTTP session. A
session id from one connection reads as **not found** from another, identically to
one that never existed, so ids cannot be probed. Records are owned by the
authenticated subject and behave the same way.

**The stored credential is only ever served to the local process.** An HTTP
session cannot hydrate from it; handing a remote client the machine owner's Google
identity would be a privilege escalation, not a convenience. Persistence is
therefore off by default for `--transport http`.

### Writes are guarded, if you ask

`updatedData` takes `expected_version` from a prior `fetchData`. A stale version
fails with `version_conflict` and a remediation naming the current version.
`expected_version: 0` asserts the record does not exist. Unknown parameters are
rejected rather than ignored — a misspelled `expected_version` would otherwise
turn a guarded write into an unguarded one.

### Errors are actionable

Failures come back as `isError: true` results, not JSON-RPC errors, because a
protocol error never reaches the model and cannot be corrected. Each carries a
stable `code`, a message, a `remediation`, and a `retryable` flag. Only an unknown
tool name is a protocol-level error.

## Configuration

Everything is read from the environment; flags override where they overlap.
Secrets belong in the environment, not on a command line visible to `ps`.

### Credentials

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUTH_MCP_PERSIST_CREDENTIALS` | `true` for stdio, `false` for http | Whether sign-in survives a restart |
| `AUTH_MCP_CREDENTIAL_BACKEND` | keychain, file fallback | `keychain`, `file`, or `memory` |
| `AUTH_MCP_CREDENTIAL_DIR` | `~/.config/authentication-mcp` | Where the index and file secrets live |

### Authorization server

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUTH_MCP_PROVIDER` | `oauth` | `oauth`, `google`, or `mock` |
| `AUTH_MCP_GOOGLE_CLIENT_ID` | — | Required for `google` |
| `AUTH_MCP_GOOGLE_CLIENT_SECRET` | — | Required for `google` |
| `AUTH_MCP_OAUTH_ISSUER` | — | Required for `oauth` |
| `AUTH_MCP_OAUTH_CLIENT_ID` | — | Required for `oauth` |
| `AUTH_MCP_OAUTH_CLIENT_SECRET` | — | Omit for a public client |
| `AUTH_MCP_OAUTH_AUTH_METHOD` | `none` / `basic` | `none`, `basic`, or `post` |
| `AUTH_MCP_OAUTH_SCOPES` | provider-dependent | Scopes to request |
| `AUTH_MCP_OAUTH_RESOURCE` | — | RFC 8707 resource indicator |
| `AUTH_MCP_OAUTH_EXTRA_AUTH_PARAMS` | — | `a=1,b=2` appended to the authorization request |
| `AUTH_MCP_OAUTH_TIMEOUT_SECONDS` | `300` | How long a user has to approve |
| `AUTH_MCP_OAUTH_LOOPBACK_PORT` | `0` (OS-assigned) | Fixed redirect port |
| `AUTH_MCP_OAUTH_REDIRECT_URI` | — | The client's fixed redirect URI, e.g. `myapp://callback`. Enables `mode: "handoff"` |
| `AUTH_MCP_SCOPE_READ` / `_WRITE` | `data:read` / `data:write`, or none for Google | Scope each tool requires; `none` disables the check |

Endpoint overrides for providers with incomplete metadata:
`AUTH_MCP_OAUTH_AUTHORIZATION_ENDPOINT`, `_TOKEN_ENDPOINT`, `_DEVICE_ENDPOINT`,
`_REVOCATION_ENDPOINT`.

### Transport and storage

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUTH_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `AUTH_MCP_HTTP_HOST` / `_PORT` / `_ENDPOINT` | `127.0.0.1` / `8080` / `/mcp` | HTTP binding |
| `AUTH_MCP_ALLOWED_ORIGINS` | loopback + the `--host` address | Extra names clients may connect with, as `host:port` or a URL — checked against both `Host` and `Origin` |
| `AUTH_MCP_STORE` | `memory` | Record store: `memory` or `file` |
| `AUTH_MCP_STORE_PATH` | `./.authentication-service/records` | Directory for the file store |
| `AUTH_MCP_LOG_LEVEL` | `info` | Logs always go to stderr |

`AUTH_MCP_MOCK_POLICY` — `immediate` (default), `manual`, `deny`, `delay:<seconds>`.

## Connecting a client

```json
{
  "mcpServers": {
    "authentication-service": {
      "command": "/absolute/path/to/.build/release/authentication-mcp",
      "env": {
        "AUTH_MCP_PROVIDER": "google",
        "AUTH_MCP_GOOGLE_CLIENT_ID": "123....apps.googleusercontent.com",
        "AUTH_MCP_GOOGLE_CLIENT_SECRET": "GOCSPX-...",
        "AUTH_MCP_OAUTH_SCOPES": "openid,email"
      }
    }
  }
}
```

Run `auth login` once in a terminal with the same environment, and the server
picks the credential up. Over HTTP, point the client at
`http://127.0.0.1:8080/mcp`; `GET /healthz` answers `{"status":"ok"}`. To serve
other devices on your network, see [LOCAL_NETWORK.md](LOCAL_NETWORK.md).

## Swapping the data store

`DataStore` is a three-method protocol. `InMemoryDataStore` and `FileDataStore`
ship; Postgres, Redis, or an upstream REST API means conforming to it:

```swift
let assembly = try ServiceAssembly.make(
    options: ServiceOptions(
        provider: .oauth(configuration),
        dataStore: .custom(MyPostgresStore(pool: pool)),
        credentials: .standard(issuer: configuration.issuer)),
    logger: logger)
```

Implementations must enforce that `owner` matches the record's owner and report a
mismatch as `DataStoreError.accessDenied`.

## Layout

```
Sources/
  AuthenticationKit/        Core
    OAuth/                  Discovery, PKCE, device grant, refresh, revocation
    Credentials/            Keychain/file credential store, sign-in coordinator
    Sessions/               Connection-scoped session store
    Data/                   DataStore protocol and two implementations
    Server/                 Tool catalog, argument validation, error mapping
    Security/               Scopes, rate limiting, audit log, redaction
    Support/                JSON Schema DSL, Value helpers, timestamps
  AuthenticationHTTP/       NIO host for Streamable HTTP, Host/Origin allowlist
  AuthenticationMCPServer/  Executable: serve + auth subcommands
Tests/
  AuthenticationKitTests/   Unit and end-to-end tests over InMemoryTransport
  AuthenticationHTTPTests/  The allowlist, checked against the SDK's own validator
Tools/
  redirect-capture/         Local MCP server that captures a sign-in redirect in Chrome
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for what each of these actually does, with
diagrams for the request lifecycle, both OAuth grants, and the credential store.

## Security notes

- **Host and Origin checking.** The HTTP endpoint accepts only requests addressed
  to a name it expects — loopback, the address passed to `--host`, and anything in
  `AUTH_MCP_ALLOWED_ORIGINS` — which defends against DNS rebinding. Only binding
  every interface (`--host 0.0.0.0`) with nothing configured switches the check
  off, and the server warns when it does. The plain-HTTP endpoint is not
  encrypted; see [LOCAL_NETWORK.md](LOCAL_NETWORK.md#security-on-a-shared-network).
- **PKCE is mandatory** for the authorization code grant, per OAuth 2.1.
- **ID tokens are parsed without signature verification**, which OpenID Connect
  Core §3.1.3.7 permits only because they arrive directly from the token endpoint
  over the TLS channel this process opened.
- **Revocation is best-effort and honest about it.** RFC 7009 requires a 200 even
  for an unknown token, and the local credential is deleted regardless.
  `upstream_complete` reports whether revocation actually landed.
- **Keychain items are bound to the code signature** of the process that created
  them. A locally built binary gets a new signature on every `swift build`, so
  macOS may re-prompt. That does not happen with a signed release build; use
  `AUTH_MCP_CREDENTIAL_BACKEND=file` to avoid prompts during development.
- **Cross-process locking.** Two servers starting at once would otherwise race on
  refresh, and the loser would persist a rotated-away refresh token. A `flock`
  serialises the whole read-refresh-write cycle.

## Development

```bash
swift build
swift test
swift build -c release
```

The capture tool has its own tests, including one that drives the built server
binary through a whole hand-off sign-in. They need Chrome, and run it headless:

```bash
python3 -m unittest discover -s Tools/redirect-capture -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the conventions this codebase follows,
how PRs are reviewed, and how to report a security issue privately.

## License

[MIT](LICENSE) © 2026 [Kazi Samin Yeaser](https://github.com/ksypinro)
