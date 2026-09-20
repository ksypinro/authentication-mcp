import Foundation
import MCP

/// The four tools this server exposes, with their JSON Schemas.
///
/// Schemas are the only contract a model ever sees, so they carry the operational
/// detail that would otherwise have to be guessed: which tool to call first, what
/// a `pending` result means, and how to recover from a version conflict.
public enum ToolCatalog {

    public enum Name {
        public static let authenticate = "authenticate"
        public static let revokeAuthentication = "revokeAuthentication"
        public static let fetchData = "fetchData"
        public static let updatedData = "updatedData"

        public static let all = [authenticate, revokeAuthentication, fetchData, updatedData]
    }

    public static var allTools: [Tool] {
        [authenticate, revokeAuthentication, fetchData, updatedData]
    }

    // MARK: - authenticate

    public static let authenticate = Tool(
        name: Name.authenticate,
        title: "Sign in",
        description: """
            Start or complete an OAuth 2.1 sign-in, and return the resulting session.

            Call this before `fetchData` or `updatedData`. If a valid session already \
            exists it is returned unchanged, so calling this tool again is cheap and safe.

            Sign-in needs a human, so the first call usually returns `status: "pending"` \
            along with a `verification_url` and a `user_code`. Show both to the user \
            verbatim, then call this tool again with the returned `flow_id` to check \
            whether they have finished. Keep polling with the same `flow_id`; do not \
            start a second flow, which would invalidate the code the user is looking at.

            Access tokens are deliberately never returned. Pass the `session_id` from \
            this result to the other tools instead.
            """,
        inputSchema: JSONSchema.object(
            properties: [
                "scopes": JSONSchema.array(
                    """
                    OAuth scopes to request. Defaults to the server's configured set. \
                    `data:read` is required by `fetchData` and `data:write` by `updatedData`.
                    """,
                    items: JSONSchema.string("An OAuth scope, e.g. 'data:read'."),
                    maxItems: 32,
                    uniqueItems: true),
                "mode": JSONSchema.string(
                    """
                    How the user signs in. 'device' shows a code to type on any device and \
                    is the only mode that works when this server is remote. 'browser' opens \
                    the local browser, and only works when the server runs on the user's own \
                    machine. 'automatic' picks the right one.
                    """,
                    enumValues: AuthorizationMode.allCases.map(\.rawValue),
                    default: AuthorizationMode.automatic.rawValue),
                "flow_id": JSONSchema.string(
                    """
                    The `flow_id` from an earlier `pending` result, to check whether the \
                    user has finished. Omit to start a new sign-in.
                    """),
                "wait_seconds": JSONSchema.integer(
                    """
                    How long to wait for the user before returning `pending`. Keep this \
                    well under the client's tool-call timeout; the flow stays alive either way.
                    """,
                    minimum: 0,
                    maximum: 120,
                    default: 30),
                "force": JSONSchema.boolean(
                    """
                    Start a new sign-in even if a valid session already exists. Use only \
                    when the user asks to switch accounts.
                    """,
                    default: false),
            ],
            required: []),
        annotations: Tool.Annotations(
            title: "Sign in",
            readOnlyHint: false,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: true),
        outputSchema: JSONSchema.object(
            properties: [
                "status": JSONSchema.string(
                    """
                    'authenticated' — a session is ready. 'pending' — waiting on the user; \
                    show them the code and call again with `flow_id`. 'denied' — the user \
                    refused. 'expired' — the code timed out; start again without a `flow_id`.
                    """,
                    enumValues: ["authenticated", "pending", "denied", "expired"]),
                "session": JSONSchema.object(
                    description: "Present when status is 'authenticated'.",
                    properties: [
                        "session_id": JSONSchema.string(
                            "Pass this to `fetchData` and `updatedData`."),
                        "subject": JSONSchema.string("The authenticated principal."),
                        "principal_name": JSONSchema.string("A display name, when known."),
                        "scopes": JSONSchema.array(
                            "Scopes actually granted, which may be narrower than requested.",
                            items: JSONSchema.string("A granted scope.")),
                        "token_type": JSONSchema.string("Usually 'Bearer'."),
                        "provider": JSONSchema.string("The authorization server."),
                        "created_at": JSONSchema.timestamp("When the session was created."),
                        "expires_at": JSONSchema.timestamp("When the access token expires."),
                        "expires_in_seconds": JSONSchema.integer("Seconds until expiry."),
                        "can_refresh": JSONSchema.boolean(
                            "Whether the session renews itself automatically."),
                    ],
                    required: ["session_id", "subject", "scopes"]),
                "flow_id": JSONSchema.string(
                    "Present when status is 'pending'. Pass it back to keep polling."),
                "user_code": JSONSchema.string(
                    "Present for a pending device sign-in. Show this to the user verbatim."),
                "verification_url": JSONSchema.string("Where the user completes sign-in."),
                "verification_url_complete": JSONSchema.string(
                    "The same URL with the code pre-filled, when the provider offers one."),
                "expires_at": JSONSchema.timestamp("When the pending request stops being accepted."),
                "instructions": JSONSchema.string("A sentence to relay to the user."),
                "reason": JSONSchema.string("Why sign-in was denied, when status is 'denied'."),
            ],
            required: ["status"]))

    // MARK: - revokeAuthentication

    public static let revokeAuthentication = Tool(
        name: Name.revokeAuthentication,
        title: "Sign out",
        description: """
            Revoke a session's credentials at the authorization server and destroy it here.

            The local session is always destroyed, even if the authorization server \
            cannot be reached — check `upstream_complete` to see whether the tokens were \
            also revoked remotely. Revoking an already-revoked or unknown session succeeds \
            quietly, so this is safe to call more than once.

            After this, `fetchData` and `updatedData` fail until `authenticate` runs again.
            """,
        inputSchema: JSONSchema.object(
            properties: [
                "session_id": JSONSchema.string(
                    "The session to revoke. Defaults to the active one."),
                "all_sessions": JSONSchema.boolean(
                    "Revoke every session on this connection. Overrides `session_id`.",
                    default: false),
            ],
            required: []),
        annotations: Tool.Annotations(
            title: "Sign out",
            readOnlyHint: false,
            // Destroys credentials, so a client should treat it as destructive,
            // but repeating it changes nothing further.
            destructiveHint: true,
            idempotentHint: true,
            openWorldHint: true),
        outputSchema: JSONSchema.object(
            properties: [
                "revoked_session_ids": JSONSchema.array(
                    "The sessions that were destroyed. Empty if there was nothing to revoke.",
                    items: JSONSchema.string("A session id.")),
                "access_token": JSONSchema.string(
                    "What happened to the access token upstream.",
                    enumValues: ["revoked", "not_present", "unsupported", "failed"]),
                "refresh_token": JSONSchema.string(
                    "What happened to the refresh token upstream.",
                    enumValues: ["revoked", "not_present", "unsupported", "failed"]),
                "upstream_complete": JSONSchema.boolean(
                    """
                    True when the authorization server confirmed the revocation. False means \
                    the local session is gone but the tokens may still be live upstream \
                    until they expire.
                    """),
                "warning": JSONSchema.string("Why the upstream revocation did not complete."),
            ],
            required: ["revoked_session_ids", "upstream_complete"]))

    // MARK: - fetchData

    public static let fetchData = Tool(
        name: Name.fetchData,
        title: "Fetch a record",
        description: """
            Read one record by id. Requires an authenticated session with the \
            `data:read` scope, and returns only records belonging to that principal.

            The result carries a `version` and an `etag`. Pass either to `updatedData` \
            as `expected_version` to make a follow-up write fail rather than silently \
            overwrite a change made in between.
            """,
        inputSchema: JSONSchema.object(
            properties: [
                "id": JSONSchema.string(
                    "The record identifier.",
                    minLength: 1,
                    maxLength: DataStoreLimits.maximumIdentifierLength,
                    examples: ["user-profile", "settings/theme"]),
                "session_id": JSONSchema.string(
                    "The session from `authenticate`. Defaults to the active one."),
                "include_metadata": JSONSchema.boolean(
                    "Include version, ownership and timestamps alongside the value.",
                    default: true),
            ],
            required: ["id"]),
        annotations: Tool.Annotations(
            title: "Fetch a record",
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: false),
        outputSchema: JSONSchema.object(
            properties: [
                "id": JSONSchema.string("The record identifier."),
                "value": JSONSchema.freeformObject("The stored JSON value."),
                "metadata": JSONSchema.object(
                    description: "Present unless `include_metadata` was false.",
                    properties: [
                        "version": JSONSchema.integer("Current version; increments on every write."),
                        "etag": JSONSchema.string("The version as a weak HTTP entity tag."),
                        "owner": JSONSchema.string("The principal that owns the record."),
                        "created_at": JSONSchema.timestamp("When the record was created."),
                        "updated_at": JSONSchema.timestamp("When it was last written."),
                        "updated_by": JSONSchema.string("Who last wrote it."),
                    ],
                    required: ["version", "etag"]),
            ],
            required: ["id", "value"]))

    // MARK: - updatedData

    public static let updatedData = Tool(
        name: Name.updatedData,
        title: "Write a record",
        description: """
            Create or update a record. Requires an authenticated session with the \
            `data:write` scope.

            By default `value` replaces the stored value entirely. Set `merge` to true \
            to shallow-merge top-level keys instead; in merge mode an explicit null \
            deletes a key.

            To avoid clobbering a concurrent change, pass `expected_version` from a prior \
            `fetchData`. The write then fails with a version conflict if the record moved \
            on — re-read it, reapply your change, and retry. Pass `expected_version: 0` to \
            require that the record does not already exist.
            """,
        inputSchema: JSONSchema.object(
            properties: [
                "id": JSONSchema.string(
                    "The record identifier. Created if it does not exist.",
                    minLength: 1,
                    maxLength: DataStoreLimits.maximumIdentifierLength),
                "value": JSONSchema.freeformObject(
                    """
                    The JSON object to store. Must be an object, not a bare array or scalar, \
                    so that `merge` has well-defined semantics.
                    """),
                "session_id": JSONSchema.string(
                    "The session from `authenticate`. Defaults to the active one."),
                "expected_version": JSONSchema.integer(
                    """
                    Apply the write only if the record is still at this version. Use 0 to \
                    assert it does not exist yet. Omit to overwrite unconditionally.
                    """,
                    minimum: 0),
                "merge": JSONSchema.boolean(
                    "Shallow-merge top-level keys instead of replacing the value.",
                    default: false),
            ],
            required: ["id", "value"]),
        annotations: Tool.Annotations(
            title: "Write a record",
            readOnlyHint: false,
            // Replaces the stored value, and repeating it is only safe when
            // `expected_version` is supplied.
            destructiveHint: true,
            idempotentHint: false,
            openWorldHint: false),
        outputSchema: JSONSchema.object(
            properties: [
                "id": JSONSchema.string("The record identifier."),
                "version": JSONSchema.integer("The version after this write."),
                "previous_version": JSONSchema.integer("The version before it; absent on create."),
                "created": JSONSchema.boolean("True when this call created the record."),
                "etag": JSONSchema.string("The new version as a weak entity tag."),
                "updated_at": JSONSchema.timestamp("When the write landed."),
                "value": JSONSchema.freeformObject("The value as now stored, after any merge."),
            ],
            required: ["id", "version", "created", "value"]))
}
