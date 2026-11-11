#!/usr/bin/env python3
"""A local MCP server with one tool, `capture_redirect`.

It is the client-side half of the authentication server's `handoff` sign-in.
That server may be on another machine and cannot see the user's browser; this
one runs next to the browser, opens the sign-in page, and returns the redirect
the authorization server sends, for the model to hand back as `redirect_url`.

Speaks MCP over stdio (newline-delimited JSON-RPC). Standard library only.

Environment:
  CHROME_PATH                         Chrome executable, when it is not in a usual place.
  REDIRECT_CAPTURE_PROFILE_DIR        Keep cookies here between captures. Default: a
                                      throwaway profile, deleted after each capture.
  REDIRECT_CAPTURE_TIMEOUT_SECONDS    How long a capture stays open. Default 300.
  REDIRECT_CAPTURE_ALLOWED_HOSTS      Comma-separated sign-in hosts. When set, any
                                      other authorize_url is refused.
  REDIRECT_CAPTURE_ALLOWED_REDIRECTS  Comma-separated redirect URIs. When set, any
                                      other redirect_uri is refused.
  REDIRECT_CAPTURE_HEADLESS           1 to run Chrome without a window (tests only).
"""
import json
import os
import secrets
import sys
import threading
from urllib.parse import urlsplit

from chrome_redirect_capture import (
    CANCELLED, CAPTURED, CLOSED, TIMED_OUT, capture_redirect, check_authorize_url, find_chrome,
    is_redirect)

SERVER_INFO = {"name": "redirect-capture", "version": "0.1.0"}
PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
MAX_WAIT_SECONDS = 120

TOOL = {
    "name": "capture_redirect",
    "title": "Capture a sign-in redirect",
    "description": (
        "Open a sign-in page in a Chrome window on the user's machine and return the URL "
        "the browser is redirected to afterwards, without letting it open an app.\n\n"
        "Use it to finish a `handoff` sign-in: call `authenticate` with `mode: \"handoff\"`, "
        "pass its `verification_url` here as `authorize_url` and its `redirect_uri` unchanged, "
        "then give the returned `redirect_url` to `authenticate` together with the `flow_id`.\n\n"
        "The user signs in by hand, which can take minutes. If they have not finished within "
        "`wait_seconds` the result is `status: \"pending\"` with a `capture_id`; call again "
        "with only that `capture_id` to keep waiting on the same window. Do not start a "
        "second capture, which would close the window the user is typing in.\n\n"
        "The returned URL carries a one-time authorization code. Pass it to `authenticate` "
        "and nowhere else, and do not repeat it to the user."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "authorize_url": {
                "type": "string",
                "description": "The sign-in page to open: `verification_url` from `authenticate`.",
            },
            "redirect_uri": {
                "type": "string",
                "description": "The redirect to watch for: `redirect_uri` from `authenticate`, "
                               "for example myapp://callback.",
            },
            "capture_id": {
                "type": "string",
                "description": "From an earlier `pending` result, to keep waiting on that capture. "
                               "Send it alone.",
            },
            "wait_seconds": {
                "type": "integer", "minimum": 0, "maximum": MAX_WAIT_SECONDS, "default": 60,
                "description": "How long to wait before returning `pending`. Keep it under the "
                               "client's tool-call timeout; the window stays open either way.",
            },
        },
        "additionalProperties": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": [CAPTURED, "pending", CLOSED, TIMED_OUT, CANCELLED, "error"],
                "description": "'captured': `redirect_url` is ready. 'pending': still waiting, "
                               "call again with `capture_id`. 'closed': the user closed the "
                               "window. 'expired': nobody signed in in time. 'cancelled': "
                               "replaced by a newer capture. 'error': see `message`.",
            },
            "redirect_url": {"type": "string",
                             "description": "The full redirect, to pass to `authenticate`."},
            "capture_id": {"type": "string", "description": "Present when status is 'pending'."},
            "message": {"type": "string", "description": "What to do next."},
        },
        "required": ["status"],
    },
    "annotations": {"title": "Capture a sign-in redirect", "readOnlyHint": False,
                    "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
}


class ToolError(Exception):
    """A bad call, worded so the model can correct it."""


def log(message):
    # stdout carries the protocol, so anything for a human goes to stderr.
    print(f"redirect-capture: {message}", file=sys.stderr, flush=True)


def env_list(name):
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


class Capture:
    """One Chrome window waiting for one redirect, on its own thread."""

    def __init__(self, authorize_url, redirect_uri):
        self.id = "cap_" + secrets.token_urlsafe(9)
        self.result = None
        self.done = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, args=(authorize_url, redirect_uri), daemon=True)
        self._thread.start()

    def _run(self, authorize_url, redirect_uri):
        try:
            self.result = capture_redirect(
                authorize_url, redirect_uri,
                timeout=float(os.environ.get("REDIRECT_CAPTURE_TIMEOUT_SECONDS", "300")),
                headless=os.environ.get("REDIRECT_CAPTURE_HEADLESS") == "1",
                profile_dir=os.environ.get("REDIRECT_CAPTURE_PROFILE_DIR") or None,
                stop=self._stop)
        except Exception as error:  # Surfaced to the model as a tool error, not a crash.
            self.result = error
        finally:
            self.done.set()

    def cancel(self):
        self._stop.set()
        self._thread.join(timeout=10)


class Server:
    def __init__(self):
        self.capture = None

    # ---- tool ----------------------------------------------------------------

    def capture_redirect(self, arguments):
        unknown = set(arguments) - set(TOOL["inputSchema"]["properties"])
        if unknown:
            raise ToolError(f"capture_redirect does not accept {sorted(unknown)}.")
        wait = arguments.get("wait_seconds", 60)
        if isinstance(wait, bool) or not isinstance(wait, int):
            raise ToolError("`wait_seconds` must be an integer.")
        wait = max(0, min(MAX_WAIT_SECONDS, wait))

        capture_id = arguments.get("capture_id")
        if capture_id is not None:
            if self.capture is None or self.capture.id != capture_id:
                raise ToolError(
                    f"No capture '{capture_id}' is running. Start again with `authorize_url` "
                    "and `redirect_uri`, using a fresh `handoff` sign-in from `authenticate`.")
        else:
            self._start(arguments)

        capture = self.capture
        if not capture.done.wait(wait):
            return {"status": "pending", "capture_id": capture.id,
                    "message": "The sign-in window is still open. Call capture_redirect again "
                               "with only this capture_id to keep waiting."}

        self.capture = None  # Delivered once; the URL is not kept.
        result = capture.result
        if isinstance(result, Exception):
            raise ToolError(f"The capture failed: {result}")
        if result.status == CAPTURED:
            return {"status": CAPTURED, "redirect_url": result.url,
                    "message": "Pass redirect_url to `authenticate` with the flow_id of this "
                               "sign-in. Do not show it to the user."}
        advice = {
            CLOSED: "The user closed the sign-in window. Ask whether they want to try again; "
                    "if so start a fresh `handoff` sign-in with `authenticate`.",
            TIMED_OUT: "Nobody finished signing in before the capture expired. Start a fresh "
                       "`handoff` sign-in with `authenticate` and capture again.",
            CANCELLED: "This capture was replaced by a newer one.",
        }
        return {"status": result.status, "message": advice[result.status]}

    def _start(self, arguments):
        authorize_url = arguments.get("authorize_url")
        redirect_uri = arguments.get("redirect_uri")
        if not isinstance(authorize_url, str) or not isinstance(redirect_uri, str):
            raise ToolError("Send `authorize_url` and `redirect_uri` to start a capture, or "
                            "`capture_id` to keep waiting on one.")
        try:
            check_authorize_url(authorize_url)
            find_chrome()
        except (ValueError, FileNotFoundError) as error:
            raise ToolError(str(error))
        if not urlsplit(redirect_uri).scheme:
            raise ToolError("`redirect_uri` must be absolute, for example myapp://callback.")

        allowed_hosts = env_list("REDIRECT_CAPTURE_ALLOWED_HOSTS")
        host = (urlsplit(authorize_url).hostname or "").lower()
        if allowed_hosts and host not in (item.lower() for item in allowed_hosts):
            raise ToolError(f"Sign-in host '{host}' is not in REDIRECT_CAPTURE_ALLOWED_HOSTS.")
        allowed_redirects = env_list("REDIRECT_CAPTURE_ALLOWED_REDIRECTS")
        if allowed_redirects and not any(is_redirect(redirect_uri, item) for item in allowed_redirects):
            raise ToolError("That redirect_uri is not in REDIRECT_CAPTURE_ALLOWED_REDIRECTS.")

        if self.capture is not None:
            self.capture.cancel()  # One window at a time.
        self.capture = Capture(authorize_url, redirect_uri)
        log(f"capture {self.capture.id} opened {host} watching {urlsplit(redirect_uri).scheme}:")

    # ---- protocol ------------------------------------------------------------

    def handle(self, request):
        method = request.get("method")
        params = request.get("params") or {}
        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            return {"protocolVersion": version, "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [TOOL]}
        if method == "tools/call":
            if params.get("name") != TOOL["name"]:
                raise LookupError(f"No tool named '{params.get('name')}'")
            return self.call_tool(params.get("arguments") or {})
        raise LookupError(f"Method not found: {method}")

    def call_tool(self, arguments):
        try:
            payload, failed = self.capture_redirect(arguments), False
        except ToolError as error:
            # Reported as a result, not a protocol error: a protocol error never
            # reaches the model, so the model could not correct the call.
            payload, failed = {"status": "error", "message": str(error)}, True
        return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                "structuredContent": payload, "isError": failed}

    def serve(self, lines=sys.stdin.buffer, out=sys.stdout):
        try:
            for line in lines:
                if not line.strip():
                    continue
                try:
                    request = json.loads(line)
                except ValueError:
                    self._reply(out, {"jsonrpc": "2.0", "id": None,
                                      "error": {"code": -32700, "message": "Parse error"}})
                    continue
                if not isinstance(request, dict) or "id" not in request:
                    continue  # A notification, or something we cannot answer.
                try:
                    reply = {"jsonrpc": "2.0", "id": request["id"], "result": self.handle(request)}
                except LookupError as error:
                    reply = {"jsonrpc": "2.0", "id": request["id"],
                             "error": {"code": -32601, "message": str(error)}}
                self._reply(out, reply)
        finally:
            if self.capture is not None:
                self.capture.cancel()  # Never leave a sign-in window behind.

    @staticmethod
    def _reply(out, message):
        out.write(json.dumps(message) + "\n")
        out.flush()


if __name__ == "__main__":
    Server().serve()
