"""The whole hand-off sign-in, with every real piece in place.

This test plays the model. It talks to the real authentication server binary
and the real capture server over MCP, exactly as an MCP host would, with a mock
authorization server standing in for the identity provider and headless Chrome
standing in for the user's browser:

    authenticate(mode: handoff)      -> flow_id, verification_url, redirect_uri
    capture_redirect(...)            -> redirect_url
    authenticate(flow_id, redirect_url) -> session

Needs `swift build` to have produced the server binary; skipped otherwise.
"""
import os
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from chrome_redirect_capture import find_chrome
from mcp_stdio_client import StdioClient
from mock_authorization_server import MockAuthorizationServer

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent
REDIRECT = "myapp://callback"


def server_binary():
    explicit = os.environ.get("AUTH_MCP_BINARY")
    candidates = [Path(explicit)] if explicit else [
        REPOSITORY / ".build" / "debug" / "authentication-mcp",
        REPOSITORY / ".build" / "release" / "authentication-mcp",
    ]
    return next((path for path in candidates if path.is_file()), None)


def skip_reason():
    if server_binary() is None:
        return "authentication-mcp is not built; run `swift build` first"
    try:
        find_chrome()
    except FileNotFoundError as error:
        return str(error)
    return None


@unittest.skipIf(skip_reason(), skip_reason())
class HandoffEndToEndTests(unittest.TestCase):

    def setUp(self):
        self.idp = MockAuthorizationServer(redirect_uri=REDIRECT, auto_approve_after=0)
        self.idp.__enter__()
        self.addCleanup(self.idp.__exit__)

        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("AUTH_MCP_")}
        self.auth = StdioClient([str(server_binary())], env=dict(
            environment,
            AUTH_MCP_PROVIDER="oauth",
            AUTH_MCP_OAUTH_ISSUER=self.idp.issuer,
            AUTH_MCP_OAUTH_CLIENT_ID=self.idp.client_id,
            AUTH_MCP_OAUTH_REDIRECT_URI=REDIRECT,
            AUTH_MCP_OAUTH_SCOPES="data:read data:write",
            # Nothing from this test may land in the developer's keychain.
            AUTH_MCP_PERSIST_CREDENTIALS="false",
            AUTH_MCP_STORE="memory",
            AUTH_MCP_LOG_LEVEL="error"))
        self.addCleanup(self.auth.close)

        self.capture = StdioClient(
            [sys.executable, str(HERE / "redirect_capture_mcp.py")], cwd=HERE,
            env=dict(os.environ, REDIRECT_CAPTURE_HEADLESS="1"))
        self.addCleanup(self.capture.close)

    def start_and_capture(self):
        pending = self.auth.call("authenticate", {"mode": "handoff"})
        self.assertEqual(pending["status"], "pending", pending)
        self.assertEqual(pending["redirect_uri"], REDIRECT)
        self.assertNotIn("user_code", pending)

        captured = self.capture.call("capture_redirect", {
            "authorize_url": pending["verification_url"],
            "redirect_uri": pending["redirect_uri"],
            "wait_seconds": 30})
        self.assertEqual(captured["status"], "captured", captured)
        return pending, captured["redirect_url"]

    def test_sign_in_through_a_captured_redirect(self):
        pending, redirect_url = self.start_and_capture()

        done = self.auth.call(
            "authenticate", {"flow_id": pending["flow_id"], "redirect_url": redirect_url})

        self.assertEqual(done["status"], "authenticated", done)
        self.assertEqual(done["session"]["subject"], "demo-user-1")
        self.assertEqual(done["session"]["principal_name"], "Demo User")
        self.assertEqual(sorted(done["session"]["scopes"]), ["data:read", "data:write"])

        # The identity provider saw one exchange, bound to the fixed redirect URI
        # and carrying a verifier — which it checked against the challenge.
        self.assertEqual(len(self.idp.token_requests), 1)
        exchange = self.idp.token_requests[0]
        self.assertEqual(exchange["redirect_uri"], REDIRECT)
        self.assertEqual(exchange["code"], parse_qs(urlsplit(redirect_url).query)["code"][0])
        self.assertTrue(exchange["code_verifier"])

        # Nothing secret came back to the model.
        rendered = str(done)
        self.assertNotIn("mock_access_", rendered)
        self.assertNotIn("mock_refresh_", rendered)
        self.assertNotIn(exchange["code"], rendered)

        # And the session is real: the data tools accept it.
        written = self.auth.call("updatedData", {"id": "note", "value": {"text": "hello"}})
        self.assertTrue(written["ok"], written)
        read = self.auth.call("fetchData", {"id": "note"})
        self.assertEqual(read["value"], {"text": "hello"})

    def test_a_captured_redirect_works_once(self):
        pending, redirect_url = self.start_and_capture()
        arguments = {"flow_id": pending["flow_id"], "redirect_url": redirect_url}
        self.assertEqual(self.auth.call("authenticate", arguments)["status"], "authenticated")

        replay = self.auth.call("authenticate", arguments)

        self.assertFalse(replay["ok"])
        self.assertEqual(len(self.idp.token_requests), 1, "the replay must not reach the provider")

    def test_a_redirect_from_another_sign_in_is_refused(self):
        # Two sign-ins; the redirect captured for the first is offered to the second.
        _, first_redirect = self.start_and_capture()
        second = self.auth.call("authenticate", {"mode": "handoff", "force": True})

        crossed = self.auth.call(
            "authenticate", {"flow_id": second["flow_id"], "redirect_url": first_redirect})

        self.assertFalse(crossed["ok"])
        self.assertEqual(crossed["error"]["code"], "authorization_failed")
        self.assertEqual(self.idp.token_requests, [], "a mismatched state must stop before the exchange")
        self.assertEqual(self.auth.call("fetchData", {"id": "note"})["error"]["code"],
                         "not_authenticated")


if __name__ == "__main__":
    unittest.main()
