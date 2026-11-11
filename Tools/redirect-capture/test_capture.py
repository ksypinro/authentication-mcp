"""Tests for the redirect capture and its MCP server.

Chrome runs headless against a local mock authorization server, so nothing
opens on screen and no network is needed.

    python3 -m unittest discover -s Tools/redirect-capture -v
"""
import os
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from chrome_redirect_capture import (
    CAPTURED, TIMED_OUT, capture_redirect, check_authorize_url, find_chrome, is_redirect)
from mcp_stdio_client import StdioClient
from mock_authorization_server import MockAuthorizationServer

HERE = Path(__file__).resolve().parent
REDIRECT = "myapp://callback"

try:
    find_chrome()
    CHROME_MISSING = None
except FileNotFoundError as error:
    CHROME_MISSING = str(error)


def authorize_url(server, state="state-1"):
    return server.issuer + "/authorize?" + urlencode({
        "response_type": "code", "client_id": server.client_id, "redirect_uri": REDIRECT,
        "state": state, "code_challenge": "x" * 43, "code_challenge_method": "S256"})


class MatchingTests(unittest.TestCase):
    def test_redirect_matching_ignores_query_and_case_but_not_path(self):
        self.assertTrue(is_redirect("myapp://callback?code=c&state=s", REDIRECT))
        self.assertTrue(is_redirect("MyApp://CALLBACK?code=c", REDIRECT))
        self.assertTrue(is_redirect("com.example.app:/oauth?code=c", "com.example.app:/oauth"))
        for other in ("myapp://callback/extra?code=c", "myapp://other?code=c",
                      "otherapp://callback?code=c", "https://callback/?code=c",
                      "https://evil.example/?next=myapp://callback", ""):
            self.assertFalse(is_redirect(other, REDIRECT), other)

    def test_only_web_sign_in_pages_are_opened(self):
        check_authorize_url("https://login.example.com/authorize?x=1")
        check_authorize_url("http://127.0.0.1:9100/authorize")
        for refused in ("file:///etc/passwd", "chrome://settings", "javascript:alert(1)",
                        "http://login.example.com/authorize", "myapp://callback", "https://"):
            with self.assertRaises(ValueError, msg=refused):
                check_authorize_url(refused)


@unittest.skipIf(CHROME_MISSING, CHROME_MISSING)
class CaptureTests(unittest.TestCase):
    def capture(self, style, **options):
        with MockAuthorizationServer(auto_approve_after=0, redirect_style=style) as server:
            return capture_redirect(authorize_url(server, f"st-{style}"), REDIRECT,
                                    headless=True, **options)

    def test_every_way_a_server_can_redirect_is_captured(self):
        for style in ("302", "js", "meta"):
            with self.subTest(style=style):
                result = self.capture(style, timeout=20)
                self.assertEqual(result.status, CAPTURED)
                self.assertTrue(is_redirect(result.url, REDIRECT))
                query = parse_qs(urlsplit(result.url).query)
                self.assertEqual(query["state"], [f"st-{style}"])
                self.assertTrue(query["code"][0])

    def test_no_sign_in_means_no_redirect(self):
        with MockAuthorizationServer(auto_approve_after=None) as server:
            result = capture_redirect(authorize_url(server), REDIRECT, timeout=3, headless=True)
        self.assertEqual(result.status, TIMED_OUT)
        self.assertEqual(result.url, "")

    def test_a_redirect_to_somewhere_else_is_not_returned(self):
        # The server redirects to myapp://callback, but we watch for another URI.
        with MockAuthorizationServer(auto_approve_after=0) as server:
            result = capture_redirect(authorize_url(server), "myapp://elsewhere",
                                      timeout=4, headless=True)
        self.assertEqual(result.status, TIMED_OUT)

    def test_the_throwaway_profile_is_removed(self):
        import glob
        import tempfile
        pattern = os.path.join(tempfile.gettempdir(), "redirect-capture-*")
        before = set(glob.glob(pattern))
        self.capture("302", timeout=20)
        self.assertEqual(set(glob.glob(pattern)) - before, set())


@unittest.skipIf(CHROME_MISSING, CHROME_MISSING)
class MCPServerTests(unittest.TestCase):
    def client(self, **extra_env):
        env = dict(os.environ, REDIRECT_CAPTURE_HEADLESS="1", **extra_env)
        return StdioClient([sys.executable, str(HERE / "redirect_capture_mcp.py")], env=env, cwd=HERE)

    def test_the_tool_is_listed_with_schemas(self):
        with self.client() as client:
            self.assertEqual(client.server["serverInfo"]["name"], "redirect-capture")
            tools = client.request("tools/list")["tools"]
            self.assertEqual([tool["name"] for tool in tools], ["capture_redirect"])
            self.assertEqual(tools[0]["inputSchema"]["type"], "object")
            self.assertIn("outputSchema", tools[0])

    def test_pending_then_captured_on_the_same_capture(self):
        with MockAuthorizationServer(auto_approve_after=3) as server, self.client() as client:
            first = client.call("capture_redirect", {
                "authorize_url": authorize_url(server, "st-mcp"), "redirect_uri": REDIRECT,
                "wait_seconds": 0})
            self.assertEqual(first["status"], "pending")
            self.assertNotIn("redirect_url", first)

            second = client.call("capture_redirect",
                                 {"capture_id": first["capture_id"], "wait_seconds": 30})
            self.assertEqual(second["status"], "captured")
            self.assertEqual(parse_qs(urlsplit(second["redirect_url"]).query)["state"], ["st-mcp"])

            # Delivered once: the capture is gone, and so is the URL.
            third = client.request("tools/call", {
                "name": "capture_redirect", "arguments": {"capture_id": first["capture_id"]}})
            self.assertTrue(third["isError"])
            self.assertNotIn("redirect_url", third["structuredContent"])

    def test_bad_calls_come_back_as_tool_errors_the_model_can_read(self):
        with self.client(REDIRECT_CAPTURE_ALLOWED_HOSTS="login.example.com",
                         REDIRECT_CAPTURE_ALLOWED_REDIRECTS=REDIRECT) as client:
            for arguments, expected in (
                ({}, "authorize_url"),
                ({"authorize_url": "file:///etc/passwd", "redirect_uri": REDIRECT}, "https"),
                ({"authorize_url": "https://other.example/a", "redirect_uri": REDIRECT},
                 "ALLOWED_HOSTS"),
                ({"authorize_url": "https://login.example.com/a", "redirect_uri": "x://y"},
                 "ALLOWED_REDIRECTS"),
                ({"authorize_url": "https://login.example.com/a", "redirect_uri": REDIRECT,
                  "extra": 1}, "extra"),
                ({"capture_id": "cap_nope"}, "cap_nope"),
            ):
                with self.subTest(arguments=arguments):
                    result = client.request(
                        "tools/call", {"name": "capture_redirect", "arguments": arguments})
                    self.assertTrue(result["isError"])
                    self.assertEqual(result["structuredContent"]["status"], "error")
                    self.assertIn(expected, result["structuredContent"]["message"])

            with self.assertRaises(RuntimeError):
                client.request("tools/call", {"name": "no_such_tool", "arguments": {}})
            self.assertEqual(client.request("ping"), {})


if __name__ == "__main__":
    unittest.main()
