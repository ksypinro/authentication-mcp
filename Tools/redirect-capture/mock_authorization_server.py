#!/usr/bin/env python3
"""A throwaway OAuth 2.1 authorization server for trying the hand-off sign-in.

It registers one public client with one fixed, custom-scheme redirect URI, which
is the situation the hand-off flow exists for. It enforces what a real server
would: the exact redirect URI, PKCE S256, and single-use codes. It has no users
and no passwords: the sign-in page is one button.

Run it to try the flow by hand; the tests import it.

    python3 mock_authorization_server.py --port 9100

Never use it for anything real. Its tokens are random strings and its ID token
is unsigned.
"""
import argparse
import base64
import hashlib
import html
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class MockAuthorizationServer:
    """Serves discovery, /authorize, /approve and /token on 127.0.0.1.

    `auto_approve_after`: seconds after which the sign-in page presses its own
    button, standing in for the user in tests. None waits for a real click.
    `redirect_style`: how the redirect is delivered: "302", "js" or "meta".
    """

    def __init__(self, client_id="demo-client", redirect_uri="myapp://callback", port=0,
                 auto_approve_after=None, redirect_style="302"):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.auto_approve_after = auto_approve_after
        self.redirect_style = redirect_style
        self.pending = {}      # transaction id -> the authorization request
        self.codes = {}        # authorization code -> the request it was issued for
        self.token_requests = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), self._handler())
        self.issuer = f"http://127.0.0.1:{self.httpd.server_port}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _handler(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body, content_type="text/html; charset=utf-8", headers=()):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                for name, value in headers:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            def _json(self, status, payload):
                self._send(status, json.dumps(payload), "application/json")

            def do_GET(self):
                url = urlsplit(self.path)
                query = {key: values[0] for key, values in parse_qs(url.query).items()}
                if url.path == "/.well-known/oauth-authorization-server":
                    self._json(200, {
                        "issuer": owner.issuer,
                        "authorization_endpoint": owner.issuer + "/authorize",
                        "token_endpoint": owner.issuer + "/token",
                        "response_types_supported": ["code"],
                        "grant_types_supported": ["authorization_code"],
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": ["none"],
                    })
                elif url.path == "/authorize":
                    self._authorize(query)
                elif url.path == "/approve":
                    self._approve(query)
                else:
                    self._send(404, "Not found")

            def _authorize(self, query):
                problem = None
                if query.get("client_id") != owner.client_id:
                    problem = "unknown client_id"
                elif query.get("redirect_uri") != owner.redirect_uri:
                    # Exact match, and never redirect to an unregistered URI.
                    problem = "redirect_uri is not the one registered for this client"
                elif query.get("response_type") != "code":
                    problem = "response_type must be code"
                elif query.get("code_challenge_method") != "S256" or not query.get("code_challenge"):
                    problem = "PKCE with S256 is required"
                if problem:
                    self._send(400, f"<h1>Sign-in request rejected</h1><p>{problem}</p>")
                    return

                transaction = secrets.token_urlsafe(12)
                owner.pending[transaction] = query
                approve = f"/approve?tx={transaction}"
                auto = ""
                if owner.auto_approve_after is not None:
                    delay = int(owner.auto_approve_after * 1000)
                    auto = f"<script>setTimeout(() => location.href = {approve!r}, {delay})</script>"
                self._send(200, (
                    "<!doctype html><meta charset=utf-8><title>Mock sign-in</title>"
                    "<body style='font:16px system-ui;max-width:28rem;margin:4rem auto'>"
                    "<h1>Mock sign-in</h1><p>This is a test authorization server. "
                    f"Client <b>{owner.client_id}</b> is asking for: "
                    f"<code>{html.escape(query.get('scope', '(no scopes)'))}</code></p>"
                    f"<p><a id=approve href='{approve}'><button>Sign in as Demo User</button></a> "
                    f"<a href='{approve}&deny=1'><button>Decline</button></a></p>{auto}"))

            def _approve(self, query):
                request = owner.pending.pop(query.get("tx", ""), None)
                if request is None:
                    self._send(400, "This sign-in page was already used.")
                    return
                if query.get("deny"):
                    answer = {"error": "access_denied", "error_description": "the user declined"}
                else:
                    code = secrets.token_urlsafe(24)
                    owner.codes[code] = request
                    answer = {"code": code}
                if "state" in request:
                    answer["state"] = request["state"]
                separator = "&" if "?" in owner.redirect_uri else "?"
                target = owner.redirect_uri + separator + urlencode(answer)

                if owner.redirect_style == "js":
                    self._send(200, f"<script>window.location = {target!r}</script>")
                elif owner.redirect_style == "meta":
                    self._send(200, f"<meta http-equiv=refresh content=\"0;url={target}\">")
                else:
                    self._send(302, "", headers=[("Location", target)])

            def do_POST(self):
                if urlsplit(self.path).path != "/token":
                    self._send(404, "Not found")
                    return
                length = int(self.headers.get("Content-Length", "0"))
                form = {key: values[0]
                        for key, values in parse_qs(self.rfile.read(length).decode()).items()}
                owner.token_requests.append(form)

                def reject(description):
                    self._json(400, {"error": "invalid_grant", "error_description": description})

                if form.get("grant_type") != "authorization_code":
                    self._json(400, {"error": "unsupported_grant_type"})
                    return
                # Single use: the code is gone whether or not the rest checks out.
                request = owner.codes.pop(form.get("code", ""), None)
                if request is None:
                    return reject("unknown or already used code")
                if form.get("client_id") != owner.client_id:
                    return reject("client_id does not match")
                if form.get("redirect_uri") != owner.redirect_uri:
                    return reject("redirect_uri does not match the authorization request")
                challenge = b64url(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
                if challenge != request["code_challenge"]:
                    return reject("PKCE verification failed")

                claims = {"iss": owner.issuer, "aud": owner.client_id, "sub": "demo-user-1",
                          "name": "Demo User"}
                id_token = ".".join([b64url(b'{"alg":"none","typ":"JWT"}'),
                                     b64url(json.dumps(claims).encode()), "unsigned"])
                self._json(200, {
                    "access_token": "mock_access_" + secrets.token_urlsafe(16),
                    "refresh_token": "mock_refresh_" + secrets.token_urlsafe(16),
                    "token_type": "Bearer", "expires_in": 3600,
                    "scope": request.get("scope", ""), "id_token": id_token,
                })

        return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--client-id", default="demo-client")
    parser.add_argument("--redirect-uri", default="myapp://callback")
    options = parser.parse_args()

    with MockAuthorizationServer(options.client_id, options.redirect_uri, options.port) as server:
        print(f"Mock authorization server on {server.issuer} (Ctrl-C to stop)\n")
        print("Environment for authentication-mcp:")
        print("  AUTH_MCP_PROVIDER=oauth")
        print(f"  AUTH_MCP_OAUTH_ISSUER={server.issuer}")
        print(f"  AUTH_MCP_OAUTH_CLIENT_ID={options.client_id}")
        print(f"  AUTH_MCP_OAUTH_REDIRECT_URI={options.redirect_uri}")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
