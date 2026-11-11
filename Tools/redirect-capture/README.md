# redirect-capture

A local MCP server with one tool, `capture_redirect`. It is the client-side half
of the `handoff` sign-in in [authentication-mcp](../../README.md).

## The problem it solves

An OAuth client registered with a fixed, custom-scheme redirect URI such as
`myapp://callback` cannot have its redirect delivered to a server. After sign-in
the browser hands that URL to the operating system, which opens whatever app
owns the scheme.

`capture_redirect` opens the sign-in page in a Chrome window it controls and
takes the redirect before Chrome acts on it. No app opens. The URL goes back to
the model, which passes it to `authenticate`.

```
authenticate(mode: "handoff")            -> flow_id, verification_url, redirect_uri
capture_redirect(authorize_url, redirect_uri) -> redirect_url
authenticate(flow_id, redirect_url)      -> session
```

## Requirements

- Python 3, standard library only (tested with 3.13). No packages to install.
- Google Chrome or Chromium.
- macOS or Linux. It must run on the machine where the user's browser is, which
  need not be the machine running `authentication-mcp`.

## Connecting it

Add both servers to the MCP client. The authentication server needs
`AUTH_MCP_OAUTH_REDIRECT_URI`, which is what enables `mode: "handoff"`.

```json
{
  "mcpServers": {
    "authentication-service": {
      "command": "/absolute/path/to/.build/release/authentication-mcp",
      "env": {
        "AUTH_MCP_PROVIDER": "oauth",
        "AUTH_MCP_OAUTH_ISSUER": "https://your-idp.example.com",
        "AUTH_MCP_OAUTH_CLIENT_ID": "your-client-id",
        "AUTH_MCP_OAUTH_REDIRECT_URI": "myapp://callback"
      }
    },
    "redirect-capture": {
      "command": "python3",
      "args": ["/absolute/path/to/Tools/redirect-capture/redirect_capture_mcp.py"],
      "env": {
        "REDIRECT_CAPTURE_ALLOWED_HOSTS": "your-idp.example.com",
        "REDIRECT_CAPTURE_ALLOWED_REDIRECTS": "myapp://callback"
      }
    }
  }
}
```

Then ask the model to sign you in. A Chrome window opens on the sign-in page;
sign in there, and the window closes when the redirect is captured.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CHROME_PATH` | usual install locations | Chrome executable |
| `REDIRECT_CAPTURE_PROFILE_DIR` | a throwaway profile, deleted after each capture | Keep cookies here between captures, so the provider can remember you |
| `REDIRECT_CAPTURE_TIMEOUT_SECONDS` | `300` | How long a capture window stays open. Match the server's `AUTH_MCP_OAUTH_TIMEOUT_SECONDS` |
| `REDIRECT_CAPTURE_ALLOWED_HOSTS` | any | Comma-separated sign-in hosts. Any other `authorize_url` is refused |
| `REDIRECT_CAPTURE_ALLOWED_REDIRECTS` | any | Comma-separated redirect URIs. Any other `redirect_uri` is refused |
| `REDIRECT_CAPTURE_HEADLESS` | off | `1` runs Chrome with no window. For tests only: a person cannot sign in to it |

Set both allowlists. Without them the tool opens whatever URL a tool call names.

## The tool

`capture_redirect` takes `authorize_url` and `redirect_uri` to start, and
`wait_seconds` (default 60, at most 120) to bound one call. A person signing in
can take longer than a tool call is allowed to, so the result is one of:

| `status` | Meaning |
| --- | --- |
| `captured` | `redirect_url` holds the redirect. Returned once, then forgotten |
| `pending` | Still waiting. Call again with only the returned `capture_id` |
| `closed` | The user closed the window |
| `expired` | Nobody signed in before the capture timed out |
| `cancelled` | A newer capture replaced this one |

Only one capture runs at a time. Starting another closes the first window.

## How it works

Chrome is launched with `--remote-debugging-pipe` and its own profile directory.
Over that pipe the tool asks Chrome to pause every document response before
acting on it.

- **The server answers with a 3xx to the redirect URI.** The tool reads the
  `Location` header, replaces the response with a plain "Signed in" page, and
  closes Chrome. Chrome never sees the custom-scheme URL.
- **The page navigates there itself** (script, link or meta refresh). There is
  no response to pause, so the tool reads the URL from the navigation request and
  closes Chrome at once.

The DevTools pipe is a pair of file descriptors inherited by that one Chrome
process. No debugging port is opened, so other local processes cannot attach.

## What it does not protect, and what does

The captured URL carries a one-time authorization code and passes through the
model's context. That is safe only because of what the authentication server
does with it: the code is bound to a PKCE verifier that never leaves the server,
the `state` must match the flow, and each flow accepts one redirect. Do not use
this tool with a server that skips any of those.

## Limits

- It works only in the window it opens. A sign-in started in your everyday
  browser still goes to the app.
- With the default throwaway profile you sign in from scratch every time, and
  saved passwords from your normal Chrome profile are not available. Set
  `REDIRECT_CAPTURE_PROFILE_DIR` to keep a dedicated profile.
- Some providers refuse sign-in in a browser under automation. This has been
  tested against the mock authorization server here, not against a real provider.
- When the redirect is done by the page rather than by a 3xx, Chrome may show
  its "Open app?" prompt for an instant before the window closes.
- Redirects inside a cross-origin iframe are not watched.

## Trying it by hand

`mock_authorization_server.py` is a throwaway OAuth server with one client, one
fixed redirect URI, PKCE enforcement and a one-button sign-in page.

```bash
python3 Tools/redirect-capture/mock_authorization_server.py --port 9100
```

It prints the environment to give `authentication-mcp`. To watch the capture on
its own, without any MCP client:

```bash
python3 Tools/redirect-capture/chrome_redirect_capture.py "http://127.0.0.1:9100/authorize?response_type=code&client_id=demo-client&redirect_uri=myapp://callback&state=demo&code_challenge=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&code_challenge_method=S256"
```

Click "Sign in as Demo User" and the redirect URL is printed.

## Tests

```bash
python3 -m unittest discover -s Tools/redirect-capture -v
```

- `test_capture.py` runs headless Chrome against the mock server: the three ways
  a server can redirect, the no-sign-in case, and the MCP server's protocol and
  error handling.
- `test_end_to_end.py` plays the model against the real `authentication-mcp`
  binary and the real capture server, through a whole sign-in. It needs
  `swift build` first and is skipped without it.

## Files

| File | Purpose |
| --- | --- |
| `redirect_capture_mcp.py` | The MCP server (stdio) |
| `chrome_redirect_capture.py` | The capture itself; also a command-line tool |
| `mock_authorization_server.py` | Test and demo authorization server |
| `mcp_stdio_client.py` | Minimal MCP client used by the tests |
