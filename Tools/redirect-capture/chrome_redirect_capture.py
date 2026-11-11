#!/usr/bin/env python3
"""Catch an OAuth redirect in Chrome before the operating system sees it.

A client registered with a fixed redirect URI such as `myapp://callback` cannot
have its redirect delivered to a server: the browser hands a custom scheme to
the OS, which opens whatever app owns it. This module launches its own Chrome
window, pauses every document response over the DevTools pipe, and takes the
redirect when it appears, so nothing is opened and the caller decides what
happens next.

Standard library only, macOS and Linux. The DevTools pipe is private to this
process: no debugging port is opened for other local processes to attach to.

    python3 chrome_redirect_capture.py "https://auth.example/authorize?..." \
        --redirect-uri myapp://callback
"""
import argparse
import base64
import fcntl
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

CHROME_CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
)

DONE_PAGE = (
    "<!doctype html><meta charset=utf-8><title>Signed in</title>"
    "<body style='font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0'>"
    "<p>Signed in. You can close this window.</p>"
)

CAPTURED, TIMED_OUT, CLOSED, CANCELLED = "captured", "expired", "closed", "cancelled"


@dataclass(frozen=True)
class CaptureResult:
    """How a capture ended. `url` is set only when `status` is CAPTURED."""
    status: str
    url: str = ""


def find_chrome(explicit=None):
    """The Chrome binary to launch: an explicit path, $CHROME_PATH, or a known location."""
    for candidate in (explicit, os.environ.get("CHROME_PATH"), *CHROME_CANDIDATES):
        if not candidate:
            continue
        path = candidate if os.path.isabs(candidate) else shutil.which(candidate)
        if path and os.access(path, os.X_OK):
            return path
    raise FileNotFoundError("Chrome was not found. Set CHROME_PATH to its executable.")


def check_authorize_url(url):
    """Refuse anything but a web sign-in page.

    The URL arrives from a tool call, so it is not trusted to be one: `file:`,
    `chrome:` and `javascript:` would turn "open the sign-in page" into reading
    local files or running script. Plain http is allowed for loopback only.
    """
    parts = urlsplit(url)
    loopback = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and loopback:
        return
    raise ValueError("authorize_url must be an https URL (http is allowed for loopback only)")


def is_redirect(url, redirect_uri):
    """Whether `url` is a navigation to `redirect_uri`, ignoring its query.

    Compared the way the authentication server compares it: scheme and host
    without regard to case, path exactly.
    """
    try:
        seen, expected = urlsplit(url), urlsplit(redirect_uri)
    except ValueError:
        return False
    return (bool(expected.scheme)
            and seen.scheme.lower() == expected.scheme.lower()
            and seen.netloc.lower() == expected.netloc.lower()
            and seen.path == expected.path)


class Chrome:
    """A Chrome process driven over --remote-debugging-pipe (fd 3 in, fd 4 out)."""

    def __init__(self, chrome_path, headless=False, profile_dir=None):
        self._owns_profile = profile_dir is None
        self.profile = profile_dir or tempfile.mkdtemp(prefix="redirect-capture-")
        os.makedirs(self.profile, mode=0o700, exist_ok=True)

        to_chrome_r, to_chrome_w = os.pipe()
        from_chrome_r, from_chrome_w = os.pipe()
        # Park the child's ends on high numbers so dup2 onto 3 and 4 cannot clobber them.
        child_in = fcntl.fcntl(to_chrome_r, fcntl.F_DUPFD, 10)
        child_out = fcntl.fcntl(from_chrome_w, fcntl.F_DUPFD, 10)

        def wire_pipe():
            os.dup2(child_in, 3)
            os.dup2(child_out, 4)

        args = [chrome_path, "--remote-debugging-pipe", f"--user-data-dir={self.profile}",
                "--no-first-run", "--no-default-browser-check", "about:blank"]
        if headless:
            args.insert(1, "--headless=new")
        try:
            self.proc = subprocess.Popen(
                args, preexec_fn=wire_pipe, pass_fds=(3, 4), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            for fd in (to_chrome_r, from_chrome_w, child_in, child_out):
                os.close(fd)
        self._w, self._r = to_chrome_w, from_chrome_r
        self._buffer = b""
        self._next_id = 0
        self.exited = False

    def send(self, method, params=None, session=None):
        self._next_id += 1
        message = {"id": self._next_id, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        os.write(self._w, json.dumps(message).encode() + b"\0")
        return self._next_id

    def messages(self, deadline, stop=None):
        """Yield messages until the deadline, a stop request, or Chrome exiting."""
        while True:
            while b"\0" in self._buffer:
                raw, self._buffer = self._buffer.split(b"\0", 1)
                yield json.loads(raw)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or (stop is not None and stop.is_set()):
                return
            ready, _, _ = select.select([self._r], [], [], min(remaining, 0.25))
            if ready:
                chunk = os.read(self._r, 65536)
                if not chunk:
                    self.exited = True  # The user quit the browser.
                    return
                self._buffer += chunk

    def close(self):
        try:
            self.send("Browser.close")
            self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()
            self.proc.wait()
        for fd in (self._w, self._r):
            try:
                os.close(fd)
            except OSError:
                pass
        if self._owns_profile:
            shutil.rmtree(self.profile, ignore_errors=True)


def capture_redirect(authorize_url, redirect_uri, timeout=300, headless=False,
                     chrome_path=None, profile_dir=None, stop=None, trace=None):
    """Open `authorize_url` in Chrome and wait for the redirect to `redirect_uri`.

    `stop` is an optional threading.Event that abandons the capture. `profile_dir`
    keeps cookies between captures; without it every capture starts signed out
    and the profile is deleted afterwards.
    """
    check_authorize_url(authorize_url)
    if not urlsplit(redirect_uri).scheme:
        raise ValueError("redirect_uri must be absolute, for example myapp://callback")

    chrome = Chrome(find_chrome(chrome_path), headless, profile_dir)
    navigated = False
    try:
        chrome.send("Target.setAutoAttach",
                    {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True})
        for message in chrome.messages(time.monotonic() + timeout, stop):
            method = message.get("method")
            params = message.get("params", {})
            session = message.get("sessionId")
            if trace and method:
                trace(method, params)

            if method == "Target.attachedToTarget":
                tab = params["sessionId"]
                if params["targetInfo"]["type"] == "page":
                    # Pause every document response, in every tab and popup, before
                    # Chrome acts on it. That is the moment a redirect can be taken.
                    chrome.send("Fetch.enable", {"patterns": [
                        {"urlPattern": "*", "resourceType": "Document", "requestStage": "Response"}
                    ]}, tab)
                    chrome.send("Page.enable", {}, tab)
                    if not navigated:
                        navigated = True
                        chrome.send("Page.navigate", {"url": authorize_url}, tab)
                chrome.send("Runtime.runIfWaitingForDebugger", {}, tab)

            elif method == "Fetch.requestPaused":
                headers = {h["name"].lower(): h["value"] for h in params.get("responseHeaders", [])}
                location = headers.get("location", "")
                status = params.get("responseStatusCode", 0)
                if 300 <= status < 400 and is_redirect(location, redirect_uri):
                    # Swap the redirect for a plain page: Chrome never learns the
                    # custom-scheme URL, so it never asks the OS to open the app.
                    chrome.send("Fetch.fulfillRequest", {
                        "requestId": params["requestId"], "responseCode": 200,
                        "responseHeaders": [{"name": "Content-Type", "value": "text/html"}],
                        "body": base64.b64encode(DONE_PAGE.encode()).decode(),
                    }, session)
                    return CaptureResult(CAPTURED, location)
                chrome.send("Fetch.continueRequest", {"requestId": params["requestId"]}, session)

            elif method == "Page.frameRequestedNavigation":
                # The page navigated to the redirect itself (script, link or meta
                # refresh), so there was no response to pause. The URL is still
                # ours first; closing Chrome below abandons the navigation.
                if is_redirect(params.get("url", ""), redirect_uri):
                    return CaptureResult(CAPTURED, params["url"])

        if chrome.exited:
            return CaptureResult(CLOSED)
        if stop is not None and stop.is_set():
            return CaptureResult(CANCELLED)
        return CaptureResult(TIMED_OUT)
    finally:
        chrome.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("authorize_url")
    parser.add_argument("--redirect-uri", default="myapp://callback")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--chrome", help="path to the Chrome executable")
    parser.add_argument("--profile-dir", help="keep cookies in this directory between runs")
    options = parser.parse_args()

    result = capture_redirect(options.authorize_url, options.redirect_uri, options.timeout,
                              chrome_path=options.chrome, profile_dir=options.profile_dir)
    if result.status != CAPTURED:
        sys.exit(f"No redirect captured: {result.status}.")
    print(result.url)


if __name__ == "__main__":
    main()
