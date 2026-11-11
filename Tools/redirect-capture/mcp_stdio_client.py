"""A minimal MCP client over stdio, for driving servers in the tests.

It plays the part an MCP host plays: start the server, shake hands, call tools.
"""
import json
import queue
import subprocess
import threading


class StdioClient:
    def __init__(self, command, env=None, cwd=None):
        self.proc = subprocess.Popen(
            command, env=env, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL)
        self._replies = queue.Queue()
        self._next_id = 0
        threading.Thread(target=self._read, daemon=True).start()
        self.server = self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "handoff-test", "version": "0"}})
        self.notify("notifications/initialized")

    def _read(self):
        for line in self.proc.stdout:
            if line.strip():
                self._replies.put(json.loads(line))
        self._replies.put(None)

    def notify(self, method, params=None):
        self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, method, params=None, timeout=60):
        self._next_id += 1
        self._write({"jsonrpc": "2.0", "id": self._next_id, "method": method,
                     "params": params or {}})
        while True:
            reply = self._replies.get(timeout=timeout)
            if reply is None:
                raise RuntimeError(f"the server exited during {method}")
            if reply.get("id") == self._next_id:
                if "error" in reply:
                    raise RuntimeError(f"{method} failed: {reply['error']}")
                return reply["result"]

    def call(self, tool, arguments=None, timeout=60):
        """Calls a tool and returns its structured content."""
        result = self.request("tools/call", {"name": tool, "arguments": arguments or {}}, timeout)
        return result.get("structuredContent") or {}

    def _write(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode())
        self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
