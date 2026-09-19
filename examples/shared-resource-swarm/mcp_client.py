"""Baseline MCP transport with application-persisted operation identities."""

import json
import select
import subprocess
import threading
import time

from store import encoded


class McpClient:
    def __init__(self, command):
        self.lock = threading.Lock()
        self.sequence = 0
        # Keep our own buffer so select never waits for bytes already read.
        self.buffer = bytearray()
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        try:
            self.request(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "swarm-baseline", "version": "1"},
                },
            )
            self.write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except BaseException:
            self.close()
            raise

    def write(self, message):
        remaining = memoryview(encoded(message).encode() + b"\n")
        while remaining:
            count = self.process.stdin.write(remaining)
            if not count:
                raise RuntimeError("MCP request write failed")
            remaining = remaining[count:]

    def request(self, method, params):
        with self.lock:
            self.sequence += 1
            message = {
                "jsonrpc": "2.0",
                "id": self.sequence,
                "method": method,
                "params": params,
            }
            self.write(message)
            deadline = time.monotonic() + 30
            while b"\n" not in self.buffer:
                if len(self.buffer) > 1024 * 1024:
                    raise RuntimeError("MCP response exceeds 1 MiB")
                remaining = deadline - time.monotonic()
                if (
                    remaining <= 0
                    or not select.select([self.process.stdout], [], [], remaining)[0]
                ):
                    raise TimeoutError("MCP outcome is unknown; no automatic retry")
                chunk = self.process.stdout.read(4096)
                if not chunk:
                    raise RuntimeError("MCP server closed before a complete response")
                self.buffer.extend(chunk)
            body, _, rest = self.buffer.partition(b"\n")
            self.buffer = bytearray(rest)
            if len(body) > 1024 * 1024:
                raise RuntimeError("MCP response exceeds 1 MiB")
            response = json.loads(body)
            if response.get("id") != self.sequence or "error" in response:
                raise RuntimeError("MCP response identity or method error")
            return response["result"]

    def invoke(self, operation_id, name, arguments):
        result = self.request(
            "tools/call",
            {
                "name": name,
                "arguments": arguments,
                "_meta": {"chioRequestId": operation_id},
            },
        )
        if result.get("isError") is not False:
            raise RuntimeError("resource request refused")
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
