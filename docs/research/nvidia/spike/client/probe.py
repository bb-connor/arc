"""Run inside the OpenShell sandbox. Stdlib only.

Subcommands:
  mcp <host> <port> <token-file>     MCP 2025-11-25 flow plus version and argument probes.
  bench <url> <n> <body-bytes> [token-file]   Sequential POST latency, prints JSON stats.
  big <url> <body-bytes> [token-file]          One POST with a large body, prints status.
"""

from __future__ import annotations

import http.client
import json
import statistics
import sys
import time


def post(host: str, port: int, path: str, body: bytes, headers: dict) -> tuple[int, dict, bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=30)
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, hdrs, data


def rpc(method: str, params: dict | None = None, msg_id: int | None = 1, meta: dict | None = None) -> bytes:
    message: dict = {"jsonrpc": "2.0", "method": method}
    if msg_id is not None:
        message["id"] = msg_id
    if params is not None or meta is not None:
        params = dict(params or {})
        if meta is not None:
            params["_meta"] = meta
        message["params"] = params
    return json.dumps(message).encode("utf-8")


def show(label: str, status: int, data: bytes) -> None:
    print(json.dumps({"case": label, "status": status, "body": data[:400].decode("utf-8", "replace")}))


def mcp(host: str, port: int, token: str) -> None:
    base = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    auth = {"x-chio-capability-token": token}
    status, hdrs, data = post(
        host, port, "/mcp",
        rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}}),
        {**base, **auth},
    )
    show("initialize_2025_11_25", status, data)
    session = hdrs.get("mcp-session-id", "")
    v = {"mcp-protocol-version": "2025-11-25", "mcp-session-id": session}
    status, _, data = post(host, port, "/mcp", rpc("notifications/initialized", msg_id=None), {**base, **auth, **v})
    show("initialized", status, data)
    status, _, data = post(host, port, "/mcp", rpc("tools/list", {}), {**base, **auth, **v})
    show("tools_list", status, data)
    status, _, data = post(host, port, "/mcp", rpc("tools/call", {"name": "file_read", "arguments": {"path": "/workspace/a.txt"}}), {**base, **auth, **v})
    show("call_file_read_allowed_path", status, data)
    status, _, data = post(host, port, "/mcp", rpc("tools/call", {"name": "file_read", "arguments": {"path": "/etc/shadow"}}), {**base, **auth, **v})
    show("call_file_read_disallowed_path", status, data)
    status, _, data = post(host, port, "/mcp", rpc("tools/call", {"name": "file_read", "arguments": {"path": "/workspace/a.txt"}}), {**base, **v})
    show("call_without_token", status, data)
    status, _, data = post(host, port, "/mcp", rpc("tools/call", {"name": "delete_resource", "arguments": {}}), {**base, **auth, **v})
    show("call_delete_resource_policy_denied", status, data)
    # Version probes.
    status, _, data = post(host, port, "/mcp", rpc("tools/list", {}), {**base, **auth, "mcp-session-id": session})
    show("tools_list_no_version_header", status, data)
    status, _, data = post(host, port, "/mcp", rpc("tools/list", {}), {**base, **auth, "mcp-session-id": session, "mcp-protocol-version": "2025-06-18"})
    show("tools_list_2025_06_18_header", status, data)
    status, _, data = post(host, port, "/mcp", rpc("initialize", {"protocolVersion": "2026-07-28", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}}), {**base, **auth})
    show("initialize_body_2026_07_28", status, data)
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    july = {"mcp-protocol-version": "2026-07-28", "mcp-method": "server/discover"}
    status, _, data = post(host, port, "/mcp", rpc("server/discover", {}, meta=meta), {**base, **auth, **july})
    show("server_discover_2026_07_28", status, data)
    july_call = {"mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "file_read"}
    status, _, data = post(host, port, "/mcp", rpc("tools/call", {"name": "file_read", "arguments": {"path": "/workspace/a.txt"}}, meta=meta), {**base, **auth, **july_call})
    show("tools_call_2026_07_28_sessionless", status, data)


def bench(url: str, n: int, size: int, token: str | None) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    filler = "x" * max(0, size - 120)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "file_read", "arguments": {"path": "/workspace/a.txt", "pad": filler}}}).encode()
    headers = {"content-type": "application/json"}
    if token:
        headers["x-chio-capability-token"] = token
    latencies = []
    statuses: dict = {}
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=30)
    for index in range(n + 5):
        started = time.perf_counter()
        try:
            conn.request("POST", parsed.path, body=body, headers=headers)
            resp = conn.getresponse()
            resp.read()
            status = resp.status
            if resp.getheader("connection", "").lower() == "close":
                conn.close()
                conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=30)
        except Exception as exc:  # noqa: BLE001
            status = type(exc).__name__
            conn.close()
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=30)
        elapsed = (time.perf_counter() - started) * 1000
        if index >= 5:
            latencies.append(elapsed)
            statuses[str(status)] = statuses.get(str(status), 0) + 1
    latencies.sort()

    def pct(p: float) -> float:
        return round(latencies[min(len(latencies) - 1, int(p * len(latencies)))], 3)

    print(json.dumps({"url": url, "n": n, "body_bytes": len(body), "token": bool(token), "statuses": statuses,
                      "p50_ms": pct(0.50), "p90_ms": pct(0.90), "p99_ms": pct(0.99), "max_ms": round(latencies[-1], 3),
                      "mean_ms": round(statistics.mean(latencies), 3)}))


def big(url: str, size: int, token: str | None) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "file_read", "arguments": {"path": "/workspace/a.txt", "pad": "y" * size}}}).encode()
    headers = {"content-type": "application/json"}
    if token:
        headers["x-chio-capability-token"] = token
    try:
        status, _, data = post(parsed.hostname, parsed.port, parsed.path, body, headers)
        print(json.dumps({"body_bytes": len(body), "status": status, "resp": data[:300].decode("utf-8", "replace")}))
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"body_bytes": len(body), "error": repr(exc)}))


def read_token(path: str | None) -> str | None:
    if not path or path == "-":
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "mcp":
        mcp(sys.argv[2], int(sys.argv[3]), read_token(sys.argv[4]) or "")
    elif cmd == "bench":
        bench(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), read_token(sys.argv[5] if len(sys.argv) > 5 else None))
    elif cmd == "big":
        big(sys.argv[2], int(sys.argv[3]), read_token(sys.argv[4] if len(sys.argv) > 4 else None))
