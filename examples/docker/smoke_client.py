#!/usr/bin/env python3

import json
import os
import urllib.error
import urllib.parse
import urllib.request


BASE_URL = os.environ.get("CHIO_BASE_URL", "http://127.0.0.1:8931")
CONTROL_URL = os.environ.get("CHIO_CONTROL_URL", "http://127.0.0.1:8940")
TOKEN = os.environ.get("CHIO_AUTH_TOKEN", "demo-token")
PROTOCOL_VERSION = "2025-11-25"


def request_json(url, *, method="GET", payload=None, headers=None):
    request = urllib.request.Request(
        url,
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        method=method,
        headers=headers or {},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"request failed: {exc.code} {body}") from exc


def post_mcp(payload, session_id=None):
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
    }
    if session_id:
        headers["MCP-Session-Id"] = session_id
    request = urllib.request.Request(
        f"{BASE_URL}/mcp",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    try:
        return urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"request failed: {exc.code} {body}") from exc


def read_sse_json(response):
    data_lines = []
    for raw_line in response:
        line = raw_line.decode("utf-8").strip()
        if not line:
            if data_lines:
                return json.loads("\n".join(data_lines))
            continue
        if line.startswith("data:"):
            data_lines.append(line.split(":", 1)[1].lstrip())
    raise SystemExit("no JSON-RPC payload received from SSE response")


def session_capability_id(session_id):
    trust = request_json(
        f"{BASE_URL}/admin/sessions/{session_id}/trust",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    capability_id = trust.get("capabilities", [{}])[0].get("capabilityId")
    if not capability_id:
        raise SystemExit("session trust endpoint did not return a capability id")
    return capability_id


def query_receipts(capability_id):
    query = urllib.parse.urlencode({"capabilityId": capability_id, "limit": 10})
    payload = request_json(
        f"{CONTROL_URL}/v1/receipts/query?{query}",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    receipts = payload.get("receipts", [])
    if not receipts:
        raise SystemExit("receipt query returned no receipts")
    return receipts[-1]


def main():
    with post_mcp(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "docker-smoke-client",
                    "version": "1.0.0",
                },
            },
        },
    ) as response:
        session_id = response.headers["MCP-Session-Id"]
        initialize = read_sse_json(response)

    with post_mcp(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        session_id=session_id,
    ):
        pass

    with post_mcp(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        session_id=session_id,
    ) as response:
        tools = read_sse_json(response)

    with post_mcp(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "echo_text",
                "arguments": {"message": "hello from docker"},
            },
        },
        session_id=session_id,
    ) as response:
        tool_call = read_sse_json(response)

    capability_id = session_capability_id(session_id)
    receipt = query_receipts(capability_id)

    print(
        json.dumps(
            {
                "sessionId": session_id,
                "capabilityId": capability_id,
                "tools": tools["result"]["tools"],
                "toolResult": tool_call["result"],
                "receiptId": receipt["id"],
                "viewerUrl": f"{CONTROL_URL}/?token={TOKEN}",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
