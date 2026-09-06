"""Scripted research-swarm planner served through the real OpenAI-compatible HTTP path.

The same deterministic decisions drive the native and the local-callback configuration,
so every difference in outcomes comes from execution, not from the model.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RESEARCHERS = 4
SOURCES_EACH = 4
FINAL = {"coordinator": "Published the checked report.", "researcher": "Findings sent."}


def checksum(text):
    """A letters-only digest: numeric runs in hex can look like identifiers to guards."""
    return "".join(
        "abcdefghijklmnop"[int(nibble, 16)] for nibble in hashlib.sha256(text.encode()).hexdigest()
    )


def calls(request):
    """Ordered (tool name, arguments, output) triples from the conversation so far."""
    pending, results = {}, []
    for message in request["messages"]:
        for call in message.get("tool_calls", []):
            pending[call["id"]] = (
                call["function"]["name"],
                json.loads(call["function"]["arguments"]),
            )
        if message["role"] == "tool":
            name, arguments = pending[message["tool_call_id"]]
            results.append((name, arguments, json.loads(message["content"])))
    return results


def offered(request):
    return {tool["function"]["name"]: tool["function"] for tool in request.get("tools", [])}


def text_of(output):
    return output["content"][0]["text"]


def coordinator(request):
    history = calls(request)
    spawned = [
        out["process"] for name, _, out in history if name == "chio-process__spawn_researcher"
    ]
    if not spawned:
        paths = offered(request)["sources__read"]["parameters"]["properties"]["path"]["enum"]
        assert len(paths) == RESEARCHERS * SOURCES_EACH
        return [
            (
                "chio-process__spawn_researcher",
                {
                    "input": {
                        "index": index,
                        "paths": paths[(index - 1) * SOURCES_EACH : index * SOURCES_EACH],
                    },
                    "budget_share_bps": 2000,
                },
            )
            for index in range(1, RESEARCHERS + 1)
        ]
    assert len(spawned) == RESEARCHERS
    waits = [out for name, _, out in history if name == "chio-process__wait_children"]
    if not waits or not waits[-1]["complete"]:
        return [("chio-process__wait_children", {"children": spawned})]
    received = [out for name, _, out in history if name == "chio-ipc__receive_findings"]
    if not received:
        return [("chio-ipc__receive_findings", {"after_sequence": "0", "limit": RESEARCHERS})]
    findings = sorted((m["payload"] for m in received[0]["messages"]), key=lambda f: f["index"])
    report = {"sources": [source for finding in findings for source in finding["sources"]]}
    if not any(name == "report__publish" for name, _, _ in history):
        return [("report__publish", {"report": json.dumps(report, separators=(",", ":"))})]
    if not any(name == "chio-ipc__ack_findings" for name, _, _ in history):
        return [("chio-ipc__ack_findings", {"through_sequence": received[0]["next_sequence"]})]
    return FINAL["coordinator"]


def researcher(request):
    history = calls(request)
    task = json.loads(request["messages"][0]["content"])["task"]
    reads = {args["path"]: out for name, args, out in history if name == "sources__read"}
    for path in task["paths"]:
        if path not in reads:
            index = task["paths"].index(path) + (task["index"] - 1) * SOURCES_EACH + 1
            return [("sources__read", {"index": index, "path": path})]
    eager = "report__publish" in offered(request)
    if eager and not any(name == "report__publish" for name, _, _ in history):
        return [("report__publish", {"report": "partial findings from one researcher"})]
    if not any(name == "chio-ipc__send_findings" for name, _, _ in history):
        sources = [
            {
                "index": (task["index"] - 1) * SOURCES_EACH + position,
                "path": path,
                "bytes": len(text_of(reads[path]).encode()),
                "checksum": checksum(text_of(reads[path])),
            }
            for position, path in enumerate(task["paths"], 1)
        ]
        return [
            (
                "chio-ipc__send_findings",
                {
                    "message_key": f"findings-{task['index']}",
                    "payload": {"index": task["index"], "sources": sources},
                },
            )
        ]
    assert history[-1][2]["status"] in ("sent", "acknowledged")
    return FINAL["researcher"]


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    with sqlite3.connect(args.database) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE requests(id INTEGER PRIMARY KEY, request TEXT, response TEXT)")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            length = int(self.headers["Content-Length"])
            assert self.path == "/v1/chat/completions" and 0 < length <= 4_194_304
            request = json.loads(self.rfile.read(length))
            assert not request.get("stream")
            plan = (
                coordinator(request) if request["model"] == "coordinator" else researcher(request)
            )
            tool_calls = (
                []
                if isinstance(plan, str)
                else [
                    {
                        "id": "call_" + uuid.uuid4().hex,
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(value)},
                    }
                    for name, value in plan
                ]
            )
            message = {"role": "assistant", "content": plan if isinstance(plan, str) else None}
            if tool_calls:
                message["tool_calls"] = tool_calls
            response = {
                "id": "response_" + uuid.uuid4().hex,
                "object": "chat.completion",
                "created": int(time.time()),
                "model": request["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls" if tool_calls else "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
            }
            with sqlite3.connect(args.database, timeout=30) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute(
                    "INSERT INTO requests(request,response) VALUES(?,?)",
                    (json.dumps(request), json.dumps(response)),
                )
            encoded = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    args.ready.write_text(json.dumps({"endpoint": f"http://127.0.0.1:{server.server_port}/v1"}))
    server.serve_forever()


if __name__ == "__main__":
    main()
