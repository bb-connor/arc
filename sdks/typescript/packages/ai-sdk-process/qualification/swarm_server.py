"""Scripted planner for real SDK/native fork, join, mailbox and publication calls."""

import argparse
import hashlib
import json
import os
import sqlite3
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def outputs(request):
    names, results = {}, []
    for message in request["messages"]:
        for call in message.get("tool_calls", []):
            names[call["id"]] = call["function"]["name"]
        if message["role"] == "tool":
            results.append((names[message["tool_call_id"]], json.loads(message["content"])))
    return results


def planned(request):
    results = outputs(request)
    model = request["model"]
    if model == "root":
        spawned = [
            value["process"] for name, value in results if name.startswith("chio-process__spawn_")
        ]
        waits = [value for name, value in results if name == "chio-process__wait_children"]
        if not spawned:
            read = next(
                tool["function"]
                for tool in request["tools"]
                if tool["function"]["name"] == "reports__read"
            )
            paths = read["parameters"]["properties"]["path"]["enum"][:2]
            return [
                (
                    "chio-process__spawn_reader",
                    {"input": {"index": index, "path": path}, "budget_share_bps": 3000},
                )
                for index, path in enumerate(paths, 1)
            ]
        assert len(spawned) == 2
        if not waits or not waits[-1]["complete"]:
            return [("chio-process__wait_children", {"children": spawned})]
        received = [value for name, value in results if name == "chio-ipc__receive_results"]
        if not received:
            return [("chio-ipc__receive_results", {"after_sequence": "0", "limit": 2})]
        messages = received[0]["messages"]
        reviews = sorted((m["payload"] for m in messages), key=lambda value: value["index"])
        assert [value["index"] for value in reviews] == [1, 2]
        assert all(
            value["bytes"] == 8192 and value["sha256"] == hashlib.sha256(b"a" * 8192).hexdigest()
            for value in reviews
        )
        if not any(name == "reports__publish" for name, _ in results):
            return [
                (
                    "reports__publish",
                    {"report": json.dumps({"reviews": reviews}, separators=(",", ":"))},
                )
            ]
        if not any(name == "chio-ipc__ack_results" for name, _ in results):
            return [
                (
                    "chio-ipc__ack_results",
                    {"through_sequence": received[0]["next_sequence"]},
                )
            ]
        return "Published both reviews."
    assert model in ("reader-1", "reader-2")
    index = int(model[-1])
    if not results:
        read = next(
            tool["function"]
            for tool in request["tools"]
            if tool["function"]["name"] == "reports__read"
        )
        path = read["parameters"]["properties"]["path"]["enum"][index - 1]
        return [("reports__read", {"index": index, "path": path})]
    if len(results) == 1:
        assert results[0][0] == "reports__read"
        content = results[0][1]["content"][0]["text"]
        return [
            (
                "chio-ipc__send_results",
                {
                    "message_key": f"review-{index}",
                    "payload": {
                        "index": index,
                        "bytes": len(content.encode()),
                        "sha256": hashlib.sha256(content.encode()).hexdigest(),
                    },
                },
            )
        ]
    assert results[-1][1]["status"] in ("sent", "acknowledged")
    return "Review sent."


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
        db.execute("CREATE TABLE arrivals(model TEXT PRIMARY KEY, arrived REAL, released REAL)")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            length = int(self.headers["Content-Length"])
            assert self.path == "/v1/chat/completions" and 0 < length <= 1_048_576
            request = json.loads(self.rfile.read(length))
            assert not request.get("stream")
            if (
                args.mode == "swarm-parallel"
                and request["model"] != "root"
                and not outputs(request)
            ):
                with sqlite3.connect(args.database) as db:
                    db.execute(
                        "INSERT INTO arrivals VALUES(?,?,NULL)",
                        (request["model"], time.monotonic()),
                    )
                deadline = time.monotonic() + 30
                while True:
                    with sqlite3.connect(args.database) as db:
                        arrived = db.execute("SELECT count(*) FROM arrivals").fetchone()[0]
                    if arrived == 2:
                        break
                    assert time.monotonic() < deadline, "both child model calls must overlap"
                    time.sleep(0.02)
                with sqlite3.connect(args.database) as db:
                    db.execute(
                        "UPDATE arrivals SET released=? WHERE model=?",
                        (time.monotonic(), request["model"]),
                    )
            plan = planned(request)
            calls = (
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
            message = {
                "role": "assistant",
                "content": plan if isinstance(plan, str) else None,
            }
            if calls:
                message["tool_calls"] = calls
            response = {
                "id": "response_" + uuid.uuid4().hex,
                "object": "chat.completion",
                "created": int(time.time()),
                "model": request["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls" if calls else "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 10,
                    "total_tokens": 20,
                },
            }
            with sqlite3.connect(args.database) as db:
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
