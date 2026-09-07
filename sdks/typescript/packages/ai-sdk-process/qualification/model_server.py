"""Scripted HTTP planning service with fresh tool IDs, used by the real SDK provider."""

import argparse
import json
import os
import socket
import sqlite3
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


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
            assert 0 < length <= 1_048_576 and self.path == "/v1/chat/completions"
            request = json.loads(self.rfile.read(length))
            complete = any(message["role"] == "tool" for message in request["messages"])
            call = {
                "id": "call_" + uuid.uuid4().hex,
                "type": "function",
                "function": {
                    "name": "reports__publish",
                    "arguments": '{"report":"Report planned by HTTP model."}',
                },
            }
            message = (
                {"role": "assistant", "content": "Published."}
                if complete
                else {"role": "assistant", "content": None, "tool_calls": [call]}
            )
            response = {
                "id": "response_" + uuid.uuid4().hex,
                "object": "chat.completion",
                "created": int(time.time()),
                "model": "fixture",
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "stop" if complete else "tool_calls",
                    }
                ],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
            }
            with sqlite3.connect(args.database) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute(
                    "INSERT INTO requests(request,response) VALUES(?,?)",
                    (json.dumps(request), json.dumps(response)),
                )
            if args.mode == "provider-death":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if not request.get("stream"):
                encoded = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()

            def send(delta, finish=None):
                data = {
                    "id": response["id"],
                    "object": "chat.completion.chunk",
                    "created": response["created"],
                    "model": "fixture",
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
                }
                self.wfile.write(("data: " + json.dumps(data) + "\n\n").encode())
                self.wfile.flush()

            try:
                send({"role": "assistant", "content": "Published." if complete else "Planning. "})
                if not complete:
                    send(
                        {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": call["id"],
                                    "type": "function",
                                    "function": {
                                        "name": call["function"]["name"],
                                        "arguments": call["function"]["arguments"][:15],
                                    },
                                }
                            ]
                        }
                    )
                    time.sleep(0.02)
                    send(
                        {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {"arguments": call["function"]["arguments"][15:]},
                                }
                            ]
                        }
                    )
                if args.mode == "truncated-stream":
                    self.close_connection = True
                    return
                send({}, "stop" if complete else "tool_calls")
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    args.ready.write_text(json.dumps({"endpoint": f"http://127.0.0.1:{server.server_port}/v1"}))
    server.serve_forever()


if __name__ == "__main__":
    main()
