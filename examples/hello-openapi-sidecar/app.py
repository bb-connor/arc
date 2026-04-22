from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class Handler(BaseHTTPRequestHandler):
    server_version = "hello-openapi-sidecar/0.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/hello":
            self._json(
                HTTPStatus.OK,
                {
                    "message": "hello from openapi-sidecar upstream",
                    "runtime": "python-http-server",
                    "chio_sdk": False,
                },
            )
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/echo":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_json", "message": "request body must be valid JSON"},
            )
            return

        message = payload.get("message")
        if not isinstance(message, str) or not message:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_request", "message": "message is required"},
            )
            return

        count = payload.get("count", 1)
        if not isinstance(count, int):
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_request", "message": "count must be an integer"},
            )
            return

        self._json(
            HTTPStatus.OK,
            {
                "message": message,
                "count": count,
                "handled_by": "plain-upstream-app",
                "chio_sdk": False,
            },
        )


def main() -> None:
    port = int(os.environ.get("HELLO_OPENAPI_SIDECAR_PORT", "8041"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
