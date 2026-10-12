"""Logging reverse proxy in front of the Chio edge. Streams responses (SSE-safe)."""
import http.client
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN = int(sys.argv[1])
UPSTREAM = ("127.0.0.1", int(sys.argv[2]))
LOG = sys.argv[3]
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-connection"}


def log(rec):
    rec["ts"] = time.time()
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        return

    def _proxy(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in HOP and k.lower() != "host"}
        rec = {"dir": "req", "method": self.command, "path": self.path,
               "headers": {k.lower(): (v if k.lower() != "authorization" else v[:12] + "...") for k, v in self.headers.items()},
               "body": body[:1500].decode("utf-8", "replace")}
        conn = http.client.HTTPConnection(*UPSTREAM, timeout=60)
        try:
            conn.request(self.command, self.path, body=body or None, headers=hdrs)
            resp = conn.getresponse()
        except Exception as exc:  # noqa: BLE001
            rec["error"] = repr(exc)
            log(rec)
            self.send_error(502)
            return
        rec["status"] = resp.status
        rec["resp_headers"] = {k.lower(): v for k, v in resp.getheaders()}
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in HOP and k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        captured = b""
        while True:
            chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)
            if not chunk:
                break
            if len(captured) < 3000:
                captured += chunk
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        rec["resp_body"] = captured[:3000].decode("utf-8", "replace")
        log(rec)

    do_POST = _proxy
    do_GET = _proxy
    do_DELETE = _proxy


ThreadingHTTPServer(("0.0.0.0", LISTEN), H).serve_forever()
