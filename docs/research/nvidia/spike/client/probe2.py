"""Spike probe v2. Runs inside the OpenShell sandbox. Stdlib only.

Subcommands (all print one JSON object per case):
  hdr <url> <token-file>                  header visibility case
  toksize <url> <token-file>...           one request per token file, reports status
  sweep <url> <proto> <token-file> <sizes-csv>   body size sweep, proto is rest or mcp
  bench <url> <n> <body-bytes> [token-file]      sequential keep-alive latency
  conc <url> <threads> <per-thread> [token-file] concurrent requests, status histogram
  loop <url> <seconds> <interval-ms> [token-file] timeline of statuses (fail-closed tests)
"""

from __future__ import annotations

import http.client
import json
import statistics
import sys
import threading
import time
from urllib.parse import urlparse


def read_token(path: str | None) -> str | None:
    if not path or path == "-":
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


def tools_call(size: int, path: str = "/workspace/a.txt") -> bytes:
    base = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "file_read", "arguments": {"path": path, "pad": ""}}}
    overhead = len(json.dumps(base).encode())
    base["params"]["arguments"]["pad"] = "x" * max(0, size - overhead)
    return json.dumps(base).encode()


def one(url: str, body: bytes, headers: dict, timeout: float = 30.0) -> tuple:
    parsed = urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    started = time.perf_counter()
    try:
        conn.request("POST", parsed.path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        status = resp.status
    except Exception as exc:  # noqa: BLE001
        data = repr(exc).encode()
        status = type(exc).__name__
    finally:
        conn.close()
    return status, data, round((time.perf_counter() - started) * 1000, 3)


def hdr(url: str, token: str) -> None:
    headers = {
        "content-type": "application/json",
        "x-chio-capability-token": token,
        "x-chio-session-id": "sess-spike-2",
        "authorization": "Bearer agent-bearer-abc",
        "proxy-authorization": "Basic cHJveHk6cHc=",
        "cookie": "session=abc",
        "x-amz-date": "20260929T000000Z",
        "x-openshell-credential-probe": "zzz",
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "x-request-id": "req-spike-2",
    }
    status, data, ms = one(url, tools_call(300), headers)
    try:
        seen = [h[0] for h in json.loads(data).get("received_headers", [])]
    except ValueError:
        seen = None
    print(json.dumps({"case": "hdr", "status": status, "upstream_header_names": seen, "ms": ms,
                      "body": None if seen is not None else data[:400].decode("utf-8", "replace")}))


def toksize(url: str, paths: list[str]) -> None:
    for path in paths:
        token = read_token(path)
        status, data, ms = one(url, tools_call(300), {"content-type": "application/json", "x-chio-capability-token": token})
        print(json.dumps({"case": "toksize", "token_file": path, "token_bytes": len(token), "status": status, "ms": ms,
                          "body": data[:300].decode("utf-8", "replace")}))


def sweep(url: str, proto: str, token: str | None, sizes: list[int]) -> None:
    for size in sizes:
        body = tools_call(size)
        headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
        if proto == "mcp":
            headers["mcp-protocol-version"] = "2025-11-25"
            headers["mcp-session-id"] = "sweep-session"
        if token:
            headers["x-chio-capability-token"] = token
        status, data, ms = one(url, body, headers, timeout=60)
        print(json.dumps({"case": "sweep", "proto": proto, "body_bytes": len(body), "status": status, "ms": ms,
                          "resp": data[:260].decode("utf-8", "replace")}))


def bench(url: str, n: int, size: int, token: str | None) -> None:
    parsed = urlparse(url)
    body = tools_call(size)
    headers = {"content-type": "application/json"}
    if token:
        headers["x-chio-capability-token"] = token
    latencies = []
    statuses: dict = {}
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=30)
    for index in range(n + 10):
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
        if index >= 10:
            latencies.append(elapsed)
            statuses[str(status)] = statuses.get(str(status), 0) + 1
    latencies.sort()

    def pct(p: float) -> float:
        return round(latencies[min(len(latencies) - 1, int(p * len(latencies)))], 3)

    print(json.dumps({"case": "bench", "url": url, "n": n, "body_bytes": len(body), "token": bool(token),
                      "statuses": statuses, "p50_ms": pct(0.50), "p90_ms": pct(0.90), "p99_ms": pct(0.99),
                      "max_ms": round(latencies[-1], 3), "mean_ms": round(statistics.mean(latencies), 3)}))


def conc(url: str, threads: int, per_thread: int, token: str | None) -> None:
    body = tools_call(1000)
    headers = {"content-type": "application/json"}
    if token:
        headers["x-chio-capability-token"] = token
    results: list = []
    lock = threading.Lock()
    barrier = threading.Barrier(threads)

    def worker() -> None:
        barrier.wait()
        for _ in range(per_thread):
            status, data, ms = one(url, body, headers, timeout=60)
            with lock:
                results.append((status, ms, data[:120].decode("utf-8", "replace")))

    started = time.perf_counter()
    pool = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()
    wall = round((time.perf_counter() - started) * 1000, 1)
    hist: dict = {}
    samples: dict = {}
    for status, ms, text in results:
        hist[str(status)] = hist.get(str(status), 0) + 1
        samples.setdefault(str(status), text)
    lat = sorted(ms for _, ms, _ in results)
    print(json.dumps({"case": "conc", "threads": threads, "per_thread": per_thread, "wall_ms": wall, "statuses": hist,
                      "p50_ms": lat[len(lat) // 2], "max_ms": lat[-1], "samples": samples}))


def loop(url: str, seconds: float, interval_ms: int, token: str | None) -> None:
    body = tools_call(500)
    headers = {"content-type": "application/json"}
    if token:
        headers["x-chio-capability-token"] = token
    end = time.time() + seconds
    while time.time() < end:
        wall = time.time()
        status, data, ms = one(url, body, headers, timeout=10)
        err = None
        if status != 200:
            try:
                parsed = json.loads(data)
                err = {k: parsed.get(k) for k in ("error", "reason_code", "detail") if k in parsed}
            except ValueError:
                err = data[:120].decode("utf-8", "replace")
        print(json.dumps({"case": "loop", "t": round(wall, 3), "status": status, "ms": ms, "err": err}), flush=True)
        time.sleep(interval_ms / 1000.0)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "hdr":
        hdr(sys.argv[2], read_token(sys.argv[3]) or "")
    elif cmd == "toksize":
        toksize(sys.argv[2], sys.argv[3:])
    elif cmd == "sweep":
        sweep(sys.argv[2], sys.argv[3], read_token(sys.argv[4]), [int(x) for x in sys.argv[5].split(",")])
    elif cmd == "bench":
        bench(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), read_token(sys.argv[5] if len(sys.argv) > 5 else None))
    elif cmd == "conc":
        conc(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), read_token(sys.argv[5] if len(sys.argv) > 5 else None))
    elif cmd == "loop":
        loop(sys.argv[2], float(sys.argv[3]), int(sys.argv[4]), read_token(sys.argv[5] if len(sys.argv) > 5 else None))
