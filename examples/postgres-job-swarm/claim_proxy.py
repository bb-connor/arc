"""Test-only stdio proxy that withholds one real, committed claim response.

The resource is the unmodified Rust gateway and PostgreSQL store. The proxy
records each assignment delivery, then forwards all bytes except the first
successful assignment response. It waits for host pipe closure at that point.
It adds no deduplication, assignment logic or replacement resource response.
"""

import argparse
import json
import os
import select
import subprocess
import sys
import uuid
from pathlib import Path

MAX_FRAME = 1024 * 1024


def write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def frame(stream):
    value = stream.readline(MAX_FRAME + 1)
    if not value:
        return None
    if len(value) > MAX_FRAME or not value.endswith(b"\n"):
        raise ValueError("incomplete or oversized test proxy frame")
    return value


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("gateway", type=Path)
    parser.add_argument("tenant")
    args = parser.parse_args()
    directory = args.evidence.resolve(strict=True)
    child = subprocess.Popen(
        [str(args.gateway.resolve(strict=True)), "operator", args.tenant],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    held, closed = False, False
    try:
        while (raw := frame(sys.stdin.buffer)) is not None:
            request = json.loads(raw)
            params = request.get("params", {})
            assignment = (
                request.get("method") == "tools/call" and params.get("name") == "assign"
            )
            if assignment:
                write(
                    directory / f"delivery-{uuid.uuid4().hex}.json",
                    {
                        "arguments": params["arguments"],
                        "caller": params.get("_meta", {}).get(
                            "chioCallerCapabilitySha256"
                        ),
                    },
                )
            child.stdin.write(raw)
            child.stdin.flush()
            if "id" not in request:
                continue
            raw_response = frame(child.stdout)
            if raw_response is None:
                raise RuntimeError("gateway closed before responding")
            response = json.loads(raw_response)
            if response.get("id") != request["id"]:
                raise AssertionError("gateway response identity changed")
            result = response.get("result", {})
            committed = (
                result.get("isError") is False
                and result.get("structuredContent", {}).get("status") == "assigned"
                and len(result["structuredContent"].get("jobs", [])) == 1
            )
            marker = directory / "committed.json"
            if assignment and committed and not marker.exists():
                held = True
                write(marker, {"response": response, "response_forwarded": False})
                # A real SIGKILL of the host closes this pipe. Never forward the
                # withheld response, even if the driver times out or misbehaves.
                if not select.select([sys.stdin.buffer], [], [], 90)[0]:
                    raise TimeoutError("host did not close the faulted pipe")
                closed = frame(sys.stdin.buffer) is None
                if not closed:
                    raise AssertionError("unexpected request while response withheld")
                return
            sys.stdout.buffer.write(raw_response)
            sys.stdout.buffer.flush()
    finally:
        child.stdin.close()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)
        child.stdout.close()
        if held:
            write(
                directory / "stopped.json",
                {"host_pipe_closed": closed, "gateway_exit_code": child.returncode},
            )


if __name__ == "__main__":
    main()
