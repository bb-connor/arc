"""Local MCP tools over a pinned snapshot and an append-only report database."""

import argparse
import hashlib
import json
import sqlite3
import sys

from snapshot import inventory, load


def schema(properties=None, required=None):
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


TOOLS = [
    {
        "name": "changes",
        "description": "List changed paths and immutable Git object identities.",
        "inputSchema": schema(),
    },
    {
        "name": "test_inventory",
        "description": "List changed test paths. Does not run tests.",
        "inputSchema": schema(),
    },
    {
        "name": "read_file",
        "description": "Read a changed file at base or head with line numbers.",
        "inputSchema": schema(
            {
                "path": {"type": "string"},
                "revision": {"type": "string", "enum": ["base", "head"]},
            },
            ["path", "revision"],
        ),
    },
    {
        "name": "publish_report",
        "description": "Append a completed review to local report history.",
        "inputSchema": schema(
            {
                "report": {"type": "string", "maxLength": 65536},
                "snapshot_hash": {"type": "string"},
            },
            ["report", "snapshot_hash"],
        ),
    },
]


def call(snapshot, snapshot_hash, database, name, args):
    if not isinstance(args, dict):
        raise ValueError("arguments must be an object")
    if name in ("changes", "test_inventory") and not args:
        return inventory(snapshot, name == "test_inventory")
    if name == "read_file" and set(args) == {"path", "revision"}:
        if args["revision"] not in ("base", "head"):
            raise ValueError("unknown revision")
        item = next((f for f in snapshot["files"] if f["path"] == args["path"]), None)
        if item is None:
            raise ValueError("path is outside the captured change set")
        source = item[args["revision"]]
        content = source.get("content")
        return {
            "path": item["path"],
            "revision": args["revision"],
            "oid": source.get("oid"),
            "omitted": source.get("reason"),
            "content": None
            if content is None
            else "\n".join(
                f"{n}: {line}" for n, line in enumerate(content.splitlines(), 1)
            ),
        }
    if name == "publish_report" and set(args) == {"report", "snapshot_hash"}:
        report = args["report"]
        if args["snapshot_hash"] != snapshot_hash:
            raise ValueError("publication belongs to another snapshot")
        if (
            not isinstance(report, str)
            or not report.strip()
            or len(report.encode()) > 65536
        ):
            raise ValueError("report must contain between 1 and 65536 UTF-8 bytes")
        report_hash = hashlib.sha256(report.encode()).hexdigest()
        with sqlite3.connect(database) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, "
                "snapshot_hash TEXT NOT NULL, report_hash TEXT NOT NULL, report TEXT NOT NULL)"
            )
            row = db.execute(
                "INSERT INTO reports(snapshot_hash, report_hash, report) VALUES(?, ?, ?)",
                (snapshot_hash, report_hash, report),
            )
            report_id = row.lastrowid
        # Tool output can be sanitized. The coordinator binds this locator to
        # the stored report and the original signed invocation parameters.
        return {"report_id": report_id}
    raise ValueError("unknown tool or invalid arguments")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--snapshot-hash", required=True)
    parser.add_argument("--database", required=True)
    args = parser.parse_args()
    snapshot = load(args.snapshot, args.snapshot_hash)
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "repository-review", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            try:
                value = call(
                    snapshot,
                    args.snapshot_hash,
                    args.database,
                    request["params"]["name"],
                    request["params"].get("arguments", {}),
                )
                result = {
                    "content": [{"type": "text", "text": json.dumps(value)}],
                    "structuredContent": value,
                    "isError": False,
                }
            except (ValueError, sqlite3.Error):
                result = {
                    "content": [{"type": "text", "text": "Repository tool failed"}],
                    "isError": True,
                }
        else:
            print(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "error": {"code": -32601, "message": "Unknown method"},
                    }
                ),
                flush=True,
            )
            continue
        print(
            json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}),
            flush=True,
        )


if __name__ == "__main__":
    main()
