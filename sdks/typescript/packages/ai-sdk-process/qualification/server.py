"""The same non-idempotent SQLite publication effect for both qualification paths."""

import argparse
import json
import os
import sqlite3
import sys


def publish(database, report):
    if not isinstance(report, str) or not 1 <= len(report.encode()) <= 1024:
        raise ValueError("report must contain 1-1024 UTF-8 bytes")
    with sqlite3.connect(database) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute(
            "CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, report TEXT NOT NULL)"
        )
        cursor = db.execute("INSERT INTO reports(report) VALUES(?)", (report,))
        return {"report_id": cursor.lastrowid}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--publish")
    parser.add_argument("--exit-after-publication", action="store_true")
    args = parser.parse_args()
    if args.publish is not None:
        print(json.dumps(publish(args.database, args.publish)))
        return
    tools = [
        {
            "name": "publish",
            "description": "Append one report",
            "inputSchema": {
                "type": "object",
                "properties": {"report": {"type": "string"}},
                "required": ["report"],
                "additionalProperties": False,
            },
        },
        {
            "name": "count",
            "description": "Read publication count",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    ]
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "publication-fixture", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": tools}
        elif method == "tools/call":
            params = request["params"]
            try:
                if params["name"] == "publish":
                    value = publish(args.database, params["arguments"]["report"])
                    if args.exit_after_publication:
                        os._exit(72)
                elif params["name"] == "count":
                    with sqlite3.connect(args.database) as db:
                        value = {"count": db.execute("SELECT count(*) FROM reports").fetchone()[0]}
                else:
                    raise ValueError("unknown tool")
                result = {
                    "content": [{"type": "text", "text": json.dumps(value)}],
                    "structuredContent": value,
                    "isError": False,
                }
            except (ValueError, KeyError, sqlite3.Error):
                result = {
                    "content": [{"type": "text", "text": "publication fixture failed"}],
                    "isError": True,
                }
        else:
            result = {}
        print(
            json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}),
            flush=True,
        )


if __name__ == "__main__":
    main()
