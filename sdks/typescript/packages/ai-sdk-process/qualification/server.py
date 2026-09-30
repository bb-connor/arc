"""The same non-idempotent SQLite publication effect for both qualification paths."""

import argparse
import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path


def connect(database):
    db = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=rw", uri=True)
    if db.execute("PRAGMA journal_mode=PERSIST").fetchone()[0] != "persist":
        db.close()
        raise ValueError("Publication store requires a persistent rollback journal")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA temp_store=MEMORY")
    return db


def prepare_store(database):
    database = Path(database)
    with database.open("xb"):
        pass
    with closing(connect(database)) as db, db:
        db.execute("CREATE TABLE reports(id INTEGER PRIMARY KEY, report TEXT NOT NULL)")
        db.execute("CREATE TABLE reads(id INTEGER PRIMARY KEY, file_index INTEGER)")
    fixture = database.parent / "fixtures"
    fixture.mkdir(mode=0o700)
    for index in range(1, 33):
        (fixture / f"file-{index:02}.txt").write_text("a" * 8192)


def publish(database, report):
    if not isinstance(report, str) or not 1 <= len(report.encode()) <= 1024:
        raise ValueError("report must contain 1-1024 UTF-8 bytes")
    with closing(connect(database)) as db, db:
        cursor = db.execute("INSERT INTO reports(report) VALUES(?)", (report,))
        return {"report_id": cursor.lastrowid}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--publish")
    parser.add_argument("--exit-after-publication", action="store_true")
    args = parser.parse_args()
    if args.publish is not None:
        print(json.dumps(publish(args.database, args.publish)))
        return
    fixture = Path(args.database).parent / "fixtures"
    files = [fixture / f"file-{index:02}.txt" for index in range(1, 33)]
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
    tools.append(
        {
            "name": "read",
            "description": "Read one 8 KiB fixture file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer", "minimum": 1, "maximum": 32},
                    "path": {"type": "string", "enum": list(map(str, files))},
                },
                "required": ["index", "path"],
                "additionalProperties": False,
            },
        }
    )
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
                elif params["name"] == "read":
                    index = params["arguments"]["index"]
                    if type(index) is not int or not 1 <= index <= 32:
                        raise ValueError("invalid fixture index")
                    if params["arguments"]["path"] != str(files[index - 1]):
                        raise ValueError("fixture path does not match index")
                    content = files[index - 1].read_text()
                    if len(content.encode()) != 8192:
                        raise ValueError("fixture content changed")
                    with closing(connect(args.database)) as db, db:
                        db.execute("INSERT INTO reads(file_index) VALUES(?)", (index,))
                    value = {"index": index}
                elif params["name"] == "count":
                    with closing(connect(args.database)) as db:
                        value = {"count": db.execute("SELECT count(*) FROM reports").fetchone()[0]}
                else:
                    raise ValueError("unknown tool")
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": content if params["name"] == "read" else json.dumps(value),
                        }
                    ],
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
