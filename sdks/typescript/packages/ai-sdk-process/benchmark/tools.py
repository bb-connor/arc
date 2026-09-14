"""Source reads and one non-idempotent publication, with handler timings for both paths."""

import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

SOURCES = 16
SOURCE_BYTES = 8192
MAX_REPORT_BYTES = 16384


def connect(database):
    db = sqlite3.connect(database, timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript(
        "CREATE TABLE IF NOT EXISTS reads(id INTEGER PRIMARY KEY, file_index INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, report TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, channel TEXT NOT NULL,"
        " message_key TEXT NOT NULL, payload TEXT NOT NULL, acked INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS timings(id INTEGER PRIMARY KEY, path TEXT NOT NULL,"
        " tool TEXT NOT NULL, duration_ms REAL NOT NULL);"
    )
    return db


def corpus(directory):
    """Sixteen distinct 8 KiB sources of short lowercase words.

    Prose-like text passes the kernel's output guards unchanged, so the checksum a
    researcher reports can be checked against the file the coordinator never reads.
    """
    directory.mkdir(exist_ok=True)
    files = []
    for index in range(1, SOURCES + 1):
        path = directory / f"source-{index:02}.txt"
        if not path.exists():
            state = index * 2654435761 % 2**32
            words = []
            while sum(len(word) + 1 for word in words) < SOURCE_BYTES:
                state = (1103515245 * state + 12345) % 2**31
                length = 2 + state % 7
                letters = []
                for _ in range(length):
                    state = (1103515245 * state + 12345) % 2**31
                    letters.append("abcdefghijklmnopqrstuvwxyz"[state % 26])
                words.append("".join(letters))
            header = "source " + "abcdefghijklmnop"[index - 1] + "\n"
            path.write_text((header + " ".join(words))[:SOURCE_BYTES])
        files.append(path)
    return files


def publish(db, report):
    if not isinstance(report, str) or not 1 <= len(report.encode()) <= MAX_REPORT_BYTES:
        raise ValueError("report must contain 1-16384 UTF-8 bytes")
    return {"report_id": db.execute("INSERT INTO reports(report) VALUES(?)", (report,)).lastrowid}


def read(db, files, index, path):
    if type(index) is not int or not 1 <= index <= SOURCES:
        raise ValueError("invalid source index")
    if path != str(files[index - 1]):
        raise ValueError("source path does not match index")
    content = files[index - 1].read_text()
    if len(content.encode()) != SOURCE_BYTES:
        raise ValueError("source content changed")
    db.execute("INSERT INTO reads(file_index) VALUES(?)", (index,))
    return content


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", choices=("sources", "report"), required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    args = parser.parse_args()
    files = corpus(args.corpus)
    if args.server == "sources":
        tools = [
            {
                "name": "read",
                "description": "Read one 8 KiB source file",
                "annotations": {"readOnlyHint": True},
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "index": {"type": "integer", "minimum": 1, "maximum": SOURCES},
                        "path": {"type": "string", "enum": list(map(str, files))},
                    },
                    "required": ["index", "path"],
                    "additionalProperties": False,
                },
            }
        ]
    else:
        tools = [
            {
                "name": "publish",
                "description": "Append one checked report",
                "inputSchema": {
                    "type": "object",
                    "properties": {"report": {"type": "string"}},
                    "required": ["report"],
                    "additionalProperties": False,
                },
            }
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
                "serverInfo": {"name": f"benchmark-{args.server}", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": tools}
        elif method == "tools/call":
            params = request["params"]
            started = time.perf_counter()
            try:
                with connect(args.database) as db:
                    if params["name"] == "read" and args.server == "sources":
                        text = read(
                            db, files, params["arguments"]["index"], params["arguments"]["path"]
                        )
                        value = {"index": params["arguments"]["index"]}
                    elif params["name"] == "publish" and args.server == "report":
                        value = publish(db, params["arguments"]["report"])
                        text = json.dumps(value)
                    else:
                        raise ValueError("unknown tool")
                    db.execute(
                        "INSERT INTO timings(path,tool,duration_ms) VALUES('mediated',?,?)",
                        (params["name"], (time.perf_counter() - started) * 1000),
                    )
                result = {
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": value,
                    "isError": False,
                }
            except (ValueError, KeyError, TypeError, sqlite3.Error):
                result = {
                    "content": [{"type": "text", "text": "benchmark tool failed"}],
                    "isError": True,
                }
        else:
            result = {}
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


if __name__ == "__main__":
    main()
