"""Application-owned conditional updates and durable operation outcomes.

This resource has no mailbox authority. A successful compare-and-swap says
that the document version matched, not that the caller still owns a job.
"""

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

SCHEMA = 2
MAX_BYTES = 65536


def encoded(value):
    # Internal request equality, not a canonical signed-payload format.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def identifier(value):
    if not isinstance(value, str) or not value or len(value.encode()) > 512:
        raise ValueError("identifier must contain 1 through 512 UTF-8 bytes")
    return value


def connect(path):
    # Serving must never silently initialize missing state.
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=rw", uri=True)
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA busy_timeout=5000")
    return db


def initialize(path, seed):
    if not isinstance(seed, dict) or set(seed) != {"task", "documents"}:
        raise ValueError("seed requires task and documents")
    documents = seed["documents"]
    if not isinstance(documents, dict) or not documents:
        raise ValueError("seed needs at least one document")
    body = encoded(seed)
    if len(body.encode()) > MAX_BYTES:
        raise ValueError("seed exceeds size limit")
    for name, value in documents.items():
        identifier(name)
        if not isinstance(value, dict):
            raise ValueError("each document must be an object")
    # Never overwrite a completed or interrupted initialization.
    with Path(path).open("xb"):
        pass
    with closing(connect(path)) as db, db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
            CREATE TABLE seed (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                               body TEXT NOT NULL, digest TEXT NOT NULL);
            CREATE TABLE task_revisions (revision INTEGER PRIMARY KEY,
                                         body TEXT NOT NULL, digest TEXT NOT NULL);
            CREATE TABLE documents (id TEXT PRIMARY KEY, version INTEGER NOT NULL,
                                    body TEXT NOT NULL);
            CREATE TABLE operations (id TEXT PRIMARY KEY, request TEXT NOT NULL,
                                     result TEXT NOT NULL, deliveries INTEGER NOT NULL);
            CREATE TABLE mutations (version INTEGER NOT NULL, document TEXT NOT NULL,
                                    operation TEXT NOT NULL UNIQUE,
                                    PRIMARY KEY(document, version));
        """)
        db.execute(
            "INSERT INTO seed VALUES(1, ?, ?)",
            (body, hashlib.sha256(body.encode()).hexdigest()),
        )
        task = encoded(seed["task"])
        db.execute(
            "INSERT INTO task_revisions VALUES(0, ?, ?)",
            (task, hashlib.sha256(task.encode()).hexdigest()),
        )
        db.executemany(
            "INSERT INTO documents VALUES(?, 0, ?)",
            [(name, encoded(value)) for name, value in documents.items()],
        )
        db.execute(f"PRAGMA user_version={SCHEMA}")


def revise_task(path, expected_revision, task):
    """Operator-only input publication; unavailable through the worker MCP tools.

    Keep the original seed and every prior revision. This does not revoke any
    worker capability or atomically fence writes derived from old task inputs.
    """
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("task revision must be a nonnegative integer")
    if not isinstance(task, dict):
        raise ValueError("task must be an object")
    body = encoded(task)
    if len(body.encode()) > MAX_BYTES:
        raise ValueError("task exceeds size limit")
    with closing(connect(path)) as db, db:
        if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA:
            raise ValueError("unsupported or incomplete resource state")
        db.execute("BEGIN IMMEDIATE")
        revision = db.execute("SELECT MAX(revision) FROM task_revisions").fetchone()[0]
        if revision != expected_revision:
            raise ValueError("task revision conflict")
        db.execute(
            "INSERT INTO task_revisions VALUES(?, ?, ?)",
            (revision + 1, body, hashlib.sha256(body.encode()).hexdigest()),
        )
        return revision + 1


def validate(name, args):
    fields = {
        "task": set(),
        "snapshot": {"document"},
        "replace": {"document", "expected_version", "value"},
        "outcome": {"operation_id"},
    }
    if name not in fields or not isinstance(args, dict) or set(args) != fields[name]:
        raise ValueError("unknown tool or incorrect argument fields")
    if "document" in args:
        identifier(args["document"])
    if name == "outcome":
        identifier(args["operation_id"])
    if name == "replace":
        version = args["expected_version"]
        if type(version) is not int or not 0 <= version < 2**63 - 1:
            raise ValueError("expected_version must be a nonnegative integer")
        if not isinstance(args["value"], dict):
            raise ValueError("value must be an object")
    if len(encoded(args).encode()) > MAX_BYTES:
        raise ValueError("arguments exceed size limit")


def execute(path, operation_id, name, args):
    identifier(operation_id)
    validate(name, args)
    request = encoded({"name": name, "arguments": args})
    with closing(connect(path)) as db, db:
        if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA:
            raise ValueError("unsupported or incomplete resource state")
        db.execute("BEGIN IMMEDIATE")
        previous = db.execute(
            "SELECT request, result FROM operations WHERE id=?", (operation_id,)
        ).fetchone()
        if previous:
            if previous[0] != request:
                raise ValueError("operation identity conflict")
            db.execute(
                "UPDATE operations SET deliveries=deliveries+1 WHERE id=?",
                (operation_id,),
            )
            return json.loads(previous[1])
        result = transition(db, operation_id, name, args)
        db.execute(
            "INSERT INTO operations VALUES(?, ?, ?, 1)",
            (operation_id, request, encoded(result)),
        )
        return result


def transition(db, operation_id, name, args):
    if name == "task":
        revision, body, digest = db.execute(
            "SELECT revision, body, digest FROM task_revisions ORDER BY revision DESC LIMIT 1"
        ).fetchone()
        return {
            "task": json.loads(body),
            "task_revision": revision,
            "task_sha256": digest,
            "seed_sha256": db.execute("SELECT digest FROM seed").fetchone()[0],
        }
    if name == "outcome":
        row = db.execute(
            "SELECT request, result FROM operations WHERE id=?", (args["operation_id"],)
        ).fetchone()
        return (
            {
                "status": "known",
                "request": json.loads(row[0]),
                "result": json.loads(row[1]),
            }
            if row
            else {"status": "unknown"}
        )
    row = db.execute(
        "SELECT version, body FROM documents WHERE id=?", (args["document"],)
    ).fetchone()
    if row is None:
        return {"status": "not_found"}
    version, body = row
    if name == "snapshot":
        return {"status": "snapshot", "version": version, "value": json.loads(body)}
    if args["expected_version"] != version:
        return {"status": "version_conflict", "version": version}
    db.execute(
        "UPDATE documents SET version=version+1, body=? WHERE id=?",
        (encoded(args["value"]), args["document"]),
    )
    db.execute(
        "INSERT INTO mutations VALUES(?, ?, ?)",
        (version + 1, args["document"], operation_id),
    )
    return {"status": "committed", "version": version + 1}


def inspect(path):
    """Operator evidence only; workers access the MCP tools instead."""
    with closing(connect(path)) as db:
        db.execute("BEGIN")
        if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA:
            raise ValueError("unsupported or incomplete resource state")
        return {
            "seed_sha256": db.execute("SELECT digest FROM seed").fetchone()[0],
            "task_revisions": [
                {"revision": revision, "task": json.loads(body), "sha256": digest}
                for revision, body, digest in db.execute(
                    "SELECT revision, body, digest FROM task_revisions ORDER BY revision"
                )
            ],
            "documents": {
                name: {"version": version, "value": json.loads(body)}
                for name, version, body in db.execute(
                    "SELECT id, version, body FROM documents ORDER BY id"
                )
            },
            "operations": [
                {
                    "id": key,
                    "request": json.loads(request),
                    "result": json.loads(result),
                    "deliveries": deliveries,
                }
                for key, request, result, deliveries in db.execute(
                    "SELECT id, request, result, deliveries FROM operations ORDER BY id"
                )
            ],
            "mutations": [
                {"document": document, "version": version, "operation_id": key}
                for document, version, key in db.execute(
                    "SELECT document, version, operation FROM mutations ORDER BY document, version"
                )
            ],
        }
