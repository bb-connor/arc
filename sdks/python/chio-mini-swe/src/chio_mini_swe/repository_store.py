"""Private serialized repository state with durable container intents."""

import fcntl
import json
import os
import re
import sqlite3
import stat
import uuid

from chio_mini_swe.operator import private_directory, write
from chio_mini_swe.provider_config import read_json
from chio_mini_swe.repository_archive import (
    MAX_ARCHIVE,
    canonical,
    contents,
    digest,
    import_revision,
    with_git,
)
from chio_mini_swe.repository_container import Containers, engine, qualify_image
from chio_mini_swe.repository_snapshots import (
    MAX_COMMANDS,
    MAX_RESERVATION,
    MAX_STORAGE,
    STORAGE_SCHEMA,
    SnapshotStore,
)
from chio_mini_swe.repository_transport import check_deadline, operation_budget
from chio_mini_swe.repository_wire import validate_result

SCHEMA = "chio.repository.workspace.v1"


def configuration_digest(config):
    return digest(json.dumps(config, sort_keys=True, separators=(",", ":")).encode())


def atomic_bytes(path, data):
    temporary = path.with_name("." + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def initialize(repository, revision, image, helper_image, state, timeout_seconds):
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise ValueError("Command timeout must be between 1 and 300 seconds")
    engine_id = engine()
    for identifier in {image, helper_image}:
        qualify_image(identifier)
    commit, data = import_revision(repository, revision)
    data = with_git(data)
    state = private_directory(state, create=True)
    snapshots = SnapshotStore.create(state / "snapshots", atomic_bytes)
    baseline = snapshots.put(data, MAX_STORAGE)
    atomic_bytes(state / "journal.db", b"")
    with sqlite3.connect(state / "journal.db") as db:
        db.executescript("""
            PRAGMA synchronous=FULL;
            PRAGMA user_version=1;
            CREATE TABLE workspace (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                revision INTEGER NOT NULL, snapshot TEXT NOT NULL);
            CREATE TABLE commands (sequence INTEGER PRIMARY KEY, lease TEXT UNIQUE NOT NULL,
                command TEXT NOT NULL, status TEXT NOT NULL, holder TEXT, worker TEXT,
                before_sha256 TEXT NOT NULL, after_sha256 TEXT, result TEXT);
        """)
        db.execute("INSERT INTO workspace VALUES (1,0,?)", [baseline])
    config = {
        "schema": STORAGE_SCHEMA,
        "id": uuid.uuid4().hex,
        "engine": engine_id,
        "image": image,
        "helper_image": helper_image,
        "source_commit": commit,
        "baseline": baseline,
        "timeout_seconds": timeout_seconds,
    }
    write(state / "workspace.json", config)
    return {"state": str(state), **config}


class Workspace:
    def __init__(self, state):
        self.state = private_directory(state)
        private_directory(self.state / "snapshots")
        self.config = read_json(self.state / "workspace.json")
        if (
            not isinstance(self.config, dict)
            or set(self.config)
            != {
                "schema",
                "id",
                "engine",
                "image",
                "helper_image",
                "source_commit",
                "baseline",
                "timeout_seconds",
            }
            or self.config["schema"] not in (SCHEMA, STORAGE_SCHEMA)
        ):
            raise ValueError("Unsupported repository workspace")
        for key, pattern in [
            ("id", r"[0-9a-f]{32}"),
            ("baseline", r"[0-9a-f]{64}"),
            ("source_commit", r"[0-9a-f]{40}|[0-9a-f]{64}"),
        ]:
            if (
                not isinstance(self.config[key], str)
                or re.fullmatch(pattern, self.config[key]) is None
            ):
                raise ValueError("Invalid repository workspace identity")
        if (
            type(self.config["timeout_seconds"]) is not int
            or not 1 <= self.config["timeout_seconds"] <= 300
        ):
            raise ValueError("Invalid repository command deadline")
        self.lock = os.open(
            self.state / "workspace.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        self.db = None
        try:
            for metadata in [os.fstat(self.lock), (self.state / "journal.db").lstat()]:
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                    or metadata.st_mode & 0o077
                ):
                    raise ValueError("Repository journal and lock must be private regular files")
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect((self.state / "journal.db").as_uri() + "?mode=rw", uri=True)
            self.db.row_factory = sqlite3.Row
            if self.db.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise ValueError("Unsupported repository journal version")
            self.db.execute("PRAGMA synchronous=FULL")
            self.snapshot_store = (
                SnapshotStore(self.state / "snapshots", atomic_bytes)
                if self.config["schema"] == STORAGE_SCHEMA
                else None
            )
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.db is not None:
            self.db.close()
        os.close(self.lock)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def snapshot(self, sha256):
        if self.snapshot_store is not None:
            return self.snapshot_store.load(sha256)
        if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            raise ValueError("Invalid repository snapshot digest")
        path = self.state / "snapshots" / sha256
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o077
                or metadata.st_size > MAX_ARCHIVE
            ):
                raise ValueError("Repository snapshot must be a bounded private regular file")
            data = stream.read(MAX_ARCHIVE + 1)
        if len(data) > MAX_ARCHIVE or digest(data) != sha256:
            raise ValueError("Repository snapshot is missing or corrupt")
        return data

    def containers(self, row):
        def remember(role, identifier):
            if role not in {"holder", "worker"}:
                raise ValueError("Invalid repository container role")
            with self.db:
                self.db.execute(
                    f"UPDATE commands SET {role}=? WHERE sequence=?", [identifier, row["sequence"]]
                )

        return Containers(
            self.config, row["lease"], {role: row[role] for role in ("holder", "worker")}, remember
        )

    def recover(self):
        rows = self.db.execute("SELECT * FROM commands WHERE status!='completed'").fetchall()
        for row in rows:
            self.containers(row).cleanup()
            if row["status"] == "pending":
                with self.db:
                    self.db.execute(
                        "UPDATE commands SET status='interrupted' WHERE sequence=?",
                        [row["sequence"]],
                    )

    def status(self):
        current = self.db.execute(
            "SELECT revision,snapshot FROM workspace WHERE singleton=1"
        ).fetchone()
        commands = [
            dict(row)
            for row in self.db.execute(
                "SELECT sequence,status,before_sha256,after_sha256 FROM commands ORDER BY sequence"
            )
        ]
        return {
            "schema": SCHEMA,
            "id": self.config["id"],
            "source_commit": self.config["source_commit"],
            **dict(current),
            "commands": commands,
            "interrupted": any(row["status"] != "completed" for row in commands),
        }

    def execute(self, command):
        if (
            not isinstance(command, str)
            or not command
            or len(command.encode()) > 65536
            or "\0" in command
        ):
            raise ValueError("Invalid repository command")
        status = self.status()
        if status["interrupted"] or len(status["commands"]) >= MAX_COMMANDS:
            raise ValueError("Repository execution stopped; inspect its retained state")
        if self.snapshot_store is None:
            storage = sum(path.stat().st_size for path in (self.state / "snapshots").iterdir())
            reservation = MAX_ARCHIVE
        else:
            storage = self.snapshot_store.usage()
            reservation = MAX_RESERVATION
        if storage + reservation > MAX_STORAGE:
            raise ValueError("Repository snapshot storage budget is exhausted")
        snapshot = self.snapshot(status["snapshot"])
        with self.db:
            cursor = self.db.execute(
                "INSERT INTO commands(lease,command,status,before_sha256) VALUES (?,?,'pending',?)",
                [uuid.uuid4().hex, command, status["snapshot"]],
            )
        sequence = cursor.lastrowid
        row = self.db.execute("SELECT * FROM commands WHERE sequence=?", [sequence]).fetchone()
        containers = self.containers(row)
        try:
            with operation_budget(self.config["timeout_seconds"] + 90):
                return self.complete(containers, snapshot, command, status, sequence)
        except BaseException:
            # Cleanup has its own bounded Docker calls after the operation
            # budget expires. Preserve pending intent if ownership or cleanup
            # cannot be established. Never rewrite an already committed result.
            containers.cleanup()
            with self.db:
                self.db.execute(
                    "UPDATE commands SET status='interrupted' "
                    "WHERE sequence=? AND status='pending'",
                    [sequence],
                )
            raise

    def complete(self, containers, snapshot, command, status, sequence):
        raw, result = containers.execute(snapshot, command)
        data = canonical(raw, allow_git=True)
        sha256 = digest(data)
        result["workspace"] = {
            "id": self.config["id"],
            "source_commit": self.config["source_commit"],
            "before_sha256": status["snapshot"],
            "after_sha256": sha256,
            "revision": status["revision"] + 1,
            "contents_sha256": digest(contents(data)),
            "configuration_sha256": configuration_digest(self.config),
        }
        validate_result(result)
        check_deadline()
        if self.snapshot_store is None:
            atomic_bytes(self.state / "snapshots" / sha256, data)
        else:
            self.snapshot_store.put(data, MAX_STORAGE)
        containers.cleanup()
        check_deadline()
        with self.db:
            self.db.execute(
                "UPDATE commands SET status='completed',after_sha256=?,result=? WHERE sequence=?",
                [sha256, json.dumps(result), sequence],
            )
            self.db.execute(
                "UPDATE workspace SET revision=revision+1,snapshot=? WHERE singleton=1",
                [sha256],
            )
        return result
