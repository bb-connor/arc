#!/usr/bin/env python3
"""Fail-closed, content-retaining RUSTC_WRAPPER for independent offline audit.

Version/sysroot discovery are separate probe records. No caller-supplied gate is
accepted. Native GNU linking requires the explicit finite Linux launch contract.
Response files and undeclared execution inputs remain unsupported.
"""
import contextlib
import base64
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import struct
import stat
import subprocess
import sys
import time
import tomllib
import unicodedata
import uuid

SCHEMA = "chio.rust-compilation.v4"
COMPLETION_SCHEMA = "chio.rust-compilation-completion.v3"
MAX_INPUT = 512 * 1024 * 1024
MAX_CONTENT = 16 * 1024 * 1024 * 1024
MAX_JSON = 16 * 1024 * 1024
MAX_RECORDS = 100000
MAX_ARTIFACTS = 100000
MAX_RETENTION_BATCHES = 100000
MAX_NATIVE_COMPILER_OUTPUT = 16 * 1024 * 1024
NATIVE_COMPILER_DISPATCH_SECONDS = 180
NATIVE_COMPILER_CLEANUP_RESERVE_SECONDS = 1
SECRET_NAMES = frozenset({"credentials", "credentials.json", "credentials.toml", ".git-credentials", ".netrc",
    ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".aws", ".ssh",
    ".gnupg", ".secrets", ".auth", ".password-store"})
SECRET_SUFFIXES = frozenset({".key", ".pem", ".p12", ".pfx", ".keystore"})
SECRET_WORD = re.compile(r"(?i)(?:api[_-]?(?:key|token)|(?:access|auth)[_-]?token|(?:^|[_-])token(?:$|[= _-])|password|credential|secret|bearer)")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
PUBLIC = re.compile(r"[A-Za-z0-9_.+-]+\Z")
NOFOLLOW = os.O_NOFOLLOW | os.O_NONBLOCK
PARENT_OPEN = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | NOFOLLOW


class Refusal(Exception):
    """Stable refusal codes carry no caller-supplied text."""


class UnitPublicationDurabilityUnconfirmed(Refusal):
    """Physical publication persists; its required final sync is unconfirmed."""
    def __init__(self, outcome):
        super().__init__("unit_publication_durability_unconfirmed")
        self.outcome = outcome


class CompilerOutputRefusal(Refusal):
    """A bounded output observation preserves its actual child exit."""
    def __init__(self, reason, compiler_exit):
        super().__init__(reason)
        self.compiler_exit = compiler_exit


def require(condition, code):
    if not condition:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def secret_path(path):
    for part in Path(path).parts:
        part = unicodedata.normalize("NFKC", part).casefold()
        if (part in SECRET_NAMES or part == ".env" or part.startswith(".env.")
                or part == "secrets" or part.startswith("secrets.") or part.startswith("private-key")
                or Path(part).suffix in SECRET_SUFFIXES):
            return True
    return False


def absolute(path, cwd=None):
    text = os.fspath(path)
    require("\x00" not in text and "\n" not in text and "\r" not in text, "unsafe_path")
    require(".." not in Path(text).parts, "parent_traversal")
    require(not text.startswith("//"), "ambiguous_path_anchor")
    require(not secret_path(text), "secret_path")
    base = os.fspath(cwd) if cwd is not None else os.getcwd()
    require(os.path.isabs(base) and ".." not in Path(base).parts and not base.startswith("//"), "unsafe_cwd")
    require(not secret_path(base), "secret_path")
    result = Path(os.path.abspath(os.path.join(base, text)))
    require(not secret_path(result), "secret_path")
    return result


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)


class HeldPath:
    """Hold every parent descriptor and refuse alias components before opening."""
    def __init__(self, path, directory=False, create=False, publication_link=False, metadata_only=False):
        self.path = absolute(path)
        self.fds = []
        self.links = []
        try:
            parent = os.open("/", PARENT_OPEN)
            self.fds.append(parent)
            for name in self.path.parts[1:-1]:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(before.st_mode), "unsafe_parent")
                child = os.open(name, PARENT_OPEN, dir_fd=parent)
                require((before.st_dev, before.st_ino) == (os.fstat(child).st_dev, os.fstat(child).st_ino), "parent_race")
                self.links.append((parent, name, child))
                self.fds.append(child)
                parent = child
            name = self.path.name
            if create:
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | NOFOLLOW
                self.fd = os.open(name, flags, 0o600, dir_fd=parent)
            else:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode), "not_regular")
                self.fd = os.open(name, (PARENT_OPEN if metadata_only and directory else
                                        os.O_RDONLY | NOFOLLOW | (os.O_DIRECTORY if directory else 0)), dir_fd=parent)
                opened = os.fstat(self.fd)
                # Cooperating writers may change directory membership before
                # flock acquisition. Bind the directory inode/type/mode here;
                # regular-file bytes still require the complete stable identity.
                opened_identity = lambda value: (value.st_dev, value.st_ino, value.st_mode)
                require(opened_identity(before) == opened_identity(opened) if directory
                        else identity(before) == identity(opened), "file_race")
            self.fds.append(self.fd)
            self.parent = parent
            self.name = name
            self.initial = identity(os.fstat(self.fd))
            self.parents = tuple(identity(os.fstat(fd)) for fd in self.fds[:-1])
            require(stat.S_ISDIR(self.initial[2]) if directory else stat.S_ISREG(self.initial[2]), "not_regular")
            require(directory or self.initial[-1] == 1 or (publication_link and self.initial[-1] == 2), "hardlink_alias")
        except Exception:
            self.close()
            raise

    def verify(self, content=True):
        for parent, name, child in self.links:
            observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(child)
            require(stat.S_ISDIR(observed.st_mode) and (observed.st_dev, observed.st_ino) == (held.st_dev, held.st_ino), "parent_race")
        observed = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
        held = os.fstat(self.fd)
        if stat.S_ISDIR(held.st_mode) and not content:
            require((observed.st_dev, observed.st_ino, observed.st_mode)
                    == (held.st_dev, held.st_ino, held.st_mode), "file_race")
        else:
            require(identity(observed) == identity(held), "file_race")
        if content:
            require(identity(held) == self.initial, "file_changed")

    def read(self, limit=MAX_INPUT):
        self.verify()
        size = os.fstat(self.fd).st_size
        require(size <= limit, "input_limit")
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks = []
        total = 0
        while True:
            part = os.read(self.fd, min(1024 * 1024, limit + 1 - total))
            if not part:
                break
            total += len(part)
            require(total <= limit, "input_limit")
            chunks.append(part)
        self.verify()
        require(total == size, "file_changed")
        return b"".join(chunks)

    def binding(self):
        return (self.initial, self.parents)

    def close(self):
        for descriptor in reversed(self.fds):
            os.close(descriptor)
        self.fds = []

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


def mkdir(parent, name):
    parent.verify(content=False)
    try:
        os.mkdir(name, 0o700, dir_fd=parent.fd)
    except FileExistsError:
        pass
    child = HeldPath(parent.path / name, directory=True)
    parent.verify(content=False)
    return child


def write_all(fd, payload):
    remaining = memoryview(payload)
    while remaining:
        amount = os.write(fd, remaining)
        require(amount > 0, "write_failed")
        remaining = remaining[amount:]
    os.fsync(fd)


def verify_publication(staged, directory, name, payload, publication_link=False):
    """Bind final bytes/inode to the still-held staging descriptor, not its name."""
    with HeldPath(directory.path / name, publication_link=publication_link) as final:
        source_info = os.fstat(staged.fd)
        final_info = os.fstat(final.fd)
        require((source_info.st_dev, source_info.st_ino) == (final_info.st_dev, final_info.st_ino), "publication_inode")
        require(final.read() == payload, "publication_bytes")
        final.verify()
        directory.verify(content=False)


def descriptor_identity(handle):
    value = os.fstat(handle.fd)
    require(stat.S_ISREG(value.st_mode), "publication_not_regular")
    return {"device": value.st_dev, "inode": value.st_ino}


def publish_held(directory, name, payload, staged, synchronize=True, quarantine_on_failure=False):
    """Publish a reserved inode whose identity can be bound before encoding."""
    require(staged.path.parent == directory.path, "publication_parent")
    created = False
    try:
        write_all(staged.fd, payload)
        staged.verify(content=False)
        os.link(staged.name, name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd, follow_symlinks=False)
        created = True
        verify_publication(staged, directory, name, payload, publication_link=True)
        staged.verify(content=False)
        os.unlink(staged.name, dir_fd=directory.fd)
        verify_publication(staged, directory, name, payload)
        if synchronize:
            os.fsync(directory.fd)
    except (Refusal, OSError):
        if created and quarantine_on_failure:
            # Quarantine preserves evidence, but it grants no completion
            # authority. Readers independently check cross-bound inode identity.
            quarantine = ".incomplete-" + name + "-" + uuid.uuid4().hex
            os.rename(name, quarantine, src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
            os.fsync(directory.fd)
        raise


def publish_file(directory, name, payload, synchronize=True, quarantine_on_failure=False):
    temporary = ".pending-" + uuid.uuid4().hex
    with HeldPath(directory.path / temporary, create=True) as staged:
        publish_held(directory, name, payload, staged, synchronize, quarantine_on_failure)


class Campaign:
    """Serialize bounded publication, retain regular descriptors, never overwrite evidence."""
    def __init__(self, root, binding):
        self.directory = HeldPath(root, directory=True)
        self.binding = binding
        self.lock = None
        self._batch = None
        self._batch_failed = False
        self._durability_unconfirmed = False
        self.retention_outcomes = []
        self.unit_publication_outcomes = []
        self._unit_durability_unconfirmed = False
        self.publication_recovery = "fresh"
        self.retention_recovery = "fresh"
        try:
            # Refuse old writer formats before the first mutation, including
            # creating a missing lock in a historical namespace. The actual
            # current state is read and checked again under flock below.
            preflight = set(os.listdir(self.directory.fd))
            if ".state.json" in preflight and ".lock" not in preflight:
                with HeldPath(root / ".state.json") as state_handle:
                    state = json.loads(state_handle.read(MAX_JSON))
                require(type(state) is dict and state.get("schema") == SCHEMA
                        and state.get("source_binding") == binding, "campaign_binding")
            else:
                require(not preflight or ".lock" in preflight, "namespace_not_fresh")
            try:
                self.lock = HeldPath(root / ".lock", create=True)
            except FileExistsError:
                self.lock = HeldPath(root / ".lock")
            fcntl.flock(self.lock.fd, fcntl.LOCK_EX)
            self.directory.verify(content=False)
            entries = set(os.listdir(self.directory.fd))
            require(entries <= {".lock", ".state.json", "records", "artifacts", "completions", "batches"}, "namespace_not_fresh")
            if ".state.json" not in entries:
                require(entries == {".lock"}, "namespace_not_fresh")
                self.state = {"schema": SCHEMA, "source_binding": binding,
                              "content_bytes": 0, "record_count": 0}
                self.artifacts = mkdir(self.directory, "artifacts")
                self.records = mkdir(self.directory, "records")
                self.completions = mkdir(self.directory, "completions")
                self.batches = mkdir(self.directory, "batches")
                self.save_state()
            else:
                with HeldPath(root / ".state.json") as handle:
                    self.state = json.loads(handle.read(MAX_JSON))
                require(set(self.state) == {"schema", "source_binding", "content_bytes", "record_count"}, "campaign_state")
                require(self.state["schema"] == SCHEMA and self.state["source_binding"] == binding, "campaign_binding")
                for key in ["content_bytes", "record_count"]:
                    require(type(self.state[key]) is int and self.state[key] >= 0, "campaign_state")
                self.artifacts = HeldPath(root / "artifacts", directory=True)
                self.records = HeldPath(root / "records", directory=True)
                self.completions = HeldPath(root / "completions", directory=True)
                self.batches = HeldPath(root / "batches", directory=True)
                self.reconcile(verify_artifacts=True)
                if os.listdir(self.batches.fd):
                    self.retention_recovery = "physical-only-durability-unknown"
                if os.listdir(self.completions.fd):
                    self.publication_recovery = "physical-only-durability-unknown"
            fcntl.flock(self.lock.fd, fcntl.LOCK_UN)
        except Exception:
            self.close()
            raise

    def reconcile(self, verify_artifacts=False):
        # State is advisory, never trusted for quotas after interrupted writes.
        contents = os.listdir(self.artifacts.fd)
        require(len(contents) <= MAX_ARTIFACTS, "artifact_limit")
        require(all(DIGEST.fullmatch(name) for name in contents), "artifact_namespace")
        total = 0
        for name in contents:
            info = os.stat(name, dir_fd=self.artifacts.fd, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_INPUT, "artifact_namespace")
            total += info.st_size
        records = os.listdir(self.records.fd)
        require(all(re.fullmatch(r"[0-9a-f]{32}\.json", name) for name in records), "record_namespace")
        for name in records:
            info = os.stat(name, dir_fd=self.records.fd, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_JSON, "record_namespace")
        completions = os.listdir(self.completions.fd)
        require(set(completions) <= set(records), "completion_namespace")
        for name in completions:
            info = os.stat(name, dir_fd=self.completions.fd, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_JSON and info.st_nlink == 1, "completion_namespace")
        self.state["content_bytes"] = total
        self.state["record_count"] = len(records)
        require(total <= MAX_CONTENT and len(records) <= MAX_RECORDS, "campaign_limit")
        self._retention_pairs = self.validate_retention_batches(verify_artifacts)

    @contextlib.contextmanager
    def locked(self):
        fcntl.flock(self.lock.fd, fcntl.LOCK_EX)
        try:
            self.lock.verify()
            self.directory.verify(content=False)
            self.artifacts.verify(content=False)
            self.records.verify(content=False)
            self.completions.verify(content=False)
            self.batches.verify(content=False)
            self.reconcile()
            yield
            self.directory.verify(content=False)
            self.artifacts.verify(content=False)
            self.records.verify(content=False)
            self.completions.verify(content=False)
            self.batches.verify(content=False)
        except BaseException:
            if self._batch is not None and self._batch.get("physical"):
                self._durability_unconfirmed = True
            raise
        finally:
            self._batch = None
            fcntl.flock(self.lock.fd, fcntl.LOCK_UN)

    def save_state(self):
        name = ".state-" + uuid.uuid4().hex
        payload = canonical(self.state) + b"\n"
        with HeldPath(self.directory.path / name, create=True) as handle:
            write_all(handle.fd, payload)
            handle.verify(content=False)
            os.replace(name, ".state.json", src_dir_fd=self.directory.fd, dst_dir_fd=self.directory.fd)
            verify_publication(handle, self.directory, ".state.json", payload)
        os.fsync(self.directory.fd)

    def require_retention_writable(self):
        require(not self._unit_durability_unconfirmed, "unit_publication_durability_unconfirmed")
        require(not self._batch_failed, "retention_batch_incomplete")
        require(not self._durability_unconfirmed, "retention_batch_durability_unconfirmed")

    def publication_inventory(self):
        observed = {}
        for name in ["records", "completions"]:
            directory = getattr(self, name)
            names = sorted(os.listdir(directory.fd))
            require(len(names) <= MAX_RECORDS and all(re.fullmatch(r"[0-9a-f]{32}\.json", item) for item in names),
                    "retention_batch_inventory_changed")
            observed[name] = [(item, identity(os.stat(item, dir_fd=directory.fd, follow_symlinks=False))) for item in names]
        return observed

    def artifact_inventory(self):
        names = sorted(os.listdir(self.artifacts.fd))
        require(len(names) <= MAX_ARTIFACTS and all(DIGEST.fullmatch(name) for name in names), "artifact_namespace")
        members = []
        for name in names:
            with HeldPath(self.artifacts.path / name) as handle:
                payload = handle.read()
                require(hashlib.sha256(payload).hexdigest() == name, "artifact_changed")
                members.append({"artifact": "artifacts/" + name, "sha256": name,
                                "size": len(payload), "identity": list(handle.initial)})
        require(sum(item["size"] for item in members) <= MAX_CONTENT, "content_limit")
        return members

    def validate_retention_batches(self, verify_artifacts=False):
        """Reopening proves persisted physical authority, never a past sync result."""
        names = set(os.listdir(self.batches.fd))
        require(len(names) <= 2 * MAX_RETENTION_BATCHES and all(
            re.fullmatch(r"[0-9a-f]{32}\.(?:start|complete)\.json", name) for name in names),
            "retention_batch_incomplete")
        ids = sorted({name.split(".")[0] for name in names})
        references = []
        for batch_id in ids:
            start_name, complete_name = batch_id + ".start.json", batch_id + ".complete.json"
            require(start_name in names and complete_name in names, "retention_batch_incomplete")
            try:
                with HeldPath(self.batches.path / start_name) as start_handle, HeldPath(self.batches.path / complete_name) as complete_handle:
                    start_bytes, complete_bytes = start_handle.read(MAX_JSON), complete_handle.read(MAX_JSON)
                    start, complete = json.loads(start_bytes), json.loads(complete_bytes)
                    start_reference = self.batch_file_reference(start_name, start_bytes, start_handle)
                    complete_reference = self.batch_file_reference(complete_name, complete_bytes, complete_handle)
                    require(set(start) == {"schema", "batch_id", "source_binding", "before", "completion_identity"}
                            and start["schema"] == "chio.compiler-retention-batch-start.v1"
                            and set(complete) == {"schema", "batch_id", "source_binding", "start", "before_sha256", "after", "retained"}
                            and complete["schema"] == "chio.compiler-retention-batch-complete.v1"
                            and start["batch_id"] == complete["batch_id"] == batch_id
                            and start["source_binding"] == complete["source_binding"] == self.binding
                            and start["completion_identity"] == complete_reference["identity"]
                            and complete["start"] == start_reference
                            and complete["before_sha256"] == digest(start["before"]), "retention_batch_incomplete")
                    before, after = start["before"], complete["after"]
                    for snapshot in [before, after]:
                        require(set(snapshot) == {"artifacts", "content_bytes", "record_count"}
                                and type(snapshot["content_bytes"]) is int and 0 <= snapshot["content_bytes"] <= MAX_CONTENT
                                and type(snapshot["record_count"]) is int and 0 <= snapshot["record_count"] <= MAX_RECORDS
                                and type(snapshot["artifacts"]) is list and len(snapshot["artifacts"]) <= MAX_ARTIFACTS,
                                "retention_batch_incomplete")
                        vector = snapshot["artifacts"]
                        require([item["sha256"] for item in vector] == sorted({item["sha256"] for item in vector})
                                and sum(item["size"] for item in vector) == snapshot["content_bytes"], "retention_batch_incomplete")
                        for item in vector:
                            require(set(item) == {"artifact", "sha256", "size", "identity"}
                                    and DIGEST.fullmatch(item["sha256"]) and item["artifact"] == "artifacts/" + item["sha256"]
                                    and type(item["size"]) is int and 0 <= item["size"] <= MAX_INPUT
                                    and type(item["identity"]) is list and len(item["identity"]) == 7
                                    and all(type(value) is int for value in item["identity"]), "retention_batch_incomplete")
                    before_members = {item["sha256"]: item for item in before["artifacts"]}
                    after_members = {item["sha256"]: item for item in after["artifacts"]}
                    require(before["record_count"] == after["record_count"]
                            and all(after_members.get(sha) == member for sha, member in before_members.items())
                            and complete["retained"] == [after_members[sha] for sha in sorted(set(after_members) - set(before_members))],
                            "retention_batch_incomplete")
                    for member in after["artifacts"]:
                        with HeldPath(self.directory.path / member["artifact"]) as handle:
                            require(list(handle.initial) == member["identity"] and handle.initial[3] == member["size"], "retention_batch_incomplete")
                            if verify_artifacts:
                                require(hashlib.sha256(handle.read()).hexdigest() == member["sha256"], "retention_batch_incomplete")
                    references.append({"batch_id": batch_id, "source_binding": self.binding,
                                       "start": start_reference, "complete": complete_reference})
            except (KeyError, TypeError, ValueError, OSError, Refusal) as error:
                raise Refusal("retention_batch_incomplete") from error
        return references

    def batch_file_reference(self, name, payload, handle):
        return {"path": "batches/" + name, "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload), "identity": descriptor_identity(handle)}

    def observe_retention_outcome(self, batch_id, start, complete, physical, durability, error=None):
        outcome = {"schema": "chio.compiler-retention-batch-outcome.v1", "source_binding": self.binding,
                   "batch_id": batch_id, "start": start, "complete": complete, "physical_status": physical,
                   "durability": {"status": durability, "phase": "completion-directory-fsync",
                                  "errno": getattr(error, "errno", None)}, "declaration_emitted": False}
        self.retention_outcomes.append(outcome)
        # This is an actual trusted-writer observation. Qualification still
        # requires the independently captured original outer execution stream.
        print("compilation_recorder.retention_batch_outcome=" + canonical(outcome).decode("ascii"), file=sys.stderr, flush=True)
        return outcome

    @contextlib.contextmanager
    def retention_batch(self):
        self.require_retention_writable()
        require(self._batch is None, "retention_batch_active")
        with self.locked():
            require(len(os.listdir(self.batches.fd)) < 2 * MAX_RETENTION_BATCHES, "retention_batch_limit")
            before = {"artifacts": self.artifact_inventory(), "content_bytes": self.state["content_bytes"],
                      "record_count": self.state["record_count"]}
            batch_id = uuid.uuid4().hex
            start_name, complete_name = batch_id + ".start.json", batch_id + ".complete.json"
            start_reference = None
            physical = False
            with HeldPath(self.batches.path / (".pending-" + uuid.uuid4().hex), create=True) as start_handle:
                with HeldPath(self.batches.path / (".pending-" + uuid.uuid4().hex), create=True) as complete_handle:
                    start = {"schema": "chio.compiler-retention-batch-start.v1", "batch_id": batch_id,
                             "source_binding": self.binding, "before": before,
                             "completion_identity": descriptor_identity(complete_handle)}
                    start_bytes = canonical(start) + b"\n"
                    require(len(start_bytes) <= MAX_JSON, "retention_batch_json_limit")
                    self._batch = {"physical": False, "publications": self.publication_inventory(),
                                   "expected": {item["sha256"]: item for item in before["artifacts"]}}
                    try:
                        publish_held(self.batches, start_name, start_bytes, start_handle)
                        start_reference = self.batch_file_reference(start_name, start_bytes, start_handle)
                        yield self
                        self.require_retention_writable()
                        require(self.publication_inventory() == self._batch["publications"], "retention_batch_inventory_changed")
                        after = {"artifacts": self.artifact_inventory(), "content_bytes": self.state["content_bytes"],
                                 "record_count": self.state["record_count"]}
                        expected = self._batch["expected"]
                        require(after["artifacts"] == [expected[sha] for sha in sorted(expected)]
                                and sum(item["size"] for item in after["artifacts"]) == after["content_bytes"]
                                and before["record_count"] == after["record_count"], "retention_batch_inventory_changed")
                        old = {item["sha256"] for item in before["artifacts"]}
                        complete = {"schema": "chio.compiler-retention-batch-complete.v1", "batch_id": batch_id,
                                    "source_binding": self.binding, "start": start_reference,
                                    "before_sha256": digest(before), "after": after,
                                    "retained": [item for item in after["artifacts"] if item["sha256"] not in old]}
                        complete_bytes = canonical(complete) + b"\n"
                        require(len(complete_bytes) <= MAX_JSON, "retention_batch_json_limit")
                        os.fsync(self.artifacts.fd)
                        self.save_state()
                        self.directory.verify(content=False)
                        self.artifacts.verify(content=False)
                        verify_publication(start_handle, self.batches, start_name, start_bytes)
                        publish_held(self.batches, complete_name, complete_bytes, complete_handle,
                                     synchronize=False, quarantine_on_failure=True)
                        verify_publication(start_handle, self.batches, start_name, start_bytes)
                        verify_publication(complete_handle, self.batches, complete_name, complete_bytes)
                        physical = True
                        self._batch["physical"] = True
                        complete_reference = self.batch_file_reference(complete_name, complete_bytes, complete_handle)
                        try:
                            os.fsync(self.batches.fd)
                        except OSError as error:
                            self._durability_unconfirmed = True
                            self.observe_retention_outcome(batch_id, start_reference, complete_reference, "complete", "unconfirmed", error)
                        else:
                            self.observe_retention_outcome(batch_id, start_reference, complete_reference, "complete", "confirmed")
                    except BaseException as error:
                        if not physical:
                            self._batch_failed = True
                            self.observe_retention_outcome(batch_id, start_reference, None, "incomplete", "not-attempted", error)
                            raise
                        # An outer observation write/late check is fallible too.
                        # Never describe verified physical completion as rolled back.
                        self._durability_unconfirmed = True
                        raise Refusal("retention_batch_outcome_unavailable") from error

    def retain(self, payload):
        try:
            return self._retain(payload)
        except BaseException:
            if self._batch is not None:
                self._batch_failed = True
            raise

    def _retain(self, payload):
        self.require_retention_writable()
        require(len(payload) <= MAX_INPUT, "input_limit")
        sha = hashlib.sha256(payload).hexdigest()
        def retain_locked():
            path = self.artifacts.path / sha
            try:
                with HeldPath(path) as handle:
                    observed = handle.read()
                    require(hashlib.sha256(observed).hexdigest() == sha and observed == payload, "artifact_changed")
                    member = {"artifact": "artifacts/" + sha, "sha256": sha, "size": len(payload), "identity": list(handle.initial)}
            except FileNotFoundError:
                require((len(self._batch["expected"]) if self._batch is not None else len(os.listdir(self.artifacts.fd))) < MAX_ARTIFACTS, "artifact_limit")
                require(self.state["content_bytes"] + len(payload) <= MAX_CONTENT, "content_limit")
                with HeldPath(self.artifacts.path / (".pending-" + uuid.uuid4().hex), create=True) as staged:
                    publish_held(self.artifacts, sha, payload, staged, synchronize=self._batch is None)
                    # publish_held just verified final body and inode against
                    # this held FD. Preserve that same physical identity for
                    # the batch inventory instead of reopening a new authority.
                    member = {"artifact": "artifacts/" + sha, "sha256": sha, "size": len(payload),
                              "identity": list(identity(os.fstat(staged.fd)))}
                self.state["content_bytes"] += len(payload)
                if self._batch is None:
                    self.save_state()
            if self._batch is not None:
                expected = self._batch["expected"]
                require(sha not in expected or expected[sha] == member, "artifact_changed")
                expected[sha] = member
        if self._batch is not None:
            retain_locked()
        else:
            with self.locked():
                retain_locked()
        return {"sha256": sha, "size": len(payload), "artifact": "artifacts/" + sha}

    def observe_unit_publication(self, row, record_reference, completion_reference, status, error=None):
        outcome = {"schema": "chio.rust-unit-publication-outcome.v1", "source_binding": self.binding,
                   "invocation_id": row["invocation_id"], "kind": row["kind"],
                   "record_status": row["status"], "compiler_exit": row["compiler_exit"],
                   "record": record_reference, "completion": completion_reference,
                   "unit_images_sha256": digest({key: row[key] for key in ["compiler", "inputs", "outputs", "depfiles"]}),
                   "physical_status": "complete", "durability": {"status": status,
                       "phase": "completion-directory-fsync", "errno": getattr(error, "errno", None)}}
        self.unit_publication_outcomes.append(outcome)
        print("compilation_recorder.unit_publication_outcome=" + canonical(outcome).decode("ascii"), file=sys.stderr, flush=True)
        return outcome

    def publish(self, row):
        self.require_retention_writable()
        require(self._batch is None, "retention_batch_active")
        name = row["invocation_id"] + ".json"
        require(set(row["publication"]) == {"completion", "marker_identity"}
                and row["publication"]["completion"] == "completions/" + name, "publication_contract")
        # Reject oversize metadata before reserving either physical object.
        require(len(canonical(row)) + 1 <= MAX_JSON, "record_json_limit")
        completed = False
        outcome = None
        try:
            with self.locked():
                row["retention_batches"] = list(self._retention_pairs)
                require(self.state["record_count"] < MAX_RECORDS, "record_limit")
                self.state["record_count"] += 1
                self.save_state()
                record_temporary = ".pending-" + uuid.uuid4().hex
                marker_temporary = ".pending-" + uuid.uuid4().hex
                with HeldPath(self.records.path / record_temporary, create=True) as record_staged:
                    with HeldPath(self.completions.path / marker_temporary, create=True) as marker_staged:
                        record_identity = descriptor_identity(record_staged)
                        marker_identity = descriptor_identity(marker_staged)
                        # These fields are measured from held regular FDs, never
                        # accepted from the caller or erased to permit export.
                        row["publication"]["marker_identity"] = marker_identity
                        payload = canonical(row) + b"\n"
                        require(len(payload) <= MAX_JSON, "record_json_limit")
                        completion = {"schema": COMPLETION_SCHEMA, "invocation_id": row["invocation_id"],
                                      "source_binding": row["source_binding"], "record_sha256": hashlib.sha256(payload).hexdigest(),
                                      "size": len(payload), "record_identity": record_identity}
                        marker = canonical(completion) + b"\n"
                        publish_held(self.records, name, payload, record_staged)
                        publish_held(self.completions, name, marker, marker_staged,
                                     synchronize=False, quarantine_on_failure=True)
                        verify_publication(record_staged, self.records, name, payload)
                        verify_publication(marker_staged, self.completions, name, marker)
                        completed = True
                        record_reference = {"path": "records/" + name, "sha256": hashlib.sha256(payload).hexdigest(),
                                            "size": len(payload), "identity": record_identity}
                        completion_reference = {"path": "completions/" + name, "sha256": hashlib.sha256(marker).hexdigest(),
                                                "size": len(marker), "identity": marker_identity}
                        try:
                            os.fsync(self.completions.fd)
                        except OSError as error:
                            self._unit_durability_unconfirmed = self._durability_unconfirmed = True
                            outcome = self.observe_unit_publication(row, record_reference, completion_reference, "unconfirmed", error)
                        else:
                            outcome = self.observe_unit_publication(row, record_reference, completion_reference, "confirmed")
        except BaseException as error:
            if not completed:
                raise
            self._unit_durability_unconfirmed = self._durability_unconfirmed = True
            # A stable physical pair is retained even if the outside outcome
            # stream or a subsequent custody check is unavailable. This is an
            # instrumentation/durability refusal, never guaranteed rollback.
            raise Refusal("unit_publication_outcome_unavailable") from error
        if outcome["durability"]["status"] != "confirmed":
            raise UnitPublicationDurabilityUnconfirmed(outcome)
        return outcome


    def close(self):
        for key in ["batches", "completions", "records", "artifacts", "lock", "directory"]:
            value = getattr(self, key, None)
            if value is not None:
                value.close()


def row_for(arguments, environment, binding):
    invocation = uuid.uuid4().hex
    return {"schema": SCHEMA, "source_binding": binding, "invocation_id": invocation,
        "kind": "compilation", "status": "refused", "compiler_exit": None,
        "invocation_sha256": digest(arguments), "environment_sha256": digest(environment),
        "compiler": None, "semantics": None, "inputs": [], "outputs": [], "depfiles": [],
        "refusal": None, "publication": {"completion": "completions/" + invocation + ".json", "marker_identity": None}}


def capture(path, role, campaign):
    with HeldPath(path) as handle:
        payload = handle.read()
        retained = campaign.retain(payload)
        handle.verify()
        return {"role": role, "path": str(handle.path), **retained}, handle.binding()


def tree_files(path, exclude=()):
    """Reject aliases without opening their target; bound traversal to record ceiling."""
    found = []
    with HeldPath(path, directory=True) as directory:
        names = sorted(os.listdir(directory.fd))
        for name in names:
            if name in exclude or secret_path(name):
                continue
            child = directory.path / name
            info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            require(not stat.S_ISLNK(info.st_mode), "input_alias")
            if stat.S_ISDIR(info.st_mode):
                found.extend(tree_files(child, exclude))
            else:
                require(stat.S_ISREG(info.st_mode), "not_regular")
                found.append(child)
            require(len(found) <= MAX_RECORDS, "input_count_limit")
        require(names == sorted(os.listdir(directory.fd)), "directory_changed")
        directory.verify(content=False)
    return found


def snapshot(paths):
    result = {}
    for path in paths:
        with HeldPath(path) as handle:
            handle.verify()
            result[str(handle.path)] = handle.binding()
    return result


def verify_unchanged(path, original, mutable_directory=None):
    directory_input = stat.S_ISDIR(original[0][2])
    with HeldPath(path, directory=directory_input, metadata_only=directory_input) as handle:
        require((handle.binding()[0][:3] == original[0][:3] if directory_input
                 else handle.binding()[0] == original[0]), "input_changed_during_compilation")
        for index, (before, after) in enumerate(zip(original[1], handle.binding()[1])):
            directory = Path("/").joinpath(*handle.path.parts[1:index + 1])
            if directory_input or (mutable_directory is not None and directory == mutable_directory) or index != len(original[1]) - 1:
                require(before[:3] == after[:3], "input_parent_changed")
            else:
                require(before == after, "input_parent_changed")


def parse(arguments, cwd, native=None):
    require(arguments, "missing_compiler_arguments")
    require(not any(value.startswith("@") for value in arguments), "response_file")
    if native is None:
        require(not any(SECRET_WORD.search(value) for value in arguments), "credential_argument")
    else:
        check_public_argument_positions(arguments, cwd, native)
    if arguments in [["-vV"], ["-V"], ["--version"], ["--verbose", "--version"]]:
        return {"kind": "probe", "probe": "version"}
    if all(value.startswith("--print=") for value in arguments):
        require(all(value.split("=", 1)[1] in {"sysroot", "target-list", "target-libdir", "cfg", "file-names"} for value in arguments), "unsupported_probe")
        return {"kind": "probe", "probe": "print"}
    if len(arguments) == 2 and arguments[0] == "--print":
        require(arguments[1] in {"sysroot", "target-list", "target-libdir", "cfg", "file-names"}, "unsupported_probe")
        return {"kind": "probe", "probe": "print"}
    result = {"kind": "compilation", "cwd": str(cwd), "source": None, "crate_name": None,
              "crate_types": [], "target": None, "profile": {"optimization": "0", "debug_info": "0"},
              "flags": [], "externs": [], "search": [], "out_dir": None, "output": None,
              "emit": {}, "sysroot": None, "probe": None}
    valued = {"--crate-name", "--crate-type", "--edition", "--emit", "--out-dir", "--extern", "--cfg",
              "--check-cfg", "--target", "--sysroot", "--error-format", "--json", "--cap-lints",
              "--diagnostic-width", "--remap-path-prefix", "--print", "-o", "-C", "-L", "-l", "-A", "-D", "-W", "-F"}
    switches = {"--test", "--verbose", "-g", "-O"}
    has_print = any(arg == "--print" or arg.startswith("--print=") for arg in arguments)
    result["prints"] = []
    index = 0
    while index < len(arguments):
        arg = arguments[index]
        index += 1
        if arg == "-" and has_print:
            continue
        if not arg.startswith("-"):
            require(result["source"] is None and arg.endswith(".rs"), "unsupported_positional")
            result["source"] = str(absolute(arg, cwd))
            continue
        if arg in switches:
            result["flags"].append({"name": arg})
            if arg == "--test":
                result["crate_types"] = ["bin"]
            if arg == "-g":
                result["profile"]["debug_info"] = "2"
            if arg == "-O":
                result["profile"]["optimization"] = "3"
            continue
        if "=" in arg and arg.split("=", 1)[0] in valued:
            key, value = arg.split("=", 1)
        elif arg[:2] in {"-C", "-L", "-l", "-A", "-D", "-W", "-F"} and len(arg) > 2:
            key, value = arg[:2], arg[2:]
        else:
            key = arg
            require(key in valued and index < len(arguments), "unsupported_option")
            value = arguments[index]
            index += 1
        require(value and not value.startswith("@"), "response_file")
        flag = {"name": key, "value_sha256": digest(value)}
        if key == "--crate-name":
            require(NAME.fullmatch(value), "crate_name")
            result["crate_name"] = value
        elif key == "--crate-type":
            types = value.split(",")
            require(all(t in {"bin", "rlib", "lib", "dylib", "staticlib", "cdylib", "proc-macro"} for t in types), "crate_type")
            result["crate_types"].extend(types)
        elif key in {"--out-dir", "-o", "--sysroot"}:
            result[{"--out-dir": "out_dir", "-o": "output", "--sysroot": "sysroot"}[key]] = str(absolute(value, cwd))
        elif key == "--target":
            require(PUBLIC.fullmatch(value) and not value.endswith(".json"), "custom_target")
            require(result["target"] is None or result["target"] == value, "ambiguous_native_target")
            result["target"] = value
        elif key == "--cfg":
            require(NAME.fullmatch(value), "opaque_cfg_value")
        elif key == "--check-cfg":
            require(re.fullmatch(r"cfg\([A-Za-z_][A-Za-z0-9_]*(?:,[A-Za-z_][A-Za-z0-9_]*)*(?:,values\((?:none\(\))?\))?\)", value), "opaque_cfg_value")
        elif key == "--extern":
            require("=" in value, "implicit_extern")
            name, path = value.split("=", 1)
            name = name.removeprefix("priv:").removeprefix("noprelude:")
            require(NAME.fullmatch(name), "extern_name")
            extension = Path(path).suffix
            require(extension in {".rlib", ".rmeta"} or (native is not None and extension == ".so"), "dynamic_extern_hidden_inputs")
            external = {"name": name, "path": str(absolute(path, cwd))}
            if extension == ".so":
                external["kind"] = "dynamic-image"
            result["externs"].append(external)
        elif key == "-L":
            scope, path = value.split("=", 1) if "=" in value else ("all", value)
            require(scope in {"dependency", "native", "all", "crate", "framework"}, "search_kind")
            result["search"].append({"kind": scope, "path": str(absolute(path, cwd))})
        elif key == "--emit":
            for item in value.split(","):
                name, path = item.split("=", 1) if "=" in item else (item, None)
                require(name in {"dep-info", "link", "metadata", "obj", "asm", "llvm-ir", "llvm-bc", "mir"}, "emit_kind")
                require(name not in result["emit"], "duplicate_emit")
                result["emit"][name] = str(absolute(path, cwd)) if path else None
        elif key == "-C":
            name, val = value.split("=", 1) if "=" in value else (value, None)
            require(name in {"opt-level", "debuginfo", "debug-assertions", "overflow-checks", "metadata", "extra-filename",
                            "embed-bitcode", "incremental", "codegen-units", "panic", "strip", "lto", "linker-plugin-lto",
                            "target-cpu", "target-feature", "relocation-model", "prefer-dynamic", "force-frame-pointers",
                            "symbol-mangling-version", "split-debuginfo", "rpath"}
                    or (native is not None and name == "linker"), "unsupported_codegen_input")
            flag["codegen"] = name
            if name == "incremental":
                raise Refusal("incremental_hidden_inputs")
            if name == "linker":
                require(val is not None, "undeclared_linker")
                result["linker"] = val
                result["explicit_linker"] = True
            if name == "split-debuginfo":
                require(val == "off", "split_debug_hidden_outputs")
            if name == "extra-filename":
                require(val is not None and PUBLIC.fullmatch(val), "output_suffix")
                result["suffix"] = val
            if name in {"opt-level", "debuginfo"}:
                require(val in ({"0", "1", "2", "3", "s", "z"} if name == "opt-level" else {"0", "1", "2", "none", "limited", "full"}), "profile")
                result["profile"]["optimization" if name == "opt-level" else "debug_info"] = val
        elif key == "-l":
            require(native is not None, "native_link_hidden_inputs")
            require(re.fullmatch(r"(?:(?:static|dylib)(?::[+-](?:bundle|whole-archive|verbatim|as-needed)(?:,[+-](?:bundle|whole-archive|verbatim|as-needed))*)?=)?[A-Za-z0-9_.+-]+", value), "unsupported_native_library")
            result.setdefault("native_libraries", []).append(value)
        elif key == "--print":
            require(value in {"file-names", "cfg", "sysroot", "target-libdir", "split-debuginfo", "crate-name"}, "unsupported_probe")
            result["probe"] = "cargo-print"
            result["prints"].append(value)
        result["flags"].append(flag)
    if native is not None:
        context, _ = native_target_context_from_parsed(native, result)
        if result.get("explicit_linker"):
            require(result["linker"] == context["images"]["linker"]["path"], "undeclared_linker")
        result.setdefault("linker", context["images"]["linker"]["path"])
    if result["probe"] is not None:
        result["kind"] = "probe"
        return result
    require(result["source"] is not None, "missing_source")
    require("dep-info" in result["emit"], "missing_dep_info")
    require(result["output"] is not None or result["out_dir"] is not None, "missing_output_directory")
    if not result["crate_types"]:
        result["crate_types"] = ["bin"]
    require(native is not None or "link" not in result["emit"] or not any(t in {"bin", "dylib", "cdylib", "proc-macro"} for t in result["crate_types"]), "external_linker_contract_required")
    if native is not None:
        supported = {item["triple"] for item in native.get("supported_targets", [])} or {"x86_64-unknown-linux-gnu"}
        require((result["target"] or "x86_64-unknown-linux-gnu") in supported, "unsupported_native_target")
        result["native_platform"] = "linux-gnu"
        result.setdefault("linker", native["images"]["linker"]["path"])
        if result["crate_name"] == "chio_credentials":
            require(any(entry["kind"] == "source" and entry["value"] == result["source"]
                        for entry in native.get("_public_arguments", [])), "public_crate_source_pair")
    return result


def require_native_linker_selection(parsed, native):
    if native is not None and parsed["kind"] == "compilation" and "link" in parsed["emit"] and any(
            kind in {"bin", "proc-macro", "cdylib", "dylib"} for kind in parsed["crate_types"]):
        require(parsed.get("explicit_linker") is True, "native_linker_selection_not_bound")


def words(text):
    result = []
    token = ""
    index = 0
    while index < len(text):
        character = text[index]
        if character == "\\":
            index += 1
            require(index < len(text) and text[index] in " \\#:", "depfile_escape")
            token += text[index]
        elif character.isspace():
            if token:
                result.append(token)
                token = ""
        else:
            require(character not in "|;\x00\r", "depfile_syntax")
            require(character != "#", "depfile_comment")
            if character == "$":
                require(index + 1 < len(text) and text[index + 1] == "$", "depfile_variable")
                index += 1
            token += character
        index += 1
    if token:
        result.append(token)
    return result


def parse_depfile(payload, cwd, environment, native=None):
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError:
        raise Refusal("depfile_encoding") from None
    text = text.replace("\\\n", " ")
    targets = {}
    requirements = {}
    rules = []
    resolutions = []

    def resolved(name, source=False):
        if native is None:
            return str(absolute(name, cwd))
        if not source:
            require(".." not in name.split("/"), "depfile_target_parent_traversal")
            require(not name.endswith("/") and name.split("/")[-1] not in {"", "."}, "depfile_target_directory_syntax")
            return str(absolute(name, cwd))
        path = checked_include_path(name, cwd, native)
        resolutions.append({"lexical_sha256": digest(name), "resolved": str(path)})
        return str(path)
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("# env-dep:"):
            value = line[len("# env-dep:"):]
            name, observed = value.split("=", 1) if "=" in value else (value, None)
            require(NAME.fullmatch(name) and not SECRET_WORD.search(name), "depfile_environment")
            require(name not in requirements and environment.get(name) == observed, "depfile_environment")
            if observed is not None:
                if name in {"CARGO_MANIFEST_DIR", "OUT_DIR"}:
                    require(os.path.isabs(observed), "depfile_environment_not_public")
                    absolute(observed, cwd)
                elif name == "CARGO_PKG_NAME":
                    require(PUBLIC.fullmatch(observed) and not SECRET_WORD.search(observed), "depfile_environment_not_public")
                elif name == "CARGO_PKG_VERSION":
                    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", observed)
                            and not SECRET_WORD.search(observed), "depfile_environment_not_public")
                elif name in {"CARGO_PKG_VERSION_MAJOR", "CARGO_PKG_VERSION_MINOR", "CARGO_PKG_VERSION_PATCH"}:
                    require(re.fullmatch(r"[0-9]+", observed), "depfile_environment_not_public")
                elif name == "CARGO_PKG_VERSION_PRE":
                    require(re.fullmatch(r"(?:|alpha(?:\.[0-9]+)?|beta(?:\.[0-9]+)?|rc(?:\.[0-9]+)?|dev|nightly(?:\.[0-9]+)?)", observed),
                            "depfile_environment_not_public")
                else:
                    require(native is not None and name.startswith(("CARGO_PKG_", "CARGO_CFG_", "CARGO_FEATURE_")), "depfile_environment_not_public")
            requirements[name] = {"name": name, "value_sha256": digest(observed)}
            continue
        require(not line.startswith("#"), "depfile_comment")
        split = None
        escaped = False
        for index, char in enumerate(line):
            if char == ":" and not escaped:
                split = index
                break
            if char == "\\":
                escaped = not escaped
            else:
                escaped = False
        require(split is not None, "depfile_syntax")
        left, right = words(line[:split]), words(line[split + 1:])
        require(left, "depfile_targets")
        absolute_targets = [resolved(name, not right) for name in left]
        dependencies = [resolved(name, True) for name in right]
        require(len(dependencies) == len(set(dependencies)), "depfile_duplicate_dependency")
        for target in absolute_targets:
            require(target not in targets, "depfile_ambiguous_target")
            targets[target] = dependencies
        rules.append((absolute_targets, dependencies))
    producing = [(left, right) for left, right in rules if right]
    require(producing, "depfile_no_dependencies")
    dependencies = sorted(set(path for _, right in producing for path in right))
    # Rustc repeats identical dependency vectors for its unit and depfile targets.
    require(all(sorted(right) == dependencies for _, right in producing), "depfile_ambiguous_dependencies")
    for left, right in rules:
        if not right:
            require(all(name in dependencies for name in left), "depfile_unbound_phony")
    result = {"targets": sorted(name for left, _ in producing for name in left),
              "dependencies": dependencies, "environment_requirements": list(requirements.values())}
    if native is not None:
        result["path_resolution"] = sorted({canonical(value): value for value in resolutions}.values(), key=lambda value: value["lexical_sha256"])
    return result


def compiler_probe(compiler, args, name, campaign, original):
    environment = getattr(campaign, "environment", dict(os.environ))
    row = row_for([str(compiler), *args], environment, campaign.binding)
    row["kind"] = "probe"
    row["semantics"] = {"probe": name}
    if getattr(campaign, "native_reference", None) is not None:
        row["semantics"]["native_scope"] = campaign.native_reference
    row["compiler"] = original
    result = dispatch_compiler(campaign, [str(compiler), *args], True)
    row["compiler_exit"] = result.returncode
    row["status"] = "success" if result.returncode == 0 else "compiler_failed"
    # Standalone probe rows keep only decoded allowlisted fields. Native
    # dispatch output is bounded inside the outside-owned private namespace.
    campaign.publish(row)
    require(result.returncode == 0 and len(result.stdout) <= MAX_JSON, "compiler_probe_failed")
    return result.stdout.decode("utf-8", errors="strict").strip()


def dispatch_compiler(campaign, argv, probe=False):
    executor = getattr(campaign, "executor", None)
    if executor is not None:
        return executor(argv, campaign.environment, campaign.cwd, probe)
    return subprocess.run(argv, env=getattr(campaign, "environment", None),
                          cwd=getattr(campaign, "cwd", None),
                          stdout=subprocess.PIPE if probe else subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False)


def compiler_inputs(compiler, parsed, campaign, native=None):
    captured, compiler_identity = capture(compiler, "compiler", campaign)
    captured.pop("role")
    captured["version"] = None
    version = compiler_probe(compiler, ["-vV"], "version", campaign, captured)
    require(re.fullmatch(r"rustc [0-9][0-9A-Za-z .()_-]*\n(?:[^\n]*\n?)*", version), "compiler_version")
    fields = {}
    for line in version.splitlines()[1:]:
        if ": " in line:
            key, val = line.split(": ", 1)
            if key in {"binary", "commit-hash", "commit-date", "host", "release", "LLVM version"}:
                require(re.fullmatch(r"[0-9A-Za-z ._-]+", val), "compiler_version")
                fields[key] = val
    require("host" in fields, "compiler_host")
    captured["version"] = {"release_line": version.splitlines()[0], "fields": fields}
    sysroot_text = compiler_probe(compiler, ["--print", "sysroot"], "sysroot", campaign, captured)
    sysroot = absolute(parsed.get("sysroot") or sysroot_text)
    target = parsed.get("target") or fields["host"]
    if native is not None:
        # The retained scope inventories bind all allowed toolchain/runtime
        # regular bytes. Do not invent a consumed-file list or duplicate that
        # complete conservative inventory on each producing invocation.
        require(fields["host"] == "x86_64-unknown-linux-gnu"
                and any(scope["role"] == "toolchain" and (sysroot.is_relative_to(Path(scope["root"]))
                        or Path(scope["root"]).is_relative_to(sysroot)) for scope in native["scopes"]), "native_sysroot_scope")
        declaration = next((entry for entry in native.get("supported_targets", []) if entry["triple"] == target), None)
        require(declaration is not None and sysroot == Path(declaration["sysroot"]), "native_target_not_declared")
        return captured, [], {str(compiler): compiler_identity}
    files = []
    top = sysroot / "lib"
    with HeldPath(top, directory=True) as directory:
        for name in sorted(os.listdir(directory.fd)):
            info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            if stat.S_ISREG(info.st_mode):
                files.append(top / name)
            else:
                require(stat.S_ISDIR(info.st_mode), "toolchain_alias")
    files.extend(tree_files(sysroot / "lib/rustlib" / target / "lib"))
    backends = sysroot / "lib/rustlib" / target / "codegen-backends"
    if backends.exists():
        files.extend(tree_files(backends))
    inputs = []
    identities = {str(compiler): compiler_identity}
    for path in files:
        item, original = capture(path, "toolchain", campaign)
        item["coverage"] = "conservative-toolchain-scope"
        inputs.append(item)
        identities[str(path)] = original
    return captured, inputs, identities


def output_paths(parsed):
    name = parsed["crate_name"] or Path(parsed["source"]).stem
    suffix = parsed.get("suffix", "")
    directory = Path(parsed["out_dir"] or Path(parsed["output"]).parent)
    types = parsed["crate_types"] or ["lib"]
    require(len(types) == 1, "multiple_crate_output_types")
    extensions = {"metadata": ".rmeta", "obj": ".o", "asm": ".s", "llvm-ir": ".ll", "llvm-bc": ".bc", "mir": ".mir"}
    native = parsed.get("native_platform") == "linux-gnu"
    unit_name = (name + suffix if native and types[0] == "bin" else
                 "lib" + name + suffix + (".so" if native and types[0] in {"dylib", "cdylib", "proc-macro"}
                                          else ".a" if types[0] == "staticlib" else ".rlib"))
    if parsed["output"]:
        primary = "link" if "link" in parsed["emit"] else next((kind for kind in parsed["emit"] if kind != "dep-info"), None)
        require(primary is not None, "missing_unit_output")
        if parsed["emit"][primary] is not None:
            require(parsed["output"] == parsed["emit"][primary], "ambiguous_output_name")
        else:
            if primary == "link":
                canonical_name = unit_name
            else:
                canonical_name = ("lib" if primary == "metadata" else "") + name + suffix + extensions[primary]
            require(Path(parsed["output"]).name == canonical_name, "noncanonical_output_name")
    emissions = {}
    for kind, explicit in parsed["emit"].items():
        if explicit:
            selected = Path(explicit)
        elif parsed["output"]:
            selected = Path(parsed["output"])
            if kind == "dep-info":
                selected = selected.with_suffix(".d")
            elif kind != "link":
                selected = selected.with_suffix(extensions[kind])
        elif kind == "dep-info":
            selected = directory / (name + suffix + ".d")
        elif kind == "link":
            selected = directory / unit_name
        else:
            prefix = "lib" if kind == "metadata" else ""
            selected = directory / (prefix + name + suffix + extensions[kind])
        require(selected.parent == directory, "output_escape")
        emissions[kind] = str(selected)
    return Path(emissions["dep-info"]), emissions


class OutputLease:
    """Cooperating wrappers own fresh output paths under one held directory lock."""
    def __init__(self, directory, emissions):
        self.directory = HeldPath(directory, directory=True)
        self.expected = {Path(path).name for path in emissions.values()}
        try:
            require(len(self.expected) == len(emissions), "overlapping_emission_paths")
            fcntl.flock(self.directory.fd, fcntl.LOCK_EX)
            self.baseline = self.entries()
            require(not self.expected.intersection(self.baseline), "preexisting_output")
        except Exception:
            self.close()
            raise

    def entries(self):
        self.directory.verify(content=False)
        names = os.listdir(self.directory.fd)
        require(len(names) <= MAX_RECORDS, "output_namespace_limit")
        entries = {}
        for name in names:
            value = os.stat(name, dir_fd=self.directory.fd, follow_symlinks=False)
            require(stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode), "output_namespace_alias")
            entries[name] = identity(value)
        require(set(names) == set(os.listdir(self.directory.fd)), "output_namespace_changed")
        self.directory.verify(content=False)
        return entries

    def produced(self):
        current = self.entries()
        require(set(current) == set(self.baseline) | self.expected, "unexpected_compiler_output")
        for name, old in self.baseline.items():
            fresh = current[name]
            require(old[:3] == fresh[:3] if stat.S_ISDIR(old[2]) else old == fresh, "preexisting_output_changed")
        for name in self.expected:
            require(stat.S_ISREG(current[name][2]) and current[name][-1] == 1, "produced_output_not_regular")
        return {name: current[name] for name in self.expected}

    def verify(self, observed):
        require(self.produced() == observed, "produced_output_changed")

    def close(self):
        if self.directory.fds:
            self.directory.close()


LINUX_ENVIRONMENT = frozenset({"PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "LANG", "LC_ALL",
    "TMPDIR", "CARGO_TARGET_DIR", "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE", "CARGO_TERM_COLOR",
    "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CHIO_CONFINED_CANARY_MODE"})
LINUX_SELECTORS = frozenset({"RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_TARGET", "RUSTC_CODEGEN_BACKEND", "RUST_TARGET_PATH", "PYTHONPATH", "PYTHONHOME",
    "CC", "CXX", "AR", "RANLIB", "CFLAGS", "CXXFLAGS", "LDFLAGS", "COMPILER_PATH", "GCC_EXEC_PREFIX",
    "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "BASH_ENV", "ENV"})
LINUX_METADATA = {"/dev/null": "character-device", "/dev/urandom": "character-device", "/dev/random": "character-device",
    "/proc/cpuinfo": "kernel-generated", "/proc/meminfo": "kernel-generated",
    "/sys/devices/system/cpu/online": "kernel-generated", "/sys/devices/system/cpu/possible": "kernel-generated"}


def linux_selector(name):
    return (name in LINUX_SELECTORS or name.startswith("RUSTC_")
            or name.startswith("CARGO_TARGET_") and name.endswith(("_LINKER", "_RUSTFLAGS", "_RUSTDOCFLAGS")))


def validate_linux_configuration(config, inherited):
    """Validate a public declaration; this does not establish kernel enforcement."""
    fields = {"schema", "candidate", "source_binding", "profile", "package_root", "runtime_inventory", "source_origin",
              "scopes", "images", "aliases", "write_roots", "environment_metadata", "environment", "records", "evidence"}
    require(type(config) is dict and fields <= set(config) <= fields | {"loader_paths", "supported_targets", "public_arguments", "linker_selection"}
            and config["schema"] == "chio.linux-compilation-launch.v1", "linux_configuration")
    require(DIGEST.fullmatch(config["source_binding"]) and type(config["profile"]) is dict
            and config["profile"].get("name") in {"dev", "test", "release"}, "linux_profile")
    require(set(config["profile"]) <= {"name", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"}
            and all(value in {"0", "1", "2"} for key, value in config["profile"].items() if key != "name"), "linux_profile")
    require(not any(linux_selector(name) or name.startswith(("LD_", "DYLD_"))
                    or "proxy" in name.casefold() or SECRET_WORD.search(name) for name in inherited), "inherited_linux_input")
    environment = config["environment"]
    require(type(environment) is dict and set(environment) <= LINUX_ENVIRONMENT
            and all(type(value) is str and not SECRET_WORD.search(value) and "\x00" not in value for value in environment.values()), "linux_environment")
    require(environment.get("CARGO_INCREMENTAL") == "0" and environment.get("CARGO_NET_OFFLINE") == "true"
            and environment.get("CARGO_TERM_COLOR") == "never", "linux_build_environment")
    for key in ["CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"]:
        if key in environment or key in config["profile"]:
            require(environment.get(key) == config["profile"].get(key), "linux_profile")
    require(environment.get("CARGO_BUILD_JOBS", "1").isdigit()
            and 1 <= int(environment.get("CARGO_BUILD_JOBS", "1")) <= 64, "linux_jobs")
    require("PATH" in environment and all(os.path.isabs(value) and value and ".." not in Path(value).parts
                                          and not secret_path(value) for value in environment["PATH"].split(os.pathsep)), "linux_environment_path")
    candidate = absolute(config["candidate"])
    require(str(candidate) == config["candidate"], "linux_candidate")
    package = absolute(config["package_root"])
    for key in ["runtime_inventory", "source_origin"]:
        reference = config[key]
        require(set(reference) == {"path", "sha256"} and DIGEST.fullmatch(reference["sha256"])
                and not os.path.isabs(reference["path"]), "linux_reference")
        require(absolute(reference["path"], package).is_relative_to(package), "linux_reference")
    require(type(config["scopes"]) is list and 1 <= len(config["scopes"]) <= 64, "linux_scopes")
    roots = []
    for scope in config["scopes"]:
        require(set(scope) == {"role", "root", "selection", "members"}
                and scope["role"] in {"candidate", "vendor", "toolchain", "native-runtime"}, "linux_scope")
        root = absolute(scope["root"])
        require(str(root) == scope["root"] and root != Path("/"), "linux_scope_root")
        require(scope["selection"] in {"complete-tree", "explicit-members"}
                and type(scope["members"]) is list, "linux_scope_selection")
        require(not scope["members"] if scope["selection"] == "complete-tree" else bool(scope["members"]), "linux_scope_selection")
        for member in scope["members"]:
            require(type(member) is str and not os.path.isabs(member) and str(absolute(member, root).relative_to(root)) == member, "linux_scope_member")
        require(len(scope["members"]) == len(set(scope["members"])), "linux_scope_member")
        roots.append(root)
    require(len(roots) == len(set(roots)) and {scope["role"] for scope in config["scopes"]}
            == {"candidate", "vendor", "toolchain", "native-runtime"}, "linux_scopes")
    require(any(scope["role"] == "candidate" and Path(scope["root"]) == candidate for scope in config["scopes"]), "linux_candidate_scope")
    require(type(config["write_roots"]) is list and bool(config["write_roots"]), "linux_write_roots")
    writes = [absolute(value) for value in config["write_roots"]]
    require(all(path.is_relative_to(candidate/"target") for path in writes)
            and len(writes) == len(set(writes)), "linux_write_roots")
    require(not any(left != right and left.is_relative_to(right) for left in writes for right in writes), "linux_write_overlap")
    require(not any(scope["role"] != "candidate" and (Path(scope["root"]).is_relative_to(write)
                    or write.is_relative_to(Path(scope["root"]))) for scope in config["scopes"] for write in writes), "linux_read_write_overlap")
    protected = [absolute(config[key]) for key in ["records", "evidence"]]
    require(all(str(path) == config[key] and path.is_relative_to(candidate / "target")
                for path, key in zip(protected, ["records", "evidence"])), "linux_evidence_location")
    require(not any(path.is_relative_to(write) or write.is_relative_to(path)
                    for path in protected for write in writes), "linux_evidence_writable")
    require(not any(left.is_relative_to(right) for left in protected for right in protected if left != right)
            and protected[0] != protected[1], "linux_evidence_overlap")
    require(not any(root.is_relative_to(path) for root in roots for path in protected), "linux_protected_read_scope")
    require(all(str(path) == value for path, value in zip(writes, config["write_roots"])), "linux_write_roots")
    for key in ["HOME", "CARGO_HOME", "TMPDIR", "CARGO_TARGET_DIR"]:
        if key in environment:
            path = absolute(environment[key])
            require(any(path.is_relative_to(root) for root in roots + writes), "linux_environment_path")
    require(type(config.get("loader_paths", [])) is list and len(config.get("loader_paths", [])) <= 128, "linux_loader_paths")
    for value in config.get("loader_paths", []):
        path = absolute(value)
        require(str(path) == value and any(path.is_relative_to(root) for root in roots + writes), "linux_loader_paths")
    require(len(config.get("loader_paths", [])) == len(set(config.get("loader_paths", []))), "linux_loader_paths")
    require(type(config["aliases"]) is list and len(config["aliases"]) <= MAX_RECORDS, "linux_aliases")
    aliases = set()
    for alias in config["aliases"]:
        require(type(alias) is dict and set(alias) in [{"path", "text", "target"}, {"path", "text", "target", "purpose"}], "linux_alias")
        path = absolute(alias["path"])
        target = absolute(alias["target"])
        require(str(path) == alias["path"] and str(target) == alias["target"], "linux_alias_target")
        if "purpose" in alias:
            require(alias["purpose"] == "public-system-elf-loader", "linux_alias_purpose")
            require_public_loader_alias(alias)
            permitted = [Path(scope["root"]) for scope in config["scopes"] if scope["role"] in {"native-runtime", "toolchain"}]
            require(any(target.is_relative_to(root) for root in permitted), "linux_loader_alias_scope")
        else:
            require(absolute(alias["text"], path.parent) == target, "linux_alias_target")
        require(any(target.is_relative_to(root) or root.is_relative_to(target) for root in roots)
                and not any(path.is_relative_to(write) or target.is_relative_to(write) for write in writes + protected), "linux_alias_target")
        require(str(path) not in aliases, "linux_alias_duplicate")
        aliases.add(str(path))
    for alias in config["aliases"]:
        if alias.get("purpose") == "public-system-elf-loader" and Path(alias["path"]).name == "ld-linux-x86-64.so.2":
            parent = Path(alias["path"]).parent
            root_alias = {"path": str(parent.parent.parent/"lib64"), "text": "usr/lib64", "target": str(parent),
                          "purpose": "public-system-elf-loader"}
            require(root_alias in config["aliases"], "linux_loader_alias_hop_not_declared")
        require(declared_path(alias["path"], config) == declared_path(alias["target"], config), "linux_alias_target_projection")
    require(type(config["environment_metadata"]) is list, "linux_metadata")
    for entry in config["environment_metadata"]:
        require(set(entry) == {"path", "kind"} and LINUX_METADATA.get(entry["path"]) == entry["kind"], "linux_metadata")
    require(type(config["images"]) is dict and set(config["images"]) == {"cargo", "rustc", "linker", "python", "recorder"}, "linux_images")
    for image in config["images"].values():
        require(set(image) == {"path", "sha256"} and DIGEST.fullmatch(image["sha256"]), "linux_image")
        path = absolute(image["path"])
        require(any(path.is_relative_to(root) for root in roots) and not any(path.is_relative_to(write) for write in writes), "linux_image_scope")
    targets = config.get("supported_targets", [])
    require(type(targets) is list and len(targets) <= 2, "linux_targets")
    require(len({item["triple"] for item in targets}) == len(targets), "linux_targets")
    for target in targets:
        require(set(target) == {"triple", "sysroot", "library_root", "crt_members"}
                and target["triple"] in {"x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"}, "linux_target")
        sysroot = absolute(target["sysroot"])
        library = absolute(target["library_root"])
        require(library == sysroot/"lib/rustlib"/target["triple"]/"lib"
                and any(scope["role"] == "toolchain" and library.is_relative_to(Path(scope["root"])) for scope in config["scopes"]), "linux_target_library")
        require(type(target["crt_members"]) is list and bool(target["crt_members"])
                and len(target["crt_members"]) == len(set(target["crt_members"])), "linux_target_crt")
        require(all(any(absolute(path).is_relative_to(root) for root in roots) and path.endswith((".o", ".a"))
                    for path in target["crt_members"]), "linux_target_crt")
    if "linker_selection" in config:
        selection = config["linker_selection"]
        require(type(selection) is dict and set(selection) == {"schema", "mode", "profile", "targets"}
                and selection["schema"] == "chio.compiler-linker-selection.v1"
                and selection["mode"] == "declared-driver-if-missing"
                and selection["profile"] == "explicit-instrumented-compiler", "linux_linker_selection")
        entries = selection["targets"]
        require(type(entries) is list and len(entries) == len(targets) and bool(entries)
                and len({entry["triple"] for entry in entries}) == len(entries)
                and {entry["triple"] for entry in entries} == {target["triple"] for target in targets}, "linux_linker_targets")
        for entry in entries:
            require(set(entry) == {"triple", "driver", "sysroot", "library_root", "crt_members"}, "linux_linker_target")
            target = next(target for target in targets if target["triple"] == entry["triple"])
            require({key: entry[key] for key in target} == target, "linux_linker_target_binding")
            driver = entry["driver"]
            require(type(driver) is dict and set(driver) == {"path", "sha256"}
                    and DIGEST.fullmatch(driver["sha256"]), "linux_linker_driver")
            path = absolute(driver["path"])
            require(str(path) == driver["path"] and any(path.is_relative_to(root) for root in roots)
                    and not any(path.is_relative_to(root) for root in writes + protected), "linux_linker_driver_scope")
    for argument in config.get("public_arguments", []):
        require(set(argument) == {"kind", "value", "source"} and argument["kind"] in {"crate-name", "source", "extern-name"}, "linux_public_argument")
        reference = argument["source"]
        require(set(reference) == {"path", "sha256"} and DIGEST.fullmatch(reference["sha256"]), "linux_public_argument")
        expected = "crates/trust/chio-credentials/" + ("src/lib.rs" if argument["kind"] == "source" else "Cargo.toml")
        require(reference["path"] == expected and argument["value"] == (str(candidate/expected) if argument["kind"] == "source" else "chio_credentials"), "linux_public_argument")
    return config


def bind_public_arguments(config, vector, members):
    """Measure the exact existing public identifier against source inventory."""
    entries = vector.get("sources", vector.get("inputs", []))
    require(type(entries) is list, "public_argument_inventory")
    expected = {item["path"]: item["sha256"] for item in entries}
    bound = []
    for argument in config.get("public_arguments", []):
        source = argument["source"]
        path = str(Path(config["candidate"])/source["path"])
        require(expected.get(source["path"]) == source["sha256"] and path in members
                and members[path]["sha256"] == source["sha256"], "public_argument_source_binding")
        with HeldPath(path) as file:
            payload = file.read()
        require(hashlib.sha256(payload).hexdigest() == source["sha256"], "public_argument_source_binding")
        if argument["kind"] != "source":
            manifest = tomllib.loads(payload.decode("utf-8"))
            require(manifest["package"]["name"] == "chio-credentials"
                    and manifest.get("lib", {}).get("name", "chio_credentials") == "chio_credentials", "public_argument_manifest")
        bound.append(argument)
    return {**config, "_public_arguments": bound}


def check_public_argument_positions(arguments, cwd, native):
    """Only fixed typed source-pinned positions get the existing-name exception."""
    exceptions = native.get("_public_arguments", [])
    valued = {"--crate-name", "--crate-type", "--edition", "--emit", "--out-dir", "--extern", "--cfg", "--check-cfg",
              "--target", "--sysroot", "--error-format", "--json", "--cap-lints", "--diagnostic-width", "--remap-path-prefix",
              "--print", "-o", "-C", "-L", "-l", "-A", "-D", "-W", "-F"}
    context = None
    for argument in arguments:
        if context is not None:
            key, value = context, argument
            context = None
        elif "=" in argument and argument.split("=", 1)[0] in valued:
            key, value = argument.split("=", 1)
        elif argument in valued:
            context = argument
            continue
        elif argument.startswith("-"):
            key, value = "option", argument
        else:
            key, value = "source", argument
        if not SECRET_WORD.search(argument):
            continue
        allowed = False
        for exception in exceptions:
            if key == "--crate-name" and exception["kind"] == "crate-name" and value == exception["value"]:
                allowed = True
            elif key == "source" and exception["kind"] == "source" and str(absolute(value, cwd)) == exception["value"]:
                allowed = True
            elif key == "--extern" and exception["kind"] == "extern-name" and "=" in value:
                name, path = value.split("=", 1)
                allowed = name == "chio_credentials" and Path(path).suffix in {".rmeta", ".rlib"} and not secret_path(path)
        require(allowed, "credential_argument")


def linux_network_filter(machine):
    """Return explicit classic BPF; no syscall execution or enforcement claim."""
    if machine == "x86_64":
        architecture = 0xC000003E
        blocked = set(range(41, 56)) | {101, 109, 112, 155, 165, 166, 246, 272, 288, 298, 299, 300, 303, 304,
                                      307, 308, 310, 311, 312, 313, 321, 323}
    elif machine == "aarch64":
        architecture = 0xC00000B7
        blocked = set(range(198, 213)) | {39, 40, 41, 97, 104, 117, 154, 157, 217, 218, 242, 243, 264, 265, 268, 269, 270, 271, 272, 280, 282}
    else:
        raise Refusal("linux_architecture")
    blocked |= {425, 426, 427, 435, 438}
    # Architecture mismatch and x32/compat syscall numbers fail closed.
    program = [[0x20, 0, 0, 4], [0x15, 1, 0, architecture], [0x06, 0, 0, 0x80000000],
               [0x20, 0, 0, 0], [0x35, 0, 1, 0x40000000], [0x06, 0, 0, 0x80000000]]
    for number in sorted(blocked):
        # clone3 ENOSYS permits ordinary libc fallback to clone with safe flags.
        error = 38 if number == 435 else 1
        program.extend([[0x15, 0, 1, number], [0x06, 0, 0, 0x00050000 | error]])
    clone = 56 if machine == "x86_64" else 220
    program.extend([[0x15, 0, 4, clone], [0x20, 0, 0, 16], [0x45, 0, 1, 0x7E020000],
                    [0x06, 0, 0, 0x00050001], [0x06, 0, 0, 0x7FFF0000], [0x06, 0, 0, 0x7FFF0000]])
    return architecture, sorted(blocked), program


def verify_alias_target_syntax(alias, parent_fd):
    """Check the raw symlink spelling with VFS semantics before projection."""
    try:
        raw = os.stat(alias["text"], dir_fd=parent_fd, follow_symlinks=True)
        projected = os.stat(alias["target"], follow_symlinks=True)
    except OSError:
        raise Refusal("linux_alias_target_syntax") from None
    require((raw.st_dev, raw.st_ino, raw.st_mode) == (projected.st_dev, projected.st_ino, projected.st_mode),
            "linux_alias_target_projection")


@contextlib.contextmanager
def declared_directory(path):
    if path == Path("/"):
        descriptor = os.open("/", PARENT_OPEN)
        before = identity(os.fstat(descriptor))[:3]
        try:
            yield descriptor
            require(identity(os.fstat(descriptor))[:3] == before, "linux_alias_directory_changed")
        finally:
            os.close(descriptor)
    else:
        with HeldPath(path, directory=True, metadata_only=True) as held:
            yield held.fd
            held.verify(content=False)


def require_public_loader_alias(alias):
    path = absolute(alias["path"])
    target = absolute(alias["target"])
    name = "ld-linux-x86-64.so.2"
    require(alias.get("purpose") == "public-system-elf-loader" and (
        path.name == "lib64" and alias["text"] == "usr/lib64" and target == path.parent/"usr/lib64"
        or path.name == name and path.parent.name == "lib64"
        and alias["text"] == "../lib/x86_64-linux-gnu/"+name
        and target == path.parent.parent/"lib/x86_64-linux-gnu"/name), "linux_loader_alias_shape")


def declared_component_path(text, cwd, config, allow_parents=False, trail=(), hops=None):
    """Walk actual directory components and only exact declared link objects."""
    require(type(text) is str and text and not text.startswith("//")
            and not any(char in text for char in ["\x00", "\n", "\r"]) and not secret_path(text), "linux_alias_text")
    require(len(trail) <= 32, "linux_alias_limit")
    if hops is None:
        hops = []
    current = Path("/") if os.path.isabs(text) else cwd
    parts = text.split("/")[1:] if os.path.isabs(text) else text.split("/")
    aliases = {item["path"]: item for item in config["aliases"]}

    def directory(path):
        if path == Path("/"):
            descriptor = os.open("/", PARENT_OPEN)
            try:
                info = os.fstat(descriptor)
                hops.append({"path": "/", "kind": "directory", "identity": list(identity(info)[:3])})
            finally:
                os.close(descriptor)
        else:
            with HeldPath(path, directory=True, metadata_only=True) as held:
                hops.append({"path": str(path), "kind": "directory", "identity": list(held.initial[:3])})
                held.verify(content=False)

    for index, part in enumerate(parts):
        if part in {"", ".", ".."}:
            directory(current)
            if part == "..":
                require(allow_parents and current != Path("/"), "parent_traversal")
                current = current.parent
            continue
        directory(current)
        selected = current/part
        with declared_directory(current) as parent_fd:
            info = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                require(str(selected) in aliases, "undeclared_linux_alias")
                require(str(selected) not in trail, "linux_alias_cycle")
                alias = aliases[str(selected)]
                raw = os.readlink(part, dir_fd=parent_fd)
                require(raw == alias["text"] and identity(info) == identity(os.stat(part, dir_fd=parent_fd, follow_symlinks=False)), "linux_alias_changed")
                hops.append({"path": str(selected), "kind": "link", "identity": list(identity(info)), "text": raw})
                if "purpose" in alias:
                    require_public_loader_alias(alias)
                else:
                    require(str(absolute(raw, current)) == alias["target"], "linux_alias_immediate_target")
                current = declared_component_path(raw, current, config, alias.get("purpose") == "public-system-elf-loader",
                                                  (*trail, str(selected)), hops)
            else:
                require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "linux_alias_nonregular")
                current = selected
        if index != len(parts)-1:
            directory(current)
    return current


def declared_path(path, config):
    """Raw caller paths refuse parent hops; tagged fixed loader links walk them."""
    selected = absolute(path)
    return declared_component_path(str(selected), Path("/"), config)


def linux_alias_chains(config):
    """Bind original link hops separately from their recursively resolved terminal."""
    chains = []
    for alias in config["aliases"]:
        hops = []
        resolved = declared_component_path(alias["path"], Path("/"), config, hops=hops)
        require(resolved == declared_path(alias["target"], config), "linux_alias_target_projection")
        with declared_directory(resolved.parent) as descriptor:
            terminal = os.stat(resolved.name, dir_fd=descriptor, follow_symlinks=False)
            require(stat.S_ISREG(terminal.st_mode) or stat.S_ISDIR(terminal.st_mode), "linux_alias_nonregular")
            is_directory = stat.S_ISDIR(terminal.st_mode)
            hops.append({"path": str(resolved), "kind": "directory" if is_directory else "regular",
                         "identity": list(identity(terminal)[:3] if is_directory else identity(terminal))})
        chains.append({"path": alias["path"], "immediate_target": alias["target"], "resolved": str(resolved),
                       "purpose": alias.get("purpose", "declared-alias"), "hops": hops})
    return chains


def linux_alias_bindings(config):
    bindings = {}
    for alias in config["aliases"]:
        path = Path(alias["path"])
        with declared_directory(path.parent) as parent_fd:
            info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            require(stat.S_ISLNK(info.st_mode) and os.readlink(path.name, dir_fd=parent_fd) == alias["text"], "linux_alias_changed")
            bindings[str(path)] = identity(info)
            require(identity(os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)) == bindings[str(path)], "linux_alias_changed")
    chains = linux_alias_chains(config)
    if chains:
        bindings["__alias_chains__"] = chains
    return bindings


def verify_linux_aliases(config, originals):
    require(linux_alias_bindings(config) == originals, "linux_alias_changed")


def checked_include_path(text, cwd, config):
    """Depfile-only parent hops walk real components before changing parents."""
    require(type(text) is str and not any(char in text for char in ["\x00", "\n", "\r"])
            and not text.startswith("//") and not secret_path(text), "unsafe_include_path")
    current = Path("/") if os.path.isabs(text) else absolute(cwd)
    # Preserve empty and dot components. The VFS requires a directory before
    # a trailing slash/dot; Path.parts would silently erase that requirement.
    parts = text.split("/")
    if os.path.isabs(text):
        parts = parts[1:]
    for index, part in enumerate(parts):
        if part == "..":
            require(current != Path("/"), "include_root_escape")
            with HeldPath(current, directory=True, metadata_only=True) as directory:
                directory.verify(content=False)
            current = current.parent
        elif part in {"", "."}:
            with HeldPath(current, directory=True, metadata_only=True) as directory:
                directory.verify(content=False)
        else:
            current = declared_path(current/part, config)
            if index != len(parts) - 1:
                with HeldPath(current, directory=True, metadata_only=True) as directory:
                    directory.verify(content=False)
    require(any(current.is_relative_to(Path(scope["root"])) for scope in config["scopes"])
            or any(current.is_relative_to(Path(root)) for root in config["write_roots"]), "include_outside_declared_scope")
    with HeldPath(current) as regular:
        regular.verify()
    return current


def _collect_linux_scope_members(config, campaign):
    """Retain a finite allowed regular-byte scope, never an observed-read trace."""
    inventories = []
    originals = {}
    readonly = {}
    references = []
    writes = [Path(path) for path in config["write_roots"]]
    protected = [Path(config[key]) for key in ["records", "evidence"]]
    aliases = {item["path"]: item for item in config["aliases"]}
    for scope in config["scopes"]:
        root = Path(scope["root"])
        members = []
        directories = []

        def member(path):
            relative = str(path.relative_to(root))
            if any(path.is_relative_to(namespace) for namespace in protected):
                members.append({"path": relative, "kind": "trusted-recorder-namespace"})
                return
            if secret_path(relative):
                members.append({"path": relative, "kind": "excluded", "reason": "secret-shaped-original"})
                return
            if any(path.is_relative_to(write) for write in writes):
                members.append({"path": relative, "kind": "campaign-produced-namespace"})
                return
            with HeldPath(path.parent, directory=True) as parent:
                info = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    require(str(path) in aliases, "undeclared_linux_alias")
                    alias = aliases[str(path)]
                    resolved = declared_path(path, config)
                    members.append({"path": relative, "kind": "link", "text": alias["text"], "target": str(resolved)})
                elif stat.S_ISDIR(info.st_mode):
                    require(scope["selection"] == "complete-tree", "linux_directory_member")
                    walk(path)
                else:
                    require(stat.S_ISREG(info.st_mode), "linux_nonregular_scope_member")
                    image, original = capture(path, "conservative-read-scope", campaign)
                    with HeldPath(path) as held:
                        metadata = os.fstat(held.fd)
                        require(held.binding()[0] == original[0], "linux_scope_changed")
                        held.verify()
                    entry = {"path": relative, "kind": "regular", "sha256": image["sha256"], "size": image["size"],
                             "mode": stat.S_IMODE(metadata.st_mode), "artifact": image["artifact"]}
                    members.append(entry)
                    originals[str(path)] = original
                    readonly[str(path)] = {"role": scope["role"], **image}
                parent.verify(content=False)
            require(len(members) <= MAX_RECORDS, "linux_scope_count")

        def walk(path):
            with HeldPath(path, directory=True) as directory:
                names = sorted(os.listdir(directory.fd))
                normalized = [unicodedata.normalize("NFC", name).casefold() for name in names]
                require(len(normalized) == len(set(normalized)), "linux_scope_name_collision")
                require(all(unicodedata.normalize("NFC", name) == name for name in names), "linux_scope_noncanonical_name")
                directories.append(str(path.relative_to(root)))
                for name in names:
                    if name in {".git", "__pycache__"}:
                        members.append({"path": str((path/name).relative_to(root)), "kind": "excluded", "reason": "discovery-metadata"})
                    else:
                        member(path/name)
                require(names == sorted(os.listdir(directory.fd)), "linux_scope_directory_changed")
                directory.verify(content=False)

        if scope["selection"] == "complete-tree":
            walk(root)
        else:
            for name in sorted(scope["members"]):
                member(root/name)
        directory_metadata = []
        if scope["selection"] == "explicit-members":
            # Import discovery needs READ_DIR on containing directories. Derive
            # this finite metadata set only from approved regular byte leaves.
            # READ_DIR supplies no regular-file read or execute authority.
            directories = sorted({str(Path(entry["path"]).parent) for entry in members if entry["kind"] == "regular"})
            require(len(directories) + len(members) <= MAX_RECORDS, "linux_scope_count")
            for name in directories:
                path = root/name
                with HeldPath(path, directory=True, metadata_only=True) as held:
                    directory_metadata.append({"path": name, "identity": list(held.initial[:3])})
                    originals[str(path)] = held.binding()
                    held.verify(content=False)
        inventory = {"schema": "chio.compilation-read-scope.v2" if directory_metadata else "chio.compilation-read-scope.v1",
                     "role": scope["role"], "root": str(root),
                     "selection": scope["selection"], "directories": sorted(directories), "members": sorted(members, key=lambda value: value["path"])}
        if directory_metadata:
            inventory["directory_metadata"] = directory_metadata
        payload = canonical(inventory) + b"\n"
        require(len(payload) <= MAX_JSON, "linux_inventory_limit")
        retained = campaign.retain(payload)
        inventories.append(inventory)
        references.append({"role": scope["role"], "root": str(root), "coverage": "conservative-read-scope",
                           "inventory": {"path": retained["artifact"], **retained}})
    directories = {str(Path(inventory["root"])/name) for inventory in inventories for name in inventory["directories"]}
    for inventory in inventories:
        for member in inventory["members"]:
            if member["kind"] == "link":
                require(member["target"] in readonly or member["target"] in directories, "linux_alias_target_not_inventoried")
    images = {}
    for kind, expected in config["images"].items():
        path = str(declared_path(expected["path"], config))
        require(path in readonly and readonly[path]["sha256"] == expected["sha256"], "linux_image_binding")
        images[kind] = {key: readonly[path][key] for key in ["path", "sha256", "size", "artifact"]}
    origins = {}
    origin_values = {}
    for kind in ["runtime_inventory", "source_origin"]:
        expected = config[kind]
        path = absolute(expected["path"], config["package_root"])
        image, original = capture(path, kind, campaign)
        require(image["sha256"] == expected["sha256"], "linux_origin_binding")
        originals[str(path)] = original
        origins[kind] = {"path": expected["path"], "sha256": image["sha256"], "size": image["size"], "artifact": image["artifact"]}
        with HeldPath(path) as origin:
            origin_values[kind] = json.loads(origin.read(MAX_JSON))
    if config.get("public_arguments"):
        bind_public_arguments(config, origin_values["runtime_inventory"], readonly)
    targets = []
    for target in config.get("supported_targets", []):
        libraries = [image for path, image in sorted(readonly.items()) if Path(path).is_relative_to(Path(target["library_root"]))]
        require(libraries and all(path in readonly for path in target["crt_members"]), "linux_target_inventory")
        image_reference = lambda image: {key: image[key] for key in ["path", "sha256", "size", "artifact"]}
        retained_target = {"triple": target["triple"], "sysroot": target["sysroot"], "library_root": target["library_root"],
                        "crt_members": [image_reference(readonly[path]) for path in target["crt_members"]],
                        "libraries": [image_reference(image) for image in libraries]}
        if "linker_selection" in config:
            entry = next(entry for entry in config["linker_selection"]["targets"] if entry["triple"] == target["triple"])
            driver_path = str(declared_path(entry["driver"]["path"], config))
            require(driver_path in readonly and readonly[driver_path]["sha256"] == entry["driver"]["sha256"], "linux_linker_driver_binding")
            retained_target["linker_driver"] = image_reference(readonly[driver_path])
        targets.append(retained_target)
    alias_chains = linux_alias_chains(config)
    scope_binding = {"configuration": config, "inventories": inventories}
    if alias_chains:
        scope_binding["alias_chains"] = alias_chains
    scope_id = digest(scope_binding)
    configuration = campaign.retain(canonical(config) + b"\n")
    declaration = {"schema": "chio.linux-compilation-scope-declaration.v2", "source_binding": config["source_binding"],
        "scope_id": scope_id, "candidate": config["candidate"], "profile": config["profile"], "scopes": references,
        **origins, "policy": {"configuration": configuration, "launcher": images["recorder"],
            "implementation": "outside-supervisor-landlock-regular-leaves-seccomp-v2", "minimum_landlock_abi": 3,
            "write_roots": config["write_roots"], "environment_metadata": config["environment_metadata"],
            "protected_namespaces": [config["records"], config["evidence"]],
            "publication_authority": "outside-supervisor-actual-dispatch-original-namespace",
            "descendant_completion": "subreaper-wait-all-no-process-group-escape",
            "path_metadata": "stat-readlink-access-unrestricted; no regular-byte or observed-read claim",
            "descriptor_inheritance": "cargo-predeclared-anonymous-pipes; compiler-stdin-null-stdout-stderr-nonsocket-close-above-two"},
        "images": images, "targets": targets, "environment": config["environment"], "generated_attribution": "campaign-produced"}
    if alias_chains:
        declaration["alias_chains"] = alias_chains
    return declaration, originals


def validate_retention_outcome(outcome, physical_reference):
    """Typed composition only; an outside actual execution is still required."""
    require(type(outcome) is dict and set(outcome) == {"schema", "source_binding", "batch_id", "start", "complete",
            "physical_status", "durability", "declaration_emitted"}
            and outcome["schema"] == "chio.compiler-retention-batch-outcome.v1"
            and outcome["physical_status"] == "complete" and outcome["declaration_emitted"] is False,
            "retention_outcome_binding")
    require({key: outcome[key] for key in ["source_binding", "batch_id", "start", "complete"]} == physical_reference,
            "retention_outcome_binding")
    durability = outcome["durability"]
    require(type(durability) is dict and set(durability) == {"status", "phase", "errno"}
            and durability["phase"] == "completion-directory-fsync"
            and durability["status"] in {"confirmed", "unconfirmed"}
            and (durability["errno"] is None or type(durability["errno"]) is int and durability["errno"] >= 0)
            and (durability["status"] != "confirmed" or durability["errno"] is None), "retention_outcome_binding")
    return durability["status"]


def collect_linux_scope(config, campaign):
    """No declaration escapes an active, failed or durability-unconfirmed batch."""
    with campaign.retention_batch():
        declaration, originals = _collect_linux_scope_members(config, campaign)
    campaign.require_retention_writable()
    outcome = campaign.retention_outcomes[-1]
    physical = {key: outcome[key] for key in ["batch_id", "source_binding", "start", "complete"]}
    require(physical in campaign.validate_retention_batches()
            and validate_retention_outcome(outcome, physical) == "confirmed", "retention_batch_durability_unconfirmed")
    declaration["retention_batch"] = {key: outcome[key] for key in ["batch_id", "source_binding", "start", "complete"]}
    declaration["retention_outcome_sha256"] = digest(outcome)
    return declaration, originals


class LinuxRuleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class LinuxPathRule(ctypes.Structure):
    _layout_ = "ms"
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class LinuxFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class LinuxFilterProgram(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint16), ("filter", ctypes.POINTER(LinuxFilter))]


def linux_abi():
    require((platform.system(), platform.machine()) == ("Linux", "x86_64"), "linux_gnu_platform_required")
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    abi = library.syscall(444, None, 0, 1)
    require(abi >= 3, "landlock_abi_required")
    return library, abi


def enforce_linux_scope(config, declaration, originals, campaign, machine, unit_writes=None):
    """Install actual kernel restrictions in the single-threaded launch child."""
    verify_linux_aliases(config, campaign.aliases)
    library, abi = linux_abi()
    rights = (1 << 15) - 1
    if abi >= 5:
        rights |= 1 << 15
    attributes = LinuxRuleset(rights)
    ruleset = library.syscall(444, ctypes.byref(attributes), ctypes.sizeof(attributes), 0)
    require(ruleset >= 0, "landlock_create_failed")
    try:
        def rule(descriptor, allowed):
            entry = LinuxPathRule(allowed, descriptor)
            require(library.syscall(445, ruleset, 1, ctypes.byref(entry), 0) == 0, "landlock_rule_failed")

        for scope in declaration["scopes"]:
            reference = scope["inventory"]
            with HeldPath(campaign.root / reference["artifact"]) as inventory_file:
                payload = inventory_file.read(MAX_JSON)
                require(hashlib.sha256(payload).hexdigest() == reference["sha256"] and len(payload) == reference["size"], "linux_inventory_changed")
            inventory = json.loads(payload)
            root = Path(inventory["root"])
            directory_metadata = {entry["path"]: entry["identity"] for entry in inventory.get("directory_metadata", [])}
            for name in inventory["directories"]:
                with HeldPath(root/name, directory=True, metadata_only=True) as directory:
                    if inventory["schema"] == "chio.compilation-read-scope.v2":
                        require(list(directory.initial[:3]) == directory_metadata.get(name)
                                and directory.initial[:3] == originals[str(root/name)][0][:3], "linux_scope_changed")
                    rule(directory.fd, 1 << 3)
            for member in inventory["members"]:
                if member["kind"] != "regular":
                    continue
                path = root/member["path"]
                with HeldPath(path) as held:
                    require(held.binding()[0] == originals[str(path)][0], "linux_scope_changed")
                    image = held.read()
                    require(hashlib.sha256(image).hexdigest() == member["sha256"] and len(image) == member["size"], "linux_scope_changed")
                    rule(held.fd, (1 << 2) | (1 if member["mode"] & 0o111 else 0))
        # Writable bytes have separate campaign attribution, not readonly input
        # authority. Device, socket and block-node creation remain denied.
        writable = sum(1 << bit for bit in [0, 1, 2, 3, 4, 5, 7, 8, 10, 12, 13, 14])
        for path in config["write_roots"]:
            with HeldPath(path, directory=True) as directory:
                rule(directory.fd, writable if unit_writes is None else sum(1 << bit for bit in [0, 2, 3]))
        if unit_writes is not None:
            for path in unit_writes:
                require(any(Path(path).is_relative_to(Path(root)) for root in config["write_roots"]), "native_unit_write_scope")
                with HeldPath(path, directory=True) as directory:
                    rule(directory.fd, writable)
        for entry in config["environment_metadata"]:
            path = Path(entry["path"])
            with HeldPath(path.parent, directory=True, metadata_only=True) as parent:
                descriptor = os.open(path.name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent.fd)
                try:
                    value = os.fstat(descriptor)
                    require(stat.S_ISCHR(value.st_mode) if entry["kind"] == "character-device" else stat.S_ISREG(value.st_mode), "linux_metadata_changed")
                    rule(descriptor, (1 << 2) | ((1 << 1) | (1 << 14) if entry["path"] == "/dev/null" else 0))
                finally:
                    os.close(descriptor)
        require(library.prctl(38, 1, 0, 0, 0) == 0, "no_new_privileges_failed")
        require(library.syscall(446, ruleset, 0) == 0, "landlock_restrict_failed")
    finally:
        os.close(ruleset)
    _, _, instructions = linux_network_filter(machine)
    filters = (LinuxFilter * len(instructions))(*(LinuxFilter(*instruction) for instruction in instructions))
    program = LinuxFilterProgram(len(instructions), filters)
    require(library.prctl(22, 2, ctypes.byref(program), 0, 0) == 0, "seccomp_filter_failed")


def generated_inventory(config, campaign, original_inputs=False):
    """Campaign output snapshots give no individual writer attribution."""
    members = []
    excluded = [Path(config[key]) for key in ["records", "evidence"]]
    for root in map(Path, config["write_roots"]):
        def walk(path):
            if any(path.is_relative_to(item) for item in excluded):
                members.append({"path": str(path), "kind": "recorder-instrumentation-namespace"})
                return
            if secret_path(path):
                members.append({"path": str(path), "kind": "excluded", "reason": "secret-shaped-original"})
                require(not original_inputs, "secret_in_existing_write_scope")
                return
            with HeldPath(path, directory=True) as directory:
                names = sorted(os.listdir(directory.fd))
                for name in names:
                    child = path/name
                    if any(child.is_relative_to(item) for item in excluded):
                        members.append({"path": str(child), "kind": "recorder-instrumentation-namespace"})
                        continue
                    if secret_path(child):
                        members.append({"path": str(child), "kind": "excluded", "reason": "secret-shaped-original"})
                        require(not original_inputs, "secret_in_existing_write_scope")
                        continue
                    info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        walk(child)
                    elif stat.S_ISREG(info.st_mode):
                        image, _ = capture(child, "campaign-produced", campaign)
                        members.append(image)
                    else:
                        # Symlink/FIFO/socket outputs cannot become an invented
                        # regular-byte generated source or writer edge.
                        members.append({"path": str(child), "kind": "nonregular-campaign-output", "mode": info.st_mode})
                require(names == sorted(os.listdir(directory.fd)), "generated_namespace_changed")
                directory.verify(content=False)
            require(len(members) <= MAX_RECORDS, "generated_count_limit")
        walk(root)
    return {"schema": "chio.campaign-produced-inputs.v1", "attribution": "campaign-produced", "members": sorted(members, key=lambda item: item["path"]),
            "individual_writer_authority": "not-established", "transient_output_coverage": "not-established"}


def written_bytes(handle):
    """Read an owned output FD after its writer exits, with a new stable bracket."""
    handle.verify(content=False)
    before = os.fstat(handle.fd)
    require(before.st_size <= MAX_INPUT, "input_limit")
    os.lseek(handle.fd, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while total <= MAX_INPUT:
        block = os.read(handle.fd, min(1024*1024, MAX_INPUT+1-total))
        if not block:
            break
        total += len(block)
        chunks.append(block)
    require(total == before.st_size and identity(before) == identity(os.fstat(handle.fd)), "written_output_changed")
    handle.verify(content=False)
    return b"".join(chunks)


def validate_native_child_environment(environment, config, declaration):
    """Cargo-created loader state is allowed only by an exact prior declaration."""
    require(not any(SECRET_WORD.search(name) or "proxy" in name.casefold()
                    or name.startswith("DYLD_") or (name.startswith("LD_") and name != "LD_LIBRARY_PATH")
                    or linux_selector(name) and name not in {"RUSTC", "RUSTC_WRAPPER", "RUSTC_LINKER", "CARGO_ENCODED_RUSTFLAGS"}
                    for name in environment), "native_hidden_environment")
    require(environment.get("RUSTC") == declaration["images"]["rustc"]["path"]
            and environment.get("RUSTC_WRAPPER") == declaration["images"]["recorder"]["path"], "native_selector_binding")
    require(environment.get("CARGO_ENCODED_RUSTFLAGS", "") == "", "native_hidden_environment")
    if "LD_LIBRARY_PATH" in environment:
        paths = environment["LD_LIBRARY_PATH"].split(os.pathsep)
        require(all(path and str(absolute(path)) == path and path in config.get("loader_paths", []) for path in paths), "native_loader_paths")
    if "RUSTC_LINKER" in environment:
        linkers = {declaration["images"]["linker"]["path"]}
        linkers.update(entry["linker_driver"]["path"] for entry in declaration.get("targets", []) if "linker_driver" in entry)
        linkers.update(entry["driver"]["path"] for entry in config.get("linker_selection", {}).get("targets", []))
        require(environment["RUSTC_LINKER"] in linkers, "native_linker_environment")


def producing_unit(campaign, image, required_crate=None, source_reference=None):
    """Join an already completed original-namespace unit, not its filename."""
    require(required_crate != "chio_credentials" or source_reference is not None, "producer_public_source_binding")
    for name in sorted(os.listdir(campaign.records.fd)):
        require(re.fullmatch(r"[0-9a-f]{32}\.json", name), "producer_record_namespace")
        with HeldPath(campaign.records.path/name) as record:
            payload = record.read(MAX_JSON)
            record_identity = descriptor_identity(record)
        row = json.loads(payload)
        if (row.get("schema") != SCHEMA or row.get("source_binding") != campaign.binding or row.get("kind") != "compilation"
                or row.get("status") != "success" or row.get("compiler_exit") != 0):
            continue
        if required_crate is not None and row.get("semantics", {}).get("crate_name") != required_crate:
            continue
        if source_reference is not None:
            if (row.get("semantics", {}).get("source") != source_reference["path"]
                    or not any(item["role"] == "source" and item["path"] == source_reference["path"]
                               and item["sha256"] == source_reference["sha256"] for item in row["inputs"])):
                continue
        outputs = [item for item in row["outputs"] if item["role"] == "unit" and
                   all(item.get(key) == image.get(key) for key in ["path", "sha256", "size", "artifact"])]
        if not outputs:
            continue
        marker_name = "completions/" + name
        with HeldPath(campaign.completions.path/name) as completion:
            marker_bytes = completion.read(MAX_JSON)
            marker_identity = descriptor_identity(completion)
        marker = json.loads(marker_bytes)
        require(row["invocation_id"] + ".json" == name
                and row["publication"] == {"completion": marker_name, "marker_identity": marker_identity}
                and marker == {"schema": COMPLETION_SCHEMA, "invocation_id": row["invocation_id"], "source_binding": campaign.binding,
                               "record_sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "record_identity": record_identity}, "producer_completion_binding")
        edge = {"invocation_id": row["invocation_id"],
                "record": {"path": "records/" + name, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)},
                "completion": {"path": marker_name, "sha256": hashlib.sha256(marker_bytes).hexdigest(), "size": len(marker_bytes)}}
        if source_reference is not None:
            edge["source"] = source_reference
        return edge
    raise Refusal("extern_producing_unit_not_completed")


def load_native_scope(environment, campaign):
    path = environment.get("CHIO_COMPILATION_SCOPE_DECLARATION")
    scope_id = environment.get("CHIO_COMPILATION_SCOPE_ID")
    if path is None and scope_id is None:
        return None, None, {}
    require(path is not None and scope_id is not None and DIGEST.fullmatch(scope_id), "native_scope_configuration")
    require((platform.system(), platform.machine()) == ("Linux", "x86_64"), "linux_gnu_platform_required")
    with HeldPath(path) as file:
        declaration_bytes = file.read(MAX_JSON)
    declaration = json.loads(declaration_bytes)
    require(declaration["schema"] == "chio.linux-compilation-scope-declaration.v2"
            and declaration["source_binding"] == campaign.binding and declaration["scope_id"] == scope_id, "native_scope_binding")
    require(type(declaration.get("retention_batch")) is dict
            and declaration["retention_batch"] in campaign.validate_retention_batches()
            and type(declaration.get("retention_outcome_sha256")) is str
            and DIGEST.fullmatch(declaration["retention_outcome_sha256"]), "native_retention_batch_binding")
    reference = declaration["policy"]["configuration"]
    require(re.fullmatch(r"artifacts/[0-9a-f]{64}", reference["artifact"]), "native_configuration_artifact")
    with HeldPath(campaign.directory.path/reference["artifact"]) as file:
        payload = file.read(MAX_JSON)
    require(hashlib.sha256(payload).hexdigest() == reference["sha256"] and len(payload) == reference["size"], "native_configuration_artifact")
    config = validate_linux_configuration(json.loads(payload), {})
    require(Path(path).is_relative_to(Path(config["evidence"]))
            and config["candidate"] == environment["CHIO_COMPILATION_SOURCE_ROOT"]
            and config["records"] == environment["CHIO_COMPILATION_RECORDS"]
            and config["source_binding"] == campaign.binding and config["profile"] == declaration["profile"], "native_configuration_binding")
    validate_native_child_environment(environment, config, declaration)
    require(all(environment.get(key) == value for key, value in config["environment"].items()), "compilation_request_profile")
    with HeldPath(Path(__file__).absolute()) as file:
        require(hashlib.sha256(file.read()).hexdigest() == declaration["images"]["recorder"]["sha256"], "native_recorder_binding")
    inventories = []
    regular = {}
    for scope in declaration["scopes"]:
        reference = scope["inventory"]
        require(re.fullmatch(r"artifacts/[0-9a-f]{64}", reference["artifact"]), "native_inventory_artifact")
        with HeldPath(campaign.directory.path/reference["artifact"]) as file:
            payload = file.read(MAX_JSON)
        require(hashlib.sha256(payload).hexdigest() == reference["sha256"] and len(payload) == reference["size"], "native_inventory_artifact")
        inventory = json.loads(payload)
        inventories.append(inventory)
        for member in inventory["members"]:
            if member["kind"] == "regular":
                regular[str(Path(inventory["root"])/member["path"])] = member
    scope_binding = {"configuration": config, "inventories": inventories}
    alias_chains = linux_alias_chains(config)
    if alias_chains:
        require(declaration.get("alias_chains") == alias_chains, "native_alias_chain_binding")
        scope_binding["alias_chains"] = alias_chains
    else:
        require("alias_chains" not in declaration, "native_alias_chain_binding")
    require(digest(scope_binding) == scope_id, "native_scope_id")
    if config.get("public_arguments"):
        reference = declaration["runtime_inventory"]
        with HeldPath(campaign.directory.path/reference["artifact"]) as source_inventory:
            payload = source_inventory.read(MAX_JSON)
        require(hashlib.sha256(payload).hexdigest() == reference["sha256"] and len(payload) == reference["size"], "public_argument_inventory")
        config = bind_public_arguments(config, json.loads(payload), regular)
    if "linker_selection" in config:
        config = {**config, "_target_linker_images": {entry["triple"]: entry["linker_driver"] for entry in declaration["targets"]}}
    record_image = campaign.retain(declaration_bytes)
    native_reference = {"scope_id": scope_id, "scope_record": {"path": str(absolute(path)), **record_image},
        "retention_batch": declaration["retention_batch"], "retention_outcome_sha256": declaration["retention_outcome_sha256"],
        "coverage": "conservative-read-scope", "platform": "linux-gnu", "linker": declaration["images"]["linker"],
        "input_attribution": "direct-source-and-extern-plus-conservative-allowed-scope", "generated_attribution": "campaign-produced"}
    return config, native_reference, regular


def native_target_context_from_parsed(config, parsed):
    target = parsed.get("target") or "x86_64-unknown-linux-gnu"
    supported = {item["triple"] for item in config.get("supported_targets", [])} or {"x86_64-unknown-linux-gnu"}
    require(target in supported, "unsupported_native_target")
    context = dict(config)
    if "linker_selection" in config:
        selected = next((entry for entry in config["linker_selection"]["targets"] if entry["triple"] == target), None)
        require(selected is not None, "native_linker_target_not_declared")
        context["images"] = {**config["images"], "linker": selected["driver"]}
    return context, target


def native_target_context(config, arguments, cwd=None):
    """Use the closed parser's option consumption, never scan argument values."""
    parsed = parse(arguments, Path(config["candidate"]) if cwd is None else cwd, config)
    return native_target_context_from_parsed(config, parsed)


def select_compiler_dispatch(raw, cwd, config, declaration):
    """Only the parent selects a declared target driver, after validating raw flags."""
    require(raw and raw[0] == declaration["images"]["rustc"]["path"], "compilation_request_program")
    parsed = parse(raw[1:], cwd, config)
    context, target = native_target_context_from_parsed(config, parsed)
    linking = parsed["kind"] == "compilation" and "link" in parsed["emit"] and any(
        kind in {"bin", "proc-macro", "cdylib", "dylib"} for kind in parsed["crate_types"])
    effective = list(raw)
    driver = None
    if linking:
        if not parsed.get("explicit_linker"):
            require("linker_selection" in config, "native_linker_selection_not_bound")
            effective += ["-C", "linker="+context["images"]["linker"]["path"]]
            reason = "missing-linker-declared-driver-opt-in"
        else:
            reason = "matching-explicit-linker"
        if "linker_selection" in config:
            target_entry = next((entry for entry in declaration["targets"] if entry["triple"] == target), None)
            require(target_entry is not None and "linker_driver" in target_entry, "native_linker_target_binding")
            driver = target_entry["linker_driver"]
        else:
            driver = declaration["images"]["linker"]
        expected = context["images"]["linker"]
        require(driver["path"] == str(declared_path(expected["path"], context))
                and driver["sha256"] == expected["sha256"], "native_linker_target_binding")
        with HeldPath(driver["path"]) as held:
            require(hashlib.sha256(held.read()).hexdigest() == driver["sha256"], "native_linker_driver_changed")
    else:
        reason = "probe-unchanged" if parsed["kind"] == "probe" else "not-linking-unit"
    return {"raw_wrapper_argv": [declaration["images"]["recorder"]["path"], *raw], "raw_compiler_argv": list(raw),
            "effective_argv": effective, "raw_wrapper_sha256": digest([declaration["images"]["recorder"]["path"], *raw]),
            "raw_compiler_sha256": digest(raw), "effective_invocation_sha256": digest(effective),
            "reason": reason, "target": target, "driver": driver,
            "profile": config.get("linker_selection", {}).get("profile")}


def retain_compiler_dispatch(campaign, selection):
    return {"raw_wrapper_argv": campaign.retain(canonical(selection["raw_wrapper_argv"]) + b"\n"),
            "effective_argv": campaign.retain(canonical(selection["effective_argv"]) + b"\n"),
            **{key: selection[key] for key in ["raw_wrapper_sha256", "raw_compiler_sha256", "effective_invocation_sha256",
                                               "reason", "target", "driver", "profile"]}}


def validate_compilation_request(request, config, declaration):
    """A pipe description supplies compiler arguments, never publication authority."""
    require(type(request) is dict and set(request) == {"schema", "id", "argv", "environment", "cwd"}
            and request["schema"] == "chio.rust-compilation-request.v1"
            and type(request["id"]) is str and re.fullmatch(r"[0-9a-f]{32}", request["id"]), "compilation_request")
    require(type(request["argv"]) is list and 1 <= len(request["argv"]) <= 8192
            and all(type(arg) is str and "\x00" not in arg for arg in request["argv"])
            and request["argv"][0] == declaration["images"]["rustc"]["path"], "compilation_request_program")
    environment = request["environment"]
    require(type(environment) is dict and all(type(key) is str and type(value) is str and "\x00" not in key + value
            for key, value in environment.items()), "compilation_request_environment")
    require("CHIO_COMPILATION_IPC" not in environment, "compilation_request_environment")
    validate_native_child_environment(environment, config, declaration)
    require(all(environment.get(key) == value for key, value in config["environment"].items()), "compilation_request_profile")
    cwd = absolute(request["cwd"])
    require(str(cwd) == request["cwd"] and cwd.is_relative_to(Path(config["candidate"]))
            and not any(cwd.is_relative_to(Path(config[key])) for key in ["records", "evidence"]), "compilation_request_cwd")
    return request


def pipe_bytes(descriptor, count):
    result = bytearray()
    while len(result) < count:
        payload = os.read(descriptor, count-len(result))
        require(payload, "compilation_ipc_eof")
        result.extend(payload)
    return bytes(result)


def pipe_write(descriptor, payload):
    while payload:
        written = os.write(descriptor, payload)
        require(written > 0, "compilation_ipc_write")
        payload = payload[written:]


def compilation_client(argv):
    """Only anonymous inherited pipe endpoints cross the descendant boundary."""
    slot = None
    table = None
    try:
        table = json.loads(os.environ["CHIO_COMPILATION_IPC"])
        require(type(table) is dict and set(table) == {"schema", "lease", "channels"}
                and table["schema"] == "chio.rust-compilation-pipes.v1"
                and type(table["lease"]) is list and len(table["lease"]) == 2
                and type(table["channels"]) is list and 1 <= len(table["channels"]) <= 16
                and all(type(pair) is list and len(pair) == 2 for pair in table["channels"]), "compilation_ipc_table")
        descriptors = table["lease"] + [fd for pair in table["channels"] for fd in pair]
        require(len(set(descriptors)) == len(descriptors) and all(type(fd) is int and fd > 2
                and stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in descriptors), "compilation_ipc_descriptors")
        slot = pipe_bytes(table["lease"][0], 1)
        require(slot[0] < len(table["channels"]), "compilation_ipc_slot")
        send, receive = table["channels"][slot[0]]
        environment = dict(os.environ)
        del environment["CHIO_COMPILATION_IPC"]
        identifier = uuid.uuid4().hex
        request = canonical({"schema": "chio.rust-compilation-request.v1", "id": identifier,
                             "argv": argv, "environment": environment, "cwd": os.getcwd()})
        require(len(request) <= MAX_JSON, "compilation_ipc_limit")
        pipe_write(send, struct.pack(">I", len(request)) + request)
        size = struct.unpack(">I", pipe_bytes(receive, 4))[0]
        require(size <= MAX_JSON, "compilation_ipc_limit")
        response = json.loads(pipe_bytes(receive, size))
        require(set(response) == {"schema", "id", "exit", "stdout"}
                and response["schema"] == "chio.rust-compilation-response.v1" and response["id"] == identifier
                and type(response["exit"]) is int and 0 <= response["exit"] <= 255, "compilation_ipc_response")
        output = base64.b64decode(response["stdout"], validate=True)
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        return response["exit"]
    except (Refusal, OSError, ValueError, KeyError, TypeError) as error:
        print("compilation_recorder." + (str(error) if isinstance(error, Refusal) else "compilation_ipc_format"), file=sys.stderr)
        return 86
    finally:
        if slot is not None and table is not None:
            pipe_write(table["lease"][1], slot)


def native_process_identity(pid):
    """Read a bounded kernel parent/start identity, without caller text."""
    require(platform.system() == "Linux" and type(pid) is int and pid > 0,
            "compiler_cleanup_unsupported")
    try:
        with open(Path("/proc") / str(pid) / "stat", "rb") as stream:
            raw = stream.read(65537)
    except FileNotFoundError:
        return None
    require(0 < len(raw) <= 65536, "compiler_cleanup_process_identity")
    fields = raw.rsplit(b")", 1)[-1].split()
    require(len(fields) >= 20 and all(fields[index].isdigit() for index in [1, 2, 3, 19]),
            "compiler_cleanup_process_identity")
    return tuple(int(fields[index]) for index in [1, 2, 3, 19])


def native_scope_owner_identity():
    """Require this existing Linux task subreaper and pidfd support."""
    require(platform.system() == "Linux" and hasattr(os, "pidfd_open")
            and hasattr(signal, "pidfd_send_signal"), "compiler_cleanup_unsupported")
    subreaper = ctypes.c_int()
    library = ctypes.CDLL(None, use_errno=True)
    require(library.prctl(37, ctypes.byref(subreaper), 0, 0, 0) == 0 and subreaper.value == 1,
            "compiler_cleanup_subreaper")
    identity = native_process_identity(os.getpid())
    require(identity is not None, "compiler_cleanup_scope_identity")
    return identity


def _stop_owned_scope_children(scope_identity, processes, deadline):
    """Drain only this dedicated kernel subreaper's children via held pidfds.

    Killing a direct child reparents its remaining descendants to this same
    subreaper. Repeated kernel parent checks therefore cover orphan pipe holders
    without creating a process group or trusting a reported descendant PID.
    """
    parent = os.getpid()
    require(scope_identity is not None and native_scope_owner_identity() == scope_identity,
            "compiler_cleanup_scope_identity")
    reaped = []
    while True:
        children = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            identity = native_process_identity(int(entry.name))
            if identity is not None and identity[0] == parent:
                children.append((int(entry.name), identity))
        require(native_process_identity(parent) == scope_identity, "compiler_cleanup_scope_identity")
        if not children:
            return {"status": "REAPED", "scope_pid": parent, "scope_start_identity": scope_identity[3],
                    "process_groups_changed": False, "children": reaped}
        require(time.monotonic() < deadline, "compiler_cleanup_deadline")
        for pid, identity in children:
            descriptor = os.pidfd_open(pid, 0)
            try:
                require(native_process_identity(pid) == identity and identity[0] == parent,
                        "compiler_cleanup_process_identity")
                signal.pidfd_send_signal(descriptor, signal.SIGSTOP)
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                with selectors.DefaultSelector() as ready:
                    ready.register(descriptor, selectors.EVENT_READ)
                    require(bool(ready.select(max(0, deadline - time.monotonic()))),
                            "compiler_cleanup_deadline")
                actual_pid, status = os.waitpid(pid, 0)
                require(actual_pid == pid, "compiler_cleanup_wait")
                code = os.waitstatus_to_exitcode(status)
                for process in processes:
                    if process is not None and process.pid == pid:
                        process.returncode = code
                reaped.append({"pid": pid, "process_start_identity": identity[3], "wait_status": status})
            finally:
                os.close(descriptor)


def stop_owned_scope_children(scope_identity, processes, deadline):
    """An unconfirmed kill, wait or kernel identity is a typed refusal."""
    try:
        return _stop_owned_scope_children(scope_identity, processes, deadline)
    except OSError as error:
        raise Refusal("compiler_cleanup_io") from error


def bounded_compiler_output(argv, environment, cwd, preexec_fn, cleanup):
    """Drain both anonymous streams within one finite execution/cleanup budget."""
    require(type(MAX_NATIVE_COMPILER_OUTPUT) is int and 0 < MAX_NATIVE_COMPILER_OUTPUT <= 16 * 1024**2
            and type(NATIVE_COMPILER_DISPATCH_SECONDS) in {int, float}
            and 0 < NATIVE_COMPILER_CLEANUP_RESERVE_SECONDS < NATIVE_COMPILER_DISPATCH_SECONDS <= 180,
            "compiler_output_policy")
    started = time.monotonic()
    deadline = started + NATIVE_COMPILER_DISPATCH_SECONDS
    process = subprocess.Popen(argv, env=environment, cwd=cwd, close_fds=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=preexec_fn)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    observed = {"stdout": 0, "stderr": 0}
    eof = {"stdout": False, "stderr": False}
    refusal = None
    cleanup_record = None
    try:
        with selectors.DefaultSelector() as ready:
            for name in buffers:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                ready.register(stream, selectors.EVENT_READ, name)
            while ready.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= NATIVE_COMPILER_CLEANUP_RESERVE_SECONDS:
                    refusal = "compiler_output_timeout"
                    break
                for key, _ in ready.select(min(0.1, remaining - NATIVE_COMPILER_CLEANUP_RESERVE_SECONDS)):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        eof[key.data] = True
                        ready.unregister(key.fileobj)
                        continue
                    observed[key.data] += len(block)
                    available = MAX_NATIVE_COMPILER_OUTPUT - len(buffers[key.data])
                    buffers[key.data].extend(block[:available])
                    if observed[key.data] > MAX_NATIVE_COMPILER_OUTPUT:
                        refusal = "compiler_output_limit"
                        break
                if refusal is not None:
                    break
        if refusal is not None:
            cleanup_record = cleanup(process, deadline)
            require(type(cleanup_record) is dict and cleanup_record.get("status") == "REAPED"
                    and process.poll() is not None, "compiler_cleanup_unconfirmed")
        else:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        result = subprocess.CompletedProcess(argv, process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
        result.output_observation = {"status": "refused" if refusal else "complete", "refusal": refusal,
            "observed_bytes": observed, "eof": eof, "elapsed_seconds": time.monotonic() - started,
            "cleanup": cleanup_record,
            "policy": {"maximum_bytes_per_stream": MAX_NATIVE_COMPILER_OUTPUT,
                       "execution_and_cleanup_seconds": NATIVE_COMPILER_DISPATCH_SECONDS,
                       "cleanup_reserve_seconds": NATIVE_COMPILER_CLEANUP_RESERVE_SECONDS,
                       "raw_diagnostics_forwarded": False}}
        result.output_deadline = deadline
        return result
    except BaseException:
        # A failed cleanup or custody observation cannot leave a success record.
        cleanup(process, deadline)
        raise
    finally:
        process.stdout.close()
        process.stderr.close()


class CompilationSupervisor:
    """Finite anonymous channels; the outside parent owns execution and evidence."""
    def __init__(self, config, declaration, originals, campaign, fixed_environment):
        self.config, self.declaration, self.originals, self.campaign = config, declaration, originals, campaign
        self.aliases = linux_alias_bindings(config)
        # Transport endpoints are added to the launch environment after this
        # snapshot. They are intentionally absent from compiler requests.
        self.fixed = dict(fixed_environment)
        self.selector = selectors.DefaultSelector()
        self.descriptors, self.channels, self.events = [], [], []
        self.dispatches = []
        self.scope_process = None
        self.scope_identity = None
        self.lease = list(os.pipe())
        self.descriptors.extend(self.lease)
        for index in range(4):
            receive, send = os.pipe()
            client_receive, reply = os.pipe()
            self.descriptors.extend([receive, send, client_receive, reply])
            os.set_blocking(receive, False)
            self.channels.append([send, client_receive])
            self.selector.register(receive, selectors.EVENT_READ, {"buffer": bytearray(), "reply": reply})
            pipe_write(self.lease[1], bytes([index]))
        self.table = {"schema": "chio.rust-compilation-pipes.v1", "lease": self.lease, "channels": self.channels}
        self.pass_fds = tuple(self.lease + [fd for pair in self.channels for fd in pair])

    def execute(self, argv, environment, cwd, probe):
        require(self.scope_identity is not None and native_scope_owner_identity() == self.scope_identity,
                "compiler_cleanup_scope_identity")
        namespace = os.fstat(self.campaign.directory.fd)
        require(stat.S_ISDIR(namespace.st_mode) and stat.S_IMODE(namespace.st_mode) == 0o700
                and namespace.st_uid == os.getuid(), "compiler_output_private_namespace")
        native, _ = native_target_context(self.config, argv[1:], Path(cwd))
        verify_linux_aliases(native, self.aliases)
        writes = []
        if not probe:
            parsed = parse(argv[1:], Path(cwd), native)
            depfile, _ = output_paths(parsed)
            writes.append(str(depfile.parent))
        if environment.get("TMPDIR"):
            writes.append(str(absolute(environment["TMPDIR"])))
        result = bounded_compiler_output(argv, environment, cwd,
            lambda: enforce_linux_scope(native, self.declaration, self.originals, self.campaign,
                                        platform.machine(), writes),
            lambda child, deadline: stop_owned_scope_children(self.scope_identity,
                [self.scope_process, child], deadline))
        output = {"schema": "chio.native-compiler-output.v1", **result.output_observation,
                  "stdout": None, "stderr": None}
        self.dispatches.append({"schema": "chio.native-compiler-dispatch.v2",
            "kind": "compiler-probe" if probe else "compiler-unit",
            "invocation_sha256": digest(argv), "environment_sha256": digest(environment),
            "cwd": cwd, "compiler_exit": result.returncode, "output": output})
        try:
            output["stdout"] = self.campaign.retain(result.stdout)
            output["stderr"] = self.campaign.retain(result.stderr)
        except (Refusal, OSError, ValueError, TypeError, KeyError) as error:
            output.update(status="publication-failed", refusal="compiler_output_publication")
            output["cleanup"] = stop_owned_scope_children(self.scope_identity,
                [self.scope_process], result.output_deadline)
            raise CompilerOutputRefusal("compiler_output_publication", result.returncode) from error
        if result.output_observation["refusal"] is not None:
            raise CompilerOutputRefusal(result.output_observation["refusal"], result.returncode)
        return result

    def respond(self, payload):
        request = json.loads(payload)
        identifier = request.get("id", "") if type(request) is dict else ""
        if type(identifier) is not str or re.fullmatch(r"[0-9a-f]{32}", identifier) is None:
            identifier = ""
        output = []
        refusal = None
        recorder_exit = None
        self.dispatches = []
        records = []
        try:
            validate_compilation_request(request, self.config, self.declaration)
            # Declared scope/environment joins belong to this parent. A client
            # cannot replace them with its own source or publication selector.
            for key, value in self.fixed.items():
                if key.startswith("CHIO_COMPILATION_") or key in {"RUSTC", "RUSTC_WRAPPER"}:
                    require(request["environment"].get(key) == value, "compilation_request_authority")
            require(not any(key.startswith("CHIO_COMPILATION_") and key not in self.fixed
                            for key in request["environment"]), "compilation_request_authority")
            selection = select_compiler_dispatch(request["argv"], Path(request["cwd"]), self.config, self.declaration)
            if request["environment"].get("RUSTC_LINKER") is not None and selection["driver"] is not None:
                context, _ = native_target_context(self.config, request["argv"][1:], Path(request["cwd"]))
                require(request["environment"]["RUSTC_LINKER"] in {selection["driver"]["path"], context["images"]["linker"]["path"]}, "native_linker_environment")
            before = set(os.listdir(self.campaign.records.fd))
            code = main(selection["effective_argv"], request["environment"], request["cwd"], self.execute, output.append, selection)
            recorder_exit = code
            for name in sorted(set(os.listdir(self.campaign.records.fd))-before):
                with HeldPath(self.campaign.records.path/name) as record:
                    row_bytes = record.read(MAX_JSON)
                row = json.loads(row_bytes)
                records.append({"invocation_id": row["invocation_id"], "path": "records/" + name,
                    "sha256": hashlib.sha256(row_bytes).hexdigest(), "size": len(row_bytes)})
        except (Refusal, OSError, ValueError, KeyError, TypeError) as error:
            refusal = str(error) if isinstance(error, Refusal) else "compilation_request_format"
            code = 86
        response = canonical({"schema": "chio.rust-compilation-response.v1", "id": identifier,
                              "exit": code, "stdout": base64.b64encode(b"".join(output)).decode("ascii")})
        response_state = "encoded"
        if len(response) > MAX_JSON:
            code = 86
            refusal = "compilation_response_limit"
            response_state = "refused"
            response = canonical({"schema": "chio.rust-compilation-response.v1", "id": identifier, "exit": code, "stdout": ""})
        require(len(response) <= MAX_JSON, "compilation_response_limit")
        self.events.append({"request_sha256": hashlib.sha256(payload).hexdigest(), "id": identifier,
                            "exit": code, "recorder_exit": recorder_exit, "response": response_state,
                            "refusal": refusal, "dispatches": self.dispatches, "records": records})
        require(len(self.events) <= MAX_RECORDS, "compilation_request_count")
        return response

    def wait(self, process, logs=None):
        if logs is not None:
            for stream, destination in [(process.stdout, logs[0]), (process.stderr, logs[1])]:
                os.set_blocking(stream.fileno(), False)
                self.selector.register(stream.fileno(), selectors.EVENT_READ, {"log": destination, "size": 0})
        while True:
            for key, _ in self.selector.select(timeout=0.1):
                channel = key.data
                data = os.read(key.fd, 65536)
                if "log" in channel:
                    if not data:
                        self.selector.unregister(key.fd)
                        continue
                    channel["size"] += len(data)
                    require(channel["size"] <= MAX_INPUT, "linux_log_limit")
                    write_all(channel["log"].fd, data)
                    continue
                require(data, "compilation_ipc_eof")
                channel["buffer"].extend(data)
                require(len(channel["buffer"]) <= MAX_JSON+4, "compilation_ipc_limit")
                if len(channel["buffer"]) >= 4:
                    size = struct.unpack(">I", channel["buffer"][:4])[0]
                    require(size <= MAX_JSON, "compilation_ipc_limit")
                    if len(channel["buffer"]) >= size+4:
                        require(len(channel["buffer"]) == size+4, "compilation_ipc_frames")
                        response = self.respond(bytes(channel["buffer"][4:]))
                        channel["buffer"].clear()
                        pipe_write(channel["reply"], struct.pack(">I", len(response)) + response)
            if process.poll() is not None:
                if any("log" in key.data for key in self.selector.get_map().values()):
                    continue
                require(not any(key.data["buffer"] for key in self.selector.get_map().values()), "compilation_ipc_incomplete")
                return process.returncode

    def close(self):
        self.selector.close()
        for fd in self.descriptors:
            os.close(fd)


def launch_scope(arguments):
    campaign = None
    supervisor = None
    process = None
    command_exit = None
    evidence_path = None
    try:
        probe = len(arguments) > 1 and arguments[1] == "--probe"
        delimiter = 2 if probe else 1
        require(len(arguments) > delimiter+1 and arguments[delimiter] == "--", "linux_launch_arguments")
        config_path = absolute(arguments[0])
        with HeldPath(config_path) as configuration:
            payload = configuration.read(MAX_JSON)
            config = validate_linux_configuration(json.loads(payload), dict(os.environ))
            config_identity = configuration.binding()
        _, abi = linux_abi()
        library = ctypes.CDLL(None, use_errno=True)
        require(library.prctl(36, 1, 0, 0, 0) == 0, "linux_subreaper_required")
        require(absolute(os.getcwd()) == Path(config["candidate"]), "linux_launch_cwd")
        for path in config["write_roots"]:
            with HeldPath(path, directory=True):
                pass
        for key in ["records", "evidence"]:
            path = Path(config[key])
            with HeldPath(path.parent, directory=True) as parent:
                try:
                    os.mkdir(path.name, 0o700, dir_fd=parent.fd)
                except FileExistsError:
                    pass
        campaign = Campaign(Path(config["records"]), config["source_binding"])
        # Expose only the recorded root to kernel setup, never infer it from a
        # retained artifact path supplied by the caller.
        campaign.root = Path(config["records"])
        declaration, originals = collect_linux_scope(config, campaign)
        alias_originals = linux_alias_bindings(config)
        campaign.aliases = alias_originals
        recorder_path = declared_path(Path(__file__).absolute(), config)
        require(str(recorder_path) == declaration["images"]["recorder"]["path"], "linux_launcher_image")
        declaration_image = campaign.retain(canonical(declaration) + b"\n")
        identifier = uuid.uuid4().hex
        evidence_path = Path(config["evidence"])/identifier
        with HeldPath(Path(config["evidence"]), directory=True) as evidence:
            launch = mkdir(evidence, identifier)
        declaration_path = evidence_path/"declaration.json"
        before = generated_inventory(config, campaign, original_inputs=True)
        before_image = campaign.retain(canonical(before) + b"\n")
        command = arguments[delimiter+1:]
        require(not any(value.startswith("@") or SECRET_WORD.search(value) for value in command), "linux_command_input")
        executable = Path(command[0]) if os.path.isabs(command[0]) else next(
            (Path(directory)/command[0] for directory in config["environment"]["PATH"].split(os.pathsep)
             if (Path(directory)/command[0]).exists()), None)
        permitted = [declaration["images"][key]["path"] for key in (["python", "rustc", "recorder"] if probe else ["cargo"])]
        require(executable is not None and str(declared_path(executable, config)) in permitted, "linux_command_image")
        with launch:
            publish_file(launch, "declaration.json", canonical(declaration) + b"\n")
            environment = {**config["environment"], "RUSTC": declaration["images"]["rustc"]["path"],
                "RUSTC_WRAPPER": declaration["images"]["recorder"]["path"], "PYTHONDONTWRITEBYTECODE": "1",
                "CHIO_COMPILATION_SOURCE_ROOT": config["candidate"], "CHIO_COMPILATION_RECORDS": config["records"],
                "CHIO_COMPILATION_SOURCE_BINDING": config["source_binding"],
                "CHIO_COMPILATION_SCOPE_DECLARATION": str(declaration_path), "CHIO_COMPILATION_SCOPE_ID": declaration["scope_id"]}
            native, _, _ = load_native_scope(environment, campaign)
            supervisor = CompilationSupervisor(native, declaration, originals, campaign, environment)
            supervisor.aliases = alias_originals
            supervisor.scope_identity = native_scope_owner_identity()
            environment["CHIO_COMPILATION_IPC"] = canonical(supervisor.table).decode("ascii")
            started = time.time()
            with HeldPath(evidence_path/"stdout.log", create=True) as stdout, HeldPath(evidence_path/"stderr.log", create=True) as stderr:
                process = subprocess.Popen(command, cwd=config["candidate"], env=environment,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                    pass_fds=supervisor.pass_fds,
                    preexec_fn=lambda: enforce_linux_scope(config, declaration, originals, campaign, platform.machine()))
                supervisor.scope_process = process
                command_exit = supervisor.wait(process, (stdout, stderr))
                reaped = []
                while True:
                    try:
                        child_pid, child_status = os.waitpid(-1, 0)
                        reaped.append({"pid": child_pid, "wait_status": child_status})
                    except ChildProcessError:
                        break
                require(probe or command_exit != 0 or all(event["exit"] == 0 for event in supervisor.events),
                        "linux_compilation_request_failed")
                os.fsync(stdout.fd)
                os.fsync(stderr.fd)
                logs = {key: campaign.retain(written_bytes(handle)) for key, handle in [("stdout", stdout), ("stderr", stderr)]}
            after = generated_inventory(config, campaign)
            after_image = campaign.retain(canonical(after) + b"\n")
            for path, original in originals.items():
                verify_unchanged(path, original)
            verify_unchanged(config_path, config_identity)
            verify_linux_aliases(config, alias_originals)
            completed = {**declaration, "schema": "chio.linux-compilation-scope.v2", "declaration": declaration_image,
                "execution": {"kind": "scope-enforcement-probe" if probe else "cargo", "command_sha256": digest(command), "environment_sha256": digest(environment),
                    "started_unix_seconds": started, "ended_unix_seconds": time.time(), "command_exit": command_exit,
                    "runner_exit": command_exit if command_exit >= 0 else 128-command_exit, "source_drift": False,
                    "linux_architecture": platform.machine(), "landlock_abi": abi,
                    "ipc": supervisor.table,
                    "reaped_descendants": reaped,
                    "generated_before": before_image, "generated_after": after_image, "logs": logs,
                    "retention_outcomes": list(campaign.retention_outcomes),
                    "supervisor_events": campaign.retain(canonical({"schema": "chio.compilation-supervisor-events.v2", "events": supervisor.events}) + b"\n")}}
            publish_file(launch, "scope.json", canonical(completed) + b"\n")
        return command_exit if command_exit >= 0 else 128-command_exit
    except (Refusal, OSError, ValueError, UnicodeError, TypeError, KeyError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, Refusal) else "linux_launch_io_or_format"
        if evidence_path is not None:
            observed_exit = command_exit if command_exit is not None else (process.poll() if process is not None else None)
            try:
                with HeldPath(evidence_path, directory=True) as failure_directory:
                    failure = {"schema": "chio.linux-compilation-scope-failure.v1",
                        "source_binding": config["source_binding"], "scope_id": declaration["scope_id"],
                        "command_exit": observed_exit, "runner_exit": 86, "refusal": reason,
                        "compiled_closure_status": "not-established"}
                    if supervisor is not None:
                        failure.update(schema="chio.linux-compilation-scope-failure.v2",
                            supervisor_events=campaign.retain(canonical({
                                "schema": "chio.compilation-supervisor-events.v2",
                                "events": supervisor.events}) + b"\n"))
                    publish_file(failure_directory, "failure.json", canonical(failure) + b"\n")
            except (Refusal, OSError, ValueError, TypeError, KeyError):
                # Failed observation persistence cannot create usable closure.
                pass
        print("compilation_recorder." + reason, file=sys.stderr)
        return 86
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()
        if supervisor is not None:
            supervisor.close()
        if campaign is not None:
            campaign.close()


def main(argv, supplied_environment=None, supplied_cwd=None, executor=None, probe_sink=None, dispatch_selection=None):
    if argv and argv[0] == "--launch-scope":
        return launch_scope(argv[1:])
    if supplied_environment is None and "CHIO_COMPILATION_IPC" in os.environ:
        return compilation_client(argv)
    campaign = None
    row = None
    dispatched = False
    actual_exit = None
    output_lease = None
    try:
        environment = dict(os.environ) if supplied_environment is None else dict(supplied_environment)
        root = absolute(environment.get("CHIO_COMPILATION_SOURCE_ROOT", ""))
        records = absolute(environment.get("CHIO_COMPILATION_RECORDS", ""))
        binding = environment.get("CHIO_COMPILATION_SOURCE_BINDING", "")
        require(environment.get("CHIO_COMPILATION_SOURCE_ROOT") and environment.get("CHIO_COMPILATION_RECORDS")
                and os.path.isabs(environment["CHIO_COMPILATION_SOURCE_ROOT"])
                and os.path.isabs(environment["CHIO_COMPILATION_RECORDS"])
                and DIGEST.fullmatch(binding), "configuration")
        require(records != root and records.is_relative_to(root / "target"), "records_not_controlled_target")
        with HeldPath(root, directory=True):
            pass
        campaign = Campaign(records, binding)
        campaign.environment = environment
        campaign.cwd = str(absolute(os.getcwd() if supplied_cwd is None else supplied_cwd))
        campaign.executor = executor
        row = row_for(argv, environment, binding)
        native, native_reference, readonly_members = load_native_scope(environment, campaign)
        if native is not None:
            native, selected_target = native_target_context(native, argv[1:], Path(campaign.cwd))
            if "_target_linker_images" in native:
                native_reference = {**native_reference, "linker": native["_target_linker_images"][selected_target]}
            if dispatch_selection is not None and dispatch_selection["driver"] is not None:
                require(dispatch_selection["driver"] == native_reference["linker"], "compiler_dispatch_driver_binding")
        campaign.native_reference = native_reference
        require(argv and os.path.isabs(argv[0]), "compiler_path")
        require(not any(SECRET_WORD.search(name) for name in environment), "credential_environment")
        for key in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"]:
            if key in environment:
                absolute(environment[key])
        # Environment injection/loader inputs cannot be represented as ordinary opaque values.
        require(not any((name.startswith(("LD_", "DYLD_")) and not (native is not None and name == "LD_LIBRARY_PATH")) or name in
                        {"RUSTC_CODEGEN_BACKEND", "RUST_TARGET_PATH", "RUSTC_OVERRIDE_VERSION_STRING"}
                        for name in environment), "hidden_environment_input")
        cwd = Path(campaign.cwd)
        compiler = absolute(argv[0])
        if native is not None:
            require(compiler == declared_path(native["images"]["rustc"]["path"], native), "native_compiler_binding")
        if any(arg == "--print" or arg.startswith("--print=") for arg in argv[1:]):
            row["kind"] = "probe"
        parsed = parse(argv[1:], cwd, native)
        require_native_linker_selection(parsed, native)
        row["kind"] = parsed["kind"]
        if parsed["kind"] == "probe":
            require(not any(flag.get("name") in {"--cfg", "--check-cfg"}
                            for flag in parsed.get("flags", [])), "opaque_probe_output")
            row["semantics"] = {"probe": parsed["probe"], "prints": parsed.get("prints", [])}
            if native_reference is not None:
                row["semantics"]["native_scope"] = native_reference
            if dispatch_selection is not None:
                require(dispatch_selection["effective_argv"] == argv, "compiler_dispatch_binding")
                row["semantics"]["compiler_dispatch"] = retain_compiler_dispatch(campaign, dispatch_selection)
            image, original = capture(compiler, "compiler", campaign)
            image.pop("role")
            image["version"] = None
            row["compiler"] = image
            dispatched = True
            probe_result = dispatch_compiler(campaign, argv, True)
            actual_exit = probe_result.returncode
            verify_unchanged(compiler, original)
            require(len(probe_result.stdout) <= MAX_JSON, "probe_output_limit")
            require(not SECRET_WORD.search(probe_result.stdout.decode("utf-8", errors="strict")), "unsafe_probe_output")
            if actual_exit == 0:
                if probe_sink is None:
                    sys.stdout.buffer.write(probe_result.stdout)
                    sys.stdout.buffer.flush()
                else:
                    probe_sink(probe_result.stdout)
            row["compiler_exit"] = actual_exit
            row["status"] = "success" if actual_exit == 0 else "compiler_failed"
            campaign.publish(row)
            return actual_exit if actual_exit >= 0 else 128 - actual_exit
        row["semantics"] = {key: parsed[key] for key in ["cwd", "source", "crate_name", "crate_types", "target", "profile", "flags"]}
        if native_reference is not None:
            row["semantics"]["native_scope"] = native_reference
            row["semantics"]["native_libraries"] = parsed.get("native_libraries", [])
        if dispatch_selection is not None:
            require(dispatch_selection["effective_argv"] == argv, "compiler_dispatch_binding")
            row["semantics"]["compiler_dispatch"] = retain_compiler_dispatch(campaign, dispatch_selection)
        depfile, emissions = output_paths(parsed)
        output_directory = depfile.parent
        require(output_directory.is_relative_to(root / "target"), "output_not_controlled_target")
        if native is not None:
            require(any(output_directory.is_relative_to(Path(path)) for path in native["write_roots"]), "native_output_scope")
        row["semantics"]["emits"] = emissions
        row["semantics"]["output_ownership"] = {"policy": "fresh-path-directory-lock", "directory": str(output_directory)}
        expected_outputs = set(emissions.values()) - {str(depfile)}
        output_lease = OutputLease(output_directory, emissions)
        row["compiler"], toolchain, identities = compiler_inputs(compiler, parsed, campaign, native)
        if native is not None:
            require(row["compiler"]["sha256"] == native["images"]["rustc"]["sha256"]
                    and row["compiler"]["version"]["fields"]["host"] == "x86_64-unknown-linux-gnu", "native_compiler_binding")
        row["inputs"].extend(toolchain)
        source = Path(parsed["source"])
        public_files = ([Path(path) for path in readonly_members] if native is not None else
                        tree_files(root, exclude={"target", ".git", "node_modules", ".venv", "__pycache__"}))
        if native is not None:
            require(str(source) in readonly_members or any(source.is_relative_to(Path(path)) for path in native["write_roots"]), "native_source_scope")
            if "link" in parsed["emit"] and any(kind in {"bin", "proc-macro", "cdylib", "dylib"} for kind in parsed["crate_types"]):
                linker, original = capture(native_reference["linker"]["path"], "native-linker", campaign)
                require(linker["sha256"] == native_reference["linker"]["sha256"], "native_linker_binding")
                linker["coverage"] = "declared-required-linker-image"
                row["inputs"].append(linker)
                identities[linker["path"]] = original
            if str(source) not in readonly_members:
                public_files.extend(tree_files(source.parent))
        elif not source.is_relative_to(root):
            public_files.extend(tree_files(source.parent))
        public_files.append(source)
        # Generated include inputs must be visible before dispatch as well.
        if environment.get("OUT_DIR"):
            out_dir = absolute(environment["OUT_DIR"])
            require(native is None or any(out_dir.is_relative_to(Path(path)) for path in native["write_roots"]), "native_generated_scope")
            public_files.extend(tree_files(out_dir))
        source_identities = snapshot(set(public_files))
        source_item, source_identity = capture(source, "source", campaign)
        if native is not None:
            if str(source) in readonly_members:
                require(source_item["sha256"] == readonly_members[str(source)]["sha256"], "native_source_binding")
            else:
                source_item["origin"] = "campaign-produced"
        row["inputs"].append(source_item)
        identities[str(source)] = source_identity
        for external in parsed["externs"]:
            if native is None:
                with HeldPath(Path(external["path"]).parent, directory=True) as directory:
                    require(not any(Path(name).suffix in {".so", ".dylib", ".dll"}
                                    for name in os.listdir(directory.fd)), "dynamic_search_hidden_inputs")
                    directory.verify(content=False)
            else:
                require(external["path"] in readonly_members or any(Path(external["path"]).is_relative_to(Path(path)) for path in native["write_roots"]), "native_extern_scope")
            with HeldPath(external["path"]) as handle:
                header = os.read(handle.fd, 8)
                require(header.startswith(b"!<arch>\n") if external["path"].endswith(".rlib") else
                        header.startswith(b"\x7fELF") if external["path"].endswith(".so") else header.startswith(b"rmeta"), "extern_image_format")
                handle.verify()
            item, observed = capture(external["path"], "extern", campaign)
            item["extern_name"] = external["name"]
            if native is not None:
                if external["path"] in readonly_members:
                    require(item["sha256"] == readonly_members[external["path"]]["sha256"], "native_extern_binding")
                    item["origin"] = "declared-immutable-scope"
                    item["immutable_scope"] = {"scope_id": native_reference["scope_id"], "path": external["path"],
                                               "sha256": item["sha256"]}
                else:
                    public_source = next(({"path": entry["value"], "sha256": entry["source"]["sha256"]}
                                          for entry in native.get("_public_arguments", []) if entry["kind"] == "source"), None)
                    item["producer"] = producing_unit(campaign, item, "chio_credentials" if external["name"] == "chio_credentials" else None,
                                                      public_source if external["name"] == "chio_credentials" else None)
                    item["origin"] = "recorded-producing-unit"
                if external.get("kind") == "dynamic-image":
                    item["extern_kind"] = "proc-macro-or-dynamic-image"
            row["inputs"].append(item)
            identities[external["path"]] = observed
        search_snapshots = {}
        for search in parsed["search"]:
            search_root = Path(search["path"])
            if native is not None:
                writable_search = any(search_root.is_relative_to(Path(path)) for path in native["write_roots"])
                require(writable_search or any(search_root.is_relative_to(Path(scope["root"])) for scope in native["scopes"])
                        and not any(search_root.is_relative_to(Path(native[key])) for key in ["records", "evidence"]), "native_search_scope")
                files = tree_files(search_root) if writable_search else [Path(path) for path in readonly_members if Path(path).is_relative_to(search_root)]
            else:
                files = tree_files(search_root)
            require(native is not None or not any(path.suffix in {".so", ".dylib", ".dll"} for path in files), "dynamic_search_hidden_inputs")
            search_snapshots[search["path"]] = sorted(str(p) for p in files)
            for path in files:
                item, observed = capture(path, "search", campaign)
                item["search_kind"] = search["kind"]
                item["coverage"] = "conservative-search-scope"
                row["inputs"].append(item)
                identities[str(path)] = observed
        for path, original in identities.items():
            verify_unchanged(path, original, output_directory)
        dispatched = True
        actual_exit = dispatch_compiler(campaign, argv).returncode
        row["compiler_exit"] = actual_exit
        if actual_exit != 0:
            row["status"] = "compiler_failed"
            campaign.publish(row)
            return actual_exit if actual_exit >= 0 else 128 - actual_exit
        produced = output_lease.produced()
        for path, original in identities.items():
            verify_unchanged(path, original, output_directory)
        for directory, original in search_snapshots.items():
            if native is None or any(Path(directory).is_relative_to(Path(path)) for path in native["write_roots"]):
                require(sorted(str(p) for p in tree_files(directory)) == original, "search_changed_during_compilation")
        with HeldPath(depfile) as handle:
            payload = handle.read()
            dep = parse_depfile(payload, cwd, environment, native)
            require(str(source) in dep["dependencies"], "source_not_in_depfile")
            for path in dep["dependencies"]:
                require(path in source_identities or path in identities, "input_not_observed_before_dispatch")
                verify_unchanged(path, source_identities.get(path, identities.get(path)), output_directory)
                if not any(item["path"] == path and item["role"] == "source" for item in row["inputs"]):
                    item, observed = capture(path, "source", campaign)
                    if native is not None:
                        if path in readonly_members:
                            require(item["sha256"] == readonly_members[path]["sha256"], "native_source_binding")
                        else:
                            item["origin"] = "campaign-produced"
                    verify_unchanged(path, source_identities.get(path, identities.get(path)), output_directory)
                    row["inputs"].append(item)
            retained = campaign.retain(payload)
            handle.verify()
            dep.update({"path": str(depfile), "sha256": retained["sha256"]})
            row["depfiles"].append(dep)
            row["outputs"].append({"role": "depfile", "path": str(depfile), **retained})
        require(expected_outputs, "missing_unit_output")
        nominal = set(dep["targets"]) - {str(depfile)}
        require(nominal, "depfile_output_binding")
        mappings = []
        for target in sorted(nominal):
            matches = [path for path in expected_outputs if target == path or
                       (parsed["output"] and target == str(Path(path).with_suffix("")))]
            # Explicit --emit paths retain rustc's nominal crate output name.
            for kind, path in emissions.items():
                if kind != "dep-info" and parsed["emit"][kind] is not None:
                    name = parsed["crate_name"] or source.stem
                    extension = Path(path).suffix
                    if target == str(cwd / ("lib" + name + parsed.get("suffix", "") + extension)):
                        matches.append(path)
            require(matches, "depfile_output_binding")
            for path in sorted(set(matches)):
                mappings.append({"target": target, "output": path})
        require(set(item["output"] for item in mappings) == expected_outputs, "depfile_output_binding")
        dep["unit_targets"] = mappings
        for path in sorted(expected_outputs):
            item, _ = capture(path, "unit", campaign)
            if native is not None and path.endswith(".so"):
                item["unit_kind"] = "linux-dynamic-image"
            row["outputs"].append(item)
        output_lease.verify(produced)
        row["status"] = "success"
        campaign.publish(row)
        return 0
    except (Refusal, OSError, ValueError, UnicodeError, TypeError, KeyError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, Refusal) else "recorder_io_or_format"
        if isinstance(error, CompilerOutputRefusal):
            actual_exit = error.compiler_exit
        if row is not None and campaign is not None:
            row["status"] = "instrumentation_failed" if dispatched and actual_exit == 0 else ("compiler_failed" if actual_exit else "refused")
            row["compiler_exit"] = actual_exit
            row["refusal"] = reason
            # Partial input/output vectors cannot masquerade as a successful record.
            try:
                campaign.publish(row)
            except (Refusal, OSError, ValueError, TypeError, KeyError):
                pass
        print("compilation_recorder." + reason, file=sys.stderr)
        if actual_exit is not None and actual_exit != 0:
            return actual_exit if actual_exit >= 0 else 128 - actual_exit
        return 86
    finally:
        if campaign is not None:
            campaign.close()
        if output_lease is not None:
            output_lease.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
