"""Capture bounded Git objects, never execute or read the working tree."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

MAX_FILES = 128
MAX_BLOB = 64 * 1024
MAX_SNAPSHOT = 8 * 1024 * 1024


def encoded(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def git(repo, *args):
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0"
    )
    return subprocess.check_output(
        ["git", "--no-pager", "-C", str(repo), *args],
        timeout=30,
        stderr=subprocess.DEVNULL,
        env=environment,
    )


def tree(repo, commit):
    entries = {}
    for entry in git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if entry:
            header, path = entry.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split()
            entries[path.decode("utf-8")] = {"mode": mode, "kind": kind, "oid": oid}
    return entries


def blob(repo, entry):
    if entry is None:
        return {"content": None, "reason": "absent"}
    if entry["mode"] not in ("100644", "100755") or entry["kind"] != "blob":
        return dict(entry, content=None, reason="not a regular file")
    if int(git(repo, "cat-file", "-s", entry["oid"])) > MAX_BLOB:
        return dict(entry, content=None, reason="exceeds 64 KiB")
    data = git(repo, "cat-file", "blob", entry["oid"])
    try:
        content = data.decode("utf-8")
        if "\0" in content:
            raise ValueError("binary")
    except (UnicodeError, ValueError):
        return dict(entry, content=None, reason="binary or non-UTF-8")
    return dict(entry, content=content, lines=len(content.splitlines()))


def is_test(path):
    parts = Path(path).parts
    name = parts[-1]
    return any(p in ("test", "tests", "__tests__") for p in parts) or (
        name.startswith("test_")
        or any(s in name for s in (".test.", ".spec.", "_test."))
    )


def capture(repo, base, head):
    commits = [
        git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
        .decode()
        .strip()
        for ref in (base, head)
    ]
    before, after = [tree(repo, commit) for commit in commits]
    paths = sorted(
        p for p in before.keys() | after.keys() if before.get(p) != after.get(p)
    )
    if not paths or len(paths) > MAX_FILES:
        raise ValueError("review requires between 1 and 128 changed paths")
    files = [
        {
            "path": p,
            "test_path": is_test(p),
            "status": "added"
            if p not in before
            else "deleted"
            if p not in after
            else "modified",
            "base": blob(repo, before.get(p)),
            "head": blob(repo, after.get(p)),
        }
        for p in paths
    ]
    result = {
        "schema": "chio.repository.snapshot.v1",
        "base": commits[0],
        "head": commits[1],
        "files": files,
    }
    if len(encoded(result)) > MAX_SNAPSHOT:
        raise ValueError("snapshot exceeds 8 MiB; select a smaller commit range")
    return result


def load(path, expected_hash):
    data = Path(path).read_bytes()
    if len(data) > MAX_SNAPSHOT:
        raise ValueError("snapshot too large")
    value = json.loads(data)
    if digest(value) != expected_hash:
        raise ValueError("snapshot changed; preserve the original run directory")
    return value


def inventory(snapshot, tests_only=False):
    files = []
    for item in snapshot["files"]:
        if tests_only and not item["test_path"]:
            continue
        files.append(
            {
                **{k: item[k] for k in ("path", "status", "test_path")},
                **{
                    side: {k: v for k, v in item[side].items() if k != "content"}
                    for side in ("base", "head")
                },
            }
        )
    return {
        "base": snapshot["base"],
        "head": snapshot["head"],
        "files": files,
        "other_changed_paths": [
            item["path"]
            for item in snapshot["files"]
            if tests_only and not item["test_path"]
        ],
        "scope": "changed test paths" if tests_only else "all changed paths",
        "test_detection": "path-name heuristic; no tests were executed",
    }
