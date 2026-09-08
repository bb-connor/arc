"""Explicit committed source paths and bounded workspace publication scope."""

import json
from pathlib import PurePosixPath

from chio_mini_swe.repository_archive import entries, path_name

SCOPED_SCHEMA = "chio.repository.workspace.v3"


def normalize_source_paths(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ValueError("Select between 1 and 64 literal repository paths")
    for name in value:
        if not isinstance(name, str) or path_name(name) != name:
            raise ValueError("Selected repository paths must be canonical relative paths")
    ordered = sorted(value)
    if len(set(ordered)) != len(ordered) or any(
        name.startswith(parent + "/") for i, name in enumerate(ordered) for parent in ordered[:i]
    ):
        raise ValueError("Selected repository paths must not repeat or overlap")
    if len(json.dumps(ordered, separators=(",", ":")).encode()) > 16384:
        raise ValueError("Selected repository paths exceed their byte limit")
    return ordered


def require_scope(data, source_paths, *, allow_git=False):
    roots = normalize_source_paths(source_paths)
    for name, (kind, _, _) in entries(data, allow_git=allow_git).items():
        if allow_git and any(part.lower() == ".git" for part in PurePosixPath(name).parts):
            continue
        if any(name == root or name.startswith(root + "/") for root in roots):
            continue
        if kind == "directory" and any(root.startswith(name + "/") for root in roots):
            continue
        raise ValueError("Workspace output contains a path outside the selected source paths")
