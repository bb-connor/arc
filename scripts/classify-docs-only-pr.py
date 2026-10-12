#!/usr/bin/env python3
"""Classify a pull request merge commit as documentation-only, failing closed."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import PurePosixPath

SHA = re.compile(r"[0-9a-f]{40}")
# Markdown under these roots is compiled, parsed, or normative protocol input.
CONTRACT_ROOTS = (
    ".github/",
    "claims/",
    "compliance/",
    "contracts/",
    "formal/",
    "fuzz/",
    "spec/",
    "tests/",
    "third_party/",
)
REGULAR_FILE_MODES = {"000000", "100644", "100755"}


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, stdout=subprocess.PIPE, text=True
    ).stdout


def parse_raw_diff(raw: str) -> list[tuple[str, str, str]]:
    """Return (old mode, new mode, path) for `git diff --raw -z --no-renames`."""
    fields = raw.split("\0")
    if fields[-1] != "" or len(fields) % 2 != 1:
        raise ValueError("unterminated raw diff")
    entries = []
    for index in range(0, len(fields) - 1, 2):
        header, path = fields[index], fields[index + 1]
        parts = header.split(" ")
        if len(parts) != 5 or not parts[0].startswith(":") or not path:
            raise ValueError(f"malformed raw diff entry: {header!r}")
        entries.append((parts[0][1:], parts[1], path))
    return entries


def reference_needles(path: str) -> list[str]:
    parts = PurePosixPath(path).parts
    return sorted({path, "/".join(parts[-2:])})


def is_doc_entry(entry: tuple[str, str, str]) -> bool:
    old_mode, new_mode, path = entry
    return (
        old_mode in REGULAR_FILE_MODES
        and new_mode in REGULAR_FILE_MODES
        and path.endswith(".md")
        and ".." not in PurePosixPath(path).parts
        and not path.startswith(CONTRACT_ROOTS)
    )


def classify(
    entries: list[tuple[str, str, str]], referenced: Callable[[list[str]], bool]
) -> bool:
    return (
        bool(entries)
        and all(is_doc_entry(entry) for entry in entries)
        and not referenced([path for _, _, path in entries])
    )


def owning_package(path: str, tracked: set[str]) -> str | None:
    for parent in PurePosixPath(path).parents:
        if parent != PurePosixPath(".") and f"{parent}/Cargo.toml" in tracked:
            return str(parent)
    return None


def tree_referenced(paths: list[str], tracked: set[str]) -> bool:
    needles = sorted({needle for path in paths for needle in reference_needles(path)})
    if git_grep(needles, [":(exclude)*.md"]):
        return True
    packages: dict[str, set[str]] = {}
    for path in paths:
        package = owning_package(path, tracked)
        if package is not None:
            packages.setdefault(package, set()).add(PurePosixPath(path).name)
    return any(
        git_grep(
            sorted(names),
            [package, ":(exclude)*.md", f":(exclude){package}/Cargo.toml"],
        )
        for package, names in sorted(packages.items())
    )


def git_grep(needles: list[str], pathspecs: list[str]) -> bool:
    patterns = [arg for needle in needles for arg in ("-e", needle)]
    result = subprocess.run(
        ["git", "grep", "-q", "-F", "-I", *patterns, "--", *pathspecs],
        stdout=subprocess.DEVNULL,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git grep failed with {result.returncode}")
    return result.returncode == 0


def main() -> int:
    docs_only = False
    try:
        head = os.environ.get("PR_HEAD_SHA", "")
        if os.environ.get("EVENT_NAME") != "pull_request":
            reason = "not a pull request"
        elif not SHA.fullmatch(head):
            reason = "missing pull request head SHA"
        elif git("rev-list", "--parents", "-n", "1", "HEAD").split()[2:] != [head]:
            reason = "checkout is not the two-parent merge of the pull request head"
        else:
            entries = parse_raw_diff(
                git("diff", "--no-renames", "--raw", "-z", "HEAD^1", "HEAD")
            )
            tracked = set(git("ls-files", "-z", "--", "*Cargo.toml").split("\0"))
            docs_only = classify(entries, lambda paths: tree_referenced(paths, tracked))
            reason = f"{len(entries)} changed paths"
            for _, _, path in entries:
                print(path)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        docs_only = False
        reason = f"classification failed: {error}"
    print(f"docs_only={str(docs_only).lower()} ({reason})")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"docs_only={str(docs_only).lower()}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
