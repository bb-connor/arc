#!/usr/bin/env python3
"""Fail when a committed Cargo.lock records a `[patch]` entry that is not used.

Cargo writes `[[patch.unused]]` for every `[patch]` replacement that no
package in the resolved graph selects. Such a patch is not inert: if a later
dependency requests a version the replacement satisfies, Cargo silently swaps
in the patched source. Every committed lockfile is checked except those under
`third_party/`, which are upstream files of vendored trees that every
workspace excludes and that are never resolved as a workspace.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path

VENDORED = "third_party/"


def committed_lockfiles(root: Path) -> list[str]:
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "Cargo.lock", "*/Cargo.lock"],
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    return sorted(path for path in listed.split("\0") if path and not path.startswith(VENDORED))


def unused_patches(lockfile: Path) -> list[str]:
    document = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    entries = document.get("patch", {}).get("unused", [])
    return [f"{entry.get('name', '?')} {entry.get('version', '?')}" for entry in entries]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    lockfiles = committed_lockfiles(root)
    if not lockfiles:
        print(f"no committed Cargo.lock under {root}", file=sys.stderr)
        return 2
    failures = []
    for relative in lockfiles:
        try:
            unused = unused_patches(root / relative)
        except (OSError, tomllib.TOMLDecodeError) as error:
            failures.append(f"{relative}: cannot read lockfile: {error}")
            continue
        failures.extend(f"{relative}: unused patch {entry}" for entry in unused)
    if failures:
        print("committed lockfiles record [patch] replacements that no package selects:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print("Remove the replacement from the manifest and regenerate the lockfile.", file=sys.stderr)
        return 1
    print(f"cargo lock patches: no unused [patch] replacement in {len(lockfiles)} committed lockfiles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
