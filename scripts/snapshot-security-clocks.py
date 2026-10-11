#!/usr/bin/env python3
"""Reproduce clock-scope evidence from immutable Git source without changing debt.

The current boundary catalogs and scanner define coverage. The selected commit
supplies source bytes. Output is evidence for manual review, never a new allowlist.
"""

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "security_clocks", ROOT / "scripts/check-security-clocks.py"
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def snapshot(root, revision):
    revision = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "rev-parse",
            "--verify",
            "--end-of-options",
            revision + "^{commit}",
        ],
        text=True,
    ).strip()
    entries = []
    roots = GATE.clock_roots(root)
    listing = subprocess.check_output(
        ["git", "-C", str(root), "ls-tree", "-r", revision, "--", "crates"], text=True
    )
    for line in listing.splitlines():
        metadata, path = line.split("\t", 1)
        if path.endswith((".rs", ".inc")) and path.startswith(roots):
            entries.append((path, metadata.split()[2]))
    found, source_hashes = Counter(), {}
    with subprocess.Popen(
        ["git", "-C", str(root), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    ) as process:
        try:
            for path, object_id in entries:
                process.stdin.write((object_id + "\n").encode())
                process.stdin.flush()
                header = process.stdout.readline().split()
                if len(header) != 3 or header[1] != b"blob":
                    raise ValueError(f"expected a source blob for {path}")
                size = int(header[2])
                data = process.stdout.read(size)
                if len(data) != size or process.stdout.read(1) != b"\n":
                    raise ValueError(f"incomplete Git source for {path}")
                observations = GATE.sites(path, data.decode())
                if observations:
                    found.update(observations)
                    source_hashes[path] = hashlib.sha256(data).hexdigest()
        finally:
            process.stdin.close()
        if process.wait() != 0:
            raise ValueError("Git source reader failed")
    return {
        "schema": "chio.clock-scope-evidence.v1",
        "base_revision": revision,
        "description": "Expanded lexical scan of unmodified base source; these are pre-existing observations, not migrated paths. Includes fixtures and native composition candidates.",
        "sites": dict(sorted(found.items())),
        "source_sha256": source_hashes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(snapshot(args.root, args.revision), indent=2))


if __name__ == "__main__":
    main()
