#!/usr/bin/env python3
"""Require every Chio error URN named in shipped Rust source to be registered.

spec/errors/registry.yaml is the source of truth for stable error URNs, and
clients resolve severity, help and string codes from it. This gate scans the
Rust sources under crates/*/*/src for `urn:chio:error:<domain>:<code>` literals
and fails when one is absent from the registry. Test-only files and the
generated registry module are skipped. A literal that ends in "-" is the stem
of a family whose last segment is built at run time, and it must be the prefix
of at least one registered URN.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

URN_LITERAL = re.compile(r"urn:chio:error:[a-z0-9_-]+:[a-z0-9_-]+")
REGISTERED_URN = re.compile(r'^\s*-\s*urn:\s*"(urn:chio:error:[^"]+)"\s*$')
TEST_DIRECTORY = re.compile(r"(^|_)tests?$")
SKIPPED_DIRECTORIES = {"benches", "examples", "_generated", "target"}


def registered_urns(registry: Path) -> set[str]:
    urns = set()
    for line in registry.read_text(encoding="utf-8").splitlines():
        match = REGISTERED_URN.match(line)
        if match:
            urns.add(match.group(1))
    return urns


def is_test_only(relative: Path) -> bool:
    if relative.name == "tests.rs" or relative.name.endswith("_tests.rs"):
        return True
    return any(TEST_DIRECTORY.search(part) for part in relative.parts[:-1])


def shipped_sources(root: Path):
    for source_root in sorted(root.glob("crates/*/*/src")):
        for path in sorted(source_root.rglob("*.rs")):
            relative = path.relative_to(source_root)
            if SKIPPED_DIRECTORIES.intersection(relative.parts[:-1]):
                continue
            if is_test_only(relative):
                continue
            yield path


def unregistered_literals(root: Path, registry: Path) -> dict[str, list[str]]:
    urns = registered_urns(registry)
    missing: dict[str, list[str]] = {}
    for path in shipped_sources(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            for literal in URN_LITERAL.findall(line):
                if literal.endswith("-"):
                    known = any(urn.startswith(literal) for urn in urns)
                else:
                    known = literal in urns
                if not known:
                    location = f"{path.relative_to(root)}:{number}"
                    missing.setdefault(literal, []).append(location)
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    registry = root / "spec/errors/registry.yaml"
    if not registry.is_file():
        print(f"error registry not found: {registry}", file=sys.stderr)
        return 2
    missing = unregistered_literals(root, registry)
    if missing:
        print("shipped source names Chio error URNs absent from spec/errors/registry.yaml:", file=sys.stderr)
        for literal in sorted(missing):
            print(f"  {literal}: {', '.join(missing[literal])}", file=sys.stderr)
        return 1
    print(f"error URN registry: every shipped urn:chio:error literal is registered ({len(registered_urns(registry))} registered)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
