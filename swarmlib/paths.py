"""Conservative overlap test for path globs (false positives are fine, misses are not)."""

from __future__ import annotations

from pathlib import PurePosixPath

WILDCARDS = frozenset("*?[")


def literal_prefix(glob: str) -> tuple[str, ...]:
    """Path components before the first component that contains a wildcard."""
    prefix = []
    for part in PurePosixPath(glob.strip("/")).parts:
        if any(char in WILDCARDS for char in part):
            break
        prefix.append(part)
    return tuple(prefix)


def globs_overlap(left: str, right: str) -> bool:
    a, b = literal_prefix(left), literal_prefix(right)
    shared = min(len(a), len(b))
    return a[:shared] == b[:shared]


def find_overlaps(wanted: list[str], held: list[str]) -> list[tuple[str, str]]:
    return [(w, h) for w in wanted for h in held if globs_overlap(w, h)]
