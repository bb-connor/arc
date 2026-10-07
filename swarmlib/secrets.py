"""Detect credential-shaped strings before anything is pushed."""

from __future__ import annotations

import re

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("sk- api key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("e2b api key", re.compile(r"\be2b_[A-Za-z0-9]{24,}")),
    ("slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    (
        "assigned secret",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_=.-]{24,}"),
    ),
)


def scan(text: str) -> list[tuple[str, int]]:
    """Return (kind, line number) for every credential-shaped match."""
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in PATTERNS:
            if pattern.search(line):
                hits.append((kind, number))
    return hits
