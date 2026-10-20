#!/usr/bin/env python3
"""Keep the offline bundle verifier offline and permissively licensed.

Reads `cargo metadata --format-version 1 --locked` output and walks the
normal (non-dev, non-build) dependency closure of `chio-bundle-verify`. The
gate fails when that closure contains an async runtime, an HTTP client, a
SQLite binding or a hosted Chio crate, or a package whose license expression
is not satisfiable from the `deny.toml` `[licenses] allow` list. A package
without a `license` field must have a `[[licenses.clarify]]` entry.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "chio-bundle-verify"
DENIED = frozenset(
    {
        "tokio",
        "rusqlite",
        "reqwest",
        "ureq",
        "hyper",
        "chio-kernel",
        "chio-control-plane",
        "chio-store-sqlite",
    }
)


def license_policy(deny_toml: Path) -> tuple[frozenset[str], dict[str, str]]:
    config = tomllib.loads(deny_toml.read_text(encoding="utf-8"))
    licenses = config.get("licenses", {})
    allow = frozenset(licenses.get("allow", []))
    clarify = {
        entry["name"]: entry["expression"] for entry in licenses.get("clarify", [])
    }
    return allow, clarify


TOKEN = re.compile(r"\(|\)|\bAND\b|\bOR\b|\bWITH\b|[A-Za-z0-9.+-]+")


def satisfiable(expression: str, allow: frozenset[str]) -> bool:
    """Whether some choice of OR branches leaves only allowed licenses."""
    tokens = TOKEN.findall(expression.replace("/", " OR "))
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def term() -> bool:
        if peek() == "(":
            take()
            value = disjunction()
            if peek() != ")":
                raise ValueError(f"unbalanced license expression: {expression}")
            take()
            return value
        name = take()
        if peek() == "WITH":
            take()
            name = f"{name} WITH {take()}"
        return name in allow

    def conjunction() -> bool:
        value = term()
        while peek() == "AND":
            take()
            value = term() and value
        return value

    def disjunction() -> bool:
        value = conjunction()
        while peek() == "OR":
            take()
            value = conjunction() or value
        return value

    result = disjunction()
    if position != len(tokens):
        raise ValueError(f"malformed license expression: {expression}")
    return result


def normal_closure(metadata: dict, package: str) -> list[dict]:
    packages = {entry["id"]: entry for entry in metadata["packages"]}
    roots = [entry["id"] for entry in metadata["packages"] if entry["name"] == package]
    if len(roots) != 1:
        raise ValueError(f"expected exactly one {package} package, found {len(roots)}")
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    seen: set[str] = set()
    stack = [roots[0]]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            if any(kind.get("kind") is None for kind in dep["dep_kinds"]):
                stack.append(dep["pkg"])
    return [packages[identifier] for identifier in sorted(seen)]


def check(metadata: dict, deny_toml: Path, package: str = PACKAGE) -> list[str]:
    allow, clarify = license_policy(deny_toml)
    errors = []
    for entry in normal_closure(metadata, package):
        name = entry["name"]
        if name in DENIED:
            errors.append(f"{package} must not depend on {name} {entry['version']}")
        expression = entry.get("license") or clarify.get(name)
        if expression is None:
            errors.append(f"{name} {entry['version']} declares no license")
            continue
        try:
            allowed = satisfiable(expression, allow)
        except (ValueError, IndexError) as error:
            errors.append(f"{name} {entry['version']}: {error}")
            continue
        if not allowed:
            errors.append(
                f"{name} {entry['version']} license {expression!r} is outside the deny.toml allow list"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--deny-toml", type=Path, default=ROOT / "deny.toml")
    args = parser.parse_args()
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    errors = check(metadata, args.deny_toml)
    for error in errors:
        print(f"check-offline-verifier-deps: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"OK {PACKAGE} normal dependency closure is offline and allow-listed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
