#!/usr/bin/env python3
"""Require every Chio error URN named in shipped Rust source to be registered.

spec/errors/registry.yaml is the source of truth for stable error URNs, and
clients resolve severity, help and string codes from it. This gate lexes the
Rust sources under crates/*/*/src, plus the .inc fragments and include! targets
they compile, and checks every string literal that names a
`urn:chio:error:` URN. Comments and character literals are not literals.

Each URN token runs until the first character that cannot appear in a URN, and
must equal a registered URN. Two uses name a family rather than one code, and
for them the token must be the prefix of at least one registered URN: a token
followed in the same literal by a format placeholder (`{`), and a literal that
is the direct argument of `.starts_with(`.

The bare namespace `urn:chio:error:` names no code and is not checked.
Test-only files are skipped. Only the module generated from the registry,
crates/core/chio-errors/src/_generated, is exempt.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

URN_PREFIX = "urn:chio:error:"
URN_CHARACTER = re.compile(r"[A-Za-z0-9_.:\-]")
REGISTERED_URN = re.compile(r'^\s*-\s*urn:\s*"(urn:chio:error:[^"]+)"\s*$')
INCLUDE = re.compile(r'include!\s*\(\s*"([^"]+)"\s*\)')
PREFIX_TEST = re.compile(r"\.starts_with\(\s*$")
TEST_DIRECTORY = re.compile(r"(^|_)tests?$")
REGISTRY_MODULE = Path("crates/core/chio-errors/src/_generated")
SKIPPED_DIRECTORIES = {"benches", "examples", "target"}


def registered_urns(registry: Path) -> set[str]:
    urns = set()
    for line in registry.read_text(encoding="utf-8").splitlines():
        match = REGISTERED_URN.match(line)
        if match:
            urns.add(match.group(1))
    return urns


CHARACTER_LITERAL = re.compile(r"'(?:\\(?:u\{[0-9A-Fa-f]{1,6}\}|x[0-9A-Fa-f]{2}|.)|[^\\'\n])'")
RAW_STRING_OPENER = re.compile(r'(?:b|c)?r(#*)"')
STRING_OPENER = re.compile(r'(?:b|c)?"')


def string_literals(source: str):
    """Yield (line, start, contents) for each string literal in `source`.

    `start` is the offset of the literal's first character, prefix included.
    Handles line and nested block comments, character literals and lifetimes,
    and normal, byte and raw string literals. Escapes are kept as written; a
    URN contains no character that needs escaping.
    """
    length = len(source)
    index = 0
    line = 1
    while index < length:
        character = source[index]
        identifier_before = index > 0 and (source[index - 1].isalnum() or source[index - 1] == "_")
        if character == "\n":
            line += 1
            index += 1
        elif source.startswith("//", index):
            end = source.find("\n", index)
            index = length if end < 0 else end
        elif source.startswith("/*", index):
            depth = 0
            while index < length:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                    if depth == 0:
                        break
                else:
                    if source[index] == "\n":
                        line += 1
                    index += 1
        elif character == "'":
            # A character literal closes within a few characters; a lifetime
            # or label does not close at all.
            match = CHARACTER_LITERAL.match(source, index)
            index = match.end() if match else index + 1
        elif not identifier_before and (opener := RAW_STRING_OPENER.match(source, index)):
            closer = '"' + opener.group(1)
            begin = opener.end()
            end = source.find(closer, begin)
            end = length if end < 0 else end
            yield line, index, source[begin:end]
            line += source.count("\n", index, end)
            index = end + len(closer)
        elif not identifier_before and (opener := STRING_OPENER.match(source, index)):
            cursor = opener.end()
            begin = cursor
            while cursor < length and source[cursor] != '"':
                cursor += 2 if source[cursor] == "\\" else 1
            yield line, index, source[begin:cursor]
            line += source.count("\n", index, cursor)
            index = cursor + 1
        else:
            index += 1


def literal_tokens(contents: str):
    """Yield (token, is_family_stem) for each URN token in a literal."""
    position = contents.find(URN_PREFIX)
    while position >= 0:
        end = position
        while end < len(contents) and URN_CHARACTER.match(contents[end]):
            end += 1
        yield contents[position:end], contents.startswith("{", end) and not contents.startswith("{{", end)
        position = contents.find(URN_PREFIX, end)


def is_test_only(relative: Path) -> bool:
    if relative.name in ("tests.rs", "tests.inc") or relative.stem.endswith("_tests"):
        return True
    return any(TEST_DIRECTORY.search(part) for part in relative.parts[:-1])


def shipped_sources(root: Path):
    seen: set[Path] = set()
    pending: list[Path] = []
    for source_root in sorted(root.glob("crates/*/*/src")):
        for path in sorted(source_root.rglob("*")):
            if path.suffix not in (".rs", ".inc") or not path.is_file():
                continue
            relative = path.relative_to(source_root)
            if SKIPPED_DIRECTORIES.intersection(relative.parts[:-1]) or is_test_only(relative):
                continue
            pending.append(path)
    while pending:
        path = pending.pop()
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_relative_to((root / REGISTRY_MODULE).resolve()):
            continue
        text = resolved.read_text(encoding="utf-8", errors="replace")
        yield resolved, text
        for target in INCLUDE.findall(text):
            included = (resolved.parent / target).resolve()
            if included.is_file() and included.is_relative_to(root):
                pending.append(included)


def unregistered_tokens(root: Path, registry: Path) -> dict[str, list[str]]:
    urns = registered_urns(registry)
    missing: dict[str, list[str]] = {}
    for path, text in shipped_sources(root):
        for line, start, contents in string_literals(text):
            prefix_test = bool(PREFIX_TEST.search(text, max(0, start - 64), start))
            for token, interpolated in literal_tokens(contents):
                if token == URN_PREFIX:
                    continue
                family = interpolated or (prefix_test and contents == token)
                if family:
                    known = any(urn.startswith(token) for urn in urns)
                else:
                    known = token in urns
                if not known:
                    location = f"{path.relative_to(root)}:{line}"
                    missing.setdefault(token, []).append(location)
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
    missing = unregistered_tokens(root, registry)
    if missing:
        print("shipped source names Chio error URNs absent from spec/errors/registry.yaml:", file=sys.stderr)
        for token in sorted(missing):
            print(f"  {token}: {', '.join(missing[token])}", file=sys.stderr)
        return 1
    print(f"error URN registry: every shipped urn:chio:error literal is registered ({len(registered_urns(registry))} registered)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
