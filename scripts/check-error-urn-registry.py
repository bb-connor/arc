#!/usr/bin/env python3
"""Require every Chio error URN named in shipped Rust source to be registered.

spec/errors/registry.yaml is the source of truth for stable error URNs, and
clients resolve severity, help and string codes from it. This gate lexes the
Rust sources under crates/*/*/src, the .inc fragments beside them, and every
file reached through a literal include! path, and checks each string literal
after decoding its escapes. Comments and character literals are not literals.

A URN token runs from `urn:chio:error:` to the next separator (whitespace,
a quote, a bracket, a comma or a semicolon) and must equal a registered URN.
Two uses name a family rather than one code, and for them the token must be
the prefix of at least one registered URN: the format string of a formatting
macro whose token is followed by a `{...}` placeholder, and a literal that is
the direct argument of `.starts_with(`. The bare namespace `urn:chio:error:`
names no code. Test-only files are skipped. Only the module generated from the
registry, crates/core/chio-errors/src/_generated, is exempt.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

URN_PREFIX = "urn:chio:error:"
SEPARATOR = re.compile(r"""[\s"'`()\[\]{}<>,;]""")
REGISTERED_URN = re.compile(r'^\s*-\s*urn:\s*"(urn:chio:error:[^"]+)"\s*$')
INCLUDE_CALL = re.compile(r"\binclude!\s*\(\s*$")
PREFIX_TEST = re.compile(r"\.starts_with\(\s*$")
FORMAT_STRING = re.compile(
    r"\b(?:(?:format|format_args|panic|print|println|eprint|eprintln|unreachable|todo|unimplemented)!\s*\(\s*"
    r"|(?:write|writeln)!\s*\(\s*[^,()]+,\s*)$"
)
ESCAPE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u\{([0-9A-Fa-f]{1,6})\}|\n\s*|(.))", re.DOTALL)
SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "0": "\0", "'": "'", '"': '"'}
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
    """Yield (line, start, contents, raw) for each string literal in `source`.

    `start` is the offset of the literal's first character, prefix included,
    and `contents` is the text between the quotes as written. Handles line and
    nested block comments, character literals and lifetimes, and normal, byte
    and raw string literals.
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
            yield line, index, source[begin:end], True
            line += source.count("\n", index, end)
            index = end + len(closer)
        elif not identifier_before and (opener := STRING_OPENER.match(source, index)):
            cursor = opener.end()
            begin = cursor
            while cursor < length and source[cursor] != '"':
                cursor += 2 if source[cursor] == "\\" else 1
            yield line, index, source[begin:cursor], False
            line += source.count("\n", index, cursor)
            index = cursor + 1
        else:
            index += 1


def decode_escapes(contents: str) -> str:
    """Apply Rust string escapes, including line continuations."""

    def replace(match: re.Match[str]) -> str:
        if match.group(1):
            return chr(int(match.group(1), 16))
        if match.group(2):
            return chr(int(match.group(2), 16))
        if match.group(3) is None:
            return ""
        return SIMPLE_ESCAPES.get(match.group(3), match.group(0))

    return ESCAPE.sub(replace, contents)


def literal_tokens(contents: str):
    """Yield (token, placeholder_follows) for each URN token in a literal."""
    position = contents.find(URN_PREFIX)
    while position >= 0:
        separator = SEPARATOR.search(contents, position)
        end = separator.start() if separator else len(contents)
        placeholder = contents.startswith("{", end) and not contents.startswith("{{", end)
        yield contents[position:end], placeholder
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
        literals = list(string_literals(text))
        yield resolved, text, literals
        for _, start, contents, raw in literals:
            if not INCLUDE_CALL.search(text, max(0, start - 64), start):
                continue
            target = contents if raw else decode_escapes(contents)
            included = (resolved.parent / target).resolve()
            if not included.is_relative_to(root) or not included.is_file():
                raise MissingInclude(
                    f"{resolved.relative_to(root)}: include! target {target} is not a file in the repository"
                )
            pending.append(included)


class MissingInclude(Exception):
    pass


def unregistered_tokens(root: Path, registry: Path) -> dict[str, list[str]]:
    urns = registered_urns(registry)
    missing: dict[str, list[str]] = {}
    for path, text, literals in shipped_sources(root):
        for line, start, written, raw in literals:
            contents = written if raw else decode_escapes(written)
            prefix_test = bool(PREFIX_TEST.search(text, max(0, start - 64), start))
            format_string = bool(FORMAT_STRING.search(text, max(0, start - 160), start))
            for token, placeholder in literal_tokens(contents):
                if token == URN_PREFIX:
                    continue
                family = (format_string and placeholder) or (prefix_test and contents == token)
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
    try:
        missing = unregistered_tokens(root, registry)
    except MissingInclude as error:
        print(f"error URN registry: {error}", file=sys.stderr)
        return 1
    if missing:
        print("shipped source names Chio error URNs absent from spec/errors/registry.yaml:", file=sys.stderr)
        for token in sorted(missing):
            print(f"  {token}: {', '.join(missing[token])}", file=sys.stderr)
        return 1
    print(f"error URN registry: every shipped urn:chio:error literal is registered ({len(registered_urns(registry))} registered)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
