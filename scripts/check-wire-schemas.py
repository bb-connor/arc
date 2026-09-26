#!/usr/bin/env python3
"""Make every wire-schema identifier change an acknowledged change.

A schema or domain identifier such as `chio.receipt.v1` is the name a reader
uses to decide whether it understands a payload. The constants that carry them
are typed by hand, hundreds of them, and a bump from `.v1` to `.v2` compiles
cleanly in the producer and is caught only where a test happens to hardcode the
old literal. The caller-return-context bump from v4 to v6 was found that way,
by two round-trip tests that pinned the literal; most identifiers here have no
such test, so a bump to them would be caught by nothing.

`spec/wire-schemas.lock` is a snapshot of every hand-written identifier
constant under `crates/`: the value, the production files that declare it and
the commit the value was first seen in. The gate refuses a tree whose
declarations disagree with the lock in either direction: an identifier value
that is declared and not recorded (new, or bumped), and a recorded value that a
listed file no longer declares (removed, or bumped). A value declared in more
than one file is recorded with every file and is not a failure here; the
consolidation of duplicates is source work and belongs to the crate owners.

What this does and does not establish. Passing this gate means an identifier
change was acknowledged by editing the lock in the same change, and nothing
more. It says nothing about compatibility: a payload's fields can change while
the identifier stays the same, and bumping identifier and lock together says
nothing about historical readers. Compatibility is a separate property that
needs a canonical-byte shape fixture and an old-reader test per schema.

Scope: `const` or `static` `&str` items under `crates/` whose value starts with
`chio` and carries a version segment (`v1`, `v2`, ...) delimited by `.`, `:`,
`-`, `/` or `_`. Test paths, items behind a `test` or `test-support` cfg, and
`_generated` output are not declarations: a test literal is a pin, and the
codegen output is pinned by the spec it is generated from. Byte-string domain
constants are covered by `check-domain-separation.py`.

`spec/wire-schemas-unpinned.md`, next to the lock, lists the identifier
constants in the security crates whose value appears in no test-scope literal,
fixture or `spec/` file, so their owners know which shape fixtures to write. A
value counts as pinned when it occurs as a token in a test-path Rust file, in a
test-scoped item of a production file, in a fixture under a test directory, or
anywhere under `spec/`. The gate fails only when an unpinned constant is absent
from that list, since that is the direction that could hide a gap; an entry
that has since been pinned is stale in the safe direction and is refreshed by
`--update`.

`--update` rewrites the lock and the report from the tree. A value new to the
lock gets the earliest commit in which its quoted literal appears under
`crates/` (`git log -S`), or the current HEAD when history does not show it;
values already recorded keep their commit. Both files are written in one
deterministic order, so a second `--update` on the same tree is a no-op.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys
import tomllib


SOURCE_PATTERNS = ("crates/*.rs", "crates/*.inc")
FIXTURE_PATTERNS = ("crates/*", "spec/*")
FIXTURE_SUFFIXES = (".json", ".ndjson", ".toml", ".yaml", ".yml", ".txt", ".md", ".rs", ".inc")
LOCK_PATH = "spec/wire-schemas.lock"
REPORT_PATH = "spec/wire-schemas-unpinned.md"
LOCK_VERSION = 1

SECURITY_CRATES = (
    "crates/security/",
    "crates/kernel/chio-kernel/",
    "crates/kernel/chio-kernel-core/",
    "crates/kernel/chio-kernel-browser/",
    "crates/kernel/chio-kernel-mobile/",
    "crates/platform/chio-control-plane/",
    "crates/platform/chio-store-sqlite/",
    "crates/core/chio-core-types/",
)

TEST_SEGMENTS = ("tests", "benches", "fixtures", "testdata")
TEST_SEGMENT_SUFFIXES = ("_tests", "_test")
GENERATED_SEGMENT = "_generated"

DECLARATION = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:"
    r"\s*&\s*(?:'static\s+)?str\s*=\s*\"(?P<value>(?:[^\"\\]|\\.)*)\"",
    re.S,
)
IDENTIFIER_SHAPE = re.compile(r"\Achio[._:/-][A-Za-z0-9._:/-]*\Z")
VERSION_SEGMENT = re.compile(r"(?<![A-Za-z0-9])v[0-9]+(?![A-Za-z0-9])")
IDENTIFIER_TOKEN = re.compile(r"chio[._:/-][A-Za-z0-9._:/-]*")
RUST_NOISE = re.compile(
    r"""
      //[^\n]*                            # line comment
    | /\*                                 # block comment; nesting handled below
    | (?:b|c)?r(\#*)"                     # raw string opener, hashes captured
    | (?:b|c)?"(?:[^"\\]|(?s:\\.))*"      # string, including \<newline> continuation
    | b?'(?:(?s:\\.)|[^\\'])'             # char literal, never a lifetime
    """,
    re.VERBOSE,
)
TEST_SCOPED_ITEM = re.compile(
    r"#\[\s*cfg\s*\([^\n]*\b(?:test|test-support)\b[^\n]*\)\s*\]"
)


@dataclass(frozen=True)
class Declaration:
    path: str
    line: int
    name: str
    value: str


@dataclass(frozen=True)
class LockEntry:
    value: str
    files: tuple[str, ...]
    first_seen: str
    line: int


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def git_files(root: Path, patterns: tuple[str, ...]) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", *patterns],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return sorted(
        line for line in result.stdout.splitlines() if line and (root / line).is_file()
    )


def is_test_path(path: str) -> bool:
    segments = path.split("/")
    directories, name = segments[:-1], segments[-1]
    if any(
        directory in TEST_SEGMENTS or directory.endswith(TEST_SEGMENT_SUFFIXES)
        for directory in directories
    ):
        return True
    return name == "tests.rs" or name.endswith(("_tests.rs", "_test.rs"))


def is_generated_path(path: str) -> bool:
    return GENERATED_SEGMENT in path.split("/")


def blank_span(span: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in span)


def blank_rust_comments(text: str) -> str:
    """Blank comments, keep literals. An identifier lives inside a literal."""
    chunks: list[str] = []
    position = 0
    while True:
        match = RUST_NOISE.search(text, position)
        if match is None:
            chunks.append(text[position:])
            return "".join(chunks)
        chunks.append(text[position : match.start()])
        if match.group(0) == "/*":
            end = match.end()
            depth = 1
            while depth and end < len(text):
                opened = text.find("/*", end)
                closed = text.find("*/", end)
                if closed == -1:
                    end = len(text)
                    break
                if opened != -1 and opened < closed:
                    depth += 1
                    end = opened + 2
                else:
                    depth -= 1
                    end = closed + 2
            chunks.append(blank_span(text[match.start() : end]))
            position = end
            continue
        if match.group(1) is not None:
            terminator = '"' + match.group(1)
            end = text.find(terminator, match.end())
            end = len(text) if end == -1 else end + len(terminator)
            chunks.append(text[match.start() : end])
            position = end
            continue
        if match.group(0).startswith("//"):
            chunks.append(blank_span(match.group(0)))
        else:
            chunks.append(match.group(0))
        position = match.end()


def test_scoped_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in TEST_SCOPED_ITEM.finditer(text):
        cursor = match.end()
        depth = 0
        body = None
        while cursor < len(text):
            char = text[cursor]
            if char == "{":
                depth += 1
                if body is None:
                    body = cursor
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            elif char == ";" and depth == 0:
                break
            cursor += 1
        end = min(cursor + 1 if body is not None else cursor, len(text))
        spans.append((match.start(), end))
    return spans


def in_spans(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)


def is_identifier(value: str) -> bool:
    return IDENTIFIER_SHAPE.match(value) is not None and VERSION_SEGMENT.search(value) is not None


def collect(root: Path) -> tuple[list[Declaration], dict[str, set[str]]]:
    """Production declarations, and the files each identifier token is pinned in."""
    declarations: list[Declaration] = []
    pins: dict[str, set[str]] = {}
    sources = set(git_files(root, SOURCE_PATTERNS))
    for path in git_files(root, FIXTURE_PATTERNS):
        if not path.endswith(FIXTURE_SUFFIXES) or path in (LOCK_PATH, REPORT_PATH):
            continue
        rust = path in sources
        if not rust and not (path.startswith("spec/") or is_test_path(path)):
            continue
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        if "chio" not in text:
            continue
        if not rust:
            for token in IDENTIFIER_TOKEN.findall(text):
                pins.setdefault(token, set()).add(path)
            continue
        readable = blank_rust_comments(text)
        if is_test_path(path) or is_generated_path(path):
            if is_test_path(path):
                for token in IDENTIFIER_TOKEN.findall(readable):
                    pins.setdefault(token, set()).add(path)
            continue
        spans = test_scoped_spans(readable)
        for start, end in spans:
            for token in IDENTIFIER_TOKEN.findall(readable[start:end]):
                pins.setdefault(token, set()).add(path)
        for match in DECLARATION.finditer(readable):
            value = match.group("value")
            if not is_identifier(value) or in_spans(match.start(), spans):
                continue
            declarations.append(
                Declaration(
                    path=path,
                    line=readable.count("\n", 0, match.start()) + 1,
                    name=match.group("name"),
                    value=value,
                )
            )
    return declarations, pins


def read_lock(root: Path) -> tuple[dict[str, LockEntry], list[str]]:
    failures: list[str] = []
    path = root / LOCK_PATH
    if not path.is_file():
        return {}, [f"{LOCK_PATH}:1 missing; run `{Path(__file__).name} --update` to create it"]
    text = path.read_text(encoding="utf-8")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return {}, [f"{LOCK_PATH}:1 unreadable: {exc}"]
    if data.get("version") != LOCK_VERSION:
        failures.append(f"{LOCK_PATH}:1 version {data.get('version')!r}, expected {LOCK_VERSION}")
    entries: dict[str, LockEntry] = {}
    lines = text.splitlines()
    for entry in data.get("schema", []):
        value = entry.get("value")
        files = entry.get("files")
        first_seen = entry.get("first_seen")
        if not isinstance(value, str) or not isinstance(files, list) or not isinstance(first_seen, str):
            failures.append(f"{LOCK_PATH}:1 entry {entry!r} lacks value, files or first_seen")
            continue
        line = next(
            (index + 1 for index, text_line in enumerate(lines) if text_line == f'value = "{value}"'),
            1,
        )
        if value in entries:
            failures.append(f"{LOCK_PATH}:{line} {value} is recorded twice")
            continue
        if not files:
            failures.append(f"{LOCK_PATH}:{line} {value} lists no declaring file")
        if list(files) != sorted(set(files)):
            failures.append(f"{LOCK_PATH}:{line} {value} lists files out of order or twice")
        entries[value] = LockEntry(value=value, files=tuple(files), first_seen=first_seen, line=line)
    return entries, failures


def toml_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_lock(entries: dict[str, LockEntry]) -> str:
    lines = [
        "# Wire-schema identifier snapshot, maintained by scripts/check-wire-schemas.py.",
        "# Refresh with `--update`; the gate refuses a tree that disagrees with it.",
        "# An entry acknowledges an identifier's existence and where it is declared.",
        "# It is not a compatibility statement about the payload behind it.",
        f"version = {LOCK_VERSION}",
    ]
    for value in sorted(entries):
        entry = entries[value]
        files = ", ".join(toml_string(path) for path in entry.files)
        lines.extend(
            [
                "",
                "[[schema]]",
                f"value = {toml_string(value)}",
                f"files = [{files}]",
                f"first_seen = {toml_string(entry.first_seen)}",
            ]
        )
    return "\n".join(lines) + "\n"


def unpinned(declarations: list[Declaration], pins: dict[str, set[str]]) -> list[Declaration]:
    return sorted(
        (
            declaration
            for declaration in declarations
            if declaration.path.startswith(SECURITY_CRATES) and declaration.value not in pins
        ),
        key=lambda declaration: (declaration.path, declaration.line, declaration.name),
    )


def render_report(gaps: list[Declaration], total: int) -> str:
    by_crate: dict[str, list[Declaration]] = {}
    for declaration in gaps:
        crate = "/".join(declaration.path.split("/")[:3])
        by_crate.setdefault(crate, []).append(declaration)
    lines = [
        "# Wire-schema identifiers without a pin",
        "",
        "Identifier constants in the security crates whose value appears in no",
        "test-scope literal, fixture or `spec/` file. Each needs a canonical-byte",
        "shape fixture and an old-reader test that names the value independently",
        "of the constant, so that a bump is caught by a test and not only by the",
        "lock. Written by `scripts/check-wire-schemas.py --update`; the gate fails",
        "when an unpinned constant is missing from this list, and an entry that has",
        "since been pinned is removed by the next `--update`.",
        "",
        f"{len(gaps)} of {total} identifier constants in the security crates are unpinned.",
    ]
    for crate in sorted(by_crate):
        lines.extend(["", f"## {crate} ({len(by_crate[crate])})", ""])
        for declaration in by_crate[crate]:
            lines.append(
                f"- `{declaration.path}:{declaration.line}` `{declaration.name}` = `{declaration.value}`"
            )
    return "\n".join(lines) + "\n"


def listed_in_report(root: Path) -> set[tuple[str, str]]:
    path = root / REPORT_PATH
    if not path.is_file():
        return set()
    listed: set[tuple[str, str]] = set()
    for match in re.finditer(
        r"^- `(?P<path>[^`:]+):(?P<line>\d+)` `(?P<name>[^`]+)` = `(?P<value>[^`]+)`$",
        path.read_text(encoding="utf-8"),
        re.M,
    ):
        listed.add((match.group("path"), match.group("value")))
    return listed


def first_seen_commit(root: Path, value: str) -> str:
    log = subprocess.run(
        ["git", "-C", str(root), "log", f'-S"{value}"', "--format=%h", "--abbrev=10", "--reverse", "--", "crates"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    commits = log.stdout.split()
    if log.returncode == 0 and commits:
        return commits[0]
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--short=10", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return head.stdout.strip() if head.returncode == 0 and head.stdout.strip() else "unrecorded"


def update(root: Path) -> int:
    declarations, pins = collect(root)
    previous, _ = read_lock(root)
    grouped: dict[str, set[str]] = {}
    for declaration in declarations:
        grouped.setdefault(declaration.value, set()).add(declaration.path)
    entries = {
        value: LockEntry(
            value=value,
            files=tuple(sorted(files)),
            first_seen=previous[value].first_seen if value in previous else first_seen_commit(root, value),
            line=0,
        )
        for value, files in grouped.items()
    }
    (root / LOCK_PATH).parent.mkdir(parents=True, exist_ok=True)
    (root / LOCK_PATH).write_text(render_lock(entries), encoding="utf-8")
    security_total = sum(1 for declaration in declarations if declaration.path.startswith(SECURITY_CRATES))
    gaps = unpinned(declarations, pins)
    (root / REPORT_PATH).write_text(render_report(gaps, security_total), encoding="utf-8")
    print(
        f"Wire schemas: wrote {len(entries)} identifiers to {LOCK_PATH} "
        f"({len(entries) - len(set(entries) & set(previous))} new, "
        f"{len(set(previous) - set(entries))} retired) and {len(gaps)} unpinned "
        f"security-crate constants to {REPORT_PATH}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check wire-schema identifiers against the lock.")
    parser.add_argument("--root", type=Path, default=repo_root(), help="repository root")
    parser.add_argument(
        "--update",
        action="store_true",
        help="rewrite the lock and the unpinned report from the tree",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    try:
        if args.update:
            return update(root)
        declarations, pins = collect(root)
    except subprocess.CalledProcessError as exc:
        print(f"failed to list files under {root}: {exc.stderr.strip()}", file=sys.stderr)
        return 1

    entries, failures = read_lock(root)
    declared: dict[tuple[str, str], Declaration] = {}
    for declaration in declarations:
        declared.setdefault((declaration.value, declaration.path), declaration)
    recorded = {(value, path) for value, entry in entries.items() for path in entry.files}

    unrecorded = sorted(
        (declared[key] for key in set(declared) - recorded),
        key=lambda declaration: (declaration.path, declaration.line, declaration.name),
    )
    for declaration in unrecorded:
        known = declaration.value in entries
        failures.append(
            f"{declaration.path}:{declaration.line} {declaration.name} = \"{declaration.value}\" "
            + (
                "is declared in a file the lock does not list for it"
                if known
                else "is not in the lock (new or bumped identifier)"
            )
            + "; acknowledge it with --update in the same change"
        )
    for value, path in sorted(recorded - set(declared)):
        entry = entries[value]
        failures.append(
            f"{LOCK_PATH}:{entry.line} {value} lists {path}, which no longer declares it "
            "(removed or bumped identifier); acknowledge it with --update in the same change"
        )

    listed = listed_in_report(root)
    gaps = unpinned(declarations, pins)
    for declaration in gaps:
        if (declaration.path, declaration.value) not in listed:
            failures.append(
                f"{declaration.path}:{declaration.line} {declaration.name} = \"{declaration.value}\" "
                f"has no pinning literal and is not listed in {REPORT_PATH}; add a shape fixture "
                "or run --update"
            )

    distinct = {declaration.value for declaration in declarations}
    files_per_value: dict[str, set[str]] = {}
    for declaration in declarations:
        files_per_value.setdefault(declaration.value, set()).add(declaration.path)
    duplicated = sum(1 for files in files_per_value.values() if len(files) > 1)
    security_total = sum(1 for declaration in declarations if declaration.path.startswith(SECURITY_CRATES))
    print(
        f"Wire schemas: {len(declarations)} identifier constants, {len(distinct)} distinct values, "
        f"{duplicated} declared in more than one file, {len(entries)} lock entries; "
        f"{len(gaps)} of {security_total} security-crate constants unpinned"
    )

    if failures:
        print("\nWire schema failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nWire schema check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
