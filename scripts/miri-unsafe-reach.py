#!/usr/bin/env python3
"""Inventory which unit tests can reach each crate's `unsafe` code.

A Miri lane over a list of crates proves nothing about a crate whose `unsafe`
blocks no unit test executes: Miri checks the code it interprets, and a green
run over tests that never enter an `unsafe` block is a green run over safe
Rust. Before a crate goes on the lane's list, this inventory shows, per
`unsafe` site, which unit tests can reach the function that contains it. A
crate with `unsafe` and no reaching test is reported so it is left off the
list rather than counted as covered.

The analysis is static and by name. It scans a crate's production source for
`unsafe` blocks, `unsafe fn` items and `unsafe impl` items, records the
function each block sits in, builds a call graph from the identifiers each
function body calls, and walks it from every `#[test]` function in the crate,
including the crate's own test modules. Two functions with the same name in
different modules are conflated, closures and trait dispatch are followed by
method name only, and macros are opaque, so the result over-approximates:
"reaches" means a name-based call chain exists, not that the test executed the
block. It never under-approximates a direct chain, which is what the lane's
list needs: a crate reported with no reaching test has none.

Usage: miri-unsafe-reach.py [--root DIR] [--depth N] CRATE_DIR...

Output is one section per crate: each `unsafe` site with its enclosing
function, the tests that reach it (or `unreached`), and a summary line the
lane's classification document quotes.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
import re
import sys


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
FN_ITEM = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<|\()")
TEST_ATTRIBUTE = re.compile(r"#\[\s*(?:[A-Za-z_:]*::)?test(?:\s*\([^)]*\))?\s*\]")
UNSAFE_SITE = re.compile(r"\bunsafe\s*(\{|fn\b|impl\b)")
CALL = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*(?:::<[^;{}]*?>)?\s*\(")
KEYWORDS = {
    "if", "while", "for", "match", "return", "loop", "fn", "let", "unsafe", "as", "in",
    "move", "ref", "mut", "impl", "where", "async", "await", "dyn", "use", "mod", "pub",
    "else", "break", "continue", "true", "false", "Some", "Ok", "Err", "None", "Box",
    "Vec", "String", "vec", "assert", "assert_eq", "assert_ne", "panic", "format",
    "println", "eprintln", "write", "writeln", "debug_assert", "unreachable", "todo",
    "matches", "Self", "self", "super", "crate", "drop", "Default", "Option", "Result",
}


@dataclass
class Function:
    name: str
    path: str
    line: int
    start: int
    end: int
    calls: set[str] = field(default_factory=set)
    unsafe_sites: list[str] = field(default_factory=list)
    is_test: bool = False


def blank_span(span: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in span)


def blank_rust_noise(text: str) -> str:
    """Blank comments and literals so braces and names inside them do not count."""
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
            chunks.append(blank_span(text[match.start() : end]))
            position = end
            continue
        chunks.append(blank_span(match.group(0)))
        position = match.end()


def body_span(text: str, start: int) -> tuple[int, int] | None:
    """The brace-delimited body of the item whose header begins at `start`."""
    cursor = start
    depth_angle = 0
    while cursor < len(text):
        char = text[cursor]
        if char == "<":
            depth_angle += 1
        elif char == ">":
            depth_angle = max(0, depth_angle - 1)
        elif char == ";" and depth_angle == 0:
            return None
        elif char == "{" and depth_angle == 0:
            break
        cursor += 1
    else:
        return None
    depth = 0
    for index in range(cursor, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return cursor, index + 1
    return cursor, len(text)


def source_files(crate: Path) -> list[Path]:
    return sorted(
        path
        for path in (crate / "src").rglob("*")
        if path.suffix in (".rs", ".inc") and path.is_file()
    )


def analyse(root: Path, crate_dir: str) -> tuple[list[Function], int]:
    functions: list[Function] = []
    site_count = 0
    crate = root / crate_dir
    for path in source_files(crate):
        raw = path.read_text(encoding="utf-8", errors="replace")
        text = blank_rust_noise(raw)
        relative = path.relative_to(root).as_posix()
        file_functions: list[Function] = []
        for match in FN_ITEM.finditer(text):
            span = body_span(text, match.end())
            if span is None:
                continue
            preceding = text[max(0, match.start() - 400) : match.start()]
            attribute_region = preceding.rsplit("}", 1)[-1]
            function = Function(
                name=match.group(1),
                path=relative,
                line=text.count("\n", 0, match.start()) + 1,
                start=span[0],
                end=span[1],
                is_test=TEST_ATTRIBUTE.search(attribute_region) is not None,
            )
            file_functions.append(function)
        for function in file_functions:
            body = text[function.start : function.end]
            function.calls = {
                name for name in CALL.findall(body) if name not in KEYWORDS
            }
        for match in UNSAFE_SITE.finditer(text):
            site_count += 1
            line = text.count("\n", 0, match.start()) + 1
            kind = {"{": "block", "fn": "fn", "impl": "impl"}[match.group(1)]
            enclosing = [
                function
                for function in file_functions
                if function.start <= match.start() < function.end
            ]
            if enclosing:
                innermost = max(enclosing, key=lambda function: function.start)
                innermost.unsafe_sites.append(f"{relative}:{line} unsafe {kind}")
            else:
                orphan = Function(
                    name=f"<item at {relative}:{line}>",
                    path=relative,
                    line=line,
                    start=match.start(),
                    end=match.end(),
                )
                orphan.unsafe_sites.append(f"{relative}:{line} unsafe {kind}")
                file_functions.append(orphan)
        functions.extend(file_functions)
    return functions, site_count


def reach(functions: list[Function], depth: int) -> dict[str, list[str]]:
    """Unsafe site -> tests whose name-based call chain reaches its function."""
    by_name: dict[str, list[Function]] = {}
    for function in functions:
        by_name.setdefault(function.name, []).append(function)
    reached: dict[str, list[str]] = {}
    for test in functions:
        if not test.is_test:
            continue
        seen = {test.name}
        frontier = deque([(test, 0)])
        while frontier:
            current, distance = frontier.popleft()
            for site in current.unsafe_sites:
                reached.setdefault(site, []).append(f"{test.name} ({test.path}:{test.line})")
            if distance >= depth:
                continue
            for callee in sorted(current.calls):
                if callee in seen:
                    continue
                seen.add(callee)
                for target in by_name.get(callee, []):
                    frontier.append((target, distance + 1))
    return reached


def main() -> int:
    parser = argparse.ArgumentParser(description="Which unit tests reach each crate's unsafe code.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--depth", type=int, default=6, help="maximum call-chain length")
    parser.add_argument("crates", nargs="+", help="crate directories relative to the root")
    args = parser.parse_args()
    root = args.root.resolve()

    for crate_dir in args.crates:
        if not (root / crate_dir / "src").is_dir():
            print(f"{crate_dir}: no src directory", file=sys.stderr)
            return 1
        functions, site_count = analyse(root, crate_dir)
        reached = reach(functions, args.depth)
        tests = sum(1 for function in functions if function.is_test)
        sites = sorted(
            {site for function in functions for site in function.unsafe_sites},
            key=lambda site: (site.split(":")[0], int(site.split(":")[1].split()[0])),
        )
        print(f"## {crate_dir}")
        for site in sites:
            tests_for_site = sorted(set(reached.get(site, [])))
            enclosing = next(
                (function.name for function in functions if site in function.unsafe_sites),
                "?",
            )
            if tests_for_site:
                print(f"- {site} in `{enclosing}`: reached by {len(tests_for_site)} test(s)")
                for name in tests_for_site[:8]:
                    print(f"    - {name}")
                if len(tests_for_site) > 8:
                    print(f"    - and {len(tests_for_site) - 8} more")
            else:
                print(f"- {site} in `{enclosing}`: unreached")
        reached_sites = sum(1 for site in sites if reached.get(site))
        print(
            f"summary: {crate_dir}: {site_count} unsafe sites, {reached_sites} reached by a "
            f"name-based call chain from {tests} unit tests, {site_count - reached_sites} unreached"
        )
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
