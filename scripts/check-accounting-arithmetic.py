#!/usr/bin/env python3
"""Bound unchecked integer arithmetic in the accounting modules.

A `u64` subtraction below zero in a budget, quota, lease or exposure
calculation does not produce a small error. It produces the largest
representable value, which a remaining-budget comparison reads as unlimited
authority. Today that correctness rests on hand-placed comparisons spread
across several implementations of one invariant, with nothing that catches the
next implementation getting it wrong.

The compiler's own answer is `#![deny(clippy::arithmetic_side_effects)]` on each
accounting module, which belongs in those modules' own source and is therefore
owned by whoever owns those crates. This gate is the measurement that has to
exist either way: it counts the unchecked sites per module and refuses growth,
so the inventory shrinks as `checked_*` and quantity newtypes replace the
operators, and a new unchecked subtraction in the money path cannot arrive
unnoticed in the meantime.

Scope is declared, not inferred: the budget stores, the supplemental quota
surface, and any file under the kernel or the SQLite store whose path names a
budget, quota, lease or exposure. Test and benchmark scope is excluded, along
with items whose `cfg` predicate cannot hold outside a test or Kani build,
because a Kani harness subtracts under a precondition the prover discharges.
The exclusion is decided by evaluating the predicate, not by spotting a word:
`cfg(not(test))`, `cfg(not(kani))` and any predicate a feature or target could
enable are production code and stay in the scan.

The scan is lexical. Comments and literals are blanked first so an operator
inside one is not counted, keyword operands and `const`/`static` initializers
are skipped (a wrap in a constant is a compile error, not a runtime grant),
and shifts are not counted at all because `>>` is indistinguishable from nested
generics without a parser. It is a bound on how much unchecked arithmetic the
money path contains, not a proof about any single site.

Baseline policy: entries are debt, not configuration. Renew only through
`--ratchet`, which re-caps each entry at the module's current site count (caps
can only shrink), drops entries whose modules have no unchecked sites left, and
advances the expiry one month.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import subprocess
import sys


SOURCE_PATTERNS = ("*.rs", "*.inc")

# The modules this gate governs, by declaration rather than by guesswork.
ACCOUNTING_ROOTS = ("crates/kernel/", "crates/platform/chio-store-sqlite/")
ACCOUNTING_TREES = (
    "crates/kernel/chio-kernel/src/budget_store/",
    "crates/platform/chio-store-sqlite/src/budget_store/",
)
ACCOUNTING_FILES = ("crates/kernel/chio-kernel/src/supplemental_quota.rs",)
# Matched against whole path words, so `release` does not read as `lease`.
ACCOUNTING_SUBJECTS = ("budget", "quota", "lease", "exposure")
ACCOUNTING_WORDS = frozenset(
    word
    for subject in ACCOUNTING_SUBJECTS
    for word in (subject, f"{subject}s", f"{subject}d")
)

BASELINE_WAVES = 4


@dataclass(frozen=True)
class BaselineEntry:
    rationale: str
    expires: str
    max_sites: int


def allow(expires: str, rationale: str, *, max_sites: int) -> BaselineEntry:
    return BaselineEntry(rationale=rationale, expires=expires, max_sites=max_sites)


# Expiries are spread across four waves, smallest count first: the modules with
# the least unchecked arithmetic are the cheapest to finish, so they come due
# first. One shared date would leave the only available response being to move
# the date again.
BASELINE: dict[str, BaselineEntry] = {
    "crates/kernel/chio-kernel/src/budget_store/in_memory/terminal.rs": allow(
        "2027-01-31",
        "in-memory budget terminal transitions; subtraction guarded by hand today; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=14,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/terminal.rs": allow(
        "2026-12-31",
        "composite budget terminal transitions; guarded in Rust and by a SQL predicate; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=11,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/trait_impl.rs": allow(
        "2026-12-31",
        "SQLite budget store transitions; subtraction guarded in the same transaction; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=10,
    ),
    "crates/kernel/chio-kernel/src/budget_store/in_memory/admission.rs": allow(
        "2026-12-31",
        "in-memory budget admission capture counters; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=5,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/reaper.rs": allow(
        "2026-12-31",
        "budget lease reaper reconciliation counters; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=4,
    ),
    "crates/kernel/chio-kernel/src/budget_store/in_memory/trait_impl.rs": allow(
        "2026-11-30",
        "in-memory budget reconciliation counters; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=2,
    ),
    "crates/kernel/chio-kernel/src/supplemental_quota.rs": allow(
        "2026-11-30",
        "supplemental quota domain-separated message length; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=2,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/capture.rs": allow(
        "2026-11-30",
        "composite budget capture transitions; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=2,
    ),
    "crates/kernel/chio-kernel/src/budget_store/in_memory/composite.rs": allow(
        "2026-10-31",
        "in-memory composite budget account version counter; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=1,
    ),
    "crates/platform/chio-store-sqlite/src/admission_operation_store/credit_exposure.rs": allow(
        "2026-10-31",
        "credit exposure authority expiry converted from milliseconds to seconds; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=1,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/composite.rs": allow(
        "2026-10-31",
        "composite budget epoch converted from milliseconds to seconds; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=1,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/store.rs": allow(
        "2026-10-31",
        "SQLite budget store lease generation successor; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=1,
    ),
    "crates/platform/chio-store-sqlite/src/serving_owner/lease_history.rs": allow(
        "2026-11-30",
        "serving-owner lease history epoch predecessor; capped until checked arithmetic or a quantity newtype replaces the operators",
        max_sites=1,
    ),
}


PATH_WORDS = re.compile(r"[^a-z0-9]+")
TEST_SEGMENT_SUFFIXES = ("_tests", "_test")
TEST_SEGMENTS = ("tests", "benches")

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
# An outer attribute opener. The attribute's extent is found by bracket matching,
# so a `cfg` predicate may span lines and nest `all`, `any` and `not` freely.
ATTRIBUTE_START = re.compile(r"#\[")
# The cfg atoms that are false in every production build. Every other atom (a
# feature, a target, a custom flag) is unknown here and may be true.
TEST_ONLY_ATOMS = frozenset({"test", "kani"})
CFG_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z0-9_]*|[(),=]')
COMPOUND_ASSIGN = re.compile(r"(?<![=!<>+\-*/%^&|])([-+*/%])=(?!=)")
BINARY_ARITHMETIC = re.compile(r"(?<=[\w)\]])\s*([-*/%])\s*(?=[\w(&*])")
# A `+` whose right operand is a type or a lifetime is a trait bound, not a sum.
BINARY_SUM = re.compile(r"(?<=[\w)\]])\s*(\+)\s*(?=[a-z_0-9(&*])")
PRECEDING_WORD = re.compile(r"(\w+)\s*$")
CONST_ITEM = re.compile(r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:const|static)\s")
# A keyword to the left means the operator is a dereference or a unary sign, not
# a binary operation on two values.
KEYWORD_OPERANDS = frozenset(
    """as await break const continue crate dyn else enum extern fn for if impl in
    let loop match mod move mut pub ref return static struct trait type unsafe use
    where while yield""".split()
)


@dataclass(frozen=True)
class ArithmeticSite:
    path: str
    line: int
    operator: str
    source: str


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def discover_sources(root: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            *SOURCE_PATTERNS,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line and (root / line).is_file()]


def is_accounting_module(path: str) -> bool:
    if not path.startswith(ACCOUNTING_ROOTS):
        return False
    if path in ACCOUNTING_FILES or path.startswith(ACCOUNTING_TREES):
        return True
    return bool(ACCOUNTING_WORDS & set(PATH_WORDS.split(path.lower())))


def is_test_scope(path: str) -> bool:
    segments = path.split("/")
    directories, name = segments[:-1], segments[-1]
    if any(
        directory in TEST_SEGMENTS or directory.endswith(TEST_SEGMENT_SUFFIXES)
        for directory in directories
    ):
        return True
    return name == "tests.rs" or name.endswith(("_tests.rs", "_test.rs"))


def blank_span(span: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in span)


def blank_rust_noise(text: str) -> str:
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


def evaluate_cfg(predicate: str) -> bool | None:
    """Evaluate a cfg predicate under production assumptions.

    `test` and `kani` are false; every other atom is unknown. The result is
    `True`, `False`, or `None` when the atoms left unknown decide it. Only a
    predicate that is `False` here can never gate production code.
    """
    tokens = CFG_TOKEN.findall(predicate)
    position = 0

    def parse() -> bool | None:
        nonlocal position
        if position >= len(tokens):
            return None
        token = tokens[position]
        position += 1
        if token in ("all", "any", "not") and position < len(tokens) and tokens[position] == "(":
            position += 1
            operands: list[bool | None] = []
            while position < len(tokens) and tokens[position] != ")":
                if tokens[position] == ",":
                    position += 1
                    continue
                operands.append(parse())
            position += 1
            if token == "not":
                operand = operands[0] if operands else None
                return None if operand is None else not operand
            if token == "all":
                if any(operand is False for operand in operands):
                    return False
                return True if all(operand is True for operand in operands) else None
            if any(operand is True for operand in operands):
                return True
            return False if all(operand is False for operand in operands) else None
        if position < len(tokens) and tokens[position] == "=":
            position += 1
            if position < len(tokens) and tokens[position].startswith('"'):
                position += 1
        return False if token in TEST_ONLY_ATOMS else None

    return parse()


def is_test_scoped_attribute(body: str) -> bool:
    """Whether the item under this attribute exists only in a test or Kani build.

    `#[test]` and `#[kani::proof]` qualify outright. A `cfg` qualifies only when
    its predicate is false under every production configuration, so
    `cfg(not(test))`, `cfg(any(test, feature = "x"))` and
    `cfg(all(not(kani), unix))` are production code and stay in the scan.
    """
    body = body.strip()
    if body == "test" or body.startswith("kani::proof"):
        return True
    if not body.startswith("cfg"):
        return False
    predicate = body[len("cfg") :].strip()
    if not (predicate.startswith("(") and predicate.endswith(")")):
        return False
    return evaluate_cfg(predicate[1:-1]) is False


def attribute_end(text: str, opener: int) -> int:
    """Index just past the `]` that closes the attribute opening at `opener`."""
    depth = 0
    cursor = opener
    while cursor < len(text):
        char = text[cursor]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return cursor + 1
        cursor += 1
    return len(text)


def blank_test_scoped_items(text: str) -> str:
    blanked = list(text)
    for match in ATTRIBUTE_START.finditer(text):
        attribute_close = attribute_end(text, match.end() - 1)
        if not is_test_scoped_attribute(text[match.end() : attribute_close - 1]):
            continue
        cursor = attribute_close
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
        for index in range(match.start(), end):
            if blanked[index] != "\n":
                blanked[index] = " "
    return "".join(blanked)


def arithmetic_sites(path: str, text: str) -> list[ArithmeticSite]:
    scanned = blank_test_scoped_items(blank_rust_noise(text))
    source_lines = text.split("\n")
    sites: list[ArithmeticSite] = []
    for pattern in (COMPOUND_ASSIGN, BINARY_ARITHMETIC, BINARY_SUM):
        for match in pattern.finditer(scanned):
            preceding = PRECEDING_WORD.search(scanned[: match.start()])
            if preceding is not None and preceding.group(1) in KEYWORD_OPERANDS:
                continue
            line = scanned.count("\n", 0, match.start()) + 1
            if CONST_ITEM.match(source_lines[line - 1]):
                continue
            sites.append(
                ArithmeticSite(
                    path=path,
                    line=line,
                    operator=match.group(0).strip(),
                    source=source_lines[line - 1].strip(),
                )
            )
    return sorted(sites, key=lambda site: (site.line, site.operator))


def count_sites(root: Path, paths: list[str]) -> dict[str, list[ArithmeticSite]]:
    counted: dict[str, list[ArithmeticSite]] = {}
    for path in sorted(paths):
        if not is_accounting_module(path) or is_test_scope(path):
            continue
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        sites = arithmetic_sites(path, text)
        if sites:
            counted[path] = sites
    return counted


def validate_baseline(errors: list[str]) -> None:
    for path, entry in sorted(BASELINE.items()):
        if not entry.rationale.strip():
            errors.append(f"{path}: baseline entry has an empty rationale")
        if not entry.expires.strip():
            errors.append(f"{path}: baseline entry has an empty expiry date")
            continue
        try:
            expires_on = date.fromisoformat(entry.expires)
        except ValueError:
            errors.append(
                f"{path}: baseline entry expiry {entry.expires!r} is not an ISO date"
            )
            continue
        if expires_on < date.today():
            errors.append(f"{path}: baseline entry expired on {entry.expires}")
        if entry.max_sites <= 0:
            errors.append(f"{path}: baseline entry has a non-positive max_sites cap")
        if not is_accounting_module(path):
            errors.append(f"{path}: baseline entry is not an accounting module")
        if is_test_scope(path):
            errors.append(f"{path}: baseline entry names test scope")


def next_month_end(today: date) -> date:
    year, month = (
        (today.year + 1, 1) if today.month == 12 else (today.year, today.month + 1)
    )
    if month == 12:
        return date(year, 12, 31)
    return date.fromordinal(date(year, month + 1, 1).toordinal() - 1)


def wave_expiries(today: date) -> list[str]:
    deadlines = [next_month_end(today)]
    for _ in range(BASELINE_WAVES - 1):
        deadlines.append(next_month_end(deadlines[-1].replace(day=1)))
    return [deadline.isoformat() for deadline in deadlines]


def ratchet_baseline(root: Path) -> int:
    counted = count_sites(root, discover_sources(root))
    expiries = wave_expiries(date.today())
    kept: list[tuple[int, str, str]] = []
    dropped: list[str] = []
    tightened: list[str] = []
    for path, entry in BASELINE.items():
        sites = counted.get(path, [])
        if not sites:
            dropped.append(f"{path}: no unchecked arithmetic remains")
            continue
        cap = min(len(sites), entry.max_sites)
        if cap < entry.max_sites:
            tightened.append(f"{path}: cap {entry.max_sites} -> {cap}")
        kept.append((cap, path, entry.rationale))
    per_wave = max(1, -(-len(kept) // BASELINE_WAVES))
    by_cap = sorted(kept, key=lambda item: (item[0], item[1]))
    schedule = {
        path: expiries[min(index // per_wave, len(expiries) - 1)]
        for index, (_, path, _) in enumerate(by_cap)
    }
    rendered = [
        f'    "{path}": allow(\n'
        f'        "{schedule[path]}",\n'
        f'        "{rationale}",\n'
        f"        max_sites={cap},\n"
        f"    ),\n"
        for cap, path, rationale in kept
    ]
    script = Path(__file__).resolve()
    source = script.read_text(encoding="utf-8")
    start_marker = "BASELINE: dict[str, BaselineEntry] = {\n"
    start = source.index(start_marker) + len(start_marker)
    end = source.index("\n}\n", start)
    script.write_text(
        source[:start] + "".join(rendered).rstrip("\n") + source[end:], encoding="utf-8"
    )
    for line in dropped:
        print(f"dropped: {line}")
    for line in tightened:
        print(f"tightened: {line}")
    print(
        f"accounting arithmetic baseline ratcheted: {len(kept)} entries kept, "
        f"{len(dropped)} dropped, {len(tightened)} tightened, "
        f"expiries {', '.join(expiries)}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bound unchecked integer arithmetic in the accounting modules."
    )
    parser.add_argument("--root", type=Path, default=repo_root(), help="repository root")
    parser.add_argument(
        "--ratchet",
        action="store_true",
        help=(
            "rewrite the baseline in place: re-cap each entry at the module's "
            "current site count (never larger than before), drop entries whose "
            "modules have no unchecked sites left, and advance expiries one month"
        ),
    )
    args = parser.parse_args()

    if args.ratchet:
        return ratchet_baseline(args.root.resolve())

    root = args.root.resolve()
    failures: list[str] = []
    validate_baseline(failures)

    try:
        paths = discover_sources(root)
    except subprocess.CalledProcessError as exc:
        print(f"failed to list Rust sources under {root}: {exc.stderr.strip()}", file=sys.stderr)
        return 1

    counted = count_sites(root, paths)
    total = sum(len(sites) for sites in counted.values())
    print(
        f"Accounting arithmetic: {total} unchecked sites across "
        f"{len(counted)} modules"
    )
    for path, sites in sorted(counted.items(), key=lambda item: (-len(item[1]), item[0])):
        entry = BASELINE.get(path)
        marker = f"cap {entry.max_sites}, expires {entry.expires}" if entry else "no baseline entry"
        print(f"{len(sites):4d} {path} ({marker})")
        for site in sites:
            print(f"       {path}:{site.line}: {site.operator}  {site.source}")

    for path, sites in sorted(counted.items()):
        entry = BASELINE.get(path)
        if entry is None:
            failures.append(
                f"{path}: {len(sites)} unchecked arithmetic sites and no baseline "
                "entry; use checked_* or a quantity newtype, or record the debt"
            )
            continue
        if len(sites) > entry.max_sites:
            failures.append(
                f"{path}: {len(sites)} unchecked arithmetic sites, cap is "
                f"{entry.max_sites}"
            )

    present = set(paths)
    for path in sorted(set(BASELINE) - set(counted)):
        if path in present:
            failures.append(
                f"{path}: no unchecked arithmetic remains; remove its baseline "
                "entry (run --ratchet)"
            )

    if failures:
        print("\nAccounting arithmetic failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nAccounting arithmetic check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
