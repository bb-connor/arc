#!/usr/bin/env python3
"""Stop new weak negative assertions in the security crates.

`assert!(result.is_err())` in a fail-closed system is close to vacuous. Almost
any mistake produces an error, so the assertion passes when the code rejects for
the wrong reason, when an unrelated earlier validation rejects first, and often
when the feature under test does not exist at all. A negative test has to assert
which rule rejected: match the specific variant, or assert on the value that
`unwrap_err` returns.

A message argument does not help. `assert!(result.is_err(), "expected a stale
scope")` records what the author believed, and still passes if a different rule
fired, so it counts the same as the bare form here.

Scope: `crates/security`, `crates/kernel/chio-kernel` and
`crates/platform/chio-control-plane`, in test and production code alike.
Negative assertions live mostly in tests, which is exactly where the weakness
matters.

Baseline policy: the existing sites are debt, pinned one by one. Each entry in
`scripts/negative-assertions-baseline.txt` names the file, the enclosing
function, the assertion's condition text, and how many assertions of exactly
that shape the function holds. A weak assertion whose identity is not in the
baseline is new and fails, whichever file it lands in and whatever else that
file lost in the same change. The first version of this gate pinned one count
per file, which let a change strengthen an old assertion and add a new weak one
beside it without a failure; identities close that gap. Line numbers are not
part of the identity because they move with every edit above them, and the
condition text is normalised to single spaces so a reflow is not a new site.

Nothing here converts the debt, because most of it cannot be converted yet:
several distinct rejection rules currently share one error variant, which leaves
an author nothing more specific to assert. The conversions land per boundary as
each rule gets its own discriminant. The baseline carries one expiry rather than
a spread of them, because one change retires all of it. Renew only through
`--ratchet`, which re-counts each site, never upward, drops sites that no longer
exist, and moves the expiry forward but never back. The first `--ratchet`, with
no baseline file present, records the debt as it stands.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import re
import subprocess
import sys


SOURCE_PATTERNS = ("crates/*.rs", "crates/*.inc")
ASSERTION_ROOTS = (
    "crates/security/",
    "crates/kernel/chio-kernel/",
    "crates/platform/chio-control-plane/",
)
BASELINE_NAME = "negative-assertions-baseline.txt"
MODULE_SCOPE = "<module>"

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
ASSERT_CALL = re.compile(r"\bassert!\s*\(")
FN_ITEM = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
# A condition that says only "something failed". `matches!` and a boolean
# operator both mean the assertion says more than that, so they are not weak.
STRONGER_CONDITION = ("matches!", "&&", "||")


@dataclass(frozen=True)
class WeakAssertion:
    path: str
    line: int
    function: str
    condition: str

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.path, self.function, self.condition)


@dataclass(frozen=True)
class Baseline:
    expires: str
    sites: dict[tuple[str, str, str], int]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_baseline_path() -> Path:
    return Path(__file__).resolve().parent / BASELINE_NAME


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
    return [
        line
        for line in result.stdout.splitlines()
        if line and line.startswith(ASSERTION_ROOTS) and (root / line).is_file()
    ]


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


def assertion_condition(text: str, start: int) -> tuple[str, int] | None:
    """The condition argument of an `assert!` starting at `start`, and its end."""
    depth = 1
    cursor = start
    condition_end = None
    while cursor < len(text) and depth:
        char = text[cursor]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                break
        elif char == "," and depth == 1 and condition_end is None:
            condition_end = cursor
        cursor += 1
    if depth:
        return None
    return text[start : condition_end if condition_end is not None else cursor], cursor


def enclosing_function(functions: list[tuple[int, str]], offset: int) -> str:
    """The nearest `fn` declared before `offset`, which is the item holding it."""
    name = MODULE_SCOPE
    for start, candidate in functions:
        if start > offset:
            break
        name = candidate
    return name


def weak_assertions(path: str, text: str) -> list[WeakAssertion]:
    scanned = blank_rust_noise(text)
    functions = [(match.start(), match.group(1)) for match in FN_ITEM.finditer(scanned)]
    found: list[WeakAssertion] = []
    for match in ASSERT_CALL.finditer(scanned):
        parsed = assertion_condition(scanned, match.end())
        if parsed is None:
            continue
        condition, _ = parsed
        collapsed = " ".join(condition.split())
        if not collapsed.endswith(".is_err()"):
            continue
        if any(marker in collapsed for marker in STRONGER_CONDITION):
            continue
        found.append(
            WeakAssertion(
                path=path,
                line=scanned.count("\n", 0, match.start()) + 1,
                function=enclosing_function(functions, match.start()),
                condition=collapsed,
            )
        )
    return found


def count_weak(root: Path, paths: list[str]) -> dict[str, list[WeakAssertion]]:
    counted: dict[str, list[WeakAssertion]] = {}
    for path in sorted(paths):
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        if "is_err" not in text:
            continue
        found = weak_assertions(path, text)
        if found:
            counted[path] = found
    return counted


def group_sites(counted: dict[str, list[WeakAssertion]]) -> dict[tuple[str, str, str], list[WeakAssertion]]:
    sites: dict[tuple[str, str, str], list[WeakAssertion]] = {}
    for found in counted.values():
        for assertion in found:
            sites.setdefault(assertion.identity, []).append(assertion)
    return sites


def read_baseline(path: Path, failures: list[str]) -> Baseline | None:
    if not path.is_file():
        failures.append(f"{path.name}: missing; run --ratchet to record the current debt")
        return None
    expires = None
    sites: dict[tuple[str, str, str], int] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        if line.startswith("#"):
            marker = line[1:].strip()
            if marker.startswith("expires "):
                expires = marker[len("expires ") :].strip()
            continue
        fields = line.split("\t")
        if len(fields) != 4 or not fields[0].isdigit() or int(fields[0]) <= 0:
            failures.append(f"{path.name}:{number} malformed entry; expected count, path, function, condition")
            continue
        count, site_path, function, condition = fields
        if not site_path.startswith(ASSERTION_ROOTS):
            failures.append(f"{path.name}:{number} {site_path} is outside the gated crates")
        identity = (site_path, function, condition)
        if identity in sites:
            failures.append(f"{path.name}:{number} duplicate entry for {site_path} {function}")
            continue
        sites[identity] = int(count)
    if expires is None:
        failures.append(f"{path.name}: no `# expires YYYY-MM-DD` line")
        return None
    try:
        expires_on = date.fromisoformat(expires)
    except ValueError:
        failures.append(f"{path.name}: expiry {expires!r} is not an ISO date")
        return None
    if expires_on < date.today():
        failures.append(f"weak negative assertion baseline expired on {expires}")
    return Baseline(expires=expires, sites=sites)


def render_baseline(expires: str, sites: dict[tuple[str, str, str], int]) -> str:
    lines = [
        "# Weak negative assertions in the security crates, pinned by site: count,",
        "# file, enclosing function, condition. Written by",
        "# scripts/check-negative-assertions.py --ratchet; counts only shrink.",
        f"# expires {expires}",
    ]
    for (path, function, condition), count in sorted(sites.items()):
        lines.append(f"{count}\t{path}\t{function}\t{condition}")
    return "\n".join(lines) + "\n"


def next_month_end(today: date) -> date:
    year, month = (
        (today.year + 1, 1) if today.month == 12 else (today.year, today.month + 1)
    )
    if month == 12:
        return date(year, 12, 31)
    return date.fromordinal(date(year, month + 1, 1).toordinal() - 1)


def ratchet_baseline(root: Path, baseline_path: Path) -> int:
    sites = group_sites(count_weak(root, discover_sources(root)))
    previous = read_baseline(baseline_path, []) if baseline_path.is_file() else None
    kept: dict[tuple[str, str, str], int] = {}
    dropped: list[str] = []
    tightened: list[str] = []
    if previous is None:
        kept = {identity: len(found) for identity, found in sites.items()}
        expires = next_month_end(date.today()).isoformat()
    else:
        for identity, cap in previous.sites.items():
            found = sites.get(identity, [])
            if not found:
                dropped.append(f"{identity[0]} {identity[1]}: `{identity[2]}` no longer present")
                continue
            count = min(len(found), cap)
            if count < cap:
                tightened.append(f"{identity[0]} {identity[1]}: {cap} -> {count}")
            kept[identity] = count
        # Forward only. A reviewed deadline further out survives a ratchet; a
        # deadline that has arrived moves one month and the commit is the review.
        expires = max(next_month_end(date.today()).isoformat(), previous.expires)
    baseline_path.write_text(render_baseline(expires, kept), encoding="utf-8")
    for line in dropped:
        print(f"dropped: {line}")
    for line in tightened:
        print(f"tightened: {line}")
    print(
        f"weak negative assertion baseline {'recorded' if previous is None else 'ratcheted'}: "
        f"{len(kept)} sites, {sum(kept.values())} assertions, {len(dropped)} dropped, "
        f"{len(tightened)} tightened, expires {expires}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refuse new weak negative assertions in the security crates."
    )
    parser.add_argument("--root", type=Path, default=repo_root(), help="repository root")
    parser.add_argument(
        "--baseline",
        type=Path,
        default=default_baseline_path(),
        help=f"baseline file (default: scripts/{BASELINE_NAME} beside this script)",
    )
    parser.add_argument(
        "--ratchet",
        action="store_true",
        help=(
            "rewrite the baseline in place: re-count each site (never upward), "
            "drop sites that no longer exist, and move the expiry forward if it "
            "has arrived; with no baseline present, record the current debt"
        ),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    baseline_path = args.baseline.resolve()

    if args.ratchet:
        return ratchet_baseline(root, baseline_path)

    failures: list[str] = []
    baseline = read_baseline(baseline_path, failures)

    try:
        paths = discover_sources(root)
    except subprocess.CalledProcessError as exc:
        print(f"failed to list Rust sources under {root}: {exc.stderr.strip()}", file=sys.stderr)
        return 1

    counted = count_weak(root, paths)
    sites = group_sites(counted)
    total = sum(len(found) for found in counted.values())
    pinned = baseline.sites if baseline is not None else {}
    print(
        f"Weak negative assertions: {total} across {len(counted)} files, "
        f"baseline {sum(pinned.values())} assertions at {len(pinned)} sites across "
        f"{len({identity[0] for identity in pinned})} files"
        + (f", expires {baseline.expires}" if baseline is not None else "")
    )

    for identity, found in sorted(sites.items(), key=lambda item: (item[1][0].path, item[1][0].line)):
        cap = pinned.get(identity)
        first = found[0]
        if cap is None:
            failures.append(
                f"{first.path}:{first.line} new weak negative assertion in `{first.function}`: "
                f"assert!({first.condition}); assert the variant that rejected"
            )
            continue
        if len(found) > cap:
            extra = found[cap]
            failures.append(
                f"{extra.path}:{extra.line} {len(found)} weak negative assertions of the shape "
                f"assert!({extra.condition}) in `{extra.function}`, baseline pins {cap}; "
                "assert the variant that rejected"
            )

    present = set(paths)
    for identity in sorted(set(pinned) - set(sites)):
        path, function, condition = identity
        if path in present:
            failures.append(
                f"{path}: baseline entry for `{function}` assert!({condition}) no longer matches "
                "anything; remove it (run --ratchet)"
            )

    if failures:
        print("\nWeak negative assertion failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nWeak negative assertion check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
