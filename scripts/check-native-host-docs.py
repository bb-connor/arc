#!/usr/bin/env python3
"""Gate for the native host program documents and public positioning copy.

Rules (NORTH-STAR-FLOWS section 7, unified roadmap section 9):

- links: relative Markdown links and anchors in the program set resolve.
- retired-phrases: retired positioning phrases do not appear in the program
  set or the public copy. SVG text nodes and alt/aria-label/title attributes
  are scanned with tags removed, so a phrase split across elements is found.
- em-dash: no U+2014 in the program set or the public copy.
- case-ids: every Q, C and H case referenced in the program set is defined
  exactly once in CASES.md.
- budgets: word budgets for the shared spec set, each annex and each plan.

Output is one `RULE: path: message` line per violation. Exit 0 when clean,
1 when any violation is found, 2 on a usage or read error (fail closed).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]

RETIRED = (
    "The kernel your agents answer to",
    "Agents that pay each other",
    "only protocol",
    "kernel for building agentic operating systems",
)
CASE_ID = re.compile(r"\b(Q(?:0[1-9]|[1-9][0-9])|C(?:0[1-9]|1[0-9])|H0[1-8][ab]?)\b")
CASE_ROW = re.compile(r"^\|\s*(Q\d\d|C\d\d|H0[1-8][ab]?)\s*\|", re.M)
LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.M)
FENCE = re.compile(r"^(```|~~~).*?^\1[^\n]*$", re.M | re.S)
INLINE_CODE = re.compile(r"`[^`\n]*`")
SVG_ATTR = re.compile(r"\b(?:alt|aria-label|title)\s*=\s*(\"[^\"]*\"|'[^']*')", re.I)
SVG_TAG = re.compile(r"<[^>]*>")
SVG_TEXT_BLOCK = re.compile(r"<(?:style|script)\b.*?</(?:style|script)>", re.I | re.S)


class Layout:
    """Every path the rules read, computed from one repository root."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.spec = root / "docs/superpowers/specs/2026-10-07-desktop-integration"
        self.omarchy = root / "docs/superpowers/specs/2026-10-07-omarchy-integration"
        self.macos = root / "docs/superpowers/specs/2026-10-07-macos-integration"
        self.plans = root / "docs/superpowers/plans"
        self.cases = self.spec / "CASES.md"
        program = (
            list(self.spec.rglob("*.md"))
            + list(self.omarchy.rglob("*.md"))
            + list(self.macos.rglob("*.md"))
            + [root / "docs/superpowers/specs/2026-10-07-omarchy-integration-design.md"]
            + [self.plans / "2026-10-07-desktop-integration.md"]
            + list(self.plans.glob("2026-10-07-*-integration/*.md"))
            + list(self.plans.glob("2026-10-08-*.md"))
            + [root / "docs/architecture/PROGRAM-MAP.md"]
            + list((root / "docs/adr").glob("ADR-0038-*.md"))
        )
        self.program = sorted({p for p in program if p.is_file()})
        public = (
            [root / "README.md", root / "AGENTS.md"]
            + list((root / "docs/start-here").rglob("*.md"))
            + [root / "docs/reference/COMPETITIVE_LANDSCAPE.md", root / "spec/PROTOCOL.md"]
            + list((root / "docs/assets").glob("*.svg"))
        )
        self.public = sorted({p for p in public if p.is_file()})
        # Inputs that quote retired phrases on purpose: the governing design
        # and ADR that retire them, the plan that removes them, and the
        # dated architecture reviews that recorded them.
        self.retired_allowlist = {
            self.spec / "NORTH-STAR-FLOWS.md",
            root / "docs/adr/ADR-0038-native-host-program.md",
            self.omarchy / "reviews/2026-10-07-architecture-review.md",
            self.macos / "reviews/2026-10-07-architecture-review.md",
            self.plans / "2026-10-08-north-star-restructure.md",
        }
        # REVIEW.md and TRIM-LEDGER.md are audit records, not specification.
        shared = [p for p in self.spec.glob("*.md") if p.name not in {"REVIEW.md", "TRIM-LEDGER.md"}]
        self.budgets = [
            ("shared spec set", self.spec, sorted(shared), 15000),
            ("omarchy annex", self.omarchy / "ANNEX.md", [self.omarchy / "ANNEX.md"], 6000),
            ("macos annex", self.macos / "ANNEX.md", [self.macos / "ANNEX.md"], 6000),
            ("shared plan", self.plans / "2026-10-07-desktop-integration.md",
             [self.plans / "2026-10-07-desktop-integration.md"], 8000),
            ("omarchy plan", self.plans / "2026-10-07-omarchy-integration/IMPLEMENTATION.md",
             [self.plans / "2026-10-07-omarchy-integration/IMPLEMENTATION.md"], 8000),
            ("macos plan", self.plans / "2026-10-07-macos-integration/IMPLEMENTATION.md",
             [self.plans / "2026-10-07-macos-integration/IMPLEMENTATION.md"], 8000),
        ]

    def rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def slug(text: str) -> str:
    """GitHub heading anchor: lowercase, drop punctuation, spaces to hyphens."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[`*]", "", text.lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.strip().replace(" ", "-")


def anchors(text: str) -> set[str]:
    seen: dict[str, int] = {}
    out = set()
    for heading in HEADING.findall(FENCE.sub("", text)):
        base = slug(heading)
        count = seen.get(base, 0)
        seen[base] = count + 1
        out.add(base if count == 0 else f"{base}-{count}")
    return out


def prose(text: str) -> str:
    """Markdown with fenced blocks and inline code removed."""
    return INLINE_CODE.sub("", FENCE.sub("", text))


def check_links(layout: Layout) -> list[str]:
    out = []
    for path in layout.program:
        for target in LINK.findall(prose(read(path))):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
                continue
            file_part, _, anchor = target.partition("#")
            dest = (path.parent / file_part).resolve() if file_part else path
            if file_part and not dest.exists():
                out.append(f"links: {layout.rel(path)}: missing target {target}")
                continue
            if anchor and dest.suffix == ".md" and anchor not in anchors(read(dest)):
                out.append(f"links: {layout.rel(path)}: missing anchor {target}")
    return out


def visible_text(path: Path, text: str) -> str:
    if path.suffix == ".svg":
        attrs = " ".join(value[1:-1] for value in SVG_ATTR.findall(text))
        body = SVG_TAG.sub(" ", SVG_TEXT_BLOCK.sub(" ", text))
        text = f"{attrs} {body}"
    return re.sub(r"\s+", " ", text).lower()


def check_retired(layout: Layout) -> list[str]:
    out = []
    for path in sorted(set(layout.program) | set(layout.public)):
        if path in layout.retired_allowlist:
            continue
        text = visible_text(path, read(path))
        for phrase in RETIRED:
            # "verify-only protocol" is not an "only protocol" claim.
            if re.search(r"(?<![\w-])" + re.escape(phrase.lower()) + r"\b", text):
                out.append(f"retired-phrases: {layout.rel(path)}: contains '{phrase}'")
    return out


def check_em_dash(layout: Layout) -> list[str]:
    out = []
    for path in sorted(set(layout.program) | set(layout.public)):
        for number, line in enumerate(read(path).splitlines(), start=1):
            if "\u2014" in line:
                out.append(f"em-dash: {layout.rel(path)}: line {number} contains U+2014")
    return out


def check_case_ids(layout: Layout) -> list[str]:
    if not layout.cases.is_file():
        return [f"case-ids: {layout.rel(layout.cases)}: CASES.md does not exist"]
    rows = CASE_ROW.findall(read(layout.cases))
    out = [
        f"case-ids: {layout.rel(layout.cases)}: duplicate row {case}"
        for case in sorted({r for r in rows if rows.count(r) > 1})
    ]
    defined = set(rows)
    for path in layout.program:
        if path == layout.cases or {"research", "reviews"} & set(path.relative_to(layout.root).parts):
            continue
        for ref in sorted(set(CASE_ID.findall(read(path)))):
            if ref not in defined:
                out.append(f"case-ids: {layout.rel(path)}: references {ref}, not defined in CASES.md")
    return out


def check_budgets(layout: Layout) -> list[str]:
    out = []
    for name, where, files, limit in layout.budgets:
        words = sum(len(read(p).split()) for p in files if p.is_file())
        if words > limit:
            out.append(f"budgets: {layout.rel(where)}: {name} has {words} words, exceeds {limit}")
    return out


RULES = {
    "links": check_links,
    "retired-phrases": check_retired,
    "em-dash": check_em_dash,
    "case-ids": check_case_ids,
    "budgets": check_budgets,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rule", action="append", choices=sorted(RULES), help="rule to run (repeatable; default all)")
    parser.add_argument("--only", action="append", default=[], metavar="PATH",
                        help="report only violations under this repository-relative path (repeatable)")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"error: root {root} is not a directory", file=sys.stderr)
        return 2
    try:
        layout = Layout(root)
        violations = [v for name in (args.rule or sorted(RULES)) for v in RULES[name](layout)]
    except (OSError, UnicodeDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    prefixes = [p.strip("/") for p in args.only]
    if prefixes:
        violations = [
            v for v in violations
            if any(v.split(": ", 2)[1] == p or v.split(": ", 2)[1].startswith(p + "/") for p in prefixes)
        ]
    for violation in violations:
        print(violation)
    print(f"{len(violations)} violation(s)", file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
