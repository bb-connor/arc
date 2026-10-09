#!/usr/bin/env python3
"""Gate for the native host program documents and public positioning copy.

Rules (NORTH-STAR-FLOWS section 7, unified roadmap section 9):

- links: relative Markdown links and anchors in the program set resolve.
  Inline destinations are parsed per CommonMark (titles in any quoting,
  angle-bracket destinations with spaces, percent-encoding); an inline link
  that does not parse is reported rather than skipped.
- retired-phrases: retired positioning phrases do not appear in the program
  set or the public copy (README, AGENTS, the ADR index, docs/start-here,
  the competitive landscape, spec/PROTOCOL.md and docs/assets SVGs). SVG text nodes and alt/aria-label/title attributes
  are scanned with tags removed, so a phrase split across elements is found.
- em-dash: no U+2014 in the program set or the public copy.
- case-ids: every Q, C and H case referenced in the program set is defined
  exactly once in CASES.md. Any two-digit Q, C or H identifier (with an
  optional letter) is a reference, and a range such as Q11-Q13 or
  "H01 to H08" references every case inside it.
- budgets: word budgets for the shared spec set, each annex and each plan.

Output is one `RULE: path: message` line per violation. Exit 0 when clean,
1 when any violation is found, 2 on a usage or read error (fail closed).

`--scope program` checks the native host program set and UNIFIED_ROADMAP.md.
It checks links, copy, case references and applicable budgets, not milestone
or dependency semantics. `--scope public` checks only the public copy, which carries a
known baseline until the roadmap's positioning items land (see
scripts/tests/check-native-host-docs.test.sh). The default scope is both.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote

DEFAULT_ROOT = Path(__file__).resolve().parents[1]

RETIRED = (
    "The kernel your agents answer to",
    "Agents that pay each other",
    "only protocol",
    "kernel for building agentic operating systems",
)
# The whole case namespace, not only the identifiers CASES.md uses today, so
# a reference to an undefined case is never silently ignored.
CASE_ID = re.compile(r"\b([QCH]\d\d[a-z]?)\b")
CASE_RANGE = re.compile(r"\b([QCH])(\d\d)([a-z]?)\s*(?:-|\u2013|\bto\b|\bthrough\b)\s*([QCH])(\d\d)([a-z]?)\b")
CASE_ROW = re.compile(r"^\|\s*([QCH]\d\d[a-z]?)\s*\|", re.M)
LINK_OPEN = re.compile(r"\]\(")
REF_DEF = re.compile(r"^ {0,3}\[([^\]]+)\]:[ \t]*\n?[ \t]*(?:<([^<>\n]*)>|(\S+))", re.M)
REF_USE = re.compile(r"\[([^\]]*)\]\[([^\]]*)\]")
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", re.M)
SETEXT = re.compile(r"^ {0,3}(\S[^\n]*?)\s*\n {0,3}(?:=+|-+)\s*$", re.M)
FENCE = re.compile(r"^([ \t]*)(```|~~~)[^\n]*\n.*?^[ \t]*\2[^\n]*$", re.M | re.S)
EM_DASH_ENTITY = re.compile(r"&(?:mdash|#8212|#x2014);", re.I)
INLINE_CODE = re.compile(r"`[^`\n]*`")
SVG_ATTR = re.compile(r"\b(?:alt|aria-label|title)\s*=\s*(\"[^\"]*\"|'[^']*')", re.I)
SVG_TAG = re.compile(r"<[^>]*>")
SVG_TEXT_BLOCK = re.compile(r"<(?:style|script)\b.*?</(?:style|script)>", re.I | re.S)


SHARED_REQUIRED = (
    "NORTH-STAR-FLOWS.md",
    "README.md",
    "CASES.md",
    "STATUS-GLOSSARY.md",
    "CAPABILITIES.md",
    "HOST-CONTRACT.md",
    "CONSUMERS.md",
    "QUALIFICATION.md",
    "FIRST-CLASS-INTEGRATIONS.md",
    "RELEASE.md",
    "OPERATOR.md",
)


class Layout:
    """Every path the rules read, computed from one repository root."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.scope = "all"
        self.spec = root / "docs/superpowers/specs/2026-10-07-desktop-integration"
        self.omarchy = root / "docs/superpowers/specs/2026-10-07-omarchy-integration"
        self.macos = root / "docs/superpowers/specs/2026-10-07-macos-integration"
        self.plans = root / "docs/superpowers/plans"
        self.cases = self.spec / "CASES.md"
        # Explicitly named inputs must exist; a missing one is a violation
        # rather than a silently smaller program set.
        self.program_required = [
            root / "docs/superpowers/specs/2026-10-07-omarchy-integration-design.md",
            self.plans / "2026-10-07-desktop-integration.md",
            root / "docs/architecture/PROGRAM-MAP.md",
            root / "docs/operations/UNIFIED_ROADMAP.md",
        ]
        self.adr = sorted((root / "docs/adr").glob("ADR-0038-*.md"))
        program = (
            list(self.spec.rglob("*.md"))
            + list(self.omarchy.rglob("*.md"))
            + list(self.macos.rglob("*.md"))
            + self.program_required
            + list(self.plans.glob("2026-10-07-*-integration/*.md"))
            + list(self.plans.glob("2026-10-08-*.md"))
            + self.adr
        )
        self.program = sorted({p for p in program if p.is_file()})
        self.public_required = [
            root / "README.md",
            root / "AGENTS.md",
            root / "docs/adr/README.md",
            root / "docs/reference/COMPETITIVE_LANDSCAPE.md",
            root / "spec/PROTOCOL.md",
        ]
        public = (
            self.public_required
            + list((root / "docs/start-here").rglob("*.md"))
            + list((root / "docs/assets").glob("*.svg"))
        )
        self.public = sorted({p for p in public if p.is_file()})
        # Inputs that quote retired phrases on purpose: the governing design
        # and ADR that retire them, the plan that removes them, and the
        # dated architecture reviews that recorded them, and the unified
        # roadmap's inventory of stale surfaces to fix.
        self.retired_allowlist = {
            self.spec / "NORTH-STAR-FLOWS.md",
            root / "docs/adr/ADR-0038-native-host-program.md",
            self.omarchy / "reviews/2026-10-07-architecture-review.md",
            self.macos / "reviews/2026-10-07-architecture-review.md",
            self.plans / "2026-10-08-north-star-restructure.md",
            root / "docs/operations/UNIFIED_ROADMAP.md",
        }
        # Every required shared document must exist; any other top-level
        # Markdown in the spec directory also counts toward the budget.
        # REVIEW.md and TRIM-LEDGER.md are audit records, not specification.
        required = [self.spec / name for name in SHARED_REQUIRED]
        extra = [p for p in self.spec.glob("*.md") if p.name not in {"REVIEW.md", "TRIM-LEDGER.md", *SHARED_REQUIRED}]
        shared = required + sorted(extra)
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
    body = FENCE.sub("", text)
    headings = HEADING.findall(body) + [h for h in SETEXT.findall(body) if not h.startswith("|")]
    for heading in headings:
        base = slug(heading)
        count = seen.get(base, 0)
        seen[base] = count + 1
        out.add(base if count == 0 else f"{base}-{count}")
    return out


def prose(text: str) -> str:
    """Markdown with fenced blocks and inline code blanked, line numbers kept."""
    text = FENCE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    return INLINE_CODE.sub(lambda m: " " * len(m.group(0)), text)


def _skip_space(text: str, i: int) -> int:
    """Skip spaces and tabs with at most one line ending (CommonMark)."""
    newline = False
    while i < len(text) and text[i] in " \t\n":
        if text[i] == "\n":
            if newline:
                break
            newline = True
        i += 1
    return i


def _link_destination(text: str, start: int) -> str | None:
    """Parse `(destination "title")` after `](`; None when it is not a link."""
    n = len(text)
    i = _skip_space(text, start)
    if i < n and text[i] == "<":
        j = i + 1
        while j < n and text[j] not in "<>\n":
            j += 2 if text[j] == "\\" else 1
        if j >= n or text[j] != ">":
            return None
        dest, i = text[i + 1 : j], j + 1
    else:
        depth, j = 0, i
        while j < n:
            char = text[j]
            if char == "\\" and j + 1 < n:
                j += 2
                continue
            if char.isspace() or ord(char) < 0x20:
                break
            if char == "(":
                depth += 1
            elif char == ")":
                if depth == 0:
                    break
                depth -= 1
            j += 1
        if depth:
            return None
        dest, i = text[i:j], j
    k = _skip_space(text, i)
    if k > i and k < n and text[k] in "\"'(":
        close = ")" if text[k] == "(" else text[k]
        m = k + 1
        while m < n and text[m] != close:
            if text.startswith("\n\n", m):
                return None  # a title never spans a blank line
            m += 2 if text[m] == "\\" else 1
        if m >= n:
            return None
        k = _skip_space(text, m + 1)
    if k < n and text[k] == ")":
        return re.sub(r"\\(.)", r"\1", dest)
    return None


def inline_links(text: str) -> tuple[list[str], list[int]]:
    """Inline link and image destinations, and the lines of unparsable ones."""
    targets, malformed = [], []
    for match in LINK_OPEN.finditer(text):
        dest = _link_destination(text, match.end())
        if dest is None:
            malformed.append(text.count("\n", 0, match.start()) + 1)
        else:
            targets.append(dest)
    return targets, malformed


def missing_inputs(layout: Layout, rule: str, public: bool) -> list[str]:
    """Report explicitly named inputs of the selected scope that do not exist."""
    if public:
        if layout.scope == "program":
            return []
        required = list(layout.public_required)
    else:
        if layout.scope == "public":
            return []
        required = list(layout.program_required)
    out = [f"{rule}: {layout.rel(p)}: required document missing" for p in required if not p.is_file()]
    if not public and not layout.adr:
        out.append(f"{rule}: docs/adr/ADR-0038-*.md: required document missing")
    return out


def check_links(layout: Layout) -> list[str]:
    out = missing_inputs(layout, "links", public=False)
    for path in layout.program:
        text = prose(read(path))
        definitions = {
            label.strip().lower(): angle or bare for label, angle, bare in REF_DEF.findall(text)
        }
        for link_text, label in REF_USE.findall(text):
            label = label or link_text  # a collapsed reference uses its text
            if label.strip() and label.strip().lower() not in definitions:
                out.append(f"links: {layout.rel(path)}: undefined reference [{label}]")
        targets, malformed = inline_links(text)
        for line in malformed:
            out.append(f"links: {layout.rel(path)}: malformed link at line {line}")
        for target in targets + list(definitions.values()):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
                continue
            file_part, _, anchor = target.partition("#")
            file_part = unquote(file_part)
            dest = (path.parent / file_part).resolve() if file_part else path
            if file_part and not dest.exists():
                out.append(f"links: {layout.rel(path)}: missing target {target}")
                continue
            if anchor and dest.suffix == ".md" and anchor not in anchors(read(dest)):
                out.append(f"links: {layout.rel(path)}: missing anchor {target}")
    return out


def visible_text(path: Path, text: str) -> str:
    """Text a reader sees: attribute text plus content with markup removed."""
    attrs = " ".join(value[1:-1] for value in SVG_ATTR.findall(text))
    if path.suffix == ".svg":
        body = SVG_TAG.sub(" ", SVG_TEXT_BLOCK.sub(" ", text))
    else:
        body = re.sub(r"\]\([^)]*\)", "]", text)  # link targets
        body = SVG_TAG.sub(" ", body)  # inline HTML tags
        body = re.sub(r"[\[\]*_~`]", "", body)  # emphasis, code and link brackets
    return re.sub(r"\s+", " ", f"{attrs} {body}").lower()


def check_retired(layout: Layout) -> list[str]:
    out = missing_inputs(layout, "retired-phrases", public=False) + missing_inputs(
        layout, "retired-phrases", public=True
    )
    for path in sorted(set(layout.program) | set(layout.public)):
        if path in layout.retired_allowlist:
            continue
        text = visible_text(path, read(path))
        for phrase in RETIRED:
            # "verify-only protocol" is not an "only protocol" claim. The
            # count lets a baseline catch an added occurrence in a known file.
            hits = len(re.findall(r"(?<![\w-])" + re.escape(phrase.lower()) + r"s?\b", text))
            if hits:
                out.append(f"retired-phrases: {layout.rel(path)}: contains '{phrase}' (count {hits})")
    return out


def check_em_dash(layout: Layout) -> list[str]:
    out = []
    for path in sorted(set(layout.program) | set(layout.public)):
        for number, line in enumerate(read(path).splitlines(), start=1):
            if "\u2014" in line or EM_DASH_ENTITY.search(line):
                out.append(f"em-dash: {layout.rel(path)}: line {number} contains U+2014")
    return out


def check_case_ids(layout: Layout) -> list[str]:
    if layout.cases is None:
        return []
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
        text = read(path)
        refs = set(CASE_ID.findall(text))
        for match in CASE_RANGE.finditer(text):
            first_prefix, first, first_suffix, last_prefix, last, last_suffix = match.groups()
            span = re.sub(r"\s+", " ", match.group(0))
            if first_suffix or last_suffix:
                # A suffixed range stays inside one case (Q11a-Q11c) and expands its letters.
                if (first_prefix, first) != (last_prefix, last) or not (first_suffix and last_suffix) \
                        or first_suffix > last_suffix:
                    out.append(f"case-ids: {layout.rel(path)}: malformed range {span}")
                    continue
                refs.update(f"{first_prefix}{first}{chr(code)}"
                            for code in range(ord(first_suffix), ord(last_suffix) + 1))
                continue
            if first_prefix != last_prefix or int(first) > int(last):
                out.append(f"case-ids: {layout.rel(path)}: malformed range {span}")
                continue
            refs.update(f"{first_prefix}{number:02d}" for number in range(int(first), int(last) + 1))
        for ref in sorted(refs):
            if ref not in defined:
                out.append(f"case-ids: {layout.rel(path)}: references {ref}, not defined in CASES.md")
    return out


def check_budgets(layout: Layout) -> list[str]:
    out = []
    for name, where, files, limit in layout.budgets:
        missing = [p for p in files if not p.is_file()]
        if missing:
            for path in missing:
                out.append(f"budgets: {layout.rel(path)}: {name} file missing")
            continue
        words = sum(len(read(p).split()) for p in files)
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
    parser.add_argument("--scope", choices=("all", "program", "public"), default="all",
                        help="program set, public copy, or both (default)")
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
        layout.scope = args.scope
        if args.scope == "program":
            layout.public = []
        elif args.scope == "public":
            layout.program = []
            layout.budgets = []
            layout.cases = None
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
