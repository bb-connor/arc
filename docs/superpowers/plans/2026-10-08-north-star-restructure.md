# North-Star Program Restructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the #1177 documentation set around the approved three flows. Cut prose from about 135k words to about 30k, align the positioning copy, and file the owner-change register as tracked issues.

**Architecture:**
- This is documentation work only. A small checker script turns the spec's rules into a gate that can fail: links, retired phrases, em dashes, case IDs and word budgets.
- Each task makes the checker report fewer violations. The last task makes it pass.
- No Rust, schema or wire file changes.

**Tech Stack:** Markdown, Python 3.11 standard library (checker), `gh` CLI (issues).

**Spec:** `docs/superpowers/specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md` (approved 2026-10-08, commit `5d0d3a21a`).

## Global Constraints

**Branch and baseline**
- Branch: `docs/omarchy-integration-specs-20261007` (PR #1177). Base it on its current head.
- Another agent edits this branch concurrently. Run `git fetch origin docs/omarchy-integration-specs-20261007 && git rebase origin/docs/omarchy-integration-specs-20261007` before every task. Push after every task.
- If a rebase conflicts on a file this plan rewrites, keep the other agent's factual corrections and this plan's structure. Never drop either side silently.

**Wording**
- North-star sentence, verbatim: "Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries."
- Supporting line, verbatim: "Authority that only narrows. Work that survives. Evidence that travels."
- Retired phrases (must not appear in the program set or public copy):
  - "The kernel your agents answer to";
  - "Agents that pay each other";
  - "only protocol";
  - "kernel for building agentic operating systems".
- No em dashes (U+2014) anywhere (CLAUDE.md).
- Every profile and claim names an ADR-0011 `boundary_class` and `planning_status`.

**Word budgets** (counted by the checker)

| Set | Budget (words) |
| --- | --- |
| Shared spec set: `docs/superpowers/specs/2026-10-07-desktop-integration/*.md`, excluding `research/` and `REVIEW.md` | 15,000 |
| Each annex: `.../2026-10-07-omarchy-integration/ANNEX.md`, `.../2026-10-07-macos-integration/ANNEX.md` | 6,000 |
| Each implementation plan: `docs/superpowers/plans/2026-10-07-*-integration/IMPLEMENTATION.md` and `docs/superpowers/plans/2026-10-07-desktop-integration.md` | 8,000 |

**Structural rules**
- `NORTH-STAR-FLOWS.md` governs. Other documents reference its sections; they never restate its flows.
- Research files under `research/` are kept. Change them only to fix factual labels.
- Commits use conventional prefixes (`docs:`) and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

These are the most likely ways the restructure goes wrong for a reader. Each gets a check in the task that owns it.

1. **A case ID disappears during consolidation.** A Q, C or H case referenced anywhere must exist exactly once in `CASES.md`. Checker rule `case-ids` (Task 1), exercised in Task 3.
2. **A link or anchor breaks** after the ADR rename or a heading change. Checker rule `links` (Task 1), exercised in Tasks 2 and 4-7.
3. **A retired phrase survives in an SVG `aria-label` or `alt` text** that a Markdown grep would miss. Checker rule `retired-phrases` scans `.svg` files too (Task 1), exercised in Task 8.
4. **A trimmed document loses a safety obligation.** Every removed `MUST` sentence must map to a `CASES.md` row or to an owner spec. Task 5 adds a trim ledger.
5. **An issue is filed twice** if Task 9 is re-run. Task 9 searches before creating.

---

## File map

| File | Change |
| --- | --- |
| `scripts/check-native-host-docs.py` | Create. The checker. |
| `docs/adr/ADR-0038-desktop-operator-program.md` | Rename to `docs/adr/ADR-0038-native-host-program.md` and amend. |
| `docs/adr/README.md` | Update the ADR-0038 entry. |
| `docs/superpowers/specs/2026-10-07-desktop-integration/CASES.md` | Create. The single case table. |
| `docs/superpowers/specs/2026-10-07-desktop-integration/{CONSUMERS,QUALIFICATION,FIRST-CLASS-INTEGRATIONS}.md` | Replace case prose with references to `CASES.md`. |
| `docs/superpowers/specs/2026-10-07-desktop-integration/{README,CAPABILITIES,HOST-CONTRACT,RELEASE,OPERATOR}.md` | Rewrite or trim. |
| `docs/superpowers/specs/2026-10-07-desktop-integration/STATUS-GLOSSARY.md` | Create. One definition of each status and disclaimer. |
| `docs/superpowers/specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md` | Section 3 step-5 correction; section 9 issue links. |
| `docs/superpowers/specs/2026-10-07-{omarchy,macos}-integration/ANNEX.md`, `README.md` | Reorganize by M1/M2/M3. |
| `docs/superpowers/plans/2026-10-07-{omarchy,macos}-integration/IMPLEMENTATION.md`, `docs/superpowers/plans/2026-10-07-desktop-integration.md` | Reorganize by M1/M2/M3. |
| `README.md`, `docs/assets/subhead.svg`, `docs/assets/subhead-mobile.svg` | Positioning copy. |
| `docs/reference/COMPETITIVE_LANDSCAPE.md`, `docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md` | Remove "only protocol" claims. |

---

### Task 1: Add the program checker and record the baseline

**Files:**
- Create: `scripts/check-native-host-docs.py`

**Interfaces:**
- Produces:
  - CLI `python3 scripts/check-native-host-docs.py [--rule RULE ...]`. Exit 0 when clean, 1 with one `RULE: path: message` line per violation.
  - Rules: `links`, `retired-phrases`, `em-dash`, `case-ids`, `budgets`.

- [ ] **Step 1: Write the checker**

```python
#!/usr/bin/env python3
"""Gate for the native host program documents (NORTH-STAR-FLOWS section 7)."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/superpowers/specs/2026-10-07-desktop-integration"
OMARCHY = ROOT / "docs/superpowers/specs/2026-10-07-omarchy-integration"
MACOS = ROOT / "docs/superpowers/specs/2026-10-07-macos-integration"
PLANS = ROOT / "docs/superpowers/plans"

PROGRAM_FILES = sorted(
    [p for p in SPEC.rglob("*.md")]
    + [p for p in OMARCHY.rglob("*.md")]
    + [p for p in MACOS.rglob("*.md")]
    + [PLANS / "2026-10-07-desktop-integration.md"]
    + sorted(PLANS.glob("2026-10-07-*-integration/*.md"))
    + [ROOT / "docs/architecture/PROGRAM-MAP.md"]
    + sorted((ROOT / "docs/adr").glob("ADR-0038-*.md"))
)
PUBLIC_COPY = [
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "docs/reference/COMPETITIVE_LANDSCAPE.md",
    ROOT / "docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md",
    *sorted((ROOT / "docs/assets").glob("*.svg")),
]
RETIRED = [
    "The kernel your agents answer to",
    "Agents that pay each other",
    "only protocol",
    "kernel for building agentic operating systems",
]
# Historical inputs that quote retired phrases on purpose.
RETIRED_ALLOWLIST = {
    SPEC / "NORTH-STAR-FLOWS.md",
    OMARCHY / "reviews/2026-10-07-architecture-review.md",
    MACOS / "reviews/2026-10-07-architecture-review.md",
    PLANS / "2026-10-08-north-star-restructure.md",
}
CASE_ID = re.compile(r"\b(Q(?:0[1-9]|[1-9][0-9])|C(?:0[1-9]|1[0-9])|H0[1-8][ab]?)\b")
LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.M)
BUDGETS = [
    ("shared spec set", [p for p in SPEC.glob("*.md") if p.name != "REVIEW.md"], 15000),
    ("omarchy annex", [OMARCHY / "ANNEX.md"], 6000),
    ("macos annex", [MACOS / "ANNEX.md"], 6000),
    ("shared plan", [PLANS / "2026-10-07-desktop-integration.md"], 8000),
    ("omarchy plan", [PLANS / "2026-10-07-omarchy-integration/IMPLEMENTATION.md"], 8000),
    ("macos plan", [PLANS / "2026-10-07-macos-integration/IMPLEMENTATION.md"], 8000),
]


def slug(text: str) -> str:
    text = re.sub(r"[`*_]", "", text.lower())
    text = re.sub(r"[^a-z0-9 -]", "", text)
    return text.strip().replace(" ", "-")


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def check_links() -> list[str]:
    out = []
    for path in PROGRAM_FILES:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for target in LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            file_part, _, anchor = target.partition("#")
            dest = (path.parent / file_part).resolve() if file_part else path
            if file_part and not dest.exists():
                out.append(f"links: {rel(path)}: missing target {target}")
                continue
            if anchor and dest.suffix == ".md":
                anchors = {slug(h) for h in HEADING.findall(dest.read_text(encoding="utf-8"))}
                if anchor not in anchors:
                    out.append(f"links: {rel(path)}: missing anchor {target}")
    return out


def check_retired() -> list[str]:
    out = []
    for path in PROGRAM_FILES + PUBLIC_COPY:
        if not path.exists() or path in RETIRED_ALLOWLIST:
            continue
        text = path.read_text(encoding="utf-8")
        for phrase in RETIRED:
            if phrase.lower() in text.lower():
                out.append(f"retired-phrases: {rel(path)}: contains '{phrase}'")
    return out


def check_em_dash() -> list[str]:
    return [
        f"em-dash: {rel(p)}: contains U+2014"
        for p in PROGRAM_FILES + PUBLIC_COPY
        if p.exists() and "\u2014" in p.read_text(encoding="utf-8")
    ]


def check_case_ids() -> list[str]:
    cases = SPEC / "CASES.md"
    if not cases.exists():
        return ["case-ids: CASES.md does not exist"]
    rows = re.findall(r"^\|\s*(Q\d\d|C\d\d|H0[1-8][ab]?)\s*\|", cases.read_text(encoding="utf-8"), re.M)
    out = [f"case-ids: CASES.md: duplicate row {i}" for i in sorted({r for r in rows if rows.count(r) > 1})]
    defined = set(rows)
    for path in PROGRAM_FILES:
        if not path.exists() or path == cases or "research" in path.parts or "reviews" in path.parts:
            continue
        for ref in sorted(set(CASE_ID.findall(path.read_text(encoding="utf-8")))):
            if ref not in defined:
                out.append(f"case-ids: {rel(path)}: references {ref}, not defined in CASES.md")
    return out


def check_budgets() -> list[str]:
    out = []
    for name, files, limit in BUDGETS:
        words = sum(len(p.read_text(encoding="utf-8").split()) for p in files if p.exists())
        if words > limit:
            out.append(f"budgets: {name}: {words} words exceeds {limit}")
    return out


RULES = {
    "links": check_links,
    "retired-phrases": check_retired,
    "em-dash": check_em_dash,
    "case-ids": check_case_ids,
    "budgets": check_budgets,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rule", action="append", choices=sorted(RULES))
    args = parser.parse_args()
    violations = [v for name in (args.rule or sorted(RULES)) for v in RULES[name]()]
    for violation in violations:
        print(violation)
    print(f"{len(violations)} violation(s)", file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run it and record the baseline**

Run: `python3 -I scripts/check-native-host-docs.py > /tmp/native-host-baseline.txt; tail -1 /tmp/native-host-baseline.txt; cut -d: -f1 /tmp/native-host-baseline.txt | sort | uniq -c`

Expected: exit 1. At `5d0d3a21a` the baseline is 17 violations:
- 11 `retired-phrases`;
- 1 `case-ids` (CASES.md does not exist);
- 5 `budgets`: shared spec set 24,821 words, Omarchy annex 9,138, macOS annex 11,990, Omarchy plan 13,156, macOS plan 31,244;
- no `links` violations.

Paste the counts into the commit message body.

- [ ] **Step 3: Self-test the slug function against a known anchor**

Run: `python3 -I -c "import importlib.util,sys;s=importlib.util.spec_from_file_location('c','scripts/check-native-host-docs.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);assert m.slug('7. Program restructure')=='7-program-restructure';assert m.slug('Flow M1: Cooperate-0')=='flow-m1-cooperate-0';print('ok')"`

Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add scripts/check-native-host-docs.py
git commit -m "docs(tooling): add native host program checker" -m "Baseline: <paste counts>" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin HEAD:docs/omarchy-integration-specs-20261007
```

### Task 2: Amend and rename ADR-0038, and correct M1 step 5

**Files:**
- Rename: `docs/adr/ADR-0038-desktop-operator-program.md` to `docs/adr/ADR-0038-native-host-program.md`.
- Modify: `docs/adr/README.md`.
- Modify: every file that links to the old ADR name (found in Step 1).
- Modify: `docs/superpowers/specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md`, section 3.

**Interfaces:**
- Produces:
  - ADR path `docs/adr/ADR-0038-native-host-program.md`, title `# ADR-0038: Native host program`.
  - An `## Amendment 2026-10-08: north star and flows` section, which later tasks cite.

- [ ] **Step 1: Find every reference to the old file name**

Run: `git grep -l 'ADR-0038-desktop-operator-program' -- . ':!*.svg'`

Expected: a list of files. Keep it for Step 3.

- [ ] **Step 2: Rename and amend the ADR**

```bash
git mv docs/adr/ADR-0038-desktop-operator-program.md docs/adr/ADR-0038-native-host-program.md
```

Change the first heading line to `# ADR-0038: Native host program`. Then append this section verbatim:

```markdown
## Amendment 2026-10-08: north star and flows

Status: accepted by the program owner on 2026-10-08.

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.** Supporting
line: **Authority that only narrows. Work that survives. Evidence that travels.**

1. **Kernel.** Chio is a userspace authority and work-state kernel. Isolation
   always comes from the host and is credited per S7 evidence kind.
2. **Retired phrases.** "The kernel your agents answer to", "Agents that pay
   each other", "only protocol" claims and unscoped "every call" are retired.
3. **Identity.** The units are organization principal, then domain, then agent
   subject, then operator. Key custody uses OS-native storage through key
   references; plaintext seed files are a labelled development profile.
4. **Order.** Cooperate comes first:
   - M1 Cooperate-0 runs on two independently operated hosts.
   - M2 runs one root grant across Claude Code, Codex, Pi and Hermes, on
     Omarchy first.
   - M3 is co-signed cross-organization work under #1173 W1/W2.
5. **Megastart.** Its aggregate allowance moves onto kernel holds.
6. **Governance.** [NORTH-STAR-FLOWS](../superpowers/specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md)
   governs the program. Other program documents reference it instead of
   restating it.
```

- [ ] **Step 3: Update links and the ADR index**

For each file from Step 1, replace `ADR-0038-desktop-operator-program.md` with `ADR-0038-native-host-program.md`:

```bash
git grep -l 'ADR-0038-desktop-operator-program' -- . ':!*.svg' | xargs sed -i.bak 's/ADR-0038-desktop-operator-program/ADR-0038-native-host-program/g'
find . -name '*.bak' -newer scripts/check-native-host-docs.py -delete
```

In `docs/adr/README.md`, replace the ADR-0038 bullet with:

`- [ADR-0038 Native Host Program](ADR-0038-native-host-program.md) - accepted for planning; north star, three flows and native host services.`

- [ ] **Step 4: Correct the M1 step-5 tool surface in NORTH-STAR-FLOWS**

In section 3, step 0, replace `plus \`chio mcp serve-http\` on B` with:

`plus, on B, the governed tool behind \`chio api protect\` with \`CHIO_TRUSTED_ISSUER_KEY\` set to B's trust-control authority key`

Add this paragraph directly after the step table:

```markdown
Step 5 uses `chio api protect` rather than `chio mcp serve-http`. The API
protect evaluator accepts a capability presented in the `X-Chio-Capability`
header from issuers named in `CHIO_TRUSTED_ISSUER_KEY(S)` (T:
`crates/products/chio-api-protect/src/evaluator.rs:463-469`,
`crates/products/chio-cli/src/cli/runtime.rs:576`). `serve-http` issues session
capabilities from its own policy and does not accept externally issued ones.
```

In section 9, change the row `Native service packaging for \`chio trust serve\` and \`chio mcp serve-http\`` to `Native service packaging for \`chio trust serve\` and \`chio api protect\``.

- [ ] **Step 5: Verify links**

Run: `python3 -I scripts/check-native-host-docs.py --rule links`

Expected: no `links:` violation mentions `ADR-0038`.

- [ ] **Step 6: Commit and push**

```bash
git add -A docs/adr docs/superpowers README.md AGENTS.md docs/architecture
git commit -m "docs(adr): amend ADR-0038 with the north star and rename it" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin HEAD:docs/omarchy-integration-specs-20261007
```

### Task 3: Consolidate all cases into CASES.md

**Files:**
- Create: `docs/superpowers/specs/2026-10-07-desktop-integration/CASES.md`
- Modify: `CONSUMERS.md`, `QUALIFICATION.md`, `FIRST-CLASS-INTEGRATIONS.md` (same directory).

**Interfaces:**
- Consumes: the ADR path from Task 2.
- Produces: `CASES.md` with one row per ID in this exact header:
  `| ID | Milestone | Case | Owner | Independent oracle | Status | Issue |`
  - Milestone values: `M1`, `M2`, `M3`, `Platform`.
  - Status values: the `STATUS-GLOSSARY.md` terms (Task 5); until then, use `specified`.

- [ ] **Step 1: Inventory every case definition**

Run: `git grep -n -E '^\| ?(Q[0-9]{2}|C[0-9]{2}|H0[1-8][ab]?) ' -- docs/superpowers/specs/2026-10-07-desktop-integration | cut -c1-160`

Expected: rows for Q01-Q31, C01-C11 and H01-H08 (with H06a/H06b and H08a/H08b). Note the file and line where each ID is defined.

- [ ] **Step 2: Build CASES.md using this milestone map**

Use this map. Copy each row's case, owner and oracle text from its current definition, shortened to one sentence each. If a definition contradicts the milestone below, keep the definition and put the milestone in the row's `Case` text with a `(reassigned: reason)` note.

| IDs | Milestone |
| --- | --- |
| C09, Q05, Q06, Q24, Q28, Q29 | M1 |
| C02, C03, C04, C05, C10, C11, Q03, Q07, Q08, Q11, Q12, Q13, Q15, Q19, Q22, Q23, Q25, Q26, Q27, H01-H08 (all variants) | M2 |
| C06, C07, C08, Q01, Q02, Q14 | M3 |
| C01, Q04, Q09, Q10, Q16, Q17, Q18, Q20, Q21, Q30, Q31 | Platform |

The file starts with:

```markdown
# Cases

Single source for every acceptance case in the native host program. Flows are
defined in [NORTH-STAR-FLOWS](NORTH-STAR-FLOWS.md). A case is executable only
when its owner gate exists; status terms are defined in
[STATUS-GLOSSARY](STATUS-GLOSSARY.md).

| ID | Milestone | Case | Owner | Independent oracle | Status | Issue |
| --- | --- | --- | --- | --- | --- | --- |
```

Then add one row per ID, sorted Q, then C, then H.

- [ ] **Step 3: Replace the case prose at the source**

In each source file, replace the case table rows and per-case paragraphs with one line:

`Cases are defined in [CASES](CASES.md); this document explains the surrounding design.`

Keep any non-case design prose.

- [ ] **Step 4: Verify that no case ID was lost**

Run: `python3 -I scripts/check-native-host-docs.py --rule case-ids --rule links`

Expected: exit 0 for these two rules.

Also run: `grep -c -E '^\| (Q|C|H)[0-9]' docs/superpowers/specs/2026-10-07-desktop-integration/CASES.md`

Expected: the same count as the number of distinct IDs from Step 1.

- [ ] **Step 5: Commit and push**

```bash
git add docs/superpowers/specs/2026-10-07-desktop-integration
git commit -m "docs(desktop): consolidate acceptance cases into CASES.md" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin HEAD:docs/omarchy-integration-specs-20261007
```

### Task 4: Rewrite the program index and the capability matrix

**Files:**
- Modify: `docs/superpowers/specs/2026-10-07-desktop-integration/README.md`
- Modify: `docs/superpowers/specs/2026-10-07-desktop-integration/CAPABILITIES.md`

**Interfaces:**
- Consumes: `CASES.md` (Task 3); the NORTH-STAR-FLOWS anchors `#3-flow-m1-cooperate-0`, `#4-flow-m2-one-root-grant-many-agents`, `#5-flow-m3-work-that-crosses-an-organization-boundary-and-comes-back-verified` and `#6-platform-delivery`.

- [ ] **Step 1: Replace README.md**

Keep the status line. The body becomes the north-star sentence and supporting line, then these sections:
- **"Three flows":** one bullet per M1, M2 and M3, each linking to its NORTH-STAR-FLOWS anchor.
- **"Platform order":** the four numbered steps from NORTH-STAR-FLOWS section 6.
- **"Read in order":** NORTH-STAR-FLOWS, ADR-0038, CASES, CAPABILITIES, HOST-CONTRACT, PROGRAM-MAP, then the Omarchy and macOS annexes.
- **"Boundaries":** one paragraph stating that hook mode is `detect_only`, isolation is credited to host backends, and receipts can be missing after dispatch (#1174 D1).

Remove all other prose.

- [ ] **Step 2: Replace CAPABILITIES.md with the matrix**

Header: `| Verb | Capability | Owner and source | Status | Omarchy | macOS | Flow |`

Add one row for each of the following, with source paths taken from NORTH-STAR-FLOWS section 10:
- passports;
- `did:chio`;
- federated issue;
- evidence export, verify and import;
- treaties and federation (`crates/trust/chio-federation`, `crates/trust/chio-federation-authority`, `crates/trust/chio-federation-transport-iroh`, ADR-0014);
- selective disclosure;
- attenuation and the sibling split;
- swarm authority;
- process trees (F);
- mailboxes (F);
- work commitments (W, **planned**);
- recovery (R, **not qualified**);
- hold ledger;
- metering and settlement (`crates/economy/chio-metering`, `crates/economy/chio-settle`, labelled library-only where no serving path exists);
- credential broker (F, Linux-only);
- model relay (F, request counts only).

Status values: `shipped`, `F`, `W planned`, `R unqualified`, `library-only`.

- [ ] **Step 3: Verify**

Run: `python3 -I scripts/check-native-host-docs.py --rule links --rule case-ids`

Expected: exit 0.

Then run: `grep -c 'WorkHandleV1\|WorkViewV1' docs/superpowers/specs/2026-10-07-desktop-integration/CAPABILITIES.md`

Expected: every match sits on a row whose Status cell reads `W planned`. Spot-check them by eye.

- [ ] **Step 4: Commit and push**

```bash
git add docs/superpowers/specs/2026-10-07-desktop-integration
git commit -m "docs(desktop): lead the program index with the three flows" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin HEAD:docs/omarchy-integration-specs-20261007
```

### Task 5: Trim HOST-CONTRACT, RELEASE and OPERATOR behind a status glossary

**Files:**
- Create: `docs/superpowers/specs/2026-10-07-desktop-integration/STATUS-GLOSSARY.md`
- Create: `docs/superpowers/specs/2026-10-07-desktop-integration/reviews/2026-10-08-trim-ledger.md`
- Modify: `HOST-CONTRACT.md`, `RELEASE.md`, `OPERATOR.md`, `CASES.md` (same directory).

**Interfaces:**
- Produces: the glossary terms `specified`, `owner-gated`, `implemented`, `installed`, `qualified`, `released`, plus the ADR-0011 classes, each defined once. `CASES.md` statuses switch to these terms.

- [ ] **Step 1: Write STATUS-GLOSSARY.md**

```markdown
# Status glossary

Every status and disclaimer in the native host program is defined here once.

| Term | Meaning |
| --- | --- |
| specified | Written in a design; no implementation exists. |
| owner-gated | Depends on a named owner change in NORTH-STAR-FLOWS section 9. |
| implemented | Code exists on a branch; not installed or qualified. |
| installed | Built artifact installed on a named host tuple. |
| qualified | Passed its CASES rows on real hosts with independent oracles. |
| released | Qualified tuple published from public sources. |

ADR-0011 classes apply per operation: `prevent` (Chio decides before effect),
`detect_only` (Chio records after or outside the effect path), `advisory_only`
(guidance; never grants scope), `cannot_see` (outside Chio's mediation).

Standing limits (cite this section instead of restating them):
- Hook-mode host activity is `detect_only`.
- Isolation is credited to the host backend through its S7 evidence kind.
- A receipt can be missing after dispatch (#1174 D1). A missing receipt is not
  evidence that no effect occurred.
- Historical evidence never qualifies a new version tuple.
```

- [ ] **Step 2: Trim each file**

In HOST-CONTRACT.md, RELEASE.md and OPERATOR.md, delete repeated disclaimer sentences. Each one becomes `See [STATUS-GLOSSARY](STATUS-GLOSSARY.md).`, cited at most once per section. Delete any acceptance prose already represented by a CASES row. For every `MUST` or `MUST NOT` sentence removed, add a line to the trim ledger:

```markdown
| Removed sentence (first 12 words) | File | Now covered by |
| --- | --- | --- |
```

The "Now covered by" cell is a CASES ID or an owner spec section. A removed sentence with no home is restored instead.

- [ ] **Step 3: Switch CASES.md statuses**

Replace `specified` with the correct glossary term per row. Rows whose owner is listed in NORTH-STAR-FLOWS section 9 become `owner-gated`.

- [ ] **Step 4: Verify budgets and links**

Run: `python3 -I scripts/check-native-host-docs.py --rule budgets --rule links --rule case-ids`

Expected: no `shared spec set` budget violation. If the set is still over 15,000 words, continue trimming the largest file (`wc -w` each) and record every removed MUST in the ledger.

- [ ] **Step 5: Commit and push**

```bash
git add docs/superpowers/specs/2026-10-07-desktop-integration
git commit -m "docs(desktop): trim shared specs behind a status glossary" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin HEAD:docs/omarchy-integration-specs-20261007
```

### Task 6: Reorganize the Omarchy annex and plan by flow, and record Herdr

**Files:**
- Modify: `docs/superpowers/specs/2026-10-07-omarchy-integration/ANNEX.md`
- Modify: `docs/superpowers/specs/2026-10-07-omarchy-integration/README.md`
- Modify: `docs/superpowers/plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md`

- [ ] **Step 1: Restructure ANNEX.md to these top-level sections, in order**

1. `## M1 on Omarchy`: systemd user units, Secret Service and `systemd-creds` custody, notification and Walker review entry. Use the Omarchy column of NORTH-STAR-FLOWS section 6.
2. `## M2 on Omarchy`: #1160 resource owner, process host, broker, Pi bubblewrap first, then Linux launchers per host, then the Megastart Linux port. Rootless engine rules stay here.
3. `## M3 on Omarchy`: executing-owner requirements.
4. `## Services, custody and IPC`.
5. `## Packaging and lifecycle`.
6. `## Herdr`, with exactly this content:

```markdown
Herdr is a third-party terminal workspace application for coding agents
(https://herdr.dev/docs/, version 0.9.3 inspected 2026-10-08). "Herdr support"
in this program currently means Megastart's Herdr plugin (G in PROGRAM-MAP).
Megastart's native composition requires Apple Silicon macOS, so Linux Herdr
cases stay blocked until the Megastart Linux port lands (NORTH-STAR-FLOWS
section 9). Herdr never issues kernel authority.
```

Move existing content into these sections. Delete content that restates shared documents and link instead.

- [ ] **Step 2: Restructure IMPLEMENTATION.md the same way**

Packets are regrouped under `## M1 packets`, `## M2 packets`, `## M3 packets` and `## Platform packets`. Merge any packet whose subject now belongs to the shared plan into a one-line reference.

- [ ] **Step 3: Verify**

Run: `python3 -I scripts/check-native-host-docs.py --rule budgets --rule links --rule case-ids`

Expected: no `omarchy annex` or `omarchy plan` budget violation; links are clean.

- [ ] **Step 4: Commit and push**

```bash
git add docs/superpowers/specs/2026-10-07-omarchy-integration docs/superpowers/plans/2026-10-07-omarchy-integration
git commit -m "docs(omarchy): organize the annex and plan by north-star flow" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin HEAD:docs/omarchy-integration-specs-20261007
```

### Task 7: Reorganize the macOS annex and plan by flow

**Files:**
- Modify: `docs/superpowers/specs/2026-10-07-macos-integration/ANNEX.md`
- Modify: `docs/superpowers/specs/2026-10-07-macos-integration/README.md`
- Modify: `docs/superpowers/plans/2026-10-07-macos-integration/IMPLEMENTATION.md`

- [ ] **Step 1: Restructure ANNEX.md**

Use the same six sections as Task 6, with these replacements:

| Section | macOS content |
| --- | --- |
| M1 | LaunchAgent, login-keychain or data-protection Keychain custody, passkey through Touch ID, native review window |
| M2 | Darwin process runner, Keychain/XPC broker, resource backend selection (Containerization, OpenShell MicroVM, Docker Desktop), Seatbelt launchers, Megastart as coordinator after its allowance moves onto kernel holds |
| Final section | `## Managed endpoint (ES/NE)`, in place of Herdr |

In the existing-owner table, change the W1 row's label from "Existing owner consumed on Mac" to "Planned W1 owner". `WorkHandleV1`, `WorkViewV1`, `WorkClient` and `WorkTransport` are design-only (PROGRAM-MAP).

- [ ] **Step 2: Restructure IMPLEMENTATION.md**

Use the same packet grouping as Task 6. The macOS plan must end at or under 8,000 words. Collapse the Seatbelt, Keychain and symlink checklists into references to their CASES rows.

- [ ] **Step 3: Verify**

Run: `python3 -I scripts/check-native-host-docs.py --rule budgets --rule links --rule case-ids`

Expected: no `macos annex` or `macos plan` budget violation.

Then run: `git grep -n 'Existing owner consumed on Mac' -- docs/superpowers/specs/2026-10-07-macos-integration`

Expected: no output.

- [ ] **Step 4: Commit and push**

```bash
git add docs/superpowers/specs/2026-10-07-macos-integration docs/superpowers/plans/2026-10-07-macos-integration
git commit -m "docs(macos): organize the annex and plan by north-star flow" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin HEAD:docs/omarchy-integration-specs-20261007
```

### Task 8: Align positioning copy

**Files:**
- Modify: `README.md`, `docs/assets/subhead.svg`, `docs/assets/subhead-mobile.svg`
- Modify: `docs/reference/COMPETITIVE_LANDSCAPE.md`, `docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md`
- Modify:
  - `docs/superpowers/specs/2026-10-07-desktop-integration/HOST-CONTRACT.md`
  - `docs/superpowers/specs/2026-10-07-desktop-integration/research/product-grounding.md`
  - `docs/superpowers/specs/2026-10-07-macos-integration/ANNEX.md`
  - `docs/superpowers/specs/2026-10-07-macos-integration/README.md`
  - `docs/superpowers/specs/2026-10-07-macos-integration/research/native-host-services.md`

- [ ] **Step 1: Confirm the current failures**

Run: `python3 -I scripts/check-native-host-docs.py --rule retired-phrases`

Expected: violations in the files listed above.

- [ ] **Step 2: Edit the README hero**

- Replace the tagline line containing "The kernel your agents answer to" with `**Authority that only narrows. Work that survives. Evidence that travels.**`
- The first paragraph under the hero becomes the north-star sentence, verbatim.
- In the subhead `<img>` alt text, replace "Agents that pay each other" with "Evidence that travels".

- [ ] **Step 3: Edit both subhead SVGs**

In `docs/assets/subhead.svg` and `docs/assets/subhead-mobile.svg`, replace the text node and any `aria-label` containing "Agents that pay each other" with "Evidence that travels".

Render both to confirm layout:

`rsvg-convert -w 1200 docs/assets/subhead.svg -o /tmp/subhead.png && rsvg-convert -w 600 docs/assets/subhead-mobile.svg -o /tmp/subhead-mobile.png`

Open both PNGs. Text must not overflow its box.

- [ ] **Step 4: Remove the "only protocol" claims**

In `COMPETITIVE_LANDSCAPE.md` and `FLAGSHIP_WALL_STOPS_MONEY.md`, rewrite each sentence containing "only protocol" as a comparative statement with no exclusivity claim. Example: replace "Chio is the only protocol that X" with "Chio provides X; see the comparison table for how other stacks handle it."

- [ ] **Step 5: Unify the "building" variant**

In the five spec files listed above, replace "a Rust kernel for building agentic operating systems" with the north-star sentence, verbatim.

- [ ] **Step 6: Verify**

Run: `python3 -I scripts/check-native-host-docs.py --rule retired-phrases --rule em-dash`

Expected: exit 0.

- [ ] **Step 7: Commit and push**

```bash
git add README.md docs/assets/subhead.svg docs/assets/subhead-mobile.svg docs/reference/COMPETITIVE_LANDSCAPE.md docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md docs/superpowers/specs
git commit -m "docs: align positioning with the north star and retire stop-listed phrases" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin HEAD:docs/omarchy-integration-specs-20261007
```

### Task 9: File the owner-change register as issues

**Files:**
- Modify: `docs/superpowers/specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md` (section 9 gains an `Issue` column).
- Modify: `docs/superpowers/specs/2026-10-07-desktop-integration/CASES.md` (`Issue` column).

**Interfaces:**
- Consumes: the 16 rows of NORTH-STAR-FLOWS section 9.
- Produces: one issue URL per row.

- [ ] **Step 1: Search for existing issues first, so a re-run never duplicates one**

For each row title, run (example for row 1):

`gh issue list -R bb-connor/arc --state all --search "custody provider SigningBackend in:title" --json number,title`

If a matching issue exists, reuse its URL.

- [ ] **Step 2: Create the missing issues**

For each row without an issue:

```bash
gh issue create -R bb-connor/arc \
  --title "<row Change text>" \
  --label enhancement \
  --body "Owner change from the native host program (NORTH-STAR-FLOWS section 9).

Owner: <row Owner>. Needed by: <row Needed by>.

Context: docs/superpowers/specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md on #1177.
Acceptance: the CASES.md rows for <milestone> that depend on this change pass on real hosts.

_Filed by Claude at the maintainer's request._"
```

Exceptions:
- **Megastart** belongs to `backbay-labs/chio`. Use `-R backbay-labs/chio`.
- **Linux launchers** belong to the plugin repositories. File one issue per repository: `backbay-labs/chio-claude-code-plugin` and `backbay-labs/chio-codex-plugin`. For Hermes, file in `bb-connor/arc`, because `sdks/python/chio-hermes` lives there.

- [ ] **Step 3: Record the links**

Add an `Issue` column to the section 9 table holding each URL. Fill the `Issue` cell of every CASES row whose owner matches.

- [ ] **Step 4: Verify**

Run: `grep -c 'github.com/.*/issues/' docs/superpowers/specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md`

Expected: 18 or more. That is 16 rows, with the launcher row split across three issues.

- [ ] **Step 5: Commit and push**

```bash
git add docs/superpowers/specs/2026-10-07-desktop-integration
git commit -m "docs(desktop): link owner changes to tracked issues" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin HEAD:docs/omarchy-integration-specs-20261007
```

### Task 10: Final gate and PR description

**Files:**
- Modify: the #1177 PR description, through `gh pr edit`.

- [ ] **Step 1: Run the full checker**

Run: `python3 -I scripts/check-native-host-docs.py`

Expected: `0 violation(s)`, exit 0.

- [ ] **Step 2: Report the volume**

Run: `cat docs/superpowers/specs/2026-10-07-desktop-integration/*.md docs/superpowers/specs/2026-10-07-*-integration/ANNEX.md docs/superpowers/plans/2026-10-07-desktop-integration.md docs/superpowers/plans/2026-10-07-*-integration/IMPLEMENTATION.md | wc -w`

Expected: 43,000 words or fewer. That is 15,000 shared, plus 6,000 for each annex, plus 8,000 for each of the two platform plans. The shared plan counts inside its own budget.

- [ ] **Step 3: Update the PR description**

```bash
gh pr edit 1177 --body-file - <<'EOF'
## North-star native host program

Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries.

This PR specifies how Chio runs as native host services on Omarchy and macOS. Three flows govern it (NORTH-STAR-FLOWS.md):

- **M1 Cooperate-0:** two independently operated hosts run the shipped passport, challenge, federated-issue and evidence loop.
- **M2:** one root grant across Claude Code, Codex, Pi and Hermes, on Omarchy first.
- **M3:** co-signed cross-organization work under #1173 W1/W2.

ADR-0038 records the decision. CASES.md holds every acceptance case. `scripts/check-native-host-docs.py` gates links, retired phrases, case IDs and word budgets. Owner changes are filed as issues and linked from NORTH-STAR-FLOWS section 9.

Specifications and plans only. No runtime is implemented or qualified here.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
```

- [ ] **Step 4: Ask the other agent's lane to adopt the checker**

Post one PR comment:

`gh pr comment 1177 --body "Program docs now have a gate: python3 scripts/check-native-host-docs.py. New findings go into CASES.md rows; keep budgets green. See NORTH-STAR-FLOWS section 7."`
