#!/usr/bin/env bash
# Regression tests for scripts/check-native-host-docs.py.
#
# Fixture cases build a minimal repository layout in a temporary directory and
# assert each rule's exit code and message. The final case runs the
# retired-phrases rule against this repository's public copy and compares the
# result with the recorded baseline below. The baseline is expected to shrink
# as the positioning items UR-U3.1 to UR-U3.3 land; UR-U3.6 empties it and turns
# the rule on in CI. A violation outside the baseline fails this test.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-native-host-docs.py"

# Public-copy violations on main before the positioning items land.
# Each entry carries its occurrence count, so an added occurrence of a known
# phrase in a known file is a new violation.
PUBLIC_COPY_BASELINE=(
  "retired-phrases: README.md: contains 'The kernel your agents answer to' (count 1)"
  "retired-phrases: README.md: contains 'Agents that pay each other' (count 1)"
  "retired-phrases: docs/assets/subhead-mobile.svg: contains 'Agents that pay each other' (count 2)"
  "retired-phrases: docs/assets/subhead.svg: contains 'Agents that pay each other' (count 2)"
  "retired-phrases: docs/reference/COMPETITIVE_LANDSCAPE.md: contains 'only protocol' (count 1)"
)

work="$(mktemp -d -t chio-native-host-docs-XXXXXX)"
trap 'rm -rf "$work"' EXIT

failures=0
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

# expect NAME EXIT_CODE MESSAGE -- CHECKER_ARGS...
# MESSAGE is a fixed string that must appear on a stdout line; "-" means the
# output must be empty.
expect() {
  local name="$1" want_code="$2" want_msg="$3"
  shift 4
  local out code=0
  out="$(python3 -I "$CHECKER" --root "$fixture" "$@" 2>/dev/null)" || code=$?
  if [[ "$code" != "$want_code" ]]; then
    fail "$name: exit $code, want $want_code; output: $out"
    return
  fi
  if [[ "$want_msg" == "-" && -n "$out" ]]; then
    fail "$name: want no violations, got: $out"
    return
  fi
  if [[ "$want_msg" != "-" ]] && ! grep -qxF -- "$want_msg" <<<"$out"; then
    fail "$name: missing line '$want_msg'; output: $out"
    return
  fi
  printf 'ok: %s\n' "$name"
}

new_fixture() {
  fixture="$work/$1"
  local spec="$fixture/docs/superpowers/specs/2026-10-07-desktop-integration"
  mkdir -p "$spec/reviews" "$fixture/docs/superpowers/specs/2026-10-07-omarchy-integration/reviews" \
    "$fixture/docs/superpowers/plans" "$fixture/docs/assets" "$fixture/docs/architecture" \
    "$fixture/docs/adr" "$fixture/docs/start-here" "$fixture/docs/reference" "$fixture/spec"
  cat >"$spec/CASES.md" <<'EOF'
# Cases

| ID | Milestone | Case | Owner | Independent oracle | Status | Issue |
| --- | --- | --- | --- | --- | --- | --- |
| Q01 | HOST-M3 | Work owner case. | W | Observer | specified | |
| C01 | Platform | Harness without frontend. | Host | Observer | specified | |
| H01 | HOST-M2 | Install and select. | Plugin | Observer | specified | |
EOF
  cat >"$spec/README.md" <<'EOF'
# Program

See [cases](CASES.md#cases), Q01, C01 and H01.

## 7. Program restructure

Back to [this section](#7-program-restructure).
EOF
  cat >"$fixture/README.md" <<'EOF'
# Chio

**Authority that only narrows. Work that survives. Evidence that travels.**
EOF
  printf '# Agents\n' >"$fixture/AGENTS.md"
  printf '# Landscape\n\nChio is compared with other stacks.\n' >"$fixture/docs/reference/COMPETITIVE_LANDSCAPE.md"
  printf '# Protocol\n' >"$fixture/spec/PROTOCOL.md"
  printf '# ADRs\n' >"$fixture/docs/adr/README.md"
  printf '# ADR-0038\n' >"$fixture/docs/adr/ADR-0038-native-host-program.md"
  printf '# Program map\n' >"$fixture/docs/architecture/PROGRAM-MAP.md"
  printf '# Design\n' >"$fixture/docs/superpowers/specs/2026-10-07-omarchy-integration-design.md"
  printf '<svg xmlns="http://www.w3.org/2000/svg" aria-label="Evidence that travels"><text>Evidence that travels</text></svg>\n' \
    >"$fixture/docs/assets/subhead.svg"
  # Every budgeted document exists; a missing one is a violation.
  local shared
  for shared in NORTH-STAR-FLOWS STATUS-GLOSSARY CAPABILITIES HOST-CONTRACT CONSUMERS QUALIFICATION \
    FIRST-CLASS-INTEGRATIONS RELEASE OPERATOR; do
    printf '# %s\n' "$shared" >"$spec/$shared.md"
  done
  mkdir -p "$fixture/docs/superpowers/specs/2026-10-07-macos-integration" \
    "$fixture/docs/superpowers/plans/2026-10-07-omarchy-integration" \
    "$fixture/docs/superpowers/plans/2026-10-07-macos-integration"
  local doc
  for doc in specs/2026-10-07-omarchy-integration/ANNEX.md specs/2026-10-07-macos-integration/ANNEX.md \
    plans/2026-10-07-desktop-integration.md plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md \
    plans/2026-10-07-macos-integration/IMPLEMENTATION.md; do
    printf '# Document\n' >"$fixture/docs/superpowers/$doc"
  done
}

# A clean tree passes every rule.
new_fixture clean
expect "clean fixture passes every rule" 0 "-" --

# A retired phrase in Markdown is found even when wrapped across lines.
new_fixture markdown-retired
printf '\n<strong>The kernel your agents\nanswer to.</strong>\n' >>"$fixture/README.md"
expect "retired phrase in Markdown" 1 "retired-phrases: README.md: contains 'The kernel your agents answer to' (count 1)" -- --rule retired-phrases

# A retired phrase in an SVG alt attribute is found.
new_fixture svg-alt-retired
printf '<svg xmlns="http://www.w3.org/2000/svg"><image href="hero.png" alt="Agents that pay each other"/></svg>\n' \
  >"$fixture/docs/assets/subhead-mobile.svg"
expect "retired phrase in SVG alt" 1 "retired-phrases: docs/assets/subhead-mobile.svg: contains 'Agents that pay each other' (count 1)" -- --rule retired-phrases

# A retired phrase split across SVG text spans is found.
new_fixture svg-tspan-retired
printf '<svg xmlns="http://www.w3.org/2000/svg"><text><tspan>Agents that pay</tspan><tspan dx="4">each other</tspan></text></svg>\n' \
  >"$fixture/docs/assets/subhead.svg"
expect "retired phrase split across SVG spans" 1 "retired-phrases: docs/assets/subhead.svg: contains 'Agents that pay each other' (count 1)" -- --rule retired-phrases

# Every occurrence counts.
new_fixture repeated-retired
printf '\nThe kernel your agents answer to.\n\nThe kernel your agents answer to.\n' >>"$fixture/README.md"
expect "repeated retired phrase is counted" 1 "retired-phrases: README.md: contains 'The kernel your agents answer to' (count 2)" -- --rule retired-phrases

# Inline Markdown cannot hide a retired phrase.
new_fixture markdown-markup
printf 'Agents that **pay** each other.\n' >"$fixture/docs/start-here/EMPHASIS.md"
printf '[The kernel your agents](https://example.com) answer to.\n' >"$fixture/docs/start-here/LINK.md"
expect "retired phrase with emphasis" 1 "retired-phrases: docs/start-here/EMPHASIS.md: contains 'Agents that pay each other' (count 1)" -- --rule retired-phrases
expect "retired phrase across a link span" 1 "retired-phrases: docs/start-here/LINK.md: contains 'The kernel your agents answer to' (count 1)" -- --rule retired-phrases

# A missing explicitly named input is reported for its scope.
new_fixture missing-inputs
rm "$fixture/docs/superpowers/specs/2026-10-07-omarchy-integration-design.md" "$fixture/docs/adr/README.md"
expect "missing named program document" 1 "links: docs/superpowers/specs/2026-10-07-omarchy-integration-design.md: required document missing" -- --scope program --rule links
expect "missing named public document" 1 "retired-phrases: docs/adr/README.md: required document missing" -- --scope public --rule retired-phrases

# A plural retired claim is still a retired claim.
new_fixture plural-retired
printf 'Chio is one of the only protocols that does this.\n' >>"$fixture/docs/reference/COMPETITIVE_LANDSCAPE.md"
expect "plural only protocols" 1 "retired-phrases: docs/reference/COMPETITIVE_LANDSCAPE.md: contains 'only protocol' (count 1)" -- --rule retired-phrases

# --scope program ignores the public copy; --scope public ignores the program set.
new_fixture scopes
printf '\nThe kernel your agents answer to.\n' >>"$fixture/README.md"
printf '\nAgents that pay each other.\n' >>"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/README.md"
expect "--scope program skips public copy" 1 "retired-phrases: docs/superpowers/specs/2026-10-07-desktop-integration/README.md: contains 'Agents that pay each other' (count 1)" -- --scope program --rule retired-phrases
expect "--scope public skips the program set" 1 "retired-phrases: README.md: contains 'The kernel your agents answer to' (count 1)" -- --scope public --rule retired-phrases
new_fixture scope-public-only
printf '\nThe kernel your agents answer to.\n' >>"$fixture/README.md"
expect "--scope program ignores a public-copy violation" 0 "-" -- --scope program
new_fixture scope-program-only
printf '\nAgents that pay each other.\n' >>"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/README.md"
expect "--scope public ignores a program violation" 0 "-" -- --scope public

# The ADR index is public copy.
new_fixture adr-index
printf '# ADRs\n\nThe kernel your agents answer to.\n' >"$fixture/docs/adr/README.md"
expect "retired phrase in the ADR index" 1 "retired-phrases: docs/adr/README.md: contains 'The kernel your agents answer to' (count 1)" -- --scope public --rule retired-phrases

# "verify-only protocol" is a projection name, not an "only protocol" claim.
new_fixture verify-only
printf 'Payments use the verify-only protocol projections.\n' >>"$fixture/docs/start-here/FLAGSHIP.md"
expect "hyphenated verify-only is not a retired claim" 0 "-" -- --rule retired-phrases

# An allowlisted historical input may quote a retired phrase.
new_fixture allowlisted
printf '# Review\n\nThe old README said "The kernel your agents answer to".\n' \
  >"$fixture/docs/superpowers/specs/2026-10-07-omarchy-integration/reviews/2026-10-07-architecture-review.md"
expect "allowlisted historical file is exempt" 0 "-" -- --rule retired-phrases

# The same quote in a non-allowlisted program file is a violation.
new_fixture not-allowlisted
printf '# Review\n\nThe old README said "only protocol".\n' \
  >"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/reviews/2026-10-08-notes.md"
expect "non-allowlisted program file is checked" 1 "retired-phrases: docs/superpowers/specs/2026-10-07-desktop-integration/reviews/2026-10-08-notes.md: contains 'only protocol' (count 1)" -- --rule retired-phrases

# An em dash is reported with its line, also as an HTML entity.
new_fixture em-dash
printf 'Second line \xe2\x80\x94 with an em dash.\n' >>"$fixture/AGENTS.md"
expect "em dash" 1 "em-dash: AGENTS.md: line 2 contains U+2014" -- --rule em-dash
new_fixture em-dash-entity
printf 'Second line &mdash; as an entity.\n' >>"$fixture/AGENTS.md"
expect "em dash entity" 1 "em-dash: AGENTS.md: line 2 contains U+2014" -- --rule em-dash

# A broken relative link and a broken anchor are reported.
new_fixture broken-link
printf '\nSee [the plan](PLAN.md) and [flows](CASES.md#flows).\n' \
  >>"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/README.md"
expect "broken relative link" 1 "links: docs/superpowers/specs/2026-10-07-desktop-integration/README.md: missing target PLAN.md" -- --rule links
expect "broken anchor" 1 "links: docs/superpowers/specs/2026-10-07-desktop-integration/README.md: missing anchor CASES.md#flows" -- --rule links

# Setext headings provide anchors.
new_fixture setext
printf '\nSetext title\n============\n\nSee [it](#setext-title).\n' \
  >>"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/README.md"
expect "setext heading anchor" 0 "-" -- --rule links

# Links inside an indented fence (a fence nested in a list) are not checked.
new_fixture indented-fence
# shellcheck disable=SC2016 # literal backticks are the fixture
printf '\n- Step:\n\n  ```markdown\n  [example](MISSING.md)\n  ```\n' \
  >>"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/README.md"
expect "links in an indented fence are ignored" 0 "-" -- --rule links

# Reference-style links are checked: a missing target and an undefined label.
new_fixture reference-links
printf '\nSee [flows][north-star] and [cases][cases-ref].\n\n[north-star]: MISSING.md\n' \
  >>"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/README.md"
expect "reference link with a missing target" 1 "links: docs/superpowers/specs/2026-10-07-desktop-integration/README.md: missing target MISSING.md" -- --rule links
expect "undefined reference label" 1 "links: docs/superpowers/specs/2026-10-07-desktop-integration/README.md: undefined reference [cases-ref]" -- --rule links

# Links inside code are not checked.
new_fixture code-link
# shellcheck disable=SC2016 # literal backticks are the fixture
printf '\n```markdown\n[example](MISSING.md)\n```\n\nInline `[x](ALSO-MISSING.md)` too.\n' \
  >>"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/README.md"
expect "links in code are ignored" 0 "-" -- --rule links

# A referenced case that CASES.md does not define is reported.
new_fixture missing-case
printf '\nAlso Q02 and H06a.\n' >>"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/README.md"
expect "missing case ID" 1 "case-ids: docs/superpowers/specs/2026-10-07-desktop-integration/README.md: references Q02, not defined in CASES.md" -- --rule case-ids
expect "missing case subcase ID" 1 "case-ids: docs/superpowers/specs/2026-10-07-desktop-integration/README.md: references H06a, not defined in CASES.md" -- --rule case-ids

# A duplicate CASES row is reported.
new_fixture duplicate-case
printf '| Q01 | HOST-M3 | Again. | W | Observer | specified | |\n' \
  >>"$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/CASES.md"
expect "duplicate case row" 1 "case-ids: docs/superpowers/specs/2026-10-07-desktop-integration/CASES.md: duplicate row Q01" -- --rule case-ids

# A missing CASES.md fails closed.
new_fixture no-cases
rm "$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/CASES.md"
expect "missing CASES.md" 1 "case-ids: docs/superpowers/specs/2026-10-07-desktop-integration/CASES.md: CASES.md does not exist" -- --rule case-ids

# A word budget overrun is reported against its document.
new_fixture budget
mkdir -p "$fixture/docs/superpowers/specs/2026-10-07-macos-integration"
python3 -I -c 'print("word " * 6001)' >"$fixture/docs/superpowers/specs/2026-10-07-macos-integration/ANNEX.md"
expect "annex budget" 1 "budgets: docs/superpowers/specs/2026-10-07-macos-integration/ANNEX.md: macos annex has 6001 words, exceeds 6000" -- --rule budgets

# --only limits the report to one path and keeps violations under it.
expect "--only filters other paths" 0 "-" -- --rule budgets --only docs/superpowers/specs/2026-10-07-desktop-integration
expect "--only keeps matching paths" 1 "budgets: docs/superpowers/specs/2026-10-07-macos-integration/ANNEX.md: macos annex has 6001 words, exceeds 6000" -- --rule budgets --only docs/superpowers/specs/2026-10-07-macos-integration

# A missing required shared document fails closed.
new_fixture missing-shared-doc
rm "$fixture/docs/superpowers/specs/2026-10-07-desktop-integration/OPERATOR.md"
expect "missing shared document" 1 "budgets: docs/superpowers/specs/2026-10-07-desktop-integration/OPERATOR.md: shared spec set file missing" -- --rule budgets

# A missing budgeted document fails closed.
new_fixture missing-budget-doc
rm "$fixture/docs/superpowers/plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md"
expect "missing budgeted document" 1 "budgets: docs/superpowers/plans/2026-10-07-omarchy-integration/IMPLEMENTATION.md: omarchy plan file missing" -- --rule budgets

# Repository baseline: every public-copy violation must be in the baseline.
public_code=0
public_out="$(python3 -I "$CHECKER" --scope public --rule retired-phrases --rule em-dash 2>/dev/null)" || public_code=$?
[[ "$public_code" == 0 || "$public_code" == 1 ]] || fail "public copy: checker exited $public_code"
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  known=0
  for entry in "${PUBLIC_COPY_BASELINE[@]}"; do
    [[ "$line" == "$entry" ]] && known=1
  done
  [[ "$known" == 1 ]] || fail "public copy: new violation outside the baseline: $line"
done <<<"$public_out"
remaining="$(grep -c . <<<"$public_out" || true)"
printf 'ok: public copy within baseline (%s of %s baseline violations remain)\n' "$remaining" "${#PUBLIC_COPY_BASELINE[@]}"

if [[ "$failures" -gt 0 ]]; then
  printf '%s check(s) failed\n' "$failures" >&2
  exit 1
fi
printf 'all native host docs checks passed\n'
