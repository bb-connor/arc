# Explicit proof residual landing plan

> **For agentic workers:** Use superpowers:executing-plans for this final composition.

**Goal:** Land the prepared strict proof repairs while recording the owner's
KANI-PROOF-QUAL acceptance amendment honestly. No new proof campaigns.

**Architecture:** Keep the complete attestation harness, source pins, domain,
assertions and completion cover. Exactly one enrollment carries the named
`open_residual = "KANI-ATTEST-DECOMP"`. A shared validator binds that marker to
one crate/harness pair and refuses new or malformed exceptions. The runner
reports it as OPEN/UNPROVED, excludes it from executed/passed totals, and keeps
all other checks. Ledger and release boundaries retain the unfinished properties.

**Tech stack:** Python standard library, Bash, TOML, Rust runtime tests.

**Authority:** Connor's 2026-10-09 ruling relayed in coord/pr1160, to-codex.md,
19:16:57Z. The claim prohibition includes release and ADR-0011 D8 previews.
The unproved real-SHA determinism, padding and context binding are distinguished
from the separately assumed SHA-256 noncollision property.

## Global constraints

- One integration writer; do not alter the shared dirty proof checkout.
- No proof reruns, solver changes, new assumptions, baseline changes or skipped
  failures represented as passes. Preserve every previous result and obligation.
- Import the prepared 44-file batch by source hash and three-way composition.
- Keep Claude's postmerge work separate. Normal protected merge gates remain.

## Task 1: Compose the prepared repairs and explicit residual

- [x] Verify all 44 source hashes and compose onto 9d7b95de64 using a private
  Git index. Expected: no conflict, shared checkout/index untouched.
- [x] Add `scripts/tests/kani-open-residual.test.py`. Test that the actual PR
  list excludes the exact attestation harness and reports OPEN/UNPROVED; an
  annotated custom manifest must not invoke it; wrong ID, wrong harness,
  duplicates, missing marker and another proof marker must be refused.
- [x] Run the new tests against the prepared unchanged runner. Expected: genuine
  failures for current enrollment and the explicit residual behavior.
- [x] Add `scripts/kani_open_residual.py` with
  `validate_open_residuals(entries, *, require_expected=False) -> set[tuple[str, str]]`.
  Use it in the runner, crypto-scope checker, public harness checker and Rust
  verification metadata checker. Add exactly one marker in `.kani/harnesses.toml`.
- [x] Pin reporting with `xtask/src/proof_coverage/tests/open_residual.rs`: the
  retained artifact must display `status=unproved`, `execution_lane=not-executed`
  and its named follow-up. Run it RED, add a typed residual field and qualifiers
  in the existing parser/renderer, then run focused xtask tests and regenerate.
- [x] Run the new and existing Kani shell/Python regression suites, static CI
  contract checks, formatting and affected Rust runtime/strict lint checks.
  Expected: pass with exact test counts; no solver invocation.

## Task 2: Bind evidence, review and land

- [x] Add a source-bound residual audit and update canonical current requirement
  states, landing boundary and final review without changing historical objects.
  Expected: ledger checker passes; old requirements preserved byte-for-value.
- [x] Record runtime and static evidence, commit a clean composition, and post
  `LANDING CANDIDATE <full SHA>` for planner's independent review.
- [ ] Address confirmed findings, then publish exact reviewed source as
  `LANDING HEAD <full SHA>`. Require the four protected exact-candidate checks
  and normal protected merge. Do not claim merged or released before evidence.

## Review focus

No arbitrary skip mechanism; residual cannot inflate passed counts; source pins
still reject a narrower domain; noncollision and unfinished concrete properties
remain distinct; other proof gates still execute; no release relies on the
unproved obligation. Changing acceptance never changes a failed run to passed.

## Task 3: Repair confirmed required-CI fixtures before publication

The frozen 63ae9a4f5c candidate reproduced three store fixture failures. Two
CLI service fixtures also fail custody under CI-style umask 022. Hold the
landing-head push until these existing tests exercise the current contracts.

- [x] Capture the exact candidate Original for both store integration targets:
  three failures, unchanged source, concrete approval-binding/custody reasons.
- [x] Compose only cd8e3395de's private-directory smoke fixtures. Keep the
  separate production sidecar proposal in the postmerge track.
- [x] Configure an explicit approval tenant/roster and sign the kernel-bound
  tool invocation. Preserve missing-server denial, initial Allow and reopened
  replay Deny assertions.
- [x] Complete final owning store tests, strict lint and formatting, retaining
  original and final source/log hashes.
- [ ] Integrate Claude's two CLI fixture repairs after exact-candidate Original,
  both umask controls and strict owning lint. No global umask or custody change.
- [ ] Record both obligations and evidence in the authoritative ledger, preserve
  the 1,840 prior requirements, and hand the final delta to the planner review.
- [ ] Publish the reviewed frozen candidate and observe the exact protected
  checks. No local result substitutes for hosted qualification or merge.
